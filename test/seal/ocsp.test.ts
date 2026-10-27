/**
 * Revocation by OCSP: the requests a seal needs, the verification of the
 * responses (their responder, their signature, their dates), at levels B, T
 * and LT. The responses come from test/helpers/ocsp.ts or from OpenSSL, not
 * from the code under test; DSS validates a seal of level LT by the OCSP
 * response it embeds.
 */

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, test } from 'node:test';

import { addSignatureTimestamp, timestampRequest } from '../../dist/seal/extend.js';
import { createSeal } from '../../dist/seal/seal.js';
import { addValidationData, validationDataRequests } from '../../dist/seal/validation.js';
import { verifySeal, type VerifyOptions } from '../../dist/seal/verify.js';
import { readZip, writeZip } from '../../dist/seal/zip.js';
import { ocspSources, readOcspResponse } from '../../dist/seal/ocsp.js';
import { X509Cert } from '../../dist/x509.js';
import { makeCrl } from '../helpers/crl.ts';
import { dssSkip, validateWithDss } from '../helpers/dss.ts';
import { makeOcspResponse, opensslOcsp, opensslOcspSkip, type OcspOptions } from '../helpers/ocsp.ts';
import { timestampResponse } from '../helpers/tsa.ts';

const CERTS = 'test/fixtures/seal/certs';
const TRUST = { caCertPath: `${CERTS}/root.cert.pem`, tsaCertPath: `${CERTS}/tsa-root.cert.pem` };
const secondsAgo = (seconds: number) => new Date(Date.now() - seconds * 1000);
const SIGNER = 'RSA 3072 Seal Dept';

function seal(key = 'rsa3072'): Buffer {
  const intermediate = key === 'offline' ? 'intermediate-offline' : 'intermediate';
  return createSeal([{ name: 'contrat.pdf', content: Buffer.from('%PDF-1.4\n') }], `${CERTS}/${key}.key.pem`, `${CERTS}/${key}.cert.pem`, 'signKeyPassword', { chain: [`${CERTS}/${intermediate}.cert.pem`] });
}

// The time-stamps are made a few seconds ago: the seal certificates are
// valid from their generation only, which may be just before the tests.
function timestamped(key = 'rsa3072', tsa: 'tsa' | 'tsa-offline' = 'tsa'): Buffer {
  const container = seal(key);
  return addSignatureTimestamp(container, timestampResponse(timestampRequest(container), { time: secondsAgo(20), name: tsa }), { tsaCertPath: TRUST.tsaCertPath });
}

/** The status of the signer by OCSP, of the intermediate by the CRL of the root. */
function check(container: Buffer, responses: Buffer[], options: Partial<VerifyOptions> = {}) {
  return verifySeal(container, { ...TRUST, ocspResponses: responses, crls: [makeCrl({ issuer: 'root' }), makeCrl({ issuer: 'tsa-root' })], ...options });
}

const ocsp = (options: Partial<OcspOptions> = {}) => makeOcspResponse({ cert: 'rsa3072', ...options });
const certificate = (name: string) => new X509Cert(readFileSync(`${CERTS}/${name}.cert.pem`, 'utf8'));

describe('the requests', () => {
  test('one for each certificate that names a responder: the signer', () => {
    const { ocsp: requests } = validationDataRequests(timestamped(), TRUST);
    assert.deepEqual(requests.map((request) => [request.certificate.getSubject().OU, request.issuer.getSubject().OU, request.urls]), [
      [SIGNER, 'Seal Intermediate CA', ['http://pki.ezxmlseal.test/ocsp']],
    ]);
  });

  test('OpenSSL reads the request: the serial number of the signer, by SHA-1 (RFC 5019, 2.1.1)', { skip: opensslOcspSkip }, () => {
    const { ocsp: [request] } = validationDataRequests(seal(), TRUST);
    const dir = mkdtempSync(join(tmpdir(), 'ezxmlseal-ocsp-req-'));
    try {
      writeFileSync(join(dir, 'request.der'), request?.request as Buffer);
      const text = spawnSync('openssl', ['ocsp', '-reqin', join(dir, 'request.der'), '-req_text'], { encoding: 'utf8' }).stdout;
      assert.match(text, /Hash Algorithm: sha1/);
      assert.match(text, new RegExp(`Serial Number: ${request?.certificate.getSerialNumber().toString('hex').toUpperCase()}`));
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('level B: the status at the current date', () => {
  const container = seal();
  const valid: [string, Partial<OcspOptions>][] = [
    ['signed by the issuer, which it names', {}],
    ['signed by the issuer, which it names by its key', { responderBy: 'key' }],
    ['signed by a responder the issuer delegated, with id-pkix-ocsp-nocheck', { signer: 'ocsp' }],
    ['a CertID by SHA-256', { certIdHash: 'sha256' }],
  ];
  for (const [name, options] of valid) {
    test(`good, ${name}: valid`, () => {
      const result = check(container, [ocsp(options)]);
      assert.equal(result.getError(), null);
      assert.equal(result.isRevocationChecked(), true);
    });
  }

  test('a response of OpenSSL to the request of the library', { skip: opensslOcspSkip }, () => {
    const { ocsp: [request] } = validationDataRequests(container, TRUST);
    assert.equal(check(container, [opensslOcsp(request?.request as Buffer)]).getError(), null);
  });

  test('the signer revoked, in a response of OpenSSL', { skip: opensslOcspSkip }, () => {
    const { ocsp: [request] } = validationDataRequests(container, TRUST);
    assert.match(check(container, [opensslOcsp(request?.request as Buffer, ['rsa3072'])]).getError() ?? '', /is revoked since 2026-01-01/);
  });

  test('the signer revoked', () => {
    assert.match(check(container, [ocsp({ status: 'revoked', reason: 1 })]).getError() ?? '', new RegExp(`${SIGNER}.* is revoked since`));
  });

  // Each response is about the signer, but cannot tell its status, for the reason given.
  const unusable: [string, Partial<OcspOptions>, RegExp][] = [
    ['a status unknown', { status: 'unknown' }, /its responder does not know the certificate/],
    ['about another certificate', { cert: 'p256' }, /it is about another certificate/],
    ['a delegated responder without id-pkix-ocsp-nocheck', { signer: 'ocsp-checked' }, /has not the extension id-pkix-ocsp-nocheck/],
    ['a certificate of the issuer that is not a responder', { signer: 'p256' }, /has not the extended key usage OCSPSigning/],
    ['signed by another CA under the name of the issuer', { signer: 'root', responder: 'intermediate' }, /its signature is not valid/],
    ['signed by the CA of the time-stamping authority', { signer: 'tsa-root' }, /its responder is not issued by the issuer of the certificate/],
    ['an altered signature', { alterSignature: true }, /its signature is not valid/],
  ];
  for (const [name, options, reason] of unusable) {
    test(`a response ${name} does not tell the status`, () => {
      const [source] = ocspSources(readOcspResponse(ocsp(options)));
      assert.match(source?.covers(certificate('rsa3072'), certificate('intermediate')) ?? 'covers', reason);
      assert.match(check(container, [ocsp(options)]).getError() ?? '', /no CRL of its issuer, nor OCSP response/);
    });
  }

  for (const [name, options] of [['past its next update', { thisUpdate: secondsAgo(120), nextUpdate: secondsAgo(60) }], ['without next update', { nextUpdate: null }]] as const) {
    test(`a response ${name} does not tell the current status`, () => {
      assert.match(check(container, [ocsp(options)]).getError() ?? '', /No current revocation data/);
    });
  }

  const refused: [string, Buffer, RegExp][] = [
    ['an answer tryLater', makeOcspResponse({ cert: 'rsa3072', responseStatus: 3 }), /the responder answered tryLater/],
    ['bytes that are not a response', Buffer.from('not a response'), /DER: /],
  ];
  for (const [name, response, message] of refused) {
    test(`refused: ${name}`, () => {
      assert.throws(() => check(container, [response]), { message: new RegExp(`an OCSP response cannot be used. OCSP response: .*${message.source}`) });
    });
  }

  test('refused: a list that is not of bytes', () => {
    assert.throws(() => check(container, ['ocsp' as unknown as Buffer]), /invalid option 'ocspResponses'/);
  });
});

describe('level T: the status at the time of the time-stamp', () => {
  const container = timestamped();

  test('a response issued after the time-stamp: valid', () => {
    assert.equal(check(container, [ocsp()]).getError(), null);
  });

  test('a response issued before the time-stamp does not tell the status at that time', () => {
    assert.match(check(container, [ocsp({ thisUpdate: secondsAgo(30) })]).getError() ?? '', /issued after the time-stamp/);
  });

  test('the signer revoked after the time-stamp: valid', () => {
    assert.equal(check(container, [ocsp({ status: 'revoked', revocationTime: secondsAgo(10) })]).getError(), null);
  });
});

describe('level LT: the responses embedded', () => {
  const crls = [makeCrl({ issuer: 'root' }), makeCrl({ issuer: 'tsa-root' })];
  const container = addValidationData(timestamped(), { ...TRUST, crls, ocspResponses: [ocsp({ signer: 'ocsp' })] });
  const xml = readZip(container).find((e) => e.name === 'META-INF/signatures001.xml')?.content.toString('utf8') as string;

  test('valid by what the seal embeds alone', () => {
    const result = verifySeal(container, TRUST);
    assert.equal(result.getError(), null);
    assert.equal(result.getLevel(), 'LT');
  });

  test('the response of the signer in OCSPValues, the CRL of the root in CRLValues', () => {
    assert.match(xml, /<xades:CertificateValues[^>]*>.*<\/xades:CertificateValues><xades:RevocationValues[^>]*><xades:CRLValues><xades:EncapsulatedCRLValue>[^<]+<\/xades:EncapsulatedCRLValue><\/xades:CRLValues><xades:OCSPValues><xades:EncapsulatedOCSPValue>[^<]+<\/xades:EncapsulatedOCSPValue><\/xades:OCSPValues><\/xades:RevocationValues><\/xades:UnsignedSignatureProperties>/);
  });

  test('a CRL given besides an OCSP response that tells the status is not embedded', () => {
    const both = addValidationData(timestamped(), { ...TRUST, crls: [...crls, makeCrl({ issuer: 'intermediate', thisUpdate: secondsAgo(1) })], ocspResponses: [ocsp({ thisUpdate: secondsAgo(2) })] });
    const embedded = readZip(both).find((e) => e.name === 'META-INF/signatures001.xml')?.content.toString('utf8') as string;
    assert.equal((embedded.match(/<xades:EncapsulatedCRLValue>/g) ?? []).length, 3);
    assert.equal((embedded.match(/<xades:EncapsulatedOCSPValue>/g) ?? []).length, 0);
  });

  test('an OCSP response that is not one, embedded', () => {
    const result = verifySeal(editSignature(container, (x) => x.replace(/<xades:EncapsulatedOCSPValue>[^<]+</, '<xades:EncapsulatedOCSPValue>AAAA<')), TRUST);
    assert.match(result.getError() ?? '', /An OCSP response of the validation data of the seal cannot be used. OCSP response: /);
  });
});

function editSignature(container: Buffer, change: (xml: string) => string): Buffer {
  return writeZip(readZip(container).map((e) => ({
    name: e.name,
    content: e.name === 'META-INF/signatures001.xml' ? Buffer.from(change(e.content.toString('utf8'))) : e.content,
    stored: e.method === 0,
  })));
}

describe('validation by DSS', { skip: dssSkip }, () => {
  test('offline, level LT, the signer by an OCSP response of its CA: TOTAL_PASSED by the data of the seal only', async () => {
    const container = addValidationData(timestamped('offline', 'tsa-offline'), {
      ...TRUST,
      crls: [makeCrl({ issuer: 'root' }), makeCrl({ issuer: 'tsa-root' })],
      ocspResponses: [makeOcspResponse({ cert: 'offline', issuer: 'intermediate-offline' })],
    });
    const report = await validateWithDss(container);
    const signature = report.signatures[0];
    assert.equal(signature?.format, 'XAdES-BASELINE-LT');
    assert.equal(signature?.indication, 'TOTAL_PASSED');
    assert.deepEqual(signature?.errors, []);
    assert.deepEqual(report.revocationOrigins, ['INPUT_DOCUMENT', 'INPUT_DOCUMENT', 'INPUT_DOCUMENT']);
  });
});
