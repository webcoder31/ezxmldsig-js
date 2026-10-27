/**
 * Level T: the time-stamp request of a seal, the addition of the token of a
 * response, and the verification of a time-stamped seal. The tokens come
 * from the test authority of test/helpers/tsa.ts or from OpenSSL, not from
 * the code under test; DSS validates the time-stamped seals.
 */

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { describe, test } from 'node:test';

import { DOMParser } from '@xmldom/xmldom';

import { canonicalize } from '../../dist/c14n.js';
import * as alg from '../../dist/seal/algorithms.js';
import { addSignatureTimestamp, timestampRequest } from '../../dist/seal/extend.js';
import { createSeal, type SealOptions } from '../../dist/seal/seal.js';
import { verifySeal, type VerifyOptions } from '../../dist/seal/verify.js';
import { readZip, writeZip } from '../../dist/seal/zip.js';
import { dssSkip, validateWithDss } from '../helpers/dss.ts';
import { opensslSkip, opensslTimestamp, readRequest, timestampResponse, type TsaOptions } from '../helpers/tsa.ts';

const CERTS = 'test/fixtures/seal/certs';
const ROOT = `${CERTS}/root.cert.pem`;
const TSA_ROOT = `${CERTS}/tsa-root.cert.pem`;
const SIGNATURE = 'META-INF/signatures001.xml';
const FILES = [{ name: 'contrat.pdf', content: Buffer.from('%PDF-1.4\n') }];

function seal(key = 'rsa3072', options: SealOptions = {}): Buffer {
  return createSeal(FILES, `${CERTS}/${key}.key.pem`, `${CERTS}/${key}.cert.pem`, 'signKeyPassword', { chain: [`${CERTS}/intermediate.cert.pem`], ...options });
}

function timestamped(container: Buffer, options: TsaOptions = {}): Buffer {
  return addSignatureTimestamp(container, timestampResponse(timestampRequest(container), options), { tsaCertPath: TSA_ROOT });
}

function check(container: Buffer, options: Partial<VerifyOptions> = {}) {
  return verifySeal(container, { caCertPath: ROOT, tsaCertPath: TSA_ROOT, revocation: false, ...options });
}

function signatureXml(container: Buffer): string {
  return readZip(container).find((e) => e.name === SIGNATURE)?.content.toString('utf8') as string;
}

function editSignature(container: Buffer, change: (xml: string) => string): Buffer {
  return writeZip(readZip(container).map((e) => ({
    name: e.name,
    content: e.name === SIGNATURE ? Buffer.from(change(e.content.toString('utf8'))) : e.content,
    stored: e.method === 0,
  })));
}

describe('the request', () => {
  test('is over ds:SignatureValue, canonicalized by exclusive canonicalization (EN 319 132-1, 5.3)', () => {
    const container = seal();
    const doc = new DOMParser().parseFromString(signatureXml(container), 'application/xml');
    const value = doc.getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'SignatureValue')[0];
    const expected = createHash('sha256').update(canonicalize(value as never, alg.EXC_C14N, null, 'test')).digest();
    assert.deepEqual(readRequest(timestampRequest(container)), { hash: 'sha256', imprint: expected });
  });

  test('with another digest on request', () => {
    assert.equal(readRequest(timestampRequest(seal(), alg.SHA512)).hash, 'sha512');
    assert.throws(() => timestampRequest(seal(), 'http://www.w3.org/2000/09/xmldsig#sha1'), /unsupported digest/);
  });
});

describe('a time-stamped seal', () => {
  const time = new Date('2027-06-01T08:00:00Z');
  const container = timestamped(seal('p256'), { time });

  test('holds the token in UnsignedSignatureProperties/SignatureTimeStamp, after the signed properties', () => {
    const xml = signatureXml(container);
    assert.match(xml, /<\/xades:SignedProperties><xades:UnsignedProperties xmlns:xades="http:\/\/uri.etsi.org\/01903\/v1.3.2#"><xades:UnsignedSignatureProperties><xades:SignatureTimeStamp Id="[^"]+-TS"><ds:CanonicalizationMethod xmlns:ds="http:\/\/www.w3.org\/2000\/09\/xmldsig#" Algorithm="http:\/\/www.w3.org\/2001\/10\/xml-exc-c14n#"\/><xades:EncapsulatedTimeStamp>[A-Za-z0-9+/=]+<\/xades:EncapsulatedTimeStamp><\/xades:SignatureTimeStamp><\/xades:UnsignedSignatureProperties><\/xades:UnsignedProperties><\/xades:QualifyingProperties>/);
  });

  test('keeps the signed part of the signature file byte for byte', () => {
    const original = seal('p256');
    const after = signatureXml(timestamped(original));
    assert.equal(after.replace(/<xades:UnsignedProperties.*<\/xades:UnsignedProperties>/, ''), signatureXml(original));
  });

  test('is a valid seal of level T, at the time of its time-stamp', () => {
    const result = check(container);
    assert.equal(result.getError(), null);
    assert.equal(result.getLevel(), 'T');
    assert.deepEqual(result.getTimestampTime(), time);
  });

  test('with a token of OpenSSL', { skip: opensslSkip }, () => {
    const original = seal('rsa3072');
    const result = check(addSignatureTimestamp(original, opensslTimestamp(timestampRequest(original)), { tsaCertPath: TSA_ROOT }));
    assert.equal(result.getError(), null);
    assert.equal(result.getLevel(), 'T');
  });

  test('with an ESS signingCertificate of version 1, and the chain of the authority in the token', () => {
    assert.equal(check(timestamped(seal(), { ess: 1, certificates: 'chain' })).getError(), null);
  });

  test('needs the trust in its time-stamping authority', () => {
    assert.match(verifySeal(container, { caCertPath: ROOT, revocation: false }).getError() ?? '', /'tsaCertPath' is needed/);
    assert.match(check(container, { tsaCertPath: ROOT }).getError() ?? '', /time-stamping authority is not trusted/);
  });

  test('checks the signing certificate at the time of the time-stamp', () => {
    // The seal certificates are valid for ten years from their generation.
    assert.match(check(timestamped(seal(), { time: new Date('2050-01-01T00:00:00Z') })).getError() ?? '', /not trusted.*at the time of the time-stamp/);
    assert.match(check(timestamped(seal(), { time: new Date('2020-01-01T00:00:00Z') })).getError() ?? '', /not trusted.*at the time of the time-stamp/);
  });
});

describe('addSignatureTimestamp() refuses', () => {
  const container = seal();
  const request = timestampRequest(container);
  const cases: [string, () => unknown, RegExp][] = [
    ['a refusal of the authority', () => addSignatureTimestamp(container, timestampResponse(request, { status: 2 }), { tsaCertPath: TSA_ROOT }), /answered rejection: request refused/],
    ['a token over another seal', () => addSignatureTimestamp(container, timestampResponse(timestampRequest(seal())), { tsaCertPath: TSA_ROOT }), /not over the signature of this seal/],
    ['an authority that is not trusted', () => addSignatureTimestamp(container, timestampResponse(request), { tsaCertPath: ROOT }), /authority is not trusted/],
    ['a certificate without the extended key usage timeStamping', () => addSignatureTimestamp(container, timestampResponse(request, { name: 'tsa-no-eku' }), { tsaCertPath: TSA_ROOT }), /extended key usage timeStamping/],
    ['a TSTInfo altered after signing', () => addSignatureTimestamp(container, timestampResponse(request, { alterTstInfo: true }), { tsaCertPath: TSA_ROOT }), /TSTInfo has been altered/],
    ['an altered signature', () => addSignatureTimestamp(container, timestampResponse(request, { alterSignature: true }), { tsaCertPath: TSA_ROOT }), /signature of the token is not valid/],
    ['a token without ESS signingCertificate', () => addSignatureTimestamp(container, timestampResponse(request, { ess: 'none' }), { tsaCertPath: TSA_ROOT }), /signingCertificate \(ESS\) is missing/],
    ['a token without the certificate of the authority', () => addSignatureTimestamp(container, timestampResponse(request, { certificates: 'none' }), { tsaCertPath: TSA_ROOT }), /certificate of the authority is not in the token/],
    ['a SHA-1 imprint', () => addSignatureTimestamp(container, timestampResponse(request, { hash: 'sha1', imprint: Buffer.alloc(20) }), { tsaCertPath: TSA_ROOT }), /unsupported digest algorithm 1.3.14.3.2.26/],
    ['a response that is not DER', () => addSignatureTimestamp(container, Buffer.from('not a response'), { tsaCertPath: TSA_ROOT }), /DER|malformed/],
    ['a seal already time-stamped', () => timestamped(timestamped(container)), /already has unsigned properties/],
    ['no tsaCertPath', () => addSignatureTimestamp(container, timestampResponse(request), {} as never), /'tsaCertPath' is required/],
  ];
  for (const [name, run, message] of cases) {
    test(name, () => {
      assert.throws(run, { message });
    });
  }
});

describe('attacks on a time-stamped seal', () => {
  const valid = timestamped(seal());
  const other = timestamped(seal());
  const token = (container: Buffer) => /<xades:EncapsulatedTimeStamp>([^<]+)</.exec(signatureXml(container))?.[1] as string;
  const cases: [string, (xml: string) => string, RegExp][] = [
    ['the token of another seal', (x) => x.replace(token(valid), token(other)), /not over the signature value of this seal/],
    ['the signature value changed', (x) => x.replace(/<ds:SignatureValue([^>]*)>(.)/, (_m, a, c) => `<ds:SignatureValue${a}>${c === 'A' ? 'B' : 'A'}`), /signature value is not valid/],
    ['a corrupted token', (x) => x.replace(token(valid), token(valid).slice(0, 200) + 'AAAA' + token(valid).slice(204)), /signature time-stamp is not valid/],
    ['no canonicalization method', (x) => x.replace(/<ds:CanonicalizationMethod xmlns:ds="[^"]+" Algorithm="[^"]+"\/><xades:Encapsulated/, '<xades:Encapsulated'), /Missing ds:CanonicalizationMethod in xades:SignatureTimeStamp/],
    ['another canonicalization than the one time-stamped', (x) => x.replace(`xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Algorithm="${alg.EXC_C14N}"/><xades:Encapsulated`, 'xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/><xades:Encapsulated'), /not over the signature value/],
    ['an XML encoding of the token', (x) => x.replace('<xades:EncapsulatedTimeStamp>', '<xades:EncapsulatedTimeStamp Encoding="http://uri.etsi.org/01903/v1.2.2#XER">'), /Unsupported encoding/],
    ['two time-stamps', (x) => x.replace(/(<xades:SignatureTimeStamp.*<\/xades:SignatureTimeStamp>)/, (t) => t + t.replace(/ Id="[^"]+"/, '')), /Too many xades:SignatureTimeStamp/],
    ['an unknown unsigned property', (x) => x.replace('</xades:UnsignedSignatureProperties>', '<xades:CertificateValues/></xades:UnsignedSignatureProperties>'), /Unexpected or misplaced element xades:CertificateValues/],
  ];
  for (const [name, change, message] of cases) {
    test(name, () => {
      assert.match(check(editSignature(valid, change)).getError() ?? 'valid', message);
    });
  }
});

describe('validation by DSS', { skip: dssSkip }, () => {
  for (const key of ['rsa3072', 'p256']) {
    test(`${key}, level T`, async () => {
      const report = await validateWithDss(timestamped(seal(key)));
      const signature = report.signatures[0];
      assert.equal(signature?.format, 'XAdES-BASELINE-T');
      assert.equal(signature?.signatureIntact, true);
      assert.ok(signature?.references.every((r) => r.found && r.intact));
      assert.ok(signature?.trusted.includes('CN=Lothbrok Seal Test,OU=TSA Root CA,O=Lothbrok Ltd,C=DK'));
      // Until the test PKI answers at pki.ezxmlseal.test, the only errors are those of the missing revocation data.
      assert.deepEqual(signature?.errors.filter((e) => !/revocation|not conclusive/.test(e)), []);
    });
  }

  test('with a token of OpenSSL', { skip: opensslSkip }, async () => {
    const original = seal('rsa3072');
    const report = await validateWithDss(addSignatureTimestamp(original, opensslTimestamp(timestampRequest(original)), { tsaCertPath: TSA_ROOT }));
    assert.equal(report.signatures[0]?.format, 'XAdES-BASELINE-T');
  });
});
