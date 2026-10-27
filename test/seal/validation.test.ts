/**
 * Level LT: the list of the CRLs a seal needs, their addition to a seal of
 * level T, and the verification of a seal by the data it embeds. The CRLs
 * come from test/helpers/crl.ts, the tokens from test/helpers/tsa.ts, not
 * from the code under test; DSS validates the seals of level LT.
 */

import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { before, describe, test } from 'node:test';

import { addSignatureTimestamp, timestampRequest } from '../../dist/seal/extend.js';
import { createSeal } from '../../dist/seal/seal.js';
import { addValidationData, validationDataRequests } from '../../dist/seal/validation.js';
import { verifySeal, type VerifyOptions } from '../../dist/seal/verify.js';
import { readZip, writeZip } from '../../dist/seal/zip.js';
import { currentCrls, extension, makeCrl, type CrlOptions } from '../helpers/crl.ts';
import { der } from '../helpers/der.ts';
import { dssSkip, publishTestCrls, validateWithDss } from '../helpers/dss.ts';
import { timestampResponse, type TsaOptions } from '../helpers/tsa.ts';

const CERTS = 'test/fixtures/seal/certs';
const ROOT = `${CERTS}/root.cert.pem`;
const TSA_ROOT = `${CERTS}/tsa-root.cert.pem`;
const SIGNATURE = 'META-INF/signatures001.xml';
const PKI = 'http://pki.ezxmlseal.test';
const TRUST = { caCertPath: ROOT, tsaCertPath: TSA_ROOT };
const secondsAgo = (seconds: number) => new Date(Date.now() - seconds * 1000);

function seal(key = 'rsa3072'): Buffer {
  const intermediate = key === 'offline' ? 'intermediate-offline' : 'intermediate';
  return createSeal([{ name: 'contrat.pdf', content: Buffer.from('%PDF-1.4\n') }], `${CERTS}/${key}.key.pem`, `${CERTS}/${key}.cert.pem`, 'signKeyPassword', { chain: [`${CERTS}/${intermediate}.cert.pem`] });
}

/**
 * A seal of the branch of the test PKI whose CRLs nobody serves
 * (offline.ezxmlseal.test): its signer, its intermediate CA and its
 * time-stamping authority. The CRLs of its chains, with the given dates.
 */
function offline(crlOptions: CrlOptions = {}): { sealT: Buffer; crls: Buffer[] } {
  const sealT = timestamped('offline', { name: 'tsa-offline' });
  const crls = (['intermediate-offline', 'root', 'tsa-root'] as const).map((issuer) => makeCrl({ ...crlOptions, issuer }));
  return { sealT, crls };
}

// The time-stamps are made a few seconds ago: the seal certificates are
// valid from their generation only, which may be just before the tests.
function timestamped(key = 'rsa3072', options: TsaOptions = {}): Buffer {
  const container = seal(key);
  return addSignatureTimestamp(container, timestampResponse(timestampRequest(container), { time: secondsAgo(20), ...options }), { tsaCertPath: TSA_ROOT });
}

function extended(container = timestamped(), crls: Buffer[] = currentCrls()): Buffer {
  return addValidationData(container, { ...TRUST, crls });
}

function check(container: Buffer, options: Partial<VerifyOptions> = {}) {
  return verifySeal(container, { ...TRUST, ...options });
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

const base64Of = (name: string) => new X509Certificate(readFileSync(`${CERTS}/${name}.cert.pem`)).raw.toString('base64');
const occurrences = (text: string, part: string) => text.split(part).length - 1;
const reason = (code: number) => extension('2.5.29.21', false, der(0x0a, Buffer.from([code])));

describe('the CRLs a seal needs', () => {
  test('level T: the signer, its intermediate CA, the time-stamping authority, from their CRL distribution points', () => {
    const { crls } = validationDataRequests(timestamped(), TRUST);
    assert.deepEqual(crls.map((request) => [request.certificate.getSubject().OU, request.issuer.getSubject().OU, request.urls]), [
      ['RSA 3072 Seal Dept', 'Seal Intermediate CA', [`${PKI}/intermediate.crl`]],
      ['Seal Intermediate CA', 'Seal Root CA', [`${PKI}/root.crl`]],
      ['Time-Stamping Unit', 'TSA Root CA', [`${PKI}/tsa-root.crl`]],
    ]);
  });

  test('level B: the chain of the signer only', () => {
    const { crls } = validationDataRequests(seal(), TRUST);
    assert.deepEqual(crls.map((request) => request.urls), [[`${PKI}/intermediate.crl`], [`${PKI}/root.crl`]]);
  });

  test('a seal that is not valid', () => {
    assert.throws(() => validationDataRequests(seal(), { caCertPath: TSA_ROOT, tsaCertPath: TSA_ROOT }), /Validation data: the seal is not valid. The signing certificate is not trusted/);
  });
});

describe('the addition of the validation data', () => {
  const original = timestamped();
  const container = extended(original);
  const xml = signatureXml(container);
  const compact = xml.replace(/\s/g, '');

  test('the seal becomes of level LT, valid with the data it embeds alone', () => {
    const result = check(container);
    assert.equal(result.getError(), null);
    assert.equal(result.getLevel(), 'LT');
    assert.equal(result.isRevocationChecked(), true);
    assert.deepEqual(result.getTimestampTime(), check(original, { crls: currentCrls() }).getTimestampTime());
  });

  test('the signed parts are left as they were', () => {
    const before = signatureXml(original);
    const end = before.indexOf('</xades:UnsignedSignatureProperties>');
    assert.equal(xml.slice(0, end), before.slice(0, end));
    assert.equal(xml.slice(xml.indexOf('</xades:UnsignedSignatureProperties>')), before.slice(end));
  });

  test('the validation data of the time-stamp right after it (EN 319 132-1, 5.5.1.2), then those of the signer', () => {
    assert.match(xml, /<\/xades:SignatureTimeStamp><xades141:TimeStampValidationData xmlns:xades141="http:\/\/uri.etsi.org\/01903\/v1.4.1#"><xades:CertificateValues[^>]*>.*<\/xades:CertificateValues><xades:RevocationValues[^>]*>.*<\/xades:RevocationValues><\/xades141:TimeStampValidationData><xades:CertificateValues[^>]*>.*<\/xades:CertificateValues><xades:RevocationValues[^>]*><xades:CRLValues>.*<\/xades:CRLValues><\/xades:RevocationValues><\/xades:UnsignedSignatureProperties>/);
  });

  test('each certificate once: the roots added, the intermediate CA left in KeyInfo, the authority in its token', () => {
    assert.equal(occurrences(compact, base64Of('root')), 1);
    assert.equal(occurrences(compact, base64Of('tsa-root')), 1);
    assert.equal(occurrences(compact, base64Of('intermediate')), 1);
    assert.equal(occurrences(compact, base64Of('rsa3072')), 1);
    assert.equal(occurrences(compact, base64Of('tsa')), 0);
  });

  test('a CRL for each certificate but the roots, once', () => {
    const embedded = [...xml.matchAll(/<xades:EncapsulatedCRLValue>([^<]+)</g)].map((match) => match[1]);
    assert.equal(embedded.length, 3);
    assert.equal(new Set(embedded).size, 3);
  });

  test('CRLs past their next update, issued after the time-stamp, still tell the status: the seal is verified later on', () => {
    const later: CrlOptions = { thisUpdate: secondsAgo(15), nextUpdate: secondsAgo(5) };
    const crls = [makeCrl(later), makeCrl({ ...later, issuer: 'root' }), makeCrl({ ...later, issuer: 'tsa-root' })];
    assert.equal(check(extended(timestamped(), crls)).getLevel(), 'LT');
  });

  const cases: [string, () => Buffer, RegExp][] = [
    ['a seal of level B', () => extended(seal()), /must be time-stamped first \(level T\)/],
    ['a seal of level LT', () => extended(container), /already has validation data/],
    ['no CRL of the time-stamping authority', () => extended(original, currentCrls().slice(0, 2)), /No revocation data for the certificate "[^"]*Time-Stamping Unit[^"]*": no CRL of its issuer/],
    ['a CRL issued before the time-stamp', () => extended(original, [makeCrl({ thisUpdate: secondsAgo(30) }), ...currentCrls().slice(1)]), /RSA 3072 Seal Dept[^"]*" issued after the time-stamp/],
    ['the signer revoked before the time-stamp', () => extended(original, currentCrls([{ cert: 'rsa3072', date: secondsAgo(25) }])), /the seal is not valid. The certificate .* is revoked since .*, before the time-stamp/],
    ['no option crls', () => addValidationData(original, TRUST as never), /'crls' is required/],
    ['no option tsaCertPath', () => addValidationData(original, { caCertPath: ROOT, crls: currentCrls() } as never), /'tsaCertPath' is required/],
  ];
  for (const [name, run, message] of cases) {
    test(`refused: ${name}`, () => {
      assert.throws(run, { message });
    });
  }
});

describe('the verification of a seal of level LT', () => {
  const container = extended();

  test('without revocation: level LT, revocation not checked', () => {
    const result = check(container, { revocation: false });
    assert.equal(result.getLevel(), 'LT');
    assert.equal(result.isRevocationChecked(), false);
  });

  test('newer CRLs of the caller: the signer revoked after the time-stamp, still valid', () => {
    assert.equal(check(container, { crls: currentCrls([{ cert: 'rsa3072', date: secondsAgo(1) }]) }).getError(), null);
  });

  test('newer CRLs of the caller: a revocation they tell before the time-stamp', () => {
    assert.match(check(container, { crls: [makeCrl({ revoked: [{ cert: 'rsa3072', date: secondsAgo(25) }] })] }).getError() ?? '', /is revoked since .*, before the time-stamp/);
  });

  const authority = (date: Date, extensions?: Buffer[]) => check(container, { crls: [makeCrl({ issuer: 'tsa-root', revoked: [{ cert: 'tsa', date, ...(extensions === undefined ? {} : { extensions }) }] })] }).getError();
  test('the time-stamping authority revoked after the time-stamp, for cessation of operation (RFC 3161, 4): still valid', () => {
    assert.equal(authority(secondsAgo(1), [reason(5)]), null);
  });

  test('the time-stamping authority revoked after the time-stamp, for a key compromise: its tokens are no longer trusted', () => {
    assert.match(authority(secondsAgo(1), [reason(1)]) ?? '', /Time-Stamping Unit.* is revoked since .*, after the time-stamp but for a compromise of a key/);
  });

  test('the time-stamping authority revoked after the time-stamp, without a reason: its tokens are no longer trusted', () => {
    assert.match(authority(secondsAgo(1)) ?? '', /after the time-stamp but without a reason/);
  });

  const attacks: [string, (xml: string) => string, RegExp][] = [
    ['the CRLs of the signer removed', (x) => x.replace(/<xades:RevocationValues[^>]*><xades:CRLValues>(?:(?!<\/xades:RevocationValues>).)*<\/xades:RevocationValues><\/xades:UnsignedSignatureProperties>/, '</xades:UnsignedSignatureProperties>'), /validation data of the seal do not suffice. No revocation data for the certificate "[^"]*RSA 3072 Seal Dept/],
    ['the validation data of the time-stamp removed', (x) => x.replace(/<xades141:TimeStampValidationData.*<\/xades141:TimeStampValidationData>/, ''), /do not suffice. No revocation data for the certificate "[^"]*Time-Stamping Unit/],
    ['a CRL that is not one', (x) => x.replace(/<xades:EncapsulatedCRLValue>[^<]+</, '<xades:EncapsulatedCRLValue>AAAA<'), /A CRL of the validation data of the seal cannot be used. CRL: /],
    ['a certificate that is not one', (x) => x.replace(/<xades:EncapsulatedX509Certificate>[^<]+</, '<xades:EncapsulatedX509Certificate>AAAA<'), /A certificate of the validation data of the seal cannot be read/],
    ['OCSP responses', (x) => x.replace('</xades:CRLValues>', '</xades:CRLValues><xades:OCSPValues><xades:EncapsulatedOCSPValue>AAAA</xades:EncapsulatedOCSPValue></xades:OCSPValues>'), /OCSP responses, which this library does not check yet/],
    ['revocation values without CRLs', (x) => x.replace(/(<xades:RevocationValues[^>]*>)<xades:CRLValues>(?:(?!<\/xades:RevocationValues>).)*(<\/xades:RevocationValues><\/xades:UnsignedSignatureProperties>)/, '$1$2'), /Missing xades:CRLValues in xades:RevocationValues/],
    ['the validation data of the time-stamp after those of the signer', (x) => {
      const data = /<xades141:TimeStampValidationData.*<\/xades141:TimeStampValidationData>/.exec(x)?.[0] as string;
      return x.replace(data, '').replace('</xades:UnsignedSignatureProperties>', `${data}</xades:UnsignedSignatureProperties>`);
    }, /Unexpected or misplaced element xades141:TimeStampValidationData/],
  ];
  for (const [name, change, message] of attacks) {
    test(`not valid: ${name}`, () => {
      assert.match(check(editSignature(container, change)).getError() ?? 'valid', message);
    });
  }

  test('not valid: the validation data of a seal time-stamped earlier, moved to a later one', () => {
    const crls = (['intermediate', 'root', 'tsa-root'] as const).map((issuer) => makeCrl({ issuer, thisUpdate: secondsAgo(18) }));
    const early = signatureXml(extended(timestamped('rsa3072', { time: secondsAgo(20) }), crls));
    const data = (/<xades141:TimeStampValidationData.*<\/xades:RevocationValues>/.exec(early) as RegExpExecArray)[0];
    const late = editSignature(timestamped('rsa3072', { time: secondsAgo(10) }), (x) => x.replace('</xades:UnsignedSignatureProperties>', `${data}</xades:UnsignedSignatureProperties>`));
    assert.match(check(late).getError() ?? 'valid', /do not suffice. No revocation data for the certificate .* issued after the time-stamp/);
  });
});

describe('a seal whose CRLs nobody serves', () => {
  test('lists the distribution points of offline.ezxmlseal.test', () => {
    assert.deepEqual(validationDataRequests(offline().sealT, TRUST).crls.map((request) => request.urls), [
      ['http://offline.ezxmlseal.test/intermediate-offline.crl'], ['http://offline.ezxmlseal.test/root.crl'], ['http://offline.ezxmlseal.test/tsa-root.crl'],
    ]);
  });

  test('level LT, its CRLs past their next update: valid by what it embeds', () => {
    const { sealT, crls } = offline({ thisUpdate: secondsAgo(15), nextUpdate: secondsAgo(5) });
    assert.equal(check(extended(sealT, crls)).getLevel(), 'LT');
  });
});

describe('validation by DSS', { skip: dssSkip }, () => {
  before(publishTestCrls);

  for (const key of ['rsa3072', 'p256']) {
    test(`${key}, level LT: XAdES-BASELINE-LT, TOTAL_PASSED, the CRLs of the seal read`, async () => {
      const report = await validateWithDss(extended(timestamped(key)));
      const signature = report.signatures[0];
      assert.equal(report.revocationOrigins.filter((origin) => origin === 'INPUT_DOCUMENT').length, 3);
      assert.equal(signature?.format, 'XAdES-BASELINE-LT');
      assert.equal(signature?.indication, 'TOTAL_PASSED');
      assert.deepEqual(signature?.errors, []);
    });
  }

  // DSS cannot reach offline.ezxmlseal.test: what it knows of the status of
  // the certificates comes from the seal, or nowhere.
  test('offline, level T: INDETERMINATE, no revocation data', async () => {
    const report = await validateWithDss(offline().sealT);
    const signature = report.signatures[0];
    assert.equal(signature?.format, 'XAdES-BASELINE-T');
    assert.equal(signature?.indication, 'INDETERMINATE');
    assert.ok(signature?.errors.includes('No revocation data found for the certificate!'), JSON.stringify(signature?.errors));
    assert.deepEqual(report.revocationOrigins, []);
  });

  for (const [name, crlOptions] of [['current', {}], ['past their next update', { thisUpdate: secondsAgo(15), nextUpdate: secondsAgo(5) }]] as const) {
    test(`offline, level LT, its CRLs ${name}: TOTAL_PASSED, by the CRLs of the seal only`, async () => {
      const { sealT, crls } = offline(crlOptions);
      const report = await validateWithDss(extended(sealT, crls));
      const signature = report.signatures[0];
      assert.equal(signature?.format, 'XAdES-BASELINE-LT');
      assert.equal(signature?.indication, 'TOTAL_PASSED');
      assert.deepEqual(signature?.errors, []);
      assert.deepEqual(report.revocationOrigins, ['INPUT_DOCUMENT', 'INPUT_DOCUMENT', 'INPUT_DOCUMENT']);
    });
  }
});
