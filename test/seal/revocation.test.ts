/**
 * Revocation by CRLs: the status of every certificate of the chains of the
 * signer and of the time-stamping authority, at the current date for a seal
 * of level B, at the time of the time-stamp for a seal of level T. The CRLs
 * come from test/helpers/crl.ts or from OpenSSL, not from the code under
 * test; DSS, which fetches them at pki.ezxmlseal.test, agrees.
 */

import assert from 'node:assert/strict';
import { before, describe, test } from 'node:test';

import { addSignatureTimestamp, timestampRequest } from '../../dist/seal/extend.js';
import { createSeal } from '../../dist/seal/seal.js';
import { verifySeal, type VerifyOptions } from '../../dist/seal/verify.js';
import { currentCrls, extension, issuingDistributionPoint, makeCrl, opensslCaSkip, opensslCrl } from '../helpers/crl.ts';
import { REVOKED, dssSkip, publishTestCrls, validateWithDss } from '../helpers/dss.ts';
import { timestampResponse } from '../helpers/tsa.ts';

const CERTS = 'test/fixtures/seal/certs';
const ROOT = `${CERTS}/root.cert.pem`;
const TSA_ROOT = `${CERTS}/tsa-root.cert.pem`;
const MINUTE = 60_000;
const ago = (minutes: number) => new Date(Date.now() - minutes * MINUTE);
const secondsAgo = (seconds: number) => new Date(Date.now() - seconds * 1000);

function seal(key = 'rsa3072'): Buffer {
  return createSeal([{ name: 'contrat.pdf', content: Buffer.from('%PDF-1.4\n') }], `${CERTS}/${key}.key.pem`, `${CERTS}/${key}.cert.pem`, 'signKeyPassword', { chain: [`${CERTS}/intermediate.cert.pem`] });
}

/** A seal time-stamped at the given time. */
function timestamped(time: Date, key = 'rsa3072'): Buffer {
  const container = seal(key);
  return addSignatureTimestamp(container, timestampResponse(timestampRequest(container), { time }), { tsaCertPath: TSA_ROOT });
}

function check(container: Buffer, crls: Buffer[], options: Partial<VerifyOptions> = {}) {
  return verifySeal(container, { caCertPath: ROOT, tsaCertPath: TSA_ROOT, crls, ...options });
}

function error(container: Buffer, crls: Buffer[], options: Partial<VerifyOptions> = {}): string | null {
  return check(container, crls, options).getError();
}

const SIGNER = '"/C=DK/O=Lothbrok Ltd/OU=RSA 3072 Seal Dept/CN=Lothbrok Seal Test"';
const INTERMEDIATE = '"/C=DK/O=Lothbrok Ltd/OU=Seal Intermediate CA/CN=Lothbrok Seal Test"';
const TSA = '"/C=DK/O=Lothbrok Ltd/OU=Time-Stamping Unit/CN=Lothbrok Seal Test"';

describe('level B: the status at the current date', () => {
  const container = seal();
  const root = makeCrl({ issuer: 'root' });

  test('current CRLs, no certificate revoked: valid, revocation checked', () => {
    const result = check(container, currentCrls());
    assert.equal(result.getError(), null);
    assert.equal(result.isRevocationChecked(), true);
  });

  test('CRLs of OpenSSL, in PEM', { skip: opensslCaSkip }, () => {
    assert.equal(error(container, [opensslCrl('intermediate'), opensslCrl('root')]), null);
  });

  test('the signer revoked', () => {
    assert.match(error(container, [makeCrl({ revoked: [{ cert: 'rsa3072', date: ago(5) }] }), root]) ?? '', new RegExp(`The certificate ${SIGNER} is revoked since`));
  });

  test('the signer revoked, in a CRL of OpenSSL', { skip: opensslCaSkip }, () => {
    assert.match(error(container, [opensslCrl('intermediate', ['rsa3072']), root]) ?? '', /is revoked since 2026-01-01/);
  });

  test('another certificate revoked', () => {
    assert.equal(error(container, [makeCrl({ revoked: [{ cert: 'p256', date: ago(5) }] }), root]), null);
  });

  test('the intermediate CA revoked by the root', () => {
    assert.match(error(container, [makeCrl(), makeCrl({ issuer: 'root', revoked: [{ cert: 'intermediate', date: ago(5) }] })]) ?? '', new RegExp(`The certificate ${INTERMEDIATE} is revoked`));
  });

  test('no CRL for the intermediate CA', () => {
    assert.match(error(container, [makeCrl()]) ?? '', new RegExp(`No revocation data for the certificate ${INTERMEDIATE}: no CRL of its issuer`));
  });

  test('no CRL at all', () => {
    assert.match(error(container, []) ?? '', new RegExp(`No revocation data for the certificate ${SIGNER}`));
  });

  const unusable: [string, Buffer, RegExp][] = [
    ['past its next update', makeCrl({ thisUpdate: ago(120), nextUpdate: ago(60) }), /No current revocation data/],
    ['without next update', makeCrl({ nextUpdate: null }), /No current revocation data/],
    ['issued in the future', makeCrl({ thisUpdate: new Date(Date.now() + 10 * MINUTE) }), /No current revocation data/],
    ['signed by another CA under the name of the issuer', makeCrl({ signer: 'root' }), /no CRL of its issuer/],
    ['with an altered signature', makeCrl({ alterSignature: true }), /no CRL of its issuer/],
    ['of another CA', makeCrl({ issuer: 'tsa-root' }), /no CRL of its issuer/],
    ['restricted to CA certificates', makeCrl({ extensions: [issuingDistributionPoint({ onlyCA: true })] }), /no CRL of its issuer/],
  ];
  for (const [name, crl, message] of unusable) {
    test(`a CRL ${name} does not tell the status`, () => {
      assert.match(error(container, [crl, root]) ?? '', message);
    });
  }

  test('a CRL restricted to end-entity certificates tells the status of the signer', () => {
    assert.equal(error(container, [makeCrl({ extensions: [issuingDistributionPoint({ onlyUser: true })] }), root]), null);
  });

  test('without revocation: valid, revocation not checked', () => {
    const result = check(container, [], { revocation: false });
    assert.equal(result.getError(), null);
    assert.equal(result.isRevocationChecked(), false);
  });
});

describe('CRLs this library does not use are refused', () => {
  const cases: [string, Buffer, RegExp][] = [
    ['a delta CRL', makeCrl({ extensions: [extension('2.5.29.27', true, Buffer.from([0x02, 0x01, 0x01]))] }), /delta CRLs are not supported/],
    ['an unknown critical extension', makeCrl({ extensions: [extension('1.3.6.1.4.1.55555.9', true, Buffer.from([0x05, 0x00]))] }), /unsupported critical extension 1.3.6.1.4.1.55555.9/],
    ['a CRL restricted to some reasons', makeCrl({ extensions: [issuingDistributionPoint({ someReasons: true })] }), /restricted to some reasons/],
    ['an indirect CRL', makeCrl({ extensions: [issuingDistributionPoint({ indirect: true })] }), /indirect CRLs/],
    ['an entry of another issuer (indirect CRL)', makeCrl({ revoked: [{ cert: 'p256', date: ago(1), extensions: [extension('2.5.29.29', true, Buffer.from([0x30, 0x00]))] }] }), /indirect CRLs are not supported/],
    ['bytes that are not a CRL', Buffer.from('not a CRL'), /DER: /],
  ];
  for (const [name, crl, message] of cases) {
    test(name, () => {
      assert.throws(() => check(seal(), [crl]), { message: new RegExp(`a CRL cannot be used. CRL: .*${message.source}`) });
    });
  }

  test('a list that is not of bytes', () => {
    assert.throws(() => check(seal(), ['crl' as unknown as Buffer]), /invalid option 'crls'/);
  });
});

// The time-stamps are made a few seconds ago: the seal certificates are
// valid from their generation only, which may be just before the tests.
describe('level T: the status at the time of the time-stamp', () => {
  const time = secondsAgo(20);
  const container = timestamped(time);

  test('CRLs issued after the time-stamp: valid', () => {
    assert.equal(error(container, currentCrls()), null);
  });

  test('a CRL issued before the time-stamp does not tell the status at that time', () => {
    assert.match(error(container, [makeCrl({ thisUpdate: secondsAgo(30) }), makeCrl({ issuer: 'root' }), makeCrl({ issuer: 'tsa-root' })]) ?? '', /issued after the time-stamp/);
  });

  test('the signer revoked after the time-stamp: valid, the time-stamp proves the seal existed before', () => {
    assert.equal(error(container, currentCrls([{ cert: 'rsa3072', date: secondsAgo(10) }])), null);
  });

  test('the signer revoked before the time-stamp', () => {
    assert.match(error(container, currentCrls([{ cert: 'rsa3072', date: secondsAgo(25) }])) ?? '', new RegExp(`The certificate ${SIGNER} is revoked since .*, before the time-stamp`));
  });

  test('a CRL past its next update still tells the status at the time of the time-stamp', () => {
    assert.equal(error(container, [makeCrl({ thisUpdate: secondsAgo(15), nextUpdate: secondsAgo(10) }), makeCrl({ issuer: 'root' }), makeCrl({ issuer: 'tsa-root' })]), null);
  });

  test('the time-stamping authority revoked', () => {
    assert.match(error(container, [makeCrl(), makeCrl({ issuer: 'root' }), makeCrl({ issuer: 'tsa-root', revoked: [{ cert: 'tsa', date: secondsAgo(1) }] })]) ?? '', new RegExp(`The certificate ${TSA} is revoked`));
  });

  test('no CRL for the time-stamping authority', () => {
    assert.match(error(container, [makeCrl(), makeCrl({ issuer: 'root' })]) ?? '', new RegExp(`No revocation data for the certificate ${TSA}`));
  });
});

describe('validation by DSS, which fetches the CRLs', { skip: dssSkip }, () => {
  before(publishTestCrls);
  const published = () => currentCrls([{ cert: REVOKED, date: ago(60) }]);

  test('level B, nothing revoked: TOTAL_PASSED, and valid here', async () => {
    const container = seal('p256');
    const signature = (await validateWithDss(container)).signatures[0];
    assert.equal(signature?.indication, 'TOTAL_PASSED');
    assert.deepEqual(signature?.errors, []);
    assert.equal(error(container, published()), null);
  });

  test('level T, nothing revoked: TOTAL_PASSED, and valid here', async () => {
    const container = timestamped(secondsAgo(20), 'p256');
    const signature = (await validateWithDss(container)).signatures[0];
    assert.equal(signature?.format, 'XAdES-BASELINE-T');
    assert.equal(signature?.indication, 'TOTAL_PASSED');
    assert.equal(error(container, published()), null);
  });

  test('level B, the signer revoked: not passed by DSS, invalid here', async () => {
    const container = seal(REVOKED);
    const signature = (await validateWithDss(container)).signatures[0];
    assert.notEqual(signature?.indication, 'TOTAL_PASSED');
    assert.ok(signature?.errors.includes('The certificate is revoked!'), JSON.stringify(signature?.errors));
    assert.match(error(container, published()) ?? '', /Revoked Seal Dept.* is revoked since/);
  });
});
