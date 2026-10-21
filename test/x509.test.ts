/**
 * X509Cert: what it reads from a certificate, and the trust in a
 * certificate (the cases of X509CertTest and TrustAnchorTest of the PHP
 * library that concern the certificate itself; those that need a token come
 * with the analysis).
 *
 * Each case of trust has its expected verdict, and every value this library
 * reads or decides is compared with what the class X509Cert of the PHP
 * library (that is OpenSSL) reads or decides, through bin/php-ezxmldsig.
 */

import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { describe, test } from 'node:test';

import { X509Cert } from '../dist/x509.js';
import { phpSkip, runPhp } from './helpers/php.ts';

const CERTS = 'test/fixtures/certs';
const DEMO = 'test/fixtures/demo-certs';
const TRUST = 'test/fixtures/trust';

/** The trusted intermediate and root of test/fixtures/certs/. */
const ANCHOR = [`${CERTS}/intermediate.cert.pem`, `${CERTS}/root.cert.pem`];

/** The same anchor, in one file. */
const BUNDLE = 'test/.cache/anchor-bundle.pem';
mkdirSync('test/.cache', { recursive: true });
writeFileSync(BUNDLE, readFileSync(ANCHOR[0] as string, 'utf8') + readFileSync(ANCHOR[1] as string, 'utf8'));

function load(path: string): X509Cert {
  return new X509Cert(readFileSync(path, 'utf8'));
}

/** [certificate, CA certificates, expected verdict, why]. */
const TRUST_CASES: Array<[string, string[], boolean, string]> = [
  [`${CERTS}/sign.cert.pem`, ANCHOR, true, 'issued by the trusted intermediate'],
  [`${CERTS}/crypt.cert.pem`, ANCHOR, true, 'issued by the trusted intermediate'],
  [`${CERTS}/sign.cert.pem`, [BUNDLE], true, 'the anchor in a single file'],
  [`${CERTS}/sign.cert.pem`, [`${CERTS}/intermediate.cert.pem`], false, 'an intermediate alone is not a trust anchor'],
  [`${CERTS}/sign.cert.pem`, [`${CERTS}/root.cert.pem`], false, 'the root alone does not trust a certificate of its intermediate'],
  [`${CERTS}/attacker.cert.pem`, ANCHOR, false, 'a certificate that copies the names of a legitimate one'],
  [`${CERTS}/intermediate.cert.pem`, [`${CERTS}/root.cert.pem`], true, 'the intermediate, issued by the root'],
  [`${CERTS}/root.cert.pem`, [`${CERTS}/root.cert.pem`], true, 'the trusted root itself'],
  [`${TRUST}/issued.cert.pem`, ANCHOR, true, 'issued by the trusted intermediate'],
  [`${TRUST}/expired.cert.pem`, ANCHOR, false, 'expired'],
  [`${TRUST}/not-yet-valid.cert.pem`, ANCHOR, false, 'not valid yet'],
  [`${TRUST}/nonrepudiation.cert.pem`, ANCHOR, true, 'key usage nonRepudiation only'],
  [`${TRUST}/no-keyusage.cert.pem`, ANCHOR, true, 'no key usage'],
  [`${TRUST}/critical-unknown.cert.pem`, ANCHOR, false, 'an unknown critical extension'],
  [`${TRUST}/noncritical-unknown.cert.pem`, ANCHOR, true, 'an unknown extension that is not critical'],
  [`${TRUST}/by-root.cert.pem`, ANCHOR, true, 'issued by the trusted root directly'],
  [`${TRUST}/by-root.cert.pem`, [`${CERTS}/root.cert.pem`], true, 'issued by the trusted root directly'],
  [`${TRUST}/rogue.cert.pem`, [`${CERTS}/sign.cert.pem`, ...ANCHOR], false, 'issued by a certificate that is not a CA'],
  [`${TRUST}/other-signer.cert.pem`, ANCHOR, false, 'issued by another intermediate of the same root'],
  [`${TRUST}/other-signer.cert.pem`, [`${TRUST}/other-intermediate.cert.pem`, `${CERTS}/root.cert.pem`], true, 'the other intermediate trusted'],
  [`${TRUST}/no-certsign-signer.cert.pem`, [`${TRUST}/no-certsign-intermediate.cert.pem`, `${CERTS}/root.cert.pem`], false, 'an intermediate whose key usage does not allow keyCertSign'],
  [`${TRUST}/no-bc-signer.cert.pem`, [`${TRUST}/no-bc-intermediate.cert.pem`, `${CERTS}/root.cert.pem`], false, 'an intermediate without basic constraints'],
  [`${TRUST}/expired-intermediate-signer.cert.pem`, [`${TRUST}/expired-intermediate.cert.pem`, `${CERTS}/root.cert.pem`], false, 'an expired intermediate'],
  [`${TRUST}/sub-signer.cert.pem`, [`${TRUST}/sub-intermediate.cert.pem`, ...ANCHOR], false, 'the path length of the intermediate exceeded'],
  [`${TRUST}/sub-intermediate.cert.pem`, ANCHOR, true, 'a CA within the path length of the intermediate'],
  [`${TRUST}/noext-signer.cert.pem`, [`${TRUST}/noext-root.cert.pem`], false, 'a root without extension, of version 3, is no CA'],
  [`${TRUST}/forged.cert.pem`, ANCHOR, false, 'the names of the intermediate as issuer, signed by another key'],
  [`${TRUST}/twin-b-signer.cert.pem`, [`${TRUST}/twin-a.cert.pem`, `${TRUST}/twin-b.cert.pem`, `${CERTS}/root.cert.pem`], true, 'its issuer told from another CA of the same name by the authority key identifier'],
  [`${TRUST}/twin-ec-signer.cert.pem`, [`${TRUST}/twin-rsa.cert.pem`, `${TRUST}/twin-ec.cert.pem`, `${CERTS}/root.cert.pem`], true, 'its issuer told from another CA of the same name by the signature algorithm'],
  [`${TRUST}/twin-new-signer.cert.pem`, [`${TRUST}/twin-old.cert.pem`, `${TRUST}/twin-new.cert.pem`, `${CERTS}/root.cert.pem`], true, 'its issuer told from an expired CA of the same name by the validity dates'],
  [`${TRUST}/names.cert.pem`, [`${TRUST}/names.cert.pem`], true, 'a self-signed certificate that is not a CA, trusted itself'],
  [`${DEMO}/rogue.cert.pem`, [`${DEMO}/intermediate.cert.pem`, `${DEMO}/root.cert.pem`], false, 'issued by an untrusted root'],
  [`${DEMO}/rogue.cert.pem`, [`${DEMO}/rogue-root.cert.pem`], true, 'issued by its own root, trusted'],
  [`${DEMO}/ec.cert.pem`, [`${DEMO}/intermediate.cert.pem`, `${DEMO}/root.cert.pem`], false, 'an EC certificate signed by its own key'],
  [`${DEMO}/sign.cert.pem`, ANCHOR, false, 'issued by the intermediate of another chain with the same names'],
];

/** [certificate, CA certificate, expected verdict of isValidCA()]. */
const CA_CASES: Array<[string, string, boolean]> = [
  [`${CERTS}/intermediate.cert.pem`, `${CERTS}/root.cert.pem`, true],
  [`${CERTS}/sign.cert.pem`, `${CERTS}/intermediate.cert.pem`, true],
  [`${CERTS}/crypt.cert.pem`, `${CERTS}/intermediate.cert.pem`, true],
  [`${CERTS}/root.cert.pem`, `${CERTS}/root.cert.pem`, true],
  [`${CERTS}/attacker.cert.pem`, `${CERTS}/intermediate.cert.pem`, false],
  [`${TRUST}/rogue.cert.pem`, `${CERTS}/sign.cert.pem`, false],
  [`${TRUST}/no-certsign-signer.cert.pem`, `${TRUST}/no-certsign-intermediate.cert.pem`, false],
  [`${TRUST}/no-bc-signer.cert.pem`, `${TRUST}/no-bc-intermediate.cert.pem`, false],
  [`${DEMO}/sign.cert.pem`, `${CERTS}/intermediate.cert.pem`, false],
  [`${TRUST}/forged.cert.pem`, `${CERTS}/intermediate.cert.pem`, false],
];

/**
 * The certificates the PHP library fails to read, with the reason: they are
 * not compared.
 */
const PHP_FAILURES: Record<string, RegExp> = {
  // EZXML-24: X509Cert reads a date after 2049 (GeneralizedTime) as a
  // two-digit year, and throws an Error.
  [`${TRUST}/not-yet-valid.cert.pem`]: /^Call to a member function (format|getTimestamp)\(\) on false$/,
};

/** Every certificate of the fixtures. */
const ALL_CERTS = [CERTS, DEMO, TRUST].flatMap((dir) =>
  readdirSync(dir).filter((file) => file.endsWith('.cert.pem')).sort().map((file) => `${dir}/${file}`));

describe('X509Cert reads a certificate', () => {
  test('subject, issuer and validity', () => {
    const cert = load(`${CERTS}/sign.cert.pem`);
    assert.equal(cert.getSubject()['OU'], 'Signature Dept');
    assert.deepEqual(cert.getIssuer(), {
      C: 'DK', ST: 'Jylland', O: 'Lothbrok Ltd', OU: 'Shield Wall Dept', CN: 'www.lothbrok.dk', emailAddress: 'ivar@lothbrok.dk',
    });
    assert.equal(cert.getDN(), '/C=DK/ST=Jylland/L=Kattegat/O=Lothbrok Ltd/OU=Signature Dept/CN=www.lothbrok.dk/emailAddress=ivar@lothbrok.dk');
    assert.equal(cert.isOutOfDate(), false);
    assert.match(cert.getValidFrom(), /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/);
    assert.equal(load(`${TRUST}/expired.cert.pem`).getValidTo(), '2021-01-01T00:00:00Z');
    assert.equal(load(`${TRUST}/expired.cert.pem`).isOutOfDate(), true);
    assert.equal(load(`${TRUST}/not-yet-valid.cert.pem`).isOutOfDate(), true);
  });

  test('repeated and multi-valued fields, and the escapes of the one-line form', () => {
    const cert = load(`${TRUST}/names.cert.pem`);
    assert.deepEqual(cert.getSubject()['OU'], ['A+B=C', 'Second Dept']);
    assert.deepEqual(cert.getSubject()['DC'], ['example', 'org']);
    assert.equal(cert.getDN(), '/C=DK/ST=Jylland/L=Kattegat/O=Lothbrok\\/Sons, Ltd/OU=A\\+B=C/OU=Second Dept/serialNumber=42+CN=www.lothbrok.dk/emailAddress=ivar@lothbrok.dk/DC=example/DC=org/UID=ivar/title=Jarl/SN=Lothbrok/GN=Ivar/street=1 Main St/postalCode=1000');
  });

  test('characters out of ASCII', () => {
    const utf8 = load(`${TRUST}/utf8.cert.pem`);
    assert.equal(utf8.getSubject()['O'], 'Lothbrok Ltée');
    assert.equal(utf8.getDN(), '/C=DK/O=Lothbrok Lt\\xC3\\xA9e/OU=D\\xC3\\xA9partement \\xC3\\x89criture/CN=\\xE6\\x97\\xA5\\xE6\\x9C\\xAC\\xE8\\xAA\\x9E \\xC3\\x86gir');
    const bmp = load(`${TRUST}/bmp.cert.pem`);
    assert.equal(bmp.getSubject()['CN'], 'Ægir Plain');
    assert.ok(bmp.getDN().startsWith('/O=\\x00L\\x00o'));
  });

  test('the key usage tells whether the certificate may sign', () => {
    assert.equal(load(`${CERTS}/sign.cert.pem`).canSign(), true);
    assert.equal(load(`${TRUST}/nonrepudiation.cert.pem`).canSign(), true);
    assert.equal(load(`${TRUST}/no-keyusage.cert.pem`).canSign(), true);
    assert.equal(load(`${CERTS}/crypt.cert.pem`).canSign(), false);
    assert.equal(load(`${CERTS}/root.cert.pem`).canSign(), false);
  });

  test('the fingerprint is the SHA-256 hash of the DER encoding', () => {
    const cert = load(`${CERTS}/sign.cert.pem`);
    assert.match(cert.getFingerprint(), /^[0-9a-f]{64}$/);
    assert.notEqual(cert.getFingerprint(), load(`${CERTS}/attacker.cert.pem`).getFingerprint());
    assert.equal(cert.getFingerprint(), load(`${CERTS}/sign.cert.pem`).getFingerprint());
  });

  test('an invalid certificate is refused', () => {
    for (const cert of ['', 'not a certificate', readFileSync(`${CERTS}/sign.key.pem`, 'utf8'), '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n']) {
      assert.throws(() => new X509Cert(cert), { message: 'Invalid certificate!' });
    }
    assert.throws(() => new X509Cert(1 as never), { message: 'Invalid certificate!' });
  });
});

describe('isTrustedBy()', () => {
  for (const [cert, anchor, expected, why] of TRUST_CASES) {
    test(`${expected ? 'trusts' : 'does not trust'} ${cert.split('/').slice(-2).join('/')}: ${why}`, () => {
      assert.equal(load(cert).isTrustedBy(anchor), expected);
    });
  }

  test('CA certificates are given by paths or by contents', () => {
    const cert = load(`${CERTS}/sign.cert.pem`);
    assert.equal(cert.isTrustedBy(ANCHOR.map((path) => readFileSync(path, 'utf8'))), true);
    assert.equal(cert.isTrustedBy(readFileSync(BUNDLE)), true);
  });

  test('a CA file that does not hold certificates trusts nothing', () => {
    const cert = load(`${CERTS}/sign.cert.pem`);
    assert.equal(cert.isTrustedBy([...ANCHOR, `${CERTS}/sign.key.pem`]), false);
    assert.equal(cert.isTrustedBy([...ANCHOR, '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n']), false);
  });

  test('a CA file that cannot be read throws', () => {
    const cert = load(`${CERTS}/sign.cert.pem`);
    assert.throws(() => cert.isTrustedBy([`${CERTS}/missing.pem`]), { message: `Cannot read CA certificate file! File: ${CERTS}/missing.pem` });
    assert.throws(() => cert.isTrustedBy([]), { message: 'No CA certificate file to verify the certificate chain!' });
  });
});

describe('isValidCA()', () => {
  for (const [cert, ca, expected] of CA_CASES) {
    test(`${cert.split('/').pop()} ${expected ? 'is' : 'is not'} issued by ${ca.split('/').pop()}`, () => {
      assert.equal(load(cert).isValidCA(readFileSync(ca, 'utf8')), expected);
    });
  }

  test('an invalid CA certificate throws', () => {
    assert.throws(() => load(`${CERTS}/sign.cert.pem`).isValidCA('not a certificate'), { message: 'Invalid CA certificate!' });
  });
});

describe('pemToDer() and derToPem()', () => {
  test('convert every certificate of the fixtures, as OpenSSL reads and writes it', () => {
    for (const path of ALL_CERTS) {
      const pem = readFileSync(path, 'utf8');
      const der = X509Cert.pemToDer(pem);
      assert.ok(der !== null, path);
      assert.ok(der.equals(new X509Certificate(pem).raw), path);
      assert.equal(X509Cert.derToPem(der), pem, path);
    }
  });

  test('write lines of 64 characters', () => {
    const lines = (X509Cert.derToPem(Buffer.alloc(100, 1)) as string).split('\n');
    assert.deepEqual(lines.map((line) => line.length), [27, 64, 64, 8, 25, 0]);
  });

  test('refuse what is not a certificate', () => {
    for (const value of [null, undefined, 1, Buffer.from('x'), 'no certificate', '-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n']) {
      assert.equal(X509Cert.pemToDer(value), null, String(value));
    }
    for (const value of [null, undefined, 1, 'MIIB']) {
      assert.equal(X509Cert.derToPem(value), null, String(value));
    }
  });
});

describe('the PHP library reads and decides the same', { skip: phpSkip }, () => {
  test('on every certificate of the fixtures', () => {
    const results = runPhp(ALL_CERTS.map((cert) => ({
      command: 'cert',
      cert,
      trustedBy: TRUST_CASES.filter(([path]) => path === cert).map(([, anchor]) => anchor),
      validCA: CA_CASES.filter(([path]) => path === cert).map(([, ca]) => ca),
    })));

    ALL_CERTS.forEach((path, index) => {
      const php = results[index] as Record<string, unknown>;
      const failure = PHP_FAILURES[path];
      if (failure !== undefined) {
        assert.match(String(php['exception']), failure, path);
        return;
      }
      const cert = load(path);
      assert.deepEqual({
        fingerprint: cert.getFingerprint(),
        subject: cert.getSubject(),
        issuer: cert.getIssuer(),
        dn: cert.getDN(),
        validFrom: cert.getValidFrom(),
        validTo: cert.getValidTo(),
        isOutOfDate: cert.isOutOfDate(),
        canSign: cert.canSign(),
        der: X509Cert.pemToDer(readFileSync(path, 'utf8'))?.toString('base64'),
        trustedBy: TRUST_CASES.filter(([p]) => p === path).map(([, anchor]) => cert.isTrustedBy(anchor)),
        validCA: CA_CASES.filter(([p]) => p === path).map(([, ca]) => cert.isValidCA(readFileSync(ca, 'utf8'))),
      }, php, path);
    });
  });
});
