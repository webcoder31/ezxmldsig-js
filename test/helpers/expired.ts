/**
 * A signer whose certificate has expired: the certificate of rsa3072 issued
 * again by the intermediate, same key, subject and extensions, with a new
 * serial number and the given dates. It lets a test seal while the
 * certificate was valid, then check revocation data issued after it expired.
 *
 * The certificate is written with the DER writer of the test helpers and
 * signed by Node.js, not by `openssl x509 -not_before -not_after`: OpenSSL
 * 3.0, that of the runners of the continuous integration, does not have
 * these options.
 */

import { X509Certificate, createPrivateKey, sign } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { children, der, int, seq, time } from './der.ts';

const CERTS = 'test/fixtures/seal/certs';

export interface ExpiredSigner {
  certPath: string;
  keyPath: string;
  /** Removes the temporary directory of the certificate. */
  remove(): void;
}

export function expiredSigner(notBefore: Date, notAfter: Date): ExpiredSigner {
  const raw = new X509Certificate(readFileSync(`${CERTS}/rsa3072.cert.pem`)).raw;
  // version [0], serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo, extensions [3]
  const fields = children(children(children(raw)[0]!.content)[0]!.content).map((field) => der(field.tag, field.content));
  let serial = Date.now().toString(16);
  serial = serial.length % 2 === 0 ? serial : `0${serial}`;
  fields[1] = int(Buffer.from(serial, 'hex'));
  fields[4] = seq(time(notBefore), time(notAfter));
  const tbs = seq(...fields);
  // The signature field of the certificate is sha256WithRSAEncryption, as the key of the intermediate.
  const signature = sign('sha256', tbs, createPrivateKey(readFileSync(`${CERTS}/intermediate.key.pem`)));
  const certificate = seq(tbs, fields[2]!, der(0x03, Buffer.concat([Buffer.from([0]), signature])));

  const dir = mkdtempSync(join(tmpdir(), 'ezxmlseal-expired-'));
  const certPath = join(dir, 'cert.pem');
  writeFileSync(certPath, `-----BEGIN CERTIFICATE-----\n${certificate.toString('base64').replace(/(.{64})/g, '$1\n').replace(/\n?$/, '\n')}-----END CERTIFICATE-----\n`);
  return { certPath, keyPath: `${CERTS}/rsa3072.key.pem`, remove: () => rmSync(dir, { recursive: true, force: true }) };
}
