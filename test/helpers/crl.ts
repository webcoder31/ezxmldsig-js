/**
 * CRLs for the tests (RFC 5280, 5), issued by the CAs of
 * test/fixtures/seal/certs/ and written apart from src/seal/crl.ts, so that
 * the CRLs the library is tested on do not come from the code under test.
 * Every field can be set, so that each test builds one fault.
 *
 * opensslCrl() asks OpenSSL (`openssl ca -gencrl`) instead.
 */

import { spawnSync } from 'node:child_process';
import { X509Certificate, createPrivateKey, sign } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { children, der, int, octets, oid, seq, time } from './der.ts';

const CERTS = 'test/fixtures/seal/certs';

export type CaName = 'root' | 'intermediate' | 'intermediate-offline' | 'tsa-root';

export interface CrlOptions {
  /** The CA whose name the CRL bears (default: intermediate). */
  issuer?: CaName;
  /** The CA whose key signs it (default: the issuer). */
  signer?: CaName;
  thisUpdate?: Date;
  /** Null: no nextUpdate. */
  nextUpdate?: Date | null;
  /** The revoked certificates: a fixture name, and the revocation date. */
  revoked?: { cert: string; date: Date; extensions?: Buffer[] }[];
  /** Extensions of the CRL (see extension()). */
  extensions?: Buffer[];
  alterSignature?: boolean;
}

/** The DER of a field of the TBSCertificate of a fixture certificate (serial 0, issuer 2, subject 4). */
function certificateField(name: string, index: number): Buffer {
  const raw = new X509Certificate(readFileSync(`${CERTS}/${name}.cert.pem`)).raw;
  const tbs = children(children(children(raw)[0]!.content)[0]!.content);
  const fields = tbs[0]!.tag === 0xa0 ? tbs.slice(1) : tbs;
  const field = fields[index]!;
  return der(field.tag, field.content);
}

/** An Extension: OID, criticality, value. */
export function extension(id: string, critical: boolean, value: Buffer): Buffer {
  return seq(oid(id), ...(critical ? [der(0x01, Buffer.from([0xff]))] : []), octets(value));
}

/** An issuing distribution point, with the given fields: [1] onlyContainsUserCerts, [2] onlyContainsCACerts, [3] onlySomeReasons, [4] indirectCRL. */
export function issuingDistributionPoint(fields: { onlyUser?: boolean; onlyCA?: boolean; someReasons?: boolean; indirect?: boolean }): Buffer {
  const parts = [
    ...(fields.onlyUser ? [der(0x81, Buffer.from([0xff]))] : []),
    ...(fields.onlyCA ? [der(0x82, Buffer.from([0xff]))] : []),
    ...(fields.someReasons ? [der(0x83, Buffer.from([0x07, 0x80]))] : []),
    ...(fields.indirect ? [der(0x84, Buffer.from([0xff]))] : []),
  ];
  return extension('2.5.29.28', true, seq(...parts));
}

/** A CRL, in DER. */
export function makeCrl(options: CrlOptions = {}): Buffer {
  const issuer = options.issuer ?? 'intermediate';
  const key = createPrivateKey(readFileSync(`${CERTS}/${options.signer ?? issuer}.key.pem`));
  // sha256WithRSAEncryption, or ecdsa-with-SHA256 (no parameters), as the key of the signer.
  const algorithm = key.asymmetricKeyType === 'ec' ? seq(oid('1.2.840.10045.4.3.2')) : seq(oid('1.2.840.113549.1.1.11'), der(0x05));
  const thisUpdate = options.thisUpdate ?? new Date(Date.now() - 5_000);
  const nextUpdate = options.nextUpdate === undefined ? new Date(thisUpdate.getTime() + 7 * 86_400_000) : options.nextUpdate;
  const revoked = (options.revoked ?? []).map((entry) => seq(
    certificateField(entry.cert, 0),
    time(entry.date),
    ...(entry.extensions === undefined ? [] : [seq(...entry.extensions)]),
  ));
  const tbs = seq(
    int(1),
    algorithm,
    certificateField(issuer, 4),
    time(thisUpdate),
    ...(nextUpdate === null ? [] : [time(nextUpdate)]),
    ...(revoked.length === 0 ? [] : [seq(...revoked)]),
    der(0xa0, seq(extension('2.5.29.20', false, int(1)), ...(options.extensions ?? []))),
  );
  const signature = sign('sha256', tbs, key);
  if (options.alterSignature) {
    signature[5]! ^= 1;
  }
  return seq(tbs, algorithm, der(0x03, Buffer.concat([Buffer.from([0]), signature])));
}

/** The CRLs of a valid seal of the tests: of the intermediate (the signers), of the root (the intermediate), of the TSA root (the authority). */
export function currentCrls(revoked: CrlOptions['revoked'] = []): Buffer[] {
  return [makeCrl({ issuer: 'intermediate', revoked }), makeCrl({ issuer: 'root' }), makeCrl({ issuer: 'tsa-root' })];
}

/** Whether `openssl ca` can run here, or why not. */
export const opensslCaSkip: string | false = (() => {
  const result = spawnSync('openssl', ['ca', '-help'], { encoding: 'utf8' });
  return result.error === undefined && /-gencrl/.test(`${result.stdout}${result.stderr}`) ? false : 'openssl ca is not available.';
})();

/** A CRL of a CA, in PEM, built by OpenSSL, which revokes the given fixture certificates (revoked on 2026-01-01). */
export function opensslCrl(issuer: CaName, revoked: string[] = []): Buffer {
  const dir = mkdtempSync(join(tmpdir(), 'ezxmlseal-crl-'));
  try {
    const lines = revoked.map((name) => {
      const cert = new X509Certificate(readFileSync(`${CERTS}/${name}.cert.pem`));
      const expiry = new Date(cert.validTo).toISOString().replace(/[-:T]/g, '').replace(/\.\d{3}Z$/, 'Z').slice(2);
      return `R\t${expiry}\t260101000000Z\t${cert.serialNumber}\tunknown\t/CN=${name}\n`;
    });
    writeFileSync(join(dir, 'index.txt'), lines.join(''));
    writeFileSync(join(dir, 'crlnumber'), '01\n');
    writeFileSync(join(dir, 'ca.cnf'), `[ca]\ndefault_ca = test\n[test]\ndatabase = ${join(dir, 'index.txt')}\ncrlnumber = ${join(dir, 'crlnumber')}\ndefault_md = sha256\ndefault_crl_days = 7\n`);
    const result = spawnSync('openssl', ['ca', '-gencrl', '-config', join(dir, 'ca.cnf'),
      '-cert', join(process.cwd(), CERTS, `${issuer}.cert.pem`), '-keyfile', join(process.cwd(), CERTS, `${issuer}.key.pem`),
      '-out', join(dir, 'crl.pem')], { encoding: 'utf8' });
    if (result.status !== 0) {
      throw new Error(`openssl ca -gencrl failed: ${result.stderr}`);
    }
    return readFileSync(join(dir, 'crl.pem'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
