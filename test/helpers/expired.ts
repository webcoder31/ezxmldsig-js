/**
 * A signer whose certificate has expired: the certificate of rsa3072 issued
 * again by the intermediate, same key, subject and extensions, with a new
 * serial number and the given dates (`openssl x509 -CA -not_before -not_after`).
 * It lets a test seal while the certificate was valid, then check revocation
 * data issued after it expired.
 */

import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const CERTS = 'test/fixtures/seal/certs';

/** `[CC]YYMMDDHHMMSSZ`, as openssl x509 takes its dates. */
const opensslDate = (date: Date) => date.toISOString().replace(/[-:T]/g, '').replace(/\.\d{3}Z$/, 'Z');

export interface ExpiredSigner {
  certPath: string;
  keyPath: string;
  /** Removes the temporary directory of the certificate. */
  remove(): void;
}

export function expiredSigner(notBefore: Date, notAfter: Date): ExpiredSigner {
  const dir = mkdtempSync(join(tmpdir(), 'ezxmlseal-expired-'));
  const run = (args: string[]) => {
    const result = spawnSync('openssl', args, { encoding: 'utf8' });
    if (result.status !== 0) {
      throw new Error(`openssl ${args[0]} failed: ${result.stderr}`);
    }
  };
  const keyPath = `${CERTS}/rsa3072.key.pem`;
  // Given a certificate and -CA, openssl x509 signs it again, its extensions kept.
  run(['x509', '-in', `${CERTS}/rsa3072.cert.pem`, '-CA', `${CERTS}/intermediate.cert.pem`, '-CAkey', `${CERTS}/intermediate.key.pem`,
    '-set_serial', `0x${Date.now().toString(16)}`, '-not_before', opensslDate(notBefore), '-not_after', opensslDate(notAfter),
    '-sha256', '-out', join(dir, 'cert.pem')]);
  return { certPath: join(dir, 'cert.pem'), keyPath, remove: () => rmSync(dir, { recursive: true, force: true }) };
}
