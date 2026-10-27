/**
 * A time-stamping authority for the tests (RFC 3161), written apart from
 * src/der.ts and src/seal/timestamp.ts so that the tokens the library is
 * tested on do not come from the code under test. Every field can be set,
 * so that each test builds one fault. The authority of
 * test/fixtures/seal/certs/tsa.cert.pem signs by default, with RSA PKCS#1
 * v1.5 and SHA-256, and an ESS signingCertificateV2 attribute.
 *
 * opensslTimestamp() asks OpenSSL (`openssl ts -reply`) instead: a token
 * that does not come from this helper either.
 */

import { spawnSync } from 'node:child_process';
import { X509Certificate, createHash, createPrivateKey, sign } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { children, der, int, octets, oid, seq, set } from './der.ts';

const CERTS = 'test/fixtures/seal/certs';

const SHA256 = '2.16.840.1.101.3.4.2.1';
const DIGESTS: Record<string, string> = { sha256: SHA256, sha384: '2.16.840.1.101.3.4.2.2', sha512: '2.16.840.1.101.3.4.2.3', sha1: '1.3.14.3.2.26' };

/** The imprint of a TimeStampReq: its algorithm (node:crypto name) and digest. */
export function readRequest(request: Buffer): { hash: string; imprint: Buffer } {
  const [fields] = children(request);
  const [, imprint] = children(fields!.content);
  const [algorithm, hashed] = children(imprint!.content);
  const [algOid] = children(algorithm!.content);
  const hash = Object.entries(DIGESTS).find(([, o]) => oid(o).subarray(2).equals(algOid!.content))?.[0];
  return { hash: hash as string, imprint: hashed!.content };
}

export interface TsaOptions {
  /** The digest time-stamped (default: that of `request`). */
  imprint?: Buffer;
  hash?: string;
  time?: Date;
  /** The certificate and key of the authority (default: tsa). */
  name?: 'tsa' | 'tsa-no-eku';
  status?: number;
  /** The ESS attribute: 2 (default), 1, or none. */
  ess?: 1 | 2 | 'none';
  /** The certificates of the token (default: the authority's). */
  certificates?: 'signer' | 'chain' | 'none';
  /** Changes the TSTInfo after it is signed. */
  alterTstInfo?: boolean;
  /** Changes the signature. */
  alterSignature?: boolean;
}

/** A TimeStampResp for a request, built by the test authority. */
export function timestampResponse(request: Buffer, options: TsaOptions = {}): Buffer {
  if (options.status !== undefined && options.status > 1) {
    return seq(seq(int(options.status), seq(der(0x0c, Buffer.from('request refused by the test authority')))));
  }
  const fromRequest = readRequest(request);
  const hash = options.hash ?? fromRequest.hash;
  const imprint = options.imprint ?? fromRequest.imprint;
  const name = options.name ?? 'tsa';
  const certPem = readFileSync(`${CERTS}/${name}.cert.pem`, 'utf8');
  const cert = new X509Certificate(certPem);
  const key = createPrivateKey(readFileSync(`${CERTS}/${name}.key.pem`));
  const time = options.time ?? new Date();
  const generalized = time.toISOString().replace(/[-:T]/g, '').replace(/\.\d{3}Z$/, 'Z');

  let tstInfo = seq(
    int(1),
    oid('1.3.6.1.4.1.55555.3.1'),
    seq(seq(oid(DIGESTS[hash] as string), der(0x05)), octets(imprint)),
    int(Buffer.from('0102030405', 'hex')),
    der(0x18, Buffer.from(generalized)),
  );
  const essHash = options.ess === 1 ? 'sha1' : 'sha256';
  const essId = createHash(essHash).update(cert.raw).digest();
  const attributes = [
    seq(oid('1.2.840.113549.1.9.3'), set(oid('1.2.840.113549.1.9.16.1.4'))),
    seq(oid('1.2.840.113549.1.9.4'), set(octets(createHash('sha256').update(tstInfo).digest()))),
  ];
  if (options.ess !== 'none') {
    attributes.push(seq(oid(options.ess === 1 ? '1.2.840.113549.1.9.16.2.12' : '1.2.840.113549.1.9.16.2.47'), set(seq(seq(seq(octets(essId)))))));
  }
  const signedAttributes = Buffer.concat(attributes);
  let signature = sign('sha256', set(signedAttributes), key);
  if (options.alterSignature) {
    signature = Buffer.from(signature);
    signature[10]! ^= 1;
  }
  if (options.alterTstInfo) {
    tstInfo = Buffer.from(tstInfo);
    tstInfo[tstInfo.length - 2]! ^= 1;
  }

  // issuerAndSerialNumber, from the TBSCertificate of the authority.
  const [certificate] = children(cert.raw);
  const tbs = children(children(certificate!.content)[0]!.content);
  const offset = tbs[0]!.tag === 0xa0 ? 1 : 0;
  const serial = der(0x02, tbs[offset]!.content);
  const issuer = der(0x30, tbs[offset + 2]!.content);
  const isEc = key.asymmetricKeyType === 'ec';
  const signerInfo = seq(
    int(1),
    seq(issuer, serial),
    seq(oid(SHA256), der(0x05)),
    der(0xa0, signedAttributes),
    isEc ? seq(oid('1.2.840.10045.4.3.2')) : seq(oid('1.2.840.113549.1.1.11'), der(0x05)),
    octets(signature),
  );
  const certs = options.certificates === 'none' ? [] : [cert.raw, ...(options.certificates === 'chain' ? [new X509Certificate(readFileSync(`${CERTS}/tsa-root.cert.pem`)).raw] : [])];
  const signedData = seq(
    int(3),
    set(seq(oid(SHA256), der(0x05))),
    seq(oid('1.2.840.113549.1.9.16.1.4'), der(0xa0, octets(tstInfo))),
    ...(certs.length === 0 ? [] : [der(0xa0, ...certs)]),
    set(signerInfo),
  );
  const token = seq(oid('1.2.840.113549.1.7.2'), der(0xa0, signedData));
  return seq(seq(int(options.status ?? 0)), token);
}

/** Whether `openssl ts` can run here, or why not. */
export const opensslSkip: string | false = (() => {
  const result = spawnSync('openssl', ['ts', '-help'], { encoding: 'utf8' });
  return result.error === undefined && /-reply/.test(`${result.stdout}${result.stderr}`) ? false : 'openssl ts is not available.';
})();

/** A TimeStampResp for a request, built by OpenSSL with the test authority. */
export function opensslTimestamp(request: Buffer): Buffer {
  const dir = mkdtempSync(join(tmpdir(), 'ezxmlseal-tsa-'));
  try {
    writeFileSync(join(dir, 'serial'), '01\n');
    writeFileSync(join(dir, 'request.tsq'), request);
    writeFileSync(join(dir, 'tsa.cnf'), [
      '[tsa]', 'default_tsa = tsa_config', '[tsa_config]',
      `serial = ${join(dir, 'serial')}`,
      `signer_cert = ${join(process.cwd(), CERTS, 'tsa.cert.pem')}`,
      `certs = ${join(process.cwd(), CERTS, 'tsa-root.cert.pem')}`,
      `signer_key = ${join(process.cwd(), CERTS, 'tsa.key.pem')}`,
      'signer_digest = sha256', 'default_policy = 1.3.6.1.4.1.55555.3.1', 'digests = sha256, sha384, sha512',
      'accuracy = secs:1', 'ess_cert_id_alg = sha256', 'ess_cert_id_chain = no', 'ordering = no', 'tsa_name = no', '',
    ].join('\n'));
    const result = spawnSync('openssl', ['ts', '-reply', '-config', join(dir, 'tsa.cnf'), '-queryfile', join(dir, 'request.tsq'), '-out', join(dir, 'response.tsr')], { encoding: 'utf8' });
    if (result.status !== 0) {
      throw new Error(`openssl ts -reply failed: ${result.stderr}`);
    }
    return readFileSync(join(dir, 'response.tsr'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
