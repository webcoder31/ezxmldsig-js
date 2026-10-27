/**
 * OCSP responses for the tests (RFC 6960, 4.2), signed by the CAs and the
 * responders of test/fixtures/seal/certs/, written apart from
 * src/seal/ocsp.ts, so that the responses the library is tested on do not
 * come from the code under test. Every field can be set, so that each test
 * builds one fault.
 *
 * opensslOcsp() asks OpenSSL (`openssl ocsp`) instead, from a request.
 */

import { spawnSync } from 'node:child_process';
import { X509Certificate, createHash, createPrivateKey, sign } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { children, der, octets, oid, seq } from './der.ts';

const CERTS = 'test/fixtures/seal/certs';

export interface OcspOptions {
  /** The certificate whose status is given (a fixture name, or the path of a PEM file). */
  cert: string;
  /** Its issuer (default: intermediate). */
  issuer?: string;
  /** Whose key signs the response (default: the issuer): a CA, or a responder of the fixtures. */
  signer?: string;
  /** Whom the ResponderID names (default: the signer), and how. */
  responder?: string;
  responderBy?: 'name' | 'key';
  status?: 'good' | 'revoked' | 'unknown';
  revocationTime?: Date;
  /** The CRLReason of a revocation, or none. */
  reason?: number;
  thisUpdate?: Date;
  /** Null: no nextUpdate. */
  nextUpdate?: Date | null;
  producedAt?: Date;
  /** The archive cutoff (RFC 6960, 4.4.4), a single extension. */
  archiveCutoff?: Date;
  /** The hash of the CertID (default: sha1). */
  certIdHash?: 'sha1' | 'sha256';
  /** The certificates of the response (default: the signer, if it is not the issuer). */
  certificates?: string[];
  /** A responseStatus other than successful (0): no response bytes. */
  responseStatus?: number;
  alterSignature?: boolean;
}

/** A fixture certificate by its name, or any certificate by the path of its PEM file. */
const certificate = (name: string) => new X509Certificate(readFileSync(name.endsWith('.pem') ? name : `${CERTS}/${name}.cert.pem`));

/** A field of the TBSCertificate of a fixture (serial 0, issuer 2, subject 4), in DER. */
function field(name: string, index: number): Buffer {
  const tbs = children(children(children(certificate(name).raw)[0]!.content)[0]!.content);
  const fields = tbs[0]!.tag === 0xa0 ? tbs.slice(1) : tbs;
  return der(fields[index]!.tag, fields[index]!.content);
}

/** The BIT STRING value of the public key of a fixture, without its unused-bits octet. */
function keyBits(name: string): Buffer {
  const spki = certificate(name).publicKey.export({ type: 'spki', format: 'der' });
  return children(children(spki)[0]!.content)[1]!.content.subarray(1);
}

/** GeneralizedTime, as OCSP writes its times. */
function generalized(date: Date): Buffer {
  return der(0x18, Buffer.from(date.toISOString().replace(/[-:T]/g, '').replace(/\.\d{3}Z$/, 'Z')));
}

/** An OCSPResponse, in DER. */
export function makeOcspResponse(options: OcspOptions): Buffer {
  if (options.responseStatus !== undefined) {
    return seq(der(0x0a, Buffer.from([options.responseStatus])));
  }
  const issuer = options.issuer ?? 'intermediate';
  const signer = options.signer ?? issuer;
  const responder = options.responder ?? signer;
  const hash = options.certIdHash ?? 'sha1';
  const hashOid = hash === 'sha1' ? '1.3.14.3.2.26' : '2.16.840.1.101.3.4.2.1';
  const certId = seq(
    seq(oid(hashOid), der(0x05)),
    octets(createHash(hash).update(field(options.cert, 2)).digest()),
    octets(createHash(hash).update(keyBits(issuer)).digest()),
    field(options.cert, 0),
  );
  const status = options.status ?? 'good';
  const certStatus = status === 'good' ? der(0x80)
    : status === 'unknown' ? der(0x82)
      : der(0xa1, generalized(options.revocationTime ?? new Date(Date.now() - 60_000)), ...(options.reason === undefined ? [] : [der(0xa0, der(0x0a, Buffer.from([options.reason])))]));
  const thisUpdate = options.thisUpdate ?? new Date(Date.now() - 5_000);
  const nextUpdate = options.nextUpdate === undefined ? new Date(thisUpdate.getTime() + 86_400_000) : options.nextUpdate;
  const single = seq(certId, certStatus, generalized(thisUpdate), ...(nextUpdate === null ? [] : [der(0xa0, generalized(nextUpdate))]),
    ...(options.archiveCutoff === undefined ? [] : [der(0xa1, seq(seq(oid('1.3.6.1.5.5.7.48.1.6'), octets(generalized(options.archiveCutoff)))))]));
  const responderId = (options.responderBy ?? 'name') === 'name'
    ? der(0xa1, field(responder, 4))
    : der(0xa2, octets(createHash('sha1').update(keyBits(responder)).digest()));
  const tbs = seq(responderId, generalized(options.producedAt ?? thisUpdate), seq(single));

  // The keys of the signers are encrypted with the password of the tests; the others are not.
  const key = createPrivateKey({ key: readFileSync(`${CERTS}/${signer}.key.pem`), passphrase: 'signKeyPassword' });
  const algorithm = key.asymmetricKeyType === 'ec' ? seq(oid('1.2.840.10045.4.3.2')) : seq(oid('1.2.840.113549.1.1.11'), der(0x05));
  const signature = sign('sha256', tbs, key);
  if (options.alterSignature) {
    signature[5]! ^= 1;
  }
  const certs = options.certificates ?? (signer === issuer ? [] : [signer]);
  const basic = seq(tbs, algorithm, der(0x03, Buffer.concat([Buffer.from([0]), signature])),
    ...(certs.length === 0 ? [] : [der(0xa0, seq(...certs.map((name) => certificate(name).raw)))]));
  return seq(der(0x0a, Buffer.from([0])), der(0xa0, seq(oid('1.3.6.1.5.5.7.48.1.1'), octets(basic))));
}

/** Whether `openssl ocsp` can run here, or why not. */
export const opensslOcspSkip: string | false = (() => {
  const result = spawnSync('openssl', ['ocsp', '-help'], { encoding: 'utf8' });
  return result.error === undefined && /-reqin/.test(`${result.stdout}${result.stderr}`) ? false : 'openssl ocsp is not available.';
})();

/**
 * The response of OpenSSL, acting as the responder `ocsp` delegated by the
 * intermediate, to a request: the given fixture certificates revoked on
 * 2026-01-01, the others good.
 */
export function opensslOcsp(request: Buffer, revoked: string[] = []): Buffer {
  const dir = mkdtempSync(join(tmpdir(), 'ezxmlseal-ocsp-'));
  try {
    const lines = [...new Set(['rsa3072', 'p256', ...revoked])].map((name) => {
      const cert = certificate(name);
      const expiry = new Date(cert.validTo).toISOString().replace(/[-:T]/g, '').replace(/\.\d{3}Z$/, 'Z').slice(2);
      return revoked.includes(name) ? `R\t${expiry}\t260101000000Z\t${cert.serialNumber}\tunknown\t/CN=${name}\n` : `V\t${expiry}\t\t${cert.serialNumber}\tunknown\t/CN=${name}\n`;
    });
    writeFileSync(join(dir, 'index.txt'), lines.join(''));
    writeFileSync(join(dir, 'request.der'), request);
    const at = (name: string) => join(process.cwd(), CERTS, name);
    const result = spawnSync('openssl', ['ocsp', '-index', join(dir, 'index.txt'), '-CA', at('intermediate.cert.pem'),
      '-rsigner', at('ocsp.cert.pem'), '-rkey', at('ocsp.key.pem'), '-reqin', join(dir, 'request.der'),
      '-respout', join(dir, 'response.der'), '-ndays', '1'], { encoding: 'utf8' });
    if (result.status !== 0) {
      throw new Error(`openssl ocsp failed: ${result.stderr}`);
    }
    return readFileSync(join(dir, 'response.der'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

