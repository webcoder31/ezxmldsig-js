/*
 * Copyright © 2026 - Thierry Thiers <webcoder31@gmail.com>
 *
 * This software is governed by the CeCILL-C license under French law and
 * abiding by the rules of distribution of free software. You can use, modify
 * and/or redistribute the software under the terms of the CeCILL-C license as
 * circulated by CEA, CNRS and INRIA at the following URL:
 * http://www.cecill.info
 */

/**
 * OCSP (RFC 6960): the request of the status of a certificate, the reading
 * of a response, and the verification of its responder.
 *
 * The request identifies the certificate by SHA-1 hashes of the name and
 * of the key of its issuer, as the lightweight profile requires (RFC 5019,
 * 2.1.1) and as responders expect: an identifier, not a signature. It has
 * no nonce: the responses of the seals are kept, and the freshness rules of
 * revocation.ts, not a nonce, tell whether one is current.
 *
 * A response is signed by the CA that issued the certificate, or by a
 * responder that CA delegated (RFC 6960, 4.2.2.2): a certificate issued
 * directly by it, of extended key usage id-kp-OCSPSigning. The delegated
 * responder must carry id-pkix-ocsp-nocheck (4.2.2.2.1): this library does
 * not check the revocation of responders.
 */

import { createHash } from 'node:crypto';

import { TAG, childrenOf, decodeGeneralizedTime, decodeOid, decodeSmallInteger, decodeUnsigned, encode, encodeOid, readElement, readElements, reencode, type Element } from '../core/der.js';
import { X509Cert } from '../core/x509.js';
import type { Revocation } from './crl.js';
import { sequenceOf, verifySignature } from './pkix.js';
import type { RevocationSource } from './revocation.js';

const OID = {
  BASIC_RESPONSE: '1.3.6.1.5.5.7.48.1.1',
  NO_CHECK: '1.3.6.1.5.5.7.48.1.5',
  ARCHIVE_CUTOFF: '1.3.6.1.5.5.7.48.1.6',
  OCSP_SIGNING: '1.3.6.1.5.5.7.3.9',
  EXTENDED_KEY_USAGE: '2.5.29.37',
  REASON_CODE: '2.5.29.21',
  SHA1: '1.3.14.3.2.26',
} as const;

/** The digests a CertID may use, by OID; SHA-1 is an identifier there, not a signature. */
const CERT_ID_DIGESTS: Readonly<Record<string, string>> = {
  [OID.SHA1]: 'sha1',
  '2.16.840.1.101.3.4.2.1': 'sha256',
  '2.16.840.1.101.3.4.2.2': 'sha384',
  '2.16.840.1.101.3.4.2.3': 'sha512',
};

const RESPONSE_STATUS = ['successful', 'malformedRequest', 'internalError', 'tryLater', '(4)', 'sigRequired', 'unauthorized'];

/** The single response of a certificate. */
interface SingleResponse {
  readonly hash: string;
  readonly issuerNameHash: Buffer;
  readonly issuerKeyHash: Buffer;
  readonly serial: Buffer;
  readonly status: 'good' | 'revoked' | 'unknown';
  readonly revocation: Revocation | null;
  readonly thisUpdate: Date;
  readonly nextUpdate: Date | null;
  readonly archiveCutoff: Date | null;
}

/** An OCSP response, read but not verified. */
export interface OcspResponse {
  readonly der: Buffer;
  readonly producedAt: Date;
  /** The responder: by its name (DER), or by the SHA-1 hash of its key. */
  readonly responder: { readonly name: Buffer } | { readonly keyHash: Buffer };
  readonly responses: readonly SingleResponse[];
  /** The certificates of the response, to find the responder. */
  readonly certificates: readonly X509Cert[];
  readonly tbs: Buffer;
  readonly signatureAlgorithm: Element;
  readonly signature: Buffer;
}

/**
 * The OCSP request of the status of a certificate (OCSPRequest, DER), to
 * send by HTTP POST with the media type `application/ocsp-request`.
 */
export function buildOcspRequest(certificate: X509Cert, issuer: X509Cert): Buffer {
  const certId = encode(TAG.SEQUENCE,
    encode(TAG.SEQUENCE, encodeOid(OID.SHA1), encode(0x05)),
    encode(TAG.OCTET_STRING, createHash('sha1').update(certificate.getRawIssuer()).digest()),
    encode(TAG.OCTET_STRING, createHash('sha1').update(publicKeyBits(issuer)).digest()),
    encode(TAG.INTEGER, integerBytes(certificate.getSerialNumber())));
  return encode(TAG.SEQUENCE, encode(TAG.SEQUENCE, encode(TAG.SEQUENCE, encode(TAG.SEQUENCE, certId))));
}

/**
 * Reads an OCSP response, in DER.
 *
 * @throws {Error} If it is malformed, if the responder did not answer
 *   successfully, or if it is not a basic response.
 */
export function readOcspResponse(data: Uint8Array): OcspResponse {
  try {
    return parse(Buffer.from(data));
  } catch (error) {
    throw new Error(`OCSP response: ${(error as Error).message}`);
  }
}

function parse(der: Buffer): OcspResponse {
  const [status, bytes, ...rest] = sequenceOf(readElement(der), 'OCSPResponse');
  if (status?.tag !== 0x0a || status.content.length !== 1 || rest.length > 0) {
    throw new Error('malformed OCSPResponse.');
  }
  if (status.content[0] !== 0) {
    throw new Error(`the responder answered ${RESPONSE_STATUS[status.content[0] as number] ?? status.content[0]}.`);
  }
  if (bytes?.tag !== 0xa0) {
    throw new Error('malformed OCSPResponse: no response bytes.');
  }
  const [type, octets] = sequenceOf(readElement(bytes.content), 'ResponseBytes');
  if (type === undefined || decodeOid(type) !== OID.BASIC_RESPONSE || octets?.tag !== TAG.OCTET_STRING) {
    throw new Error('not a basic OCSP response.');
  }
  // BasicOCSPResponse: tbsResponseData, signatureAlgorithm, signature, [0] certs OPTIONAL.
  const [tbs, signatureAlgorithm, signature, certs, ...more] = sequenceOf(readElement(octets.content), 'BasicOCSPResponse');
  if (tbs === undefined || signatureAlgorithm === undefined || signature?.tag !== TAG.BIT_STRING || signature.content[0] !== 0 || more.length > 0 || (certs !== undefined && certs.tag !== 0xa0)) {
    throw new Error('malformed BasicOCSPResponse.');
  }
  const certificates = certs === undefined ? [] : childrenOf(readElement(certs.content), TAG.SEQUENCE).map((cert) => {
    try {
      return new X509Cert(X509Cert.derToPem(reencode(cert)) as string);
    } catch {
      throw new Error('a certificate of the response cannot be read.');
    }
  });

  // ResponseData: [0] version DEFAULT v1, responderID, producedAt, responses, [1] responseExtensions.
  const fields = sequenceOf(tbs, 'ResponseData');
  if (fields[0]?.tag === 0xa0) {
    if (decodeSmallInteger(readElement((fields.shift() as Element).content)) !== 0) {
      throw new Error('unsupported version.');
    }
  }
  const [responderId, producedAt, list, extensions, ...extra] = fields;
  if (responderId === undefined || producedAt === undefined || list?.tag !== TAG.SEQUENCE || extra.length > 0 || (extensions !== undefined && extensions.tag !== 0xa1)) {
    throw new Error('malformed ResponseData.');
  }
  const responder = responderId.tag === 0xa1 ? { name: reencode(readElement(responderId.content)) }
    : responderId.tag === 0xa2 ? { keyHash: readOctets(readElement(responderId.content)) }
      : (() => { throw new Error('malformed ResponderID.'); })();
  if (extensions !== undefined) {
    checkExtensions(readElement(extensions.content), new Set(['1.3.6.1.5.5.7.48.1.2']));
  }
  const responses = readElements(list.content).map(readSingleResponse);
  if (responses.length === 0) {
    throw new Error('no single response.');
  }
  return {
    der,
    producedAt: decodeGeneralizedTime(producedAt),
    responder,
    responses,
    certificates,
    tbs: reencode(tbs),
    signatureAlgorithm,
    signature: signature.content.subarray(1),
  };
}

function readSingleResponse(element: Element): SingleResponse {
  // SingleResponse: certID, certStatus, thisUpdate, [0] nextUpdate, [1] singleExtensions.
  const [certId, status, thisUpdate, ...optional] = sequenceOf(element, 'SingleResponse');
  if (certId === undefined || status === undefined || thisUpdate === undefined) {
    throw new Error('malformed SingleResponse.');
  }
  const [algorithm, nameHash, keyHash, serial, ...rest] = sequenceOf(certId, 'CertID');
  const [hashOid, parameters] = sequenceOf(algorithm as Element, 'AlgorithmIdentifier');
  const hash = CERT_ID_DIGESTS[decodeOid(hashOid as Element)];
  if (hash === undefined || (parameters !== undefined && parameters.tag !== 0x05) || nameHash === undefined || keyHash === undefined || serial === undefined || rest.length > 0) {
    throw new Error('malformed or unsupported CertID.');
  }

  let revocation: Revocation | null = null;
  let kind: SingleResponse['status'];
  if (status.tag === 0x80 && status.content.length === 0) {
    kind = 'good';
  } else if (status.tag === 0xa1) {
    // RevokedInfo: revocationTime, [0] revocationReason OPTIONAL.
    const [time, reason] = readElements(status.content);
    if (time === undefined || (reason !== undefined && reason.tag !== 0xa0)) {
      throw new Error('malformed RevokedInfo.');
    }
    kind = 'revoked';
    revocation = { date: decodeGeneralizedTime(time), reason: reason === undefined ? null : readReason(readElement(reason.content)) };
  } else if (status.tag === 0x82 && status.content.length === 0) {
    kind = 'unknown';
  } else {
    throw new Error('malformed CertStatus.');
  }

  let nextUpdate: Date | null = null;
  let archiveCutoff: Date | null = null;
  for (const field of optional) {
    if (field.tag === 0xa0 && nextUpdate === null) {
      nextUpdate = decodeGeneralizedTime(readElement(field.content));
    } else if (field.tag === 0xa1) {
      for (const extension of checkExtensions(readElement(field.content), new Set([OID.ARCHIVE_CUTOFF, OID.REASON_CODE, '2.5.29.24']))) {
        if (extension.oid === OID.ARCHIVE_CUTOFF) {
          archiveCutoff = decodeGeneralizedTime(readElement(extension.value));
        }
      }
    } else {
      throw new Error('malformed SingleResponse.');
    }
  }
  return {
    hash,
    issuerNameHash: readOctets(nameHash),
    issuerKeyHash: readOctets(keyHash),
    serial: decodeUnsigned(serial),
    status: kind,
    revocation,
    thisUpdate: decodeGeneralizedTime(thisUpdate),
    nextUpdate,
    archiveCutoff,
  };
}

/** The extensions of a sequence of them; a critical one not known makes the response unusable. */
function checkExtensions(element: Element, known: ReadonlySet<string>): { oid: string; value: Buffer }[] {
  return childrenOf(element, TAG.SEQUENCE).map((extension) => {
    const fields = sequenceOf(extension, 'Extension');
    const value = fields[fields.length - 1];
    if (fields.length < 2 || fields.length > 3 || value?.tag !== TAG.OCTET_STRING) {
      throw new Error('malformed extension.');
    }
    const oid = decodeOid(fields[0] as Element);
    const critical = fields.length === 3 && fields[1]?.tag === TAG.BOOLEAN && fields[1].content[0] !== 0;
    if (critical && !known.has(oid)) {
      throw new Error(`unsupported critical extension ${oid}.`);
    }
    return { oid, value: value.content };
  });
}

function readReason(element: Element): number {
  if (element.tag !== 0x0a || element.content.length !== 1 || (element.content[0] as number) > 10) {
    throw new Error('malformed reason code.');
  }
  return element.content[0] as number;
}

function readOctets(element: Element): Buffer {
  if (element.tag !== TAG.OCTET_STRING) {
    throw new Error('OCTET STRING expected.');
  }
  return element.content;
}

/** The value of the BIT STRING of the public key of a certificate, without its unused-bits octet (RFC 6960, 4.1.1). */
function publicKeyBits(certificate: X509Cert): Buffer {
  const spki = certificate.getPublicKey().export({ type: 'spki', format: 'der' });
  const [, bits] = sequenceOf(readElement(spki), 'SubjectPublicKeyInfo');
  return (bits as Element).content.subarray(1);
}

/** Unsigned big-endian bytes as the content of a DER INTEGER. */
function integerBytes(unsigned: Buffer): Buffer {
  return unsigned[0]! & 0x80 ? Buffer.concat([Buffer.from([0]), unsigned]) : unsigned;
}

/**
 * The certificate that signed a response for certificates the issuer
 * issued, if it may: the issuer itself, or a responder it delegated (see
 * the comment of the module).
 *
 * @returns The signer, or why there is none.
 */
function responderOf(response: OcspResponse, issuer: X509Cert): X509Cert | string {
  const matches = (cert: X509Cert) => ('name' in response.responder
    ? response.responder.name.equals(cert.getRawSubject())
    : response.responder.keyHash.equals(createHash('sha1').update(publicKeyBits(cert)).digest()));
  if (matches(issuer)) {
    return issuer;
  }
  const delegated = response.certificates.find(matches);
  if (delegated === undefined) {
    return 'its responder is neither the issuer nor a certificate of the response';
  }
  if (!delegated.getRawIssuer().equals(issuer.getRawSubject()) || !verifiesWith(delegated, issuer)) {
    return 'its responder is not issued by the issuer of the certificate';
  }
  const usage = delegated.getExtension(OID.EXTENDED_KEY_USAGE);
  if (usage === null || !childrenOf(readElement(usage.value), TAG.SEQUENCE).map(decodeOid).includes(OID.OCSP_SIGNING)) {
    return 'its responder has not the extended key usage OCSPSigning';
  }
  if (delegated.getExtension(OID.NO_CHECK) === null) {
    return 'its responder has not the extension id-pkix-ocsp-nocheck, and this library does not check the revocation of responders';
  }
  if (!delegated.canSign()) {
    return 'the key usage of its responder does not allow signing';
  }
  const from = new Date(delegated.getValidFrom());
  const to = new Date(delegated.getValidTo());
  if (response.producedAt < from || response.producedAt >= to) {
    return 'its responder was not valid when it was produced';
  }
  return delegated;
}

/** Whether a certificate is signed by the key of another one. */
function verifiesWith(certificate: X509Cert, issuer: X509Cert): boolean {
  const [tbs, algorithm, signature] = sequenceOf(readElement(certificate.getDer()), 'Certificate');
  try {
    return verifySignature(algorithm as Element, null, issuer.getPublicKey(), reencode(tbs as Element), (signature as Element).content.subarray(1));
  } catch {
    return false;
  }
}

/**
 * The answers of a response as sources of revocation status: one for each
 * single response. Each tells the status of its certificate once its
 * signature is verified, by the issuer of the certificate or a responder
 * it delegated.
 */
export function ocspSources(response: OcspResponse): RevocationSource[] {
  const verified = new Map<string, string | null>();
  const signedFor = (issuer: X509Cert): string | null => {
    const key = issuer.getDer().toString('base64');
    if (!verified.has(key)) {
      const responder = responderOf(response, issuer);
      let result: string | null;
      if (typeof responder === 'string') {
        result = responder;
      } else {
        try {
          result = verifySignature(response.signatureAlgorithm, null, responder.getPublicKey(), response.tbs, response.signature) ? null : 'its signature is not valid';
        } catch (error) {
          result = `its signature cannot be verified: ${(error as Error).message}`;
        }
      }
      verified.set(key, result);
    }
    return verified.get(key) as string | null;
  };
  return response.responses.map((single) => ({
    kind: 'ocsp' as const,
    der: response.der,
    thisUpdate: single.thisUpdate,
    nextUpdate: single.nextUpdate,
    keepsExpiredFrom: single.archiveCutoff,
    covers(certificate: X509Cert, issuer: X509Cert): string | null {
      if (!single.serial.equals(certificate.getSerialNumber())
        || !single.issuerNameHash.equals(createHash(single.hash).update(certificate.getRawIssuer()).digest())
        || !single.issuerKeyHash.equals(createHash(single.hash).update(publicKeyBits(issuer)).digest())) {
        return 'it is about another certificate';
      }
      if (single.status === 'unknown') {
        return 'its responder does not know the certificate';
      }
      return signedFor(issuer);
    },
    revocationOf: () => single.revocation,
  }));
}
