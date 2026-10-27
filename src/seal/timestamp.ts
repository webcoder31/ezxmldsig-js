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
 * Time-stamps (RFC 3161, updated by RFC 5816): the request, the response,
 * and the verification of a time-stamp token, a CMS SignedData (RFC 5652)
 * whose content is a TSTInfo.
 *
 * No network access: the caller sends the request to the time-stamping
 * authority of its choice. The token is checked as a signature of its own:
 * one signer, the signed attributes that bind the content and the
 * certificate of the authority (ESS signing-certificate, RFC 2634 and
 * RFC 5035), the extended key usage timeStamping of that certificate
 * (RFC 3161, 2.3), the algorithms of the seals. Whether the authority is
 * trusted is decided by the caller, with the certificate this module
 * returns.
 */

import { X509Certificate, constants, createHash, verify, type KeyObject } from 'node:crypto';

import {
  TAG, childrenOf, decodeBoolean, decodeGeneralizedTime, decodeOid, decodeSmallInteger, decodeUnsigned, encode, encodeInteger, encodeOid,
  readElement, readElements, reencode, type Element,
} from '../der.js';
import { X509Cert } from '../x509.js';
import { CURVES, MIN_RSA_BITS } from './algorithms.js';

const OID = {
  SHA256: '2.16.840.1.101.3.4.2.1',
  SHA384: '2.16.840.1.101.3.4.2.2',
  SHA512: '2.16.840.1.101.3.4.2.3',
  SIGNED_DATA: '1.2.840.113549.1.7.2',
  TST_INFO: '1.2.840.113549.1.9.16.1.4',
  CONTENT_TYPE: '1.2.840.113549.1.9.3',
  MESSAGE_DIGEST: '1.2.840.113549.1.9.4',
  SIGNING_CERTIFICATE: '1.2.840.113549.1.9.16.2.12',
  SIGNING_CERTIFICATE_V2: '1.2.840.113549.1.9.16.2.47',
  RSA: '1.2.840.113549.1.1.1',
  RSA_PSS: '1.2.840.113549.1.1.10',
  RSA_SHA256: '1.2.840.113549.1.1.11',
  RSA_SHA384: '1.2.840.113549.1.1.12',
  RSA_SHA512: '1.2.840.113549.1.1.13',
  ECDSA_SHA256: '1.2.840.10045.4.3.2',
  ECDSA_SHA384: '1.2.840.10045.4.3.3',
  ECDSA_SHA512: '1.2.840.10045.4.3.4',
  MGF1: '1.2.840.113549.1.1.8',
  EXTENDED_KEY_USAGE: '2.5.29.37',
  TIME_STAMPING: '1.3.6.1.5.5.7.3.8',
} as const;

/** The digests of messages, imprints and signatures: their node:crypto name by OID. */
const DIGEST_OIDS: Readonly<Record<string, string>> = {
  [OID.SHA256]: 'sha256',
  [OID.SHA384]: 'sha384',
  [OID.SHA512]: 'sha512',
};
const OIDS_OF_DIGESTS: Readonly<Record<string, string>> = { sha256: OID.SHA256, sha384: OID.SHA384, sha512: OID.SHA512 };

/** Signature algorithms of the token whose OID names the digest. */
const SIGNATURES: Readonly<Record<string, { keyType: 'rsa' | 'ec'; hash: string | null }>> = {
  [OID.RSA]: { keyType: 'rsa', hash: null },
  [OID.RSA_SHA256]: { keyType: 'rsa', hash: 'sha256' },
  [OID.RSA_SHA384]: { keyType: 'rsa', hash: 'sha384' },
  [OID.RSA_SHA512]: { keyType: 'rsa', hash: 'sha512' },
  [OID.ECDSA_SHA256]: { keyType: 'ec', hash: 'sha256' },
  [OID.ECDSA_SHA384]: { keyType: 'ec', hash: 'sha384' },
  [OID.ECDSA_SHA512]: { keyType: 'ec', hash: 'sha512' },
};

const PKI_STATUS = ['granted', 'grantedWithMods', 'rejection', 'waiting', 'revocationWarning', 'revocationNotification'];

/** What a verified token says. */
export interface TimestampToken {
  /** The time of the time-stamp (genTime). */
  readonly time: Date;
  /** The digest of the imprint, by its node:crypto name. */
  readonly imprintAlgorithm: string;
  /** The digest the authority time-stamped. */
  readonly imprint: Buffer;
  /** The certificate of the authority, which signed the token. */
  readonly certificate: X509Cert;
  /** The other certificates of the token, to build the chain of the authority. */
  readonly chain: X509Cert[];
  /** The policy of the authority. */
  readonly policy: string;
  readonly serialNumber: Buffer;
}

/**
 * A TimeStampReq (RFC 3161, 2.4.1): version 1, the imprint, and the
 * request of the certificate of the authority in the token (certReq), which
 * the verifier needs.
 *
 * @param imprint The digest of the data to time-stamp.
 * @param hash Its algorithm, by its node:crypto name: sha256, sha384, sha512.
 */
export function buildTimestampRequest(imprint: Buffer, hash: string): Buffer {
  const oid = OIDS_OF_DIGESTS[hash];
  if (oid === undefined) {
    throw new Error(`Time-stamp: unsupported digest ${hash}.`);
  }
  return encode(TAG.SEQUENCE,
    encodeInteger(1),
    encode(TAG.SEQUENCE, encode(TAG.SEQUENCE, encodeOid(oid), encode(0x05)), encode(TAG.OCTET_STRING, imprint)),
    encode(TAG.BOOLEAN, Buffer.from([0xff])));
}

/**
 * The token of a TimeStampResp (RFC 3161, 2.4.2), if the authority granted it.
 *
 * @throws {Error} If the response is malformed, or the authority did not grant the time-stamp.
 */
export function readTimestampResponse(response: Buffer): Buffer {
  const [status, token, ...rest] = sequenceOf(readElement(response), 'TimeStampResp');
  if (status === undefined || rest.length > 0) {
    throw new Error('Time-stamp: malformed TimeStampResp.');
  }
  const [code, ...details] = sequenceOf(status, 'PKIStatusInfo');
  const value = decodeSmallInteger(code as Element);
  if (value !== 0 && value !== 1) {
    const text = details.find((detail) => detail.tag === TAG.SEQUENCE);
    const reason = text === undefined ? '' : `: ${readElements(text.content).map((t) => t.content.toString('utf8')).join(' ')}`;
    throw new Error(`Time-stamp: the authority answered ${PKI_STATUS[value] ?? value}${reason}.`);
  }
  if (token === undefined) {
    throw new Error('Time-stamp: the response grants a time-stamp but holds no token.');
  }
  return reencode(token);
}

/**
 * Verifies a time-stamp token, and reads it.
 *
 * @throws {Error} Why the token is not valid.
 */
export function verifyTimestampToken(token: Buffer): TimestampToken {
  // ContentInfo: contentType signedData, [0] EXPLICIT SignedData.
  const [contentType, wrapped, ...extra] = sequenceOf(readElement(token), 'ContentInfo');
  if (contentType === undefined || decodeOid(contentType) !== OID.SIGNED_DATA || wrapped?.tag !== 0xa0 || extra.length > 0) {
    throw new Error('Time-stamp: the token is not a CMS SignedData.');
  }
  // SignedData: version, digestAlgorithms, encapContentInfo, [0] certificates, [1] crls, signerInfos.
  const signedData = sequenceOf(readElement(wrapped.content), 'SignedData');
  const [, , encapsulated] = signedData;
  const signerInfos = signedData[signedData.length - 1];
  if (encapsulated === undefined || signerInfos === undefined) {
    throw new Error('Time-stamp: malformed SignedData.');
  }
  const certificates = signedData.slice(3, -1).find((element) => element.tag === 0xa0);
  const [eContentType, eContentWrapped] = sequenceOf(encapsulated, 'EncapsulatedContentInfo');
  if (eContentType === undefined || decodeOid(eContentType) !== OID.TST_INFO || eContentWrapped?.tag !== 0xa0) {
    throw new Error('Time-stamp: the token does not hold a TSTInfo.');
  }
  const eContent = readElement(eContentWrapped.content);
  if (eContent.tag !== TAG.OCTET_STRING) {
    throw new Error('Time-stamp: malformed TSTInfo.');
  }
  const tstInfo = readTstInfo(eContent.content);

  // The certificates of the token: the one of the signer, and the chain.
  const certs = certificates === undefined ? [] : readElements(certificates.content).filter((element) => element.tag === TAG.SEQUENCE).map(reencode);

  // The one signer.
  const signers = childrenOf(signerInfos, TAG.SET);
  if (signers.length !== 1) {
    throw new Error('Time-stamp: the token must have one signer.');
  }
  const [version, sid, digestAlgorithm, signedAttrs, signatureAlgorithm, signature, ...unsigned] = sequenceOf(signers[0] as Element, 'SignerInfo');
  if (version === undefined || sid === undefined || digestAlgorithm === undefined || signedAttrs?.tag !== 0xa0 || signatureAlgorithm === undefined || signature?.tag !== TAG.OCTET_STRING || unsigned.some((u) => u.tag !== 0xa1)) {
    throw new Error('Time-stamp: malformed SignerInfo (the signed attributes are required).');
  }
  const signerCertDer = certs.find((der) => identifies(sid, der));
  if (signerCertDer === undefined) {
    throw new Error('Time-stamp: the certificate of the authority is not in the token.');
  }
  const digest = digestOf(digestAlgorithm);

  // The signed attributes: content type, message digest, signing certificate.
  const attributes = new Map<string, Element[]>();
  for (const attribute of readElements(signedAttrs.content)) {
    const [type, values] = sequenceOf(attribute, 'Attribute');
    const oid = decodeOid(type as Element);
    if (attributes.has(oid) || values === undefined) {
      throw new Error('Time-stamp: a signed attribute is repeated or malformed.');
    }
    attributes.set(oid, childrenOf(values, TAG.SET));
  }
  const single = (oid: string, name: string): Element => {
    const values = attributes.get(oid);
    if (values === undefined || values.length !== 1) {
      throw new Error(`Time-stamp: the signed attribute ${name} is missing or not single.`);
    }
    return values[0] as Element;
  };
  if (decodeOid(single(OID.CONTENT_TYPE, 'contentType')) !== OID.TST_INFO) {
    throw new Error('Time-stamp: the signed content type is not TSTInfo.');
  }
  const messageDigest = single(OID.MESSAGE_DIGEST, 'messageDigest');
  if (messageDigest.tag !== TAG.OCTET_STRING || !createHash(digest).update(eContent.content).digest().equals(messageDigest.content)) {
    throw new Error('Time-stamp: the TSTInfo has been altered (message digest mismatch).');
  }
  checkSigningCertificate(attributes, signerCertDer);

  // The signature, over the DER of the signed attributes as a SET.
  let certificate: X509Cert;
  let publicKey: KeyObject;
  let chain: X509Cert[];
  try {
    certificate = new X509Cert(X509Cert.derToPem(signerCertDer) as string);
    publicKey = new X509Certificate(signerCertDer).publicKey;
    chain = certs.filter((der) => !der.equals(signerCertDer)).map((der) => new X509Cert(X509Cert.derToPem(der) as string));
  } catch {
    throw new Error('Time-stamp: a certificate of the token cannot be read.');
  }
  if (!verifySignature(signatureAlgorithm, digest, publicKey, encode(TAG.SET, signedAttrs.content), signature.content)) {
    throw new Error('Time-stamp: the signature of the token is not valid.');
  }
  if (!hasTimeStampingUsage(signerCertDer)) {
    throw new Error('Time-stamp: the certificate of the authority does not have the extended key usage timeStamping alone, critical (RFC 3161, 2.3).');
  }
  return { ...tstInfo, certificate, chain };
}

/** TSTInfo (RFC 3161, 2.4.2): version 1, policy, messageImprint, serialNumber, genTime, then optional fields. */
function readTstInfo(content: Buffer): { time: Date; imprintAlgorithm: string; imprint: Buffer; policy: string; serialNumber: Buffer } {
  const [version, policy, messageImprint, serialNumber, genTime] = sequenceOf(readElement(content), 'TSTInfo');
  if (version === undefined || decodeSmallInteger(version) !== 1 || policy === undefined || messageImprint === undefined || serialNumber === undefined || genTime === undefined) {
    throw new Error('Time-stamp: malformed TSTInfo.');
  }
  const [algorithm, hashed] = sequenceOf(messageImprint, 'MessageImprint');
  if (algorithm === undefined || hashed?.tag !== TAG.OCTET_STRING) {
    throw new Error('Time-stamp: malformed MessageImprint.');
  }
  return {
    time: decodeGeneralizedTime(genTime),
    imprintAlgorithm: digestOf(algorithm),
    imprint: hashed.content,
    policy: decodeOid(policy),
    serialNumber: decodeUnsigned(serialNumber),
  };
}

/**
 * The ESS signing-certificate attribute binds the certificate of the
 * authority to its signature: version 2 (a digest of the certificate with
 * the given algorithm, SHA-256 by default), or version 1 (SHA-1, which
 * identifies the certificate here, without signing anything).
 */
function checkSigningCertificate(attributes: Map<string, Element[]>, certificate: Buffer): void {
  const v2 = attributes.get(OID.SIGNING_CERTIFICATE_V2);
  const v1 = attributes.get(OID.SIGNING_CERTIFICATE);
  const value = (v2 ?? v1)?.[0];
  if (value === undefined || (v2 ?? v1)?.length !== 1) {
    throw new Error('Time-stamp: the signed attribute signingCertificate (ESS) is missing.');
  }
  // SigningCertificate(V2) ::= SEQUENCE { certs SEQUENCE OF ESSCertID(v2), policies OPTIONAL }
  const [certs] = sequenceOf(value, 'SigningCertificate');
  const first = childrenOf(certs as Element, TAG.SEQUENCE)[0];
  if (first === undefined) {
    throw new Error('Time-stamp: the signed attribute signingCertificate names no certificate.');
  }
  const fields = sequenceOf(first, 'ESSCertID');
  let hash = 'sha1';
  let index = 0;
  if (v2 !== undefined) {
    hash = 'sha256';
    if (fields[0]?.tag === TAG.SEQUENCE) {
      hash = digestOf(fields[0]);
      index = 1;
    }
  }
  const certHash = fields[index];
  if (certHash?.tag !== TAG.OCTET_STRING || !createHash(hash).update(certificate).digest().equals(certHash.content)) {
    throw new Error('Time-stamp: the signed attribute signingCertificate does not name the certificate of the signer.');
  }
}

/** Whether a SignerIdentifier names a certificate: issuerAndSerialNumber, or [0] subjectKeyIdentifier. */
function identifies(sid: Element, der: Buffer): boolean {
  if (sid.tag === TAG.SEQUENCE) {
    const [issuer, serial] = readElements(sid.content);
    const tbs = sequenceOf(sequenceOf(readElement(der), 'Certificate')[0] as Element, 'TBSCertificate');
    const offset = tbs[0]?.tag === 0xa0 ? 1 : 0;
    return issuer !== undefined && serial !== undefined
      && reencode(issuer).equals(reencode(tbs[offset + 2] as Element))
      && decodeUnsigned(serial).equals(decodeUnsigned(tbs[offset] as Element));
  }
  if (sid.tag === 0x80) {
    return subjectKeyIdentifier(der)?.equals(sid.content) ?? false;
  }
  return false;
}

/** The subject key identifier of a certificate, or null. */
function subjectKeyIdentifier(der: Buffer): Buffer | null {
  const extension = extensionOf(der, '2.5.29.14');
  return extension === null ? null : readElement(extension.value).content;
}

/** An extension of a certificate: its criticality and its value (the content of its OCTET STRING), or null. */
function extensionOf(der: Buffer, oid: string): { critical: boolean; value: Buffer } | null {
  const tbs = sequenceOf(sequenceOf(readElement(der), 'Certificate')[0] as Element, 'TBSCertificate');
  const extensions = tbs.find((element) => element.tag === 0xa3);
  if (extensions === undefined) {
    return null;
  }
  for (const extension of childrenOf(readElement(extensions.content), TAG.SEQUENCE)) {
    const fields = sequenceOf(extension, 'Extension');
    if (decodeOid(fields[0] as Element) === oid) {
      const critical = fields.length === 3 ? decodeBoolean(fields[1] as Element) : false;
      const value = fields[fields.length - 1] as Element;
      return { critical, value: value.content };
    }
  }
  return null;
}

/** RFC 3161, 2.3: the certificate of the authority has one extended key usage, timeStamping, critical. */
function hasTimeStampingUsage(der: Buffer): boolean {
  const extension = extensionOf(der, OID.EXTENDED_KEY_USAGE);
  if (extension === null || !extension.critical) {
    return false;
  }
  const usages = childrenOf(readElement(extension.value), TAG.SEQUENCE).map(decodeOid);
  return usages.length === 1 && usages[0] === OID.TIME_STAMPING;
}

/** Verifies the signature of the token, with the algorithms and key sizes of the seals. */
function verifySignature(algorithm: Element, digest: string, key: KeyObject, data: Buffer, signature: Buffer): boolean {
  const [oidElement, parameters] = sequenceOf(algorithm, 'AlgorithmIdentifier');
  const oid = decodeOid(oidElement as Element);
  if (key.asymmetricKeyType === 'rsa' && (key.asymmetricKeyDetails?.modulusLength ?? 0) < MIN_RSA_BITS) {
    throw new Error(`Time-stamp: the RSA key of the authority has less than ${MIN_RSA_BITS} bits.`);
  }
  if (key.asymmetricKeyType === 'ec' && CURVES[key.asymmetricKeyDetails?.namedCurve ?? ''] === undefined) {
    throw new Error('Time-stamp: the EC key of the authority is not on P-256, P-384 or P-521.');
  }
  if (oid === OID.RSA_PSS) {
    const pss = readPssParameters(parameters);
    if (key.asymmetricKeyType !== 'rsa' || pss.hash !== digest) {
      throw new Error('Time-stamp: unsupported RSASSA-PSS parameters.');
    }
    return verify(digest, data, { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: pss.saltLength }, signature);
  }
  const scheme = SIGNATURES[oid];
  if (scheme === undefined) {
    throw new Error(`Time-stamp: unsupported signature algorithm ${oid}.`);
  }
  if (scheme.keyType !== key.asymmetricKeyType || (scheme.hash !== null && scheme.hash !== digest)) {
    throw new Error('Time-stamp: the signature algorithm does not suit the key or the digest of the token.');
  }
  return verify(digest, data, scheme.keyType === 'rsa' ? { key, padding: constants.RSA_PKCS1_PADDING } : key, signature);
}

/** RSASSA-PSS-params (RFC 4055): the digest, MGF1 with the same digest, the salt length, trailer 1. */
function readPssParameters(parameters: Element | undefined): { hash: string; saltLength: number } {
  if (parameters === undefined) {
    throw new Error('Time-stamp: RSASSA-PSS without parameters.');
  }
  let hash = 'sha1';
  let mgfHash = 'sha1';
  let saltLength = 20;
  for (const field of childrenOf(parameters, TAG.SEQUENCE)) {
    const inner = readElement(field.content);
    if (field.tag === 0xa0) {
      hash = digestOf(inner);
    } else if (field.tag === 0xa1) {
      const [mgf, mgfParameters] = sequenceOf(inner, 'MaskGenAlgorithm');
      if (decodeOid(mgf as Element) !== OID.MGF1 || mgfParameters === undefined) {
        throw new Error('Time-stamp: unsupported mask generation function.');
      }
      mgfHash = digestOf(mgfParameters);
    } else if (field.tag === 0xa2) {
      saltLength = decodeSmallInteger(inner);
    } else if (field.tag !== 0xa3 || decodeSmallInteger(inner) !== 1) {
      throw new Error('Time-stamp: unsupported RSASSA-PSS parameters.');
    }
  }
  if (mgfHash !== hash) {
    throw new Error('Time-stamp: unsupported RSASSA-PSS parameters.');
  }
  return { hash, saltLength };
}

/** A digest AlgorithmIdentifier: SHA-256, SHA-384 or SHA-512, parameters absent or NULL. */
function digestOf(algorithm: Element): string {
  const [oid, parameters, ...rest] = sequenceOf(algorithm, 'AlgorithmIdentifier');
  const digest = DIGEST_OIDS[decodeOid(oid as Element)];
  if (digest === undefined || rest.length > 0 || (parameters !== undefined && (parameters.tag !== 0x05 || parameters.content.length !== 0))) {
    throw new Error(`Time-stamp: unsupported digest algorithm ${decodeOid(oid as Element)}.`);
  }
  return digest;
}

function sequenceOf(element: Element, what: string): Element[] {
  if (element.tag !== TAG.SEQUENCE) {
    throw new Error(`Time-stamp: malformed ${what}.`);
  }
  return readElements(element.content);
}
