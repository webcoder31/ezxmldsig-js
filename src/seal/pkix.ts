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
 * What the signed structures of the PKI share (time-stamp tokens, CRLs):
 * their algorithm identifiers, the verification of their signature with the
 * algorithms and key sizes of the seals, and their times. The functions
 * throw an Error whose message says what is wrong, for the caller to put in
 * context.
 */

import { constants, verify, type KeyObject } from 'node:crypto';

import { TAG, childrenOf, decodeGeneralizedTime, decodeOid, decodeSmallInteger, readElement, readElements, type Element } from '../der.js';
import { CURVES, MIN_RSA_BITS } from './algorithms.js';

export const OID_SHA256 = '2.16.840.1.101.3.4.2.1';
export const OID_SHA384 = '2.16.840.1.101.3.4.2.2';
export const OID_SHA512 = '2.16.840.1.101.3.4.2.3';
const OID_RSA_PSS = '1.2.840.113549.1.1.10';
const OID_MGF1 = '1.2.840.113549.1.1.8';

/** The digests accepted, their node:crypto name by OID. */
const DIGEST_OIDS: Readonly<Record<string, string>> = {
  [OID_SHA256]: 'sha256',
  [OID_SHA384]: 'sha384',
  [OID_SHA512]: 'sha512',
};

/** The OID of a digest, by its node:crypto name. */
export const OIDS_OF_DIGESTS: Readonly<Record<string, string>> = { sha256: OID_SHA256, sha384: OID_SHA384, sha512: OID_SHA512 };

/** Signature algorithms but RSASSA-PSS: the type of key, and the digest the OID names (null: the one given beside, as in CMS). */
const SIGNATURES: Readonly<Record<string, { keyType: 'rsa' | 'ec'; hash: string | null }>> = {
  '1.2.840.113549.1.1.1': { keyType: 'rsa', hash: null },
  '1.2.840.113549.1.1.11': { keyType: 'rsa', hash: 'sha256' },
  '1.2.840.113549.1.1.12': { keyType: 'rsa', hash: 'sha384' },
  '1.2.840.113549.1.1.13': { keyType: 'rsa', hash: 'sha512' },
  '1.2.840.10045.4.3.2': { keyType: 'ec', hash: 'sha256' },
  '1.2.840.10045.4.3.3': { keyType: 'ec', hash: 'sha384' },
  '1.2.840.10045.4.3.4': { keyType: 'ec', hash: 'sha512' },
};

/** The elements of a SEQUENCE. */
export function sequenceOf(element: Element, what: string): Element[] {
  if (element.tag !== TAG.SEQUENCE) {
    throw new Error(`malformed ${what}.`);
  }
  return readElements(element.content);
}

/** A digest AlgorithmIdentifier: SHA-256, SHA-384 or SHA-512, parameters absent or NULL. */
export function digestOf(algorithm: Element): string {
  const [oid, parameters, ...rest] = sequenceOf(algorithm, 'AlgorithmIdentifier');
  const digest = DIGEST_OIDS[decodeOid(oid as Element)];
  if (digest === undefined || rest.length > 0 || (parameters !== undefined && (parameters.tag !== 0x05 || parameters.content.length !== 0))) {
    throw new Error(`unsupported digest algorithm ${decodeOid(oid as Element)}.`);
  }
  return digest;
}

/** A Time (RFC 5280, 4.1.2.5): UTCTime (years 1950 to 2049) or GeneralizedTime, in UTC. */
export function decodeTime(element: Element): Date {
  if (element.tag === TAG.GENERALIZED_TIME) {
    return decodeGeneralizedTime(element);
  }
  const match = element.tag === TAG.UTC_TIME ? /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(element.content.toString('latin1')) : null;
  if (match === null) {
    throw new Error('malformed time.');
  }
  const [, yy, month, day, hour, minute, second] = match;
  const year = Number(yy) < 50 ? 2000 + Number(yy) : 1900 + Number(yy);
  const date = new Date(Date.UTC(year, Number(month) - 1, Number(day), Number(hour), Number(minute), Number(second)));
  if (date.getUTCDate() !== Number(day) || date.getUTCMonth() !== Number(month) - 1) {
    throw new Error('malformed time.');
  }
  return date;
}

/**
 * Verifies a signature with its AlgorithmIdentifier, the algorithms and key
 * sizes of the seals.
 *
 * @param digest The digest given beside the algorithm (CMS digestAlgorithm),
 *   or null when the algorithm alone must name it (a CRL).
 */
export function verifySignature(algorithm: Element, digest: string | null, key: KeyObject, data: Buffer, signature: Buffer): boolean {
  const [oidElement, parameters] = sequenceOf(algorithm, 'AlgorithmIdentifier');
  const oid = decodeOid(oidElement as Element);
  if (key.asymmetricKeyType === 'rsa' && (key.asymmetricKeyDetails?.modulusLength ?? 0) < MIN_RSA_BITS) {
    throw new Error(`the RSA key of the signer has less than ${MIN_RSA_BITS} bits.`);
  }
  if (key.asymmetricKeyType === 'ec' && CURVES[key.asymmetricKeyDetails?.namedCurve ?? ''] === undefined) {
    throw new Error('the EC key of the signer is not on P-256, P-384 or P-521.');
  }
  if (oid === OID_RSA_PSS) {
    const pss = readPssParameters(parameters);
    if (key.asymmetricKeyType !== 'rsa' || (digest !== null && pss.hash !== digest)) {
      throw new Error('unsupported RSASSA-PSS parameters.');
    }
    return verify(pss.hash, data, { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: pss.saltLength }, signature);
  }
  const scheme = SIGNATURES[oid];
  if (scheme === undefined) {
    throw new Error(`unsupported signature algorithm ${oid}.`);
  }
  const hash = scheme.hash ?? digest;
  if (hash === null || scheme.keyType !== key.asymmetricKeyType || (digest !== null && hash !== digest)) {
    throw new Error('the signature algorithm does not suit the key or the digest.');
  }
  return verify(hash, data, scheme.keyType === 'rsa' ? { key, padding: constants.RSA_PKCS1_PADDING } : key, signature);
}

/** RSASSA-PSS-params (RFC 4055): the digest, MGF1 with the same digest, the salt length, trailer 1. */
function readPssParameters(parameters: Element | undefined): { hash: string; saltLength: number } {
  if (parameters === undefined) {
    throw new Error('RSASSA-PSS without parameters.');
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
      if (decodeOid(mgf as Element) !== OID_MGF1 || mgfParameters === undefined) {
        throw new Error('unsupported mask generation function.');
      }
      mgfHash = digestOf(mgfParameters);
    } else if (field.tag === 0xa2) {
      saltLength = decodeSmallInteger(inner);
    } else if (field.tag !== 0xa3 || decodeSmallInteger(inner) !== 1) {
      throw new Error('unsupported RSASSA-PSS parameters.');
    }
  }
  if (mgfHash !== hash || hash === 'sha1') {
    throw new Error('unsupported RSASSA-PSS parameters.');
  }
  return { hash, saltLength };
}
