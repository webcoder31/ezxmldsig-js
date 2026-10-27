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
 * Certificate revocation lists (RFC 5280, 5): their reading, the
 * verification of their signature by the CA that issued the certificate,
 * and the status of a certificate at a time.
 *
 * Only complete, direct CRLs are used: a delta CRL, an indirect CRL, a CRL
 * restricted to some reasons, or a critical extension this module does not
 * know, make the CRL unusable rather than partly read.
 */

import { TAG, childrenOf, decodeBoolean, decodeOid, decodeSmallInteger, decodeUnsigned, readElement, reencode, type Element } from '../core/der.js';
import type { X509Cert } from '../core/x509.js';
import { decodeTime, sequenceOf, verifySignature } from './pkix.js';
import type { RevocationSource } from './revocation.js';

const EXTENSION = {
  AUTHORITY_KEY_ID: '2.5.29.35',
  CRL_NUMBER: '2.5.29.20',
  DELTA_CRL_INDICATOR: '2.5.29.27',
  ISSUING_DISTRIBUTION_POINT: '2.5.29.28',
  FRESHEST_CRL: '2.5.29.46',
  AUTHORITY_INFO_ACCESS: '1.3.6.1.5.5.7.1.1',
  EXPIRED_CERTS_ON_CRL: '2.5.29.60',
  REASON_CODE: '2.5.29.21',
  INVALIDITY_DATE: '2.5.29.24',
  CERTIFICATE_ISSUER: '2.5.29.29',
  HOLD_INSTRUCTION_CODE: '2.5.29.23',
} as const;

/** The extensions of a CRL it may have, critical or not; any other critical one makes it unusable. */
const KNOWN_CRL_EXTENSIONS: ReadonlySet<string> = new Set([
  EXTENSION.AUTHORITY_KEY_ID, EXTENSION.CRL_NUMBER, EXTENSION.ISSUING_DISTRIBUTION_POINT,
  EXTENSION.FRESHEST_CRL, EXTENSION.AUTHORITY_INFO_ACCESS, EXTENSION.EXPIRED_CERTS_ON_CRL,
]);
const KNOWN_ENTRY_EXTENSIONS: ReadonlySet<string> = new Set([EXTENSION.REASON_CODE, EXTENSION.INVALIDITY_DATE, EXTENSION.HOLD_INSTRUCTION_CODE]);

const ENUMERATED = 0x0a;

/** The PEM label of a CRL. */
const PEM = /-----BEGIN X509 CRL-----([\s\S]*?)-----END X509 CRL-----/;

/** The revocation of a certificate in a CRL. */
export interface Revocation {
  readonly date: Date;
  /** The reason code of the entry (RFC 5280, 5.3.1), or null if it has none. */
  readonly reason: number | null;
}

/** A CRL, read but not verified. */
export interface Crl {
  /** The DER encoding of the CRL. */
  readonly der: Buffer;
  /** The DER encoding of its issuer name. */
  readonly issuer: Buffer;
  readonly thisUpdate: Date;
  readonly nextUpdate: Date | null;
  /** The revoked certificates, by their serial number (hexadecimal). */
  readonly revoked: ReadonlyMap<string, Revocation>;
  /** The scope given by its issuing distribution point. */
  readonly onlyUserCerts: boolean;
  readonly onlyCACerts: boolean;
  /** The date from which it keeps the revoked certificates that have expired (ExpiredCertsOnCRL), or null. */
  readonly expiredCertsOnCrl: Date | null;
  readonly tbs: Buffer;
  readonly signatureAlgorithm: Element;
  readonly signature: Buffer;
}

/**
 * Reads a CRL, in DER or in PEM.
 *
 * @throws {Error} If it is malformed, or if it is not a complete, direct CRL.
 */
export function readCrl(data: Uint8Array): Crl {
  let der = Buffer.from(data);
  const pem = PEM.exec(der.toString('latin1'));
  if (pem !== null) {
    der = Buffer.from((pem[1] as string).replace(/\s/g, ''), 'base64');
  }
  try {
    return parse(der);
  } catch (error) {
    throw new Error(`CRL: ${(error as Error).message}`);
  }
}

function parse(der: Buffer): Crl {
  // CertificateList: tbsCertList, signatureAlgorithm, signatureValue.
  const [tbsElement, signatureAlgorithm, signatureValue, ...rest] = sequenceOf(readElement(der), 'CertificateList');
  if (tbsElement === undefined || signatureAlgorithm === undefined || signatureValue?.tag !== TAG.BIT_STRING || signatureValue.content[0] !== 0 || rest.length > 0) {
    throw new Error('malformed CertificateList.');
  }
  // TBSCertList: version (v2) OPTIONAL, signature, issuer, thisUpdate, nextUpdate OPTIONAL,
  // revokedCertificates OPTIONAL, [0] crlExtensions OPTIONAL.
  const fields = sequenceOf(tbsElement, 'TBSCertList');
  if (fields[0]?.tag === TAG.INTEGER) {
    if (decodeSmallInteger(fields.shift() as Element) !== 1) {
      throw new Error('unsupported version.');
    }
  }
  const [innerAlgorithm, issuer, thisUpdate, ...optional] = fields;
  if (innerAlgorithm === undefined || issuer?.tag !== TAG.SEQUENCE || thisUpdate === undefined || !reencode(innerAlgorithm).equals(reencode(signatureAlgorithm))) {
    throw new Error('malformed TBSCertList.');
  }
  let nextUpdate: Date | null = null;
  if (optional[0] !== undefined && (optional[0].tag === TAG.UTC_TIME || optional[0].tag === TAG.GENERALIZED_TIME)) {
    nextUpdate = decodeTime(optional.shift() as Element);
  }
  const revoked = new Map<string, Revocation>();
  if (optional[0]?.tag === TAG.SEQUENCE) {
    for (const entry of childrenOf(optional.shift() as Element, TAG.SEQUENCE)) {
      const [serial, date, entryExtensions] = sequenceOf(entry, 'revoked certificate');
      if (serial === undefined || date === undefined) {
        throw new Error('malformed revoked certificate.');
      }
      let reason: number | null = null;
      for (const extension of entryExtensions === undefined ? [] : readExtensions(entryExtensions)) {
        if (extension.oid === EXTENSION.REASON_CODE) {
          reason = readReasonCode(extension.value);
        } else if (extension.oid === EXTENSION.CERTIFICATE_ISSUER) {
          throw new Error('indirect CRLs are not supported.');
        }
        if (extension.critical && !KNOWN_ENTRY_EXTENSIONS.has(extension.oid)) {
          throw new Error(`unsupported critical extension ${extension.oid} of a revoked certificate.`);
        }
      }
      const key = decodeUnsigned(serial).toString('hex');
      if (revoked.has(key)) {
        throw new Error('a certificate is listed twice.');
      }
      revoked.set(key, { date: decodeTime(date), reason });
    }
  }
  let onlyUserCerts = false;
  let onlyCACerts = false;
  let expiredCertsOnCrl: Date | null = null;
  const extensions = optional.shift();
  if (extensions !== undefined) {
    if (extensions.tag !== 0xa0 || optional.length > 0) {
      throw new Error('malformed TBSCertList.');
    }
    const seen = new Set<string>();
    for (const extension of readExtensions(readElement(extensions.content))) {
      if (seen.has(extension.oid)) {
        throw new Error(`extension ${extension.oid} repeated.`);
      }
      seen.add(extension.oid);
      if (extension.oid === EXTENSION.DELTA_CRL_INDICATOR) {
        throw new Error('delta CRLs are not supported.');
      }
      if (extension.critical && !KNOWN_CRL_EXTENSIONS.has(extension.oid)) {
        throw new Error(`unsupported critical extension ${extension.oid}.`);
      }
      if (extension.oid === EXTENSION.ISSUING_DISTRIBUTION_POINT) {
        ({ onlyUserCerts, onlyCACerts } = readIssuingDistributionPoint(extension.value));
      } else if (extension.oid === EXTENSION.EXPIRED_CERTS_ON_CRL) {
        expiredCertsOnCrl = decodeTime(readElement(extension.value));
      }
    }
  }
  return {
    der,
    issuer: reencode(issuer),
    thisUpdate: decodeTime(thisUpdate),
    nextUpdate,
    revoked,
    onlyUserCerts,
    onlyCACerts,
    expiredCertsOnCrl,
    tbs: reencode(tbsElement),
    signatureAlgorithm,
    signature: signatureValue.content.subarray(1),
  };
}

/**
 * IssuingDistributionPoint (RFC 5280, 5.2.5): the distribution point name
 * and the restriction to user or CA certificates are read; a restriction
 * to some reasons, an indirect CRL, or a CRL of attribute certificates make
 * the CRL unusable.
 */
function readIssuingDistributionPoint(value: Buffer): { onlyUserCerts: boolean; onlyCACerts: boolean } {
  let onlyUserCerts = false;
  let onlyCACerts = false;
  for (const field of sequenceOf(readElement(value), 'IssuingDistributionPoint')) {
    const flag = field.content.length === 1 && field.content[0] !== 0;
    if (field.tag === 0xa0) {
      continue;
    } else if (field.tag === 0x81) {
      onlyUserCerts = flag;
    } else if (field.tag === 0x82) {
      onlyCACerts = flag;
    } else {
      throw new Error('CRLs restricted to some reasons, indirect CRLs and CRLs of attribute certificates are not supported.');
    }
  }
  return { onlyUserCerts, onlyCACerts };
}

/** CRLReason (RFC 5280, 5.3.1): an ENUMERATED of one byte. */
function readReasonCode(value: Buffer): number {
  const element = readElement(value);
  if (element.tag !== ENUMERATED || element.content.length !== 1 || (element.content[0] as number) > 10) {
    throw new Error('malformed reason code.');
  }
  return element.content[0] as number;
}

function readExtensions(element: Element): { oid: string; critical: boolean; value: Buffer }[] {
  return childrenOf(element, TAG.SEQUENCE).map((extension) => {
    const fields = sequenceOf(extension, 'Extension');
    const value = fields[fields.length - 1];
    if (fields.length < 2 || fields.length > 3 || value?.tag !== TAG.OCTET_STRING) {
      throw new Error('malformed extension.');
    }
    return {
      oid: decodeOid(fields[0] as Element),
      critical: fields.length === 3 ? decodeBoolean(fields[1] as Element) : false,
      value: value.content,
    };
  });
}

/**
 * Whether a CRL can tell the status of a certificate: issued by the issuer
 * of the certificate (its name, its signature, its key usage cRLSign), and
 * of a scope that includes it.
 *
 * @returns Null if it can, or why it cannot.
 */
export function crlCovers(crl: Crl, certificate: X509Cert, issuer: X509Cert): string | null {
  if (!crl.issuer.equals(certificate.getRawIssuer()) || !crl.issuer.equals(issuer.getRawSubject())) {
    return 'its issuer is not the issuer of the certificate';
  }
  if (crl.onlyUserCerts && certificate.isCA()) {
    return 'it covers the end-entity certificates only';
  }
  if (crl.onlyCACerts && !certificate.isCA()) {
    return 'it covers the CA certificates only';
  }
  if (!issuer.canSignCrls()) {
    return 'the key usage of its issuer does not allow signing CRLs';
  }
  let valid: boolean;
  try {
    valid = verifySignature(crl.signatureAlgorithm, null, issuer.getPublicKey(), crl.tbs, crl.signature);
  } catch (error) {
    return `its signature cannot be verified: ${(error as Error).message}`;
  }
  return valid ? null : 'its signature is not valid';
}

/** The revocation of a certificate in a CRL, or null if the CRL does not list it. */
export function revocationOf(crl: Crl, certificate: X509Cert): Revocation | null {
  return crl.revoked.get(certificate.getSerialNumber().toString('hex')) ?? null;
}

/** A CRL as a source of revocation status. */
export function crlSource(crl: Crl): RevocationSource {
  return {
    kind: 'crl',
    der: crl.der,
    thisUpdate: crl.thisUpdate,
    nextUpdate: crl.nextUpdate,
    keepsExpiredFrom: crl.expiredCertsOnCrl,
    covers: (certificate, issuer) => crlCovers(crl, certificate, issuer),
    revocationOf: (certificate) => revocationOf(crl, certificate),
  };
}
