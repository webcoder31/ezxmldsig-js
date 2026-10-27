/*
 * Copyright © 2026 - Thierry Thiers <webcoder31@gmail.com>
 *
 * This software is governed by the CeCILL-C license under French law and
 * abiding by the rules of distribution of free software. You can use, modify
 * and/or redistribute the software under the terms of the CeCILL-C license as
 * circulated by CEA, CNRS and INRIA at the following URL:
 * http://www.cecill.info
 */

import { X509Certificate, createHash, type KeyObject } from 'node:crypto';

import {
  TAG,
  childrenOf,
  decodeBits,
  decodeBoolean,
  decodeOid,
  decodeSmallInteger,
  encode,
  readElement,
  readElements,
  type Element,
} from './der.js';
import { describeSource, readPem, type PemSource } from './material.js';

/** The fields of a name (subject or issuer), by short name. A field
repeated in the name is an array of its values. */
export type NameFields = Record<string, string | string[]>;

/** A field of a name, as encoded in the certificate. */
interface NameEntry {
  readonly oid: string;
  readonly tag: number;
  readonly value: Buffer;
  /** The index of the RDN (the set) the field belongs to. */
  readonly set: number;
}

/** A name: its fields, and its canonical form, which OpenSSL compares
names by (null if OpenSSL cannot compute it: the name matches none). */
interface Name {
  readonly entries: NameEntry[];
  readonly canonical: string | null;
}

/** An extension of the certificate. */
interface Extension {
  readonly critical: boolean;
  readonly value: Buffer;
}

/** The authority key identifier of a certificate. */
interface AuthorityKeyId {
  readonly keyId: Buffer | null;
  readonly issuer: Name | null;
  readonly serial: Buffer | null;
}

/**
 * The short names OpenSSL gives to the attributes of names (`OBJ_nid2sn()`),
 * which the subject and the issuer are written with, as in the PHP library.
 */
const SHORT_NAMES: Readonly<Record<string, string>> = {
  '2.5.4.3': 'CN',
  '2.5.4.4': 'SN',
  '2.5.4.5': 'serialNumber',
  '2.5.4.6': 'C',
  '2.5.4.7': 'L',
  '2.5.4.8': 'ST',
  '2.5.4.9': 'street',
  '2.5.4.10': 'O',
  '2.5.4.11': 'OU',
  '2.5.4.12': 'title',
  '2.5.4.13': 'description',
  '2.5.4.15': 'businessCategory',
  '2.5.4.16': 'postalAddress',
  '2.5.4.17': 'postalCode',
  '2.5.4.18': 'postOfficeBox',
  '2.5.4.20': 'telephoneNumber',
  '2.5.4.41': 'name',
  '2.5.4.42': 'GN',
  '2.5.4.43': 'initials',
  '2.5.4.44': 'generationQualifier',
  '2.5.4.45': 'x500UniqueIdentifier',
  '2.5.4.46': 'dnQualifier',
  '2.5.4.65': 'pseudonym',
  '2.5.4.72': 'role',
  '2.5.4.97': 'organizationIdentifier',
  '1.2.840.113549.1.9.1': 'emailAddress',
  '1.2.840.113549.1.9.2': 'unstructuredName',
  '1.2.840.113549.1.9.8': 'unstructuredAddress',
  '0.9.2342.19200300.100.1.1': 'UID',
  '0.9.2342.19200300.100.1.25': 'DC',
  '1.3.6.1.4.1.311.60.2.1.1': 'jurisdictionL',
  '1.3.6.1.4.1.311.60.2.1.2': 'jurisdictionST',
  '1.3.6.1.4.1.311.60.2.1.3': 'jurisdictionC',
};

const OID = {
  KEY_USAGE: '2.5.29.15',
  BASIC_CONSTRAINTS: '2.5.29.19',
  NAME_CONSTRAINTS: '2.5.29.30',
  SUBJECT_KEY_ID: '2.5.29.14',
  AUTHORITY_KEY_ID: '2.5.29.35',
} as const;

/**
 * The extensions whose criticality the verification of a chain accepts.
 * They are those OpenSSL handles (`X509_supported_extension()`), but name
 * constraints, which it enforces and this library does not: a CA
 * certificate that has them is refused (see `isTrustedBy()`), and the
 * extensions of IP addresses and AS numbers (RFC 3779) and of proxy
 * certificates, which it does not handle either.
 */
const HANDLED_CRITICAL_EXTENSIONS = new Set([
  '2.16.840.1.113730.1.1', // Netscape certificate type
  OID.KEY_USAGE,
  '2.5.29.17', // subject alternative name
  OID.BASIC_CONSTRAINTS,
  '2.5.29.32', // certificate policies
  '2.5.29.31', // CRL distribution points
  '2.5.29.37', // extended key usage
  '1.3.6.1.5.5.7.48.1.5', // OCSP no check
  '2.5.29.36', // policy constraints
  '2.5.29.33', // policy mappings
  '2.5.29.54', // inhibit any policy
]);

/**
 * The key types (node:crypto `asymmetricKeyType`) that may sign with each
 * signature algorithm. OpenSSL takes a certificate whose signature
 * algorithm does not suit the key of a certificate as not issued by it.
 */
const SIGNATURE_KEY_TYPES: Readonly<Record<string, readonly string[]>> = {
  '1.2.840.113549.1.1.4': ['rsa'], // md5WithRSAEncryption
  '1.2.840.113549.1.1.5': ['rsa'], // sha1WithRSAEncryption
  '1.2.840.113549.1.1.11': ['rsa'], // sha256WithRSAEncryption
  '1.2.840.113549.1.1.12': ['rsa'], // sha384WithRSAEncryption
  '1.2.840.113549.1.1.13': ['rsa'], // sha512WithRSAEncryption
  '1.2.840.113549.1.1.14': ['rsa'], // sha224WithRSAEncryption
  '1.2.840.113549.1.1.10': ['rsa-pss', 'rsa'], // RSASSA-PSS
  '1.2.840.10045.4.1': ['ec'], // ecdsa-with-SHA1
  '1.2.840.10045.4.3.1': ['ec'], // ecdsa-with-SHA224
  '1.2.840.10045.4.3.2': ['ec'], // ecdsa-with-SHA256
  '1.2.840.10045.4.3.3': ['ec'], // ecdsa-with-SHA384
  '1.2.840.10045.4.3.4': ['ec'], // ecdsa-with-SHA512
  '1.3.101.112': ['ed25519'],
  '1.3.101.113': ['ed448'],
  '1.2.840.10040.4.3': ['dsa'], // dsa-with-SHA1
  '2.16.840.1.101.3.4.3.1': ['dsa'], // dsa-with-SHA224
  '2.16.840.1.101.3.4.3.2': ['dsa'], // dsa-with-SHA256
};

/** The string types OpenSSL compares names by in canonical form
(`ASN1_MASK_CANON`): converted to UTF-8, trimmed, with collapsed white
space and in lowercase ASCII. */
const CANONICAL_STRING_TAGS: ReadonlySet<number> = new Set([
  TAG.UTF8_STRING,
  TAG.BMP_STRING,
  TAG.UNIVERSAL_STRING,
  TAG.PRINTABLE_STRING,
  TAG.T61_STRING,
  TAG.IA5_STRING,
  TAG.VISIBLE_STRING,
]);

/** The key usages, by their bit in the extension. */
const KEY_USAGE_BITS = {
  digitalSignature: 0,
  nonRepudiation: 1,
  keyCertSign: 5,
  cRLSign: 6,
} as const;

/** The deepest chain OpenSSL builds by default. */
const MAX_CHAIN_LENGTH = 100;

/**
 * Analyzes an X.509 certificate: the counterpart of the class `X509Cert` of
 * the PHP library.
 *
 * It extracts the information of the certificate (subject, issuer, validity
 * dates, fingerprint) and makes the checks the analysis of a token needs: the
 * validity at the current date, the key usage, and the chain of the
 * certificate up to trusted CA certificates (`isTrustedBy()`), which follows
 * the rules OpenSSL applies for the PHP library. The certificate is parsed
 * by OpenSSL (node:crypto), which also verifies the signature of each link
 * of a chain; the fields node:crypto does not expose are read from the DER
 * encoding of the certificate.
 */
export class X509Cert {
  readonly #pem: string;
  readonly #x509: X509Certificate;
  readonly #version: number;
  readonly #serial: Buffer;
  /** The signature algorithm the certificate is signed with. */
  readonly #signatureAlgorithm: string;
  readonly #subject: Name;
  readonly #issuer: Name;
  readonly #extensions: Map<string, Extension>;
  /** Whether an extension is repeated or malformed: OpenSSL then refuses
  any chain the certificate is part of. */
  readonly #hasInvalidExtension: boolean;
  /** The bits of the key usage extension, or null without it. */
  readonly #keyUsage: boolean[] | null;
  /** The basic constraints, or null without them. */
  readonly #basicConstraints: { ca: boolean; pathLength: number | null } | null;
  readonly #subjectKeyId: Buffer | null;
  readonly #authorityKeyId: AuthorityKeyId | null;

  /**
   * @param cert An X.509 certificate in PEM format (its content).
   * @throws {Error} If the certificate cannot be read.
   */
  constructor(cert: string | Uint8Array) {
    const pem = typeof cert === 'string' ? cert : cert instanceof Uint8Array ? Buffer.from(cert).toString('utf8') : null;
    if (pem === null || !pem.includes('-----BEGIN CERTIFICATE-----')) {
      throw new Error('Invalid certificate!');
    }
    let x509: X509Certificate;
    try {
      x509 = new X509Certificate(pem);
    } catch {
      throw new Error('Invalid certificate!');
    }
    this.#pem = pem;
    this.#x509 = x509;

    // TBSCertificate: [0] version (absent: v1), serialNumber, signature,
    // issuer, validity, subject, subjectPublicKeyInfo, [1] issuerUniqueID,
    // [2] subjectUniqueID, [3] extensions.
    let extensions: Map<string, Extension>;
    let invalid: boolean;
    try {
      const tbs = childrenOf(childrenOf(readElement(x509.raw), TAG.SEQUENCE)[0] as Element, TAG.SEQUENCE);
      const version = tbs[0]?.tag === 0xa0 ? tbs.shift() as Element : null;
      this.#version = version === null ? 1 : decodeSmallInteger(readElement(version.content)) + 1;
      const [serial, signature, issuer, , subject, , ...optional] = tbs;
      if (serial?.tag !== TAG.INTEGER || signature === undefined || issuer === undefined || subject === undefined) {
        throw new Error('DER: malformed certificate.');
      }
      this.#serial = serial.content;
      this.#signatureAlgorithm = decodeOid(childrenOf(signature, TAG.SEQUENCE)[0] as Element);
      this.#issuer = readName(issuer);
      this.#subject = readName(subject);
      ({ extensions, invalid } = readExtensions(optional.find((element) => element.tag === 0xa3)));
    } catch {
      throw new Error('Failed to extract X.509 information from certificate!');
    }
    this.#extensions = extensions;

    // The extensions the verification of a chain reads: one that cannot be
    // decoded makes the certificate invalid, as for OpenSSL.
    let keyUsage: boolean[] | null = null;
    let basicConstraints: { ca: boolean; pathLength: number | null } | null = null;
    let subjectKeyId: Buffer | null = null;
    let authorityKeyId: AuthorityKeyId | null = null;
    try {
      const ku = extensions.get(OID.KEY_USAGE);
      keyUsage = ku === undefined ? null : decodeBits(readElement(ku.value));
      const bc = extensions.get(OID.BASIC_CONSTRAINTS);
      if (bc !== undefined) {
        basicConstraints = readBasicConstraints(bc.value);
        // A path length without CA is invalid for OpenSSL.
        if (basicConstraints.pathLength !== null && !basicConstraints.ca) {
          invalid = true;
        }
      }
      const skid = extensions.get(OID.SUBJECT_KEY_ID);
      if (skid !== undefined) {
        const element = readElement(skid.value);
        if (element.tag !== TAG.OCTET_STRING) {
          throw new Error('DER: malformed subject key identifier.');
        }
        subjectKeyId = element.content;
      }
      const akid = extensions.get(OID.AUTHORITY_KEY_ID);
      authorityKeyId = akid === undefined ? null : readAuthorityKeyId(akid.value);
    } catch {
      invalid = true;
    }
    this.#keyUsage = keyUsage;
    this.#basicConstraints = basicConstraints;
    this.#subjectKeyId = subjectKeyId;
    this.#authorityKeyId = authorityKeyId;
    this.#hasInvalidExtension = invalid;
  }

  /** Gets the certificate in PEM format. */
  getPem(): string {
    return this.#pem;
  }

  /**
   * Gets the fingerprint of the certificate: the hash of its DER encoding.
   * Two certificates are the same certificate if, and only if, their
   * fingerprints are equal.
   *
   * @param algorithm The hash algorithm. Default: 'sha256'.
   * @returns The fingerprint, as a lowercase hexadecimal string.
   */
  getFingerprint(algorithm = 'sha256'): string {
    return createHash(algorithm).update(this.#x509.raw).digest('hex');
  }

  /** Gets the fields of the issuer of the certificate. */
  getIssuer(): NameFields {
    return nameFields(this.#issuer.entries);
  }

  /** Gets the fields of the subject of the certificate. */
  getSubject(): NameFields {
    return nameFields(this.#subject.entries);
  }

  /**
   * Gets the Distinguished Name of the subject of the certificate, in the
   * OpenSSL "oneline" format, as the PHP library gives it: every field, in
   * the order of the certificate, written `/<short name>=<value>`, the
   * fields of one RDN joined by `+`, with `/` and `+` escaped by a backslash
   * and every byte out of printable ASCII written `\xHH`.
   */
  getDN(): string {
    return oneline(this.#subject.entries);
  }

  /** Gets the date from which the certificate is valid, in UTC
  (`YYYY-MM-DDThh:mm:ssZ`). */
  getValidFrom(): string {
    return formatDate(this.#x509.validFromDate);
  }

  /** Gets the date until which the certificate is valid, in UTC
  (`YYYY-MM-DDThh:mm:ssZ`). */
  getValidTo(): string {
    return formatDate(this.#x509.validToDate);
  }

  /** Indicates whether the certificate is out of date at the current date. */
  isOutOfDate(): boolean {
    const now = Math.floor(Date.now() / 1000);
    return now < seconds(this.#x509.validFromDate) || now > seconds(this.#x509.validToDate);
  }

  /**
   * Indicates whether the key usage of the certificate allows it to sign
   * data: the key usage extension, when the certificate has one, must allow
   * "digitalSignature" or "nonRepudiation". A certificate without this
   * extension is not restricted.
   */
  canSign(): boolean {
    return this.#keyUsage === null
      || this.#keyUsage[KEY_USAGE_BITS.digitalSignature] === true
      || this.#keyUsage[KEY_USAGE_BITS.nonRepudiation] === true;
  }

  /**
   * Checks that the certificate is trusted: its chain is built and verified
   * up to a self-signed certificate of the given CA certificates, with the
   * rules OpenSSL applies for the PHP library (`openssl_x509_checkpurpose()`,
   * purpose "any").
   *
   * Every given certificate is trusted, and the chain is built from these
   * certificates only (and the `untrusted` ones), never from those of the
   * system. A certificate is
   * taken as the issuer of another one when its subject is the issuer of the
   * other one (names compared in the canonical form of OpenSSL), when the
   * authority key identifier of the other one matches it, and when its key
   * suits the signature algorithm of the other one. Then:
   *
   * - OpenSSL verifies the signature of each link (but the root's own);
   * - every certificate of the chain, the root included, is valid at the
   *   current date (or at `at`);
   * - every issuer is a CA: basic constraints with "CA:TRUE" and, if it has
   *   a key usage, "keyCertSign"; the root may also be a CA by its key usage
   *   alone, or by being self-signed and of version 1;
   * - the path length of each CA is respected;
   * - no certificate has a critical extension the verification does not
   *   handle, nor a repeated or malformed extension.
   *
   * A chain that stops at an intermediate CA is rejected: to trust the
   * certificates issued by an intermediate CA, give its certificate and the
   * certificates up to its root. A certificate issued by another
   * intermediate CA of the same root is then rejected, since the chain
   * cannot be built without that other intermediate certificate.
   *
   * Name constraints are not enforced: a CA certificate that has them is
   * rejected, where OpenSSL would enforce them.
   *
   * @param caCerts The CA certificates: paths of PEM files, or PEM contents,
   *     each of which may hold several certificates.
   * @param options `untrusted`: certificates the chain may be built with,
   *     after the CA certificates, without being trusted (the intermediate
   *     CAs a signature embeds): the root must still be one of the CA
   *     certificates. `at`: the date the certificates must be valid at,
   *     instead of the current date.
   * @returns True if the chain of the certificate has been verified.
   * @throws {Error} If a CA certificate file cannot be read.
   */
  isTrustedBy(caCerts: PemSource | PemSource[], options: { untrusted?: readonly X509Cert[]; at?: Date } = {}): boolean {
    return this.getTrustedChain(caCerts, options) !== null;
  }

  /**
   * The chain `isTrustedBy()` verifies, from this certificate to its root,
   * or null if the certificate is not trusted.
   *
   * @throws {Error} If a CA certificate file cannot be read.
   */
  getTrustedChain(caCerts: PemSource | PemSource[], options: { untrusted?: readonly X509Cert[]; at?: Date } = {}): X509Cert[] | null {
    const sources: unknown[] = Array.isArray(caCerts) ? caCerts : [caCerts];
    if (sources.length === 0) {
      throw new Error('No CA certificate file to verify the certificate chain!');
    }
    const trusted: X509Cert[] = [];
    for (const source of sources) {
      const pem = readPem(source);
      if (pem === null) {
        throw new Error(`Cannot read CA certificate file! File: ${describeSource(source)}`);
      }
      // A file OpenSSL cannot load as a whole trusts nothing.
      const blocks = pem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g);
      if (blocks === null) {
        return null;
      }
      for (const block of blocks) {
        try {
          trusted.push(new X509Cert(block));
        } catch {
          return null;
        }
      }
    }

    const time = Math.floor((options.at ?? new Date()).getTime() / 1000);
    const chain = this.#buildChain(trusted, options.untrusted ?? [], time);
    return chain !== null && X509Cert.#verifyChain(chain, time) ? chain : null;
  }

  /** The DER encoding of the certificate. */
  getDer(): Buffer {
    return Buffer.from(this.#x509.raw);
  }

  /** The public key of the certificate. */
  getPublicKey(): KeyObject {
    return this.#x509.publicKey;
  }

  /** The serial number, as unsigned big-endian bytes. */
  getSerialNumber(): Buffer {
    const serial = this.#serial;
    return serial.length > 1 && serial[0] === 0 ? Buffer.from(serial.subarray(1)) : Buffer.from(serial);
  }

  /** The DER encoding of the issuer name, as a CRL names its issuer. */
  getRawIssuer(): Buffer {
    return this.#rawName(2);
  }

  /** The DER encoding of the subject name. */
  getRawSubject(): Buffer {
    return this.#rawName(4);
  }

  /** An extension, by its OID: its criticality and its value (the content of its OCTET STRING), or null. */
  getExtension(oid: string): {
    /** Whether the extension is critical. */
    critical: boolean;
    /** The DER of its value, the content of its OCTET STRING. */
    value: Buffer;
  } | null {
    const extension = this.#extensions.get(oid);
    return extension === undefined ? null : { critical: extension.critical, value: Buffer.from(extension.value) };
  }

  /** Whether the key usage of the certificate, if it has one, allows it to sign CRLs. */
  canSignCrls(): boolean {
    return this.#keyUsage === null || this.#keyUsage[KEY_USAGE_BITS.cRLSign] === true;
  }

  /** Whether the certificate is a CA by its basic constraints. */
  isCA(): boolean {
    return this.#basicConstraints?.ca === true;
  }

  /** The DER of a field of the TBSCertificate (serialNumber 0, signature 1, issuer 2, validity 3, subject 4), the version left out. */
  #rawName(index: number): Buffer {
    const tbs = childrenOf(childrenOf(readElement(this.#x509.raw), TAG.SEQUENCE)[0] as Element, TAG.SEQUENCE);
    const fields = tbs[0]?.tag === 0xa0 ? tbs.slice(1) : tbs;
    const field = fields[index] as Element;
    return encode(field.tag, field.content);
  }

  /**
   * Checks the origin of the certificate: it was issued by the given CA
   * certificate. The CA certificate must be a CA ("CA:TRUE" basic
   * constraint and, if it has a key usage, "keyCertSign"), the issuer of
   * the certificate must have the fields of the subject of the CA
   * certificate, and OpenSSL must verify the signature of the certificate
   * with the key of the CA certificate.
   *
   * Only this link is checked: neither the validity dates nor the chain of
   * the CA certificate. Use `isTrustedBy()` to verify the whole chain.
   *
   * @param caCert The CA certificate, in PEM format (its content).
   * @throws {Error} If the CA certificate cannot be read.
   */
  isValidCA(caCert: string | Uint8Array): boolean {
    let ca: X509Cert;
    try {
      ca = new X509Cert(caCert);
    } catch {
      throw new Error('Invalid CA certificate!');
    }
    if (ca.#basicConstraints?.ca !== true) {
      return false;
    }
    if (ca.#keyUsage !== null && ca.#keyUsage[KEY_USAGE_BITS.keyCertSign] !== true) {
      return false;
    }
    if (JSON.stringify(this.getIssuer()) !== JSON.stringify(ca.getSubject())) {
      return false;
    }
    return this.#x509.verify(ca.#x509.publicKey);
  }

  /**
   * Converts a PEM encoded X.509 certificate to its DER encoding: the
   * base64 content of its first `CERTIFICATE` block, decoded. Characters
   * out of the base64 alphabet are ignored, as by the PHP library.
   *
   * @param pemCertificate PEM encoded X.509 certificate.
   * @returns The DER encoded certificate, or null if the parameter is not a
   *     string or holds no `-----BEGIN CERTIFICATE-----` line.
   */
  static pemToDer(pemCertificate: unknown): Buffer | null {
    if (typeof pemCertificate !== 'string') {
      return null;
    }
    const parts = pemCertificate.split(/-----(?:BEGIN|END) CERTIFICATE-----/);
    if (parts.length < 2) {
      return null;
    }
    return Buffer.from(parts[1] as string, 'base64');
  }

  /**
   * Converts a DER encoded X.509 certificate to its PEM encoding, with lines
   * of 64 base64 characters (RFC 7468, as OpenSSL writes them).
   *
   * @param derCertificate DER encoded X.509 certificate.
   * @returns The PEM encoded certificate, or null if the parameter is not
   *     bytes.
   */
  static derToPem(derCertificate: unknown): string | null {
    if (!(derCertificate instanceof Uint8Array)) {
      return null;
    }
    const base64 = Buffer.from(derCertificate.buffer, derCertificate.byteOffset, derCertificate.byteLength).toString('base64');
    return `-----BEGIN CERTIFICATE-----\n${base64.match(/.{1,64}/g)?.join('\n') ?? ''}\n-----END CERTIFICATE-----\n`;
  }

  /**
   * Builds the chain of the certificate from the trusted certificates, as
   * OpenSSL does: from the certificate, take as issuer the first trusted
   * certificate, then the first untrusted one, that may have issued it and
   * is valid at the given time (or else the last one that may have issued
   * it), until a self-signed certificate, which must be a trusted one.
   *
   * @param time The time of the verification, in seconds.
   * @returns The chain, from this certificate to its root, or null.
   */
  #buildChain(trusted: X509Cert[], untrusted: readonly X509Cert[], time: number): X509Cert[] | null {
    const known = [...trusted, ...untrusted];
    const chain: X509Cert[] = [this];
    for (;;) {
      const last = chain[chain.length - 1] as X509Cert;
      if (last.#isSelfSigned()) {
        return trusted.some((cert) => cert.#x509.raw.equals(last.#x509.raw)) ? chain : null;
      }
      if (chain.length >= MAX_CHAIN_LENGTH) {
        return null;
      }
      const candidates = known.filter((cert) => last.#mayBeIssuedBy(cert));
      const issuer = candidates.find((cert) => cert.#isValidAt(time)) ?? candidates[candidates.length - 1];
      if (issuer === undefined) {
        return null;
      }
      chain.push(issuer);
    }
  }

  /**
   * Verifies a chain built by `#buildChain()`, as OpenSSL does (see
   * `isTrustedBy()`).
   */
  static #verifyChain(chain: X509Cert[], now: number): boolean {
    let pathLength = 0;
    for (let i = 0; i < chain.length; i++) {
      const cert = chain[i] as X509Cert;

      if (now < seconds(cert.#x509.validFromDate) || now >= seconds(cert.#x509.validToDate)) {
        return false;
      }
      const issuer = chain[i + 1];
      if (issuer !== undefined && !cert.#x509.verify(issuer.#x509.publicKey)) {
        return false;
      }

      if (cert.#hasInvalidExtension) {
        return false;
      }
      for (const [oid, extension] of cert.#extensions) {
        if (extension.critical && !HANDLED_CRITICAL_EXTENSIONS.has(oid)) {
          return false;
        }
      }
      if (i === 0) {
        continue;
      }

      if (cert.#extensions.has(OID.NAME_CONSTRAINTS)) {
        return false;
      }
      // An intermediate CA must be one by its basic constraints; the root
      // may be one otherwise.
      const kind = cert.#caKind();
      if (kind === 0 || (i + 1 < chain.length && kind !== 1)) {
        return false;
      }
      // The path length of a CA counts the CAs below it, but the
      // self-issued ones.
      const limit = cert.#basicConstraints?.pathLength ?? null;
      if (i > 1 && limit !== null && pathLength > limit) {
        return false;
      }
      if (!cert.#isSelfIssued()) {
        pathLength++;
      }
    }
    return true;
  }

  /**
   * Indicates whether the certificate may have been issued by another one,
   * as OpenSSL tells it to build a chain (`ossl_x509_likely_issued()`): the
   * issuer of the certificate is the subject of the other one, its
   * authority key identifier, if any, matches the other one, and the key of
   * the other one suits its signature algorithm. Neither the signature nor
   * the key usage of the other one are checked here.
   */
  #mayBeIssuedBy(issuer: X509Cert): boolean {
    if (this.#hasInvalidExtension || issuer.#hasInvalidExtension) {
      return false;
    }
    if (!sameName(this.#issuer, issuer.#subject)) {
      return false;
    }
    const akid = this.#authorityKeyId;
    if (akid !== null) {
      if (akid.keyId !== null && issuer.#subjectKeyId !== null && !akid.keyId.equals(issuer.#subjectKeyId)) {
        return false;
      }
      if (akid.serial !== null && !akid.serial.equals(issuer.#serial)) {
        return false;
      }
      if (akid.issuer !== null && !sameName(akid.issuer, issuer.#issuer)) {
        return false;
      }
    }
    const keyType = issuer.#x509.publicKey.asymmetricKeyType;
    return keyType !== undefined && (SIGNATURE_KEY_TYPES[this.#signatureAlgorithm] ?? []).includes(keyType);
  }

  /** Indicates whether the certificate is self-signed, as OpenSSL tells it
  (its signature is not verified). */
  #isSelfSigned(): boolean {
    return this.#mayBeIssuedBy(this);
  }

  /** Indicates whether the certificate is self-issued: its subject is its
  issuer, whatever key signed it. */
  #isSelfIssued(): boolean {
    return sameName(this.#issuer, this.#subject);
  }

  /** Indicates whether the certificate is valid at a time (in seconds), as
  OpenSSL tells it: it is no longer valid at its very date of expiry. */
  #isValidAt(time: number): boolean {
    return time >= seconds(this.#x509.validFromDate) && time < seconds(this.#x509.validToDate);
  }

  /**
   * Indicates how the certificate is a CA, as OpenSSL does
   * (`X509_check_ca()`): 0 if it is not, 1 by its basic constraints, 3 by
   * being self-signed and of version 1, 4 by its key usage alone.
   */
  #caKind(): number {
    if (this.#keyUsage !== null && this.#keyUsage[KEY_USAGE_BITS.keyCertSign] !== true) {
      return 0;
    }
    if (this.#basicConstraints !== null) {
      return this.#basicConstraints.ca ? 1 : 0;
    }
    if (this.#version === 1 && this.#isSelfSigned()) {
      return 3;
    }
    return this.#keyUsage !== null ? 4 : 0;
  }
}

/** Reads a name (a sequence of sets of fields). */
function readName(element: Element): Name {
  const entries: NameEntry[] = [];
  childrenOf(element, TAG.SEQUENCE).forEach((rdn, set) => {
    for (const attribute of childrenOf(rdn, TAG.SET)) {
      const [type, value, ...rest] = childrenOf(attribute, TAG.SEQUENCE);
      if (type === undefined || value === undefined || rest.length > 0) {
        throw new Error('DER: malformed name.');
      }
      entries.push({ oid: decodeOid(type), tag: value.tag, value: value.content, set });
    }
  });
  return { entries, canonical: canonicalName(entries) };
}

/** Indicates whether two names are the same name, as OpenSSL compares them
(`X509_NAME_cmp()`). */
function sameName(a: Name, b: Name): boolean {
  return a.canonical !== null && a.canonical === b.canonical;
}

/**
 * The canonical form of a name, as OpenSSL compares names
 * (`x509_name_canon()`): the values of the string types converted to UTF-8,
 * without leading and trailing white space, each run of white space
 * collapsed into one space, ASCII letters in lowercase; the values of other
 * types kept as they are, with their type. The fields of an RDN are
 * compared as a set. Null if a value cannot be converted.
 */
function canonicalName(entries: NameEntry[]): string | null {
  const rdns: string[][] = [];
  for (const entry of entries) {
    let value: string;
    if (CANONICAL_STRING_TAGS.has(entry.tag)) {
      const utf8 = toUtf8(entry);
      if (utf8 === null) {
        return null;
      }
      value = `s:${Buffer.from(canonicalString(utf8), 'utf8').toString('hex')}`;
    } else {
      value = `${entry.tag}:${entry.value.toString('hex')}`;
    }
    (rdns[entry.set] ??= []).push(`${entry.oid}=${value}`);
  }
  return rdns.map((rdn) => rdn.sort().join('+')).join('/');
}

/** Trims, collapses the white space of, and lowercases a string, as
`asn1_string_canon()` does with the ASCII characters. */
function canonicalString(value: string): string {
  return value
    .replace(/^[ \t\n\v\f\r]+|[ \t\n\v\f\r]+$/g, '')
    .replace(/[ \t\n\v\f\r]+/g, ' ')
    .replace(/[A-Z]+/g, (letters) => letters.toLowerCase());
}

/** Reads the basic constraints. */
function readBasicConstraints(value: Buffer): { ca: boolean; pathLength: number | null } {
  let ca = false;
  let pathLength: number | null = null;
  for (const field of childrenOf(readElement(value), TAG.SEQUENCE)) {
    if (field.tag === TAG.BOOLEAN && pathLength === null) {
      ca = decodeBoolean(field);
    } else {
      pathLength = decodeSmallInteger(field);
    }
  }
  return { ca, pathLength };
}

/**
 * Reads the authority key identifier: [0] key identifier, [1] issuer (the
 * first directory name of the general names, as OpenSSL takes it), [2]
 * serial number of the issuer.
 */
function readAuthorityKeyId(value: Buffer): AuthorityKeyId {
  let keyId: Buffer | null = null;
  let issuer: Name | null = null;
  let serial: Buffer | null = null;
  for (const field of childrenOf(readElement(value), TAG.SEQUENCE)) {
    if (field.tag === 0x80) {
      keyId = field.content;
    } else if (field.tag === 0xa1) {
      const directoryName = readElements(field.content).find((name) => name.tag === 0xa4);
      issuer = directoryName === undefined ? null : readName(readElement(directoryName.content));
    } else if (field.tag === 0x82) {
      serial = field.content;
    } else {
      throw new Error('DER: malformed authority key identifier.');
    }
  }
  return { keyId, issuer, serial };
}

/** Reads the extensions, and tells whether one is repeated. */
function readExtensions(element: Element | undefined): { extensions: Map<string, Extension>; invalid: boolean } {
  const extensions = new Map<string, Extension>();
  let invalid = false;
  if (element === undefined) {
    return { extensions, invalid };
  }
  for (const extension of childrenOf(readElement(element.content), TAG.SEQUENCE)) {
    const fields = childrenOf(extension, TAG.SEQUENCE);
    const oid = decodeOid(fields[0] as Element);
    const critical = fields.length === 3 ? decodeBoolean(fields[1] as Element) : false;
    const value = fields[fields.length - 1] as Element;
    if (fields.length < 2 || fields.length > 3 || value.tag !== TAG.OCTET_STRING) {
      throw new Error('DER: malformed extension.');
    }
    if (extensions.has(oid)) {
      invalid = true;
    }
    extensions.set(oid, { critical, value: value.content });
  }
  return { extensions, invalid };
}

/**
 * Converts the value of a field to UTF-8, as OpenSSL does
 * (`ASN1_STRING_to_UTF8()`), or gives null for a type it does not convert.
 */
function toUtf8(entry: NameEntry): string | null {
  switch (entry.tag) {
    case TAG.UTF8_STRING:
      try {
        return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(entry.value);
      } catch {
        return null;
      }
    case TAG.NUMERIC_STRING:
    case TAG.PRINTABLE_STRING:
    case TAG.T61_STRING:
    case TAG.IA5_STRING:
    case TAG.UTC_TIME:
    case TAG.GENERALIZED_TIME:
    case TAG.VISIBLE_STRING:
      return entry.value.toString('latin1');
    case TAG.BMP_STRING:
      return entry.value.length % 2 === 0 ? Buffer.from(entry.value).swap16().toString('utf16le') : null;
    case TAG.UNIVERSAL_STRING: {
      if (entry.value.length % 4 !== 0) {
        return null;
      }
      const codePoints: number[] = [];
      for (let i = 0; i < entry.value.length; i += 4) {
        codePoints.push(entry.value.readUInt32BE(i));
      }
      try {
        return String.fromCodePoint(...codePoints);
      } catch {
        return null;
      }
    }
    default:
      return null;
  }
}

/** The fields of a name, as PHP gives them (`openssl_x509_parse()`): by
short name ("UNDEF" for an attribute OpenSSL does not know), the values in
UTF-8, a repeated field as an array of its values. */
function nameFields(entries: NameEntry[]): NameFields {
  const fields: NameFields = {};
  for (const entry of entries) {
    const value = toUtf8(entry);
    if (value === null) {
      continue;
    }
    const key = SHORT_NAMES[entry.oid] ?? 'UNDEF';
    const existing = fields[key];
    if (existing === undefined) {
      fields[key] = value;
    } else if (Array.isArray(existing)) {
      existing.push(value);
    } else {
      fields[key] = [existing, value];
    }
  }
  return fields;
}

/** A name in the OpenSSL "oneline" format (`X509_NAME_oneline()`, OpenSSL 3). */
function oneline(entries: NameEntry[]): string {
  let line = '';
  entries.forEach((entry, index) => {
    line += index > 0 && entries[index - 1]?.set === entry.set ? '+' : '/';
    line += `${SHORT_NAMES[entry.oid] ?? entry.oid}=`;
    const bytes = entry.value;
    // A GeneralString whose bytes are those of a UCS-4 string of ASCII
    // characters is written with one byte per character.
    let keep = (_index: number) => true;
    if (entry.tag === TAG.GENERAL_STRING && bytes.length % 4 === 0) {
      const nonZero = [false, false, false, false];
      bytes.forEach((byte, i) => {
        if (byte !== 0) {
          nonZero[i & 3] = true;
        }
      });
      if (!(nonZero[0] || nonZero[1] || nonZero[2])) {
        keep = (i) => (i & 3) === 3;
      }
    }
    bytes.forEach((byte, i) => {
      if (!keep(i)) {
        return;
      }
      if (byte === 0x2f || byte === 0x2b) {
        line += `\\${String.fromCharCode(byte)}`;
      } else if (byte < 0x20 || byte > 0x7e) {
        line += `\\x${byte.toString(16).toUpperCase().padStart(2, '0')}`;
      } else {
        line += String.fromCharCode(byte);
      }
    });
  });
  return line;
}

function seconds(date: Date): number {
  return Math.floor(date.getTime() / 1000);
}

function formatDate(date: Date): string {
  return date.toISOString().replace(/\.\d{3}Z$/, 'Z');
}

/** Indicates whether a name holds the expected fields: each with the very
same value, character case included; a repeated field is an array of its
values. */
export function matchesName(name: NameFields, expected: Record<string, string | string[]>): boolean {
  return Object.entries(expected).every(([key, value]) =>
    Object.hasOwn(name, key) && JSON.stringify(name[key]) === JSON.stringify(value));
}
