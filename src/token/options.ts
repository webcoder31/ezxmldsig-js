/*
 * Copyright © 2026 - Thierry Thiers <webcoder31@gmail.com>
 *
 * This software is governed by the CeCILL-C license under French law and
 * abiding by the rules of distribution of free software. You can use, modify
 * and/or redistribute the software under the terms of the CeCILL-C license as
 * circulated by CEA, CNRS and INRIA at the following URL:
 * http://www.cecill.info
 */

import { X509Certificate } from 'node:crypto';

import {
  AES128_CBC,
  AES128_GCM,
  AES192_CBC,
  AES192_GCM,
  AES256_CBC,
  AES256_GCM,
  C14N,
  C14N_COMMENTS,
  EXC_C14N,
  EXC_C14N_COMMENTS,
  RIPEMD160,
  RSA_OAEP_MGF1P,
  RSA_SHA1,
  RSA_SHA256,
  RSA_SHA384,
  RSA_SHA512,
  SHA1,
  SHA256,
  SHA384,
  SHA512,
  TRIPLEDES_CBC,
} from './algorithms.js';
import { describeSource, readPem, type PemSource } from '../core/material.js';

/** The latest expiry the format of the timestamp can write
(9999-12-31T23:59:59Z), in seconds since the UNIX epoch. */
export const MAX_EXPIRY_TIME = 253402300799;

/**
 * The options of the four factories.
 *
 * Each option applies to a context: token creation (`createXMLToken()`,
 * `createSecureXMLToken()`), token analysis (`analyzeXMLToken()`,
 * `analyzeSecureXMLToken()`), or both. The encryption options only apply
 * when an encryption certificate (creation) or a decryption key (analysis)
 * is given. An unknown option, an option given out of its context, or an
 * option whose value is null, undefined or invalid throws: none is ignored.
 *
 * The algorithm options apply to both contexts: at creation, they are the
 * algorithms the token is built with; at analysis, the algorithms the token
 * must have been built with. A token built with other algorithms is
 * rejected (`getError()` names them), unless `checkSigningAlgorithms` or
 * `checkCryptingAlgorithms` is false. Their values are the URIs of the
 * XMLDSIG and XML Encryption specifications, given by the constants of
 * `XMLDSigToken` (e.g. `XMLDSigToken.RSA_SHA512`).
 */
export interface TokenOptions {
  /**
   * Creation. Whether to encode the values of the data in base64 (marked
   * `Algorithm="base64"`). Default: true.
   */
  base64Encode?: boolean;

  /**
   * Creation. The namespace prefix of the elements of the signature; the
   * empty string for none. Default: `'ds'`.
   */
  xmldsigNsPrefix?: string;

  /**
   * Creation. The audience, or the list of audiences, the token is
   * addressed to: names of the receivers (an application name, a URL...),
   * agreed between the issuer and each receiver. Each one is a non-empty
   * string, without surrounding spaces nor control characters. They are
   * written in the token, covered by the signature (see `getAudience()`).
   * Default: none.
   */
  audience?: string | string[];

  /**
   * Creation. The number of seconds after which the token is out of date,
   * whatever the time to live the receiver gives to `isOutOfDate()`. The
   * expiry date is written in the token, covered by the signature (see
   * `getExpiry()`). Default: none (only the receiver sets the time to live).
   */
  validity?: number;

  /**
   * Analysis. The audience of this receiver, which the token must be
   * addressed to: `isSignatureValid()` returns false if the token names no
   * audience or does not name this one. A token that names audiences is
   * rejected when this option is not given. Compared as is, character case
   * included. Default: none.
   */
  expectedAudience?: string;

  /**
   * Creation and analysis. The canonicalization of `ds:SignedInfo`, and the
   * transform of the reference: `C14N` (default), `C14N_COMMENTS`,
   * `EXC_C14N` or `EXC_C14N_COMMENTS`.
   */
  canonicalizationAlgorithm?: string;

  /**
   * Creation and analysis. The signature algorithm: `RSA_SHA1`,
   * `RSA_SHA256` (default), `RSA_SHA384` or `RSA_SHA512`. A key transport
   * algorithm is refused.
   */
  signatureAlgorithm?: string;

  /**
   * Creation and analysis. The digest algorithm: `SHA1`, `SHA256`
   * (default), `SHA384`, `SHA512` or `RIPEMD160`.
   */
  digestAlgorithm?: string;

  /**
   * Analysis. Whether to check that the signature, digest and
   * canonicalization algorithms of the token are the expected ones. Even
   * when false, an algorithm out of the lists is rejected. Default: true.
   */
  checkSigningAlgorithms?: boolean;

  /**
   * Analysis. The trusted CA certificates: a PEM file or content, or a list
   * of them, each of which may hold several certificates. The chain of the
   * signing certificate must be verified up to a self-signed certificate of
   * them: give the issuing CA and the certificates up to its root. Default:
   * none. See the README, "Trust anchor".
   */
  caCertPath?: PemSource | PemSource[];

  /**
   * Analysis. The certificate the token must be signed with (pinning), as a
   * PEM file or content. Given alone, it is the trust anchor; given with
   * `caCertPath`, both are required. Default: none.
   */
  signerCertPath?: PemSource;

  /**
   * Analysis. The subject the signing certificate must have: an object of
   * the fields to check, as `getCertSubject()` gives them (`{ O: 'Lothbrok
   * Ltd', OU: 'Signature Dept' }`), or the full Distinguished Name, as
   * `getCertDN()` gives it. Character case is significant. It does not
   * replace a trust anchor. Default: none.
   */
  expectedSubject?: string | Record<string, string | string[]>;

  /**
   * Encryption (creation with an encryption certificate, analysis with a
   * decryption key). The symmetric algorithm of the data: `AES128_GCM`,
   * `AES192_GCM`, `AES256_GCM` (default), or the algorithms without
   * integrity `TRIPLEDES_CBC`, `AES128_CBC`, `AES192_CBC`, `AES256_CBC`,
   * which an analysis only decrypts when this option names them, even when
   * `checkCryptingAlgorithms` is false.
   */
  sessionKeyCipheringAlgorithm?: string;

  /**
   * Encryption (creation with an encryption certificate, analysis with a
   * decryption key). The key transport algorithm: `RSA_OAEP_MGF1P`
   * (default, and only one). RSA 1.5 is refused.
   */
  cryptAlgorithm?: string;

  /**
   * Analysis with a decryption key. Whether to check that the encryption
   * algorithms of the token are the expected ones. Even when false, an
   * algorithm out of the lists, or an undeclared CBC algorithm, is
   * rejected. Default: true.
   */
  checkCryptingAlgorithms?: boolean;
}

/**
 * The context each option applies to (see `checkOptions()`): token creation,
 * token analysis, both ("any"), encryption (creation with an encryption
 * certificate, or analysis with a decryption key) or decryption (analysis
 * with a decryption key).
 */
const OPTION_CONTEXTS: Readonly<Record<keyof TokenOptions, 'creation' | 'analysis' | 'any' | 'encryption' | 'decryption'>> = {
  base64Encode: 'creation',
  xmldsigNsPrefix: 'creation',
  audience: 'creation',
  validity: 'creation',
  expectedAudience: 'analysis',
  canonicalizationAlgorithm: 'any',
  signatureAlgorithm: 'any',
  digestAlgorithm: 'any',
  checkSigningAlgorithms: 'analysis',
  caCertPath: 'analysis',
  signerCertPath: 'analysis',
  expectedSubject: 'analysis',
  sessionKeyCipheringAlgorithm: 'encryption',
  cryptAlgorithm: 'encryption',
  checkCryptingAlgorithms: 'decryption',
};

/**
 * Checks the options given to a factory against what it is called for.
 *
 * Each option is only read in its context (see `OPTION_CONTEXTS`). A
 * misspelt option, or an option given out of its context, would be ignored
 * without notice and leave the token without the configuration the caller
 * asked for: it throws instead, as does an option whose value is null,
 * undefined or of the wrong type. The values of the algorithm and trust
 * options are checked where they are loaded.
 *
 * @param options The options.
 * @param isCreation True if a token is created, false if one is analyzed.
 * @param isEncryption True if an encryption certificate (token creation) or
 *     a decryption key (token analysis) is given.
 * @throws {Error} If an option is refused.
 */
export function checkOptions(options: unknown, isCreation: boolean, isEncryption: boolean): asserts options is TokenOptions {
  if (typeof options !== 'object' || options === null || Array.isArray(options)) {
    throw new Error("Invalid parameter 'options'! Parameter must be an object.");
  }

  for (const [name, value] of Object.entries(options)) {
    // Object.hasOwn(): a name of Object.prototype ("toString") is unknown.
    if (!Object.hasOwn(OPTION_CONTEXTS, name)) {
      throw new Error(`Unknown option '${name}'!`);
    }

    switch (OPTION_CONTEXTS[name as keyof TokenOptions]) {
      case 'creation':
        if (!isCreation) {
          throw new Error(`Option '${name}' only applies to token creation!`);
        }
        break;
      case 'analysis':
        if (isCreation) {
          throw new Error(`Option '${name}' only applies to token analysis! A created token is checked with the certificate of its own signing key.`);
        }
        break;
      case 'encryption':
        if (!isEncryption) {
          throw new Error(`Option '${name}' only applies to an encrypted token! Give the encryption certificate (createSecureXMLToken()) or the decryption key (analyzeSecureXMLToken()).`);
        }
        break;
      case 'decryption':
        if (isCreation || !isEncryption) {
          throw new Error(`Option '${name}' only applies to the analysis of an encrypted token! Give the decryption key (analyzeSecureXMLToken()).`);
        }
        break;
      case 'any':
        break;
    }

    if (value === null || value === undefined) {
      throw new Error(`Invalid option '${name}'! Its value must not be null or undefined.`);
    }

    if (['base64Encode', 'checkSigningAlgorithms', 'checkCryptingAlgorithms'].includes(name) && typeof value !== 'boolean') {
      throw new Error(`Invalid option '${name}'! It must be a boolean.`);
    }

    if (name === 'xmldsigNsPrefix' && typeof value !== 'string') {
      throw new Error(`Invalid option '${name}'! It must be a string.`);
    }

    if (name === 'audience') {
      const audiences: unknown[] = Array.isArray(value) ? value : [value];
      if (audiences.length === 0 || !audiences.every(isValidAudience)) {
        throw new Error("Invalid option 'audience'! It must be a non-empty string, or a non-empty list of them, without control characters.");
      }
      if (new Set(audiences).size !== audiences.length) {
        throw new Error("Invalid option 'audience'! An audience is given twice.");
      }
    }

    if (name === 'expectedAudience' && !isValidAudience(value)) {
      throw new Error("Invalid option 'expectedAudience'! It must be a non-empty string without control characters.");
    }

    if (name === 'validity' && !(Number.isSafeInteger(value) && (value as number) > 0)) {
      throw new Error("Invalid option 'validity'! It must be a number of seconds greater than 0.");
    }

    // The expiry is written with a four-digit year: a validity that takes
    // it past the year 9999 could not be written.
    if (name === 'validity' && (value as number) > MAX_EXPIRY_TIME - Math.floor(Date.now() / 1000)) {
      throw new Error("Invalid option 'validity'! The expiry would be after 9999-12-31T23:59:59Z.");
    }
  }
}

/**
 * Indicates whether a value can be an audience of a token (options
 * "audience" and "expectedAudience"): a non-empty string, without
 * surrounding spaces, made of characters XML 1.0 can hold as text.
 *
 * Control characters are refused: XML 1.0 cannot hold most of them, and the
 * others (tab, line feed, carriage return) are normalized by XML parsers, so
 * that the audience read back would differ from the one written. So are
 * U+FFFE and U+FFFF, which XML 1.0 cannot hold either, and lone surrogates,
 * which are not characters.
 *
 * @param audience The value to check.
 * @returns True if the value can be an audience.
 */
export function isValidAudience(audience: unknown): audience is string {
  return typeof audience === 'string'
    && audience !== ''
    && !audience.startsWith(' ')
    && !audience.endsWith(' ')
    && audience.isWellFormed()
    && !/[\x00-\x1F\x7F￾￿]/.test(audience);
}

/**
 * The trust anchor of an analysis (options "caCertPath", "signerCertPath"
 * and "expectedSubject").
 */
export interface TrustOptions {
  /** The PEM contents of the trusted CA certificates, or null. */
  caCerts: string[] | null;
  /** The pinned signing certificate, in PEM format, or null. */
  pinnedSignerCert: string | null;
  /** The subject expected for the signing certificate, or null. */
  expectedSubject: string | Record<string, string | string[]> | null;
}

/**
 * Loads and checks the trust options of an analysis.
 *
 * A trust option of the wrong type, or naming a file that cannot be read,
 * throws instead of being ignored: ignoring it would leave the token without
 * the constraint the caller asked for. Their absence is not an error here:
 * the analysis then reports that no certificate can be trusted.
 *
 * @param options The options, already checked by `checkOptions()`.
 * @throws {Error} If a trust option is refused.
 */
export function loadTrustOptions(options: TokenOptions): TrustOptions {
  const trust: TrustOptions = { caCerts: null, pinnedSignerCert: null, expectedSubject: null };

  if (options.caCertPath !== undefined) {
    const sources: unknown[] = Array.isArray(options.caCertPath) ? options.caCertPath : [options.caCertPath];
    if (sources.length === 0) {
      throw new Error("Invalid option 'caCertPath'! It must be a path or a non-empty list of paths.");
    }
    trust.caCerts = sources.map((source) => {
      const pem = readPem(source);
      if (pem === null) {
        throw new Error(`Invalid option 'caCertPath'! Cannot read CA certificate file: ${describeSource(source)}.`);
      }
      return pem;
    });
  }

  if (options.signerCertPath !== undefined) {
    const pem = readPem(options.signerCertPath);
    if (pem === null || !isCertificate(pem)) {
      throw new Error("Invalid option 'signerCertPath'! Cannot read the pinned X.509 certificate.");
    }
    trust.pinnedSignerCert = pem;
  }

  if (options.expectedSubject !== undefined) {
    const expected: unknown = options.expectedSubject;
    const isSubject = typeof expected === 'string'
      ? expected !== ''
      : typeof expected === 'object' && expected !== null && !Array.isArray(expected) && Object.keys(expected).length > 0;
    if (!isSubject) {
      throw new Error("Invalid option 'expectedSubject'! It must be a non-empty string or object.");
    }
    trust.expectedSubject = options.expectedSubject;
  }

  return trust;
}

/** Indicates whether a PEM content holds an X.509 certificate. */
function isCertificate(pem: string): boolean {
  try {
    new X509Certificate(pem);
    return true;
  } catch {
    return false;
  }
}

/* Algorithm lists. A value of another type than string is in none. */

/** Indicates whether an algorithm canonicalizes XML. */
export function isValidCanonicalizationAlgorithm(algorithm: unknown): algorithm is string {
  return [C14N, C14N_COMMENTS, EXC_C14N, EXC_C14N_COMMENTS].includes(algorithm as string);
}

/** Indicates whether an algorithm computes a digest. */
export function isValidHashAlgorithm(algorithm: unknown): algorithm is string {
  return [SHA1, SHA256, SHA384, SHA512, RIPEMD160].includes(algorithm as string);
}

/**
 * Indicates whether an algorithm signs the node "ds:SignedInfo".
 *
 * Signature and key transport algorithms (see
 * `isValidKeyTransportAlgorithm()`) are both asymmetric, but each list only
 * holds its own: a key transport algorithm is not a signature algorithm, and
 * the reverse.
 */
export function isValidSignatureAlgorithm(algorithm: unknown): algorithm is string {
  return [RSA_SHA1, RSA_SHA256, RSA_SHA384, RSA_SHA512].includes(algorithm as string);
}

/**
 * Indicates whether an algorithm encrypts the session key that encrypts the
 * token (key transport).
 *
 * RSA 1.5 (PKCS #1 v1.5 padding) is not valid, neither to create nor to
 * analyze a token: whether the padding of a submitted session key is valid
 * can be told from the decryption (Bleichenbacher), which lets an attacker
 * who can submit altered tokens decrypt a session key.
 */
export function isValidKeyTransportAlgorithm(algorithm: unknown): algorithm is string {
  return algorithm === RSA_OAEP_MGF1P;
}

/** Indicates whether an algorithm encrypts the token with the session key. */
export function isValidSymmetricCipheringAlgorithm(algorithm: unknown): algorithm is string {
  return [TRIPLEDES_CBC, AES128_CBC, AES192_CBC, AES256_CBC, AES128_GCM, AES192_GCM, AES256_GCM].includes(algorithm as string);
}

/**
 * Indicates whether a symmetric algorithm authenticates the data it
 * decrypts.
 *
 * AES-GCM checks an authentication tag before returning any decrypted data:
 * altered data fails as a whole. CBC has no integrity: altered data is
 * decrypted all the same, and how the decrypted content then fails
 * (padding, XML parsing) can tell an attacker who can submit altered tokens
 * what it holds (Jager-Somorovsky). A token encrypted with CBC is therefore
 * only decrypted if the analysis declares this algorithm (option
 * "sessionKeyCipheringAlgorithm"), whatever "checkCryptingAlgorithms".
 */
export function isAuthenticatedCipheringAlgorithm(algorithm: unknown): boolean {
  return [AES128_GCM, AES192_GCM, AES256_GCM].includes(algorithm as string);
}
