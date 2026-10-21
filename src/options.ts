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
import { describeSource, readPem, type PemSource } from './material.js';

/** The latest expiry the format of the timestamp can write
(9999-12-31T23:59:59Z), in seconds since the UNIX epoch. */
export const MAX_EXPIRY_TIME = 253402300799;

/**
 * The options of the four factories (see the README for each of them).
 */
export interface TokenOptions {
  base64Encode?: boolean;
  xmldsigNsPrefix?: string;
  audience?: string | string[];
  validity?: number;
  expectedAudience?: string;
  canonicalizationAlgorithm?: string;
  signatureAlgorithm?: string;
  digestAlgorithm?: string;
  checkSigningAlgorithms?: boolean;
  caCertPath?: PemSource | PemSource[];
  signerCertPath?: PemSource;
  expectedSubject?: string | Record<string, string | string[]>;
  sessionKeyCipheringAlgorithm?: string;
  cryptAlgorithm?: string;
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
