/*
 * Copyright © 2026 - Thierry Thiers <webcoder31@gmail.com>
 *
 * This software is governed by the CeCILL-C license under French law and
 * abiding by the rules of distribution of free software. You can use, modify
 * and/or redistribute the software under the terms of the CeCILL-C license as
 * circulated by CEA, CNRS and INRIA at the following URL:
 * http://www.cecill.info
 */

import { X509Certificate, createHash, createPrivateKey, createPublicKey, randomBytes, sign, verify, type KeyObject } from 'node:crypto';
import { inspect } from 'node:util';

import { XMLSerializer, type Document, type Element, type Node } from '@xmldom/xmldom';
import xpath from 'xpath';

import * as alg from './algorithms.js';
import { canonicalize } from './c14n.js';
import { escapeAttribute, escapeText, formatTokenDate, isXmlName, parseTokenDate, phpBase64Decode } from './encoding.js';
import { extractCertificates, readPem, type PemSource } from './material.js';
import {
  checkOptions,
  isAuthenticatedCipheringAlgorithm,
  isValidAudience,
  isValidCanonicalizationAlgorithm,
  isValidHashAlgorithm,
  isValidKeyTransportAlgorithm,
  isValidSignatureAlgorithm,
  isValidSymmetricCipheringAlgorithm,
  loadTrustOptions,
  type TokenOptions,
} from './options.js';
import { X509Cert, type NameFields, matchesName } from './x509.js';
import { loadXML, parseFragment } from './xml.js';
import { decryptKey, decryptSymmetric, encryptKey, encryptSymmetric, generateSessionKey } from './xmlenc.js';

/** A value of the token data: a leaf, or nested values. */
export type TokenValue = string | number | boolean | null | Uint8Array | TokenData;

/** The token data: named values, nested at will. */
export interface TokenData {
  [name: string]: TokenValue;
}

/** The token data as an analysis reads them: strings, or bytes when a
base64 value is not UTF-8 text, nested as they were written. */
export interface ReadTokenData {
  [name: string]: string | Buffer | ReadTokenData;
}

const TOKEN_NAME = 'Token';
const TOKEN_DATA_NAME = 'TokenData';
const TOKEN_TIMESTAMP_NAME = 'TokenTimestamp';
const TOKEN_ID_NAME = 'TokenId';
const TOKEN_ID_BYTES = 16;
const TOKEN_AUDIENCE_NAME = 'TokenAudience';
const TOKEN_EXPIRY_NAME = 'TokenExpiry';

/** The error of every failure that depends on the decrypted content. */
const DECRYPTION_FAILED = 'Token decryption failed!';

/** The node:crypto names of the digest algorithms. */
const HASHES: Readonly<Record<string, string>> = {
  [alg.SHA1]: 'sha1',
  [alg.SHA256]: 'sha256',
  [alg.SHA384]: 'sha384',
  [alg.SHA512]: 'sha512',
  [alg.RIPEMD160]: 'ripemd160',
};

/** The node:crypto names of the digests of the signature algorithms. */
const SIGNATURE_HASHES: Readonly<Record<string, string>> = {
  [alg.RSA_SHA1]: 'sha1',
  [alg.RSA_SHA256]: 'sha256',
  [alg.RSA_SHA384]: 'sha384',
  [alg.RSA_SHA512]: 'sha512',
};

/** The canonicalization a same-document reference ("#Token") is digested
with: without comments, whatever its transform says (as xmlseclibs does,
following XMLDSIG). */
const WITHOUT_COMMENTS: Readonly<Record<string, string>> = {
  [alg.C14N_COMMENTS]: alg.C14N,
  [alg.EXC_C14N_COMMENTS]: alg.EXC_C14N,
};

/** The algorithms xmlseclibs knows (`XMLSecurityKey`): the first
"xenc:EncryptionMethod" of an encrypted node must name one of them, or the
key it describes cannot be located. */
const XMLSECLIBS_ALGORITHMS: ReadonlySet<string> = new Set([
  alg.TRIPLEDES_CBC, alg.AES128_CBC, alg.AES192_CBC, alg.AES256_CBC, alg.AES128_GCM, alg.AES192_GCM, alg.AES256_GCM,
  `${alg.XMLENC_NS}rsa-1_5`, alg.RSA_OAEP_MGF1P, 'http://www.w3.org/2009/xmlenc11#rsa-oaep',
  'http://www.w3.org/2000/09/xmldsig#dsa-sha1', alg.RSA_SHA1, alg.RSA_SHA256, alg.RSA_SHA384, alg.RSA_SHA512,
  'http://www.w3.org/2000/09/xmldsig#hmac-sha1',
]);

const select = xpath.useNamespaces({ ds: alg.XMLDSIG_NS, xenc: alg.XMLENC_NS });

// xpath and xml-crypto declare the DOM types of the browser; xmldom, its
// own ones: the nodes are converted where they are passed.

/** The nodes an XPath expression selects. */
function nodes(expression: string, context: Node): Node[] {
  return select(expression, context as never) as unknown as Node[];
}

/** The string value of an XPath expression. */
function evaluate(expression: string, context: Node): string {
  return select(`string(${expression})`, context as never) as unknown as string;
}

/** The values `getPrettyXML()` splits into lines, the first node of each. */
const PRETTY_SPLIT_VALUES = [
  '//ds:Signature/ds:SignatureValue',
  '//ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate',
  '//ds:Signature/ds:Object/xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey/xenc:CipherData/xenc:CipherValue',
  '//ds:Signature/ds:Object/xenc:EncryptedData/xenc:CipherData/xenc:CipherValue',
];

/** The indentation step of `getPrettyXML()`. */
const PRETTY_INDENT = 2;

/**
 * Splits the value of the node an XPath expression selects into lines of
 * 64 characters, as `getPrettyXML()` of the PHP library does: the document
 * is loaded as a token is, the value replaced, and the document serialized
 * again as libxml does (`serializeAsLibxml()`). A document that cannot be
 * loaded, or has no such node, is returned unchanged; so is one whose value
 * is empty or "0", which PHP takes as false, except that the PHP library
 * then removes "&#xD;" from it all the same.
 */
function splitNodeValue(xml: string, expression: string): string {
  let doc: Document;
  try {
    doc = loadXML(xml, 'XML content');
  } catch {
    return xml;
  }
  const node = nodes(expression, doc)[0];
  if (node === undefined) {
    return xml;
  }
  const value = node.textContent ?? '';
  if (value !== '' && value !== '0') {
    node.textContent = '\n' + (value.match(/[\s\S]{1,64}/g) as string[]).join('\n') + '\n';
    xml = serializeAsLibxml(doc);
  }
  return xml.split('&#xD;').join('');
}

/**
 * Serializes a document as `saveXML()` of PHP (libxml) does: the XML
 * declaration, with the version, encoding and standalone of the document,
 * then each node of the document (the root element, and comments or
 * processing instructions around it) on a line of its own; the whitespace
 * between them is not kept. libxml writes the namespace declarations of an
 * element before its other attributes: they are moved so here, the
 * document being thrown away after.
 */
function serializeAsLibxml(doc: Document): string {
  const elements = nodes('//*', doc) as Element[];
  for (const element of elements) {
    const attributes = Array.from(element.attributes);
    const isDeclaration = (name: string) => name === 'xmlns' || name.startsWith('xmlns:');
    const firstDeclaration = attributes.findIndex((attribute) => isDeclaration(attribute.name));
    if (firstDeclaration > 0 && attributes.slice(0, firstDeclaration).some((attribute) => !isDeclaration(attribute.name))) {
      for (const attribute of attributes.filter((candidate) => !isDeclaration(candidate.name))) {
        element.removeAttributeNode(attribute);
        element.setAttributeNode(attribute);
      }
    }
  }
  const serializer = new XMLSerializer();
  let declaration = '<?xml version="1.0"?>\n';
  let body = '';
  for (let child = doc.firstChild; child !== null; child = child.nextSibling) {
    if (child.nodeType === child.PROCESSING_INSTRUCTION_NODE && child.nodeName === 'xml') {
      const data = child.nodeValue ?? '';
      const attribute = (name: string) => new RegExp(`${name}\\s*=\\s*(["'])([^"']*)\\1`).exec(data)?.[2];
      const version = attribute('version') ?? '1.0';
      const encoding = attribute('encoding');
      const standalone = attribute('standalone');
      declaration = `<?xml version="${version}"${encoding === undefined ? '' : ` encoding="${encoding}"`}`
        + `${standalone === undefined ? '' : ` standalone="${standalone}"`}?>\n`;
    } else if (child.nodeType !== child.TEXT_NODE) {
      body += serializer.serializeToString(child) + '\n';
    }
  }
  // Without a declared encoding, libxml writes ASCII: every other character
  // as a character reference.
  if (!declaration.includes(' encoding=')) {
    body = body.replace(/[^\x00-\x7F]/gu, (char) => `&#x${(char.codePointAt(0) as number).toString(16).toUpperCase()};`);
  }
  return declaration + body;
}

/** The empty() of PHP on a string: "" and "0" are empty. */
function isEmpty(value: string): boolean {
  return value === '' || value === '0';
}

/** Whether a node is an element. */
function isElement(node: Node | null | undefined): node is Element {
  return node !== null && node !== undefined && node.nodeType === node.ELEMENT_NODE;
}

/** Whether a node is a text node (not CDATA). */
function isText(node: Node | null | undefined): boolean {
  return node !== null && node !== undefined && node.nodeType === node.TEXT_NODE;
}

/**
 * An XML token: an enveloping XML digital signature that holds timestamped
 * user data, optionally encrypted. The counterpart of the class
 * `XMLDSigToken` of the PHP library ezxmldsig: both create and verify the
 * same tokens.
 *
 * Get an instance with one of the factories, `createXMLToken()` to create a
 * token, `analyzeXMLToken()` to analyze one. An analysis requires a trust
 * anchor (options `caCertPath` and/or `signerCertPath`): without it, no
 * token is valid.
 *
 * **`isSignatureValid()` checks neither the freshness of the token nor
 * whether it is replayed.** Before trusting the data of a received token,
 * the receiver must check that `isSignatureValid()` returns true, that
 * `isOutOfDate(ttl)` returns false, and that the identifier returned by
 * `getTokenId()` has not been accepted before (store it atomically, and
 * refuse the token if it already is).
 */
export class XMLDSigToken {
  /** The default XMLDSIG namespace prefix used in the XML digital signature. */
  static readonly XMLDSIG_NS_PREFIX = 'ds';
  /** The name of the token node. */
  static readonly TOKEN_NAME = TOKEN_NAME;
  /** The name of the token data node. */
  static readonly TOKEN_DATA_NAME = TOKEN_DATA_NAME;
  /** The name of the token timestamp node. */
  static readonly TOKEN_TIMESTAMP_NAME = TOKEN_TIMESTAMP_NAME;
  /** The name of the token identifier node. */
  static readonly TOKEN_ID_NAME = TOKEN_ID_NAME;
  /** The number of random bytes of the token identifier, written in
  hexadecimal (see `getTokenId()`). */
  static readonly TOKEN_ID_BYTES = TOKEN_ID_BYTES;
  /** The name of the node that holds one audience of the token. */
  static readonly TOKEN_AUDIENCE_NAME = TOKEN_AUDIENCE_NAME;
  /** The name of the token expiry node. */
  static readonly TOKEN_EXPIRY_NAME = TOKEN_EXPIRY_NAME;
  /** The format of the token timestamp, in the notation of PHP
  (YYYY-MM-DDThh:mm:ssZ, in UTC). */
  static readonly TOKEN_TIMESTAMP_FORMAT = 'Y-m-d\\TH:i:s\\Z';
  /** The default time to live (in seconds) used by `isOutOfDate()`. */
  static readonly TOKEN_DEFAULT_TTL = 60;
  /** The clock offset (in seconds) allowed by `isOutOfDate()` for a token
  whose timestamp is in the future. */
  static readonly DESYNC_TOLERANCE = 30;

  /** Inclusive canonicalization (default). */
  static readonly C14N = alg.C14N;
  /** Inclusive canonicalization, with comments. */
  static readonly C14N_COMMENTS = alg.C14N_COMMENTS;
  /** Exclusive canonicalization. */
  static readonly EXC_C14N = alg.EXC_C14N;
  /** Exclusive canonicalization, with comments. */
  static readonly EXC_C14N_COMMENTS = alg.EXC_C14N_COMMENTS;
  /** SHA-1. */
  static readonly SHA1 = alg.SHA1;
  /** SHA-256 (default). */
  static readonly SHA256 = alg.SHA256;
  /** SHA-384. */
  static readonly SHA384 = alg.SHA384;
  /** SHA-512. */
  static readonly SHA512 = alg.SHA512;
  /** RIPEMD-160. */
  static readonly RIPEMD160 = alg.RIPEMD160;
  /** Triple DES CBC, without integrity. */
  static readonly TRIPLEDES_CBC = alg.TRIPLEDES_CBC;
  /** AES-128-CBC, without integrity. */
  static readonly AES128_CBC = alg.AES128_CBC;
  /** AES-192-CBC, without integrity. */
  static readonly AES192_CBC = alg.AES192_CBC;
  /** AES-256-CBC, without integrity. */
  static readonly AES256_CBC = alg.AES256_CBC;
  /** AES-128-GCM. */
  static readonly AES128_GCM = alg.AES128_GCM;
  /** AES-192-GCM. */
  static readonly AES192_GCM = alg.AES192_GCM;
  /** AES-256-GCM (default). */
  static readonly AES256_GCM = alg.AES256_GCM;
  /** RSA-OAEP with MGF1-SHA1 (default key transport). */
  static readonly RSA_OAEP_MGF1P = alg.RSA_OAEP_MGF1P;
  /** RSA-SHA1. */
  static readonly RSA_SHA1 = alg.RSA_SHA1;
  /** RSA-SHA256 (default). */
  static readonly RSA_SHA256 = alg.RSA_SHA256;
  /** RSA-SHA384. */
  static readonly RSA_SHA384 = alg.RSA_SHA384;
  /** RSA-SHA512. */
  static readonly RSA_SHA512 = alg.RSA_SHA512;

  #xmldsigNsPrefix: string = XMLDSigToken.XMLDSIG_NS_PREFIX;
  #canonicalizationAlgorithm: string = alg.C14N;
  #signatureAlgorithm: string = alg.RSA_SHA256;
  #digestAlgorithm: string = alg.SHA256;
  #transformAlgorithm: string = alg.C14N;
  #checkSigningAlgorithms = true;
  #sessionKeyCipheringAlgorithm: string = alg.AES256_GCM;
  #cryptAlgorithm: string = alg.RSA_OAEP_MGF1P;
  #checkCryptingAlgorithms = true;

  #signKey: string | null = null;
  #signKeyPassword: string | null = null;
  #signCert: string | null = null;
  #cryptKey: string | null = null;
  #cryptKeyPassword: string | null = null;
  #cryptCert: string | null = null;

  #xml: string | null = null;
  #data: ReadTokenData | null = null;
  #base64EncodeData = true;
  #timestamp: string | null = null;
  #tokenId: string | null = null;
  #audienceToWrite: string[] | null = null;
  #audience: string[] | null = null;
  #validity: number | null = null;
  #expiry: string | null = null;
  #hasExpiryNode = false;
  #expectedAudience: string | null = null;

  #x509Certificate: X509Cert | null = null;
  #trustedCACerts: string[] | null = null;
  #pinnedSignerCert: string | null = null;
  #expectedSubject: string | Record<string, string | string[]> | null = null;
  #isCertTrusted: boolean | null = null;
  #isDataEncrypted: boolean | null = null;
  #isDigestValueOk: boolean | null = null;
  #isSignatureValueOk: boolean | null = null;
  #error: string | null = null;
  #anomalies: string[] = [];

  /**
   * Use the factories: `createXMLToken()`, `analyzeXMLToken()`.
   */
  private constructor(
    xmlOrData: unknown,
    isCreation: boolean,
    signKeyPath: unknown,
    signKeyPassword: unknown,
    signCertPath: unknown,
    cryptKeyPath: unknown,
    cryptKeyPassword: unknown,
    cryptCertPath: unknown,
    options: unknown,
  ) {
    const given = (value: unknown) => value !== null && value !== undefined;

    // Check the options against what the object is created for: an unknown
    // option, or an option that does not apply here, throws.
    checkOptions(options, isCreation, given(isCreation ? cryptCertPath : cryptKeyPath));

    if (options.canonicalizationAlgorithm !== undefined) {
      if (!isValidCanonicalizationAlgorithm(options.canonicalizationAlgorithm)) {
        throw new Error("Invalid parameter 'canonicalizationAlgorithm'! Unknown canonicalization algorithm.");
      }
      this.#canonicalizationAlgorithm = options.canonicalizationAlgorithm;
      this.#transformAlgorithm = options.canonicalizationAlgorithm;
    }
    if (options.signatureAlgorithm !== undefined) {
      if (!isValidSignatureAlgorithm(options.signatureAlgorithm)) {
        throw new Error("Invalid parameter 'signatureAlgorithm'! Unknown signature algorithm.");
      }
      this.#signatureAlgorithm = options.signatureAlgorithm;
    }
    if (options.digestAlgorithm !== undefined) {
      if (!isValidHashAlgorithm(options.digestAlgorithm)) {
        throw new Error("Invalid parameter 'digestAlgorithm'! Unknown digest algorithm.");
      }
      this.#digestAlgorithm = options.digestAlgorithm;
    }
    if (options.checkSigningAlgorithms === false) {
      this.#checkSigningAlgorithms = false;
    }

    if (isCreation) {
      const data = xmlOrData;
      if (typeof data !== 'object' || data === null || Array.isArray(data) || data instanceof Uint8Array) {
        throw new Error("Invalid parameter 'data'! Token data should be an object of named values.");
      }
      if (Object.keys(data).length === 0) {
        throw new Error("Invalid parameter 'data'! Token data should not be an empty object.");
      }
      checkData(data as TokenData);

      if (options.base64Encode === false) {
        this.#base64EncodeData = false;
      }
      if (options.audience !== undefined) {
        this.#audienceToWrite = Array.isArray(options.audience) ? [...options.audience] : [options.audience];
      }
      if (options.validity !== undefined) {
        this.#validity = options.validity;
      }

      if (!given(signKeyPath)) {
        throw new Error("Missing parameter 'signKeyPath'! A private key is required to sign token.");
      }
      if (!given(signCertPath)) {
        throw new Error("Missing parameter 'signCertPath'! An X.509 certificate is required to sign token.");
      }
      this.#signKey = readPem(signKeyPath);
      if (this.#signKey === null) {
        throw new Error("Invalid parameter 'signKeyPath'! Cannot read private key to sign token.");
      }
      if (given(signKeyPassword)) {
        if (typeof signKeyPassword !== 'string') {
          throw new Error("Invalid parameter 'signKeyPassword'! Parameter must be a string.");
        }
        this.#signKeyPassword = signKeyPassword;
      }
      this.#signCert = readPem(signCertPath);
      if (this.#signCert === null) {
        throw new Error("Invalid parameter 'signCertPath'! Cannot read X.509 certificate to sign token.");
      }

      // The created token is analyzed to check it: it must be signed with
      // this very certificate.
      this.#pinnedSignerCert = this.#signCert;

      if (options.xmldsigNsPrefix !== undefined) {
        this.#xmldsigNsPrefix = options.xmldsigNsPrefix;
      }

      if (given(cryptCertPath)) {
        this.#loadEncryptionParameters(cryptCertPath, cryptKeyPath, cryptKeyPassword, options);
      }

      try {
        this.#writeXML(data as TokenData);
      } catch (error) {
        this.#error = (error as Error).message;
      }
    } else {
      // Load the trust anchor. Its absence is not an error here: the
      // analysis then reports that no certificate can be trusted.
      const trust = loadTrustOptions(options);
      this.#trustedCACerts = trust.caCerts;
      this.#pinnedSignerCert = trust.pinnedSignerCert;
      this.#expectedSubject = trust.expectedSubject;

      if (options.expectedAudience !== undefined) {
        this.#expectedAudience = options.expectedAudience;
      }

      if (given(cryptKeyPath)) {
        this.#loadDecryptionParameters(cryptKeyPath, cryptKeyPassword, options);
      }

      try {
        this.#readXML(xmlOrData, false);
      } catch (error) {
        this.#error = (error as Error).message;
      }
    }
  }

  /**
   * Creates an XML token for the given user data.
   *
   * The created token is analyzed right away to check it, with the
   * certificate of its own signing key as trust anchor. If it cannot be
   * created, `getError()` tells why; a parameter or an option that is
   * refused throws.
   *
   * @param data The token data: named values, nested at will. A value is a
   *     string, a number, a boolean, null (written as an empty string), or
   *     bytes (a Uint8Array).
   * @param signKeyPath The private key that signs the token, in PEM format:
   *     the path of its file, or its content.
   * @param signCertPath The X.509 certificate of this key, in PEM format,
   *     included in the token: the path of its file, or its content.
   * @param signKeyPassword The password of the private key, if any.
   * @param options The options (see the README).
   */
  static createXMLToken(
    data: TokenData,
    signKeyPath: PemSource,
    signCertPath: PemSource,
    signKeyPassword: string | null = null,
    options: TokenOptions = {},
  ): XMLDSigToken {
    return new XMLDSigToken(data, true, signKeyPath, signKeyPassword, signCertPath, null, null, null, options);
  }

  /**
   * Analyzes an XML token.
   *
   * The options must hold a trust anchor, `caCertPath` and/or
   * `signerCertPath`; without it, `isSignatureValid()` returns false. If
   * the token is not valid, `getError()` tells why; an option that is
   * refused throws.
   *
   * @param xml The XML token, as a string or as the bytes of its UTF-8
   *     encoding.
   * @param options The options, trust anchor included (see the README).
   */
  static analyzeXMLToken(xml: string | Uint8Array, options: TokenOptions = {}): XMLDSigToken {
    return new XMLDSigToken(xml, false, null, null, null, null, null, null, options);
  }

  /**
   * Creates a signed token whose data are encrypted for the owner of the
   * encryption certificate: only the private key of this certificate
   * decrypts them. The sender does not need this private key: pass null as
   * `cryptKeyPath`.
   *
   * The created token is checked right away. Without `cryptKeyPath`, the
   * check covers everything that can be verified without decrypting the
   * token (structure, algorithms, digest, signature, trust in the signing
   * certificate): `isSignatureValid()` and `isDataEncrypted()` return true,
   * while `getData()`, `getTimestamp()`, `getTokenId()`, `getAudience()`
   * and `getExpiry()` return null. With `cryptKeyPath`, the token is also
   * decrypted and its content read.
   *
   * @param data The token data (see `createXMLToken()`).
   * @param signKeyPath The private key that signs the token, in PEM format.
   * @param signCertPath The X.509 certificate of this key, in PEM format.
   * @param cryptKeyPath The private key of the recipient, in PEM format, to
   *     check the content of the created token; null without it.
   * @param cryptCertPath The encryption certificate of the recipient, in
   *     PEM format.
   * @param signKeyPassword The password of the signing key, if any.
   * @param cryptKeyPassword The password of the private key of the
   *     recipient, if any (null without `cryptKeyPath`).
   * @param options The options (see the README).
   */
  static createSecureXMLToken(
    data: TokenData,
    signKeyPath: PemSource,
    signCertPath: PemSource,
    cryptKeyPath: PemSource | null,
    cryptCertPath: PemSource,
    signKeyPassword: string | null = null,
    cryptKeyPassword: string | null = null,
    options: TokenOptions = {},
  ): XMLDSigToken {
    // Without an encryption certificate, the token would not be encrypted.
    if (cryptCertPath === null || cryptCertPath === undefined) {
      throw new Error("Missing parameter 'cryptCertPath'! An X.509 certificate is required to encrypt token.");
    }
    return new XMLDSigToken(data, true, signKeyPath, signKeyPassword, signCertPath, cryptKeyPath, cryptKeyPassword, cryptCertPath, options);
  }

  /**
   * Analyzes an XML token whose data are encrypted, with the private key of
   * the recipient. An unencrypted token can also be analyzed this way.
   *
   * The token is only decrypted once its structure, its algorithms, its
   * digest, its signature and the trust in its certificate have been
   * verified, and every failure of the decryption gives the same error,
   * `Token decryption failed!`.
   *
   * @param xml The XML token, as a string or as the bytes of its UTF-8
   *     encoding.
   * @param cryptKeyPath The private key of the recipient, in PEM format:
   *     the path of its file, or its content.
   * @param cryptKeyPassword The password of this key, if any.
   * @param options The options, trust anchor included (see the README).
   */
  static analyzeSecureXMLToken(
    xml: string | Uint8Array,
    cryptKeyPath: PemSource,
    cryptKeyPassword: string | null = null,
    options: TokenOptions = {},
  ): XMLDSigToken {
    return new XMLDSigToken(xml, false, null, null, null, cryptKeyPath, cryptKeyPassword, null, options);
  }

  /**
   * Loads the encryption parameters of a token creation: the encryption
   * certificate, the private key of the recipient if given (only to check
   * the created token), and the encryption algorithms.
   */
  #loadEncryptionParameters(cryptCertPath: unknown, cryptKeyPath: unknown, cryptKeyPassword: unknown, options: TokenOptions): void {
    this.#cryptCert = readPem(cryptCertPath);
    if (this.#cryptCert === null) {
      throw new Error("Invalid parameter 'cryptCertPath'! Cannot read X.509 certificate to encrypt token.");
    }
    if (cryptKeyPath !== null && cryptKeyPath !== undefined) {
      this.#cryptKey = readPem(cryptKeyPath);
      if (this.#cryptKey === null) {
        throw new Error("Invalid parameter 'cryptKeyPath'! Cannot read private key to decrypt token.");
      }
    }
    // A password without a key would be ignored: it throws instead.
    if (cryptKeyPassword !== null && cryptKeyPassword !== undefined) {
      if (cryptKeyPath === null || cryptKeyPath === undefined) {
        throw new Error("Invalid parameter 'cryptKeyPassword'! It only applies with the parameter 'cryptKeyPath'.");
      }
      if (typeof cryptKeyPassword !== 'string') {
        throw new Error("Invalid parameter 'cryptKeyPassword'! Parameter must be a string.");
      }
      this.#cryptKeyPassword = cryptKeyPassword;
    }
    this.#loadEncryptionAlgorithms(options);
  }

  /**
   * Loads the decryption parameters of a token analysis: the private key of
   * the recipient, and the expected encryption algorithms.
   */
  #loadDecryptionParameters(cryptKeyPath: unknown, cryptKeyPassword: unknown, options: TokenOptions): void {
    this.#cryptKey = readPem(cryptKeyPath);
    if (this.#cryptKey === null) {
      throw new Error("Invalid parameter 'cryptKeyPath'! Cannot read private key to decrypt token.");
    }
    if (cryptKeyPassword !== null && cryptKeyPassword !== undefined) {
      if (typeof cryptKeyPassword !== 'string') {
        throw new Error("Invalid parameter 'cryptKeyPassword'! Parameter must be a string.");
      }
      this.#cryptKeyPassword = cryptKeyPassword;
    }
    this.#loadEncryptionAlgorithms(options);
  }

  /** Loads the options of the encryption algorithms. */
  #loadEncryptionAlgorithms(options: TokenOptions): void {
    if (options.sessionKeyCipheringAlgorithm !== undefined) {
      if (!isValidSymmetricCipheringAlgorithm(options.sessionKeyCipheringAlgorithm)) {
        throw new Error("Invalid parameter 'sessionKeyCipheringAlgorithm'! Unknown session key ciphering algorithm.");
      }
      this.#sessionKeyCipheringAlgorithm = options.sessionKeyCipheringAlgorithm;
    }
    if (options.cryptAlgorithm !== undefined) {
      if (!isValidKeyTransportAlgorithm(options.cryptAlgorithm)) {
        throw new Error("Invalid parameter 'cryptAlgorithm'! Unknown crypt algorithm.");
      }
      this.#cryptAlgorithm = options.cryptAlgorithm;
    }
    if (options.checkCryptingAlgorithms === false) {
      this.#checkCryptingAlgorithms = false;
    }
  }

  /**
   * Writes the XML digital signature of the token for the given data, as
   * the PHP library writes it (the same layout, byte for byte, but for the
   * values), then analyzes it to check it.
   */
  #writeXML(data: TokenData): void {
    const now = Math.floor(Date.now() / 1000);

    let token = `<${TOKEN_NAME}${this.#xmldsigNsPrefix === '' ? ' xmlns=""' : ''}>`;
    token += `<${TOKEN_TIMESTAMP_NAME}>${formatTokenDate(now)}</${TOKEN_TIMESTAMP_NAME}>`;
    token += `<${TOKEN_ID_NAME}>${randomBytes(TOKEN_ID_BYTES).toString('hex')}</${TOKEN_ID_NAME}>`;
    if (this.#validity !== null) {
      token += `<${TOKEN_EXPIRY_NAME}>${formatTokenDate(now + this.#validity)}</${TOKEN_EXPIRY_NAME}>`;
    }
    for (const audience of this.#audienceToWrite ?? []) {
      token += `<${TOKEN_AUDIENCE_NAME}>${escapeText(audience)}</${TOKEN_AUDIENCE_NAME}>`;
    }
    token += writeData(TOKEN_DATA_NAME, data, this.#base64EncodeData);
    token += `</${TOKEN_NAME}>`;

    const p = this.#xmldsigNsPrefix === '' ? '' : `${this.#xmldsigNsPrefix}:`;

    // The node "Token" is encrypted if an encryption certificate is given:
    // the node "xenc:EncryptedData", of type Element, replaces it, with the
    // session key encrypted for the recipient in its "ds:KeyInfo".
    let objectContent = token;
    if (this.#cryptCert !== null) {
      let publicKey: KeyObject;
      try {
        publicKey = new X509Certificate(this.#cryptCert).publicKey;
      } catch {
        throw new Error('Unable to extract public key');
      }
      const sessionKey = generateSessionKey(this.#sessionKeyCipheringAlgorithm);
      let encryptedKey: Buffer;
      try {
        encryptedKey = encryptKey(publicKey, sessionKey);
      } catch {
        throw new Error('Failure encrypting Data (openssl public)');
      }
      const encryptedData = encryptSymmetric(this.#sessionKeyCipheringAlgorithm, sessionKey, Buffer.from(token, 'utf8'));
      objectContent = `<xenc:EncryptedData xmlns:xenc="${alg.XMLENC_NS}" Type="${alg.XMLENC_NS}Element">`
        + `<xenc:EncryptionMethod Algorithm="${escapeAttribute(this.#sessionKeyCipheringAlgorithm)}"/>`
        + `<${p}KeyInfo xmlns:dsig="${alg.XMLDSIG_NS}"><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="${escapeAttribute(this.#cryptAlgorithm)}"/>`
        + `<xenc:CipherData><xenc:CipherValue>${encryptedKey.toString('base64')}</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></${p}KeyInfo>`
        + `\n   <xenc:CipherData>\n      <xenc:CipherValue>${encryptedData.toString('base64')}</xenc:CipherValue>\n   </xenc:CipherData>\n</xenc:EncryptedData>`;
    }

    const certificates = extractCertificates(this.#signCert as string);
    const document = (digestValue: string, signatureValue: string) => '<?xml version="1.0"?>\n'
      + `<${p}Signature ${p === '' ? 'xmlns' : `xmlns:${this.#xmldsigNsPrefix}`}="${alg.XMLDSIG_NS}">\n`
      + `  <${p}SignedInfo><${p}CanonicalizationMethod Algorithm="${escapeAttribute(this.#canonicalizationAlgorithm)}"/>\n`
      + `    <${p}SignatureMethod Algorithm="${escapeAttribute(this.#signatureAlgorithm)}"/>\n`
      + `  <${p}Reference URI="#${TOKEN_NAME}"><${p}Transforms><${p}Transform Algorithm="${escapeAttribute(this.#transformAlgorithm)}"/></${p}Transforms>`
      + `<${p}DigestMethod Algorithm="${escapeAttribute(this.#digestAlgorithm)}"/><${p}DigestValue>${digestValue}</${p}DigestValue></${p}Reference></${p}SignedInfo>`
      + `<${p}SignatureValue>${signatureValue}</${p}SignatureValue>\n`
      + `<${p}KeyInfo><${p}X509Data>${certificates.map((cert) => `<${p}X509Certificate>${cert}</${p}X509Certificate>`).join('')}</${p}X509Data></${p}KeyInfo>`
      + `<${p}Object Id="${TOKEN_NAME}">${objectContent}</${p}Object></${p}Signature>\n`;

    // The digest of the node "ds:Object", then the signature of the node
    // "ds:SignedInfo", each computed over the document as it will be read.
    const signature = (doc: Document) => doc.documentElement as Element;
    const child = (parent: Element, name: string) => nodes(`ds:${name}`, parent)[0] as Element;

    let doc = loadXML(document('', ''), 'XML Digital Signature');
    const object = child(signature(doc), 'Object');
    const digest = createHash(HASHES[this.#digestAlgorithm] as string)
      .update(canonicalize(object, WITHOUT_COMMENTS[this.#transformAlgorithm] ?? this.#transformAlgorithm, null, 'referenced node'))
      .digest('base64');

    let privateKey: KeyObject;
    try {
      privateKey = createPrivateKey({ key: this.#signKey as string, format: 'pem', ...(this.#signKeyPassword === null ? {} : { passphrase: this.#signKeyPassword }) });
    } catch {
      throw new Error('Failed loading private key to sign token data!');
    }
    if (privateKey.asymmetricKeyType !== 'rsa') {
      throw new Error('The signing key is not an RSA key: the signature algorithms are RSA ones!');
    }

    doc = loadXML(document(digest, ''), 'XML Digital Signature');
    const signedInfo = child(signature(doc), 'SignedInfo');
    const signatureValue = sign(
      SIGNATURE_HASHES[this.#signatureAlgorithm] as string,
      Buffer.from(canonicalize(signedInfo, this.#canonicalizationAlgorithm, null, 'ds:SignedInfo'), 'utf8'),
      privateKey,
    ).toString('base64');

    this.#readXML(document(digest, signatureValue), true);
  }

  /**
   * Reads the XML digital signature of a token: checks that it is valid and
   * that its certificate is trusted, decrypts it if it is encrypted, then
   * reads its timestamp, identifier, expiry, audiences and data. The checks
   * are those of the PHP library, in its order, with its messages.
   *
   * @param isCreation True if the object has just created the token.
   */
  #readXML(xml: unknown, isCreation: boolean): void {
    this.#xml = typeof xml === 'string' ? xml : xml instanceof Uint8Array ? Buffer.from(xml).toString('utf8') : null;

    // A document with a document type declaration, not in UTF-8 or not
    // well formed is refused before it is parsed (see loadXML()).
    const doc = loadXML(xml, 'XML Digital Signature');
    const root = doc.documentElement as Element;

    // The structure is fixed: "ds:Signature" is the document element, a
    // single element has the attribute Id="Token", and every expected
    // element is there once. With two elements Id="Token", or a signature
    // wrapped in another element, a copy of the signed "ds:Object" placed
    // where the signature does not cover it could be taken for it
    // (signature wrapping). The token is also read only from the node whose
    // digest is verified (see below).
    if (root.namespaceURI !== alg.XMLDSIG_NS || root.localName !== 'Signature') {
      throw new Error('XML digital signature is malformed! The document element must be ds:Signature.');
    }
    if (nodes(`//@*[local-name()="Id" and .="${TOKEN_NAME}"]`, doc).length !== 1) {
      throw new Error(`XML digital signature is malformed! Exactly one element must have the attribute Id="${TOKEN_NAME}".`);
    }
    for (const query of [
      '//ds:Signature',
      '//ds:Signature/ds:SignedInfo',
      '//ds:Signature/ds:SignedInfo/ds:CanonicalizationMethod',
      '//ds:Signature/ds:SignedInfo/ds:SignatureMethod',
      '//ds:Signature/ds:SignedInfo/ds:Reference',
      '//ds:Signature/ds:SignedInfo/ds:Reference/ds:Transforms',
      '//ds:Signature/ds:SignedInfo/ds:Reference/ds:Transforms/ds:Transform',
      '//ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestMethod',
      '//ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestValue',
      '//ds:Signature/ds:SignatureValue',
      '//ds:Signature/ds:KeyInfo',
      '//ds:Signature/ds:KeyInfo/ds:X509Data',
      '//ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate',
      '//ds:Signature/ds:Object',
    ]) {
      if (nodes(query, doc).length !== 1) {
        throw new Error('XML digital signature is malformed!');
      }
    }
    if (evaluate('//ds:Signature/ds:SignedInfo/ds:Reference/@URI', doc) !== `#${TOKEN_NAME}`
      || evaluate('//ds:Signature/ds:Object/@Id', doc) !== TOKEN_NAME) {
      throw new Error('XML digital signature is malformed!');
    }

    // The algorithms used to sign the token: an algorithm out of the lists
    // throws; one that is not the expected one is an anomaly.
    this.#checkAlgorithms(doc, [
      ['//ds:Signature/ds:SignedInfo/ds:CanonicalizationMethod/@Algorithm', 'Canonicalization', isValidCanonicalizationAlgorithm, this.#canonicalizationAlgorithm],
      ['//ds:Signature/ds:SignedInfo/ds:SignatureMethod/@Algorithm', 'Signature', isValidSignatureAlgorithm, this.#signatureAlgorithm],
      ['//ds:Signature/ds:SignedInfo/ds:Reference/ds:Transforms/ds:Transform/@Algorithm', 'Transform', isValidCanonicalizationAlgorithm, this.#transformAlgorithm],
      ['//ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestMethod/@Algorithm', 'Digest', isValidHashAlgorithm, this.#digestAlgorithm],
    ], this.#checkSigningAlgorithms);

    if (nodes('//ds:Signature/ds:Object/xenc:EncryptedData', doc).length === 1) {
      this.#checkEncryptedStructure(doc);
    }

    const signatureNode = root;
    const signedInfo = nodes('ds:SignedInfo', signatureNode)[0] as Element;
    const reference = nodes('ds:Reference', signedInfo)[0] as Element;

    // The key and the certificate of the token, read from "ds:KeyInfo" as
    // xmlseclibs reads them.
    const { key, certificate } = locateKeyInfo(nodes('ds:KeyInfo', signatureNode)[0] as Element);
    this.#x509Certificate = new X509Cert(certificate ?? '');

    // The digest of the node "ds:Object", the only element Id="Token" (see
    // above). The token is read from this node only, never by searching the
    // document.
    const object = nodes('/ds:Signature/ds:Object', doc)[0] as Element;
    try {
      const transform = nodes('ds:Transforms/ds:Transform', reference)[0] as Element;
      const transformAlgorithm = transform.getAttribute('Algorithm') ?? '';
      const data = canonicalize(object, WITHOUT_COMMENTS[transformAlgorithm] ?? transformAlgorithm, transformPrefixList(transform), 'referenced node');
      const digestAlgorithm = evaluate('ds:DigestMethod/@Algorithm', reference);
      const computed = createHash(HASHES[digestAlgorithm] as string).update(data, 'utf8').digest();
      if (!computed.equals(phpBase64Decode(evaluate('ds:DigestValue', reference)))) {
        throw new Error('Reference validation failed');
      }
      this.#isDigestValueOk = true;
    } catch {
      this.#isDigestValueOk = false;
      this.#anomalies.push('Token hash verification failed!');
    }

    // The signature of the node "ds:SignedInfo", verified with the key of
    // the token. It must be an RSA key, as the signature algorithms are RSA
    // ones: a key of another type would verify another signature than the
    // one the algorithm declares.
    const canonicalizationMethod = nodes('ds:CanonicalizationMethod', signedInfo)[0] as Element;
    const signedInfoCanon = canonicalize(signedInfo, canonicalizationMethod.getAttribute('Algorithm') ?? '', signedInfoPrefixList(canonicalizationMethod), 'ds:SignedInfo');
    let signatureOk = false;
    try {
      const signatureValue = evaluate('ds:SignatureValue', signatureNode);
      const signatureAlgorithm = evaluate('ds:SignatureMethod/@Algorithm', signedInfo);
      if (!isEmpty(signatureValue) && key.asymmetricKeyType === 'rsa') {
        signatureOk = verify(SIGNATURE_HASHES[signatureAlgorithm] as string, Buffer.from(signedInfoCanon, 'utf8'), key, phpBase64Decode(signatureValue));
      }
    } catch {
      signatureOk = false;
    }
    this.#isSignatureValueOk = signatureOk;
    if (!signatureOk) {
      this.#anomalies.push('Token hash signature verification failed!');
    }

    // Neither decrypt nor read a token whose digest or signature is not
    // valid: its content is not the signed one.
    if (!this.#isDigestValueOk || !this.#isSignatureValueOk) {
      this.#throwAnomalies();
    }

    // The signature has only been verified with the certificate the token
    // carries, which anyone can produce. Neither decrypt nor read a token
    // whose certificate is not trusted.
    this.#verifyCertTrust();

    const encryptedData = nodes('xenc:EncryptedData', object)[0];
    if (encryptedData === undefined) {
      this.#isDataEncrypted = false;
    } else {
      this.#isDataEncrypted = true;

      // Do not decrypt a token encrypted with other algorithms than the
      // expected ones: the decryption itself is what an attacker submitting
      // altered tokens probes.
      if (this.#anomalies.length > 0) {
        this.#throwAnomalies();
      }

      // A token created without the private key of the recipient cannot be
      // decrypted: everything that can be checked without decrypting it has
      // been, and its content is left unread.
      if (isCreation && this.#cryptKey === null) {
        return;
      }

      this.#decryptToken(encryptedData as Element);
    }

    this.#readToken(object, isCreation);
  }

  /**
   * Reads the content of the token, in the digested node "ds:Object":
   * timestamp, identifier, expiry, audiences, then the data.
   */
  #readToken(object: Element, isCreation: boolean): void {
    for (const query of [TOKEN_NAME, `${TOKEN_NAME}/${TOKEN_TIMESTAMP_NAME}`, `${TOKEN_NAME}/${TOKEN_DATA_NAME}`]) {
      if (nodes(query, object).length !== 1) {
        // The structure of an encrypted token is that of its decrypted
        // content: it fails as the decryption does.
        throw new Error(this.#isDataEncrypted === true ? DECRYPTION_FAILED : 'Malformed token!');
      }
    }

    // The timestamp: a single text node, in the format of the timestamp.
    const timestampNode = nodes(`${TOKEN_NAME}/${TOKEN_TIMESTAMP_NAME}`, object)[0] as Element;
    if (timestampNode.childNodes.length === 1 && isText(timestampNode.firstChild)) {
      const value = timestampNode.firstChild?.nodeValue ?? '';
      if (parseTokenDate(value) !== null) {
        this.#timestamp = value;
      } else {
        this.#anomalies.push('Token timestamp format is invalid!');
      }
    } else {
      this.#anomalies.push('Token timestamp is malformed!');
    }

    // The identifier. A token without identifier (as created by the 0.x
    // versions of the PHP library) is rejected: the receiver could not tell
    // it from a replayed one (see getTokenId()).
    const idNodes = nodes(`${TOKEN_NAME}/${TOKEN_ID_NAME}`, object) as Element[];
    if (idNodes.length === 0) {
      this.#anomalies.push('Token identifier is missing!');
    } else if (idNodes.length === 1
      && idNodes[0]?.childNodes.length === 1
      && isText(idNodes[0].firstChild)
      && new RegExp(`^[0-9a-f]{${2 * TOKEN_ID_BYTES}}$`).test(idNodes[0].firstChild?.nodeValue ?? '')) {
      this.#tokenId = idNodes[0].firstChild?.nodeValue ?? null;
    } else {
      this.#anomalies.push('Token identifier is malformed!');
    }

    // The expiry, if any: a token created without the option "validity"
    // has none.
    const expiryNodes = nodes(`${TOKEN_NAME}/${TOKEN_EXPIRY_NAME}`, object) as Element[];
    this.#hasExpiryNode = expiryNodes.length > 0;
    if (this.#hasExpiryNode) {
      const node = expiryNodes[0] as Element;
      const value = node.firstChild?.nodeValue ?? '';
      const expiry = expiryNodes.length === 1 && node.childNodes.length === 1 && isText(node.firstChild) ? parseTokenDate(value) : null;
      const timestamp = this.#timestamp === null ? null : parseTokenDate(this.#timestamp);
      if (expiry === null || formatTokenDate(expiry) !== value) {
        this.#anomalies.push('Token expiry is malformed!');
      } else if (timestamp !== null && expiry <= timestamp) {
        this.#anomalies.push('Token expiry is not after its timestamp!');
      } else {
        this.#expiry = value;
      }
    }

    // The audiences, if any, checked against the expected audience (see
    // #verifyAudience()) before the data are read.
    const audienceNodes = nodes(`${TOKEN_NAME}/${TOKEN_AUDIENCE_NAME}`, object) as Element[];
    if (audienceNodes.length > 0) {
      const audiences: string[] = [];
      for (const node of audienceNodes) {
        const value = node.firstChild?.nodeValue;
        if (node.childNodes.length !== 1 || !isText(node.firstChild) || !isValidAudience(value)) {
          // A malformed audience is not one the receiver can be sure of:
          // the token is rejected before its data are read.
          this.#anomalies.push('Token audience is malformed!');
          this.#throwAnomalies();
        }
        audiences.push(value as string);
      }
      this.#audience = audiences;
    }

    // A token whose timestamp, identifier or expiry is malformed is rejected
    // here, before its data are read and its audience checked.
    if (this.#anomalies.length > 0) {
      this.#throwAnomalies();
    }

    this.#verifyAudience(isCreation);

    // The data, read from the node tree of "TokenData".
    const dataNode = nodes(`${TOKEN_NAME}/${TOKEN_DATA_NAME}`, object)[0] as Element;
    const data: ReadTokenData = {};
    this.#readData(dataNode, data);
    this.#data = data;

    if (this.#anomalies.length > 0) {
      this.#throwAnomalies();
    }
  }

  /**
   * Reads a node tree of the data into an object, as the PHP library reads
   * it: an element holding a single text node is a value (decoded from
   * base64 if it has the attribute Algorithm="base64"), an element holding
   * other nodes is nested values, an empty element is skipped, and a text
   * node next to other nodes is an anomaly.
   */
  #readData(root: Element, data: ReadTokenData): void {
    if (!root.hasChildNodes()) {
      this.#anomalies.push('Token data is empty!');
      return;
    }
    for (let node = root.firstChild; node !== null; node = node.nextSibling) {
      if (isText(node) && root.childNodes.length !== 1) {
        this.#anomalies.push('Token data is malformed!');
      }
      if (isElement(node) && node.hasChildNodes()) {
        let value: string | Buffer | ReadTokenData;
        if (node.childNodes.length === 1 && isText(node.firstChild)) {
          const text = node.firstChild?.nodeValue ?? '';
          value = node.getAttribute('Algorithm') === 'base64' ? decodeValue(phpBase64Decode(text)) : text;
        } else {
          value = {};
          this.#readData(node, value);
        }
        // defineProperty(): a value named "__proto__" is a value, not the
        // prototype of the object.
        Object.defineProperty(data, node.nodeName, { value, enumerable: true, writable: true, configurable: true });
      }
    }
  }

  /**
   * Checks the algorithms read from the token: missing or out of their list,
   * they throw; not the expected ones, they are anomalies, unless the check
   * is turned off.
   */
  #checkAlgorithms(doc: Document, checks: Array<[string, string, (value: unknown) => boolean, string]>, check: boolean): void {
    for (const [query, name, isValid, expected] of checks) {
      const used = evaluate(query, doc);
      if (isEmpty(used)) {
        throw new Error(`${name} algorithm is missing!`);
      }
      if (!isValid(used)) {
        throw new Error(`${name} algorithm is invalid!`);
      }
      if (used !== expected && check) {
        this.#anomalies.push(`Unauthorized ${name} algorithm! Expected: ${expected}, Used: ${used}.`);
      }
    }
  }

  /**
   * Checks the structure, the type and the algorithms of the encrypted
   * data of the token, before anything is verified or decrypted.
   */
  #checkEncryptedStructure(doc: Document): void {
    for (const query of [
      '//ds:Signature/ds:Object/xenc:EncryptedData/xenc:EncryptionMethod',
      '//ds:Signature/ds:Object/xenc:EncryptedData/ds:KeyInfo',
      '//ds:Signature/ds:Object/xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey',
      '//ds:Signature/ds:Object/xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey/xenc:EncryptionMethod',
      '//ds:Signature/ds:Object/xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey/xenc:CipherData',
      '//ds:Signature/ds:Object/xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey/xenc:CipherData/xenc:CipherValue',
      '//ds:Signature/ds:Object/xenc:EncryptedData/xenc:CipherData',
      '//ds:Signature/ds:Object/xenc:EncryptedData/xenc:CipherData/xenc:CipherValue',
    ]) {
      if (nodes(query, doc).length !== 1) {
        throw new Error('Encrypted data is malformed!');
      }
    }

    // The encrypted content is the node "Token": an element, or the content
    // of the node "ds:Object", which XML Encryption 1.1 (section 4.2)
    // describes as the types Element and Content, both of which a decryptor
    // must read. Any other type is refused.
    const type = evaluate('//ds:Signature/ds:Object/xenc:EncryptedData/@Type', doc);
    if (type !== `${alg.XMLENC_NS}Element` && type !== `${alg.XMLENC_NS}Content`) {
      throw new Error('Encrypted data is malformed!');
    }

    this.#checkAlgorithms(doc, [
      ['//ds:Signature/ds:Object/xenc:EncryptedData/xenc:EncryptionMethod/@Algorithm', 'Session Key Ciphering', isValidSymmetricCipheringAlgorithm, this.#sessionKeyCipheringAlgorithm],
      ['//ds:Signature/ds:Object/xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey/xenc:EncryptionMethod/@Algorithm', 'Crypt', isValidKeyTransportAlgorithm, this.#cryptAlgorithm],
    ], this.#checkCryptingAlgorithms);

    // An algorithm without integrity (CBC) is only accepted when it is the
    // declared one, even if the check of the algorithms is turned off.
    const used = evaluate('//ds:Signature/ds:Object/xenc:EncryptedData/xenc:EncryptionMethod/@Algorithm', doc);
    if (!isAuthenticatedCipheringAlgorithm(used) && used !== this.#sessionKeyCipheringAlgorithm && !this.#checkCryptingAlgorithms) {
      this.#anomalies.push(`Unauthorized Session Key Ciphering algorithm! ${used} has no integrity: declare it with the option 'sessionKeyCipheringAlgorithm' to accept it.`);
    }
  }

  /**
   * Decrypts the node "xenc:EncryptedData" in place, as the PHP library
   * does (`_decryptToken()`, with xmlseclibs).
   *
   * The failures that do not depend on the token content (no decryption
   * key, a key that cannot be loaded) or only on its structure have their
   * own message. Every failure that depends on the decrypted content
   * (session key, token data, parsing of the decrypted XML) gives the same
   * error, without its reason: a message per failure would tell an attacker
   * who can submit altered tokens which step failed, which is how padding
   * oracles (Bleichenbacher on RSA 1.5, Jager-Somorovsky on CBC) decrypt a
   * token step by step. `#readXML()` only calls this function once the
   * digest, the signature, the certificate and the algorithms of the token
   * have been verified.
   *
   * The plaintext replaces the node "xenc:EncryptedData" as an XML fragment,
   * for the type Element as for the type Content: it cannot hold a document
   * type declaration.
   */
  #decryptToken(encryptedData: Element): void {
    if (this.#cryptKey === null) {
      throw new Error('Token is encrypted but no private key is provided for decryption!');
    }

    // The algorithm of the data is that of the first "xenc:EncryptionMethod"
    // below "xenc:EncryptedData", as xmlseclibs finds it.
    const dataAlgorithm = (nodes('.//xenc:EncryptionMethod', encryptedData)[0] as Element | undefined)?.getAttribute('Algorithm') ?? null;
    if (dataAlgorithm === null || !XMLSECLIBS_ALGORITHMS.has(dataAlgorithm)) {
      throw new Error('Cannot locate session key ciphering algorithm!');
    }

    // The encrypted session key: the first child "EncryptedKey" of the
    // "ds:KeyInfo" of "xenc:EncryptedData".
    const keyInfo = nodes('ds:KeyInfo', encryptedData)[0] as Element | undefined;
    let encryptedKey: Element | undefined;
    for (let child = keyInfo?.firstChild ?? null; child !== null && encryptedKey === undefined; child = child.nextSibling) {
      if (isElement(child) && child.localName === 'EncryptedKey') {
        encryptedKey = child;
      }
    }
    if (encryptedKey === undefined) {
      throw new Error('Cannot locate session key!');
    }
    const keyAlgorithm = (nodes('.//xenc:EncryptionMethod', encryptedKey)[0] as Element | undefined)?.getAttribute('Algorithm') ?? null;
    if (keyAlgorithm === null || !XMLSECLIBS_ALGORITHMS.has(keyAlgorithm)) {
      throw new Error('Unable to locate algorithm for this Encrypted Key');
    }

    let privateKey: KeyObject;
    try {
      privateKey = createPrivateKey({ key: this.#cryptKey, format: 'pem', ...(this.#cryptKeyPassword === null ? {} : { passphrase: this.#cryptKeyPassword }) });
    } catch {
      throw new Error('Failed loading private key to decrypt session key!');
    }

    // From here on, every failure gives the same error.
    let fragment: Node[] | null = null;
    try {
      const cipherValue = (element: Element) => phpBase64Decode(evaluate('xenc:CipherData/xenc:CipherValue', element));
      if (keyAlgorithm === alg.RSA_OAEP_MGF1P && isValidSymmetricCipheringAlgorithm(dataAlgorithm)) {
        const sessionKey = decryptKey(privateKey, cipherValue(encryptedKey));
        const plaintext = decryptSymmetric(dataAlgorithm, sessionKey, cipherValue(encryptedData));
        fragment = parseFragment(new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(plaintext));
      }
    } catch {
      fragment = null;
    }
    if (fragment === null) {
      throw new Error(DECRYPTION_FAILED);
    }

    const doc = encryptedData.ownerDocument as Document;
    const parent = encryptedData.parentNode as Node;
    for (const child of fragment) {
      parent.insertBefore(doc.importNode(child, true), encryptedData);
    }
    parent.removeChild(encryptedData);
  }

  /**
   * Verifies that the X.509 certificate of the token is trusted: a trust
   * anchor is required; the certificate must be valid at the current date,
   * its key usage must allow signing; it must be the pinned certificate, if
   * any; its chain must be verified up to the trusted CA certificates, if
   * any; its subject must be the expected one, if any.
   */
  #verifyCertTrust(): void {
    this.#isCertTrusted = false;
    const cert = this.#x509Certificate as X509Cert;

    if (this.#trustedCACerts === null && this.#pinnedSignerCert === null) {
      throw new Error("No trust anchor! Pass the option 'caCertPath' (trusted CA certificates) and/or 'signerCertPath' (pinned signing certificate) to analyze a token: without them, no signing certificate can be trusted.");
    }
    if (cert.isOutOfDate()) {
      throw new Error(`Signing certificate is not valid at the current date (valid from ${cert.getValidFrom()} to ${cert.getValidTo()})!`);
    }
    if (!cert.canSign()) {
      throw new Error('Signing certificate is not allowed to sign (key usage)!');
    }
    if (this.#pinnedSignerCert !== null && new X509Cert(this.#pinnedSignerCert).getFingerprint() !== cert.getFingerprint()) {
      throw new Error('Signing certificate is not the pinned certificate!');
    }
    if (this.#trustedCACerts !== null && !cert.isTrustedBy(this.#trustedCACerts)) {
      throw new Error("Signing certificate is not issued by a trusted CA: its chain could not be verified up to the CA certificates of the option 'caCertPath', which must hold the issuing CA and the certificates up to its root!");
    }
    if (this.#expectedSubject !== null) {
      const matches = typeof this.#expectedSubject === 'string'
        ? cert.getDN() === this.#expectedSubject
        : matchesName(cert.getSubject(), this.#expectedSubject);
      if (!matches) {
        throw new Error(`Subject of the signing certificate is not the expected one! Subject: ${cert.getDN()}.`);
      }
    }

    this.#isCertTrusted = true;
  }

  /**
   * Verifies that the token is addressed to the expected audience: a token
   * that names audiences is rejected unless "expectedAudience" is one of
   * them; a token that names none is rejected when "expectedAudience" is
   * given. A token just created must name the audiences it was given.
   */
  #verifyAudience(isCreation: boolean): void {
    const audiences = this.#audience ?? [];

    if (isCreation) {
      if (JSON.stringify(audiences) !== JSON.stringify(this.#audienceToWrite ?? [])) {
        throw new Error('Token audience is not the one written!');
      }
      return;
    }

    if (this.#expectedAudience === null) {
      if (audiences.length > 0) {
        throw new Error(`Token is addressed to an audience ('${audiences.join("', '")}'), but the option 'expectedAudience' is not given: pass the audience of this receiver to accept it!`);
      }
      return;
    }
    if (audiences.length === 0) {
      throw new Error(`Token is not addressed to any audience, but the audience '${this.#expectedAudience}' is expected!`);
    }
    if (!audiences.includes(this.#expectedAudience)) {
      throw new Error(`Token is not addressed to the expected audience! Expected: '${this.#expectedAudience}'. Token audience: '${audiences.join("', '")}'.`);
    }
  }

  /** Throws an error whose message lists the anomalies. */
  #throwAnomalies(): never {
    const count = this.#anomalies.length;
    throw new Error(`${count}${count === 1 ? ' anomaly' : ' anomalies'} detected: ${this.#anomalies.join(' ; ')}`);
  }

  /**
   * Indicates whether the XML token is valid: no error and no anomaly, the
   * digest and the signature verified, the signing certificate trusted
   * (see `isCertTrusted()`), and the token addressed to the expected
   * audience. Without a trust anchor given to the analysis, it returns
   * false.
   *
   * **It checks neither the freshness of the token nor whether it is
   * replayed**: see `isOutOfDate()` and `getTokenId()`.
   */
  isSignatureValid(): boolean {
    return this.#isDigestValueOk === true
      && this.#isSignatureValueOk === true
      && this.#isCertTrusted === true
      && this.#error === null;
  }

  /** Indicates whether the signing certificate is trusted, according to the
  trust anchor of the analysis; null if it could not be evaluated. */
  isCertTrusted(): boolean | null {
    return this.#isCertTrusted;
  }

  /**
   * Indicates whether the token is out of date: its timestamp is more than
   * `ttl` seconds in the past, or more than `DESYNC_TOLERANCE` seconds in
   * the future, or it has no valid timestamp, or its expiry, if any, is
   * passed (or could not be read).
   *
   * @param ttl The time to live (in seconds) allowed for the token.
   */
  isOutOfDate(ttl: number = XMLDSigToken.TOKEN_DEFAULT_TTL): boolean {
    if (typeof ttl !== 'number' || !Number.isFinite(ttl)) {
      throw new Error("Invalid parameter 'ttl'! It must be a number of seconds.");
    }
    if (this.#timestamp === null) {
      return true;
    }
    const timestamp = parseTokenDate(this.#timestamp);
    if (timestamp === null) {
      return true;
    }
    const now = Math.floor(Date.now() / 1000);

    // A token whose expiry is passed is out of date, whatever ttl; so is a
    // token whose expiry could not be read.
    if (this.#hasExpiryNode && this.#expiry === null) {
      return true;
    }
    if (this.#expiry !== null) {
      const expiry = parseTokenDate(this.#expiry);
      if (expiry === null || expiry < now) {
        return true;
      }
    }

    return timestamp > now + XMLDSigToken.DESYNC_TOLERANCE || timestamp + ttl < now;
  }

  /** Indicates whether the token data are encrypted; null if it could not
  be evaluated. */
  isDataEncrypted(): boolean | null {
    return this.#isDataEncrypted;
  }

  /** Indicates whether the digest of the token has been verified and is
  valid; null if it could not be evaluated. */
  isDigestValueOk(): boolean | null {
    return this.#isDigestValueOk;
  }

  /** Indicates whether the signature of the digest has been verified and is
  valid; null if it could not be evaluated. */
  isSignatureValueOk(): boolean | null {
    return this.#isSignatureValueOk;
  }

  /** Gets the XML token. */
  getXML(): string | null {
    return this.#xml;
  }

  /**
   * Gets the XML token in a readable form, for display only: use
   * `getXML()` to get the token to work with. The signature value, the
   * certificate and the encrypted values are split into lines of 64
   * characters, and the elements are indented by 2 spaces. The result is
   * the one of `getPrettyXML()` of the PHP library, whose steps it follows.
   * A token that is not an XML document is returned as it is, one line per
   * line.
   */
  getPrettyXML(): string | null {
    if (this.#xml === null) {
      return null;
    }
    let xml = this.#xml;
    // The PHP library selects the values with the prefix of the option
    // xmldsigNsPrefix in place of "ds:": with no prefix, its expressions
    // select elements in no namespace, and no value is split.
    if (this.#xmldsigNsPrefix !== '') {
      for (const expression of PRETTY_SPLIT_VALUES) {
        xml = splitNodeValue(xml, expression);
      }
    }

    // One tag per line, then each line indented by the depth of the
    // elements: a line that opens an element indents the following ones, a
    // line that closes one is outdented, and a line that opens and closes
    // an element changes nothing. A closing line keeps the indentation step
    // of the line before it, as in the PHP library.
    xml = xml.replace(/(>)[ \t\n\x0B\f\r]*(<)(\/*)/g, '$1\n$2$3');
    let formatted = '';
    let pad = 0;
    let indent = 0;
    for (const line of xml.split('\n').filter((part) => part !== '')) {
      if (/[^\n]+<\/\w[^>]*>$/.test(line)) {
        indent = 0;
      } else if (/^<\/\w/.test(line)) {
        pad -= PRETTY_INDENT;
      } else if (/^<\w[^>]*[^/]>[^\n]*$/.test(line)) {
        indent = PRETTY_INDENT;
      } else {
        indent = 0;
      }
      formatted += ' '.repeat(Math.max(pad, 0)) + line + '\n';
      pad += indent;
    }
    return formatted;
  }

  /**
   * Gets the token data. They can only be trusted if `isSignatureValid()`
   * returns true (and the token is neither out of date nor replayed).
   * Values written empty are not read back, as with the PHP library.
   */
  getData(): ReadTokenData | null {
    return this.#data;
  }

  /** Gets the timestamp of a valid token (YYYY-MM-DDThh:mm:ssZ, UTC). */
  getTimestamp(): string | null {
    return this.isSignatureValid() ? this.#timestamp : null;
  }

  /**
   * Gets the identifier of a valid token: 128 random bits, in 32 lowercase
   * hexadecimal characters, covered by the signature. The library keeps no
   * list of the tokens it analyzed: refuse a token whose identifier you
   * have already accepted, and keep each one at least `ttl +
   * DESYNC_TOLERANCE` seconds.
   */
  getTokenId(): string | null {
    return this.isSignatureValid() ? this.#tokenId : null;
  }

  /** Gets the audiences of a valid token, or null if it names none. */
  getAudience(): string[] | null {
    return this.isSignatureValid() && this.#audience !== null ? [...this.#audience] : null;
  }

  /** Gets the expiry of a valid token (YYYY-MM-DDThh:mm:ssZ, UTC), or null
  if it has none. */
  getExpiry(): string | null {
    return this.isSignatureValid() ? this.#expiry : null;
  }

  /** Gets the error of the analysis, or null. */
  getError(): string | null {
    return this.#error;
  }

  /** Gets the anomalies detected by the analysis. */
  getAnomalies(): string[] {
    return [...this.#anomalies];
  }

  /** Gets the X.509 certificate of the token, in PEM format. */
  getCertificate(): string | null {
    return this.#x509Certificate?.getPem() ?? null;
  }

  /** Gets the fields of the issuer of the certificate of the token. */
  getCertIssuer(): NameFields | null {
    return this.#x509Certificate?.getIssuer() ?? null;
  }

  /** Gets the fields of the subject of the certificate of the token. */
  getCertSubject(): NameFields | null {
    return this.#x509Certificate?.getSubject() ?? null;
  }

  /** Gets the Distinguished Name of the certificate of the token (see
  `X509Cert.getDN()`). */
  getCertDN(): string | null {
    return this.#x509Certificate?.getDN() ?? null;
  }

  /** Gets the date from which the certificate of the token is valid. */
  getCertValidFrom(): string | null {
    return this.#x509Certificate?.getValidFrom() ?? null;
  }

  /** Gets the date until which the certificate of the token is valid. */
  getCertValidTo(): string | null {
    return this.#x509Certificate?.getValidTo() ?? null;
  }

  /** Indicates whether the certificate of the token is out of date (true
  without certificate). */
  isCertOutOfDate(): boolean {
    return this.#x509Certificate?.isOutOfDate() ?? true;
  }

  /**
   * Checks that the issuer of the certificate of the token has the given
   * fields. This only compares names, which any certificate can copy:
   * `isSignatureValid()` verifies the certificate against the trust anchor.
   *
   * @param expectedIssuerInfo The fields the issuer must have, e.g.
   *     `{ O: 'Lothbrok Ltd', OU: 'Shield Wall Dept' }`.
   */
  isValidCertIssuer(expectedIssuerInfo: Record<string, string | string[]>): boolean {
    if (typeof expectedIssuerInfo !== 'object' || expectedIssuerInfo === null || Array.isArray(expectedIssuerInfo)) {
      throw new Error("Invalid parameter 'issuerInfo'! Issuer information should be an object.");
    }
    const issuer = this.getCertIssuer();
    return issuer !== null && matchesName(issuer, expectedIssuerInfo);
  }

  /**
   * Checks that the certificate of the token was issued by the given CA
   * certificate (only this link: see `X509Cert.isValidCA()`).
   * `isSignatureValid()` verifies the whole chain against the trust anchor.
   *
   * @param caCertPath The CA certificate, in PEM format: the path of its
   *     file, or its content.
   */
  isValidCertCA(caCertPath: PemSource): boolean {
    if (this.#x509Certificate === null) {
      return false;
    }
    const caCert = readPem(caCertPath);
    if (caCert === null) {
      throw new Error(`Cannot read CA certificate to perform signer check! File: ${String(caCertPath)}`);
    }
    return this.#x509Certificate.isValidCA(caCert);
  }

  /** What `console.log()` and `util.inspect()` show: the results of the
  analysis, without the keys. */
  [inspect.custom](): object {
    return {
      isValid: this.isSignatureValid(),
      isDigestValueOk: this.#isDigestValueOk,
      isSignatureValueOk: this.#isSignatureValueOk,
      isCertTrusted: this.#isCertTrusted,
      isDataEncrypted: this.#isDataEncrypted,
      timestamp: this.#timestamp,
      tokenId: this.getTokenId(),
      audience: this.getAudience(),
      expiry: this.getExpiry(),
      data: this.#data,
      error: this.#error,
      anomalies: this.#anomalies,
    };
  }
}

/**
 * Checks the token data before they are written: named values, nested at
 * will, whose leaves are strings, finite numbers, booleans, null or bytes.
 * The names are checked as the token is written (see `writeData()`).
 */
function checkData(data: TokenData): void {
  for (const value of Object.values(data)) {
    if (typeof value === 'string') {
      if (!value.isWellFormed()) {
        throw new Error("Invalid parameter 'data'! A string value holds a lone surrogate, which is not a character.");
      }
    } else if (typeof value === 'number') {
      if (!Number.isFinite(value)) {
        throw new Error("Invalid parameter 'data'! A number value must be finite.");
      }
    } else if (value instanceof Uint8Array) {
      continue;
    } else if (typeof value === 'object' && value !== null) {
      if (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null && !Array.isArray(value)) {
        throw new Error("Invalid parameter 'data'! A value must be a string, a number, a boolean, null, bytes, or nested values.");
      }
      checkData(value as TokenData);
    } else if (typeof value !== 'boolean' && value !== null) {
      throw new Error("Invalid parameter 'data'! A value must be a string, a number, a boolean, null, bytes, or nested values.");
    }
  }
}

/**
 * Writes the node tree of the data, as the PHP library writes it: an
 * element per value, named by its name, nested for nested values, the
 * leaves encoded in base64 and marked Algorithm="base64" unless the option
 * "base64Encode" is false.
 *
 * @throws {Error} "Invalid Character Error" for a name that is not an XML
 *     name, as PHP (DOMDocument::createElement()) throws it.
 */
function writeData(name: string, value: TokenValue, base64: boolean): string {
  if (!isXmlName(name)) {
    throw new Error('Invalid Character Error');
  }
  if (typeof value === 'object' && value !== null && !(value instanceof Uint8Array)) {
    const children = Object.entries(value).map(([childName, child]) => writeData(childName, child, base64)).join('');
    return children === '' ? `<${name}/>` : `<${name}>${children}</${name}>`;
  }
  const bytes = value instanceof Uint8Array ? Buffer.from(value) : Buffer.from(leafString(value), 'utf8');
  const text = base64 ? bytes.toString('base64') : escapeText(value instanceof Uint8Array ? bytes.toString('utf8') : leafString(value));
  const attribute = base64 ? ' Algorithm="base64"' : '';
  return text === '' ? `<${name}${attribute}/>` : `<${name}${attribute}>${text}</${name}>`;
}

/** The string a leaf is written as: true is "1", false and null are "", as
PHP converts them. */
function leafString(value: string | number | boolean | null): string {
  if (value === true) {
    return '1';
  }
  if (value === false || value === null) {
    return '';
  }
  return String(value);
}

/** A base64 value as read: a string if its bytes are UTF-8 text, the bytes
otherwise. */
function decodeValue(bytes: Buffer): string | Buffer {
  try {
    return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return bytes;
  }
}

/**
 * Reads the key and the certificate of the token from its "ds:KeyInfo", as
 * xmlseclibs does (`staticLocateKeyInfo()`): its children are read in
 * order, by local name, and the last key read is the one the signature is
 * verified with. A key read from a "KeyValue" has no certificate, and a
 * token without certificate is refused.
 *
 * @throws {Error} With the message of xmlseclibs.
 */
function locateKeyInfo(keyInfo: Element): { key: KeyObject; certificate: string | null } {
  let key: KeyObject | null = null;
  let certificate: string | null = null;
  for (let child = keyInfo.firstChild; child !== null; child = child.nextSibling) {
    if (!isElement(child)) {
      continue;
    }
    switch (child.localName) {
      case 'KeyValue':
        for (let value = child.firstChild; value !== null; value = value.nextSibling) {
          if (!isElement(value)) {
            continue;
          }
          if (value.localName === 'DSAKeyValue') {
            throw new Error('DSAKeyValue currently not supported');
          }
          if (value.localName === 'RSAKeyValue') {
            const modulus = phpBase64Decode(value.getElementsByTagNameNS('*', 'Modulus')[0]?.textContent ?? '');
            const exponent = phpBase64Decode(value.getElementsByTagNameNS('*', 'Exponent')[0]?.textContent ?? '');
            if (modulus.length === 0 || exponent.length === 0) {
              throw new Error('Missing Modulus or Exponent');
            }
            try {
              key = createPublicKey({ key: { kty: 'RSA', n: modulus.toString('base64url'), e: exponent.toString('base64url') }, format: 'jwk' });
            } catch {
              throw new Error('Unable to extract public key');
            }
            certificate = null;
          }
        }
        break;
      case 'EncryptedKey':
      case 'RetrievalMethod':
        // A key that xmlseclibs reads as an encrypted key has no
        // certificate: the token is refused.
        if (child.localName === 'EncryptedKey' || child.getAttribute('Type') === `${alg.XMLENC_NS}EncryptedKey`) {
          throw new Error('Invalid certificate!');
        }
        break;
      case 'X509Data': {
        const certificateNode = child.getElementsByTagNameNS('*', 'X509Certificate')[0];
        if (certificateNode !== undefined) {
          const base64 = (certificateNode.textContent ?? '').replace(/[\r\n \t]/g, '');
          const pem = `-----BEGIN CERTIFICATE-----\n${base64.match(/.{1,64}/g)?.join('\n') ?? ''}\n-----END CERTIFICATE-----\n`;
          try {
            key = createPublicKey(pem);
          } catch {
            throw new Error('Unable to extract public key');
          }
          certificate = pem;
        }
        break;
      }
      default:
        break;
    }
  }
  if (key === null || certificate === null) {
    throw new Error('Invalid certificate!');
  }
  return { key, certificate };
}

/** The prefix list of the "InclusiveNamespaces" child of an exclusive
canonicalization transform, as xmlseclibs reads it (its first one). */
function transformPrefixList(transform: Element): string[] | null {
  const algorithm = transform.getAttribute('Algorithm');
  if (algorithm !== alg.EXC_C14N && algorithm !== alg.EXC_C14N_COMMENTS) {
    return null;
  }
  for (let node = transform.firstChild; node !== null; node = node.nextSibling) {
    if (isElement(node) && node.localName === 'InclusiveNamespaces') {
      const prefixes = (node.getAttribute('PrefixList') ?? '').split(' ').map((prefix) => prefix.trim()).filter((prefix) => !isEmpty(prefix));
      return prefixes.length > 0 ? prefixes : null;
    }
  }
  return null;
}

/** The prefix list of the "InclusiveNamespaces" children of the
canonicalization method of "ds:SignedInfo", as xmlseclibs reads it (all of
them). */
function signedInfoPrefixList(method: Element): string[] | null {
  let prefixes: string[] | null = null;
  for (let node = method.firstChild; node !== null; node = node.nextSibling) {
    if (isElement(node) && node.localName === 'InclusiveNamespaces') {
      const list = (node.getAttribute('PrefixList') ?? '').split(' ').filter((prefix) => !isEmpty(prefix));
      if (list.length > 0) {
        prefixes = [...(prefixes ?? []), ...list];
      }
    }
  }
  return prefixes;
}
