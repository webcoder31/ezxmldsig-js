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
 * The verification of seals: an ASiC-E container holding one XAdES baseline
 * signature over its files (see design/seal.md, "Verification rules").
 *
 * The structure is read strictly: every element of the signature is where
 * the baseline puts it, once, and anything this library does not process
 * (a signature policy, a manifest of references, a transform) makes the
 * seal invalid rather than ignored. A seal is valid only if every file of
 * the container outside META-INF is covered, so that a file added to a
 * sealed container cannot pass for a sealed one.
 */

import { X509Certificate, createHash, verify, type KeyObject } from 'node:crypto';

import type { Document, Element, Node } from '@xmldom/xmldom';

import { C14N, XMLDSIG_NS } from '../algorithms.js';
import { canonicalize } from '../c14n.js';
import { describeSource, readPem, type PemSource } from '../material.js';
import { X509Cert, matchesName, type NameFields } from '../x509.js';
import { loadXML } from '../xml.js';
import * as alg from './algorithms.js';
import { ASICE_MIMETYPE, ASIC_NS, MANIFEST_NS, MANIFEST_PATH, SIGNED_PROPERTIES_TYPE, XADES_NS } from './seal.js';
import { DEFAULT_ZIP_LIMITS, readZip, type ZipEntry, type ZipLimits } from './zip.js';

export interface VerifyOptions {
  /** The trusted CA certificates: the root of the signer, and the intermediate CAs if the seal does not embed them. */
  readonly caCertPath: PemSource | readonly PemSource[];
  /** The subject the signing certificate must have: its one-line DN, or fields that must all match. */
  readonly expectedSubject?: string | NameFields;
  /**
   * Whether the revocation of the certificates is checked (default true). A
   * seal whose revocation cannot be checked is invalid; false verifies it
   * without, which `isRevocationChecked()` then tells.
   */
  readonly revocation?: boolean;
  /** The limits of the reading of the container. */
  readonly limits?: ZipLimits;
}

/** A file the seal covers. */
export interface SealedFile {
  readonly name: string;
  /** The media type the signature gives it (DataObjectFormat). */
  readonly mimeType: string;
}

/** The result of the verification of a seal. */
export class SealVerification {
  readonly #error: string | null;
  readonly #files: readonly SealedFile[];
  readonly #signingTime: Date | null;
  readonly #signer: X509Cert | null;
  readonly #revocationChecked: boolean;

  /** @internal */
  constructor(result: { error: string | null; files?: SealedFile[]; signingTime?: Date | null; signer?: X509Cert | null; revocationChecked?: boolean }) {
    this.#error = result.error;
    this.#files = result.error === null ? Object.freeze([...(result.files ?? [])]) : [];
    this.#signingTime = result.signingTime ?? null;
    this.#signer = result.signer ?? null;
    this.#revocationChecked = result.revocationChecked ?? false;
  }

  /** Indicates whether the seal is valid: structure, algorithms, digests, signature, trust, revocation. */
  isValid(): boolean {
    return this.#error === null;
  }

  /** Why the seal is not valid, or null. */
  getError(): string | null {
    return this.#error;
  }

  /** The level of the seal: 'B' (the time-stamped levels come later), or null if it is not valid. */
  getLevel(): 'B' | null {
    return this.#error === null ? 'B' : null;
  }

  /** The time the signer claims (SigningTime): not a proven one. */
  getSigningTime(): Date | null {
    return this.#signingTime === null ? null : new Date(this.#signingTime);
  }

  /** The proven time of the seal (level T), or null. */
  getTimestampTime(): Date | null {
    return null;
  }

  /** The files the seal covers, in the order of its references; empty if it is not valid. */
  getFiles(): readonly SealedFile[] {
    return this.#files;
  }

  /** The signing certificate, once it has been found. */
  getSigningCertificate(): X509Cert | null {
    return this.#signer;
  }

  /** Indicates whether the revocation of the certificates was checked. */
  isRevocationChecked(): boolean {
    return this.#revocationChecked;
  }
}

/** An invalid seal: the message becomes the error of the verification. */
class InvalidSeal extends Error {}

function invalid(message: string): never {
  throw new InvalidSeal(message);
}

/** The canonicalizations accepted for SignedInfo and the signed properties. */
const CANONICALIZATIONS: ReadonlySet<string> = new Set([alg.EXC_C14N, C14N]);

/**
 * Verifies a seal.
 *
 * @param container The ASiC-E container.
 * @throws {Error} On a misuse: the options are not valid, or a CA
 *   certificate cannot be read. An invalid seal does not throw: see
 *   `getError()`.
 */
export function verifySeal(container: Uint8Array, options: VerifyOptions): SealVerification {
  if (!(container instanceof Uint8Array)) {
    throw new Error('Seal verification: the container must be bytes (Uint8Array).');
  }
  const caCerts = readCaCerts(options?.caCertPath);
  const expectedSubject = options.expectedSubject;
  if (expectedSubject !== undefined && (expectedSubject === null || (typeof expectedSubject !== 'string' && typeof expectedSubject !== 'object') || expectedSubject === '')) {
    throw new Error("Seal verification: invalid option 'expectedSubject'.");
  }
  const checkRevocation = options.revocation ?? true;
  if (typeof checkRevocation !== 'boolean') {
    throw new Error("Seal verification: invalid option 'revocation'.");
  }

  let signer: X509Cert | null = null;
  let signingTime: Date | null = null;
  try {
    const { files, signatureFile } = readContainer(Buffer.from(container), options.limits ?? DEFAULT_ZIP_LIMITS);
    const signature = readSignature(signatureFile, files);
    signer = signature.signer;
    signingTime = signature.signingTime;

    // The trust in the signer, at the current date: SigningTime is claimed
    // by the signer, and cannot date the check of its certificate.
    const certificate = signature.signer;
    if (!certificate.canSign()) {
      invalid('The key usage of the signing certificate does not allow signing.');
    }
    if (!certificate.isTrustedBy(caCerts, { untrusted: signature.chain })) {
      invalid('The signing certificate is not trusted: no valid chain up to a trusted CA certificate.');
    }
    if (expectedSubject !== undefined) {
      const matches = typeof expectedSubject === 'string' ? certificate.getDN() === expectedSubject : matchesName(certificate.getSubject(), expectedSubject);
      if (!matches) {
        invalid('The subject of the signing certificate is not the expected one.');
      }
    }
    if (checkRevocation) {
      invalid('No revocation data for the signing certificate (the option revocation: false verifies the seal without).');
    }
    return new SealVerification({ error: null, files: signature.files, signingTime, signer, revocationChecked: false });
  } catch (error) {
    if (error instanceof InvalidSeal) {
      return new SealVerification({ error: error.message, signingTime, signer });
    }
    throw error;
  }
}

function readCaCerts(source: unknown): PemSource[] {
  const sources = Array.isArray(source) ? source : [source];
  if (source === undefined || sources.length === 0) {
    throw new Error("Seal verification: the option 'caCertPath' is required.");
  }
  return sources.map((item) => {
    const pem = readPem(item);
    if (pem === null) {
      throw new Error(`Seal verification: cannot read the CA certificate file ${describeSource(item)}.`);
    }
    return pem;
  });
}

/** The layout of the container (EN 319 162-1, 4.4.3.2, Table 5, A.1). */
function readContainer(archive: Buffer, limits: ZipLimits): { files: Map<string, Buffer>; signatureFile: Buffer } {
  let entries: ZipEntry[];
  try {
    entries = readZip(archive, limits);
  } catch (error) {
    invalid(`The container is not a valid ZIP archive. ${(error as Error).message}`);
  }
  const files = new Map<string, Buffer>();
  const signatureFiles: ZipEntry[] = [];
  let manifest: ZipEntry | null = null;
  for (const [index, entry] of entries.entries()) {
    if (entry.name === 'mimetype') {
      if (index !== 0 || entry.method !== 0 || entry.extra.length !== 0) {
        invalid('The mimetype file must be the first entry, stored, without extra field.');
      }
      if (entry.content.toString('latin1') !== ASICE_MIMETYPE) {
        invalid(`The container is not an ASiC-E container (mimetype ${JSON.stringify(entry.content.toString('latin1').slice(0, 100))}).`);
      }
    } else if (entry.name.startsWith('META-INF/')) {
      const base = entry.name.slice('META-INF/'.length).toLowerCase();
      if (entry.name === MANIFEST_PATH) {
        manifest = entry;
      } else if (base.includes('signatures') && base.endsWith('.xml') && !base.includes('/')) {
        signatureFiles.push(entry);
      } else if (/signature|timestamp|manifest|evidencerecord/.test(base)) {
        invalid(`Unsupported file in META-INF: ${JSON.stringify(entry.name)} (only XAdES signatures are supported).`);
      }
    } else {
      files.set(entry.name, entry.content);
    }
  }
  if (manifest === null) {
    invalid('The container has no META-INF/manifest.xml.');
  }
  checkManifest(manifest.content);
  if (signatureFiles.length !== 1) {
    invalid(signatureFiles.length === 0 ? 'The container has no signature file.' : 'The container has several signature files: one seal per container is supported.');
  }
  if (files.size === 0) {
    invalid('The container has no file outside META-INF.');
  }
  return { files, signatureFile: (signatureFiles[0] as ZipEntry).content };
}

/** The manifest must be an ODF manifest. It is not signed: the media types of the seal are those of its signature. */
function checkManifest(content: Buffer): void {
  let doc: Document;
  try {
    doc = loadXML(content, 'manifest');
  } catch (error) {
    invalid(`The manifest is not valid: ${(error as Error).message}`);
  }
  const root = doc.documentElement;
  if (root === null || root.namespaceURI !== MANIFEST_NS || root.localName !== 'manifest') {
    invalid('The manifest is not an ODF manifest.');
  }
}

interface ReadSignature {
  files: SealedFile[];
  signingTime: Date;
  signer: X509Cert;
  chain: X509Cert[];
}

/** The XAdES signature (EN 319 132-1, level B-B): its structure, its references, its signed properties, its value. */
function readSignature(content: Buffer, files: Map<string, Buffer>): ReadSignature {
  let doc: Document;
  try {
    doc = loadXML(content, 'XAdES signature');
  } catch (error) {
    invalid(`The signature file is not valid: ${(error as Error).message}`);
  }
  const root = doc.documentElement as Element;
  if (!is(root, ASIC_NS, 'XAdESSignatures')) {
    invalid('The root of the signature file must be asic:XAdESSignatures.');
  }
  const [signature] = sequence(root, [[XMLDSIG_NS, 'Signature', 1, Infinity]]).get('Signature') as Element[];
  if ((root.getElementsByTagNameNS(XMLDSIG_NS, 'Signature').length) !== 1) {
    invalid('The signature file must hold one ds:Signature: one seal per container is supported.');
  }
  // With unique Ids, the reference to the signed properties has one target:
  // the element whose digest is checked below.
  uniqueIds(doc);
  const signatureId = attribute(signature as Element, 'Id', 'ds:Signature');

  const parts = sequence(signature as Element, [
    [XMLDSIG_NS, 'SignedInfo', 1, 1],
    [XMLDSIG_NS, 'SignatureValue', 1, 1],
    [XMLDSIG_NS, 'KeyInfo', 1, 1],
    [XMLDSIG_NS, 'Object', 1, 1],
  ]);
  const signedInfo = first(parts, 'SignedInfo');
  const info = sequence(signedInfo, [
    [XMLDSIG_NS, 'CanonicalizationMethod', 1, 1],
    [XMLDSIG_NS, 'SignatureMethod', 1, 1],
    [XMLDSIG_NS, 'Reference', 2, Infinity],
  ]);
  const canonicalization = algorithmOf(first(info, 'CanonicalizationMethod'));
  if (!CANONICALIZATIONS.has(canonicalization)) {
    invalid(`Unsupported canonicalization of SignedInfo: ${canonicalization}.`);
  }
  const signatureAlgorithm = algorithmOf(first(info, 'SignatureMethod'));
  const scheme = alg.SIGNATURE_SCHEMES[signatureAlgorithm];
  if (scheme === undefined) {
    invalid(`Unsupported signature algorithm: ${signatureAlgorithm}.`);
  }

  // The qualifying properties, in the one ds:Object.
  const qualifying = first(sequence(first(parts, 'Object'), [[XADES_NS, 'QualifyingProperties', 1, 1]]), 'QualifyingProperties');
  if (qualifying.getAttribute('Target') !== `#${signatureId}`) {
    invalid('The Target of QualifyingProperties must be the Id of the signature.');
  }
  const qualifyingParts = sequence(qualifying, [
    [XADES_NS, 'SignedProperties', 1, 1],
    [XADES_NS, 'UnsignedProperties', 0, 1],
  ]);
  if ((qualifyingParts.get('UnsignedProperties') ?? []).length > 0) {
    invalid('Unsigned properties (levels T and beyond) are not supported yet.');
  }
  const signedProperties = first(qualifyingParts, 'SignedProperties');
  const signedPropertiesId = attribute(signedProperties, 'Id', 'xades:SignedProperties');
  const properties = sequence(signedProperties, [
    [XADES_NS, 'SignedSignatureProperties', 1, 1],
    [XADES_NS, 'SignedDataObjectProperties', 1, 1],
  ]);
  const signatureProperties = sequence(first(properties, 'SignedSignatureProperties'), [
    [XADES_NS, 'SigningTime', 1, 1],
    [XADES_NS, 'SigningCertificateV2', 1, 1],
    [XADES_NS, 'SignatureProductionPlaceV2', 0, 1],
    [XADES_NS, 'SignerRoleV2', 0, 1],
  ]);
  const signingTime = parseDateTime(text(first(signatureProperties, 'SigningTime')));
  const cert = first(sequence(first(signatureProperties, 'SigningCertificateV2'), [[XADES_NS, 'Cert', 1, 1]]), 'Cert');
  const certDigest = first(sequence(cert, [[XADES_NS, 'CertDigest', 1, 1], [XADES_NS, 'IssuerSerialV2', 0, 1]]), 'CertDigest');
  const certDigestParts = sequence(certDigest, [[XMLDSIG_NS, 'DigestMethod', 1, 1], [XMLDSIG_NS, 'DigestValue', 1, 1]]);
  const certDigestAlgorithm = digestOf(first(certDigestParts, 'DigestMethod'));
  const certDigestValue = base64(text(first(certDigestParts, 'DigestValue')), 'the digest of the signing certificate');
  const formats = sequence(first(properties, 'SignedDataObjectProperties'), [
    [XADES_NS, 'DataObjectFormat', 1, Infinity],
    [XADES_NS, 'CommitmentTypeIndication', 0, Infinity],
  ]).get('DataObjectFormat') as Element[];
  const mimeTypes = new Map<string, string>();
  for (const format of formats) {
    const target = format.getAttribute('ObjectReference') ?? '';
    const parts = sequence(format, [
      [XADES_NS, 'Description', 0, 1],
      [XADES_NS, 'ObjectIdentifier', 0, 1],
      [XADES_NS, 'MimeType', 1, 1],
      [XADES_NS, 'Encoding', 0, 1],
    ]);
    if (!target.startsWith('#') || mimeTypes.has(target.slice(1))) {
      invalid('Each DataObjectFormat must point at a reference of its own.');
    }
    mimeTypes.set(target.slice(1), text(first(parts, 'MimeType')));
  }

  // The signing certificate, and the chain the seal embeds.
  const certificates = (sequence(first(sequence(first(parts, 'KeyInfo'), [[XMLDSIG_NS, 'X509Data', 1, 1]]), 'X509Data'), [
    [XMLDSIG_NS, 'X509Certificate', 1, Infinity],
  ]).get('X509Certificate') as Element[]).map((element) => base64(text(element), 'a certificate of KeyInfo'));
  const signing = certificates.filter((der) => createHash(certDigestAlgorithm).update(der).digest().equals(certDigestValue));
  if (signing.length === 0) {
    invalid('The signing certificate (SigningCertificateV2) is not in KeyInfo.');
  }
  const signerDer = signing[0] as Buffer;
  let signer: X509Cert;
  let chain: X509Cert[];
  let publicKey: KeyObject;
  try {
    signer = new X509Cert(X509Cert.derToPem(signerDer) as string);
    publicKey = new X509Certificate(signerDer).publicKey;
    chain = certificates.filter((der) => !der.equals(signerDer)).map((der) => new X509Cert(X509Cert.derToPem(der) as string));
  } catch {
    invalid('A certificate of KeyInfo cannot be read.');
  }
  checkSigningKey(publicKey, signatureAlgorithm, scheme);

  // The references: the signed properties once, then each file of the container once.
  const sealed: SealedFile[] = [];
  const covered = new Set<string>();
  let propertiesReferences = 0;
  for (const reference of info.get('Reference') as Element[]) {
    const referenceParts = sequence(reference, [
      [XMLDSIG_NS, 'Transforms', 0, 1],
      [XMLDSIG_NS, 'DigestMethod', 1, 1],
      [XMLDSIG_NS, 'DigestValue', 1, 1],
    ]);
    const digest = digestOf(first(referenceParts, 'DigestMethod'));
    const expected = base64(text(first(referenceParts, 'DigestValue')), 'a DigestValue');
    const transforms = referenceParts.get('Transforms') ?? [];
    const uri = reference.getAttribute('URI');
    const type = reference.getAttribute('Type');
    if (type === SIGNED_PROPERTIES_TYPE) {
      propertiesReferences++;
      if (uri !== `#${signedPropertiesId}`) {
        invalid('The reference of type SignedProperties must point at the signed properties of the signature.');
      }
      if (transforms.length !== 1) {
        invalid('The reference to the signed properties must canonicalize them (one Transform).');
      }
      const transform = first(sequence(transforms[0] as Element, [[XMLDSIG_NS, 'Transform', 1, 1]]), 'Transform');
      const transformAlgorithm = algorithmOf(transform);
      if (!CANONICALIZATIONS.has(transformAlgorithm) || transform.firstChild !== null) {
        invalid(`Unsupported transform of the signed properties: ${transformAlgorithm}.`);
      }
      const computed = createHash(digest).update(canonicalize(signedProperties, transformAlgorithm, null, 'xades:SignedProperties')).digest();
      if (!computed.equals(expected)) {
        invalid('The signed properties have been altered (digest mismatch).');
      }
      continue;
    }
    if (type !== null && type !== '') {
      invalid(`Unsupported reference type: ${type}.`);
    }
    if (transforms.length > 0) {
      invalid('A reference to a file must have no transform.');
    }
    const name = fileName(uri);
    const content = files.get(name);
    if (content === undefined) {
      invalid(`A reference points at no file of the container: ${JSON.stringify(uri)}.`);
    }
    if (covered.has(name)) {
      invalid(`Two references point at the same file: ${JSON.stringify(name)}.`);
    }
    covered.add(name);
    if (!createHash(digest).update(content).digest().equals(expected)) {
      invalid(`The file ${JSON.stringify(name)} has been altered (digest mismatch).`);
    }
    const referenceId = reference.getAttribute('Id') ?? '';
    const mimeType = mimeTypes.get(referenceId);
    if (referenceId === '' || mimeType === undefined) {
      invalid(`The reference to ${JSON.stringify(name)} has no DataObjectFormat.`);
    }
    mimeTypes.delete(referenceId);
    sealed.push({ name, mimeType });
  }
  if (propertiesReferences !== 1) {
    invalid('The signature must have one reference to its signed properties.');
  }
  if (mimeTypes.size > 0) {
    invalid('A DataObjectFormat points at no reference to a file.');
  }
  for (const name of files.keys()) {
    if (!covered.has(name)) {
      invalid(`The file ${JSON.stringify(name)} is in the container but not sealed.`);
    }
  }

  // The signature value, over SignedInfo as the document holds it.
  const signatureValue = base64(text(first(parts, 'SignatureValue')), 'the SignatureValue');
  const data = Buffer.from(canonicalize(signedInfo, canonicalization, null, 'ds:SignedInfo'), 'utf8');
  let verified = false;
  try {
    verified = verify(scheme.hash, data, { key: publicKey, ...scheme.options }, signatureValue);
  } catch {
    verified = false;
  }
  if (!verified) {
    invalid('The signature value is not valid.');
  }
  return { files: sealed, signingTime, signer, chain };
}

/** The key of the signing certificate must suit the signature algorithm, with the sizes the seals accept. */
function checkSigningKey(key: KeyObject, signatureAlgorithm: string, scheme: alg.SignatureScheme): void {
  if (key.asymmetricKeyType !== scheme.keyType) {
    invalid(`The signature algorithm ${signatureAlgorithm} does not suit the key of the signing certificate.`);
  }
  if (scheme.keyType === 'rsa' && (key.asymmetricKeyDetails?.modulusLength ?? 0) < alg.MIN_RSA_BITS) {
    invalid(`The RSA key of the signing certificate has less than ${alg.MIN_RSA_BITS} bits.`);
  }
  if (scheme.keyType === 'ec' && alg.CURVES[key.asymmetricKeyDetails?.namedCurve ?? ''] === undefined) {
    invalid('The EC key of the signing certificate is not on P-256, P-384 or P-521.');
  }
}

/**
 * The name of the file a reference points at: a relative URI, resolved
 * against the root of the container (EN 319 162-1, A.6), each segment
 * percent-decoded. An absolute URI, a query or a fragment points outside.
 */
function fileName(uri: string | null): string {
  if (uri === null || uri === '' || uri.startsWith('/') || /^[A-Za-z][A-Za-z0-9+.-]*:/.test(uri) || /[?#]/.test(uri)) {
    invalid(`A reference to a file must be a relative URI inside the container: ${JSON.stringify(uri)}.`);
  }
  try {
    return uri.split('/').map(decodeURIComponent).join('/');
  } catch {
    invalid(`A reference to a file is not a valid URI: ${JSON.stringify(uri)}.`);
  }
}

/** The element children of an element, checked against a sequence of [namespace, name, min, max]; nothing else is allowed. */
function sequence(parent: Element, spec: [string, string, number, number][]): Map<string, Element[]> {
  const found = new Map<string, Element[]>(spec.map(([, name]) => [name, []]));
  let position = 0;
  for (let node: Node | null = parent.firstChild; node !== null; node = node.nextSibling) {
    if (node.nodeType === node.TEXT_NODE) {
      if ((node.nodeValue ?? '').trim() !== '') {
        invalid(`Unexpected text in ${parent.nodeName}.`);
      }
      continue;
    }
    if (node.nodeType !== node.ELEMENT_NODE) {
      invalid(`Unexpected ${node.nodeName} in ${parent.nodeName}.`);
    }
    const element = node as Element;
    while (position < spec.length && !is(element, spec[position]?.[0] ?? '', spec[position]?.[1] ?? '')) {
      position++;
    }
    const entry = spec[position];
    if (entry === undefined) {
      invalid(`Unexpected or misplaced element ${element.nodeName} in ${parent.nodeName}.`);
    }
    const list = found.get(entry[1]) as Element[];
    list.push(element);
    if (list.length > entry[3]) {
      invalid(`Too many ${element.nodeName} in ${parent.nodeName}.`);
    }
  }
  for (const [namespace, name, min] of spec) {
    if ((found.get(name) as Element[]).length < min) {
      invalid(`Missing ${namespace === XMLDSIG_NS ? 'ds' : 'xades'}:${name} in ${parent.nodeName}.`);
    }
  }
  return found;
}

function first(parts: Map<string, Element[]>, name: string): Element {
  return (parts.get(name) as Element[])[0] as Element;
}

function is(element: Element, namespace: string, name: string): boolean {
  return element.namespaceURI === namespace && element.localName === name;
}

function attribute(element: Element, name: string, what: string): string {
  const value = element.getAttribute(name);
  if (value === null || value === '') {
    invalid(`${what} must have an ${name}.`);
  }
  return value;
}

function algorithmOf(element: Element): string {
  if (element.firstChild !== null && element.localName !== 'DigestMethod') {
    invalid(`Unsupported parameters of ${element.nodeName}.`);
  }
  return attribute(element, 'Algorithm', element.nodeName);
}

function digestOf(element: Element): string {
  const algorithm = attribute(element, 'Algorithm', element.nodeName);
  const digest = alg.DIGESTS[algorithm];
  if (digest === undefined || element.firstChild !== null) {
    invalid(`Unsupported digest algorithm: ${algorithm}.`);
  }
  return digest;
}

/** The text of an element that holds text only. */
function text(element: Element): string {
  for (let node: Node | null = element.firstChild; node !== null; node = node.nextSibling) {
    if (node.nodeType !== node.TEXT_NODE) {
      invalid(`${element.nodeName} must hold text only.`);
    }
  }
  return element.textContent ?? '';
}

/** Base64 content, white space allowed (XML Schema base64Binary). */
function base64(value: string, what: string): Buffer {
  const compact = value.replace(/[\s]/g, '');
  if (compact === '' || compact.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(compact)) {
    invalid(`${what} is not valid base64.`);
  }
  return Buffer.from(compact, 'base64');
}

/** An xsd:dateTime with a time zone, as SigningTime is written. */
function parseDateTime(value: string): Date {
  const match = /^\s*(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})\s*$/.exec(value);
  const time = match === null ? NaN : Date.parse(value.trim());
  if (Number.isNaN(time)) {
    invalid(`SigningTime is not a date and time with a time zone: ${JSON.stringify(value)}.`);
  }
  return new Date(time);
}

/** The Id attributes of the document, which must be unique: a reference by Id must not have two targets. */
function uniqueIds(doc: Document): void {
  const ids = new Set<string>();
  const visit = (element: Element) => {
    const id = element.getAttribute('Id');
    if (id !== null) {
      if (ids.has(id)) {
        invalid(`Two elements have the Id ${JSON.stringify(id)}.`);
      }
      ids.add(id);
    }
    for (let node: Node | null = element.firstChild; node !== null; node = node.nextSibling) {
      if (node.nodeType === node.ELEMENT_NODE) {
        visit(node as Element);
      }
    }
  };
  visit(doc.documentElement as Element);
}
