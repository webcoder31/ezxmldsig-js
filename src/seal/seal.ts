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
 * The creation of seals: files sealed by a detached XAdES baseline signature
 * (ETSI EN 319 132-1, level B-B), in an ASiC-E container (ETSI EN 319 162-1).
 * See design/seal.md for the structure and the rules followed.
 */

import { X509Certificate, createHash, createPrivateKey, createPublicKey, randomBytes, sign, type KeyObject } from 'node:crypto';

import { XMLDSIG_NS } from '../core/algorithms.js';
import { canonicalize } from '../core/c14n.js';
import { escapeAttribute, escapeText } from '../core/encoding.js';
import { describeSource, extractCertificates, readPem, type PemSource } from '../core/material.js';
import { X509Cert } from '../core/x509.js';
import { loadXML } from '../core/xml.js';
import * as alg from './algorithms.js';
import { writeZip } from './zip.js';

export const ASIC_NS = 'http://uri.etsi.org/02918/v1.2.1#';
export const XADES_NS = 'http://uri.etsi.org/01903/v1.3.2#';
/** The namespace of the properties XAdES 1.4.1 added, such as TimeStampValidationData. */
export const XADES141_NS = 'http://uri.etsi.org/01903/v1.4.1#';
export const MANIFEST_NS = 'urn:oasis:names:tc:opendocument:xmlns:manifest:1.0';
export const SIGNED_PROPERTIES_TYPE = 'http://uri.etsi.org/01903#SignedProperties';
export const ASICE_MIMETYPE = 'application/vnd.etsi.asic-e+zip';

/** The path of the signature in the container. */
export const SIGNATURE_PATH = 'META-INF/signatures001.xml';
export const MANIFEST_PATH = 'META-INF/manifest.xml';

/** A file to seal. */
export interface SealFile {
  /** Its path in the container, `/` separated, outside `META-INF/`. */
  readonly name: string;
  /** Its bytes. */
  readonly content: Uint8Array;
  /** Its media type; by default, from the extension of its name (see MEDIA_TYPES). */
  readonly mimeType?: string;
}

/** The options of createSeal(). */
export interface SealOptions {
  /** Certificates of the path of the signing certificate, to embed for the verifier (intermediate CAs). */
  readonly chain?: readonly PemSource[];
  /** The signature algorithm; by default, RSA-PSS for an RSA key, ECDSA for an EC key (its digest after the curve). */
  readonly signatureAlgorithm?: string;
  /** The digest of the sealed files, the signed properties and the signing certificate (default SHA-256). */
  readonly digestAlgorithm?: string;
  /** The time the signer claims (default: now), written to the second. */
  readonly signingTime?: Date;
}

/** The media types written for the most common extensions; any other file is application/octet-stream. */
export const MEDIA_TYPES: Readonly<Record<string, string>> = {
  pdf: 'application/pdf',
  txt: 'text/plain',
  md: 'text/markdown',
  html: 'text/html',
  htm: 'text/html',
  xml: 'application/xml',
  json: 'application/json',
  csv: 'text/csv',
  png: 'image/png',
  jpg: 'image/jpeg',
  jpeg: 'image/jpeg',
  svg: 'image/svg+xml',
  odt: 'application/vnd.oasis.opendocument.text',
  docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
};

/** A media type: type/subtype, then parameters (RFC 6838, 4.2). */
const MEDIA_TYPE = /^[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}\/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}(\s*;\s*[A-Za-z0-9!#$&^_.+-]+=("[^"\\\r\n]*"|[A-Za-z0-9!#$&^_.+-]+))*$/;

/**
 * Seals files: an ASiC-E container that holds them, its manifest, and a
 * XAdES-B-B signature over them.
 *
 * @param files The files to seal, in the order of the container.
 * @param signKey The private key, a PEM file or content.
 * @param signCert The certificate of the key, a PEM file or content; the
 *   certificates that follow the first one are embedded as its chain.
 * @param signKeyPassword The password of the key, or null.
 * @returns The container (`.asice`).
 * @throws {Error} On a misuse: no file, a name or a media type that cannot
 *   be sealed, a key that does not match the certificate, an algorithm that
 *   does not suit the key, a certificate that cannot sign at `signingTime`.
 */
export function createSeal(
  files: readonly SealFile[],
  signKey: PemSource,
  signCert: PemSource,
  signKeyPassword: string | null,
  options: SealOptions = {},
): Buffer {
  if (!Array.isArray(files) || files.length === 0) {
    throw new Error('Seal: no file to seal.');
  }
  const sealed = files.map(checkFile);

  const certPem = readPem(signCert);
  if (certPem === null) {
    throw new Error(`Seal: unable to read the signing certificate (${describeSource(signCert)}).`);
  }
  const certificates = extractCertificates(certPem);
  for (const source of options.chain ?? []) {
    const pem = readPem(source);
    if (pem === null) {
      throw new Error(`Seal: unable to read a chain certificate (${describeSource(source)}).`);
    }
    certificates.push(...extractCertificates(pem));
  }
  const signingCertBase64 = certificates[0];
  if (signingCertBase64 === undefined) {
    throw new Error('Seal: the signing certificate holds no certificate.');
  }
  const certificateDer = Buffer.from(signingCertBase64, 'base64');
  const certificate = new X509Cert(X509Cert.derToPem(certificateDer) as string);

  const keyPem = readPem(signKey);
  if (keyPem === null) {
    throw new Error(`Seal: unable to read the signing key (${describeSource(signKey)}).`);
  }
  let privateKey: KeyObject;
  try {
    privateKey = createPrivateKey({ key: keyPem, format: 'pem', ...(signKeyPassword === null ? {} : { passphrase: signKeyPassword }) });
  } catch {
    throw new Error('Seal: unable to load the signing key (wrong password?).');
  }
  const publicKey = new X509Certificate(certificateDer).publicKey;
  if (!createPublicKey(privateKey).export({ type: 'spki', format: 'der' }).equals(publicKey.export({ type: 'spki', format: 'der' }))) {
    throw new Error('Seal: the signing key does not match the signing certificate.');
  }
  const signatureAlgorithm = options.signatureAlgorithm ?? defaultSignatureAlgorithm(privateKey);
  checkKey(privateKey, signatureAlgorithm);
  const scheme = alg.SIGNATURE_SCHEMES[signatureAlgorithm] as alg.SignatureScheme;

  const digestAlgorithm = options.digestAlgorithm ?? alg.SHA256;
  const digest = alg.DIGESTS[digestAlgorithm];
  if (digest === undefined) {
    throw new Error(`Seal: unsupported digest algorithm ${digestAlgorithm}.`);
  }

  const signingTime = new Date(Math.floor((options.signingTime ?? new Date()).getTime() / 1000) * 1000);
  if (Number.isNaN(signingTime.getTime())) {
    throw new Error('Seal: invalid signing time.');
  }
  if (signingTime < new Date(certificate.getValidFrom()) || signingTime > new Date(certificate.getValidTo())) {
    throw new Error('Seal: the signing certificate is not valid at the signing time.');
  }
  if (!certificate.canSign()) {
    throw new Error('Seal: the key usage of the signing certificate does not allow signing.');
  }

  // Identifiers of the signature, of its references, of its signed properties.
  const id = `S-${randomBytes(16).toString('hex')}`;
  const ds = 'ds:';
  const hash = (data: Uint8Array | string) => createHash(digest).update(data).digest('base64');
  const method = (name: string, algorithm: string) => `<${ds}${name} Algorithm="${escapeAttribute(algorithm)}"/>`;

  const fileReferences = sealed
    .map((file, index) => `<${ds}Reference Id="${id}-R${index + 1}" URI="${escapeAttribute(referenceUri(file.name))}">`
      + method('DigestMethod', digestAlgorithm)
      + `<${ds}DigestValue>${hash(file.content)}</${ds}DigestValue></${ds}Reference>`)
    .join('');
  const signedProperties = `<xades:SignedProperties Id="${id}-SP">`
    + '<xades:SignedSignatureProperties>'
    + `<xades:SigningTime>${signingTime.toISOString().replace(/\.\d{3}Z$/, 'Z')}</xades:SigningTime>`
    + '<xades:SigningCertificateV2><xades:Cert><xades:CertDigest>'
    + method('DigestMethod', digestAlgorithm)
    + `<${ds}DigestValue>${hash(certificateDer)}</${ds}DigestValue>`
    + '</xades:CertDigest></xades:Cert></xades:SigningCertificateV2>'
    + '</xades:SignedSignatureProperties>'
    + '<xades:SignedDataObjectProperties>'
    + sealed.map((file, index) => `<xades:DataObjectFormat ObjectReference="#${id}-R${index + 1}">`
      + `<xades:MimeType>${escapeText(file.mimeType)}</xades:MimeType></xades:DataObjectFormat>`).join('')
    + '</xades:SignedDataObjectProperties>'
    + '</xades:SignedProperties>';

  const document = (propertiesDigest: string, signatureValue: string) => '<?xml version="1.0" encoding="UTF-8"?>'
    + `<asic:XAdESSignatures xmlns:asic="${ASIC_NS}">`
    + `<${ds}Signature xmlns:ds="${XMLDSIG_NS}" Id="${id}">`
    + `<${ds}SignedInfo>`
    + method('CanonicalizationMethod', alg.EXC_C14N)
    + method('SignatureMethod', signatureAlgorithm)
    + fileReferences
    + `<${ds}Reference Type="${SIGNED_PROPERTIES_TYPE}" URI="#${id}-SP">`
    + `<${ds}Transforms>${method('Transform', alg.EXC_C14N)}</${ds}Transforms>`
    + method('DigestMethod', digestAlgorithm)
    + `<${ds}DigestValue>${propertiesDigest}</${ds}DigestValue></${ds}Reference>`
    + `</${ds}SignedInfo>`
    + `<${ds}SignatureValue Id="${id}-SV">${signatureValue}</${ds}SignatureValue>`
    + `<${ds}KeyInfo><${ds}X509Data>${certificates.map((cert) => `<${ds}X509Certificate>${cert}</${ds}X509Certificate>`).join('')}</${ds}X509Data></${ds}KeyInfo>`
    + `<${ds}Object><xades:QualifyingProperties xmlns:xades="${XADES_NS}" Target="#${id}">${signedProperties}</xades:QualifyingProperties></${ds}Object>`
    + `</${ds}Signature></asic:XAdESSignatures>`;

  // The digest of the signed properties, then the signature of SignedInfo,
  // each computed over the document as it will be read.
  let doc = loadXML(document('', ''), 'XAdES signature');
  const properties = doc.getElementsByTagNameNS(XADES_NS, 'SignedProperties')[0];
  if (properties === undefined) {
    throw new Error('Seal: SignedProperties not found.');
  }
  const propertiesDigest = hash(canonicalize(properties, alg.EXC_C14N, null, 'xades:SignedProperties'));

  doc = loadXML(document(propertiesDigest, ''), 'XAdES signature');
  const signedInfo = doc.getElementsByTagNameNS(XMLDSIG_NS, 'SignedInfo')[0];
  if (signedInfo === undefined) {
    throw new Error('Seal: SignedInfo not found.');
  }
  const signatureValue = sign(
    scheme.hash,
    Buffer.from(canonicalize(signedInfo, alg.EXC_C14N, null, 'ds:SignedInfo'), 'utf8'),
    { key: privateKey, ...scheme.options },
  ).toString('base64');

  return writeZip(
    [
      { name: 'mimetype', content: Buffer.from(ASICE_MIMETYPE), stored: true },
      ...sealed.map((file) => ({ name: file.name, content: Buffer.from(file.content) })),
      { name: MANIFEST_PATH, content: Buffer.from(manifest(sealed), 'utf8') },
      { name: SIGNATURE_PATH, content: Buffer.from(document(propertiesDigest, signatureValue), 'utf8') },
    ],
    signingTime,
  );
}

/** The reference to a file of the container: a relative URI, each segment of its path percent-encoded. */
export function referenceUri(name: string): string {
  return name.split('/').map(encodeURIComponent).join('/');
}

/** The ODF manifest of the container (EN 319 162-1, A.4): the container itself, then each sealed file. */
function manifest(files: readonly Required<SealFile>[]): string {
  return '<?xml version="1.0" encoding="UTF-8"?>'
    + `<manifest:manifest xmlns:manifest="${MANIFEST_NS}" manifest:version="1.2">`
    + `<manifest:file-entry manifest:full-path="/" manifest:media-type="${ASICE_MIMETYPE}"/>`
    + files.map((file) => `<manifest:file-entry manifest:full-path="${escapeAttribute(file.name)}" manifest:media-type="${escapeAttribute(file.mimeType)}"/>`).join('')
    + '</manifest:manifest>';
}

function checkFile(file: SealFile, index: number): Required<SealFile> {
  if (file === null || typeof file !== 'object' || typeof file.name !== 'string' || !(file.content instanceof Uint8Array)) {
    throw new Error(`Seal: file ${index + 1} must have a name and a content (Uint8Array).`);
  }
  const { name } = file;
  if (name === 'mimetype' || name.startsWith('META-INF/') || name === 'META-INF') {
    throw new Error(`Seal: ${JSON.stringify(name)} is reserved by the container.`);
  }
  if (name !== name.normalize('NFC')) {
    throw new Error(`Seal: the name ${JSON.stringify(name)} is not in Unicode normalization form C.`);
  }
  const extension = /\.([^./]+)$/.exec(name)?.[1]?.toLowerCase();
  const mimeType = file.mimeType ?? (extension === undefined ? undefined : MEDIA_TYPES[extension]) ?? 'application/octet-stream';
  if (typeof mimeType !== 'string' || !MEDIA_TYPE.test(mimeType)) {
    throw new Error(`Seal: invalid media type for ${JSON.stringify(name)}.`);
  }
  return { name, content: file.content, mimeType };
}

function defaultSignatureAlgorithm(key: KeyObject): string {
  if (key.asymmetricKeyType === 'rsa') {
    return alg.RSA_PSS_SHA256;
  }
  if (key.asymmetricKeyType === 'ec') {
    const curve = alg.CURVES[key.asymmetricKeyDetails?.namedCurve ?? ''];
    if (curve !== undefined) {
      return curve;
    }
  }
  throw new Error('Seal: the signing key must be an RSA key or an EC key on P-256, P-384 or P-521.');
}

function checkKey(key: KeyObject, signatureAlgorithm: string): void {
  const scheme = alg.SIGNATURE_SCHEMES[signatureAlgorithm];
  if (scheme === undefined) {
    throw new Error(`Seal: unsupported signature algorithm ${signatureAlgorithm}.`);
  }
  if (key.asymmetricKeyType !== scheme.keyType) {
    throw new Error(`Seal: the signature algorithm ${signatureAlgorithm} needs an ${scheme.keyType.toUpperCase()} key.`);
  }
  if (scheme.keyType === 'rsa' && (key.asymmetricKeyDetails?.modulusLength ?? 0) < alg.MIN_RSA_BITS) {
    throw new Error(`Seal: RSA keys of less than ${alg.MIN_RSA_BITS} bits are refused.`);
  }
  if (scheme.keyType === 'ec' && alg.CURVES[key.asymmetricKeyDetails?.namedCurve ?? ''] === undefined) {
    throw new Error('Seal: the EC key must be on P-256, P-384 or P-521.');
  }
}
