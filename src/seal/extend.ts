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
 * The extension of a seal to level T (EN 319 132-1, 5.3): a signature
 * time-stamp over the ds:SignatureValue element, in the unsigned properties.
 *
 * Without network access: timestampRequest() builds the request, the caller
 * sends it to the time-stamping authority of its choice, and
 * addSignatureTimestamp() checks the response before it embeds the token.
 * The signed parts of the signature file are left byte for byte as they
 * are: the unsigned properties are inserted after the signed ones.
 */

import { createHash } from 'node:crypto';

import type { Document, Element } from '@xmldom/xmldom';

import { XMLDSIG_NS } from '../algorithms.js';
import { canonicalize } from '../c14n.js';
import { escapeAttribute } from '../encoding.js';
import { describeSource, readPem, type PemSource } from '../material.js';
import { loadXML } from '../xml.js';
import * as alg from './algorithms.js';
import { XADES_NS } from './seal.js';
import { buildTimestampRequest, readTimestampResponse, verifyTimestampToken } from './timestamp.js';
import { readZip, writeZip, type ZipEntry } from './zip.js';

/** The canonicalization of ds:SignatureValue for its time-stamp. */
export const TIMESTAMP_CANONICALIZATION = alg.EXC_C14N;

export interface TimestampOptions {
  /** The trusted certificates of the time-stamping authority: its root, and its intermediate CAs if the token does not embed them. */
  readonly tsaCertPath: PemSource | readonly PemSource[];
}

/**
 * The time-stamp request of a seal (RFC 3161 TimeStampReq, DER), to send to
 * a time-stamping authority, with the media type
 * `application/timestamp-query`.
 *
 * @param digestAlgorithm The digest of the imprint: SHA256 (default), SHA384 or SHA512.
 * @throws {Error} If the container does not hold one XAdES signature.
 */
export function timestampRequest(container: Uint8Array, digestAlgorithm: string = alg.SHA256): Buffer {
  const digest = alg.DIGESTS[digestAlgorithm];
  if (digest === undefined) {
    throw new Error(`Time-stamp: unsupported digest algorithm ${digestAlgorithm}.`);
  }
  const { signatureValue } = locate(readZip(Buffer.from(container)));
  return buildTimestampRequest(imprintOf(signatureValue, digest), digest);
}

/**
 * Adds the signature time-stamp of a response to a seal: level B becomes
 * level T.
 *
 * @param response The response of the authority (RFC 3161 TimeStampResp, DER).
 * @returns The container, with the time-stamp in its signature.
 * @throws {Error} If the authority did not grant the time-stamp, if the token
 *   is not valid, is not over this seal, or its authority is not trusted, or
 *   if the seal is already time-stamped.
 */
export function addSignatureTimestamp(container: Uint8Array, response: Uint8Array, options: TimestampOptions): Buffer {
  const tsaCerts = readTrusted(options?.tsaCertPath, 'tsaCertPath');
  const entries = readZip(Buffer.from(container));
  const { entry, signature, signatureValue, signedProperties } = locate(entries);
  if ((signedProperties.parentNode as Element).getElementsByTagNameNS(XADES_NS, 'UnsignedProperties').length > 0) {
    throw new Error('Time-stamp: the seal already has unsigned properties.');
  }

  const token = readTimestampResponse(Buffer.from(response));
  const verified = verifyTimestampToken(token);
  if (!verified.imprint.equals(imprintOf(signatureValue, verified.imprintAlgorithm))) {
    throw new Error('Time-stamp: the token is not over the signature of this seal.');
  }
  if (!verified.certificate.isTrustedBy(tsaCerts, { untrusted: verified.chain })) {
    throw new Error('Time-stamp: the time-stamping authority is not trusted.');
  }

  // Inserted after the closing tag of SignedProperties, the namespaces
  // declared on the inserted elements themselves.
  const xml = entry.content.toString('utf8');
  const closing = `</${signedProperties.nodeName}>`;
  const at = xml.indexOf(closing);
  if (at < 0 || xml.indexOf(closing, at + 1) >= 0) {
    throw new Error('Time-stamp: the end of the signed properties cannot be told in the signature file.');
  }
  // An Id of its own, as DSS writes one, unless the signature has no Id to derive it from.
  const id = `${signature.getAttribute('Id') ?? ''}-TS`;
  const idAttribute = id === '-TS' || xml.includes(`"${id}"`) ? '' : ` Id="${escapeAttribute(id)}"`;
  const unsigned = `<xades:UnsignedProperties xmlns:xades="${XADES_NS}"><xades:UnsignedSignatureProperties>`
    + `<xades:SignatureTimeStamp${idAttribute}>`
    + `<ds:CanonicalizationMethod xmlns:ds="${XMLDSIG_NS}" Algorithm="${TIMESTAMP_CANONICALIZATION}"/>`
    + `<xades:EncapsulatedTimeStamp>${token.toString('base64')}</xades:EncapsulatedTimeStamp>`
    + '</xades:SignatureTimeStamp></xades:UnsignedSignatureProperties></xades:UnsignedProperties>';
  const extended = xml.slice(0, at + closing.length) + unsigned + xml.slice(at + closing.length);
  loadXML(extended, 'XAdES signature');

  return writeZip(entries.map((e) => ({
    name: e.name,
    content: e === entry ? Buffer.from(extended, 'utf8') : e.content,
    stored: e.method === 0,
  })), verified.time);
}

/** The digest a signature time-stamp is over: ds:SignatureValue, canonicalized (EN 319 132-1, 5.3). */
export function imprintOf(signatureValue: Element, digest: string, canonicalization: string = TIMESTAMP_CANONICALIZATION): Buffer {
  return createHash(digest).update(canonicalize(signatureValue, canonicalization, null, 'ds:SignatureValue'), 'utf8').digest();
}

/** @internal The signature file of a seal, and its elements the time-stamp needs. */
export function locate(entries: ZipEntry[], what = 'Time-stamp'): { entry: ZipEntry; doc: Document; signature: Element; signatureValue: Element; signedProperties: Element } {
  const files = entries.filter((e) => /^META-INF\/[^/]*signatures[^/]*\.xml$/i.test(e.name));
  if (files.length !== 1) {
    throw new Error(`${what}: the container must hold one signature file.`);
  }
  const entry = files[0] as ZipEntry;
  const doc = loadXML(entry.content, 'XAdES signature');
  const signatures = doc.getElementsByTagNameNS(XMLDSIG_NS, 'Signature');
  if (signatures.length !== 1) {
    throw new Error(`${what}: the signature file must hold one ds:Signature.`);
  }
  const signature = signatures[0] as Element;
  const values = [...signature.childNodes].filter((n) => (n as Element).localName === 'SignatureValue' && (n as Element).namespaceURI === XMLDSIG_NS);
  const properties = signature.getElementsByTagNameNS(XADES_NS, 'SignedProperties');
  if (values.length !== 1 || properties.length !== 1) {
    throw new Error(`${what}: the signature has no SignatureValue or no SignedProperties.`);
  }
  return { entry, doc, signature, signatureValue: values[0] as Element, signedProperties: properties[0] as Element };
}

function readTrusted(source: unknown, name: string): string[] {
  const sources = Array.isArray(source) ? source : [source];
  if (source === undefined || sources.length === 0) {
    throw new Error(`Time-stamp: the option '${name}' is required.`);
  }
  return sources.map((item) => {
    const pem = readPem(item);
    if (pem === null) {
      throw new Error(`Time-stamp: cannot read the certificate file ${describeSource(item)}.`);
    }
    return pem;
  });
}
