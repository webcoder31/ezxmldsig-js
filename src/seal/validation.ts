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
 * The extension of a seal to level LT (EN 319 132-1, 5.4, 5.5.1, 6.3): the
 * certificates and the CRLs that validate it, embedded in its unsigned
 * properties, so that a third party can validate it without reaching the
 * CAs.
 *
 * Without network access, as for the time-stamp: validationDataRequests()
 * lists the CRLs to fetch, the caller fetches them, and addValidationData()
 * checks them before it embeds them. The signed parts of the signature
 * file are left byte for byte as they are.
 *
 * What goes where:
 *
 * - xades141:TimeStampValidationData, right after the time-stamp (5.5.1.2):
 *   the certificates of the chain of the time-stamping authority the token
 *   does not hold, and their CRLs;
 * - xades:CertificateValues (5.4.2): the certificates of the chain of the
 *   signer ds:KeyInfo does not hold, its trust anchor included;
 * - xades:RevocationValues (5.4.3): a CRL for each certificate of that
 *   chain, its trust anchor excepted.
 *
 * A certificate or a CRL is embedded once (Table 2, q and v). The CRLs must
 * be issued after the time-stamp: they show that the certificates were not
 * revoked at that time. Right after the time-stamp, a CA has not issued one
 * yet; the extension then waits for its next CRL.
 */

import { TAG, childrenOf, readElement, readElements } from '../der.js';
import type { PemSource } from '../material.js';
import type { X509Cert } from '../x509.js';
import { loadXML } from '../xml.js';
import type { Crl } from './crl.js';
import { locate } from './extend.js';
import { XADES141_NS, XADES_NS } from './seal.js';
import { inspectSeal, type InspectedSeal } from './verify.js';
import { readZip, writeZip } from './zip.js';

const CRL_DISTRIBUTION_POINTS = '2.5.29.31';

export interface ValidationDataOptions {
  /** The trusted CA certificates of the signer, as for verifySeal(). */
  readonly caCertPath: PemSource | readonly PemSource[];
  /** The trusted certificates of the time-stamping authority, as for verifySeal(). */
  readonly tsaCertPath: PemSource | readonly PemSource[];
}

export interface AddValidationDataOptions extends ValidationDataOptions {
  /** The CRLs, in DER or PEM, fetched from the URLs validationDataRequests() lists. */
  readonly crls: readonly Uint8Array[];
}

/** A CRL to fetch: for a certificate, from the URLs of its CRL distribution points. */
export interface CrlRequest {
  readonly certificate: X509Cert;
  /** Its issuer, whose CRL it is. */
  readonly issuer: X509Cert;
  /** The http and https URLs of its CRL distribution points; empty if it names none. */
  readonly urls: readonly string[];
}

/**
 * The CRLs a seal needs: one for each certificate of the chains of the
 * signer and of the time-stamping authority, their trust anchors excepted.
 * Also useful at level B or T, to get the CRLs verifySeal() needs.
 *
 * @throws {Error} If the seal is not valid, revocation aside.
 */
export function validationDataRequests(container: Uint8Array, options: ValidationDataOptions): { crls: CrlRequest[] } {
  const inspected = inspect(container, { ...options, revocation: false });
  const crls: CrlRequest[] = [];
  for (const chain of [inspected.chain, inspected.tsaChain]) {
    for (let index = 0; chain !== null && index + 1 < chain.length; index++) {
      const certificate = chain[index] as X509Cert;
      if (!crls.some((request) => request.certificate.getDer().equals(certificate.getDer()))) {
        crls.push({ certificate, issuer: chain[index + 1] as X509Cert, urls: distributionPoints(certificate) });
      }
    }
  }
  return { crls };
}

/**
 * Adds to a seal of level T the certificates and the CRLs that validate
 * it: it becomes a seal of level LT.
 *
 * @returns The container, with the validation data in its signature.
 * @throws {Error} If the seal is not valid, is not of level T, or if the
 *   CRLs do not tell the status of every certificate after the time-stamp.
 */
export function addValidationData(container: Uint8Array, options: AddValidationDataOptions): Buffer {
  if (!Array.isArray(options?.crls)) {
    throw new Error("Validation data: the option 'crls' is required: an array of CRLs (Uint8Array).");
  }
  const inspected = inspect(container, { caCertPath: options.caCertPath, tsaCertPath: options.tsaCertPath, crls: options.crls });
  const level = inspected.result.getLevel();
  if (level !== 'T') {
    throw new Error(level === 'B' ? 'Validation data: the seal must be time-stamped first (level T).' : 'Validation data: the seal already has validation data.');
  }
  const chain = inspected.chain as X509Cert[];
  const tsaChain = inspected.tsaChain as X509Cert[];

  // Each certificate and each CRL once: the signer's first, then what the
  // time-stamping authority needs besides.
  const held = [...inspected.keyInfo, ...inspected.tokenCertificates];
  const signerCertificates = unique(chain.map((cert) => cert.getDer()), inspected.keyInfo);
  const tsaCertificates = unique(tsaChain.map((cert) => cert.getDer()), [...held, ...signerCertificates]);
  const signerCrls = unique(inspected.signerCrls.map((crl: Crl) => crl.der), []);
  const tsaCrls = unique(inspected.tsaCrls.map((crl: Crl) => crl.der), signerCrls);

  const entries = readZip(Buffer.from(container));
  const { entry, signature } = locate(entries, 'Validation data');
  const properties = signature.getElementsByTagNameNS(XADES_NS, 'UnsignedSignatureProperties');
  const xml = entry.content.toString('utf8');
  const closing = `</${properties[0]?.nodeName ?? ''}>`;
  const at = xml.indexOf(closing);
  if (properties.length !== 1 || at < 0 || xml.indexOf(closing, at + 1) >= 0) {
    throw new Error('Validation data: the end of the unsigned signature properties cannot be told in the signature file.');
  }
  const timestampData = tsaCertificates.length + tsaCrls.length === 0 ? ''
    : `<xades141:TimeStampValidationData xmlns:xades141="${XADES141_NS}">${certificateValues(tsaCertificates)}${revocationValues(tsaCrls)}</xades141:TimeStampValidationData>`;
  const added = timestampData + certificateValues(signerCertificates) + revocationValues(signerCrls);
  const extended = xml.slice(0, at) + added + xml.slice(at);
  loadXML(extended, 'XAdES signature');

  const result = writeZip(entries.map((e) => ({
    name: e.name,
    content: e === entry ? Buffer.from(extended, 'utf8') : e.content,
    stored: e.method === 0,
  })), new Date());

  // The seal must now validate with what it embeds alone.
  const check = inspectSeal(result, { caCertPath: options.caCertPath, tsaCertPath: options.tsaCertPath });
  if (check.result.getLevel() !== 'LT') {
    throw new Error(`Validation data: the extended seal does not validate by itself. ${check.result.getError() ?? `Level ${check.result.getLevel()}.`}`);
  }
  return result;
}

/** inspectSeal(), an invalid seal turned into an exception. */
function inspect(container: Uint8Array, options: Parameters<typeof inspectSeal>[1]): InspectedSeal {
  if (options.tsaCertPath === undefined) {
    throw new Error("Validation data: the option 'tsaCertPath' is required.");
  }
  let inspected: InspectedSeal;
  try {
    inspected = inspectSeal(container, options, true);
  } catch (error) {
    throw new Error(`Validation data: ${(error as Error).message}`);
  }
  const error = inspected.result.getError();
  if (error !== null) {
    throw new Error(`Validation data: the seal is not valid. ${error}`);
  }
  return inspected;
}

/** The DER encodings of a list, without duplicates nor those of `held`. */
function unique(list: Buffer[], held: readonly Buffer[]): Buffer[] {
  const kept: Buffer[] = [];
  for (const der of list) {
    if (!held.some((other) => other.equals(der)) && !kept.some((other) => other.equals(der))) {
      kept.push(der);
    }
  }
  return kept;
}

function certificateValues(certificates: readonly Buffer[]): string {
  return certificates.length === 0 ? ''
    : `<xades:CertificateValues xmlns:xades="${XADES_NS}">${certificates.map((der) => `<xades:EncapsulatedX509Certificate>${der.toString('base64')}</xades:EncapsulatedX509Certificate>`).join('')}</xades:CertificateValues>`;
}

function revocationValues(crls: readonly Buffer[]): string {
  return crls.length === 0 ? ''
    : `<xades:RevocationValues xmlns:xades="${XADES_NS}"><xades:CRLValues>${crls.map((der) => `<xades:EncapsulatedCRLValue>${der.toString('base64')}</xades:EncapsulatedCRLValue>`).join('')}</xades:CRLValues></xades:RevocationValues>`;
}

/**
 * The http and https URLs of the CRL distribution points of a certificate
 * (RFC 5280, 4.2.1.13). A distribution point restricted to some reasons or
 * with a CRL issuer of its own is left out: its CRLs are partial or
 * indirect, which this library does not use.
 */
function distributionPoints(certificate: X509Cert): string[] {
  const extension = certificate.getExtension(CRL_DISTRIBUTION_POINTS);
  if (extension === null) {
    return [];
  }
  const urls: string[] = [];
  try {
    for (const point of childrenOf(readElement(extension.value), TAG.SEQUENCE)) {
      const fields = childrenOf(point, TAG.SEQUENCE);
      // distributionPoint [0], reasons [1], cRLIssuer [2].
      if (fields.some((field) => field.tag !== 0xa0)) {
        continue;
      }
      for (const name of fields.flatMap((field) => readElements(field.content))) {
        // fullName [0] GeneralNames, of which uniformResourceIdentifier [6].
        if (name.tag !== 0xa0) {
          continue;
        }
        for (const general of readElements(name.content)) {
          const url = general.content.toString('latin1');
          if (general.tag === 0x86 && /^https?:\/\//i.test(url)) {
            urls.push(url);
          }
        }
      }
    }
  } catch {
    return [];
  }
  return urls;
}
