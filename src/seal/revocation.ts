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
 * The revocation status of the certificates of a chain, from CRLs (see
 * design/seal.md, "Verification rules").
 *
 * Every certificate of the chain but its trust anchor needs a CRL of its
 * issuer that tells its status:
 *
 * - at the current date (a seal of level B, the time-stamping authority):
 *   the CRL is current, its next update not passed, and the certificate is
 *   not listed;
 * - at the time of a time-stamp (a seal of level T): the CRL was issued
 *   after that time, and the certificate is not listed, or was revoked
 *   after that time only.
 *
 * A CRL issued after the certificate expired proves nothing of it, since a
 * CA may drop the expired certificates from its CRLs, unless the CRL keeps
 * them (ExpiredCertsOnCRL).
 */

import type { X509Cert } from '../x509.js';
import { crlCovers, revocationDate, type Crl } from './crl.js';

/** When the status is checked: at the current date, or at the time of a time-stamp. */
export type RevocationTime = { readonly kind: 'current'; readonly now: Date } | { readonly kind: 'timestamp'; readonly time: Date; readonly now: Date };

/**
 * Checks the revocation status of a chain.
 *
 * @param chain The chain, from the certificate to its trust anchor.
 * @returns Null if no certificate of the chain is revoked, or why the
 *   status cannot be told or is a revocation.
 */
export function checkRevocation(chain: readonly X509Cert[], crls: readonly Crl[], when: RevocationTime): string | null {
  for (let index = 0; index + 1 < chain.length; index++) {
    const certificate = chain[index] as X509Cert;
    const issuer = chain[index + 1] as X509Cert;
    const name = JSON.stringify(certificate.getDN());
    const covering = crls.filter((crl) => crlCovers(crl, certificate, issuer) === null);
    if (covering.length === 0) {
      return `No revocation data for the certificate ${name}: no CRL of its issuer.`;
    }
    const validTo = new Date(certificate.getValidTo());
    const usable = covering
      .filter((crl) => crl.thisUpdate <= when.now)
      .filter((crl) => crl.thisUpdate <= validTo || (crl.expiredCertsOnCrl !== null && crl.expiredCertsOnCrl <= validTo))
      .filter((crl) => (when.kind === 'current' ? crl.nextUpdate !== null && when.now <= crl.nextUpdate : crl.thisUpdate >= when.time))
      .sort((a, b) => b.thisUpdate.getTime() - a.thisUpdate.getTime());
    const crl = usable[0];
    if (crl === undefined) {
      return when.kind === 'current'
        ? `No current revocation data for the certificate ${name}: the CRLs of its issuer are past their next update, or issued after it expired.`
        : `No revocation data for the certificate ${name} issued after the time-stamp (${when.time.toISOString()}), while it was valid.`;
    }
    const revoked = revocationDate(crl, certificate);
    if (revoked !== null && (when.kind === 'current' || revoked <= when.time)) {
      return `The certificate ${name} is revoked since ${revoked.toISOString()}${when.kind === 'timestamp' ? ', before the time-stamp' : ''}.`;
    }
  }
  return null;
}
