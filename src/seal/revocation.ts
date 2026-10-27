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
 * issuer that tells its status. Two questions are told apart:
 *
 * - which CRLs count: current ones, their next update not passed (a seal
 *   of level B, the time-stamping authority of a seal of level T), or ones
 *   issued after a time-stamp (the signer of a seal of level T or LT, and
 *   its time-stamping authority at level LT, whose CRLs are embedded and
 *   no longer current when the seal is verified);
 * - which revocation makes the certificate unusable: any one, or one at or
 *   before the time-stamp only, the time-stamp proving that the seal
 *   existed before.
 *
 * The certificates of a time-stamping authority follow RFC 3161, 4: a
 * revocation after the time-stamp leaves its tokens valid only if the CRL
 * gives a reason that is not a compromise of a key. Without a reason, or
 * for a key compromise, every token of the authority is distrusted.
 *
 * A CRL issued after the certificate expired proves nothing of it, since a
 * CA may drop the expired certificates from its CRLs, unless the CRL keeps
 * them (ExpiredCertsOnCRL).
 */

import type { X509Cert } from '../x509.js';
import { crlCovers, revocationOf, type Crl, type Revocation } from './crl.js';

/** The reason codes (RFC 5280, 5.3.1) of a compromise: keyCompromise, cACompromise, aACompromise. */
const COMPROMISE_REASONS: ReadonlySet<number> = new Set([1, 2, 10]);

/** How the status of a chain is checked. */
export interface RevocationCheck {
  readonly now: Date;
  /** Null: the CRLs must be current. A time: they must be issued after it. */
  readonly issuedAfter: Date | null;
  /** Null: any revocation counts. A time: a revocation after it leaves the certificate usable. */
  readonly time: Date | null;
  /** The chain of a time-stamping authority: a revocation after `time` must give a reason other than a compromise. */
  readonly authority?: boolean;
}

/** The result of the check: why it fails, or null, and the CRL used for each certificate. */
export interface RevocationResult {
  readonly error: string | null;
  readonly used: readonly Crl[];
}

/**
 * Checks the revocation status of a chain.
 *
 * @param chain The chain, from the certificate to its trust anchor.
 */
export function checkRevocation(chain: readonly X509Cert[], crls: readonly Crl[], check: RevocationCheck): RevocationResult {
  const used: Crl[] = [];
  const fail = (error: string): RevocationResult => ({ error, used });
  for (let index = 0; index + 1 < chain.length; index++) {
    const certificate = chain[index] as X509Cert;
    const issuer = chain[index + 1] as X509Cert;
    const name = JSON.stringify(certificate.getDN());
    const covering = crls.filter((crl) => crlCovers(crl, certificate, issuer) === null);
    if (covering.length === 0) {
      return fail(`No revocation data for the certificate ${name}: no CRL of its issuer.`);
    }
    const validTo = new Date(certificate.getValidTo());
    const { issuedAfter } = check;
    const usable = covering
      .filter((crl) => crl.thisUpdate <= check.now)
      .filter((crl) => crl.thisUpdate <= validTo || (crl.expiredCertsOnCrl !== null && crl.expiredCertsOnCrl <= validTo))
      .filter((crl) => (issuedAfter === null ? crl.nextUpdate !== null && check.now <= crl.nextUpdate : crl.thisUpdate >= issuedAfter))
      .sort((a, b) => b.thisUpdate.getTime() - a.thisUpdate.getTime());
    // The newest CRL tells the status. Of two issued at the same second, the
    // precision of their dates, the one that lists the certificate.
    const crl = usable.find((other) => other.thisUpdate.getTime() === usable[0]?.thisUpdate.getTime() && revocationOf(other, certificate) !== null) ?? usable[0];
    if (crl === undefined) {
      return fail(issuedAfter === null
        ? `No current revocation data for the certificate ${name}: the CRLs of its issuer are past their next update, or issued after it expired.`
        : `No revocation data for the certificate ${name} issued after the time-stamp (${issuedAfter.toISOString()}), while it was valid.`);
    }
    used.push(crl);
    const revocation = revocationOf(crl, certificate);
    if (revocation !== null && !tolerated(revocation, check)) {
      const since = `The certificate ${name} is revoked since ${revocation.date.toISOString()}`;
      if (check.time === null) {
        return fail(`${since}.`);
      }
      return fail(revocation.date <= check.time
        ? `${since}, before the time-stamp.`
        : `${since}, after the time-stamp but ${revocation.reason === null ? 'without a reason' : 'for a compromise of a key'}: the tokens of the time-stamping authority are no longer trusted (RFC 3161, 4).`);
    }
  }
  return { error: null, used };
}

/** Whether a revocation leaves the certificate usable. */
function tolerated(revocation: Revocation, check: RevocationCheck): boolean {
  if (check.time === null || revocation.date <= check.time) {
    return false;
  }
  return check.authority !== true || (revocation.reason !== null && !COMPROMISE_REASONS.has(revocation.reason));
}
