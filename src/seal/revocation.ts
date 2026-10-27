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
 * The revocation status of the certificates of a chain, from CRLs and OCSP
 * responses (see design/seal.md, "Verification rules").
 *
 * Every certificate of the chain but its trust anchor needs a CRL of its
 * issuer, or an OCSP response of its issuer or of a responder it
 * delegated, that tells its status. Two questions are told apart:
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
 * A CRL or a response issued after the certificate expired proves nothing
 * of it, since a CA may drop the expired certificates from its CRLs and a
 * responder forget them, unless they say they keep them (ExpiredCertsOnCRL,
 * archive cutoff).
 */

import type { X509Cert } from '../core/x509.js';
import type { Revocation } from './crl.js';

/**
 * What tells the status of certificates: a CRL, or the answer of an OCSP
 * response for one certificate.
 */
export interface RevocationSource {
  readonly kind: 'crl' | 'ocsp';
  /** The DER encoding of the CRL or of the whole OCSP response. */
  readonly der: Buffer;
  readonly thisUpdate: Date;
  readonly nextUpdate: Date | null;
  /** The date from which it keeps the status of the expired certificates (ExpiredCertsOnCRL, archive cutoff), or null. */
  readonly keepsExpiredFrom: Date | null;
  /** Null if it tells the status of the certificate, which the issuer issued, or why it does not. */
  covers(certificate: X509Cert, issuer: X509Cert): string | null;
  /** The revocation of the certificate, or null if it is not revoked. */
  revocationOf(certificate: X509Cert): Revocation | null;
}

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

/** The result of the check: why it fails, or null, and the source used for each certificate. */
export interface RevocationResult {
  readonly error: string | null;
  readonly used: readonly RevocationSource[];
}

/**
 * Checks the revocation status of a chain.
 *
 * @param chain The chain, from the certificate to its trust anchor.
 */
export function checkRevocation(chain: readonly X509Cert[], sources: readonly RevocationSource[], check: RevocationCheck): RevocationResult {
  const used: RevocationSource[] = [];
  const fail = (error: string): RevocationResult => ({ error, used });
  for (let index = 0; index + 1 < chain.length; index++) {
    const certificate = chain[index] as X509Cert;
    const issuer = chain[index + 1] as X509Cert;
    const name = JSON.stringify(certificate.getDN());
    const covering = sources.filter((source) => source.covers(certificate, issuer) === null);
    if (covering.length === 0) {
      return fail(`No revocation data for the certificate ${name}: no CRL of its issuer, nor OCSP response.`);
    }
    const validTo = new Date(certificate.getValidTo());
    const { issuedAfter } = check;
    const usable = covering
      .filter((crl) => crl.thisUpdate <= check.now)
      .filter((crl) => crl.thisUpdate <= validTo || (crl.keepsExpiredFrom !== null && crl.keepsExpiredFrom <= validTo))
      .filter((crl) => (issuedAfter === null ? crl.nextUpdate !== null && check.now <= crl.nextUpdate : crl.thisUpdate >= issuedAfter))
      .sort((a, b) => b.thisUpdate.getTime() - a.thisUpdate.getTime());
    // The newest source tells the status. Of two issued at the same second,
    // the precision of their dates, the one that tells a revocation.
    const crl = usable.find((other) => other.thisUpdate.getTime() === usable[0]?.thisUpdate.getTime() && other.revocationOf(certificate) !== null) ?? usable[0];
    if (crl === undefined) {
      return fail(issuedAfter === null
        ? `No current revocation data for the certificate ${name}: the CRLs and OCSP responses are past their next update, have none, or were issued after it expired.`
        : `No revocation data for the certificate ${name} issued after the time-stamp (${issuedAfter.toISOString()}), while it was valid.`);
    }
    used.push(crl);
    const revocation = crl.revocationOf(certificate);
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
