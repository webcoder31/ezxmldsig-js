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
 * The algorithms of the seals, and their parameters for node:crypto. The
 * identifiers of RSA-PSS and ECDSA are those of RFC 6931; the digests are
 * those of the tokens (src/algorithms.ts), SHA-1 and RIPEMD-160 excepted.
 */

import { constants } from 'node:crypto';

import { RSA_SHA256, RSA_SHA384, RSA_SHA512, SHA256, SHA384, SHA512 } from '../algorithms.js';

export { EXC_C14N, RSA_SHA256, RSA_SHA384, RSA_SHA512, SHA256, SHA384, SHA512 } from '../algorithms.js';

/** RSASSA-PSS, MGF1 with the same digest, salt as long as the digest (RFC 6931, 2.3.10). */
export const RSA_PSS_SHA256 = 'http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1';
export const RSA_PSS_SHA384 = 'http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1';
export const RSA_PSS_SHA512 = 'http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1';

/** ECDSA, the value written as r || s (RFC 6931, 2.3.6; RFC 4050). */
export const ECDSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256';
export const ECDSA_SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384';
export const ECDSA_SHA512 = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512';

/** The node:crypto names of the digest algorithms of the seals. */
export const DIGESTS: Readonly<Record<string, string>> = {
  [SHA256]: 'sha256',
  [SHA384]: 'sha384',
  [SHA512]: 'sha512',
};

/** A signature algorithm: the type of key it needs, and how node:crypto computes it. */
export interface SignatureScheme {
  readonly keyType: 'rsa' | 'ec';
  readonly hash: string;
  /** The options of sign() and verify() besides the key. */
  readonly options: { padding?: number; saltLength?: number; dsaEncoding?: 'ieee-p1363' };
}

const PSS = { padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: constants.RSA_PSS_SALTLEN_DIGEST };
const ECDSA = { dsaEncoding: 'ieee-p1363' } as const;

export const SIGNATURE_SCHEMES: Readonly<Record<string, SignatureScheme>> = {
  [RSA_PSS_SHA256]: { keyType: 'rsa', hash: 'sha256', options: PSS },
  [RSA_PSS_SHA384]: { keyType: 'rsa', hash: 'sha384', options: PSS },
  [RSA_PSS_SHA512]: { keyType: 'rsa', hash: 'sha512', options: PSS },
  [RSA_SHA256]: { keyType: 'rsa', hash: 'sha256', options: { padding: constants.RSA_PKCS1_PADDING } },
  [RSA_SHA384]: { keyType: 'rsa', hash: 'sha384', options: { padding: constants.RSA_PKCS1_PADDING } },
  [RSA_SHA512]: { keyType: 'rsa', hash: 'sha512', options: { padding: constants.RSA_PKCS1_PADDING } },
  [ECDSA_SHA256]: { keyType: 'ec', hash: 'sha256', options: ECDSA },
  [ECDSA_SHA384]: { keyType: 'ec', hash: 'sha384', options: ECDSA },
  [ECDSA_SHA512]: { keyType: 'ec', hash: 'sha512', options: ECDSA },
};

/** The curves of the EC keys accepted (TS 119 312, Table 2), and the signature algorithm each one takes by default. */
export const CURVES: Readonly<Record<string, string>> = {
  'prime256v1': ECDSA_SHA256,
  'secp384r1': ECDSA_SHA384,
  'secp521r1': ECDSA_SHA512,
};

/** The smallest RSA key accepted, in bits. TS 119 312 (Table 6) lists no size below 1 900 bits, and keys below 3 000 bits as legacy. */
export const MIN_RSA_BITS = 2048;
