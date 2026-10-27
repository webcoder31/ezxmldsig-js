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
 * The algorithms of XML Signature the tokens and the seals are built with,
 * named by their URIs. Those of the tokens have the names and the values of
 * the constants of the PHP class `XMLDSigToken` (which takes them from
 * xmlseclibs), so that an option reads the same in both libraries; RSA-PSS
 * and ECDSA, of the seals, are those of RFC 6931.
 */

/** Namespace of XML Digital Signature. */
export const XMLDSIG_NS = 'http://www.w3.org/2000/09/xmldsig#';

/* Canonicalization. */

/** Inclusive canonicalization (default). */
export const C14N = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
/** Inclusive canonicalization, with comments. */
export const C14N_COMMENTS = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments';
/** Exclusive canonicalization. */
export const EXC_C14N = 'http://www.w3.org/2001/10/xml-exc-c14n#';
/** Exclusive canonicalization, with comments. */
export const EXC_C14N_COMMENTS = 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments';

/* Digest. */

/** SHA-1. */
export const SHA1 = 'http://www.w3.org/2000/09/xmldsig#sha1';
/** SHA-256 (default). */
export const SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256';
/** SHA-384. */
export const SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#sha384';
/** SHA-512. */
export const SHA512 = 'http://www.w3.org/2001/04/xmlenc#sha512';
/** RIPEMD-160. */
export const RIPEMD160 = 'http://www.w3.org/2001/04/xmlenc#ripemd160';

/* Signature. */

/** RSA-SHA1. */
export const RSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
/** RSA-SHA256 (default). */
export const RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
/** RSA-SHA384. */
export const RSA_SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384';
/** RSA-SHA512. */
export const RSA_SHA512 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512';

/** RSASSA-PSS, MGF1 with the same digest, salt as long as the digest (RFC 6931, 2.3.10). */
export const RSA_PSS_SHA256 = 'http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1';
/** RSASSA-PSS with SHA-384. */
export const RSA_PSS_SHA384 = 'http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1';
/** RSASSA-PSS with SHA-512. */
export const RSA_PSS_SHA512 = 'http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1';

/** ECDSA, the value written as r || s (RFC 6931, 2.3.6; RFC 4050). */
export const ECDSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256';
/** ECDSA with SHA-384. */
export const ECDSA_SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384';
/** ECDSA with SHA-512. */
export const ECDSA_SHA512 = 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512';
