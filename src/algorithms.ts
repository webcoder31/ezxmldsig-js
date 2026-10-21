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
 * The algorithms a token can be built with, named by the URIs of the XMLDSIG
 * and XML Encryption specifications. They have the names and the values of
 * the constants of the PHP class `XMLDSigToken` (which takes them from
 * xmlseclibs), so that an option reads the same in both libraries.
 */

/** Namespace of XML Digital Signature. */
export const XMLDSIG_NS = 'http://www.w3.org/2000/09/xmldsig#';

/** Namespace of XML Encryption. */
export const XMLENC_NS = 'http://www.w3.org/2001/04/xmlenc#';

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

export const SHA1 = 'http://www.w3.org/2000/09/xmldsig#sha1';
/** SHA-256 (default). */
export const SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256';
export const SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#sha384';
export const SHA512 = 'http://www.w3.org/2001/04/xmlenc#sha512';
export const RIPEMD160 = 'http://www.w3.org/2001/04/xmlenc#ripemd160';

/* Signature. */

export const RSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
/** RSA-SHA256 (default). */
export const RSA_SHA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
export const RSA_SHA384 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha384';
export const RSA_SHA512 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512';

/* Symmetric encryption of the token (session key). */

export const AES128_GCM = 'http://www.w3.org/2009/xmlenc11#aes128-gcm';
export const AES192_GCM = 'http://www.w3.org/2009/xmlenc11#aes192-gcm';
/** AES-256-GCM (default). */
export const AES256_GCM = 'http://www.w3.org/2009/xmlenc11#aes256-gcm';
/** Without integrity: an analysis only accepts it when it declares it. */
export const TRIPLEDES_CBC = 'http://www.w3.org/2001/04/xmlenc#tripledes-cbc';
/** Without integrity: an analysis only accepts it when it declares it. */
export const AES128_CBC = 'http://www.w3.org/2001/04/xmlenc#aes128-cbc';
/** Without integrity: an analysis only accepts it when it declares it. */
export const AES192_CBC = 'http://www.w3.org/2001/04/xmlenc#aes192-cbc';
/** Without integrity: an analysis only accepts it when it declares it. */
export const AES256_CBC = 'http://www.w3.org/2001/04/xmlenc#aes256-cbc';

/* Key transport (encryption of the session key). */

/** RSA-OAEP with MGF1-SHA1 (default, and only accepted one). */
export const RSA_OAEP_MGF1P = 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p';
