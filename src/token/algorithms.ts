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
 * The algorithms of XML Encryption a token can be encrypted with, named by
 * their URIs, with the names and the values of the constants of the PHP
 * class `XMLDSigToken` (which takes them from xmlseclibs). Those of XML
 * Signature are in the core (src/core/algorithms.ts), and re-exported here,
 * so that the tokens name every algorithm from one module.
 */

export * from '../core/algorithms.js';

/** Namespace of XML Encryption. */
export const XMLENC_NS = 'http://www.w3.org/2001/04/xmlenc#';

/* Symmetric encryption of the token (session key). */

/** AES-128-GCM. */
export const AES128_GCM = 'http://www.w3.org/2009/xmlenc11#aes128-gcm';
/** AES-192-GCM. */
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
