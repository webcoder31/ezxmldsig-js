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
 * Signed and encrypted XML tokens (XML Digital Signature, XML Encryption),
 * interoperable with the PHP library ezxmldsig. The certificates and the
 * algorithms of signature come from `@webcoder31/ezxmldsig/core`.
 *
 * @module token
 */

export {
  AES128_CBC, AES128_GCM, AES192_CBC, AES192_GCM, AES256_CBC, AES256_GCM, RSA_OAEP_MGF1P, TRIPLEDES_CBC, XMLENC_NS,
} from './algorithms.js';
export { XMLDSigToken, type TokenData, type TokenValue, type ReadTokenData } from './token.js';
export type { TokenOptions } from './options.js';
