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
 * The core of ezxmldsig, shared by the tokens and the seals: certificates
 * and their chain of trust, and the identifiers of the algorithms of XML
 * Signature.
 *
 * @module core
 */

export * from './algorithms.js';
export { X509Cert, type NameFields } from './x509.js';
export type { PemSource } from './material.js';
