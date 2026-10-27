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
 * Seals of files: detached XAdES baseline signatures (ETSI EN 319 132-1) in
 * an ASiC-E container (ETSI EN 319 162-1), at levels B, T and LT. The
 * certificates and the algorithms come from `@webcoder31/ezxmldsig/core`.
 *
 * Experimental in 2.x: its API may change in a minor version.
 *
 * @module seal
 */

export { createSeal, type SealFile, type SealOptions } from './seal.js';
export { timestampRequest, addSignatureTimestamp, type TimestampOptions } from './extend.js';
export {
  validationDataRequests, addValidationData, type ValidationDataOptions, type AddValidationDataOptions, type CrlRequest, type OcspRequest,
} from './validation.js';
export { verifySeal, SealVerification, type VerifyOptions, type SealLevel, type SealedFile } from './verify.js';
export type { ZipLimits } from './zip.js';
