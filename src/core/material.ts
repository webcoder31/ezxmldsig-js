/*
 * Copyright © 2026 - Thierry Thiers <webcoder31@gmail.com>
 *
 * This software is governed by the CeCILL-C license under French law and
 * abiding by the rules of distribution of free software. You can use, modify
 * and/or redistribute the software under the terms of the CeCILL-C license as
 * circulated by CEA, CNRS and INRIA at the following URL:
 * http://www.cecill.info
 */

import { readFileSync, statSync } from 'node:fs';

/**
 * A key or a certificate in PEM format: the path of a PEM file, or the PEM
 * content itself, as a string or as bytes. A string holding `-----BEGIN ` is
 * the content; any other string is a path.
 */
export type PemSource = string | Uint8Array;

/**
 * Reads a key or a certificate given by its path or by its content.
 *
 * @param source The path of a PEM file, or the PEM content.
 * @returns The PEM content, or null if the source is neither a string nor
 *     bytes, or names a file that cannot be read.
 */
export function readPem(source: unknown): string | null {
  if (source instanceof Uint8Array) {
    return Buffer.from(source.buffer, source.byteOffset, source.byteLength).toString('utf8');
  }
  if (typeof source !== 'string' || source === '') {
    return null;
  }
  if (source.includes('-----BEGIN ')) {
    return source;
  }
  try {
    if (!statSync(source).isFile()) {
      return null;
    }
    return readFileSync(source, 'utf8');
  } catch {
    return null;
  }
}

/**
 * Describes a source for an error message: its path, or what it is when it
 * is not a path. The content of a key is never written in a message.
 */
export function describeSource(source: unknown): string {
  if (typeof source === 'string') {
    return source.includes('-----BEGIN ') ? 'PEM content' : source;
  }
  if (source instanceof Uint8Array) {
    return 'PEM content';
  }
  return source === null ? 'null' : Array.isArray(source) ? 'array' : typeof source;
}

/**
 * The certificates of a PEM content, as xmlseclibs extracts them to write
 * them in the token (`staticGet509XCerts()`): the lines between each
 * `-----BEGIN CERTIFICATE` line and the next `-----END CERTIFICATE` line,
 * trimmed and joined.
 */
export function extractCertificates(pem: string): string[] {
  const certificates: string[] = [];
  let data: string | null = null;
  for (const line of pem.split('\n')) {
    if (data === null) {
      if (line.startsWith('-----BEGIN CERTIFICATE')) {
        data = '';
      }
    } else if (line.startsWith('-----END CERTIFICATE')) {
      certificates.push(data);
      data = null;
    } else {
      data += line.trim();
    }
  }
  return certificates;
}
