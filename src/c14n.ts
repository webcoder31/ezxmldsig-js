/*
 * Copyright © 2026 - Thierry Thiers <webcoder31@gmail.com>
 *
 * This software is governed by the CeCILL-C license under French law and
 * abiding by the rules of distribution of free software. You can use, modify
 * and/or redistribute the software under the terms of the CeCILL-C license as
 * circulated by CEA, CNRS and INRIA at the following URL:
 * http://www.cecill.info
 */

import type { Element } from '@xmldom/xmldom';
import { SignedXml } from 'xml-crypto';
import { findAncestorNsForElement } from 'xml-crypto/lib/utils.js';

/**
 * Canonicalizes a node with xml-crypto, in the context of its document.
 * Digests and signatures are computed over canonical XML: a
 * canonicalization that fails or yields an empty string throws, so that a
 * forged reference cannot be validated by the digest of an empty string.
 * This check must not be removed.
 */
export function canonicalize(node: Element, algorithm: string, prefixList: string[] | null, what: string): string {
  let data: unknown;
  try {
    data = new SignedXml().getCanonXml([algorithm], node as never, {
      ancestorNamespaces: findAncestorNsForElement(node as never),
      ...(prefixList === null ? {} : { inclusiveNamespacesPrefixList: prefixList }),
    });
  } catch (error) {
    throw new Error(`Canonicalization of ${what} failed! Reason: ${(error as Error).message}`);
  }
  if (typeof data !== 'string' || data === '') {
    throw new Error(`Canonicalization of ${what} failed or is empty!`);
  }
  return data;
}
