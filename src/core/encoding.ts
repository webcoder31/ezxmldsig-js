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
 * The escaping of XML text and attribute values, as libxml writes them: the
 * tokens and the seals write their XML with it, so that it is canonicalized
 * the same way by every reader.
 */

/** Escapes text content as libxml writes it. */
export function escapeText(text: string): string {
  return text.replace(/[&<>\r]/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '\r': '&#xD;' })[char] as string);
}

/** Escapes an attribute value (in double quotes) as libxml writes it. */
export function escapeAttribute(text: string): string {
  return text.replace(/[&<>"\r\n\t]/g, (char) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', '\r': '&#13;', '\n': '&#10;', '\t': '&#9;',
  })[char] as string);
}
