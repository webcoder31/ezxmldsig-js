/*
 * Copyright © 2026 - Thierry Thiers <webcoder31@gmail.com>
 *
 * This software is governed by the CeCILL-C license under French law and
 * abiding by the rules of distribution of free software. You can use, modify
 * and/or redistribute the software under the terms of the CeCILL-C license as
 * circulated by CEA, CNRS and INRIA at the following URL:
 * http://www.cecill.info
 */

import { DOMParser, type Document, type Node } from '@xmldom/xmldom';

/** The characters XML 1.0 cannot hold, raw or as character references.
With the flag "u", a surrogate pair is one character: the class of the
surrogates only matches a lone one. */
const INVALID_XML_CHARS = /[\x00-\x08\x0B\x0C\x0E-\x1F\uFFFE\uFFFF\uD800-\uDFFF]/u;

/** A declared encoding, in the XML declaration that starts a document. */
const DECLARED_ENCODING = /^<\?xml\s[^>]*?\bencoding\s*=\s*(["'])([^"']*)\1/;

const UTF8_BOM = '\uFEFF';

/** The deepest nesting of elements libxml accepts by default (it refuses
258 nested elements, under PHP 7.4 and 8.3 alike). */
const MAX_DEPTH = 257;

/**
 * Loads an XML document, as the PHP library does (`_loadXML()`).
 *
 * A document type declaration (DOCTYPE) declares entities, which a parser
 * expands where the document references them: nested internal entities make
 * a small document expand into gigabytes ("billion laughs"), and external
 * entities read files or URLs. An XML token never has one, so a document
 * holding `<!DOCTYPE` is refused before it is parsed, whatever it declares.
 * This check reads the document as it is given: it only holds for an encoding
 * in which `<!DOCTYPE` can only be written as these very characters, which is
 * why a document is also refused, before it is parsed, when it is not in
 * UTF-8, the encoding of the tokens: one that holds a NUL character (UTF-16,
 * UTF-32 read as bytes), that declares another encoding, or that does not
 * start with `<` (EBCDIC, among others). The parsed document is refused too
 * if it has a document type node, should the check above miss one.
 *
 * The document is given as a string, or as the bytes of its UTF-8 encoding;
 * bytes that are not valid UTF-8 refuse it. A UTF-8 byte order mark is
 * accepted. The parser (xmldom) never accesses the network nor reads files,
 * and any error or warning it reports refuses the document. It is more
 * lenient than libxml on a few points, which are checked here: a character
 * XML 1.0 cannot hold, written as is or as a character reference, refuses
 * the document. Whitespace is preserved: digests are computed over the
 * document as it was signed.
 *
 * @param xml The XML document.
 * @param what What the document is, for the error messages.
 * @returns The loaded document.
 * @throws {Error} If the document is refused.
 */
export function loadXML(xml: unknown, what: string): Document {
  let text: string;
  if (typeof xml === 'string') {
    text = xml;
  } else if (xml instanceof Uint8Array) {
    // The checks before parsing read the bytes, one character per byte: a
    // NUL byte, or "<!DOCTYPE" in ASCII, is found the same way.
    text = Buffer.from(xml.buffer, xml.byteOffset, xml.byteLength).toString('latin1');
  } else {
    throw new Error(`${what} is not a valid XML document!`);
  }
  if (text === '') {
    throw new Error(`${what} is not a valid XML document!`);
  }

  const start = text.replace(/^(\uFEFF|\xEF\xBB\xBF)/, '').replace(/^[ \t\r\n]+/, '');
  const declared = DECLARED_ENCODING.exec(start);
  if (text.includes('\0') || (declared !== null && declared[2]?.toUpperCase() !== 'UTF-8')) {
    throw new Error(`${what} must be encoded in UTF-8!`);
  }
  if (!start.startsWith('<')) {
    throw new Error(`${what} is not a valid XML document!`);
  }

  if (text.includes('<!DOCTYPE')) {
    throw new Error(`${what} must not have a document type declaration (DOCTYPE)!`);
  }

  if (typeof xml !== 'string') {
    try {
      text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(xml as Uint8Array);
    } catch {
      throw new Error(`${what} is not a valid XML document!`);
    }
  }
  if (text.startsWith(UTF8_BOM)) {
    text = text.slice(UTF8_BOM.length);
  }

  const doc = parse(text);
  if (doc === null) {
    throw new Error(`${what} is not a valid XML document!`);
  }

  for (let node = doc.firstChild; node !== null; node = node.nextSibling) {
    if (node.nodeType === node.DOCUMENT_TYPE_NODE) {
      throw new Error(`${what} must not have a document type declaration (DOCTYPE)!`);
    }
  }

  return doc;
}

/**
 * Parses an XML document with xmldom.
 *
 * @param text The XML text.
 * @returns The document, or null if the parser reported any error or
 *     warning, if the document holds a character XML 1.0 cannot hold, or if
 *     it nests elements deeper than libxml accepts.
 */
export function parse(text: string, maxDepth = MAX_DEPTH): Document | null {
  if (INVALID_XML_CHARS.test(text)) {
    return null;
  }

  let failed = false;
  let doc: Document;
  try {
    doc = new DOMParser({
      onError: () => {
        failed = true;
      },
    }).parseFromString(text, 'text/xml');
  } catch {
    return null;
  }
  if (failed || doc.documentElement === null || !isAcceptable(doc, maxDepth)) {
    return null;
  }

  return doc;
}

/**
 * Indicates whether a parsed document holds only characters XML 1.0 can
 * hold, and nests elements no deeper than libxml accepts (`MAX_DEPTH`, by
 * default). An
 * invalid character can only come from a character reference (`&#0;`),
 * which xmldom accepts: the text was checked before parsing. The walk is
 * iterative: a deeply nested document cannot exhaust the stack.
 */
function isAcceptable(doc: Document, maxDepth: number): boolean {
  const pending: Array<[Node, number]> = [[doc, 0]];
  for (let item = pending.pop(); item !== undefined; item = pending.pop()) {
    const [node, depth] = item;
    if (depth > maxDepth) {
      return false;
    }
    if (node.nodeValue !== null && INVALID_XML_CHARS.test(node.nodeValue)) {
      return false;
    }
    const attributes = (node as { attributes?: ArrayLike<Node> }).attributes;
    for (let i = 0; attributes !== undefined && i < attributes.length; i++) {
      const value = attributes[i]?.nodeValue;
      if (typeof value === 'string' && INVALID_XML_CHARS.test(value)) {
        return false;
      }
    }
    for (let child = node.firstChild; child !== null; child = child.nextSibling) {
      pending.push([child, child.nodeType === child.ELEMENT_NODE ? depth + 1 : depth]);
    }
  }
  return true;
}

/**
 * Parses an XML fragment (the plaintext of an encrypted token), as PHP does
 * (`DOMDocumentFragment::appendXML()`): any content XML allows in an
 * element, without document type declaration, nor namespace declared
 * around it. It is parsed inside a wrapping element, which cannot be closed
 * by the fragment without leaving the document malformed.
 *
 * @returns The nodes of the fragment, in a document of their own, or null
 *     if the fragment is not well formed, holds `<!DOCTYPE` or a character
 *     XML 1.0 cannot hold, or nests elements deeper than libxml accepts.
 */
export function parseFragment(text: string): Node[] | null {
  if (text === '' || text.includes('<!DOCTYPE')) {
    return null;
  }
  const doc = parse(`<fragment>${text}</fragment>`, MAX_DEPTH + 1);
  if (doc === null) {
    return null;
  }
  return Array.from((doc.documentElement as Node).childNodes);
}
