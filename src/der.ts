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
 * A minimal reader of DER (the binary encoding of X.509 certificates), for
 * what node:crypto does not expose: the fields of names, the key usage, the
 * basic constraints and the criticality of extensions. The certificates it
 * reads have been parsed by OpenSSL first (node:crypto X509Certificate):
 * every malformation still throws here, and the certificate is then refused.
 */

/** Universal tags. */
export const TAG = {
  BOOLEAN: 0x01,
  INTEGER: 0x02,
  BIT_STRING: 0x03,
  OCTET_STRING: 0x04,
  OID: 0x06,
  UTF8_STRING: 0x0c,
  NUMERIC_STRING: 0x12,
  PRINTABLE_STRING: 0x13,
  T61_STRING: 0x14,
  IA5_STRING: 0x16,
  UTC_TIME: 0x17,
  GENERALIZED_TIME: 0x18,
  VISIBLE_STRING: 0x1a,
  GENERAL_STRING: 0x1b,
  UNIVERSAL_STRING: 0x1c,
  BMP_STRING: 0x1e,
  SEQUENCE: 0x30,
  SET: 0x31,
} as const;

/** An element: its identifier octet and its content. */
export interface Element {
  /** The identifier octet (class, constructed bit and tag number). */
  readonly tag: number;
  /** The content octets. */
  readonly content: Buffer;
}

/**
 * Reads the elements that follow each other in a buffer.
 *
 * @throws {Error} If the buffer is not a sequence of DER elements.
 */
export function readElements(buffer: Buffer): Element[] {
  const elements: Element[] = [];
  let offset = 0;
  while (offset < buffer.length) {
    const tag = buffer[offset++] as number;
    if ((tag & 0x1f) === 0x1f) {
      throw new Error('DER: multi-byte tags are not supported.');
    }
    if (offset >= buffer.length) {
      throw new Error('DER: truncated length.');
    }
    let length = buffer[offset++] as number;
    if (length & 0x80) {
      const count = length & 0x7f;
      if (count === 0 || count > 4 || offset + count > buffer.length) {
        throw new Error('DER: invalid length.');
      }
      length = 0;
      for (let i = 0; i < count; i++) {
        length = length * 256 + (buffer[offset++] as number);
      }
    }
    if (offset + length > buffer.length) {
      throw new Error('DER: truncated content.');
    }
    elements.push({ tag, content: buffer.subarray(offset, offset + length) });
    offset += length;
  }
  return elements;
}

/**
 * Reads the single element a buffer holds.
 *
 * @throws {Error} If the buffer does not hold exactly one element.
 */
export function readElement(buffer: Buffer): Element {
  const elements = readElements(buffer);
  if (elements.length !== 1) {
    throw new Error('DER: one element expected.');
  }
  return elements[0] as Element;
}

/**
 * Reads the elements of a constructed element of the given tag.
 *
 * @throws {Error} If the element has another tag.
 */
export function childrenOf(element: Element, tag: number): Element[] {
  if (element.tag !== tag) {
    throw new Error(`DER: tag ${tag.toString(16)} expected, ${element.tag.toString(16)} found.`);
  }
  return readElements(element.content);
}

/** Decodes an object identifier into its dotted form. */
export function decodeOid(element: Element): string {
  if (element.tag !== TAG.OID || element.content.length === 0) {
    throw new Error('DER: object identifier expected.');
  }
  const arcs: number[] = [];
  let value = 0;
  for (const byte of element.content) {
    value = value * 128 + (byte & 0x7f);
    if (!(byte & 0x80)) {
      arcs.push(value);
      value = 0;
    }
  }
  if (element.content[element.content.length - 1]! & 0x80) {
    throw new Error('DER: truncated object identifier.');
  }
  const first = arcs.shift() as number;
  const head = first < 40 ? [0, first] : first < 80 ? [1, first - 40] : [2, first - 80];
  return [...head, ...arcs].join('.');
}

/** Decodes a boolean. */
export function decodeBoolean(element: Element): boolean {
  if (element.tag !== TAG.BOOLEAN || element.content.length !== 1) {
    throw new Error('DER: boolean expected.');
  }
  return element.content[0] !== 0;
}

/** Decodes a non-negative integer that fits in a JavaScript number. */
export function decodeSmallInteger(element: Element): number {
  if (element.tag !== TAG.INTEGER || element.content.length === 0 || element.content.length > 6) {
    throw new Error('DER: small integer expected.');
  }
  if (element.content[0]! & 0x80) {
    throw new Error('DER: negative integer.');
  }
  return element.content.readUIntBE(0, element.content.length);
}

/**
 * Decodes a bit string into its bits, the first one (bit 0) first.
 */
export function decodeBits(element: Element): boolean[] {
  if (element.tag !== TAG.BIT_STRING || element.content.length === 0) {
    throw new Error('DER: bit string expected.');
  }
  const unused = element.content[0] as number;
  if (unused > 7 || (element.content.length === 1 && unused !== 0)) {
    throw new Error('DER: invalid bit string.');
  }
  const bits: boolean[] = [];
  const count = (element.content.length - 1) * 8 - unused;
  for (let i = 0; i < count; i++) {
    bits.push(((element.content[1 + (i >> 3)] as number) >> (7 - (i & 7)) & 1) === 1);
  }
  return bits;
}
