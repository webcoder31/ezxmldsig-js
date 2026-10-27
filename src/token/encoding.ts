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
 * Encodings the tokens are written and read with, as the PHP library writes
 * and reads them: what a token holds must be read the same way by both.
 */

const BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

/**
 * Decodes base64 as PHP does without strict mode (`base64_decode()`):
 * every character out of the alphabet, padding included, is skipped, and a
 * last group of a single character gives nothing.
 */
export function phpBase64Decode(text: string): Buffer {
  const sextets: number[] = [];
  for (const char of text) {
    const value = BASE64_ALPHABET.indexOf(char);
    if (value >= 0) {
      sextets.push(value);
    }
  }
  const bytes: number[] = [];
  for (let i = 0; i + 1 < sextets.length; i += 4) {
    const [a, b, c, d] = [sextets[i] as number, sextets[i + 1] as number, sextets[i + 2], sextets[i + 3]];
    bytes.push((a << 2) | (b >> 4));
    if (c !== undefined) {
      bytes.push(((b & 0x0f) << 4) | (c >> 2));
      if (d !== undefined) {
        bytes.push(((c & 0x03) << 6) | d);
      }
    }
  }
  return Buffer.from(bytes);
}

const NAME_START_CHAR = ':A-Z_a-z\\u00C0-\\u00D6\\u00D8-\\u00F6\\u00F8-\\u02FF\\u0370-\\u037D\\u037F-\\u1FFF\\u200C-\\u200D\\u2070-\\u218F\\u2C00-\\u2FEF\\u3001-\\uD7FF\\uF900-\\uFDCF\\uFDF0-\\uFFFD\\u{10000}-\\u{EFFFF}';
const NAME = new RegExp(`^[${NAME_START_CHAR}][${NAME_START_CHAR}\\-.0-9\\u00B7\\u0300-\\u036F\\u203F-\\u2040]*$`, 'u');

/** Indicates whether a string is an XML name (XML 1.0, production Name). */
export function isXmlName(name: string): boolean {
  return NAME.test(name);
}

/** The format of the token dates: YYYY-MM-DDThh:mm:ssZ, in UTC. */
const TOKEN_DATE = /^(\d{1,4})-(\d{1,2})-(\d{1,2})T(\d{1,2}):(\d{2}):(\d{2})Z$/;

/**
 * Reads a token date as PHP does (`DateTime::createFromFormat()` with the
 * format `Y-m-d\TH:i:s\Z`, in UTC): the year has 1 to 4 digits, the month,
 * the day and the hour 1 or 2, the minutes and the seconds 2, and a value
 * out of its range carries over (the 30th of February is the 2nd of March).
 *
 * @returns The date, in seconds since the UNIX epoch, or null if PHP does not
 *     read it.
 */
export function parseTokenDate(text: string): number | null {
  const match = TOKEN_DATE.exec(text);
  if (match === null) {
    return null;
  }
  const [year, month, day, hours, minutes, seconds] = match.slice(1).map(Number) as [number, number, number, number, number, number];
  const date = new Date(0);
  date.setUTCFullYear(year, month - 1, day);
  date.setUTCHours(hours, minutes, seconds, 0);
  return date.getTime() / 1000;
}

/** Writes a date, in seconds since the UNIX epoch, in the format of the
token dates, as PHP does (`Y-m-d\TH:i:s\Z`). */
export function formatTokenDate(time: number): string {
  const date = new Date(time * 1000);
  const pad = (value: number, length = 2) => String(value).padStart(length, '0');
  return `${pad(date.getUTCFullYear(), 4)}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())}`
    + `T${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}:${pad(date.getUTCSeconds())}Z`;
}
