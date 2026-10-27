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
 * The ZIP archives of ASiC containers (ETSI EN 319 162-1, 4.2): a writer of
 * what a container needs, and a strict reader.
 *
 * A seal covers the files of its container: the reader refuses whatever lets
 * two tools see different files in the same archive, which general ZIP
 * readers accept. A local header that differs from its central directory
 * entry, bytes between entries, two names that look the same, a path that
 * leaves the container: each is refused, not resolved one way or the other.
 *
 * Neither ZIP64 nor encryption is supported, nor any method but stored (0)
 * and deflate (8).
 */

import { crc32, deflateRawSync, inflateRawSync } from 'node:zlib';

/** An entry of an archive, in the order of the archive. */
export interface ZipEntry {
  /** The path of the entry, `/` separated. */
  readonly name: string;
  /** The uncompressed content. */
  readonly content: Buffer;
  /** The compression method: 0 stored, 8 deflate. */
  readonly method: 0 | 8;
  /** The extra field of the local header, empty if none. */
  readonly extra: Buffer;
}

/** An entry to write. */
export interface ZipInput {
  readonly name: string;
  readonly content: Buffer;
  /** Store the content uncompressed (the `mimetype` entry of a container). */
  readonly stored?: boolean;
}

/** The limits of the reader. */
export interface ZipLimits {
  /** The largest number of entries. */
  readonly maxEntries: number;
  /** The largest uncompressed size of the entries together, in bytes. */
  readonly maxTotalSize: number;
}

export const DEFAULT_ZIP_LIMITS: ZipLimits = {
  maxEntries: 1000,
  maxTotalSize: 512 * 1024 * 1024,
};

const LOCAL_SIGNATURE = 0x04034b50;
const CENTRAL_SIGNATURE = 0x02014b50;
const END_SIGNATURE = 0x06054b50;
const DESCRIPTOR_SIGNATURE = 0x08074b50;

const LOCAL_SIZE = 30;
const CENTRAL_SIZE = 46;
const END_SIZE = 22;

/** General purpose flags: data descriptor and UTF-8 names. */
const FLAG_DESCRIPTOR = 0x0008;
const FLAG_UTF8 = 0x0800;
/** Flags a reader may meet: bits 1 and 2 only tell how deflate was tuned. */
const ALLOWED_FLAGS = 0x0006 | FLAG_DESCRIPTOR | FLAG_UTF8;

/** Extra fields that change the meaning of the header: ZIP64, and a second name (Info-ZIP Unicode path). */
const REFUSED_EXTRA_IDS = new Set([0x0001, 0x7075]);

const MAX_16 = 0xffff;
const MAX_32 = 0xffffffff;

/**
 * Writes an archive: names in UTF-8, sizes and CRC in the local headers (no
 * data descriptor), deflate unless `stored`, no comment.
 *
 * @param modified The date of every entry, in UTC. A fixed date makes the
 *   archive depend on its entries only.
 * @throws {Error} If a name is not acceptable to the reader, if two names
 *   collide, or if the archive would need ZIP64.
 */
export function writeZip(inputs: readonly ZipInput[], modified: Date = new Date()): Buffer {
  if (inputs.length > MAX_16) {
    throw new Error('ZIP: too many entries for an archive without ZIP64.');
  }
  const { time, date } = dosDateTime(modified);
  const names = new Set<string>();
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;
  for (const input of inputs) {
    checkName(input.name);
    const key = input.name.normalize('NFC');
    if (names.has(key)) {
      throw new Error(`ZIP: duplicate entry ${JSON.stringify(input.name)}.`);
    }
    names.add(key);
    const name = Buffer.from(input.name, 'utf8');
    const method = input.stored ? 0 : 8;
    const data = method === 0 ? input.content : deflateRawSync(input.content);
    const crc = crc32(input.content);
    if (input.content.length > MAX_32 - 1 || data.length > MAX_32 - 1 || offset > MAX_32 - 1) {
      throw new Error('ZIP: entry too large for an archive without ZIP64.');
    }
    const version = method === 0 ? 10 : 20;

    const local = Buffer.alloc(LOCAL_SIZE);
    local.writeUInt32LE(LOCAL_SIGNATURE, 0);
    local.writeUInt16LE(version, 4);
    local.writeUInt16LE(FLAG_UTF8, 6);
    local.writeUInt16LE(method, 8);
    local.writeUInt16LE(time, 10);
    local.writeUInt16LE(date, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(input.content.length, 22);
    local.writeUInt16LE(name.length, 26);
    local.writeUInt16LE(0, 28);

    const central = Buffer.alloc(CENTRAL_SIZE);
    central.writeUInt32LE(CENTRAL_SIGNATURE, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(version, 6);
    central.writeUInt16LE(FLAG_UTF8, 8);
    central.writeUInt16LE(method, 10);
    central.writeUInt16LE(time, 12);
    central.writeUInt16LE(date, 14);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(data.length, 20);
    central.writeUInt32LE(input.content.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt32LE(offset, 42);

    locals.push(local, name, data);
    centrals.push(central, name);
    offset += LOCAL_SIZE + name.length + data.length;
  }
  const directory = Buffer.concat(centrals);
  if (offset + directory.length > MAX_32 - 1) {
    throw new Error('ZIP: archive too large without ZIP64.');
  }
  const end = Buffer.alloc(END_SIZE);
  end.writeUInt32LE(END_SIGNATURE, 0);
  end.writeUInt16LE(inputs.length, 8);
  end.writeUInt16LE(inputs.length, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, directory, end]);
}

/**
 * Reads an archive, entries in their order. Directory entries (a name
 * ending with `/`, empty) are checked and left out.
 *
 * @throws {Error} If the archive is malformed, ambiguous, or beyond `limits`.
 */
export function readZip(archive: Buffer, limits: ZipLimits = DEFAULT_ZIP_LIMITS): ZipEntry[] {
  const end = findEnd(archive);
  const count = end.readUInt16LE(10);
  const directorySize = end.readUInt32LE(12);
  const directoryOffset = end.readUInt32LE(16);
  if (end.readUInt16LE(4) !== 0 || end.readUInt16LE(6) !== 0 || end.readUInt16LE(8) !== count) {
    throw new Error('ZIP: archives on several disks are not supported.');
  }
  if (count === MAX_16 || directorySize === MAX_32 || directoryOffset === MAX_32) {
    throw new Error('ZIP: ZIP64 is not supported.');
  }
  if (count > limits.maxEntries) {
    throw new Error(`ZIP: more than ${limits.maxEntries} entries.`);
  }
  const endOffset = archive.length - END_SIZE - end.readUInt16LE(20);
  if (directoryOffset + directorySize !== endOffset) {
    throw new Error('ZIP: the central directory does not end where the archive ends.');
  }
  const directory = archive.subarray(directoryOffset, endOffset);

  const entries: ZipEntry[] = [];
  const names = new Set<string>();
  let position = 0;
  let expectedOffset = 0;
  let totalSize = 0;
  for (let index = 0; index < count; index++) {
    if (position + CENTRAL_SIZE > directory.length || directory.readUInt32LE(position) !== CENTRAL_SIGNATURE) {
      throw new Error('ZIP: malformed central directory.');
    }
    const flags = directory.readUInt16LE(position + 8);
    const method = directory.readUInt16LE(position + 10);
    const crc = directory.readUInt32LE(position + 16);
    const compressedSize = directory.readUInt32LE(position + 20);
    const size = directory.readUInt32LE(position + 24);
    const nameLength = directory.readUInt16LE(position + 28);
    const extraLength = directory.readUInt16LE(position + 30);
    const commentLength = directory.readUInt16LE(position + 32);
    const disk = directory.readUInt16LE(position + 34);
    const localOffset = directory.readUInt32LE(position + 42);
    const fieldsEnd = position + CENTRAL_SIZE + nameLength + extraLength + commentLength;
    if (fieldsEnd > directory.length) {
      throw new Error('ZIP: malformed central directory.');
    }
    const nameBytes = directory.subarray(position + CENTRAL_SIZE, position + CENTRAL_SIZE + nameLength);
    checkExtra(directory.subarray(position + CENTRAL_SIZE + nameLength, position + CENTRAL_SIZE + nameLength + extraLength));
    decodeText(directory.subarray(position + CENTRAL_SIZE + nameLength + extraLength, fieldsEnd), flags, 'comment');
    position = fieldsEnd;

    if (flags & ~ALLOWED_FLAGS) {
      throw new Error('ZIP: encrypted or unsupported entry.');
    }
    if (method !== 0 && method !== 8) {
      throw new Error(`ZIP: unsupported compression method ${method}.`);
    }
    if (disk !== 0) {
      throw new Error('ZIP: archives on several disks are not supported.');
    }
    if (compressedSize === MAX_32 || size === MAX_32 || localOffset === MAX_32) {
      throw new Error('ZIP: ZIP64 is not supported.');
    }
    const name = decodeText(nameBytes, flags, 'name');
    const isDirectory = name.endsWith('/');
    checkName(isDirectory ? name.slice(0, -1) : name);
    const key = name.normalize('NFC');
    if (names.has(key)) {
      throw new Error(`ZIP: duplicate entry ${JSON.stringify(name)}.`);
    }
    names.add(key);
    if (method === 0 && compressedSize !== size) {
      throw new Error(`ZIP: stored entry ${JSON.stringify(name)} with two sizes.`);
    }
    if (isDirectory && size !== 0) {
      throw new Error(`ZIP: directory entry ${JSON.stringify(name)} with content.`);
    }
    totalSize += size;
    if (totalSize > limits.maxTotalSize) {
      throw new Error(`ZIP: more than ${limits.maxTotalSize} bytes once uncompressed.`);
    }

    // The local header, where the previous entry ended.
    if (localOffset !== expectedOffset) {
      throw new Error(`ZIP: entry ${JSON.stringify(name)} is not where the previous entry ends.`);
    }
    if (localOffset + LOCAL_SIZE > directoryOffset || archive.readUInt32LE(localOffset) !== LOCAL_SIGNATURE) {
      throw new Error(`ZIP: missing local header for ${JSON.stringify(name)}.`);
    }
    const local = archive.subarray(localOffset, localOffset + LOCAL_SIZE);
    const localNameLength = local.readUInt16LE(26);
    const localExtraLength = local.readUInt16LE(28);
    const dataOffset = localOffset + LOCAL_SIZE + localNameLength + localExtraLength;
    if (dataOffset + compressedSize > directoryOffset) {
      throw new Error(`ZIP: entry ${JSON.stringify(name)} overlaps the central directory.`);
    }
    const localName = archive.subarray(localOffset + LOCAL_SIZE, localOffset + LOCAL_SIZE + localNameLength);
    const extra = archive.subarray(localOffset + LOCAL_SIZE + localNameLength, dataOffset);
    checkExtra(extra);
    const sameSizes = local.readUInt32LE(14) === crc && local.readUInt32LE(18) === compressedSize && local.readUInt32LE(22) === size;
    const zeroSizes = local.readUInt32LE(14) === 0 && local.readUInt32LE(18) === 0 && local.readUInt32LE(22) === 0;
    if (
      local.readUInt16LE(6) !== flags ||
      local.readUInt16LE(8) !== method ||
      !localName.equals(nameBytes) ||
      !(sameSizes || (flags & FLAG_DESCRIPTOR && zeroSizes))
    ) {
      throw new Error(`ZIP: local header of ${JSON.stringify(name)} differs from the central directory.`);
    }
    expectedOffset = dataOffset + compressedSize;
    if (flags & FLAG_DESCRIPTOR) {
      expectedOffset = readDescriptor(archive, expectedOffset, directoryOffset, crc, compressedSize, size, name);
    }

    const data = archive.subarray(dataOffset, dataOffset + compressedSize);
    const content = method === 0 ? data : inflate(data, size, name);
    if (crc32(content) !== crc) {
      throw new Error(`ZIP: CRC mismatch for ${JSON.stringify(name)}.`);
    }
    if (!isDirectory) {
      entries.push({ name, content, method, extra });
    }
  }
  if (position !== directory.length || expectedOffset !== directoryOffset) {
    throw new Error('ZIP: bytes outside the entries of the archive.');
  }
  return entries;
}

/** Finds the end of central directory record, which the archive must end with (its comment included). */
function findEnd(archive: Buffer): Buffer {
  for (let offset = archive.length - END_SIZE; offset >= Math.max(0, archive.length - END_SIZE - MAX_16); offset--) {
    if (archive.readUInt32LE(offset) === END_SIGNATURE && offset + END_SIZE + archive.readUInt16LE(offset + 20) === archive.length) {
      const end = archive.subarray(offset, offset + END_SIZE);
      decodeText(archive.subarray(offset + END_SIZE), FLAG_UTF8, 'comment');
      return end;
    }
  }
  throw new Error('ZIP: not a ZIP archive.');
}

/** Reads a data descriptor, with or without its signature, and returns where it ends. */
function readDescriptor(archive: Buffer, offset: number, limit: number, crc: number, compressedSize: number, size: number, name: string): number {
  const signed = offset + 4 <= limit && archive.readUInt32LE(offset) === DESCRIPTOR_SIGNATURE;
  const start = signed ? offset + 4 : offset;
  if (start + 12 > limit) {
    throw new Error(`ZIP: missing data descriptor for ${JSON.stringify(name)}.`);
  }
  if (archive.readUInt32LE(start) !== crc || archive.readUInt32LE(start + 4) !== compressedSize || archive.readUInt32LE(start + 8) !== size) {
    throw new Error(`ZIP: data descriptor of ${JSON.stringify(name)} differs from the central directory.`);
  }
  return start + 12;
}

/** Inflates exactly `size` bytes from all of `data`. */
function inflate(data: Buffer, size: number, name: string): Buffer {
  let result: { buffer: Buffer; engine: { bytesWritten: number } };
  try {
    // At least one byte of room: a stream that inflates beyond `size` then fails here.
    result = inflateRawSync(data, { maxOutputLength: size + 1, info: true }) as unknown as typeof result;
  } catch {
    throw new Error(`ZIP: entry ${JSON.stringify(name)} does not inflate to its size.`);
  }
  // inflateRawSync ignores what follows the end of the stream: bytesWritten is the input it consumed.
  if (result.buffer.length !== size || result.engine.bytesWritten !== data.length) {
    throw new Error(`ZIP: entry ${JSON.stringify(name)} does not inflate to its size.`);
  }
  return result.buffer;
}

/** Checks that an extra field is a well-formed list, without a field that changes the header. */
function checkExtra(extra: Buffer): void {
  let offset = 0;
  while (offset < extra.length) {
    if (offset + 4 > extra.length) {
      throw new Error('ZIP: malformed extra field.');
    }
    const id = extra.readUInt16LE(offset);
    const length = extra.readUInt16LE(offset + 2);
    if (REFUSED_EXTRA_IDS.has(id)) {
      throw new Error(`ZIP: unsupported extra field 0x${id.toString(16).padStart(4, '0')}.`);
    }
    offset += 4 + length;
  }
  if (offset !== extra.length) {
    throw new Error('ZIP: malformed extra field.');
  }
}

/** Decodes a name or a comment: UTF-8 when flagged, ASCII otherwise (the legacy code page is refused). */
function decodeText(bytes: Buffer, flags: number, what: string): string {
  if (!(flags & FLAG_UTF8) && bytes.some((byte) => byte > 0x7f)) {
    throw new Error(`ZIP: ${what} neither in UTF-8 nor in ASCII.`);
  }
  try {
    return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    throw new Error(`ZIP: ${what} is not valid UTF-8.`);
  }
}

/** Checks a path: relative, `/` separated, without empty, `.` or `..` segment, nor control character or backslash. */
function checkName(name: string): void {
  if (name === '' || /[\u0000-\u001f\u007f\\]/.test(name) || name.startsWith('/')) {
    throw new Error(`ZIP: invalid entry name ${JSON.stringify(name)}.`);
  }
  for (const segment of name.split('/')) {
    if (segment === '' || segment === '.' || segment === '..') {
      throw new Error(`ZIP: invalid entry name ${JSON.stringify(name)}.`);
    }
  }
}

/** The MS-DOS time and date of a moment, from its UTC fields (1980 to 2107). */
function dosDateTime(moment: Date): { time: number; date: number } {
  const year = moment.getUTCFullYear();
  if (Number.isNaN(year) || year < 1980 || year > 2107) {
    throw new Error('ZIP: the date of the entries must be between 1980 and 2107.');
  }
  return {
    time: (moment.getUTCHours() << 11) | (moment.getUTCMinutes() << 5) | (moment.getUTCSeconds() >> 1),
    date: ((year - 1980) << 9) | ((moment.getUTCMonth() + 1) << 5) | moment.getUTCDate(),
  };
}
