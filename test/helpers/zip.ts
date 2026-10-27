/**
 * A ZIP builder for the tests, written apart from src/seal/zip.ts so that
 * the archives the reader is tested on do not come from the code under test.
 * Every field can be set, so that each test builds one malformation; by
 * default, an entry is written as the archives of DSS are: UTF-8 name,
 * deflate, sizes in a data descriptor.
 */

import { crc32, deflateRawSync } from 'node:zlib';

export interface RawEntry {
  name: string | Buffer;
  content: Buffer;
  method?: number;
  /** The general purpose flags, the same in both headers (default: UTF-8 and data descriptor). */
  flags?: number;
  /** The compressed bytes, instead of the content compressed with `method`. */
  data?: Buffer;
  crc?: number;
  /** The uncompressed size written in the headers. */
  size?: number;
  extra?: Buffer;
  /** The descriptor has its signature (default true). */
  descriptorSignature?: boolean;
  /** Overrides of the local header only. */
  local?: { name?: string | Buffer; method?: number; flags?: number; extra?: Buffer };
  /** Left out of the central directory. */
  hidden?: boolean;
}

export interface RawOptions {
  /** Bytes before the first entry. */
  prefix?: Buffer;
  /** Bytes between entries, after the entry of this index. */
  gapAfter?: { index: number; bytes: Buffer };
  comment?: Buffer;
  /** Bytes after the end record. */
  suffix?: Buffer;
  /** The number of entries the end record declares. */
  count?: number;
}

export const UTF8 = 0x0800;
export const DESCRIPTOR = 0x0008;

export function rawZip(entries: RawEntry[], options: RawOptions = {}): Buffer {
  const parts: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;
  const push = (bytes: Buffer) => {
    parts.push(bytes);
    offset += bytes.length;
  };
  if (options.prefix) {
    push(options.prefix);
  }
  entries.forEach((entry, index) => {
    const method = entry.method ?? 8;
    const flags = entry.flags ?? UTF8 | DESCRIPTOR;
    const name = Buffer.from(entry.name);
    const data = entry.data ?? (method === 8 ? deflateRawSync(entry.content) : entry.content);
    const crc = entry.crc ?? crc32(entry.content);
    const size = entry.size ?? entry.content.length;
    const extra = entry.extra ?? Buffer.alloc(0);
    const localName = Buffer.from(entry.local?.name ?? name);
    const localExtra = entry.local?.extra ?? extra;
    const localFlags = entry.local?.flags ?? flags;
    const withDescriptor = (localFlags & DESCRIPTOR) !== 0;

    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(localFlags, 6);
    local.writeUInt16LE(entry.local?.method ?? method, 8);
    if (!withDescriptor) {
      local.writeUInt32LE(crc, 14);
      local.writeUInt32LE(data.length, 18);
      local.writeUInt32LE(size, 22);
    }
    local.writeUInt16LE(localName.length, 26);
    local.writeUInt16LE(localExtra.length, 28);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(flags, 8);
    central.writeUInt16LE(method, 10);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(data.length, 20);
    central.writeUInt32LE(size, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt16LE(extra.length, 30);
    central.writeUInt32LE(offset, 42);
    if (!entry.hidden) {
      centrals.push(central, name, extra);
    }

    push(Buffer.concat([local, localName, localExtra, data]));
    if (withDescriptor) {
      const descriptor = Buffer.alloc(12);
      descriptor.writeUInt32LE(crc, 0);
      descriptor.writeUInt32LE(data.length, 4);
      descriptor.writeUInt32LE(size, 8);
      push(entry.descriptorSignature === false ? descriptor : Buffer.concat([Buffer.from([0x50, 0x4b, 0x07, 0x08]), descriptor]));
    }
    if (options.gapAfter?.index === index) {
      push(options.gapAfter.bytes);
    }
  });
  const directory = Buffer.concat(centrals);
  const count = options.count ?? entries.filter((entry) => !entry.hidden).length;
  const comment = options.comment ?? Buffer.alloc(0);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(count, 8);
  end.writeUInt16LE(count, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(offset, 16);
  end.writeUInt16LE(comment.length, 20);
  return Buffer.concat([...parts, directory, end, comment, options.suffix ?? Buffer.alloc(0)]);
}

/** An extra field of one record. */
export function extraField(id: number, data: Buffer = Buffer.alloc(0)): Buffer {
  const header = Buffer.alloc(4);
  header.writeUInt16LE(id, 0);
  header.writeUInt16LE(data.length, 2);
  return Buffer.concat([header, data]);
}
