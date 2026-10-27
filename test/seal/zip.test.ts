/**
 * The ZIP archives of ASiC containers: the writer, the reading of a
 * container built by DSS, and the refusal of each archive that two readers
 * could see differently. The malformed archives are built by
 * test/helpers/zip.ts, not by the writer under test.
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, test } from 'node:test';
import { deflateRawSync } from 'node:zlib';

import { readZip, writeZip } from '../../dist/seal/zip.js';
import { DESCRIPTOR, UTF8, extraField, rawZip, type RawEntry } from '../helpers/zip.ts';

const MIMETYPE = Buffer.from('application/vnd.etsi.asic-e+zip');
const DATE = new Date('2026-01-01T12:00:00Z');

function entry(name: string | Buffer, text: string, more: Partial<RawEntry> = {}): RawEntry {
  return { name, content: Buffer.from(text), ...more };
}

function refused(archive: Buffer, message: RegExp) {
  assert.throws(() => readZip(archive), { message });
}

describe('writer', () => {
  const archive = writeZip(
    [
      { name: 'mimetype', content: MIMETYPE, stored: true },
      { name: "notes d'été.md", content: Buffer.from('# Notes\n') },
      { name: 'META-INF/manifest.xml', content: Buffer.from('<manifest/>') },
    ],
    DATE,
  );

  test('the entries are read back in their order', () => {
    const entries = readZip(archive);
    assert.deepEqual(
      entries.map((e) => [e.name, e.content.toString(), e.method, e.extra.length]),
      [
        ['mimetype', MIMETYPE.toString(), 0, 0],
        ["notes d'été.md", '# Notes\n', 8, 0],
        ['META-INF/manifest.xml', '<manifest/>', 8, 0],
      ],
    );
  });

  test('the mimetype can be read at the offsets of EN 319 162-1, A.1', () => {
    assert.deepEqual([...archive.subarray(0, 4)], [0x50, 0x4b, 0x03, 0x04]);
    assert.equal(archive.subarray(30, 38).toString(), 'mimetype');
    assert.equal(archive.readUInt32LE(18), MIMETYPE.length);
    assert.equal(archive.subarray(38, 38 + MIMETYPE.length).toString(), MIMETYPE.toString());
  });

  test('the archive depends on its entries and its date only', () => {
    const again = writeZip(
      [
        { name: 'mimetype', content: MIMETYPE, stored: true },
        { name: "notes d'été.md", content: Buffer.from('# Notes\n') },
        { name: 'META-INF/manifest.xml', content: Buffer.from('<manifest/>') },
      ],
      DATE,
    );
    assert.ok(again.equals(archive));
  });

  test('names the reader would refuse are refused', () => {
    for (const name of ['', '/abs', '../up', 'a/../b', 'a//b', 'a\\b', 'dir/', 'nul\u0000']) {
      assert.throws(() => writeZip([{ name, content: Buffer.alloc(0) }]), /invalid entry name/, name);
    }
  });

  test('two names that only differ by their Unicode normalization are refused', () => {
    assert.throws(
      () => writeZip([{ name: 'été', content: Buffer.alloc(0) }, { name: 'été', content: Buffer.alloc(0) }]),
      /duplicate entry/,
    );
  });

  test('a date outside the MS-DOS range is refused', () => {
    assert.throws(() => writeZip([], new Date('1979-12-31T00:00:00Z')), /between 1980 and 2107/);
  });
});

test('a container built by DSS is read', () => {
  const entries = readZip(readFileSync('test/fixtures/seal/dss-xades-b.asice'));
  assert.deepEqual(
    entries.map((e) => e.name),
    ['mimetype', 'contrat final.pdf', "notes d'été.md", 'META-INF/signatures001.xml', 'META-INF/manifest.xml'],
  );
  assert.equal(entries[0]?.content.toString(), MIMETYPE.toString());
  assert.equal(entries[0]?.method, 0);
  assert.equal(entries[2]?.content.toString(), "# Notes d'été\n");
});

describe('the builder of the tests makes archives the reader accepts', () => {
  test('with data descriptors, signed or not', () => {
    const archive = rawZip([entry('a.txt', 'A'), entry('b.txt', 'B', { descriptorSignature: false })]);
    assert.deepEqual(readZip(archive).map((e) => e.content.toString()), ['A', 'B']);
  });

  test('without data descriptor, with an ASCII name not flagged UTF-8', () => {
    const archive = rawZip([entry('a.txt', 'A', { flags: 0, method: 0 })]);
    assert.equal(readZip(archive)[0]?.content.toString(), 'A');
  });

  test('with a comment, and a directory entry, left out', () => {
    const archive = rawZip([entry('META-INF/', ''), entry('META-INF/a.xml', '<a/>')], { comment: Buffer.from('mimetype=application/vnd.etsi.asic-e+zip') });
    assert.deepEqual(readZip(archive).map((e) => e.name), ['META-INF/a.xml']);
  });
});

describe('an ambiguous archive is refused', () => {
  test('bytes before the first entry', () => {
    refused(rawZip([entry('a.txt', 'A')], { prefix: Buffer.from('xx') }), /not where the previous entry ends/);
  });

  test('bytes between two entries', () => {
    refused(rawZip([entry('a.txt', 'A'), entry('b.txt', 'B')], { gapAfter: { index: 0, bytes: Buffer.from('xx') } }), /not where the previous entry ends/);
  });

  test('an entry absent from the central directory', () => {
    refused(rawZip([entry('a.txt', 'A'), entry('hidden.txt', 'H', { hidden: true })]), /bytes outside the entries/);
  });

  test('bytes after the end record', () => {
    refused(rawZip([entry('a.txt', 'A')], { suffix: Buffer.from('xx') }), /not a ZIP archive/);
  });

  test('a local name that differs from the central one', () => {
    refused(rawZip([entry('a.txt', 'A', { local: { name: 'b.txt' } })]), /local header of "a.txt" differs/);
  });

  test('a local method that differs from the central one', () => {
    refused(rawZip([entry('a.txt', 'A', { method: 0, local: { method: 8 } })]), /local header of "a.txt" differs/);
  });

  test('a data descriptor that differs from the central directory', () => {
    const archive = rawZip([entry('a.txt', 'A')]);
    // The CRC of the descriptor follows its signature.
    const at = archive.indexOf(Buffer.from([0x50, 0x4b, 0x07, 0x08])) + 4;
    archive.writeUInt32LE((archive.readUInt32LE(at) ^ 1) >>> 0, at);
    refused(archive, /data descriptor of "a.txt" differs/);
  });

  test('two entries of the same name', () => {
    refused(rawZip([entry('a.txt', 'A'), entry('a.txt', 'B')]), /duplicate entry "a.txt"/);
  });

  test('two names that only differ by their Unicode normalization', () => {
    refused(rawZip([entry('été.txt', 'A'), entry('été.txt', 'B')]), /duplicate entry/);
  });

  test('a second name in an Info-ZIP Unicode path field', () => {
    refused(rawZip([entry('a.txt', 'A', { extra: extraField(0x7075, Buffer.from('\u0001xxxxb.txt')) })]), /unsupported extra field 0x7075/);
  });

  test('a ZIP64 field', () => {
    refused(rawZip([entry('a.txt', 'A', { extra: extraField(0x0001, Buffer.alloc(16)) })]), /unsupported extra field 0x0001/);
  });

  test('a malformed extra field', () => {
    refused(rawZip([entry('a.txt', 'A', { extra: Buffer.from([0x99, 0x99, 0x10, 0x00]) })]), /malformed extra field/);
  });

  test('a stored entry with two sizes', () => {
    refused(rawZip([entry('a.txt', 'AAAA', { method: 0, flags: UTF8, size: 3 })]), /stored entry "a.txt" with two sizes/);
  });

  test('a declared count different from the central directory', () => {
    refused(rawZip([entry('a.txt', 'A'), entry('b.txt', 'B')], { count: 1 }), /bytes outside the entries/);
  });
});

describe('a name that leaves the container or hides its path is refused', () => {
  for (const name of ['/etc/passwd', '../up.txt', 'a/../../b', 'a\\..\\b', 'a//b', './a', 'tab\there']) {
    test(JSON.stringify(name), () => {
      refused(rawZip([entry(name, 'A')]), /invalid entry name/);
    });
  }

  test('a name that is not valid UTF-8', () => {
    refused(rawZip([entry(Buffer.from([0x61, 0xff, 0x62]), 'A')]), /name is not valid UTF-8/);
  });

  test('a name not in ASCII without the UTF-8 flag (legacy code page)', () => {
    refused(rawZip([entry(Buffer.from([0x82, 0x74, 0x82]), 'A', { flags: DESCRIPTOR })]), /name neither in UTF-8 nor in ASCII/);
  });
});

describe('an unsupported entry is refused', () => {
  test('encrypted', () => {
    refused(rawZip([entry('a.txt', 'A', { flags: UTF8 | DESCRIPTOR | 0x0001 })]), /encrypted or unsupported/);
  });

  test('compressed with another method (bzip2)', () => {
    refused(rawZip([entry('a.txt', 'A', { method: 12, data: Buffer.from('BZh') })]), /compression method 12/);
  });
});

describe('content that does not match its headers is refused', () => {
  test('a CRC mismatch', () => {
    refused(rawZip([entry('a.txt', 'A', { crc: 0x12345678 })]), /CRC mismatch for "a.txt"/);
  });

  test('a deflate stream followed by other bytes', () => {
    const data = Buffer.concat([deflateRawSync(Buffer.from('A')), Buffer.from('hidden')]);
    refused(rawZip([entry('a.txt', 'A', { data })]), /does not inflate to its size/);
  });

  test('a deflate stream longer than its declared size', () => {
    const content = Buffer.alloc(100_000);
    refused(rawZip([{ name: 'bomb', content, data: deflateRawSync(content), size: 10 }]), /does not inflate to its size/);
  });

  test('a truncated deflate stream', () => {
    const data = deflateRawSync(Buffer.from('some content to compress'));
    refused(rawZip([entry('a.txt', 'some content to compress', { data: data.subarray(0, data.length - 2) })]), /does not inflate to its size/);
  });
});

describe('limits', () => {
  test('the number of entries', () => {
    const archive = rawZip([entry('a', 'A'), entry('b', 'B'), entry('c', 'C')]);
    assert.throws(() => readZip(archive, { maxEntries: 2, maxTotalSize: 1000 }), /more than 2 entries/);
  });

  test('the total uncompressed size, checked before inflating', () => {
    const archive = rawZip([entry('a', 'A'.repeat(600)), entry('b', 'B'.repeat(600))]);
    assert.throws(() => readZip(archive, { maxEntries: 10, maxTotalSize: 1000 }), /more than 1000 bytes/);
  });
});
