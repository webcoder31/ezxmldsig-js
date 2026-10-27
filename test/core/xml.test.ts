/**
 * Loading of XML documents: a document type declaration is refused before
 * the document is parsed, and so is a document whose encoding would hide one
 * from that check (the cases of XMLParsingTest of the PHP library, at the
 * level of the loader; those that need a valid token come with the
 * analysis). Any error or warning of the parser refuses the document.
 */

import assert from 'node:assert/strict';
import { describe, test } from 'node:test';

import { loadXML } from '../../dist/core/xml.js';

const DOCTYPE_ERROR = 'XML Digital Signature must not have a document type declaration (DOCTYPE)!';
const ENCODING_ERROR = 'XML Digital Signature must be encoded in UTF-8!';
const INVALID_ERROR = 'XML Digital Signature is not a valid XML document!';

/** A document shaped as a token, whose content does not matter here. */
const DOCUMENT = '<?xml version="1.0"?>\n<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:Object Id="Token"><Token><TokenData><name Algorithm="base64">UmFnbmFy</name></TokenData></Token></ds:Object></ds:Signature>\n';

function load(xml: unknown) {
  return loadXML(xml, 'XML Digital Signature');
}

function withDoctype(internalSubset: string, xml = DOCUMENT): string {
  return xml.replace(/^(<\?xml[^>]*\?>\s*)/, `$1<!DOCTYPE ds:Signature [${internalSubset}]>\n`);
}

function withDeclaredEncoding(encoding: string, xml: string): string {
  return xml.replace(/^<\?xml[^>]*\?>/, `<?xml version="1.0" encoding="${encoding}"?>`);
}

/** Encodes a string in UTF-16, big-endian or little-endian. */
function utf16(text: string, endianness: 'BE' | 'LE'): Buffer {
  const le = Buffer.from(text, 'utf16le');
  return endianness === 'LE' ? le : Buffer.from(le).swap16();
}

test('a document without document type declaration is loaded', () => {
  assert.equal(load(DOCUMENT).documentElement?.localName, 'Signature');
  assert.equal(load(Buffer.from(DOCUMENT, 'utf8')).documentElement?.localName, 'Signature');
});

describe('a document type declaration is refused', () => {
  const doctypes = {
    'empty': '',
    'internal entity': '<!ENTITY e "expanded">',
    'nested internal entities': '<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">',
    'external entity': '<!ENTITY e SYSTEM "file:///etc/passwd">',
    'external parameter entity': '<!ENTITY % p SYSTEM "http://127.0.0.1/parameter"> %p;',
  };
  for (const [name, internalSubset] of Object.entries(doctypes)) {
    test(name, () => {
      assert.throws(() => load(withDoctype(internalSubset)), { message: DOCTYPE_ERROR });
      assert.throws(() => load(Buffer.from(withDoctype(internalSubset))), { message: DOCTYPE_ERROR });
    });
  }

  test('an entity referenced in the token', () => {
    const xml = withDoctype('<!ENTITY e SYSTEM "file:///etc/passwd">').replace('<TokenData>', '<TokenData><e>&e;</e>');
    assert.throws(() => load(xml), { message: DOCTYPE_ERROR });
  });
});

describe('another encoding than UTF-8 is refused', () => {
  const doctype = withDoctype('<!ENTITY e SYSTEM "file:///etc/passwd">');
  const cases: Record<string, [unknown, string]> = {
    'UTF-16 with BOM': [Buffer.concat([Buffer.from([0xff, 0xfe]), utf16(withDeclaredEncoding('UTF-16', doctype), 'LE')]), ENCODING_ERROR],
    'UTF-16 without BOM': [utf16(withDeclaredEncoding('UTF-16', doctype), 'BE'), ENCODING_ERROR],
    'UTF-16 read as a string': [utf16(withDeclaredEncoding('UTF-16', doctype), 'BE').toString('latin1'), ENCODING_ERROR],
    'declared ISO-8859-1': [withDeclaredEncoding('ISO-8859-1', doctype), ENCODING_ERROR],
    // libxml detects EBCDIC from these first bytes ("<?xm").
    'EBCDIC': [Buffer.concat([Buffer.from([0x4c, 0x6f, 0xa7, 0x94]), Buffer.from(doctype.slice(4))]), INVALID_ERROR],
  };
  for (const [name, [xml, error]] of Object.entries(cases)) {
    test(name, () => {
      assert.throws(() => load(xml), { message: error });
    });
  }
});

test('a declared UTF-8 encoding, with a byte order mark, is accepted', () => {
  const xml = withDeclaredEncoding('utf-8', DOCUMENT);
  assert.equal(load(`﻿${xml}`).documentElement?.localName, 'Signature');
  assert.equal(load(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(xml)])).documentElement?.localName, 'Signature');
});

test('bytes that are not UTF-8 are refused', () => {
  assert.throws(() => load(Buffer.from('<a>\xC3</a>', 'latin1')), { message: INVALID_ERROR });
});

test('an invalid document is refused', () => {
  for (const xml of ['', 'not XML', '<a>', '<a/><b/>', '<a/>trailing', ' <?xml version="1.0"?><a/>', '<a></b>', '<p:a/>', '<a x="1" x="2"/>', 123, null, undefined, {}]) {
    assert.throws(() => load(xml), { message: INVALID_ERROR }, String(xml));
  }
});

test('a document the parser only warns about is refused', () => {
  // xmldom accepts an unquoted attribute value, with a warning; libxml
  // refuses it.
  assert.throws(() => load('<a b=c/>'), { message: INVALID_ERROR });
  // xmldom reports an undeclared entity as an error, and goes on.
  assert.throws(() => load('<a>&e;</a>'), { message: INVALID_ERROR });
});

test('a character XML 1.0 cannot hold is refused, as is or as a character reference', () => {
  for (const xml of ['<a>\u0001</a>', '<a>&#0;</a>', '<a>&#x1;</a>', '<a b="&#x1F;"/>', '<a>&#xFFFE;</a>', '<a>\uD800</a>', '<a>￿</a>']) {
    assert.throws(() => load(xml), { message: INVALID_ERROR }, JSON.stringify(xml));
  }
  assert.equal(load('<a>😀&#x1F600;\t\n\r</a>').documentElement?.textContent, '😀😀\t\n\n');
});

test('elements nested deeper than libxml accepts are refused', () => {
  const nested = (depth: number) => '<a>'.repeat(depth) + '</a>'.repeat(depth);
  assert.equal(load(nested(257)).documentElement?.localName, 'a');
  assert.throws(() => load(nested(258)), { message: INVALID_ERROR });
  assert.throws(() => load(nested(200000)), { message: INVALID_ERROR });
});

test('whitespace is preserved', () => {
  const doc = load('<a>\n  <b> x </b>\n</a>');
  assert.equal(doc.documentElement?.childNodes.length, 3);
  assert.equal(doc.documentElement?.textContent, '\n   x \n');
});
