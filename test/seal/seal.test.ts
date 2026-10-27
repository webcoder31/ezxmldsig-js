/**
 * The creation of seals at level B: the layout of the container, the
 * structure of the XAdES signature (EN 319 132-1, level B-B), the choice of
 * the algorithms, the refusal of misuses, and the validation of the seals by
 * DSS, which does not go through the code under test.
 */

import assert from 'node:assert/strict';
import { X509Certificate, createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, test } from 'node:test';

import { DOMParser, type Document, type Element } from '@xmldom/xmldom';
import xpath from 'xpath';

import * as alg from '../../dist/seal/algorithms.js';
import { createSeal, type SealFile, type SealOptions } from '../../dist/seal/seal.js';
import { readZip } from '../../dist/seal/zip.js';
import { dssSkip, validateWithDss } from '../helpers/dss.ts';

const CERTS = 'test/fixtures/seal/certs';
const PASSWORD = 'signKeyPassword';
const INTERMEDIATE = `${CERTS}/intermediate.cert.pem`;
const SIGNING_TIME = new Date('2027-03-01T10:20:30.456Z');

const select = xpath.useNamespaces({
  ds: 'http://www.w3.org/2000/09/xmldsig#',
  xades: 'http://uri.etsi.org/01903/v1.3.2#',
  asic: 'http://uri.etsi.org/02918/v1.2.1#',
  manifest: 'urn:oasis:names:tc:opendocument:xmlns:manifest:1.0',
});

const FILES: SealFile[] = [
  { name: 'contrat final.pdf', content: Buffer.from('%PDF-1.4\n') },
  { name: "notes d'été.md", content: Buffer.from("# Notes d'été\n") },
  { name: 'docs/a#b%c.txt', content: Buffer.from('odd name\n') },
  { name: 'data.bin', content: Buffer.from([0, 1, 2, 255]), mimeType: 'application/x-test; charset="none"' },
];

function seal(key = 'rsa3072', options: SealOptions = {}, files: SealFile[] = FILES): Buffer {
  return createSeal(files, `${CERTS}/${key}.key.pem`, `${CERTS}/${key}.cert.pem`, PASSWORD, { chain: [INTERMEDIATE], signingTime: SIGNING_TIME, ...options });
}

function parse(xml: Buffer): Document {
  return new DOMParser().parseFromString(xml.toString('utf8'), 'application/xml') as unknown as Document;
}

function values(expression: string, doc: Document): string[] {
  return (select(expression, doc as never) as unknown as { nodeValue?: string; textContent?: string }[])
    .map((node) => node.nodeValue ?? node.textContent ?? '');
}

function value(expression: string, doc: Document): string {
  const found = values(expression, doc);
  assert.equal(found.length, 1, expression);
  return found[0] as string;
}

/** The DER of the first certificate of a PEM file, read by node:crypto. */
function der(path: string): Buffer {
  return new X509Certificate(readFileSync(path)).raw;
}

describe('the container', () => {
  const entries = readZip(seal());

  test('holds the mimetype first, the sealed files, the manifest and the signature', () => {
    assert.deepEqual(entries.map((e) => e.name), [
      'mimetype', 'contrat final.pdf', "notes d'été.md", 'docs/a#b%c.txt', 'data.bin', 'META-INF/manifest.xml', 'META-INF/signatures001.xml',
    ]);
    assert.equal(entries[0]?.content.toString(), 'application/vnd.etsi.asic-e+zip');
    assert.equal(entries[0]?.method, 0);
    assert.equal(entries[0]?.extra.length, 0);
    for (const [index, file] of FILES.entries()) {
      assert.ok(entries[index + 1]?.content.equals(file.content), file.name);
    }
  });

  test('the manifest lists the container and each sealed file with its media type', () => {
    const manifest = parse(entries[5]?.content as Buffer);
    assert.deepEqual(values('/manifest:manifest/manifest:file-entry/@manifest:full-path', manifest), ['/', ...FILES.map((f) => f.name)]);
    assert.deepEqual(values('/manifest:manifest/manifest:file-entry/@manifest:media-type', manifest), [
      'application/vnd.etsi.asic-e+zip', 'application/pdf', 'text/markdown', 'text/plain', 'application/x-test; charset="none"',
    ]);
    assert.equal(value('/manifest:manifest/@manifest:version', manifest), '1.2');
  });
});

describe('the signature (EN 319 132-1, 6.3)', () => {
  const entries = readZip(seal());
  const doc = parse(entries[6]?.content as Buffer);
  const id = value('/asic:XAdESSignatures/ds:Signature/@Id', doc);

  test('one ds:Signature in asic:XAdESSignatures', () => {
    assert.equal(values('/asic:XAdESSignatures/*', doc).length, 1);
    assert.equal(values('//ds:Signature', doc).length, 1);
  });

  test('exclusive canonicalization, RSA-PSS by default for an RSA key', () => {
    assert.equal(value('//ds:SignedInfo/ds:CanonicalizationMethod/@Algorithm', doc), alg.EXC_C14N);
    assert.equal(value('//ds:SignedInfo/ds:SignatureMethod/@Algorithm', doc), alg.RSA_PSS_SHA256);
  });

  test('one reference per sealed file, without transform, its URI percent-encoded, its digest that of the file', () => {
    const references = select('//ds:SignedInfo/ds:Reference[not(@Type)]', doc as never) as unknown as Element[];
    assert.deepEqual(references.map((r) => r.getAttribute('URI')), ['contrat%20final.pdf', "notes%20d'%C3%A9t%C3%A9.md", 'docs/a%23b%25c.txt', 'data.bin']);
    for (const [index, reference] of references.entries()) {
      assert.equal(reference.getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'Transforms').length, 0);
      const digest = createHash('sha256').update(FILES[index]?.content as Buffer).digest('base64');
      assert.equal(reference.getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'DigestValue')[0]?.textContent, digest);
    }
  });

  test('a reference to the signed properties, of the type of XAdES', () => {
    assert.equal(value('//ds:Reference[@Type="http://uri.etsi.org/01903#SignedProperties"]/@URI', doc), `#${value('//xades:SignedProperties/@Id', doc)}`);
    assert.equal(value('//ds:Reference[@Type]/ds:Transforms/ds:Transform/@Algorithm', doc), alg.EXC_C14N);
  });

  test('one QualifyingProperties whose Target is the signature', () => {
    assert.equal(value('/asic:XAdESSignatures/ds:Signature/ds:Object/xades:QualifyingProperties/@Target', doc), `#${id}`);
    assert.equal(values('//xades:QualifyingProperties', doc).length, 1);
    assert.equal(values('//xades:UnsignedProperties', doc).length, 0);
  });

  test('SigningTime in UTC, to the second', () => {
    assert.equal(value('//xades:SigningTime', doc), '2027-03-01T10:20:30Z');
  });

  test('SigningCertificateV2: the digest of the signing certificate, no IssuerSerialV2, no SigningCertificate', () => {
    assert.equal(value('//xades:SigningCertificateV2/xades:Cert/xades:CertDigest/ds:DigestValue', doc), createHash('sha256').update(der(`${CERTS}/rsa3072.cert.pem`)).digest('base64'));
    assert.equal(values('//xades:IssuerSerialV2', doc).length, 0);
    assert.equal(values('//xades:SigningCertificate', doc).length, 0);
  });

  test('a DataObjectFormat with a MimeType per file, pointing at its reference', () => {
    const referenceIds = values('//ds:SignedInfo/ds:Reference[not(@Type)]/@Id', doc);
    assert.deepEqual(values('//xades:DataObjectFormat/@ObjectReference', doc), referenceIds.map((r) => `#${r}`));
    assert.deepEqual(values('//xades:DataObjectFormat/xades:MimeType', doc), ['application/pdf', 'text/markdown', 'text/plain', 'application/x-test; charset="none"']);
  });

  test('the signing certificate first in KeyInfo, then the chain', () => {
    assert.deepEqual(values('//ds:KeyInfo/ds:X509Data/ds:X509Certificate', doc).map((b64) => Buffer.from(b64, 'base64')), [der(`${CERTS}/rsa3072.cert.pem`), der(INTERMEDIATE)]);
  });

  test('the identifiers differ from one seal to the next', () => {
    const other = parse(readZip(seal())[6]?.content as Buffer);
    assert.notEqual(value('/asic:XAdESSignatures/ds:Signature/@Id', other), id);
  });
});

describe('the algorithms follow the key', () => {
  const method = (container: Buffer) => value('//ds:SignatureMethod/@Algorithm', parse(readZip(container).at(-1)?.content as Buffer));

  test('ECDSA with SHA-256 on P-256, with SHA-384 on P-384', () => {
    assert.equal(method(seal('p256')), alg.ECDSA_SHA256);
    assert.equal(method(seal('p384')), alg.ECDSA_SHA384);
  });

  test('RSA PKCS#1 v1.5 on request', () => {
    assert.equal(method(seal('rsa3072', { signatureAlgorithm: alg.RSA_SHA256 })), alg.RSA_SHA256);
  });

  test('the digest of the files on request', () => {
    const doc = parse(readZip(seal('p256', { digestAlgorithm: alg.SHA512 })).at(-1)?.content as Buffer);
    assert.deepEqual(new Set(values('//ds:DigestMethod/@Algorithm', doc)), new Set([alg.SHA512]));
  });
});

describe('misuses are refused', () => {
  const cases: [string, () => unknown, RegExp][] = [
    ['no file', () => seal('rsa3072', {}, []), /no file to seal/],
    ['the name mimetype', () => seal('rsa3072', {}, [{ name: 'mimetype', content: Buffer.alloc(0) }]), /reserved by the container/],
    ['a name in META-INF', () => seal('rsa3072', {}, [{ name: 'META-INF/x.xml', content: Buffer.alloc(0) }]), /reserved by the container/],
    ['a name not in NFC', () => seal('rsa3072', {}, [{ name: 'été.txt', content: Buffer.alloc(0) }]), /normalization form C/],
    ['a path that leaves the container', () => seal('rsa3072', {}, [{ name: '../x.txt', content: Buffer.alloc(0) }]), /invalid entry name/],
    ['two files of the same name', () => seal('rsa3072', {}, [{ name: 'a', content: Buffer.alloc(0) }, { name: 'a', content: Buffer.alloc(0) }]), /duplicate entry/],
    ['an invalid media type', () => seal('rsa3072', {}, [{ name: 'a', content: Buffer.alloc(0), mimeType: 'text' }]), /invalid media type/],
    ['a content that is not bytes', () => seal('rsa3072', {}, [{ name: 'a', content: 'text' as unknown as Uint8Array }]), /must have a name and a content/],
    ['a key that does not match the certificate', () => createSeal(FILES, `${CERTS}/rsa2048.key.pem`, `${CERTS}/rsa3072.cert.pem`, PASSWORD), /does not match the signing certificate/],
    ['a wrong password', () => createSeal(FILES, `${CERTS}/rsa3072.key.pem`, `${CERTS}/rsa3072.cert.pem`, 'wrong'), /unable to load the signing key/],
    ['ECDSA with an RSA key', () => seal('rsa3072', { signatureAlgorithm: alg.ECDSA_SHA256 }), /needs an EC key/],
    ['RSA-PSS with an EC key', () => seal('p256', { signatureAlgorithm: alg.RSA_PSS_SHA256 }), /needs an RSA key/],
    ['RSA-SHA1', () => seal('rsa3072', { signatureAlgorithm: 'http://www.w3.org/2000/09/xmldsig#rsa-sha1' }), /unsupported signature algorithm/],
    ['SHA-1 digests', () => seal('rsa3072', { digestAlgorithm: 'http://www.w3.org/2000/09/xmldsig#sha1' }), /unsupported digest algorithm/],
    ['an RSA key of 1024 bits', () => seal('rsa1024'), /less than 2048 bits/],
    ['a signing time before the certificate', () => seal('rsa3072', { signingTime: new Date('2020-01-01T00:00:00Z') }), /not valid at the signing time/],
    ['a certificate whose key usage does not allow signing', () => createSeal(FILES, `${CERTS}/intermediate.key.pem`, INTERMEDIATE, null), /key usage/],
  ];
  for (const [name, run, message] of cases) {
    test(name, () => {
      assert.throws(run, { message });
    });
  }
});

describe('validation by DSS', { skip: dssSkip }, () => {
  const expected = ['contrat final.pdf', "notes d'été.md", 'docs/a#b%c.txt', 'data.bin'];
  const seals: [string, () => Buffer][] = [
    ['RSA 3072, RSA-PSS', () => seal('rsa3072', { signingTime: new Date() })],
    ['RSA 2048, RSA-PSS', () => seal('rsa2048', { signingTime: new Date() })],
    ['RSA 3072, PKCS#1 v1.5', () => seal('rsa3072', { signingTime: new Date(), signatureAlgorithm: alg.RSA_SHA256 })],
    ['P-256, ECDSA', () => seal('p256', { signingTime: new Date() })],
    ['P-384, ECDSA, SHA-512 digests', () => seal('p384', { signingTime: new Date(), digestAlgorithm: alg.SHA512 })],
  ];
  for (const [name, make] of seals) {
    test(name, async () => {
      const report = await validateWithDss(make());
      assert.equal(report.containerType, 'ASiC-E');
      assert.equal(report.signatures.length, 1);
      const signature = report.signatures[0];
      assert.equal(signature?.format, 'XAdES-BASELINE-B');
      assert.deepEqual(signature?.scope, expected);
      assert.equal(signature?.signatureIntact, true);
      assert.equal(signature?.references.length, expected.length + 1);
      assert.ok(signature?.references.every((r) => r.found && r.intact));
      assert.deepEqual(signature?.trusted, ['CN=Lothbrok Seal Test,OU=Seal Root CA,O=Lothbrok Ltd,C=DK']);
      // Until the test PKI answers at pki.ezxmlseal.test, the only errors are those of the missing revocation data.
      assert.equal(signature?.indication, 'INDETERMINATE');
      assert.deepEqual(signature?.errors, ['The certificate validation is not conclusive!', 'No revocation data found for the certificate!']);
    });
  }
});
