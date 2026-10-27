/**
 * The verification of seals at level B: valid seals, the seal of another
 * producer (DSS), the trust in the signer, and the attacks on a sealed
 * container. Each attack starts from a valid seal and changes one thing; the
 * error says which rule refused it.
 */

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, test } from 'node:test';

import * as alg from '../../dist/seal/algorithms.js';
import { createSeal, type SealFile, type SealOptions } from '../../dist/seal/seal.js';
import { verifySeal, type VerifyOptions } from '../../dist/seal/verify.js';
import { readZip, writeZip, type ZipEntry } from '../../dist/seal/zip.js';

const CERTS = 'test/fixtures/seal/certs';
const PASSWORD = 'signKeyPassword';
const ROOT = `${CERTS}/root.cert.pem`;
const INTERMEDIATE = `${CERTS}/intermediate.cert.pem`;
const SIGNATURE = 'META-INF/signatures001.xml';

const FILES: SealFile[] = [
  { name: 'contrat final.pdf', content: Buffer.from('%PDF-1.4\n') },
  { name: "notes d'été.md", content: Buffer.from("# Notes d'été\n") },
];

function seal(key = 'rsa3072', options: SealOptions = {}, files: SealFile[] = FILES): Buffer {
  return createSeal(files, `${CERTS}/${key}.key.pem`, `${CERTS}/${key}.cert.pem`, PASSWORD, { chain: [INTERMEDIATE], ...options });
}

function check(container: Buffer, options: Partial<VerifyOptions> = {}) {
  return verifySeal(container, { caCertPath: ROOT, revocation: false, ...options });
}

function error(container: Buffer, options: Partial<VerifyOptions> = {}): string | null {
  return check(container, options).getError();
}

/** The container with its entries changed. */
function rebuild(container: Buffer, change: (entries: { name: string; content: Buffer; stored?: boolean }[]) => { name: string; content: Buffer; stored?: boolean }[]): Buffer {
  const entries = readZip(container).map((e: ZipEntry) => ({ name: e.name, content: e.content, stored: e.method === 0 }));
  return writeZip(change(entries));
}

/** The container with its signature file changed (as text). */
function editSignature(container: Buffer, change: (xml: string) => string): Buffer {
  return rebuild(container, (entries) => entries.map((e) => {
    if (e.name !== SIGNATURE) {
      return e;
    }
    const xml = change(e.content.toString('utf8'));
    assert.notEqual(xml, e.content.toString('utf8'), 'the change applies');
    return { ...e, content: Buffer.from(xml, 'utf8') };
  }));
}

describe('valid seals', () => {
  for (const key of ['rsa3072', 'rsa2048', 'p256', 'p384']) {
    test(key, () => {
      const result = check(seal(key));
      assert.equal(result.getError(), null);
      assert.equal(result.isValid(), true);
      assert.equal(result.getLevel(), 'B');
      assert.deepEqual(result.getFiles(), [
        { name: 'contrat final.pdf', mimeType: 'application/pdf' },
        { name: "notes d'été.md", mimeType: 'text/markdown' },
      ]);
      assert.equal(result.getTimestampTime(), null);
      assert.equal(result.isRevocationChecked(), false);
      assert.equal(result.getSigningCertificate()?.getSubject()['OU'], `${key.startsWith('rsa') ? `RSA ${key.slice(3)}` : `P-${key.slice(1)}`} Seal Dept`);
    });
  }

  test('the signing time is the claimed one, to the second', () => {
    const result = check(seal('p256', { signingTime: new Date('2027-01-02T03:04:05.678Z') }));
    assert.deepEqual(result.getSigningTime(), new Date('2027-01-02T03:04:05Z'));
  });

  test('RSA PKCS#1 v1.5, and SHA-512 digests', () => {
    assert.equal(error(seal('rsa3072', { signatureAlgorithm: alg.RSA_SHA256 })), null);
    assert.equal(error(seal('p384', { digestAlgorithm: alg.SHA512 })), null);
  });

  test('a seal built by DSS, whose certificate is trusted', () => {
    const result = verifySeal(readFileSync('test/fixtures/seal/dss-xades-b.asice'), { caCertPath: 'test/fixtures/seal/dss-signer.cert.pem', revocation: false });
    assert.equal(result.getError(), null);
    assert.deepEqual(result.getFiles(), [
      { name: 'contrat final.pdf', mimeType: 'application/pdf' },
      { name: "notes d'été.md", mimeType: 'application/octet-stream' },
    ]);
  });

  test('a container without mimetype (it is optional)', () => {
    assert.equal(error(rebuild(seal(), (entries) => entries.filter((e) => e.name !== 'mimetype'))), null);
  });
});

describe('revocation', () => {
  test('is checked by default: without revocation data, the seal is invalid', () => {
    const result = verifySeal(seal(), { caCertPath: ROOT });
    assert.equal(result.isValid(), false);
    assert.match(result.getError() ?? '', /No revocation data for the signing certificate/);
    assert.deepEqual(result.getFiles(), []);
  });
});

describe('trust in the signer', () => {
  test('the intermediate CA given by the verifier, when the seal does not embed it', () => {
    const container = seal('rsa3072', { chain: [] });
    assert.match(error(container) ?? '', /not trusted/);
    assert.equal(error(container, { caCertPath: [INTERMEDIATE, ROOT] }), null);
  });

  test('a root embedded in the seal is not trusted for that', () => {
    const container = seal('rsa3072', { chain: [INTERMEDIATE, ROOT] });
    assert.equal(error(container), null);
    assert.match(error(container, { caCertPath: 'test/fixtures/certs/root.cert.pem' }) ?? '', /not trusted/);
  });

  test('another CA is not trusted', () => {
    assert.match(error(seal(), { caCertPath: ['test/fixtures/certs/intermediate.cert.pem', 'test/fixtures/certs/root.cert.pem'] }) ?? '', /not trusted/);
  });

  test('the expected subject, as a DN or as fields', () => {
    const container = seal('p256');
    const dn = check(container).getSigningCertificate()?.getDN() as string;
    assert.equal(error(container, { expectedSubject: dn }), null);
    assert.equal(error(container, { expectedSubject: { OU: 'P-256 Seal Dept', O: 'Lothbrok Ltd' } }), null);
    assert.match(error(container, { expectedSubject: { OU: 'P-384 Seal Dept' } }) ?? '', /not the expected one/);
    assert.match(error(container, { expectedSubject: dn.replace('P-256', 'P-384') }) ?? '', /not the expected one/);
  });
});

describe('attacks on the container', () => {
  const valid = seal();
  const cases: [string, () => Buffer, RegExp][] = [
    ['a file added', () => rebuild(valid, (e) => [...e, { name: 'avenant.pdf', content: Buffer.from('%PDF') }]), /"avenant.pdf" is in the container but not sealed/],
    ['a file added in a directory', () => rebuild(valid, (e) => [...e, { name: 'annexes/b.pdf', content: Buffer.from('%PDF') }]), /"annexes\/b.pdf" is in the container but not sealed/],
    ['a file replaced', () => rebuild(valid, (e) => e.map((x) => (x.name === 'contrat final.pdf' ? { ...x, content: Buffer.from('%PDF-forged\n') } : x))), /"contrat final.pdf" has been altered/],
    ['a file renamed', () => rebuild(valid, (e) => e.map((x) => (x.name === 'contrat final.pdf' ? { ...x, name: 'contrat.pdf' } : x))), /points at no file of the container: "contrat%20final.pdf"/],
    ['a file removed', () => rebuild(valid, (e) => e.filter((x) => x.name !== "notes d'été.md")), /points at no file of the container/],
    ['the manifest removed', () => rebuild(valid, (e) => e.filter((x) => x.name !== 'META-INF/manifest.xml')), /no META-INF\/manifest.xml/],
    ['the manifest replaced by another document', () => rebuild(valid, (e) => e.map((x) => (x.name === 'META-INF/manifest.xml' ? { ...x, content: Buffer.from('<x/>') } : x))), /not an ODF manifest/],
    ['another mimetype', () => rebuild(valid, (e) => e.map((x) => (x.name === 'mimetype' ? { ...x, content: Buffer.from('application/vnd.etsi.asic-s+zip') } : x))), /not an ASiC-E container/],
    ['the mimetype compressed', () => rebuild(valid, (e) => e.map((x) => (x.name === 'mimetype' ? { ...x, stored: false } : x))), /mimetype file must be the first entry, stored/],
    ['the mimetype not first', () => rebuild(valid, (e) => [...e.slice(1), e[0] as { name: string; content: Buffer }]), /mimetype file must be the first entry/],
    ['a second signature file', () => rebuild(valid, (e) => [...e, { name: 'META-INF/signatures002.xml', content: e.find((x) => x.name === SIGNATURE)?.content as Buffer }]), /several signature files/],
    ['a time-stamp file (ASiC with CAdES)', () => rebuild(valid, (e) => [...e, { name: 'META-INF/timestamp.tst', content: Buffer.from('x') }]), /Unsupported file in META-INF/],
    ['no signature file', () => rebuild(valid, (e) => e.filter((x) => x.name !== SIGNATURE)), /no signature file/],
    ['not a ZIP archive', () => Buffer.from('not a zip'), /not a valid ZIP archive/],
  ];
  for (const [name, make, message] of cases) {
    test(name, () => {
      assert.match(error(make()) ?? 'valid', message);
    });
  }

  test('a container beyond the limits', () => {
    assert.match(error(valid, { limits: { maxEntries: 3, maxTotalSize: 1_000_000 } }) ?? 'valid', /more than 3 entries/);
  });
});

describe('attacks on the signature', () => {
  const valid = seal();
  const xml = readZip(valid).find((e: ZipEntry) => e.name === SIGNATURE)?.content.toString('utf8') as string;
  const id = /<ds:Signature [^>]*Id="([^"]+)"/.exec(xml)?.[1] as string;
  const digestOf = (content: string) => createHash('sha256').update(content).digest('base64');

  const cases: [string, (xml: string) => string, RegExp][] = [
    ['the signing time changed', (x) => x.replace(/<xades:SigningTime>[^<]+</, '<xades:SigningTime>2020-01-01T00:00:00Z<'), /signed properties have been altered/],
    ['a media type changed', (x) => x.replace('<xades:MimeType>application/pdf<', '<xades:MimeType>text/html<'), /signed properties have been altered/],
    ['the signature value changed', (x) => x.replace(/<ds:SignatureValue([^>]*)>(.)/, (_m, attrs, c) => `<ds:SignatureValue${attrs}>${c === 'A' ? 'B' : 'A'}`), /signature value is not valid/],
    ['the signing certificate swapped in KeyInfo', (x) => x.replace(/<ds:X509Certificate>[^<]+</, `<ds:X509Certificate>${readFileSync(`${CERTS}/p256.cert.pem`, 'utf8').replace(/-----[^-]+-----|\s/g, '')}<`), /signing certificate \(SigningCertificateV2\) is not in KeyInfo/],
    ['a duplicate Id', (x) => x.replace(`Id="${id}-SV"`, `Id="${id}-SP"`), /Two elements have the Id/],
    ['a transform on a file reference', (x) => x.replace(/(URI="contrat%20final.pdf">)/, '$1<ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#base64"/></ds:Transforms>'), /must have no transform/],
    ['a reference outside the container', (x) => x.replace('URI="contrat%20final.pdf"', 'URI="https://example.com/contrat.pdf"'), /relative URI inside the container/],
    ['a reference with a fragment', (x) => x.replace('URI="contrat%20final.pdf"', 'URI="contrat%20final.pdf#page=1"'), /relative URI inside the container/],
    ['a reference that climbs out of the container', (x) => x.replace('URI="contrat%20final.pdf"', 'URI="../contrat%20final.pdf"'), /points at no file/],
    ['a reference to META-INF', (x) => x.replace('URI="contrat%20final.pdf"', 'URI="META-INF/manifest.xml"'), /points at no file/],
    ['two references to the same file', (x) => x.replace(/(<ds:Reference Id="[^"]+-R1"[^>]*>.*?<\/ds:Reference>)/, (r) => r + r.replace(/ Id="[^"]+"/, '')), /Two references point at the same file/],
    ['a DataObjectFormat removed', (x) => x.replace(/<xades:DataObjectFormat ObjectReference="#[^"]+-R2">.*?<\/xades:DataObjectFormat>/, ''), /has no DataObjectFormat/],
    ['empty unsigned properties', (x) => x.replace('</xades:SignedProperties>', '</xades:SignedProperties><xades:UnsignedProperties/>'), /Missing xades:UnsignedSignatureProperties/],
    ['a signature policy', (x) => x.replace('</xades:SigningCertificateV2>', '</xades:SigningCertificateV2><xades:SignaturePolicyIdentifier/>'), /Unexpected or misplaced element xades:SignaturePolicyIdentifier/],
    ['SigningCertificate version 1', (x) => x.replace('xades:SigningCertificateV2>', 'xades:SigningCertificate>').replace('xades:SigningCertificateV2>', 'xades:SigningCertificate>'), /Unexpected or misplaced element xades:SigningCertificate in/],
    ['a second ds:Object', (x) => x.replace('</ds:Signature>', '<ds:Object Id="extra"/></ds:Signature>'), /Too many ds:Object/],
    ['a second signature', (x) => x.replace('</asic:XAdESSignatures>', `${/<ds:Signature [\s\S]*<\/ds:Signature>/.exec(x)?.[0].replaceAll(id, 'other')}</asic:XAdESSignatures>`), /one ds:Signature/],
    ['a wrong Target', (x) => x.replace(`Target="#${id}"`, 'Target="#other"'), /Target of QualifyingProperties/],
    ['SHA-1 digests', (x) => x.replace('http://www.w3.org/2001/04/xmlenc#sha256', 'http://www.w3.org/2000/09/xmldsig#sha1'), /Unsupported digest algorithm/],
    ['RSA-SHA1', (x) => x.replace(alg.RSA_PSS_SHA256, 'http://www.w3.org/2000/09/xmldsig#rsa-sha1'), /Unsupported signature algorithm/],
    ['ECDSA announced on an RSA key', (x) => x.replace(alg.RSA_PSS_SHA256, alg.ECDSA_SHA256), /does not suit the key/],
    ['inclusive canonicalization with comments', (x) => x.replace(`<ds:CanonicalizationMethod Algorithm="${alg.EXC_C14N}"/>`, '<ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"/>'), /Unsupported canonicalization/],
    ['text in SignedInfo', (x) => x.replace('<ds:SignedInfo>', '<ds:SignedInfo>text'), /Unexpected text in ds:SignedInfo/],
    ['a comment in SignedInfo', (x) => x.replace('<ds:SignedInfo>', '<ds:SignedInfo><!--c-->'), /Unexpected #comment in ds:SignedInfo/],
    ['a document type declaration', (x) => x.replace('?>', '?><!DOCTYPE x [<!ENTITY e "e">]>'), /document type declaration/],
    ['another root', (x) => x.replace(/asic:XAdESSignatures/g, 'asic:Signatures'), /root of the signature file must be asic:XAdESSignatures/],
    ['an invalid signing time', (x) => x.replace(/<xades:SigningTime>[^<]+</, '<xades:SigningTime>yesterday<'), /SigningTime is not a date/],
  ];
  for (const [name, change, message] of cases) {
    test(name, () => {
      assert.match(error(editSignature(valid, change)) ?? 'valid', message);
    });
  }

  test('a file replaced, and its digest in SignedInfo with it', () => {
    const forged = rebuild(
      editSignature(valid, (x) => x.replace(/(URI="contrat%20final.pdf">.*?<ds:DigestValue>)[^<]+/, `$1${digestOf('forged')}`)),
      (entries) => entries.map((e) => (e.name === 'contrat final.pdf' ? { ...e, content: Buffer.from('forged') } : e)),
    );
    assert.match(error(forged) ?? 'valid', /signature value is not valid/);
  });
});

describe('misuses throw', () => {
  const valid = seal();
  test('no CA certificate', () => {
    assert.throws(() => verifySeal(valid, {} as VerifyOptions), /'caCertPath' is required/);
    assert.throws(() => verifySeal(valid, { caCertPath: [] }), /'caCertPath' is required/);
  });

  test('a CA certificate file that cannot be read', () => {
    assert.throws(() => verifySeal(valid, { caCertPath: `${CERTS}/missing.pem` }), /cannot read the certificate file .*'caCertPath'/);
  });

  test('a container that is not bytes', () => {
    assert.throws(() => verifySeal('seal' as unknown as Uint8Array, { caCertPath: ROOT }), /must be bytes/);
  });

  test('invalid options', () => {
    assert.throws(() => verifySeal(valid, { caCertPath: ROOT, revocation: 'no' as unknown as boolean }), /'revocation'/);
    assert.throws(() => verifySeal(valid, { caCertPath: ROOT, expectedSubject: '' }), /'expectedSubject'/);
  });
});
