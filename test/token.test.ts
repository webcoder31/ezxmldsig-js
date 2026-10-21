/**
 * Signed tokens: creation and analysis, the cases of the tests of the PHP
 * library on signed tokens (XMLDSigTokenTest, SignatureWrappingTest,
 * CanonicalizationGuardTest, SignatureVerificationResultTest, TokenIdTest,
 * AudienceAndExpiryTest, and the cases of XMLParsingTest, OptionsTest and
 * TrustAnchorTest that need a token). Every analysis is also compared with
 * the analysis of the PHP library (see compareWithPhp()).
 */

import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { describe, test } from 'node:test';

import { XMLDSigToken } from '../dist/index.js';
import { canonicalize } from '../dist/c14n.js';
import { loadXML } from '../dist/xml.js';
import { runPhp } from './helpers/php.ts';
import {
  ANCHOR,
  CERTS,
  DEMO,
  DSIG_NS,
  INTERMEDIATE_DN,
  SIGN_KEY_PASSWORD,
  TRUST,
  alter,
  analyze,
  compareWithPhp,
  createToken,
  forge,
  node,
  sampleData,
  setChild,
  signAgain,
  trustAnchor,
  utc,
} from './helpers/token.ts';

const RSA_1_5 = 'http://www.w3.org/2001/04/xmlenc#rsa-1_5';

/** The algorithms a token declares. */
function algorithmsOf(xml: string) {
  const doc = loadXML(xml, 'token');
  const read = (query: string) => node(doc, query).getAttribute('Algorithm');
  return {
    canonicalization: read('/ds:Signature/ds:SignedInfo/ds:CanonicalizationMethod'),
    signature: read('/ds:Signature/ds:SignedInfo/ds:SignatureMethod'),
    digest: read('/ds:Signature/ds:SignedInfo/ds:Reference/ds:DigestMethod'),
  };
}

function assertValid(token: XMLDSigToken): void {
  assert.equal(token.getError(), null);
  assert.equal(token.isSignatureValid(), true);
}

describe('creation and analysis', () => {
  test('creates a signed token', () => {
    const token = createToken();
    assertValid(token);
    assert.equal(token.isDataEncrypted(), false);
    assert.ok(token.getXML()?.includes('<ds:Signature'));
    assert.ok(token.getXML()?.includes('Id="Token"'));
  });

  test('analyzes a signed token', () => {
    const token = analyze('signed token', { xml: createToken().getXML() as string, options: trustAnchor() });
    assertValid(token);
    assert.deepEqual(token.getAnomalies(), []);
    assert.equal(token.isDigestValueOk(), true);
    assert.equal(token.isSignatureValueOk(), true);
    assert.equal(token.isDataEncrypted(), false);
    assert.deepEqual(token.getData(), sampleData());
  });

  test('round trips nested data', () => {
    const data = { user: { name: 'Lagertha', roles: { shieldmaiden: 'yes', earl: 'Hedeby' } }, location: 'Kattegat' };
    const token = analyze('nested data', { xml: createToken(data).getXML() as string, options: trustAnchor() });
    assertValid(token);
    assert.deepEqual(token.getData(), data);
  });

  test('writes values as the PHP library does, and reads them back as strings', () => {
    const data = { text: 'x & < > " \' é €', number: 42, decimal: 1.5, yes: true, no: false, nothing: null, empty: '', bytes: Buffer.from('bytes') };
    const token = analyze('values', { xml: createToken(data).getXML() as string, options: trustAnchor() });
    assertValid(token);
    // Empty values (false, null, '') are written as empty elements, which
    // are not read back, as with the PHP library.
    assert.deepEqual(token.getData(), { text: 'x & < > " \' é €', number: '42', decimal: '1.5', yes: '1', bytes: 'bytes' });
  });

  test('reads base64 values that are not UTF-8 text as bytes', () => {
    const bytes = Buffer.from([0xff, 0x00, 0xc3]);
    const token = analyze('bytes', { xml: createToken({ bytes }).getXML() as string, options: trustAnchor() });
    assertValid(token);
    assert.deepEqual(token.getData(), { bytes });
  });

  test('reads a value named __proto__ as a value', () => {
    const token = analyze('__proto__', { xml: createToken(JSON.parse('{"__proto__": "x", "a": "b"}')).getXML() as string, options: trustAnchor() });
    assertValid(token);
    const data = token.getData() as Record<string, unknown>;
    assert.equal(Object.getPrototypeOf(data), Object.prototype);
    assert.equal(Object.getOwnPropertyDescriptor(data, '__proto__')?.value, 'x');
  });

  test('timestamps the token', () => {
    const before = Math.floor(Date.now() / 1000);
    const xml = createToken().getXML() as string;
    const after = Math.floor(Date.now() / 1000);
    const token = analyze('timestamp', { xml, options: trustAnchor(), ttl: 120 });
    const timestamp = Date.parse(token.getTimestamp() as string) / 1000;
    assert.match(token.getTimestamp() as string, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/);
    assert.ok(timestamp >= before - 1 && timestamp <= after + 1);
    assert.equal(token.isOutOfDate(120), false);
  });

  test('exposes the signing certificate', () => {
    const token = analyze('certificate', { xml: createToken().getXML() as string, options: trustAnchor() });
    assert.equal(token.isCertOutOfDate(), false);
    assert.equal(token.getCertSubject()?.['OU'], 'Signature Dept');
    assert.deepEqual(token.getCertIssuer(), INTERMEDIATE_DN);
    assert.equal(token.isValidCertIssuer(INTERMEDIATE_DN), true);
    assert.equal(token.isValidCertCA(`${CERTS}/intermediate.cert.pem`), true);
    assert.equal(token.isValidCertCA(`${CERTS}/root.cert.pem`), false);
    assert.equal(token.getCertificate()?.startsWith('-----BEGIN CERTIFICATE-----'), true);
  });

  test('writes the token as the PHP library does', () => {
    const [php] = runPhp([{ command: 'create', data: sampleData(), signKey: `${CERTS}/sign.key.pem`, signCert: `${CERTS}/sign.cert.pem`, signKeyPassword: SIGN_KEY_PASSWORD, options: { audience: 'crm', validity: 60 } }]);
    const ours = createToken(sampleData(), { audience: 'crm', validity: 60 }).getXML() as string;
    // The same bytes, but for the values that differ from a token to another.
    const skeleton = (xml: string) => xml
      .replace(/<(ds:)?(DigestValue|SignatureValue|TokenTimestamp|TokenId|TokenExpiry)>[^<]*</g, '<$1$2>…<');
    assert.equal(skeleton(ours), skeleton(php?.['xml'] as string));
    for (const prefix of ['', 'sig']) {
      const [other] = runPhp([{ command: 'create', data: { a: 'b' }, signKey: `${CERTS}/sign.key.pem`, signCert: `${CERTS}/sign.cert.pem`, signKeyPassword: SIGN_KEY_PASSWORD, options: { xmldsigNsPrefix: prefix, base64Encode: false } }]);
      const mine = createToken({ a: 'b' }, { xmldsigNsPrefix: prefix, base64Encode: false }).getXML() as string;
      const generic = (xml: string) => skeleton(xml).replace(/<((?:sig:)?)(DigestValue|SignatureValue)>[^<]*</g, '<$1$2>…<');
      assert.equal(generic(mine), generic(other?.['xml'] as string), `prefix '${prefix}'`);
    }
  });
});

describe('XML parsing of a token', () => {
  const DOCTYPE_ERROR = 'XML Digital Signature must not have a document type declaration (DOCTYPE)!';

  function withDoctype(internalSubset: string): string {
    return (createToken().getXML() as string).replace(/^(<\?xml[^>]*\?>\s*)/, `$1<!DOCTYPE ds:Signature [${internalSubset}]>\n`);
  }

  test('the document type declaration is the only change', () => {
    const xml = withDoctype('');
    assert.ok(xml.includes('<!DOCTYPE ds:Signature []>'));
    assertValid(analyze('without doctype', { xml: xml.replace('<!DOCTYPE ds:Signature []>\n', ''), options: trustAnchor() }));
  });

  for (const [name, internalSubset] of Object.entries({
    'empty': '',
    'internal entity': '<!ENTITY e "expanded">',
    'external entity': '<!ENTITY e SYSTEM "file:///etc/passwd">',
  })) {
    test(`a token with a document type declaration is refused: ${name}`, () => {
      const token = analyze(`doctype ${name}`, { xml: withDoctype(internalSubset), options: trustAnchor() });
      assert.equal(token.isSignatureValid(), false);
      assert.equal(token.getError(), DOCTYPE_ERROR);
      assert.equal(token.getData(), null);
      assert.equal(token.getCertificate(), null);
    });
  }

  test('a declared UTF-8 encoding, with a byte order mark, is accepted', () => {
    const xml = (createToken().getXML() as string).replace(/^<\?xml[^>]*\?>/, '\uFEFF<?xml version="1.0" encoding="utf-8"?>');
    assertValid(analyze('BOM', { xml, options: trustAnchor() }));
    assertValid(XMLDSigToken.analyzeXMLToken(Buffer.from(xml), trustAnchor()));
  });

  test('whitespace is preserved', () => {
    const data = { indented: '\n  ', name: 'Ragnar' };
    const created = createToken(data, { base64Encode: false });
    assertValid(created);
    const token = analyze('whitespace', { xml: created.getXML() as string, options: trustAnchor() });
    assertValid(token);
    assert.deepEqual(token.getData(), data);
  });

  test('an invalid document is refused', () => {
    for (const xml of ['', 'not XML', '<a>', '<a/><b/>']) {
      assert.equal(analyze(`invalid ${JSON.stringify(xml)}`, { xml, options: trustAnchor() }).getError(), 'XML Digital Signature is not a valid XML document!');
    }
  });
});

describe('options', () => {
  test('a token created without options is signed with RSA-SHA256, SHA-256 and inclusive C14N', () => {
    assert.deepEqual(algorithmsOf(createToken().getXML() as string), {
      canonicalization: XMLDSigToken.C14N,
      signature: XMLDSigToken.RSA_SHA256,
      digest: XMLDSigToken.SHA256,
    });
  });

  test('createXMLToken() applies its options', () => {
    const token = createToken(sampleData(), {
      signatureAlgorithm: XMLDSigToken.RSA_SHA512,
      digestAlgorithm: XMLDSigToken.SHA512,
      canonicalizationAlgorithm: XMLDSigToken.EXC_C14N,
      base64Encode: false,
      xmldsigNsPrefix: 'sig',
    });
    assertValid(token);
    const xml = token.getXML() as string;
    assert.ok(xml.includes('<sig:Signature'));
    assert.ok(xml.includes('<name>Ragnar Lothbrok</name>'));
    assert.deepEqual(algorithmsOf(xml), { canonicalization: XMLDSigToken.EXC_C14N, signature: XMLDSigToken.RSA_SHA512, digest: XMLDSigToken.SHA512 });
  });

  for (const c14n of [XMLDSigToken.C14N, XMLDSigToken.C14N_COMMENTS, XMLDSigToken.EXC_C14N, XMLDSigToken.EXC_C14N_COMMENTS]) {
    for (const digest of [XMLDSigToken.SHA1, XMLDSigToken.SHA256, XMLDSigToken.SHA384, XMLDSigToken.SHA512, XMLDSigToken.RIPEMD160]) {
      for (const signature of [XMLDSigToken.RSA_SHA1, XMLDSigToken.RSA_SHA256, XMLDSigToken.RSA_SHA384, XMLDSigToken.RSA_SHA512]) {
        const options = { canonicalizationAlgorithm: c14n, digestAlgorithm: digest, signatureAlgorithm: signature };
        test(`algorithms ${[c14n, digest, signature].map((uri) => uri.split(/[#/]/).pop()).join(', ')}`, () => {
          const token = analyze(`algorithms ${c14n} ${digest} ${signature}`, { xml: createToken(sampleData(), options).getXML() as string, options: trustAnchor(options) });
          assertValid(token);
        });
      }
    }
  }

  test('a token signed with RSA-SHA1 is rejected by default', () => {
    const xml = createToken(sampleData(), { signatureAlgorithm: XMLDSigToken.RSA_SHA1, digestAlgorithm: XMLDSigToken.SHA1 }).getXML() as string;
    const token = analyze('RSA-SHA1 by default', { xml, options: trustAnchor() });
    assert.equal(token.isSignatureValid(), false);
    assert.ok(token.getError()?.includes('Unauthorized Signature algorithm!'));
    assert.ok(token.getError()?.includes('Unauthorized Digest algorithm!'));
  });

  test('a token signed with RSA-SHA1 is accepted when expected, or unchecked', () => {
    const xml = createToken(sampleData(), { signatureAlgorithm: XMLDSigToken.RSA_SHA1, digestAlgorithm: XMLDSigToken.SHA1 }).getXML() as string;
    const expected = analyze('RSA-SHA1 expected', { xml, options: trustAnchor({ signatureAlgorithm: XMLDSigToken.RSA_SHA1, digestAlgorithm: XMLDSigToken.SHA1 }) });
    assertValid(expected);
    assert.deepEqual(expected.getData(), sampleData());
    assertValid(analyze('RSA-SHA1 unchecked', { xml, options: trustAnchor({ checkSigningAlgorithms: false }) }));
  });

  for (const algorithm of [RSA_1_5, XMLDSigToken.RSA_OAEP_MGF1P]) {
    test(`a key transport algorithm is refused as signature algorithm: ${algorithm.split('#').pop()}`, () => {
      assert.throws(() => createToken(sampleData(), { signatureAlgorithm: algorithm }), { message: /^Invalid parameter 'signatureAlgorithm'!/ });
      assert.throws(() => XMLDSigToken.analyzeXMLToken('not an XML token', trustAnchor({ signatureAlgorithm: algorithm })), { message: /^Invalid parameter 'signatureAlgorithm'!/ });
      const xml = alter(createToken().getXML() as string, (doc) => node(doc, '/ds:Signature/ds:SignedInfo/ds:SignatureMethod').setAttribute('Algorithm', algorithm));
      const token = analyze(`key transport ${algorithm} as signature`, { xml, options: trustAnchor({ checkSigningAlgorithms: false }) });
      assert.equal(token.isSignatureValid(), false);
      assert.equal(token.getError(), 'Signature algorithm is invalid!');
    });
  }

  test('an unknown option is refused', () => {
    assert.throws(() => createToken(sampleData(), { digestAlgoritm: XMLDSigToken.SHA512 } as never), { message: "Unknown option 'digestAlgoritm'!" });
    assert.throws(() => XMLDSigToken.analyzeXMLToken('not an XML token', trustAnchor({ digestAlgoritm: XMLDSigToken.SHA512 } as never)), { message: "Unknown option 'digestAlgoritm'!" });
  });

  test('an option out of its context is refused', () => {
    assert.throws(() => createToken(sampleData(), { caCertPath: ANCHOR }), { message: /^Option 'caCertPath' only applies to token analysis!/ });
    assert.throws(() => createToken(sampleData(), { sessionKeyCipheringAlgorithm: XMLDSigToken.AES256_CBC }), { message: /^Option 'sessionKeyCipheringAlgorithm' only applies to an encrypted token!/ });
    assert.throws(() => XMLDSigToken.analyzeXMLToken('not an XML token', trustAnchor({ base64Encode: false })), { message: "Option 'base64Encode' only applies to token creation!" });
    assert.throws(() => XMLDSigToken.analyzeXMLToken('not an XML token', trustAnchor({ checkCryptingAlgorithms: false })), { message: /^Option 'checkCryptingAlgorithms' only applies to the analysis of an encrypted token!/ });
  });

  test('an invalid option value is refused', () => {
    assert.throws(() => createToken(sampleData(), { base64Encode: 'no' as never }), { message: "Invalid option 'base64Encode'! It must be a boolean." });
    assert.throws(() => createToken(sampleData(), { xmldsigNsPrefix: false as never }), { message: "Invalid option 'xmldsigNsPrefix'! It must be a string." });
    assert.throws(() => createToken(sampleData(), { signatureAlgorithm: null as never }), { message: "Invalid option 'signatureAlgorithm'! Its value must not be null or undefined." });
    assert.throws(() => createToken(sampleData(), { signatureAlgorithm: true as never }), { message: /^Invalid parameter 'signatureAlgorithm'!/ });
  });
});

describe('parameters of createXMLToken()', () => {
  test('the data must be named values', () => {
    for (const data of [null, 'data', [], ['a'], Buffer.from('x'), 1]) {
      assert.throws(() => createToken(data as never), { message: "Invalid parameter 'data'! Token data should be an object of named values." }, String(data));
    }
    assert.throws(() => createToken({}), { message: "Invalid parameter 'data'! Token data should not be an empty object." });
    for (const data of [{ a: undefined }, { a: () => 1 }, { a: new Date() }, { a: Number.NaN }, { a: 1n }, { a: { b: Symbol('x') } }, { a: '\uD800' }]) {
      assert.throws(() => createToken(data as never), { message: /^Invalid parameter 'data'!/ }, String(Object.values(data)[0]));
    }
  });

  test('a name that is not an XML name gives an error', () => {
    for (const data of [{ '1a': 'x' }, { 'a b': 'x' }, { a: { '': 'x' } }, { list: ['a', 'b'] }]) {
      const token = createToken(data as never);
      assert.equal(token.isSignatureValid(), false);
      assert.equal(token.getError(), 'Invalid Character Error', JSON.stringify(data));
    }
  });

  test('the key and the certificate are required, by path or by content', () => {
    const key = readFileSync(`${CERTS}/sign.key.pem`, 'utf8');
    const cert = readFileSync(`${CERTS}/sign.cert.pem`);
    assertValid(XMLDSigToken.createXMLToken(sampleData(), key, cert, SIGN_KEY_PASSWORD));
    assert.throws(() => XMLDSigToken.createXMLToken(sampleData(), null as never, `${CERTS}/sign.cert.pem`), { message: /^Missing parameter 'signKeyPath'!/ });
    assert.throws(() => XMLDSigToken.createXMLToken(sampleData(), key, null as never), { message: /^Missing parameter 'signCertPath'!/ });
    assert.throws(() => XMLDSigToken.createXMLToken(sampleData(), `${CERTS}/missing.pem`, cert), { message: "Invalid parameter 'signKeyPath'! Cannot read private key to sign token." });
    assert.throws(() => XMLDSigToken.createXMLToken(sampleData(), key, `${CERTS}/missing.pem`), { message: "Invalid parameter 'signCertPath'! Cannot read X.509 certificate to sign token." });
    assert.throws(() => XMLDSigToken.createXMLToken(sampleData(), key, cert, 1 as never), { message: "Invalid parameter 'signKeyPassword'! Parameter must be a string." });
  });

  test('a key that cannot be loaded, or that is not the key of the certificate, gives an error', () => {
    assert.equal(XMLDSigToken.createXMLToken(sampleData(), `${CERTS}/sign.key.pem`, `${CERTS}/sign.cert.pem`, 'wrong').getError(), 'Failed loading private key to sign token data!');
    assert.equal(XMLDSigToken.createXMLToken(sampleData(), `${CERTS}/sign.key.pem`, `${CERTS}/sign.cert.pem`).getError(), 'Failed loading private key to sign token data!');
    assert.equal(XMLDSigToken.createXMLToken(sampleData(), `${CERTS}/crypt.key.pem`, `${CERTS}/sign.cert.pem`).getError(), '1 anomaly detected: Token hash signature verification failed!');
  });

  test('a certificate that does not allow signing gives an error', () => {
    assert.equal(XMLDSigToken.createXMLToken(sampleData(), `${CERTS}/crypt.key.pem`, `${CERTS}/crypt.cert.pem`).getError(), 'Signing certificate is not allowed to sign (key usage)!');
  });
});

describe('signature wrapping', () => {
  const FORGED_DATA = { name: 'Forged', role: 'Forged', location: 'Forged' };

  /** Replaces the content of a node "ds:Object" with a token holding the
  forged data and the given timestamp. */
  function forgeObjectContent(object: ReturnType<typeof node>, timestamp: string): void {
    const doc = object.ownerDocument as NonNullable<typeof object.ownerDocument>;
    while (object.firstChild !== null) {
      object.removeChild(object.firstChild);
    }
    const token = object.appendChild(doc.createElement('Token'));
    token.appendChild(doc.createElement('TokenTimestamp')).appendChild(doc.createTextNode(timestamp));
    const tokenData = token.appendChild(doc.createElement('TokenData'));
    for (const [name, value] of Object.entries(FORGED_DATA)) {
      const leaf = doc.createElement(name);
      leaf.setAttribute('Algorithm', 'base64');
      leaf.appendChild(doc.createTextNode(Buffer.from(value).toString('base64')));
      tokenData.appendChild(leaf);
    }
  }

  function assertNotForged(token: XMLDSigToken, timestamp: string): void {
    assert.equal(token.isSignatureValid(), false);
    assert.notEqual(token.getError(), null);
    assert.equal(token.getData(), null);
    assert.notEqual(token.getTimestamp(), timestamp);
  }

  test('a signed ds:Object copied into ds:KeyInfo, the original forged, is rejected', () => {
    const timestamp = utc(20);
    const original = createToken().getXML() as string;
    const object = original.slice(original.indexOf('<ds:Object'), original.indexOf('</ds:Object>') + '</ds:Object>'.length);
    const wrapped = alter(original.replace('</ds:KeyInfo>', `${object}</ds:KeyInfo>`), (doc) => forgeObjectContent(node(doc, '/ds:Signature/ds:Object'), timestamp));
    assertNotForged(analyze('wrapping into KeyInfo', { xml: wrapped, options: trustAnchor() }), timestamp);
  });

  test('a signature that is not the document element is rejected', () => {
    const timestamp = utc(20);
    const xml = alter(createToken().getXML() as string, (doc) => {
      const signature = doc.documentElement as NonNullable<typeof doc.documentElement>;
      const object = node(doc, '/ds:Signature/ds:Object');
      const envelope = doc.createElement('Envelope');
      doc.replaceChild(envelope, signature);
      envelope.appendChild(object.cloneNode(true));
      envelope.appendChild(signature);
      forgeObjectContent(object, timestamp);
    });
    const token = analyze('signature not the document element', { xml, options: trustAnchor() });
    assertNotForged(token, timestamp);
    assert.notEqual(token.isDigestValueOk(), true);
  });

  test('a legitimate token wrapped in another element is rejected', () => {
    const xml = alter(createToken().getXML() as string, (doc) => {
      const signature = doc.documentElement as NonNullable<typeof doc.documentElement>;
      const envelope = doc.createElement('Envelope');
      doc.replaceChild(envelope, signature);
      envelope.appendChild(signature);
    });
    const token = analyze('wrapped legitimate token', { xml, options: trustAnchor() });
    assert.equal(token.isSignatureValid(), false);
    assert.equal(token.getData(), null);
    assert.ok(token.getError()?.includes('ds:Signature'));
  });

  test('a document with two elements Id="Token" is rejected', () => {
    const xml = alter(createToken().getXML() as string, (doc) => {
      const extra = doc.createElement('Extra');
      extra.setAttribute('Id', 'Token');
      extra.appendChild(doc.createTextNode('unsigned'));
      node(doc, '/ds:Signature').appendChild(extra);
    });
    const token = analyze('two Id=Token', { xml, options: trustAnchor() });
    assert.equal(token.isSignatureValid(), false);
    assert.equal(token.getData(), null);
    assert.ok(token.getError()?.includes('Id'));
  });

  test('a namespaced attribute Id="Token" counts as a second one', () => {
    const xml = alter(createToken().getXML() as string, (doc) => {
      node(doc, '/ds:Signature/ds:KeyInfo').setAttributeNS('urn:other', 'o:Id', 'Token');
    });
    assert.ok(analyze('namespaced Id=Token', { xml, options: trustAnchor() }).getError()?.includes('Exactly one element'));
  });
});

describe('canonicalization guard', () => {
  test('a canonicalization that fails throws, with the reason', () => {
    const doc = loadXML('<a><b/></a>', 'test');
    assert.throws(() => canonicalize(doc.documentElement as never, 'http://example.org/unknown', null, 'referenced node'), { message: /^Canonicalization of referenced node failed! Reason: / });
  });

  test('a reference whose transform selects nothing, with the digest of the empty string, is rejected', () => {
    // The data are forged, a second transform (XPath "false()") is added,
    // the digest is that of the empty string, and ds:SignedInfo is signed
    // again with the trusted key.
    const altered = alter(createToken().getXML() as string, (doc) => {
      const reference = node(doc, '/ds:Signature/ds:SignedInfo/ds:Reference');
      const transform = doc.createElementNS(DSIG_NS, 'ds:Transform');
      transform.setAttribute('Algorithm', 'http://www.w3.org/TR/1999/REC-xpath-19991116');
      transform.appendChild(doc.createElementNS(DSIG_NS, 'ds:XPath')).appendChild(doc.createTextNode('false()'));
      node(reference, 'ds:Transforms').appendChild(transform);
      for (const leaf of Array.from(node(doc, '/ds:Signature/ds:Object/Token/TokenData').childNodes)) {
        leaf.textContent = 'forged';
      }
      node(reference, 'ds:DigestValue').textContent = createHash('sha256').update('').digest('base64');
    });
    const [xml] = forge([{ xml: altered, steps: [{ op: 'resign', key: `${CERTS}/sign.key.pem`, password: SIGN_KEY_PASSWORD, cert: `${CERTS}/sign.cert.pem` }] }]);
    const token = analyze('empty canonicalization', { xml: xml as string, options: trustAnchor() });
    assert.equal(token.isSignatureValid(), false);
    assert.equal(token.getError(), 'XML digital signature is malformed!');
  });
});

describe('signature verification result', () => {
  const FORGED_DATA = { name: 'Forged' };

  /** Forges a token without any private key: the data are altered, the
  digest computed again, and the certificate replaced. */
  function forgeWith(certificate: string | null, signatureValue: string | null): string {
    const altered = alter(createToken().getXML() as string, (doc) => {
      const tokenData = node(doc, '/ds:Signature/ds:Object/Token/TokenData');
      while (tokenData.firstChild !== null) {
        tokenData.removeChild(tokenData.firstChild);
      }
      for (const [name, value] of Object.entries(FORGED_DATA)) {
        tokenData.appendChild(doc.createElement(name)).appendChild(doc.createTextNode(value));
      }
      if (signatureValue !== null) {
        node(doc, '/ds:Signature/ds:SignatureValue').textContent = signatureValue;
      }
    });
    return forge([{ xml: altered, steps: certificate === null ? [{ op: 'redigest' }] : [{ op: 'redigest' }, { op: 'replaceCertificate', cert: certificate }] }])[0] as string;
  }

  for (const [name, certificate, signatureValue] of [
    ['EC certificate', `${DEMO}/ec.cert.pem`, null],
    ['EC certificate, empty signature value', `${DEMO}/ec.cert.pem`, '='],
    ['DSA certificate', `${TRUST}/dsa.cert.pem`, null],
    ['signing certificate, random signature value', null, randomBytes(256).toString('base64')],
  ] as Array<[string, string | null, string | null]>) {
    test(`only a valid RSA signature is valid: ${name}`, () => {
      const token = analyze(`signature result: ${name}`, { xml: forgeWith(certificate, signatureValue), options: trustAnchor() });
      assert.equal(token.isDigestValueOk(), true);
      assert.equal(token.isSignatureValueOk(), false);
      assert.equal(token.isSignatureValid(), false);
      assert.notDeepEqual(token.getData(), FORGED_DATA);
    });
  }
});

test('a token signed with ECDSA under an RSA signature algorithm is refused', () => {
  // The PHP library 1.2.0 accepts it (EZXML-26): this case is not compared.
  const [created] = runPhp([{ command: 'create', data: sampleData(), signKey: `${TRUST}/ec-signer.key.pem`, signCert: `${TRUST}/ec-signer.cert.pem` }]);
  assert.equal(created?.['isSignatureValid'], true, 'The PHP library accepts it.');
  const token = XMLDSigToken.analyzeXMLToken(created?.['xml'] as string, { signerCertPath: `${TRUST}/ec-signer.cert.pem` });
  assert.equal(token.isDigestValueOk(), true);
  assert.equal(token.isSignatureValueOk(), false);
  assert.equal(token.getError(), '1 anomaly detected: Token hash signature verification failed!');
  assert.equal(
    XMLDSigToken.createXMLToken(sampleData(), `${TRUST}/ec-signer.key.pem`, `${TRUST}/ec-signer.cert.pem`).getError(),
    'The private key to sign token data is not an RSA key!',
  );
});

describe('token identifier', () => {
  const TOKEN_ID = '/ds:Signature/ds:Object/Token/TokenId';

  test('a created token has a random identifier, in the token', () => {
    const token = createToken();
    assertValid(token);
    assert.match(token.getTokenId() as string, /^[0-9a-f]{32}$/);
    assert.equal(node(loadXML(token.getXML(), 'token'), TOKEN_ID).textContent, token.getTokenId());
  });

  test('the analysis gives the identifier', () => {
    const xml = createToken().getXML() as string;
    const token = analyze('identifier', { xml, options: trustAnchor() });
    assertValid(token);
    assert.equal(token.getTokenId(), node(loadXML(xml, 'token'), TOKEN_ID).textContent);
  });

  test('identifiers are unique', () => {
    const ids = new Set(Array.from({ length: 20 }, () => createToken().getTokenId()));
    assert.equal(ids.size, 20);
  });

  test('an altered identifier invalidates the token', () => {
    const xml = alter(createToken().getXML() as string, (doc) => {
      node(doc, TOKEN_ID).textContent = '0'.repeat(32);
    });
    const token = analyze('altered identifier', { xml, options: trustAnchor() });
    assert.equal(token.isSignatureValid(), false);
    assert.equal(token.isDigestValueOk(), false);
    assert.ok(token.getError()?.includes('Token hash verification failed!'));
    assert.equal(token.getTokenId(), null);
  });

  test('a token without identifier is rejected', () => {
    const xml = signAgain(createToken().getXML() as string, (_doc, token) => {
      token?.removeChild(Array.from(token.childNodes).find((child) => child.nodeName === 'TokenId') as never);
    });
    const token = analyze('no identifier', { xml, options: trustAnchor() });
    assert.equal(token.isSignatureValueOk(), true);
    assert.equal(token.isCertTrusted(), true);
    assert.equal(token.isSignatureValid(), false);
    assert.equal(token.getError(), '1 anomaly detected: Token identifier is missing!');
    assert.equal(token.getTokenId(), null);
  });

  for (const [name, change] of Object.entries({
    'too short': (id: ReturnType<typeof node>) => { id.textContent = 'a'.repeat(31); },
    'too long': (id: ReturnType<typeof node>) => { id.textContent = 'a'.repeat(33); },
    'upper case': (id: ReturnType<typeof node>) => { id.textContent = 'A'.repeat(32); },
    'not hexadecimal': (id: ReturnType<typeof node>) => { id.textContent = 'g'.repeat(32); },
    'empty': (id: ReturnType<typeof node>) => { id.textContent = ''; },
    'element': (id: ReturnType<typeof node>) => {
      id.textContent = '';
      id.appendChild(id.ownerDocument?.createElement('x') as never).appendChild(id.ownerDocument?.createTextNode('a'.repeat(32)) as never);
    },
    'twice': (id: ReturnType<typeof node>) => { id.parentNode?.appendChild(id.cloneNode(true)); },
  })) {
    test(`a malformed identifier is rejected: ${name}`, () => {
      const xml = signAgain(createToken().getXML() as string, (doc) => change(node(doc, TOKEN_ID)));
      const token = analyze(`malformed identifier ${name}`, { xml, options: trustAnchor() });
      assert.equal(token.isSignatureValueOk(), true);
      assert.equal(token.isCertTrusted(), true);
      assert.equal(token.isSignatureValid(), false);
      assert.equal(token.getError(), '1 anomaly detected: Token identifier is malformed!');
      assert.equal(token.getTokenId(), null);
    });
  }

  test('a token with another anomaly gives no identifier', () => {
    const xml = signAgain(createToken().getXML() as string, (_doc, token) => setChild(token as never, 'TokenTimestamp', 'yesterday'));
    const token = analyze('timestamp yesterday', { xml, options: trustAnchor() });
    assert.equal(token.isCertTrusted(), true);
    assert.equal(token.getError(), '1 anomaly detected: Token timestamp format is invalid!');
    assert.equal(token.getTokenId(), null);
  });

  test('an untrusted token gives no identifier', () => {
    const token = analyze('untrusted', { xml: createToken().getXML() as string, options: { signerCertPath: `${CERTS}/crypt.cert.pem` } });
    assert.equal(token.isSignatureValid(), false);
    assert.equal(token.isDigestValueOk(), true);
    assert.equal(token.getTokenId(), null);
  });
});

describe('timestamp', () => {
  // The PHP library reads the timestamp with DateTime::createFromFormat(),
  // which accepts more than the format it writes.
  for (const [value, valid] of [
    ['2026-1-01T00:00:00Z', true],
    ['26-01-01T00:00:00Z', true],
    ['2026-02-30T00:00:00Z', true],
    ['2026-01-01T24:00:00Z', true],
    ['2026-01-05T1:00:00Z', true],
    ['2026-01-05T01:2:00Z', false],
    ['2026-01-01T00:00:00.5Z', false],
    ['2026-01-01T00:00:00+00:00', false],
    [' 2026-01-01T00:00:00Z', false],
  ] as Array<[string, boolean]>) {
    test(`a timestamp ${JSON.stringify(value)} is ${valid ? 'read' : 'refused'}`, () => {
      const xml = signAgain(createToken().getXML() as string, (_doc, token) => setChild(token as never, 'TokenTimestamp', value));
      const token = analyze(`timestamp ${value}`, { xml, options: trustAnchor(), ttl: 10 ** 12 });
      assert.equal(token.isSignatureValid(), valid, token.getError() ?? '');
    });
  }
});

describe('audience', () => {
  test('a created token names its audiences in the signed token', () => {
    const token = createToken(sampleData(), { audience: ['mail', 'crm'] });
    assertValid(token);
    assert.deepEqual(token.getAudience(), ['mail', 'crm']);
    const doc = loadXML(token.getXML(), 'token');
    assert.equal(node(doc, '/ds:Signature/ds:Object/Token/TokenAudience').textContent, 'mail');
  });

  test('a token is accepted by each audience it names', () => {
    const xml = createToken(sampleData(), { audience: ['mail', 'crm'] }).getXML() as string;
    for (const audience of ['mail', 'crm']) {
      const token = analyze(`audience ${audience}`, { xml, options: trustAnchor({ expectedAudience: audience }) });
      assertValid(token);
      assert.deepEqual(token.getAudience(), ['mail', 'crm']);
      assert.deepEqual(token.getData(), sampleData());
    }
  });

  test('a token is rejected by another audience', () => {
    const xml = createToken(sampleData(), { audience: 'mail' }).getXML() as string;
    const token = analyze('another audience', { xml, options: trustAnchor({ expectedAudience: 'crm' }) });
    assert.equal(token.isSignatureValid(), false);
    assert.equal(token.getError(), "Token is not addressed to the expected audience! Expected: 'crm'. Token audience: 'mail'.");
    assert.equal(token.getData(), null);
    assert.equal(token.getAudience(), null);
    assert.equal(token.getTokenId(), null);
    assert.equal(token.getTimestamp(), null);
  });

  test('the audience is compared as is', () => {
    const xml = createToken(sampleData(), { audience: 'Mail' }).getXML() as string;
    assert.equal(analyze('audience case', { xml, options: trustAnchor({ expectedAudience: 'mail' }) }).isSignatureValid(), false);
  });

  test('a token naming an audience is rejected without expected audience', () => {
    const xml = createToken(sampleData(), { audience: 'mail' }).getXML() as string;
    const token = analyze('no expected audience', { xml, options: trustAnchor() });
    assert.equal(token.getError(), "Token is addressed to an audience ('mail'), but the option 'expectedAudience' is not given: pass the audience of this receiver to accept it!");
    assert.equal(token.getData(), null);
  });

  test('a token without audience is rejected when an audience is expected, accepted otherwise', () => {
    const xml = createToken().getXML() as string;
    assert.equal(analyze('audience expected', { xml, options: trustAnchor({ expectedAudience: 'mail' }) }).getError(), "Token is not addressed to any audience, but the audience 'mail' is expected!");
    const token = analyze('no audience', { xml, options: trustAnchor() });
    assertValid(token);
    assert.equal(token.getAudience(), null);
  });

  test('an audience keeps its characters', () => {
    const audience = 'https://crm.example.com/sso?a=1&b=<2> "é€"';
    const token = analyze('audience characters', { xml: createToken(sampleData(), { audience }).getXML() as string, options: trustAnchor({ expectedAudience: audience }) });
    assertValid(token);
    assert.deepEqual(token.getAudience(), [audience]);
  });

  test('the audience is covered by the digest', () => {
    const xml = alter(createToken(sampleData(), { audience: 'mail' }).getXML() as string, (doc) => {
      node(doc, '/ds:Signature/ds:Object/Token/TokenAudience').textContent = 'crm';
    });
    const token = analyze('audience digest', { xml, options: trustAnchor({ expectedAudience: 'crm' }) });
    assert.equal(token.isSignatureValid(), false);
    assert.equal(token.isDigestValueOk(), false);
  });

  for (const [name, change] of Object.entries({
    'child element': (audience: ReturnType<typeof node>) => { audience.appendChild(audience.ownerDocument?.createElement('Extra') as never).appendChild(audience.ownerDocument?.createTextNode('crm') as never); },
    'empty': (audience: ReturnType<typeof node>) => { audience.textContent = ''; },
    'CDATA': (audience: ReturnType<typeof node>) => { audience.textContent = ''; audience.appendChild(audience.ownerDocument?.createCDATASection('mail') as never); },
    'surrounding space': (audience: ReturnType<typeof node>) => { audience.textContent = ' mail'; },
  })) {
    test(`a malformed audience is rejected before the data are read: ${name}`, () => {
      const xml = signAgain(createToken(sampleData(), { audience: 'mail' }).getXML() as string, (doc) => change(node(doc, '/ds:Signature/ds:Object/Token/TokenAudience')));
      const token = analyze(`malformed audience ${name}`, { xml, options: trustAnchor({ expectedAudience: 'mail' }) });
      assert.equal(token.isSignatureValid(), false);
      assert.ok(token.getError()?.includes('Token audience is malformed!'));
      assert.equal(token.getData(), null);
    });
  }

  test('an audience node in a namespace is not an audience', () => {
    const xml = signAgain(createToken().getXML() as string, (doc, token) => {
      token?.appendChild(doc.createElementNS('urn:other', 'o:TokenAudience')).appendChild(doc.createTextNode('mail'));
    });
    assert.equal(analyze('namespaced audience, expected', { xml, options: trustAnchor({ expectedAudience: 'mail' }) }).getError(), "Token is not addressed to any audience, but the audience 'mail' is expected!");
    const none = analyze('namespaced audience', { xml, options: trustAnchor() });
    assertValid(none);
    assert.equal(none.getAudience(), null);
  });

  test('earlier anomalies are reported before the audience', () => {
    const xml = signAgain(createToken(sampleData(), { audience: 'mail' }).getXML() as string, (_doc, token) => setChild(token as never, 'TokenId', 'not-hexadecimal'));
    const token = analyze('anomaly before audience', { xml, options: trustAnchor({ expectedAudience: 'crm' }) });
    assert.equal(token.getError(), '1 anomaly detected: Token identifier is malformed!');
    assert.equal(token.getData(), null);
  });

  test('the audience options are checked', () => {
    for (const audience of ['', [], ' mail', 'mail\ncrm', 42, ['mail', ''], { a: 'mail' }, 'mail\uFFFE']) {
      assert.throws(() => createToken(sampleData(), { audience: audience as never }), { message: /^Invalid option 'audience'!/ }, JSON.stringify(audience));
    }
    assert.throws(() => createToken(sampleData(), { audience: ['mail', 'crm', 'mail'] }), { message: "Invalid option 'audience'! An audience is given twice." });
    assert.throws(() => createToken(sampleData(), { expectedAudience: 'mail' }), { message: /^Option 'expectedAudience' only applies to token analysis!/ });
    for (const expectedAudience of ['', ['mail'], 'mail\t']) {
      assert.throws(() => XMLDSigToken.analyzeXMLToken('x', trustAnchor({ expectedAudience: expectedAudience as never })), { message: /^Invalid option 'expectedAudience'!/ });
    }
    assert.throws(() => XMLDSigToken.analyzeXMLToken('x', trustAnchor({ audience: 'mail' })), { message: "Option 'audience' only applies to token creation!" });
  });
});

describe('expiry', () => {
  test('a created token holds its expiry', () => {
    const token = createToken(sampleData(), { validity: 300 });
    assertValid(token);
    assert.equal(Date.parse(token.getExpiry() as string) - Date.parse(token.getTimestamp() as string), 300_000);
    const analyzed = analyze('expiry', { xml: token.getXML() as string, options: trustAnchor(), ttl: 600 });
    assertValid(analyzed);
    assert.equal(analyzed.getExpiry(), token.getExpiry());
    assert.equal(analyzed.isOutOfDate(600), false);
  });

  test('a token without validity has no expiry', () => {
    const token = analyze('no expiry', { xml: createToken().getXML() as string, options: trustAnchor() });
    assertValid(token);
    assert.equal(token.getExpiry(), null);
    assert.ok(!token.getXML()?.includes('TokenExpiry'));
  });

  test('a token whose expiry is passed is out of date, whatever the time to live', () => {
    const xml = signAgain(createToken().getXML() as string, (_doc, token) => {
      setChild(token as never, 'TokenTimestamp', utc(-20));
      setChild(token as never, 'TokenExpiry', utc(-10));
    });
    const token = analyze('expired', { xml, options: trustAnchor(), ttl: 3600 });
    assertValid(token);
    assert.equal(token.isOutOfDate(3600), true);
  });

  test('the time to live of the receiver still applies', () => {
    const xml = signAgain(createToken().getXML() as string, (_doc, token) => {
      setChild(token as never, 'TokenTimestamp', utc(-120));
      setChild(token as never, 'TokenExpiry', utc(86400));
    });
    const token = analyze('ttl applies', { xml, options: trustAnchor() });
    assertValid(token);
    assert.equal(token.isOutOfDate(60), true);
    assert.equal(token.isOutOfDate(600), false);
  });

  test('a token whose timestamp is too far in the future is out of date', () => {
    const near = signAgain(createToken().getXML() as string, (_doc, token) => setChild(token as never, 'TokenTimestamp', utc(20)));
    assert.equal(analyze('future 20 s', { xml: near, options: trustAnchor() }).isOutOfDate(), false);
    const far = signAgain(createToken().getXML() as string, (_doc, token) => setChild(token as never, 'TokenTimestamp', utc(60)));
    assert.equal(analyze('future 60 s', { xml: far, options: trustAnchor() }).isOutOfDate(), true);
  });

  for (const [name, change, anomaly] of [
    ['not a date', (token: ReturnType<typeof node>) => setChild(token, 'TokenExpiry', 'tomorrow'), 'Token expiry is malformed!'],
    ['out of range date', (token: ReturnType<typeof node>) => setChild(token, 'TokenExpiry', '2030-02-30T00:00:00Z'), 'Token expiry is malformed!'],
    ['two expiries', (token: ReturnType<typeof node>) => {
      setChild(token, 'TokenExpiry', utc(3600));
      token.appendChild(token.ownerDocument?.createElement('TokenExpiry') as never).appendChild(token.ownerDocument?.createTextNode(utc(7200)) as never);
    }, 'Token expiry is malformed!'],
    ['time zone suffix', (token: ReturnType<typeof node>) => setChild(token, 'TokenExpiry', utc(3600).replace('Z', '+00:00')), 'Token expiry is malformed!'],
    ['child element', (token: ReturnType<typeof node>) => {
      setChild(token, 'TokenExpiry', '');
      const expiry = Array.from(token.childNodes).find((child) => child.nodeName === 'TokenExpiry') as ReturnType<typeof node>;
      expiry.removeChild(expiry.firstChild as never);
      expiry.appendChild(token.ownerDocument?.createElement('Date') as never).appendChild(token.ownerDocument?.createTextNode(utc(3600)) as never);
    }, 'Token expiry is malformed!'],
    ['before the timestamp', (token: ReturnType<typeof node>) => {
      setChild(token, 'TokenTimestamp', utc(0));
      setChild(token, 'TokenExpiry', utc(-3600));
    }, 'Token expiry is not after its timestamp!'],
    ['equal to the timestamp', (token: ReturnType<typeof node>) => {
      const now = utc(0);
      setChild(token, 'TokenTimestamp', now);
      setChild(token, 'TokenExpiry', now);
    }, 'Token expiry is not after its timestamp!'],
  ] as Array<[string, (token: ReturnType<typeof node>) => void, string]>) {
    test(`a malformed expiry makes the token invalid: ${name}`, () => {
      const xml = signAgain(createToken().getXML() as string, (_doc, token) => change(token as never));
      const token = analyze(`malformed expiry ${name}`, { xml, options: trustAnchor(), ttl: 3600 });
      assert.equal(token.isSignatureValid(), false);
      assert.ok(token.getError()?.includes(anomaly), token.getError() ?? '');
      assert.equal(token.getData(), null);
      assert.equal(token.getExpiry(), null);
      assert.equal(token.isOutOfDate(3600), true);
    });
  }

  test('the validity option is checked', () => {
    for (const validity of [0, -60, '60', 60.5, Number.MAX_SAFE_INTEGER]) {
      assert.throws(() => createToken(sampleData(), { validity: validity as never }), { message: /^Invalid option 'validity'!/ }, String(validity));
    }
  });
});

describe('trust anchor', () => {
  function assertRejected(token: XMLDSigToken, reason: string): void {
    assert.equal(token.isSignatureValid(), false);
    assert.equal(token.isCertTrusted(), false);
    assert.ok(token.getError()?.includes(reason), token.getError() ?? '');
    assert.equal(token.getData(), null);
  }

  function assertAccepted(token: XMLDSigToken): void {
    assert.equal(token.getError(), null);
    assert.equal(token.isCertTrusted(), true);
    assert.equal(token.isSignatureValid(), true);
  }

  /** A token signed with a key and certificate of test/fixtures/trust/. */
  function tokenOf(name: string): string {
    const created = XMLDSigToken.createXMLToken(sampleData(), `${TRUST}/${name}.key.pem`, `${TRUST}/${name}.cert.pem`);
    assert.equal(created.getError(), null);
    return created.getXML() as string;
  }

  const attackerToken = () => XMLDSigToken.createXMLToken(sampleData(), `${CERTS}/attacker.key.pem`, `${CERTS}/attacker.cert.pem`).getXML() as string;

  test('a token signed with a certificate that copies the names of the legitimate one is rejected', () => {
    const token = analyze('attacker', { xml: attackerToken(), options: trustAnchor() });
    assert.equal(token.isSignatureValueOk(), true);
    assert.equal(token.isValidCertIssuer(INTERMEDIATE_DN), true);
    assertRejected(token, 'not issued by a trusted CA');
  });

  test('the same, when the signer is pinned', () => {
    assertRejected(analyze('attacker pinned', { xml: attackerToken(), options: { signerCertPath: `${CERTS}/sign.cert.pem` } }), 'not the pinned certificate');
  });

  test('a legitimate token is rejected without trust anchor', () => {
    const token = analyze('no anchor', { xml: createToken().getXML() as string });
    assert.equal(token.isSignatureValueOk(), true);
    assertRejected(token, 'No trust anchor');
  });

  test('a legitimate token is accepted with the pinned signer', () => {
    const token = analyze('pinned', { xml: createToken().getXML() as string, options: { signerCertPath: `${CERTS}/sign.cert.pem` } });
    assertAccepted(token);
    assert.deepEqual(token.getData(), sampleData());
  });

  test('another pinned certificate rejects the token', () => {
    assertRejected(analyze('other pinned', { xml: createToken().getXML() as string, options: trustAnchor({ signerCertPath: `${CERTS}/crypt.cert.pem` }) }), 'not the pinned certificate');
  });

  test('the expected subject is accepted, by fields or by DN', () => {
    const xml = createToken().getXML() as string;
    assertAccepted(analyze('subject fields', { xml, options: trustAnchor({ expectedSubject: { O: 'Lothbrok Ltd', OU: 'Signature Dept' } }) }));
    assertAccepted(analyze('subject DN', { xml, options: trustAnchor({ expectedSubject: '/C=DK/ST=Jylland/L=Kattegat/O=Lothbrok Ltd/OU=Signature Dept/CN=www.lothbrok.dk/emailAddress=ivar@lothbrok.dk' }) }));
  });

  test('another subject is rejected', () => {
    const xml = createToken().getXML() as string;
    assertRejected(analyze('other subject fields', { xml, options: trustAnchor({ expectedSubject: { O: 'Lothbrok Ltd', OU: 'Cryptography Dept' } }) }), 'Subject of the signing certificate is not the expected one');
    assertRejected(analyze('other subject DN', { xml, options: trustAnchor({ expectedSubject: '/C=DK/ST=Jylland/L=Kattegat/O=Lothbrok Ltd/OU=Cryptography Dept/CN=www.lothbrok.dk/emailAddress=ivar@lothbrok.dk' }) }), 'Subject of the signing certificate is not the expected one');
  });

  test('a token signed with an expired certificate is rejected', () => {
    const [xml] = forge([{ xml: tokenOf('issued'), steps: [{ op: 'resign', key: `${TRUST}/expired.key.pem`, cert: `${TRUST}/expired.cert.pem` }] }]);
    const token = analyze('expired certificate', { xml: xml as string, options: trustAnchor() });
    assert.equal(token.isSignatureValueOk(), true);
    assertRejected(token, 'not valid at the current date (valid from 2020-01-01T00:00:00Z to 2021-01-01T00:00:00Z)');
  });

  test('a certificate issued by the trusted intermediate is accepted', () => {
    assertAccepted(analyze('issued', { xml: tokenOf('issued'), options: trustAnchor() }));
  });

  test('a certificate of another intermediate of the same root is rejected, unless it is trusted', () => {
    const xml = tokenOf('other-signer');
    assertRejected(analyze('other intermediate', { xml, options: trustAnchor() }), 'not issued by a trusted CA');
    assertAccepted(analyze('other intermediate trusted', { xml, options: { caCertPath: [`${TRUST}/other-intermediate.cert.pem`, `${CERTS}/root.cert.pem`] } }));
  });

  test('a certificate issued by a certificate that is not a CA is rejected', () => {
    assertRejected(analyze('rogue', { xml: tokenOf('rogue'), options: { caCertPath: [`${CERTS}/sign.cert.pem`, ...ANCHOR] } }), 'not issued by a trusted CA');
  });

  test('an intermediate alone is not a trust anchor', () => {
    assertRejected(analyze('intermediate alone', { xml: createToken().getXML() as string, options: { caCertPath: `${CERTS}/intermediate.cert.pem` } }),
      "not issued by a trusted CA: its chain could not be verified up to the CA certificates of the option 'caCertPath', which must hold the issuing CA and the certificates up to its root!");
  });

  test('the root alone is not a trust anchor for a certificate of its intermediate', () => {
    assertRejected(analyze('root alone', { xml: createToken().getXML() as string, options: { caCertPath: `${CERTS}/root.cert.pem` } }), 'not issued by a trusted CA');
  });

  test('the anchor is accepted as a single file, or as PEM contents', () => {
    const bundle = 'test/.cache/token-anchor.pem';
    writeFileSync(bundle, ANCHOR.map((path) => readFileSync(path, 'utf8')).join(''));
    const xml = createToken().getXML() as string;
    assertAccepted(analyze('anchor bundle', { xml, options: { caCertPath: bundle } }));
    assertAccepted(XMLDSigToken.analyzeXMLToken(xml, { caCertPath: ANCHOR.map((path) => readFileSync(path, 'utf8')) }));
    assertAccepted(XMLDSigToken.analyzeXMLToken(xml, { signerCertPath: readFileSync(`${CERTS}/sign.cert.pem`) }));
  });

  test('an unreadable trust option throws', () => {
    assert.throws(() => XMLDSigToken.analyzeXMLToken(createToken().getXML() as string, { caCertPath: `${CERTS}/missing.cert.pem` }), { message: /^Invalid option 'caCertPath'/ });
  });

  test('isValidCertCA() does not fail without certificate', () => {
    const token = analyze('not a token', { xml: 'not an XML token', options: trustAnchor() });
    assert.notEqual(token.getError(), null);
    assert.equal(token.getCertificate(), null);
    assert.equal(token.isValidCertCA(`${CERTS}/intermediate.cert.pem`), false);
  });
});

describe('comments', () => {
  // A same-document reference ("#Token") is digested without comments,
  // whatever its transform says: a comment added to the signed token does
  // not break its digest.
  for (const c14n of [XMLDSigToken.C14N, XMLDSigToken.C14N_COMMENTS, XMLDSigToken.EXC_C14N_COMMENTS]) {
    test(`a comment between the values does not change the token: ${c14n.split('/').pop()}`, () => {
      const xml = alter(createToken(sampleData(), { canonicalizationAlgorithm: c14n }).getXML() as string, (doc) => {
        const tokenData = node(doc, '/ds:Signature/ds:Object/Token/TokenData');
        tokenData.insertBefore(doc.createComment('added'), tokenData.firstChild);
      });
      const token = analyze(`comment between values ${c14n}`, { xml, options: trustAnchor({ canonicalizationAlgorithm: c14n }) });
      assertValid(token);
      assert.deepEqual(token.getData(), sampleData());
    });
  }

  test('a comment inside a value makes the data malformed', () => {
    const xml = alter(createToken().getXML() as string, (doc) => {
      const leaf = node(doc, '/ds:Signature/ds:Object/Token/TokenData/name');
      const text = leaf.firstChild as NonNullable<typeof leaf.firstChild>;
      const value = text.nodeValue as string;
      leaf.removeChild(text);
      leaf.appendChild(doc.createTextNode(value.slice(0, 4)));
      leaf.appendChild(doc.createComment('added'));
      leaf.appendChild(doc.createTextNode(value.slice(4)));
    });
    const token = analyze('comment inside a value', { xml, options: trustAnchor() });
    assert.equal(token.isSignatureValid(), false);
    assert.ok(token.getError()?.includes('Token data is malformed!'), token.getError() ?? '');
  });
});

describe('key information', () => {
  test('a certificate that cannot be read gives the error of xmlseclibs', () => {
    const xml = alter(createToken().getXML() as string, (doc) => {
      node(doc, '/ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate').textContent = 'AAAA';
    });
    assert.equal(analyze('unreadable certificate', { xml, options: trustAnchor() }).getError(), 'Unable to extract public key');
  });

  test('a key value after the certificate leaves the token without certificate', () => {
    const xml = alter(createToken().getXML() as string, (doc) => {
      const keyValue = doc.createElementNS(DSIG_NS, 'ds:KeyValue');
      const rsa = keyValue.appendChild(doc.createElementNS(DSIG_NS, 'ds:RSAKeyValue'));
      rsa.appendChild(doc.createElementNS(DSIG_NS, 'ds:Modulus')).appendChild(doc.createTextNode(randomBytes(256).toString('base64')));
      rsa.appendChild(doc.createElementNS(DSIG_NS, 'ds:Exponent')).appendChild(doc.createTextNode('AQAB'));
      node(doc, '/ds:Signature/ds:KeyInfo').appendChild(keyValue);
    });
    const token = analyze('key value after certificate', { xml, options: trustAnchor() });
    assert.equal(token.isSignatureValid(), false);
  });

  test('a key value before the certificate is replaced by the certificate', () => {
    const xml = alter(createToken().getXML() as string, (doc) => {
      const keyValue = doc.createElementNS(DSIG_NS, 'ds:KeyValue');
      const rsa = keyValue.appendChild(doc.createElementNS(DSIG_NS, 'ds:RSAKeyValue'));
      rsa.appendChild(doc.createElementNS(DSIG_NS, 'ds:Modulus')).appendChild(doc.createTextNode(randomBytes(256).toString('base64')));
      rsa.appendChild(doc.createElementNS(DSIG_NS, 'ds:Exponent')).appendChild(doc.createTextNode('AQAB'));
      const keyInfo = node(doc, '/ds:Signature/ds:KeyInfo');
      keyInfo.insertBefore(keyValue, keyInfo.firstChild);
    });
    assertValid(analyze('key value before certificate', { xml, options: trustAnchor() }));
  });

  test('a certificate in another namespace, before the signing one, is the one read', () => {
    const xml = alter(createToken().getXML() as string, (doc) => {
      const x509Data = node(doc, '/ds:Signature/ds:KeyInfo/ds:X509Data');
      const other = doc.createElementNS('urn:other', 'o:X509Certificate');
      other.appendChild(doc.createTextNode(readFileSync(`${CERTS}/attacker.cert.pem`, 'utf8').replace(/-----[^-]+-----|\s/g, '')));
      x509Data.insertBefore(other, x509Data.firstChild);
    });
    const token = analyze('certificate in another namespace', { xml, options: trustAnchor() });
    assert.equal(token.isSignatureValid(), false);
  });
});

compareWithPhp(test);
