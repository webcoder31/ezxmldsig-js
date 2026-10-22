/**
 * Interoperability, both ways:
 *
 * - with the PHP library ezxmldsig 1.2.1, under PHP 7.4 and 8.3: the
 *   tokens it creates are analyzed here, and the tokens created here are
 *   analyzed by it, signed and encrypted, with and without audience and
 *   expiry, with several algorithms;
 * - with xml-crypto and xml-encryption, as the README of the PHP library
 *   shows them: tokens they create are analyzed here, and they read the
 *   tokens created here.
 */

import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, test } from 'node:test';

import { DOMParser, XMLSerializer, type Element, type Node } from '@xmldom/xmldom';
import { SignedXml } from 'xml-crypto';
import xmlenc from 'xml-encryption';

import { XMLDSigToken, type TokenOptions } from '../dist/index.js';
import { PHP_VERSIONS, phpSkip, runPhp } from './helpers/php.ts';
import { CERTS, SIGN_KEY_PASSWORD, alter, node, trustAnchor } from './helpers/token.ts';

const SIGN_KEY = `${CERTS}/sign.key.pem`;
const SIGN_CERT = `${CERTS}/sign.cert.pem`;
const CRYPT_KEY = `${CERTS}/crypt.key.pem`;
const CRYPT_CERT = `${CERTS}/crypt.cert.pem`;

const DATA = {
  name: 'Ragnar Lothbrok',
  role: 'Jarl',
  city: 'Kattegat & Hedeby <north> "fjord"',
  nested: { a: '1', b: 'Æsir € 日本' },
};

interface Variant {
  name: string;
  encrypted?: boolean;
  /** Creation options. */
  options?: TokenOptions;
  /** Analysis options, besides the trust anchor. */
  analysis?: TokenOptions;
}

const VARIANTS: Variant[] = [
  { name: 'signed' },
  { name: 'signed, audience and expiry', options: { audience: ['crm', 'mail'], validity: 300 }, analysis: { expectedAudience: 'mail' } },
  {
    name: 'signed, RSA-SHA512, SHA-512, exclusive C14N, no prefix',
    options: { signatureAlgorithm: XMLDSigToken.RSA_SHA512, digestAlgorithm: XMLDSigToken.SHA512, canonicalizationAlgorithm: XMLDSigToken.EXC_C14N, xmldsigNsPrefix: '' },
    analysis: { signatureAlgorithm: XMLDSigToken.RSA_SHA512, digestAlgorithm: XMLDSigToken.SHA512, canonicalizationAlgorithm: XMLDSigToken.EXC_C14N },
  },
  { name: 'signed, RIPEMD-160, C14N with comments, prefix sig', options: { digestAlgorithm: XMLDSigToken.RIPEMD160, canonicalizationAlgorithm: XMLDSigToken.C14N_COMMENTS, xmldsigNsPrefix: 'sig' }, analysis: { digestAlgorithm: XMLDSigToken.RIPEMD160, canonicalizationAlgorithm: XMLDSigToken.C14N_COMMENTS } },
  { name: 'signed, values not in base64', options: { base64Encode: false } },
  { name: 'encrypted', encrypted: true },
  { name: 'encrypted, audience and expiry', encrypted: true, options: { audience: 'crm', validity: 60 }, analysis: { expectedAudience: 'crm' } },
  { name: 'encrypted, AES-128-CBC', encrypted: true, options: { sessionKeyCipheringAlgorithm: XMLDSigToken.AES128_CBC }, analysis: { sessionKeyCipheringAlgorithm: XMLDSigToken.AES128_CBC } },
  { name: 'encrypted, Triple DES, no prefix', encrypted: true, options: { sessionKeyCipheringAlgorithm: XMLDSigToken.TRIPLEDES_CBC, xmldsigNsPrefix: '' }, analysis: { sessionKeyCipheringAlgorithm: XMLDSigToken.TRIPLEDES_CBC } },
];

function analysisOptions(variant: Variant): TokenOptions {
  return trustAnchor(variant.analysis ?? {});
}

/** The request that creates a token of the variant with the PHP library. */
function phpCreate(variant: Variant, withRecipientKey: boolean) {
  return {
    command: 'create' as const,
    data: DATA,
    signKey: SIGN_KEY,
    signCert: SIGN_CERT,
    signKeyPassword: SIGN_KEY_PASSWORD,
    ...(variant.encrypted ? { cryptCert: CRYPT_CERT, ...(withRecipientKey ? { cryptKey: CRYPT_KEY } : {}) } : {}),
    options: variant.options ?? {},
  };
}

/** Creates a token of the variant with this library. */
function create(variant: Variant): XMLDSigToken {
  return variant.encrypted
    ? XMLDSigToken.createSecureXMLToken(DATA, SIGN_KEY, SIGN_CERT, null, CRYPT_CERT, SIGN_KEY_PASSWORD, null, variant.options ?? {})
    : XMLDSigToken.createXMLToken(DATA, SIGN_KEY, SIGN_CERT, SIGN_KEY_PASSWORD, variant.options ?? {});
}

/** Analyzes a token of the variant with this library. */
function analyze(variant: Variant, xml: string): XMLDSigToken {
  return variant.encrypted
    ? XMLDSigToken.analyzeSecureXMLToken(xml, CRYPT_KEY, null, analysisOptions(variant))
    : XMLDSigToken.analyzeXMLToken(xml, analysisOptions(variant));
}

for (const version of PHP_VERSIONS) {
  describe(`with the PHP library, under PHP ${version}`, { skip: phpSkip }, () => {
    test('the tokens it creates are valid here', () => {
      const created = runPhp([
        ...VARIANTS.map((variant) => phpCreate(variant, true)),
        // Encrypted by a sender without the private key of the recipient.
        ...VARIANTS.filter((variant) => variant.encrypted).map((variant) => phpCreate(variant, false)),
      ], version);
      const cases = [...VARIANTS, ...VARIANTS.filter((variant) => variant.encrypted)];
      cases.forEach((variant, index) => {
        const php = created[index] as Record<string, unknown>;
        assert.equal(php['isSignatureValid'], true, `${variant.name}: ${php['error']}`);
        const token = analyze(variant, php['xml'] as string);
        assert.equal(token.getError(), null, variant.name);
        assert.equal(token.isSignatureValid(), true, variant.name);
        assert.equal(token.isDataEncrypted(), variant.encrypted === true, variant.name);
        assert.deepEqual(token.getData(), DATA, variant.name);
        assert.equal(token.isOutOfDate(), false, variant.name);
        if (php['tokenId'] !== null) {
          // The PHP library read its own token (not encrypted, or encrypted
          // with the recipient key): the same values are read here.
          assert.equal(token.getTokenId(), php['tokenId'], variant.name);
          assert.equal(token.getTimestamp(), php['timestamp'], variant.name);
          assert.deepEqual(token.getAudience(), php['audience'], variant.name);
          assert.equal(token.getExpiry(), php['expiry'], variant.name);
        }
      });
    });

    test('the tokens created here are valid for it', () => {
      const tokens = VARIANTS.map((variant) => create(variant));
      tokens.forEach((token, index) => assert.equal(token.getError(), null, VARIANTS[index]?.name));
      const analyzed = runPhp(VARIANTS.map((variant, index) => ({
        command: 'analyze',
        xml: tokens[index]?.getXML(),
        options: analysisOptions(variant),
        ...(variant.encrypted ? { cryptKey: CRYPT_KEY } : {}),
      })), version);
      VARIANTS.forEach((variant, index) => {
        const php = analyzed[index] as Record<string, unknown>;
        assert.equal(php['error'], null, variant.name);
        assert.equal(php['isSignatureValid'], true, variant.name);
        assert.equal(php['isDataEncrypted'], variant.encrypted === true, variant.name);
        assert.deepEqual(php['data'], DATA, variant.name);
        assert.equal(php['isOutOfDate'], false, variant.name);
        assert.match(php['tokenId'] as string, /^[0-9a-f]{32}$/, variant.name);
        const ours = analyze(variant, tokens[index]?.getXML() as string);
        assert.equal(php['tokenId'], ours.getTokenId(), variant.name);
        assert.deepEqual(php['audience'], ours.getAudience(), variant.name);
        assert.equal(php['expiry'], ours.getExpiry(), variant.name);
      });
    });

    test('a token created here and altered is refused by it', () => {
      const xml = alter(create(VARIANTS[0] as Variant).getXML() as string, (doc) => {
        node(doc, '/ds:Signature/ds:Object/Token/TokenData/role').textContent = Buffer.from('Thrall').toString('base64');
      });
      const [php] = runPhp([{ command: 'analyze', xml, options: trustAnchor() }], version);
      assert.equal(php?.['isSignatureValid'], false);
      assert.equal(php?.['error'], '1 anomaly detected: Token hash verification failed!');
    });
  });
}

/* With xml-crypto and xml-encryption, as the README of the PHP library
shows them. */

const C14N = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
const date = (d: Date) => d.toISOString().replace(/\.\d{3}Z$/, 'Z');
const b64 = (s: string) => Buffer.from(s, 'utf8').toString('base64');

/** The first child element of a node: whitespace may come before it. */
function firstElement(parent: Node): Element | null {
  for (let child = parent.firstChild; child !== null; child = child.nextSibling) {
    if (child.nodeType === 1) {
      return child as Element;
    }
  }
  return null;
}

function encrypt(xml: string): Promise<string> {
  return new Promise((resolve, reject) => xmlenc.encrypt(xml, {
    rsa_pub: readFileSync(CRYPT_CERT),
    pem: readFileSync(CRYPT_CERT),
    encryptionAlgorithm: 'http://www.w3.org/2009/xmlenc11#aes256-gcm',
    keyEncryptionAlgorithm: 'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p',
  }, (error: Error | null, result: string) => (error ? reject(error) : resolve(result))));
}

function decrypt(xml: string): Promise<string> {
  return new Promise((resolve, reject) => xmlenc.decrypt(xml, { key: readFileSync(CRYPT_KEY) },
    (error: Error | null, result: string) => (error ? reject(error) : resolve(result))));
}

/** Creates a token with xml-crypto, and xml-encryption if it is encrypted. */
async function createWithXmlCrypto(encrypted: boolean): Promise<string> {
  const now = new Date();
  let token = '<Token>'
    + `<TokenTimestamp>${date(now)}</TokenTimestamp>`
    + `<TokenId>${randomBytes(16).toString('hex')}</TokenId>`
    + `<TokenExpiry>${date(new Date(now.getTime() + 300e3))}</TokenExpiry>`
    + '<TokenAudience>receiver</TokenAudience>'
    + `<TokenData><name Algorithm="base64">${b64('Ragnar Lothbrok')}</name><city Algorithm="base64">${b64('Kattegat & Hedeby')}</city></TokenData>`
    + '</Token>';
  if (encrypted) {
    token = await encrypt(token);
  }

  // xml-crypto places a signature inside an existing document: sign in a
  // throwaway root, then keep the signature alone, as the document element.
  // Its private key cannot have a password: the key of sign.key.pem is
  // decrypted first.
  const { createPrivateKey } = await import('node:crypto');
  const privateKey = createPrivateKey({ key: readFileSync(SIGN_KEY), passphrase: SIGN_KEY_PASSWORD }).export({ type: 'pkcs8', format: 'pem' });
  const signature = new SignedXml({
    privateKey,
    publicCert: readFileSync(SIGN_CERT),
    canonicalizationAlgorithm: C14N,
    signatureAlgorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    objects: [{ content: token, attributes: { Id: 'Token' } }],
  });
  signature.addReference({ xpath: "//*[@Id='Token']", digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256', transforms: [C14N] });
  signature.computeSignature('<root/>', { prefix: 'ds' });

  const doc = new DOMParser().parseFromString(signature.getSignedXml(), 'text/xml');
  return `<?xml version="1.0"?>\n${new XMLSerializer().serializeToString(doc.documentElement?.firstChild as Node)}`;
}

/**
 * Reads a token with xml-crypto, and xml-encryption if it is encrypted: the
 * signature verified with the signing certificate, the data read from the
 * content the signature covers.
 */
interface Values {
  [name: string]: string | Values;
}

async function readWithXmlCrypto(xml: string): Promise<Values> {
  const doc = new DOMParser().parseFromString(xml, 'text/xml');
  const signature = new SignedXml({ publicCert: readFileSync(SIGN_CERT) });
  signature.loadSignature(doc.documentElement as never);
  if (!signature.checkSignature(xml)) {
    throw new Error('Invalid signature');
  }
  const [signed] = signature.getSignedReferences();
  let content = firstElement(new DOMParser().parseFromString(signed as string, 'text/xml').documentElement as Node);
  if (content?.localName === 'EncryptedData') {
    const plain = await decrypt(new XMLSerializer().serializeToString(content));
    content = new DOMParser().parseFromString(plain, 'text/xml').documentElement;
  }
  assert.equal(content?.localName, 'Token');
  const tokenData = Array.from(content?.childNodes ?? []).find((child) => child.nodeName === 'TokenData') as Element;
  return readValues(tokenData);
}

/** Reads the node tree of the data: an element holding a single text node
is a value, an element holding elements is nested values. */
function readValues(parent: Element): Values {
  const values: Values = {};
  for (const child of Array.from(parent.childNodes)) {
    if (child.nodeType !== 1) {
      continue;
    }
    const element = child as Element;
    const leaf = element.childNodes.length === 1 && element.firstChild?.nodeType === 3;
    values[element.nodeName] = !leaf
      ? readValues(element)
      : element.getAttribute('Algorithm') === 'base64' ? Buffer.from(element.textContent ?? '', 'base64').toString('utf8') : element.textContent ?? '';
  }
  return values;
}

describe('with xml-crypto and xml-encryption', () => {
  for (const encrypted of [false, true]) {
    const kind = encrypted ? 'encrypted' : 'signed';

    test(`a ${kind} token they create is valid here`, async () => {
      const xml = await createWithXmlCrypto(encrypted);
      const options = trustAnchor({ expectedAudience: 'receiver', expectedSubject: { O: 'Lothbrok Ltd', OU: 'Signature Dept' } });
      const token = encrypted ? XMLDSigToken.analyzeSecureXMLToken(xml, CRYPT_KEY, null, options) : XMLDSigToken.analyzeXMLToken(xml, options);
      assert.equal(token.getError(), null);
      assert.equal(token.isSignatureValid(), true);
      assert.equal(token.isDataEncrypted(), encrypted);
      assert.deepEqual(token.getData(), { name: 'Ragnar Lothbrok', city: 'Kattegat & Hedeby' });
      assert.deepEqual(token.getAudience(), ['receiver']);
      assert.equal(token.isOutOfDate(120), false);
    });

    test(`a ${kind} token they create and that is altered is refused here`, async () => {
      const xml = alter(await createWithXmlCrypto(encrypted), (doc) => {
        const value = node(doc, encrypted
          ? '/ds:Signature/ds:Object/xenc:EncryptedData/xenc:CipherData/xenc:CipherValue'
          : '/ds:Signature/ds:Object/Token/TokenData/name');
        value.textContent = encrypted ? randomBytes(64).toString('base64') : b64('Forged');
      });
      const token = encrypted ? XMLDSigToken.analyzeSecureXMLToken(xml, CRYPT_KEY, null, trustAnchor({ expectedAudience: 'receiver' })) : XMLDSigToken.analyzeXMLToken(xml, trustAnchor({ expectedAudience: 'receiver' }));
      assert.equal(token.isSignatureValid(), false);
      assert.equal(token.getError(), '1 anomaly detected: Token hash verification failed!');
    });

    test(`they read a ${kind} token created here`, async () => {
      const created = encrypted
        ? XMLDSigToken.createSecureXMLToken(DATA, SIGN_KEY, SIGN_CERT, null, CRYPT_CERT, SIGN_KEY_PASSWORD)
        : XMLDSigToken.createXMLToken(DATA, SIGN_KEY, SIGN_CERT, SIGN_KEY_PASSWORD);
      assert.equal(created.getError(), null);
      const data = await readWithXmlCrypto(created.getXML() as string);
      assert.deepEqual(data, DATA);
    });
  }

  test('xml-crypto refuses a token created here and altered', async () => {
    const xml = alter(XMLDSigToken.createXMLToken(DATA, SIGN_KEY, SIGN_CERT, SIGN_KEY_PASSWORD).getXML() as string, (doc) => {
      node(doc, '/ds:Signature/ds:Object/Token/TokenData/role').textContent = b64('Thrall');
    });
    await assert.rejects(readWithXmlCrypto(xml), /invalid signature|Invalid signature|digest/i);
  });

  test('the digest xml-crypto computes is the one written here', () => {
    // A control of the canonicalization, outside of both libraries' own
    // verification: the digest of the canonical ds:Object, by xml-crypto.
    const xml = XMLDSigToken.createXMLToken(DATA, SIGN_KEY, SIGN_CERT, SIGN_KEY_PASSWORD).getXML() as string;
    const signature = new SignedXml({ publicCert: readFileSync(SIGN_CERT) });
    const doc = new DOMParser().parseFromString(xml, 'text/xml');
    signature.loadSignature(doc.documentElement as never);
    assert.equal(signature.checkSignature(xml), true);
    const [signed] = signature.getSignedReferences();
    const digest = createHash('sha256').update(signed as string).digest('base64');
    assert.ok(xml.includes(`<ds:DigestValue>${digest}</ds:DigestValue>`));
  });
});
