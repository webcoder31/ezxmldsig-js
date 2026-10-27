/**
 * Encrypted tokens: default algorithms, refused algorithms, and the
 * failures of the decryption, which must neither be told apart nor happen
 * before the token is verified (the cases of EncryptionTest of the PHP
 * library, and the cases of the other tests on encrypted tokens). The
 * encrypted tokens built for the tests are encrypted and signed by the PHP
 * library (xmlseclibs), not by the code under test. Every analysis is also
 * compared with the analysis of the PHP library.
 */

import assert from 'node:assert/strict';
import { constants, createCipheriv, publicEncrypt, randomBytes } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { inspect } from 'node:util';
import { describe, test } from 'node:test';

import { XMLDSigToken } from '../../dist/token/index.js';
import { loadXML } from '../../dist/core/xml.js';
import { runPhp } from '../helpers/php.ts';
import {
  CERTS,
  SIGN_KEY_PASSWORD,
  alter,
  analyze,
  compareWithPhp,
  createToken,
  forge,
  node,
  sampleData,
  trustAnchor,
  type ForgeStep,
} from '../helpers/token.ts';

const DECRYPTION_FAILED = 'Token decryption failed!';
const ENCRYPTED_KEY = '/ds:Signature/ds:Object/xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey/xenc:CipherData/xenc:CipherValue';
const ENCRYPTED_DATA = '/ds:Signature/ds:Object/xenc:EncryptedData/xenc:CipherData/xenc:CipherValue';
const RSA_1_5 = 'http://www.w3.org/2001/04/xmlenc#rsa-1_5';
const ELEMENT = 'http://www.w3.org/2001/04/xmlenc#Element';
const CRYPT_KEY = `${CERTS}/crypt.key.pem`;
const CRYPT_CERT = `${CERTS}/crypt.cert.pem`;

/** A decryption key that cannot be loaded: it is only loaded to decrypt,
so that the error it gives tells that a decryption was attempted. */
const UNLOADABLE_KEY = 'test/.cache/unloadable.key.pem';
mkdirSync('test/.cache', { recursive: true });
writeFileSync(UNLOADABLE_KEY, 'not a key\n');

/** Creates an encrypted token with the test certificates. */
function createSecureToken(cryptKey: string | null = CRYPT_KEY, options = {}, signCert = `${CERTS}/sign.cert.pem`, cryptKeyPassword: string | null = null): XMLDSigToken {
  return XMLDSigToken.createSecureXMLToken(sampleData(), `${CERTS}/sign.key.pem`, signCert, cryptKey, CRYPT_CERT, SIGN_KEY_PASSWORD, cryptKeyPassword, options);
}

interface Build {
  keyTransport?: string;
  cipher?: string;
  type?: 'Element' | 'Content';
  /** Steps after the encryption, before the signature. */
  steps?: ForgeStep[];
  /** Alteration of the XML after the encryption, before the signature. */
  change?: (doc: Parameters<Parameters<typeof alter>[1]>[0]) => void;
  signer?: 'sign' | 'attacker';
}

/**
 * Builds encrypted tokens with xmlseclibs, whatever the algorithms the
 * library accepts: the plain token comes from createXMLToken(), is
 * encrypted for crypt.cert.pem by the PHP library, optionally altered, then
 * digested and signed again by it.
 */
function buildEncryptedTokens(builds: Build[]): string[] {
  const encrypted = forge(builds.map((build) => ({
    xml: createToken().getXML() as string,
    steps: [
      { op: 'encrypt', cert: CRYPT_CERT, cipher: build.cipher ?? XMLDSigToken.AES256_GCM, keyTransport: build.keyTransport ?? XMLDSigToken.RSA_OAEP_MGF1P, type: build.type ?? 'Content' },
      ...(build.steps ?? []),
    ],
  })));
  return forge(builds.map((build, index) => ({
    xml: build.change === undefined ? encrypted[index] as string : alter(encrypted[index] as string, build.change),
    steps: [
      { op: 'redigest' },
      build.signer === 'attacker'
        ? { op: 'resign', key: `${CERTS}/attacker.key.pem`, cert: `${CERTS}/attacker.cert.pem` }
        : { op: 'resign', key: `${CERTS}/sign.key.pem`, password: SIGN_KEY_PASSWORD, cert: `${CERTS}/sign.cert.pem` },
    ],
  })));
}

function buildEncryptedToken(build: Build = {}): string {
  return buildEncryptedTokens([build])[0] as string;
}

/** An alteration that replaces the content of a CipherValue (decoded). */
function replaceCipherValue(query: string, replace: (value: Buffer) => Buffer) {
  return (doc: Parameters<Parameters<typeof alter>[1]>[0]) => {
    const cipherValue = node(doc, query);
    cipherValue.textContent = replace(Buffer.from(cipherValue.textContent ?? '', 'base64')).toString('base64');
  };
}

/** A session key encrypted with RSA-OAEP for crypt.cert.pem, with
node:crypto. */
function oaepEncrypt(sessionKey: Buffer): Buffer {
  return publicEncrypt({ key: readFileSync(CRYPT_CERT), padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha1' }, sessionKey);
}

function assertNotDecrypted(token: XMLDSigToken, reason: string): void {
  assert.ok(token.getError()?.includes(reason), token.getError() ?? '');
  assert.ok(!token.getError()?.includes('private key'), token.getError() ?? '');
  assert.equal(token.isSignatureValid(), false);
  assert.equal(token.getData(), null);
}

function algorithmsOf(xml: string) {
  const doc = loadXML(xml, 'token');
  return {
    sessionKey: node(doc, '/ds:Signature/ds:Object/xenc:EncryptedData/xenc:EncryptionMethod').getAttribute('Algorithm'),
    keyTransport: node(doc, '/ds:Signature/ds:Object/xenc:EncryptedData/ds:KeyInfo/xenc:EncryptedKey/xenc:EncryptionMethod').getAttribute('Algorithm'),
  };
}

describe('encryption', () => {
  test('a token encrypted without option uses AES-256-GCM and RSA-OAEP, and is decrypted', () => {
    const created = createSecureToken();
    assert.equal(created.getError(), null);
    assert.deepEqual(algorithmsOf(created.getXML() as string), { sessionKey: XMLDSigToken.AES256_GCM, keyTransport: XMLDSigToken.RSA_OAEP_MGF1P });
    const token = analyze('encrypted', { xml: created.getXML() as string, cryptKey: CRYPT_KEY, options: trustAnchor() });
    assert.equal(token.getError(), null);
    assert.equal(token.isSignatureValid(), true);
    assert.equal(token.isDataEncrypted(), true);
    assert.deepEqual(token.getData(), sampleData());
  });

  test('an encrypted token declares the type Element, and replaces the node Token', () => {
    const doc = loadXML(createSecureToken().getXML(), 'token');
    assert.equal(node(doc, '/ds:Signature/ds:Object/xenc:EncryptedData').getAttribute('Type'), ELEMENT);
    assert.equal(node(doc, '/ds:Signature/ds:Object').childNodes.length, 1);
  });

  test('the token is written as the PHP library writes it', () => {
    const [php] = runPhp([{ command: 'create', data: sampleData(), signKey: `${CERTS}/sign.key.pem`, signCert: `${CERTS}/sign.cert.pem`, signKeyPassword: SIGN_KEY_PASSWORD, cryptCert: CRYPT_CERT }]);
    const skeleton = (xml: string) => xml.replace(/<(ds:|xenc:)?(DigestValue|SignatureValue|CipherValue)>[^<]*</g, '<$1$2>…<');
    assert.equal(skeleton(createSecureToken(null).getXML() as string), skeleton(php?.['xml'] as string));
    for (const prefix of ['', 'sig']) {
      const [other] = runPhp([{ command: 'create', data: sampleData(), signKey: `${CERTS}/sign.key.pem`, signCert: `${CERTS}/sign.cert.pem`, signKeyPassword: SIGN_KEY_PASSWORD, cryptCert: CRYPT_CERT, options: { xmldsigNsPrefix: prefix } }]);
      const generic = (xml: string) => skeleton(xml).replace(/<((?:sig:)?)(DigestValue|SignatureValue)>[^<]*</g, '<$1$2>…<');
      assert.equal(generic(createSecureToken(null, { xmldsigNsPrefix: prefix }).getXML() as string), generic(other?.['xml'] as string), `prefix '${prefix}'`);
    }
  });

  for (const cipher of [XMLDSigToken.AES128_GCM, XMLDSigToken.AES192_GCM, XMLDSigToken.AES256_GCM, XMLDSigToken.AES128_CBC, XMLDSigToken.AES192_CBC, XMLDSigToken.AES256_CBC, XMLDSigToken.TRIPLEDES_CBC]) {
    test(`a token encrypted with ${cipher.split('#').pop()} is decrypted when declared`, () => {
      const options = { sessionKeyCipheringAlgorithm: cipher };
      const created = createSecureToken(CRYPT_KEY, options);
      assert.equal(created.getError(), null);
      assert.deepEqual(created.getData(), sampleData());
      const token = analyze(`cipher ${cipher}`, { xml: created.getXML() as string, cryptKey: CRYPT_KEY, options: trustAnchor(options) });
      assert.equal(token.getError(), null);
      assert.deepEqual(token.getData(), sampleData());
      const built = analyze(`cipher ${cipher} by xmlseclibs`, { xml: buildEncryptedToken({ cipher, type: 'Element' }), cryptKey: CRYPT_KEY, options: trustAnchor(options) });
      assert.equal(built.getError(), null);
    });
  }

  for (const type of ['Element', 'Content'] as const) {
    test(`a token encrypted with the type ${type} is decrypted`, () => {
      const token = analyze(`type ${type}`, { xml: buildEncryptedToken({ type }), cryptKey: CRYPT_KEY, options: trustAnchor() });
      assert.equal(token.getError(), null);
      assert.equal(token.isSignatureValid(), true);
      assert.deepEqual(token.getData(), sampleData());
    });
  }

  for (const [name, type] of [['no type', null], ['empty type', ''], ['type EncryptedKey', 'http://www.w3.org/2001/04/xmlenc#EncryptedKey'], ['MIME type', 'text/xml']] as Array<[string, string | null]>) {
    test(`any other type is refused without decryption: ${name}`, () => {
      const xml = buildEncryptedToken({
        type: 'Element',
        change: (doc) => {
          const encryptedData = node(doc, '/ds:Signature/ds:Object/xenc:EncryptedData');
          if (type === null) {
            encryptedData.removeAttribute('Type');
          } else {
            encryptedData.setAttribute('Type', type);
          }
        },
      });
      assertNotDecrypted(analyze(`other type ${name}`, { xml, cryptKey: UNLOADABLE_KEY, options: trustAnchor() }), 'Encrypted data is malformed!');
    });
  }

  for (const type of ['Element', 'Content'] as const) {
    test(`a plaintext with a document type declaration is refused: type ${type}`, () => {
      const token = node(loadXML(createToken().getXML(), 'token'), '/ds:Signature/ds:Object/Token').toString();
      const withDoctype = `<!DOCTYPE Token [<!ENTITY role "Admin">]>${token.replace('<TokenData>', '<TokenData><extra>&role;</extra>')}`;
      const [refused, accepted] = buildEncryptedTokens([
        { type, steps: [{ op: 'encryptPlaintext', cert: CRYPT_CERT, plaintext: withDoctype }] },
        { type, steps: [{ op: 'encryptPlaintext', cert: CRYPT_CERT, plaintext: token }] },
      ]);
      const analyzed = analyze(`plaintext doctype ${type}`, { xml: refused as string, cryptKey: CRYPT_KEY, options: trustAnchor() });
      assert.equal(analyzed.getError(), DECRYPTION_FAILED);
      assert.equal(analyzed.isSignatureValid(), false);
      assert.equal(analyzed.getData(), null);
      // Without the document type declaration, the same plaintext is a
      // valid token: the declaration alone makes it refused.
      assert.equal(analyze(`plaintext ${type}`, { xml: accepted as string, cryptKey: CRYPT_KEY, options: trustAnchor() }).isSignatureValid(), true);
    });
  }
});

describe('refused algorithms', () => {
  test('RSA 1.5 is refused at creation, and cannot be declared at analysis', () => {
    assert.throws(() => createSecureToken(CRYPT_KEY, { cryptAlgorithm: RSA_1_5 }), { message: /^Invalid parameter 'cryptAlgorithm'!/ });
    assert.throws(() => XMLDSigToken.analyzeSecureXMLToken('not an XML token', CRYPT_KEY, null, trustAnchor({ cryptAlgorithm: RSA_1_5 })), { message: /^Invalid parameter 'cryptAlgorithm'!/ });
  });

  for (const [name, options] of [['algorithms checked', {}], ['algorithms not checked', { checkCryptingAlgorithms: false }]] as const) {
    test(`a token whose session key is encrypted with RSA 1.5 is refused without decryption: ${name}`, () => {
      // AES-128-CBC is declared, so that only the key transport is at stake.
      const xml = buildEncryptedToken({ keyTransport: RSA_1_5, cipher: XMLDSigToken.AES128_CBC });
      const declared = { ...options, sessionKeyCipheringAlgorithm: XMLDSigToken.AES128_CBC };
      assertNotDecrypted(analyze(`RSA 1.5 unloadable ${name}`, { xml, cryptKey: UNLOADABLE_KEY, options: trustAnchor(declared) }), 'Crypt algorithm is invalid!');
      assertNotDecrypted(analyze(`RSA 1.5 ${name}`, { xml, cryptKey: CRYPT_KEY, options: trustAnchor(declared) }), 'Crypt algorithm is invalid!');
    });

    test(`a token encrypted with CBC is refused without decryption, unless declared: ${name}`, () => {
      const xml = buildEncryptedToken({ cipher: XMLDSigToken.AES128_CBC });
      assertNotDecrypted(analyze(`CBC unloadable ${name}`, { xml, cryptKey: UNLOADABLE_KEY, options: trustAnchor(options) }), 'Unauthorized Session Key Ciphering algorithm!');
      assertNotDecrypted(analyze(`CBC ${name}`, { xml, cryptKey: CRYPT_KEY, options: trustAnchor(options) }), 'Unauthorized Session Key Ciphering algorithm!');
    });
  }

  test('the declared CBC and AES-GCM are both accepted when the algorithms are not checked', () => {
    const options = { sessionKeyCipheringAlgorithm: XMLDSigToken.AES128_CBC, checkCryptingAlgorithms: false };
    const [declared, undeclared] = buildEncryptedTokens([{ cipher: XMLDSigToken.AES128_CBC }, { cipher: XMLDSigToken.AES256_CBC }]);
    for (const [name, xml] of [['declared CBC', declared], ['AES-GCM', createSecureToken().getXML()]] as Array<[string, string]>) {
      const token = analyze(`unchecked ${name}`, { xml, cryptKey: CRYPT_KEY, options: trustAnchor(options) });
      assert.equal(token.getError(), null);
      assert.deepEqual(token.getData(), sampleData());
    }
    assertNotDecrypted(analyze('unchecked undeclared CBC', { xml: undeclared as string, cryptKey: UNLOADABLE_KEY, options: trustAnchor(options) }), 'Unauthorized Session Key Ciphering algorithm!');
  });
});

describe('decryption failures', () => {
  const alterations: Record<string, [string, (value: Buffer) => Buffer]> = {
    'session key: random bytes': [ENCRYPTED_KEY, (value) => Buffer.concat([Buffer.from([0]), randomBytes(value.length - 1)])],
    'session key: 5-byte key': [ENCRYPTED_KEY, () => oaepEncrypt(Buffer.from('12345'))],
    'session key: another key': [ENCRYPTED_KEY, () => oaepEncrypt(randomBytes(32))],
    'data: altered byte': [ENCRYPTED_DATA, (value) => { const altered = Buffer.from(value); altered[20] = (altered[20] as number) ^ 0xff; return altered; }],
    'data: altered last block': [ENCRYPTED_DATA, (value) => { const altered = Buffer.from(value); altered[altered.length - 17] = (altered[altered.length - 17] as number) ^ 0x01; return altered; }],
    'data: truncated': [ENCRYPTED_DATA, (value) => value.subarray(0, -1)],
    'data: too short': [ENCRYPTED_DATA, (value) => value.subarray(0, 8)],
  };
  const ciphers: Record<string, [string, object]> = {
    'AES-256-GCM': [XMLDSigToken.AES256_GCM, {}],
    'AES-128-CBC declared': [XMLDSigToken.AES128_CBC, { sessionKeyCipheringAlgorithm: XMLDSigToken.AES128_CBC }],
  };

  for (const [cipherName, [cipher, options]] of Object.entries(ciphers)) {
    test(`every decryption failure gives the same error, without detail: ${cipherName}`, () => {
      const names = Object.keys(alterations);
      const xmls = buildEncryptedTokens(names.map((name) => {
        const [query, replace] = alterations[name] as [string, (value: Buffer) => Buffer];
        return { cipher, change: replaceCipherValue(query, replace) };
      }));
      names.forEach((name, index) => {
        const token = analyze(`decryption failure ${cipherName}, ${name}`, { xml: xmls[index] as string, cryptKey: CRYPT_KEY, options: trustAnchor(options) });
        assert.equal(token.isSignatureValueOk(), true, name);
        assert.equal(token.isCertTrusted(), true, name);
        assert.equal(token.getError(), DECRYPTION_FAILED, name);
        assert.deepEqual(token.getAnomalies(), [], name);
        assert.equal(token.getData(), null, name);
        const shown = inspect(token, { depth: 5 });
        for (const detail of ['Reason', 'openssl', 'Key must', 'parser', 'Session key', 'Token data', 'auth', 'bad decrypt']) {
          assert.ok(!shown.includes(detail), `${name}: ${detail}`);
        }
      });
    });
  }

  test('a session key longer than the key of the algorithm is truncated, as PHP does', () => {
    // A 32-byte session key for AES-128-CBC, whose first 16 bytes encrypt
    // the token, written with node:crypto in the format of xmlseclibs (IV,
    // then the data padded by their padding length).
    const sessionKey = randomBytes(32);
    const iv = randomBytes(16);
    const plaintext = Buffer.from(node(loadXML(createToken().getXML(), 'token'), '/ds:Signature/ds:Object/Token').toString());
    const padding = 16 - (plaintext.length % 16);
    const cipher = createCipheriv('aes-128-cbc', sessionKey.subarray(0, 16), iv).setAutoPadding(false);
    const data = Buffer.concat([iv, cipher.update(Buffer.concat([plaintext, Buffer.alloc(padding, padding)])), cipher.final()]);
    const xml = buildEncryptedToken({
      cipher: XMLDSigToken.AES128_CBC,
      change: (doc) => {
        node(doc, ENCRYPTED_KEY).textContent = oaepEncrypt(sessionKey).toString('base64');
        node(doc, ENCRYPTED_DATA).textContent = data.toString('base64');
      },
    });
    const token = analyze('long session key', { xml, cryptKey: CRYPT_KEY, options: trustAnchor({ sessionKeyCipheringAlgorithm: XMLDSigToken.AES128_CBC }) });
    assert.equal(token.getError(), null);
    assert.deepEqual(token.getData(), sampleData());
  });
});

describe('verification before decryption', () => {
  test('a token that fails its verification is not decrypted', () => {
    const [attacker, legitimate] = buildEncryptedTokens([{ signer: 'attacker' }, {}]);
    const alteredData = alter(legitimate as string, replaceCipherValue(ENCRYPTED_DATA, (value) => { const altered = Buffer.from(value); altered[20] = (altered[20] as number) ^ 0xff; return altered; }));
    const alteredSignature = alter(legitimate as string, (doc) => {
      const signatureValue = node(doc, '/ds:Signature/ds:SignatureValue');
      const value = Buffer.from(signatureValue.textContent ?? '', 'base64');
      value[10] = (value[10] as number) ^ 0xff;
      signatureValue.textContent = value.toString('base64');
    });
    for (const [name, xml, reason] of [
      ['untrusted signer', attacker, 'not issued by a trusted CA'],
      ['altered data, not signed again', alteredData, 'Token hash verification failed!'],
      ['altered signature value', alteredSignature, 'Token hash signature verification failed!'],
    ] as Array<[string, string, string]>) {
      const token = analyze(`not verified: ${name}`, { xml, cryptKey: UNLOADABLE_KEY, options: trustAnchor() });
      assertNotDecrypted(token, reason);
      assert.equal(token.isDataEncrypted(), null, name);
    }
  });

  test('without trust anchor, an encrypted token is not decrypted', () => {
    assertNotDecrypted(analyze('encrypted without anchor', { xml: createSecureToken().getXML() as string, cryptKey: UNLOADABLE_KEY }), 'No trust anchor');
  });

  test('a signed ds:Object copied into ds:KeyInfo, the original forged, is rejected', () => {
    const original = createSecureToken().getXML() as string;
    const object = original.slice(original.indexOf('<ds:Object'), original.indexOf('</ds:Object>') + '</ds:Object>'.length);
    const wrapped = alter(original.replace('</ds:KeyInfo>\n', `${object}</ds:KeyInfo>\n`), (doc) => {
      const signed = node(doc, '/ds:Signature/ds:Object');
      while (signed.firstChild !== null) {
        signed.removeChild(signed.firstChild);
      }
      const token = signed.appendChild(doc.createElement('Token'));
      token.appendChild(doc.createElement('TokenTimestamp')).appendChild(doc.createTextNode(new Date().toISOString().replace(/\.\d{3}Z$/, 'Z')));
      const leaf = doc.createElement('name');
      leaf.setAttribute('Algorithm', 'base64');
      token.appendChild(doc.createElement('TokenData')).appendChild(leaf);
      leaf.appendChild(doc.createTextNode(Buffer.from('Forged').toString('base64')));
    });
    const token = analyze('encrypted wrapping', { xml: wrapped, cryptKey: CRYPT_KEY, options: trustAnchor() });
    assert.equal(token.isSignatureValid(), false);
    assert.equal(token.getData(), null);
  });
});

describe('creation', () => {
  test('a token created without the private key of the recipient is checked, and decrypted by the recipient', () => {
    const created = createSecureToken(null);
    assert.equal(created.getError(), null);
    assert.deepEqual(created.getAnomalies(), []);
    assert.equal(created.isDigestValueOk(), true);
    assert.equal(created.isSignatureValueOk(), true);
    assert.equal(created.isCertTrusted(), true);
    assert.equal(created.isSignatureValid(), true);
    assert.equal(created.isDataEncrypted(), true);
    for (const value of [created.getData(), created.getTimestamp(), created.getTokenId(), created.getAudience(), created.getExpiry()]) {
      assert.equal(value, null);
    }
    assert.ok(!created.getXML()?.includes('TokenData'));

    const token = analyze('created without recipient key', { xml: created.getXML() as string, cryptKey: CRYPT_KEY, options: trustAnchor() });
    assert.equal(token.getError(), null);
    assert.equal(token.isSignatureValid(), true);
    assert.deepEqual(token.getData(), sampleData());
    assert.match(token.getTokenId() as string, /^[0-9a-f]{32}$/);
    assert.equal(token.isOutOfDate(), false);
  });

  test('a token created with the private key of the recipient is decrypted at creation', () => {
    const created = createSecureToken(CRYPT_KEY);
    assert.equal(created.getError(), null);
    assert.deepEqual(created.getData(), sampleData());
    assert.notEqual(created.getTimestamp(), null);
    const token = analyze('created with recipient key', { xml: created.getXML() as string, cryptKey: CRYPT_KEY, options: trustAnchor() });
    assert.equal(token.isSignatureValid(), true);
    assert.equal(token.getTokenId(), created.getTokenId());
    assert.equal(XMLDSigToken.analyzeSecureXMLToken(created.getXML() as string, readFileSync(CRYPT_KEY), null, trustAnchor()).isSignatureValid(), true);
  });

  test('a token created without the private key of the recipient is still checked', () => {
    const created = createSecureToken(null, {}, `${CERTS}/attacker.cert.pem`);
    assert.equal(created.isSignatureValid(), false);
    assert.ok(created.getError()?.includes('Token hash signature verification failed!'));
    assert.equal(created.getData(), null);
  });

  test('the parameters are checked', () => {
    assert.throws(() => createSecureToken(null, {}, `${CERTS}/sign.cert.pem`, 'cryptKeyPassword'), { message: /^Invalid parameter 'cryptKeyPassword'!/ });
    assert.throws(() => XMLDSigToken.createSecureXMLToken(sampleData(), `${CERTS}/sign.key.pem`, `${CERTS}/sign.cert.pem`, CRYPT_KEY, null as never, SIGN_KEY_PASSWORD), { message: /^Missing parameter 'cryptCertPath'!/ });
    assert.throws(() => XMLDSigToken.createSecureXMLToken(sampleData(), `${CERTS}/sign.key.pem`, `${CERTS}/sign.cert.pem`, CRYPT_KEY, `${CERTS}/missing.pem`, SIGN_KEY_PASSWORD), { message: "Invalid parameter 'cryptCertPath'! Cannot read X.509 certificate to encrypt token." });
    assert.throws(() => XMLDSigToken.createSecureXMLToken(sampleData(), `${CERTS}/sign.key.pem`, `${CERTS}/sign.cert.pem`, `${CERTS}/missing.pem`, CRYPT_CERT, SIGN_KEY_PASSWORD), { message: "Invalid parameter 'cryptKeyPath'! Cannot read private key to decrypt token." });
    assert.throws(() => XMLDSigToken.analyzeSecureXMLToken('x', `${CERTS}/missing.pem`, null, trustAnchor()), { message: "Invalid parameter 'cryptKeyPath'! Cannot read private key to decrypt token." });
    assert.throws(() => createSecureToken(CRYPT_KEY, { sessionKeyCipheringAlgorithm: XMLDSigToken.SHA256 }), { message: /^Invalid parameter 'sessionKeyCipheringAlgorithm'!/ });
    assert.throws(() => createSecureToken(CRYPT_KEY, { cryptAlgorithm: XMLDSigToken.RSA_SHA256 }), { message: /^Invalid parameter 'cryptAlgorithm'!/ });
  });

  test('a certificate without key for RSA-OAEP gives an error', () => {
    assert.equal(XMLDSigToken.createSecureXMLToken(sampleData(), `${CERTS}/sign.key.pem`, `${CERTS}/sign.cert.pem`, null, `${CERTS}/sign.key.pem`, SIGN_KEY_PASSWORD).getError(), 'Unable to extract public key');
  });

  test('the options of the encrypted factories are checked in their context', () => {
    for (const name of ['checkCryptingAlgorithms', 'checkSigningAlgorithms', 'caCertPath', 'expectedSubject']) {
      assert.throws(() => createSecureToken(CRYPT_KEY, { [name]: name === 'caCertPath' ? CRYPT_CERT : name === 'expectedSubject' ? { O: 'x' } : false }), { message: new RegExp(`^Option '${name}' only applies to`) });
    }
    for (const name of ['base64Encode', 'xmldsigNsPrefix']) {
      assert.throws(() => XMLDSigToken.analyzeSecureXMLToken('x', CRYPT_KEY, null, trustAnchor({ [name]: name === 'base64Encode' ? false : '' })), { message: new RegExp(`^Option '${name}' only applies to token creation!`) });
    }
    assert.throws(() => XMLDSigToken.analyzeSecureXMLToken('x', CRYPT_KEY, null, trustAnchor({ digestAlgoritm: 'x' } as never)), { message: "Unknown option 'digestAlgoritm'!" });
  });
});

describe('encrypted tokens and the other checks', () => {
  test('a signed token is analyzed with a decryption key', () => {
    const token = analyze('signed with decryption key', { xml: createToken().getXML() as string, cryptKey: CRYPT_KEY, options: trustAnchor() });
    assert.equal(token.isSignatureValid(), true);
    assert.equal(token.isDataEncrypted(), false);
    assert.deepEqual(token.getData(), sampleData());
  });

  test('an encrypted token analyzed without decryption key gives an error', () => {
    assert.equal(analyze('encrypted without key', { xml: createSecureToken().getXML() as string, options: trustAnchor() }).getError(), 'Token is encrypted but no private key is provided for decryption!');
  });

  test('an encrypted token carries its identifier, its audience and its expiry', () => {
    const created = createSecureToken(CRYPT_KEY, { audience: 'mail', validity: 60 });
    assert.equal(created.getError(), null);
    assert.ok(!created.getXML()?.includes('TokenAudience'));
    assert.ok(!created.getXML()?.includes('TokenId'));
    const ok = analyze('encrypted audience', { xml: created.getXML() as string, cryptKey: CRYPT_KEY, options: trustAnchor({ expectedAudience: 'mail' }) });
    assert.equal(ok.isSignatureValid(), true);
    assert.deepEqual(ok.getAudience(), ['mail']);
    assert.equal(ok.getExpiry(), created.getExpiry());
    assert.equal(ok.getTokenId(), created.getTokenId());
    const other = analyze('encrypted other audience', { xml: created.getXML() as string, cryptKey: CRYPT_KEY, options: trustAnchor({ expectedAudience: 'crm' }) });
    assert.equal(other.isSignatureValid(), false);
    assert.equal(other.getData(), null);
  });

  test('an encrypted token created without the recipient key leaves its audience and expiry unread', () => {
    const created = createSecureToken(null, { audience: 'mail', validity: 60 });
    assert.equal(created.isSignatureValid(), true);
    assert.equal(created.getAudience(), null);
    assert.equal(created.getExpiry(), null);
  });

  test('a malformed decrypted token fails as the decryption does', () => {
    const [xml] = buildEncryptedTokens([{ type: 'Element', steps: [{ op: 'encryptPlaintext', cert: CRYPT_CERT, plaintext: '<Other/>' }] }]);
    assert.equal(analyze('decrypted malformed', { xml: xml as string, cryptKey: CRYPT_KEY, options: trustAnchor() }).getError(), DECRYPTION_FAILED);
  });

  for (const [name, plaintext] of Object.entries({
    'two tokens': (token: string) => token + token,
    'text around the token': (token: string) => `text${token}text`,
    'a comment before the token': (token: string) => `<!-- x -->${token}`,
    'an XML declaration': (token: string) => `<?xml version="1.0"?>${token}`,
    'a prefix not declared': (token: string) => token.replace('<TokenData>', '<TokenData><p:x>1</p:x>'),
    'a default namespace on the token': (token: string) => token.replace('<Token>', '<Token xmlns="urn:other">'),
    'not UTF-8': (token: string) => token.replace('<TokenData>', '<TokenData><x>é</x>'),
    'not well formed': (token: string) => token.replace('</Token>', ''),
  })) {
    test(`a decrypted plaintext is read as an XML fragment, as PHP reads it: ${name}`, () => {
      const token = node(loadXML(createToken().getXML(), 'token'), '/ds:Signature/ds:Object/Token').toString();
      const [xml] = buildEncryptedTokens([{ type: 'Element', steps: [{ op: 'encryptPlaintext', cert: CRYPT_CERT, plaintext: plaintext(token) }] }]);
      analyze(`fragment: ${name}`, { xml: xml as string, cryptKey: CRYPT_KEY, options: trustAnchor() });
    });
  }
});

compareWithPhp(test);
