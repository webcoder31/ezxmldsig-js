/**
 * Options of the four factories: names, contexts, types and values (the
 * cases of OptionsTest and AudienceAndExpiryTest of the PHP library that are
 * decided before a token is created or analyzed), algorithm lists and trust
 * options.
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, test } from 'node:test';

import * as alg from '../dist/algorithms.js';
import {
  MAX_EXPIRY_TIME,
  checkOptions,
  isAuthenticatedCipheringAlgorithm,
  isValidAudience,
  isValidCanonicalizationAlgorithm,
  isValidHashAlgorithm,
  isValidKeyTransportAlgorithm,
  isValidSignatureAlgorithm,
  isValidSymmetricCipheringAlgorithm,
  loadTrustOptions,
} from '../dist/options.js';

const CERTS = 'test/fixtures/certs';
const RSA_1_5 = 'http://www.w3.org/2001/04/xmlenc#rsa-1_5';

type Factory = 'createXMLToken' | 'createSecureXMLToken' | 'analyzeXMLToken' | 'analyzeSecureXMLToken';

/** Checks options as the given factory does. */
function check(factory: Factory, options: unknown): void {
  checkOptions(options, factory.startsWith('create'), factory.includes('Secure'));
}

const FACTORIES: Factory[] = ['createXMLToken', 'createSecureXMLToken', 'analyzeXMLToken', 'analyzeSecureXMLToken'];

describe('an unknown option is refused', () => {
  for (const factory of FACTORIES) {
    test(factory, () => {
      assert.throws(() => check(factory, { digestAlgoritm: alg.SHA512 }), { message: "Unknown option 'digestAlgoritm'!" });
    });
  }

  test('a name of Object.prototype', () => {
    assert.throws(() => check('analyzeXMLToken', { toString: 'x' }), { message: "Unknown option 'toString'!" });
    assert.throws(() => check('analyzeXMLToken', JSON.parse('{"__proto__": {"caCertPath": "x"}}')), { message: "Unknown option '__proto__'!" });
  });
});

describe('an option out of its context is refused', () => {
  const cases: Record<Factory, Record<string, unknown>> = {
    createXMLToken: {
      sessionKeyCipheringAlgorithm: alg.AES256_CBC,
      cryptAlgorithm: alg.RSA_OAEP_MGF1P,
      checkCryptingAlgorithms: false,
      checkSigningAlgorithms: false,
      caCertPath: `${CERTS}/root.cert.pem`,
      signerCertPath: `${CERTS}/sign.cert.pem`,
      expectedSubject: { O: 'Lothbrok Ltd' },
      expectedAudience: 'crm',
    },
    createSecureXMLToken: {
      checkCryptingAlgorithms: false,
      checkSigningAlgorithms: false,
      caCertPath: `${CERTS}/root.cert.pem`,
      signerCertPath: `${CERTS}/sign.cert.pem`,
      expectedSubject: { O: 'Lothbrok Ltd' },
      expectedAudience: 'crm',
    },
    analyzeXMLToken: {
      base64Encode: false,
      xmldsigNsPrefix: '',
      sessionKeyCipheringAlgorithm: alg.AES256_CBC,
      cryptAlgorithm: alg.RSA_OAEP_MGF1P,
      checkCryptingAlgorithms: false,
      audience: 'crm',
      validity: 60,
    },
    analyzeSecureXMLToken: {
      base64Encode: false,
      xmldsigNsPrefix: '',
      audience: 'crm',
      validity: 60,
    },
  };
  for (const [factory, options] of Object.entries(cases) as Array<[Factory, Record<string, unknown>]>) {
    for (const [name, value] of Object.entries(options)) {
      test(`${factory}: ${name}`, () => {
        assert.throws(() => check(factory, { [name]: value }), (error: Error) => error.message.startsWith(`Option '${name}' only applies to`));
      });
    }
  }
});

test('each option is accepted in its context', () => {
  check('createXMLToken', { base64Encode: false, xmldsigNsPrefix: '', audience: ['crm', 'mail'], validity: 60, canonicalizationAlgorithm: alg.C14N, signatureAlgorithm: alg.RSA_SHA256, digestAlgorithm: alg.SHA256 });
  check('createSecureXMLToken', { sessionKeyCipheringAlgorithm: alg.AES256_GCM, cryptAlgorithm: alg.RSA_OAEP_MGF1P });
  check('analyzeXMLToken', { expectedAudience: 'crm', checkSigningAlgorithms: false, caCertPath: 'x', signerCertPath: 'x', expectedSubject: 'x' });
  check('analyzeSecureXMLToken', { sessionKeyCipheringAlgorithm: alg.AES256_GCM, cryptAlgorithm: alg.RSA_OAEP_MGF1P, checkCryptingAlgorithms: false });
});

test('the options must be an object', () => {
  for (const options of [null, undefined, [], 'options', 1]) {
    assert.throws(() => check('analyzeXMLToken', options), { message: "Invalid parameter 'options'! Parameter must be an object." });
  }
});

test('an invalid option value is refused', () => {
  const cases: Array<[string, unknown, string]> = [
    ['base64Encode', 'no', 'It must be a boolean.'],
    ['base64Encode', 0, 'It must be a boolean.'],
    ['xmldsigNsPrefix', false, 'It must be a string.'],
    ['signatureAlgorithm', null, 'Its value must not be null or undefined.'],
    ['signatureAlgorithm', undefined, 'Its value must not be null or undefined.'],
  ];
  for (const [name, value, message] of cases) {
    assert.throws(() => check('createXMLToken', { [name]: value }), { message: `Invalid option '${name}'! ${message}` }, `${name}: ${String(value)}`);
  }
  assert.throws(() => check('analyzeXMLToken', { checkSigningAlgorithms: 'false' }), { message: "Invalid option 'checkSigningAlgorithms'! It must be a boolean." });
  assert.throws(() => check('analyzeSecureXMLToken', { checkCryptingAlgorithms: 1 }), { message: "Invalid option 'checkCryptingAlgorithms'! It must be a boolean." });
});

describe('audience', () => {
  const AUDIENCE_ERROR = "Invalid option 'audience'! It must be a non-empty string, or a non-empty list of them, without control characters.";

  test('a string or a list of strings is accepted', () => {
    check('createXMLToken', { audience: 'crm' });
    check('createXMLToken', { audience: ['crm', 'https://mail.example.org/', 'Équipe A&B <x>'] });
  });

  test('an invalid audience is refused', () => {
    const invalid: unknown[] = ['', ' crm', 'crm ', 'c\trm', 'c\nrm', 'c\u007Frm', 'c￾rm', 'c\uD800rm', 1, true, {}, [], [''], ['crm', 1], { 0: 'crm' }, [['crm']]];
    for (const audience of invalid) {
      assert.throws(() => check('createXMLToken', { audience }), { message: AUDIENCE_ERROR }, JSON.stringify(audience));
    }
  });

  test('an audience given twice is refused', () => {
    assert.throws(() => check('createXMLToken', { audience: ['crm', 'mail', 'crm'] }), { message: "Invalid option 'audience'! An audience is given twice." });
  });

  test('an invalid expected audience is refused', () => {
    for (const expectedAudience of ['', ' crm', 'c\nrm', ['crm'], 1]) {
      assert.throws(() => check('analyzeXMLToken', { expectedAudience }), { message: "Invalid option 'expectedAudience'! It must be a non-empty string without control characters." });
    }
  });

  test('isValidAudience() follows the rules of the PHP library', () => {
    assert.equal(isValidAudience('a b'), true);
    assert.equal(isValidAudience(' crm'), true);
    assert.equal(isValidAudience('😀'), true);
    assert.equal(isValidAudience('\u0000'), false);
  });
});

describe('validity', () => {
  const VALIDITY_ERROR = "Invalid option 'validity'! It must be a number of seconds greater than 0.";

  test('a positive number of seconds is accepted', () => {
    check('createXMLToken', { validity: 1 });
    check('createXMLToken', { validity: 300 });
  });

  test('an invalid validity is refused', () => {
    for (const validity of [0, -1, 1.5, '60', Number.NaN, Number.POSITIVE_INFINITY, 2 ** 53, true]) {
      assert.throws(() => check('createXMLToken', { validity }), { message: VALIDITY_ERROR }, String(validity));
    }
  });

  test('an expiry after the year 9999 is refused', () => {
    const now = Math.floor(Date.now() / 1000);
    check('createXMLToken', { validity: MAX_EXPIRY_TIME - now - 60 });
    assert.throws(() => check('createXMLToken', { validity: MAX_EXPIRY_TIME - now + 60 }), { message: "Invalid option 'validity'! The expiry would be after 9999-12-31T23:59:59Z." });
  });
});

describe('algorithm lists', () => {
  test('canonicalization', () => {
    for (const algorithm of [alg.C14N, alg.C14N_COMMENTS, alg.EXC_C14N, alg.EXC_C14N_COMMENTS]) {
      assert.equal(isValidCanonicalizationAlgorithm(algorithm), true, algorithm);
    }
    assert.equal(isValidCanonicalizationAlgorithm(alg.SHA256), false);
  });

  test('digest', () => {
    for (const algorithm of [alg.SHA1, alg.SHA256, alg.SHA384, alg.SHA512, alg.RIPEMD160]) {
      assert.equal(isValidHashAlgorithm(algorithm), true, algorithm);
    }
    assert.equal(isValidHashAlgorithm(alg.RSA_SHA256), false);
  });

  test('a key transport algorithm is not a signature algorithm, and the reverse', () => {
    for (const algorithm of [alg.RSA_SHA1, alg.RSA_SHA256, alg.RSA_SHA384, alg.RSA_SHA512]) {
      assert.equal(isValidSignatureAlgorithm(algorithm), true, algorithm);
      assert.equal(isValidKeyTransportAlgorithm(algorithm), false, algorithm);
    }
    for (const algorithm of [alg.RSA_OAEP_MGF1P, RSA_1_5]) {
      assert.equal(isValidSignatureAlgorithm(algorithm), false, algorithm);
    }
    assert.equal(isValidKeyTransportAlgorithm(alg.RSA_OAEP_MGF1P), true);
  });

  test('RSA 1.5 is refused as key transport algorithm', () => {
    assert.equal(isValidKeyTransportAlgorithm(RSA_1_5), false);
  });

  test('symmetric ciphering, and those that authenticate the data', () => {
    for (const algorithm of [alg.AES128_GCM, alg.AES192_GCM, alg.AES256_GCM]) {
      assert.equal(isValidSymmetricCipheringAlgorithm(algorithm), true, algorithm);
      assert.equal(isAuthenticatedCipheringAlgorithm(algorithm), true, algorithm);
    }
    for (const algorithm of [alg.TRIPLEDES_CBC, alg.AES128_CBC, alg.AES192_CBC, alg.AES256_CBC]) {
      assert.equal(isValidSymmetricCipheringAlgorithm(algorithm), true, algorithm);
      assert.equal(isAuthenticatedCipheringAlgorithm(algorithm), false, algorithm);
    }
    assert.equal(isValidSymmetricCipheringAlgorithm(alg.SHA256), false);
  });

  test('a value of another type than string is in no list', () => {
    for (const value of [true, 1, null, undefined, {}, [alg.C14N]]) {
      assert.equal(isValidCanonicalizationAlgorithm(value), false);
      assert.equal(isValidHashAlgorithm(value), false);
      assert.equal(isValidSignatureAlgorithm(value), false);
      assert.equal(isValidKeyTransportAlgorithm(value), false);
      assert.equal(isValidSymmetricCipheringAlgorithm(value), false);
    }
  });
});

describe('trust options', () => {
  const root = readFileSync(`${CERTS}/root.cert.pem`, 'utf8');

  test('without them, there is no trust anchor', () => {
    assert.deepEqual(loadTrustOptions({}), { caCerts: null, pinnedSignerCert: null, expectedSubject: null });
  });

  test('CA certificates are given by paths or by contents', () => {
    const trust = loadTrustOptions({ caCertPath: [`${CERTS}/root.cert.pem`, root, Buffer.from(root)] });
    assert.deepEqual(trust.caCerts, [root, root, root]);
    assert.deepEqual(loadTrustOptions({ caCertPath: `${CERTS}/root.cert.pem` }).caCerts, [root]);
  });

  test('a CA certificate file that cannot be read is refused', () => {
    assert.throws(() => loadTrustOptions({ caCertPath: [`${CERTS}/root.cert.pem`, `${CERTS}/missing.pem`] }), { message: `Invalid option 'caCertPath'! Cannot read CA certificate file: ${CERTS}/missing.pem.` });
    assert.throws(() => loadTrustOptions({ caCertPath: CERTS }), { message: `Invalid option 'caCertPath'! Cannot read CA certificate file: ${CERTS}.` });
    assert.throws(() => loadTrustOptions({ caCertPath: [1] as never }), { message: "Invalid option 'caCertPath'! Cannot read CA certificate file: number." });
    assert.throws(() => loadTrustOptions({ caCertPath: [] }), { message: "Invalid option 'caCertPath'! It must be a path or a non-empty list of paths." });
  });

  test('the pinned certificate must be a certificate', () => {
    assert.equal(loadTrustOptions({ signerCertPath: `${CERTS}/sign.cert.pem` }).pinnedSignerCert, readFileSync(`${CERTS}/sign.cert.pem`, 'utf8'));
    for (const signerCertPath of [`${CERTS}/missing.pem`, `${CERTS}/sign.key.pem`, '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n', 1]) {
      assert.throws(() => loadTrustOptions({ signerCertPath: signerCertPath as never }), { message: "Invalid option 'signerCertPath'! Cannot read the pinned X.509 certificate." });
    }
  });

  test('the expected subject is a non-empty string or object', () => {
    assert.equal(loadTrustOptions({ expectedSubject: '/O=Lothbrok Ltd' }).expectedSubject, '/O=Lothbrok Ltd');
    assert.deepEqual(loadTrustOptions({ expectedSubject: { O: 'Lothbrok Ltd' } }).expectedSubject, { O: 'Lothbrok Ltd' });
    for (const expectedSubject of ['', {}, [], ['O'], 1, true]) {
      assert.throws(() => loadTrustOptions({ expectedSubject: expectedSubject as never }), { message: "Invalid option 'expectedSubject'! It must be a non-empty string or object." });
    }
  });
});
