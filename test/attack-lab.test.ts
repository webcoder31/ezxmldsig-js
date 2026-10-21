/**
 * The attack lab of the PHP library demo, replayed here: each attack is run
 * by the lab itself (in PHP), which forges a token from a legitimate one and
 * submits it to the receiver of the demo; the same forged token is submitted
 * to a receiver configured the same way with this library. Each attack must
 * meet its expected verdict, and this library must reach the very verdict of
 * the PHP library: accepted or not, error, anomalies, and the checks of the
 * caller (freshness, replay).
 */

import assert from 'node:assert/strict';
import { describe, test } from 'node:test';

import { XMLDSigToken, type TokenOptions } from '../dist/index.js';
import { phpSkip, runPhp, type PhpResult } from './helpers/php.ts';

const DEMO_CERTS = 'test/fixtures/demo-certs';

/** The certificates of the demo, as the PHP container sees them, and here. */
function localPath(path: string): string {
  return path.replace(/^\/ezxmldsig\/demo\/certs\//, `${DEMO_CERTS}/`);
}

/** The receiver of the demo, with this library: the analysis, then the
checks of the caller, freshness and replay (see the README). */
class Receiver {
  readonly #options: TokenOptions;
  readonly #cryptKey: string;
  readonly #cryptKeyPassword: string;
  readonly #ttl: number;
  readonly #accepted = new Set<string>();

  constructor(config: { options: Record<string, unknown>; cryptKey: string; cryptKeyPassword: string; ttl: number }) {
    const options = { ...config.options } as TokenOptions & { caCertPath?: string[] };
    if (Array.isArray(options.caCertPath)) {
      options.caCertPath = options.caCertPath.map(localPath);
    }
    if (typeof options.signerCertPath === 'string') {
      options.signerCertPath = localPath(options.signerCertPath);
    }
    this.#options = options;
    this.#cryptKey = localPath(config.cryptKey);
    this.#cryptKeyPassword = config.cryptKeyPassword;
    this.#ttl = config.ttl;
  }

  verify(xml: string) {
    const token = XMLDSigToken.analyzeSecureXMLToken(xml, this.#cryptKey, this.#cryptKeyPassword, this.#options);
    const signatureValid = token.isSignatureValid();
    const fresh = signatureValid && !token.isOutOfDate(this.#ttl);
    let replayOk = true;
    if (fresh) {
      const id = token.getTokenId() as string;
      replayOk = !this.#accepted.has(id);
      this.#accepted.add(id);
    }
    const accepted = signatureValid && fresh && replayOk;
    return {
      accepted,
      signatureValid,
      error: token.getError(),
      anomalies: token.getAnomalies(),
      freshness: !signatureValid ? 'skip' : fresh ? 'pass' : 'fail',
      replay: !fresh ? 'skip' : replayOk ? 'pass' : 'fail',
      data: accepted ? token.getData() : null,
    };
  }
}

type Verdict = ReturnType<Receiver['verify']>;

/** What each attack must meet, whatever the library. */
const EXPECTED: Record<string, (verdict: Verdict) => void> = {
  'tamper': (v) => assert.equal(v.error, '1 anomaly detected: Token hash verification failed!'),
  'wrapping': (v) => assert.equal(v.error, 'XML digital signature is malformed! Exactly one element must have the attribute Id="Token".'),
  'copied-name': (v) => assert.match(v.error ?? '', /^Signing certificate is not issued by a trusted CA/),
  'ec-key': (v) => assert.equal(v.error, '1 anomaly detected: Token hash signature verification failed!'),
  'replay': (v) => { assert.equal(v.signatureValid, true); assert.equal(v.replay, 'fail'); },
  'expired': (v) => { assert.equal(v.signatureValid, true); assert.equal(v.freshness, 'fail'); },
  'other-audience': (v) => assert.equal(v.error, "Token is not addressed to the expected audience! Expected: 'receiver'. Token audience: 'mail'."),
  'past-expiry': (v) => { assert.equal(v.signatureValid, true); assert.equal(v.freshness, 'fail'); },
  'doctype': (v) => assert.equal(v.error, 'XML Digital Signature must not have a document type declaration (DOCTYPE)!'),
  'ciphertext': (v) => assert.equal(v.error, 'Token decryption failed!'),
  'untrusted-ca': (v) => assert.match(v.error ?? '', /^Signing certificate is not issued by a trusted CA/),
  'script': (v) => {
    assert.equal(v.accepted, true);
    assert.equal((v.data as Record<string, unknown>)['note'], '<img src=x onerror="alert(document.domain)"><script>alert(1)</script>');
  },
};

/** PHP gives an empty array where JavaScript gives an empty object. */
function normalize(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.length === 0 ? {} : value.map(normalize);
  }
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, normalize(child)]));
  }
  return value;
}

function compare(ours: Verdict, php: PhpResult, what: string): void {
  const steps = php['steps'] as Record<string, string>;
  assert.deepEqual(normalize({
    accepted: ours.accepted,
    signatureValid: ours.signatureValid,
    error: ours.error,
    anomalies: ours.anomalies,
    freshness: ours.freshness,
    replay: ours.replay,
    data: ours.data,
  }), normalize({
    accepted: php['accepted'],
    signatureValid: php['signatureValid'],
    error: php['error'],
    anomalies: php['anomalies'],
    freshness: steps['freshness'],
    replay: steps['replay'],
    data: php['data'],
  }), what);
}

describe('the attack lab of the PHP library demo', { skip: phpSkip }, () => {
  const ids = Object.keys(EXPECTED);
  const runs = phpSkip === false ? runPhp(ids.map((id) => ({ command: 'attack', id }))) : [];

  test('every attack of the lab is replayed', () => {
    const [catalog] = runPhp([{ command: 'attacks' }]);
    assert.deepEqual(catalog, ids);
  });

  ids.forEach((id, index) => {
    test(`${id}: the same verdict as the PHP library`, () => {
      const run = runs[index] as PhpResult;
      assert.equal(run['exception'], undefined, String(run['exception']));
      const receiver = new Receiver(run['receiver'] as never);

      // The legitimate token is accepted, by both libraries.
      const base = receiver.verify(run['base'] as string);
      assert.equal(base.accepted, true, base.error ?? '');
      compare(base, run['baseVerdict'] as PhpResult, 'legitimate token');

      // The replay attack submits the token to the receiver that has
      // accepted it; the others, to a receiver that has not seen it.
      const verdict = (id === 'replay' ? receiver : new Receiver(run['receiver'] as never)).verify(run['forged'] as string);
      (EXPECTED[id] as (verdict: Verdict) => void)(verdict);
      if (id !== 'script') {
        assert.equal(verdict.accepted, false);
      }
      compare(verdict, run['verdict'] as PhpResult, 'forged token');
    });
  });
});
