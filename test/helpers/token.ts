/**
 * Tokens for the tests: creation with this library or with the PHP one,
 * alteration of their XML, signature again with the trusted key (by the PHP
 * library, so that a forged token does not depend on the code under test),
 * and the comparison of an analysis with the analysis of the PHP library.
 */

import assert from 'node:assert/strict';

import { DOMParser, XMLSerializer, type Document, type Element } from '@xmldom/xmldom';
import xpath from 'xpath';

import { XMLDSigToken, type TokenData, type TokenOptions } from '../../dist/token/index.js';
import { phpSkip, runPhp, type PhpResult } from './php.ts';

export const CERTS = 'test/fixtures/certs';
export const TRUST = 'test/fixtures/trust';
export const DEMO = 'test/fixtures/demo-certs';
export const SIGN_KEY_PASSWORD = 'signKeyPassword';

export const DSIG_NS = 'http://www.w3.org/2000/09/xmldsig#';
export const XENC_NS = 'http://www.w3.org/2001/04/xmlenc#';

/** The trusted intermediate and root of test/fixtures/certs/. */
export const ANCHOR = [`${CERTS}/intermediate.cert.pem`, `${CERTS}/root.cert.pem`];

/** The issuer of sign.cert.pem. */
export const INTERMEDIATE_DN = {
  C: 'DK',
  ST: 'Jylland',
  O: 'Lothbrok Ltd',
  OU: 'Shield Wall Dept',
  CN: 'www.lothbrok.dk',
  emailAddress: 'ivar@lothbrok.dk',
};

/** The options of an analysis that trusts test/fixtures/certs/. */
export function trustAnchor(options: TokenOptions = {}): TokenOptions {
  return { caCertPath: ANCHOR, ...options };
}

export function sampleData(): TokenData {
  return { name: 'Ragnar Lothbrok', role: 'Jarl', location: 'Kattegat' };
}

/** Creates a signed token with the test signing certificate. */
export function createToken(data: TokenData = sampleData(), options: TokenOptions = {}): XMLDSigToken {
  return XMLDSigToken.createXMLToken(data, `${CERTS}/sign.key.pem`, `${CERTS}/sign.cert.pem`, SIGN_KEY_PASSWORD, options);
}

const select = xpath.useNamespaces({ ds: DSIG_NS, xenc: XENC_NS });

/** The first node an XPath expression selects. */
export function node(doc: Document | Element, expression: string): Element {
  const found = select(expression, doc as never) as unknown as Element[];
  assert.ok(found.length > 0, `No node for ${expression}`);
  return found[0] as Element;
}

/**
 * Alters the XML of a token with a function that receives its document and
 * its node "Token", if any.
 */
export function alter(xml: string, change: (doc: Document, token: Element | null) => void): string {
  const doc = new DOMParser().parseFromString(xml, 'text/xml');
  const tokens = select('/ds:Signature/ds:Object/Token', doc as never) as unknown as Element[];
  change(doc, tokens[0] ?? null);
  return new XMLSerializer().serializeToString(doc);
}

/** Replaces the text of the child of the token node, or adds it. */
export function setChild(token: Element, name: string, value: string): void {
  const doc = token.ownerDocument as Document;
  let child = Array.from(token.childNodes).find((n) => n.nodeName === name) as Element | undefined;
  if (child === undefined) {
    child = doc.createElement(name);
    token.appendChild(child);
  }
  while (child.firstChild !== null) {
    child.removeChild(child.firstChild);
  }
  child.appendChild(doc.createTextNode(value));
}

/** A UTC date, `offset` seconds from now, in the format of the token. */
export function utc(offset: number): string {
  return new Date(Math.floor(Date.now() / 1000 + offset) * 1000).toISOString().replace(/\.\d{3}Z$/, 'Z');
}

export type ForgeStep =
  | { op: 'redigest' }
  | { op: 'resign'; key: string; password?: string | null; cert: string }
  | { op: 'replaceCertificate'; cert: string }
  | { op: 'encrypt'; cert: string; cipher: string; keyTransport: string; type: 'Element' | 'Content' }
  | { op: 'encryptPlaintext'; cert: string; plaintext: string };

/** The steps that sign a token again with the trusted signing key. */
export const SIGN_AGAIN: ForgeStep[] = [
  { op: 'redigest' },
  { op: 'resign', key: `${CERTS}/sign.key.pem`, password: SIGN_KEY_PASSWORD, cert: `${CERTS}/sign.cert.pem` },
];

/** Alters tokens with the class Forge of the PHP library demo. */
export function forge(jobs: Array<{ xml: string; steps: ForgeStep[] }>): string[] {
  return runPhp(jobs.map(({ xml, steps }) => ({ command: 'forge', xml, steps }))).map((result) => {
    assert.equal(result['exception'], undefined, String(result['exception']));
    return result['xml'] as string;
  });
}

/** Alters a token, then signs it again with the trusted signing key, as the
trusted issuer would have created it. */
export function signAgain(xml: string, change: (doc: Document, token: Element | null) => void = () => {}): string {
  return forge([{ xml: alter(xml, change), steps: SIGN_AGAIN }])[0] as string;
}

/** An analysis to compare with the PHP library. */
export interface Analysis {
  xml: string;
  options?: TokenOptions;
  cryptKey?: string;
  cryptKeyPassword?: string | null;
  ttl?: number;
}

/** What the accessors of a token return, as the PHP bridge gives them. */
export function summarize(token: XMLDSigToken, ttl = 60): PhpResult {
  return {
    isSignatureValid: token.isSignatureValid(),
    isDigestValueOk: token.isDigestValueOk(),
    isSignatureValueOk: token.isSignatureValueOk(),
    isCertTrusted: token.isCertTrusted(),
    isDataEncrypted: token.isDataEncrypted(),
    isOutOfDate: token.isOutOfDate(ttl),
    error: token.getError(),
    anomalies: token.getAnomalies(),
    data: token.getData(),
    timestamp: token.getTimestamp(),
    tokenId: token.getTokenId(),
    audience: token.getAudience(),
    expiry: token.getExpiry(),
    certDN: token.getCertDN(),
    certSubject: token.getCertSubject(),
    certIssuer: token.getCertIssuer(),
    certValidFrom: token.getCertValidFrom(),
    certValidTo: token.getCertValidTo(),
    prettyXml: token.getPrettyXML(),
  };
}

/** What the accessors of a token return, `isOutOfDate()` evaluated at the
given time (in seconds since the UNIX epoch). */
function summarizeAt(token: XMLDSigToken, ttl: number | undefined, now: number): PhpResult {
  const realNow = Date.now;
  Date.now = () => now * 1000;
  try {
    return summarize(token, ttl);
  } finally {
    Date.now = realNow;
  }
}

/** The analyses made by the tests, compared with the PHP library at the end
of each test file (see `compareWithPhp()`). */
const analyses: Array<{ name: string; analysis: Analysis; token: XMLDSigToken }> = [];

/**
 * Analyzes a token with this library, and records the analysis to compare
 * it with the PHP library.
 */
export function analyze(name: string, analysis: Analysis): XMLDSigToken {
  const token = analysis.cryptKey === undefined
    ? XMLDSigToken.analyzeXMLToken(analysis.xml, analysis.options ?? {})
    : XMLDSigToken.analyzeSecureXMLToken(analysis.xml, analysis.cryptKey, analysis.cryptKeyPassword ?? null, analysis.options ?? {});
  analyses.push({ name, analysis, token });
  return token;
}

/** PHP gives an empty array where JavaScript gives an empty object, and
the PHP bridge gives bytes as {"bytes": base64}. */
function normalize(value: unknown): unknown {
  if (Buffer.isBuffer(value)) {
    return { bytes: value.toString('base64') };
  }
  if (Array.isArray(value)) {
    return value.length === 0 ? {} : value.map(normalize);
  }
  if (value !== null && typeof value === 'object' && !Buffer.isBuffer(value)) {
    return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, normalize(child)]));
  }
  return value;
}

/**
 * Compares every analysis recorded by `analyze()` with the analysis of the
 * same token, with the same options, by the PHP library: the verdict, the
 * error, the anomalies, and everything the accessors return.
 *
 * @param except Accessors not compared, with the reason, by name of
 *     analysis.
 */
export function compareWithPhp(test: (name: string, options: { skip: string | false }, run: () => void) => void, except: Record<string, string[]> = {}): void {
  test('the PHP library gives the same results on every analysis', { skip: phpSkip }, () => {
    const results = runPhp(analyses.map(({ analysis }) => ({
      command: 'analyze',
      xml: analysis.xml,
      options: analysis.options ?? {},
      ...(analysis.cryptKey === undefined ? {} : { cryptKey: analysis.cryptKey, cryptKeyPassword: analysis.cryptKeyPassword ?? null }),
      ...(analysis.ttl === undefined ? {} : { ttl: analysis.ttl }),
    })));
    assert.ok(analyses.length > 0, 'No analysis was recorded.');
    analyses.forEach(({ name, analysis, token }, index) => {
      const php = { ...(results[index] as PhpResult) };
      // isOutOfDate() depends on the current time: it is evaluated here at
      // the very second the PHP library evaluated it.
      const ours = summarizeAt(token, analysis.ttl, php['now'] as number);
      delete php['now'];
      assert.deepEqual(php['phpMessages'], [], `${name}: the PHP library emitted messages`);
      delete php['phpMessages'];
      delete php['xml'];
      const mine = { ...ours };
      for (const key of Object.hasOwn(except, name) ? except[name] as string[] : []) {
        delete php[key];
        delete mine[key];
      }
      assert.deepEqual(normalize(mine), normalize(php), name);
    });
    console.log(`# ${analyses.length} analyses compared with the PHP library`);
  });
}
