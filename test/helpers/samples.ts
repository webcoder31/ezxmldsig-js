/**
 * The sample seals: the seals made here that the verifiers apart from this
 * library check, the same as those of the PHP library (sampleSeals() in its
 * tests/SealTestCase.php): each algorithm at level B, each level with
 * RSA 3072, and level LT with an EC key.
 */

import * as alg from '../../dist/seal/algorithms.js';
import { addSignatureTimestamp, timestampRequest } from '../../dist/seal/extend.js';
import { createSeal, type SealFile, type SealOptions } from '../../dist/seal/seal.js';
import { addValidationData } from '../../dist/seal/validation.js';
import { currentCrls, makeCrl } from './crl.ts';
import { makeOcspResponse } from './ocsp.ts';
import { timestampResponse } from './tsa.ts';

const CERTS = 'test/fixtures/seal/certs';
const PASSWORD = 'signKeyPassword';

/** The trust of the tests: the root of the signers and that of the authority. */
export const SAMPLE_TRUST = { caCertPath: `${CERTS}/root.cert.pem`, tsaCertPath: `${CERTS}/tsa-root.cert.pem` };

/**
 * The files of the sample seals: names a verifier could get wrong (spaces,
 * accents, a directory, # and %), and a media type with parameters.
 */
export const SAMPLE_FILES: SealFile[] = [
  { name: 'contrat final.pdf', content: Buffer.from('%PDF-1.4\n') },
  { name: "notes d'été.md", content: Buffer.from("# Notes d'été\n") },
  { name: 'docs/a#b%c.txt', content: Buffer.from('odd name\n') },
  { name: 'data.bin', content: Buffer.from([0, 1, 2, 255]), mimeType: 'application/x-test; charset="none"' },
];

/** The names of the sample seals: the level, then the key and the algorithms. */
export const SAMPLE_SEALS = [
  'B, RSA 3072, RSA-PSS', 'B, RSA 3072, PKCS#1 v1.5', 'B, RSA 2048, SHA-512 digests', 'B, P-256', 'B, P-384', 'B, P-521',
  'T, RSA 3072', 'LT by CRLs, RSA 3072', 'LT by OCSP, RSA 3072', 'LT by CRLs, P-384',
] as const;

export interface SampleSeal {
  container: Buffer;
  /** The certificate of the signer. */
  cert: string;
  level: 'B' | 'T' | 'LT';
  /** The CRLs its verifier needs: none at level LT, the seal embeds its own. */
  crls: Buffer[];
}

/**
 * A sample seal of SAMPLE_SEALS, of the files of SAMPLE_FILES. It is signed
 * 30 seconds ago and time-stamped 20 seconds ago, before its validation data
 * is issued.
 */
export function sampleSeal(name: (typeof SAMPLE_SEALS)[number]): SampleSeal {
  const [level, ...rest] = name.split(', ');
  const what = rest.join(', ');
  const now = Date.now();
  const options: SealOptions = { signingTime: new Date(now - 30_000) };
  let key = 'rsa3072';
  if (what === 'RSA 3072, PKCS#1 v1.5') {
    Object.assign(options, { signatureAlgorithm: alg.RSA_SHA256 });
  } else if (what === 'RSA 2048, SHA-512 digests') {
    key = 'rsa2048';
    Object.assign(options, { digestAlgorithm: alg.SHA512 });
  } else if (what !== 'RSA 3072, RSA-PSS' && what !== 'RSA 3072') {
    key = what.replace('-', '').toLowerCase();
  }
  const dir = key === 'p521' ? 'test/fixtures/seal/p521' : CERTS;
  const cert = `${dir}/${key}.cert.pem`;
  let container = createSeal(SAMPLE_FILES, `${dir}/${key}.key.pem`, cert, PASSWORD, { chain: [`${CERTS}/intermediate.cert.pem`], ...options });
  if (level !== 'B') {
    container = addSignatureTimestamp(container, timestampResponse(timestampRequest(container), { time: new Date(now - 20_000) }), { tsaCertPath: SAMPLE_TRUST.tsaCertPath });
  }
  if (level === 'LT by CRLs') {
    container = addValidationData(container, { ...SAMPLE_TRUST, crls: currentCrls() });
  }
  if (level === 'LT by OCSP') {
    container = addValidationData(container, {
      ...SAMPLE_TRUST,
      crls: [makeCrl({ issuer: 'root' }), makeCrl({ issuer: 'tsa-root' })],
      ocspResponses: [makeOcspResponse({ cert: key, signer: 'ocsp' })],
    });
  }
  const lt = level?.startsWith('LT') === true;
  return { container, cert, level: lt ? 'LT' : (level as 'B' | 'T'), crls: lt ? [] : currentCrls() };
}
