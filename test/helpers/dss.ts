/**
 * Validation of seals by DSS (Digital Signature Service, the validator of
 * the European Commission), which does not go through the code under test.
 *
 * DSS runs at DSS_URL, which bin/test (npm test) sets when it starts DSS
 * with bin/dss, unless DSS=0: built from the Dockerfile of
 * esig/dss-demonstrations, it trusts test/fixtures/seal/certs/root.cert.pem
 * and tsa-root.cert.pem, and reaches the CRL and OCSP of the test PKI at
 * pki.ezxmlseal.test.
 *
 * The tests that need it are skipped, with the reason, when DSS_URL is not
 * set (DSS=0, or the tests run without bin/test), or when DSS does not
 * answer there. In continuous integration (CI=true), with DSS_URL set, they
 * fail instead if DSS does not answer: the workflow
 * .github/workflows/dss.yml runs them, and fails if any is skipped.
 */

import { mkdirSync, renameSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { makeCrl } from './crl.ts';

export const DSS_URL = process.env['DSS_URL'] ?? '';

/** Why the DSS tests are skipped, or false when they run. */
export const dssSkip: string | false = await (async () => {
  if (DSS_URL === '') {
    return process.env['DSS'] === '0'
      ? 'DSS=0: DSS is not started.'
      : 'DSS_URL is not set: run the tests with npm test (bin/test), which starts DSS.';
  }
  if (process.env['CI'] === 'true') {
    return false;
  }
  try {
    const response = await fetch(DSS_URL, { signal: AbortSignal.timeout(3000) });
    return response.ok ? false : `DSS answers ${response.status} at ${DSS_URL}.`;
  } catch {
    return `DSS does not answer at ${DSS_URL}.`;
  }
})();

/** What the tests read from the reports of DSS, for one signature. */
export interface DssSignature {
  /** The format, such as XAdES-BASELINE-B. */
  readonly format: string;
  readonly indication: string;
  readonly subIndication: string | null;
  /** The names of the files the signature covers. */
  readonly scope: string[];
  /** The errors of the AdES validation (the qualification, which needs an EU trusted list, is left out). */
  readonly errors: string[];
  readonly signatureIntact: boolean;
  /** Each reference: found and intact. */
  readonly references: { type: string; found: boolean; intact: boolean }[];
  /** The subjects of the certificates DSS trusts, among those it used. */
  readonly trusted: string[];
}

export interface DssReport {
  readonly containerType: string | null;
  readonly signatures: DssSignature[];
  /** Where each revocation data DSS used comes from: INPUT_DOCUMENT (the seal), EXTERNAL (fetched)… */
  readonly revocationOrigins: string[];
}

type Json = Record<string, any>;

/** Sends a container to DSS, with its default validation policy. */
export async function validateWithDss(container: Buffer, name = 'seal.asice'): Promise<DssReport> {
  const response = await fetch(`${DSS_URL}/services/rest/validation/validateSignature`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
    body: JSON.stringify({ signedDocument: { bytes: container.toString('base64'), name }, originalDocuments: [], policy: null, signatureId: null }),
    signal: AbortSignal.timeout(120_000),
  });
  if (!response.ok) {
    throw new Error(`DSS answered ${response.status}: ${await response.text()}`);
  }
  const report = (await response.json()) as Json;
  const simple = report['SimpleReport'] as Json;
  const diagnostic = report['DiagnosticData'] as Json;
  const values = (list: unknown): string[] => ((list as Json[] | null) ?? []).map((item) => (typeof item === 'string' ? item : item['value']));
  const trusted = ((diagnostic['Certificate'] as Json[] | null) ?? [])
    .filter((cert) => cert['Trusted']?.['value'] === true)
    .map((cert) => (cert['SubjectDistinguishedName'] as Json[]).find((name) => name['Format'] === 'RFC2253')?.['value'] as string);
  const signatures = ((simple['signatureOrTimestampOrEvidenceRecord'] as Json[] | null) ?? []).map((entry) => {
    const signature = (entry['Signature'] ?? entry) as Json;
    const diag = ((diagnostic['Signature'] as Json[]) ?? []).find((s) => s['Id'] === signature['Id']) ?? {};
    return {
      format: signature['SignatureFormat'],
      indication: signature['Indication'],
      subIndication: signature['SubIndication'] ?? null,
      scope: ((signature['SignatureScope'] as Json[] | null) ?? []).map((scope) => scope['name']),
      errors: values(signature['AdESValidationDetails']?.['Error']),
      signatureIntact: diag['BasicSignature']?.['SignatureIntact'] === true && diag['BasicSignature']?.['SignatureValid'] === true,
      references: ((diag['DigestMatcher'] as Json[] | null) ?? []).map((matcher) => ({
        type: matcher['type'],
        found: matcher['DataFound'] === true,
        intact: matcher['DataIntact'] === true,
      })),
      trusted,
    };
  });
  const revocationOrigins = ((diagnostic['Revocation'] as Json[] | null) ?? []).map((revocation) => revocation['Origin'] as string);
  return { containerType: simple['ContainerType'] ?? null, signatures, revocationOrigins };
}

/** The directory bin/dss serves at http://pki.ezxmlseal.test/, on the network of DSS. */
const PKI_DIR = fileURLToPath(new URL('../.cache/dss/pki/', import.meta.url));

/** The certificate the published CRLs revoke; no other one is. */
export const REVOKED = 'revoked';

/**
 * Publishes the CRLs of the test PKI where its certificates say they are:
 * intermediate.crl (the seal certificates), root.crl (the intermediate CA),
 * tsa-root.crl (the time-stamping authority). Every test file publishes
 * the same ones, which revoke test/fixtures/seal/certs/revoked.cert.pem
 * only: the test files run at the same time, and none of them changes what
 * another one is validating. DSS keeps them one second in its cache
 * (bin/dss): the promise resolves once it is past.
 */
export async function publishTestCrls(): Promise<void> {
  mkdirSync(PKI_DIR, { recursive: true });
  const crls = {
    'intermediate': makeCrl({ revoked: [{ cert: REVOKED, date: new Date(Date.now() - 3_600_000) }] }),
    'root': makeCrl({ issuer: 'root' }),
    'tsa-root': makeCrl({ issuer: 'tsa-root' }),
  };
  for (const [name, crl] of Object.entries(crls)) {
    writeFileSync(`${PKI_DIR}${name}.crl.part`, crl);
    renameSync(`${PKI_DIR}${name}.crl.part`, `${PKI_DIR}${name}.crl`);
  }
  await new Promise((resolve) => setTimeout(resolve, 1500));
}
