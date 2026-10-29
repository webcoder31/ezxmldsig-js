/**
 * Seals made here, verified by the PHP library ezxmldsig, under PHP 7.4 and
 * 8.3 (test/helpers/php.ts): the sample seals (test/helpers/samples.ts),
 * valid at their level, with the verdict of this library, and a seal whose
 * file was changed, refused by both. The error messages are not compared,
 * only whether there is one.
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { describe, test } from 'node:test';

import { X509Cert } from '../../dist/core/x509.js';
import { verifySeal } from '../../dist/seal/verify.js';
import { readZip, writeZip } from '../../dist/seal/zip.js';
import { PHP_VERSIONS, phpSkip, runPhp, type PhpResult } from '../helpers/php.ts';
import { SAMPLE_FILES, SAMPLE_SEALS, SAMPLE_TRUST, sampleSeal } from '../helpers/samples.ts';

const bytes = (buffer: Buffer) => ({ bytes: buffer.toString('base64') });

/** The verdicts of the PHP library: see "verifySeal" in test/php/ezxmldsig.php. */
function verifyInPhp(seals: { container: Buffer; crls: Buffer[] }[], version: string): PhpResult[] {
  const results = runPhp(seals.map(({ container, crls }) => ({
    command: 'verifySeal' as const,
    container: bytes(container),
    options: { ...SAMPLE_TRUST, crls: crls.map(bytes) },
  })), version);
  results.forEach((result) => assert.ok('valid' in result, String(result['exception'])));
  return results;
}

/** The verdict of this library, in the form of verifyInPhp(). */
function verifyHere(container: Buffer, crls: Buffer[]) {
  const result = verifySeal(container, { ...SAMPLE_TRUST, crls });
  return {
    valid: result.isValid(),
    error: result.getError(),
    level: result.getLevel(),
    files: result.getFiles(),
    signingTime: result.getSigningTime()?.toISOString() ?? null,
    timestampTime: result.getTimestampTime()?.toISOString() ?? null,
    signer: result.getSigningCertificate()?.getDN() ?? null,
    revocationChecked: result.isRevocationChecked(),
  };
}

/** The container with the content of the first file changed. */
function changeFirstFile(container: Buffer): Buffer {
  return writeZip(readZip(container).map((e) => ({
    name: e.name,
    content: e.name === 'contrat final.pdf' ? Buffer.from('%PDF-1.5\n') : e.content,
    stored: e.method === 0,
  })));
}

for (const version of PHP_VERSIONS) {
  describe(`verified by the PHP library, under PHP ${version}`, { skip: phpSkip }, () => {
    test('the sample seals are valid at their level, with the verdict of this library', () => {
      const seals = SAMPLE_SEALS.map((name) => ({ name, ...sampleSeal(name) }));
      const verdicts = verifyInPhp(seals, version);
      seals.forEach((seal, index) => {
        const php = verdicts[index] as PhpResult;
        assert.equal(php['error'], null, seal.name);
        assert.equal(php['valid'], true, seal.name);
        assert.equal(php['level'], seal.level, seal.name);
        assert.equal(php['revocationChecked'], true, seal.name);
        const files = php['files'] as { name: string; mimeType: string }[];
        assert.deepEqual(files.map((file) => file.name), SAMPLE_FILES.map((file) => file.name), seal.name);
        assert.equal(files[3]?.mimeType, SAMPLE_FILES[3]?.mimeType, seal.name);
        assert.equal(php['signer'], new X509Cert(readFileSync(seal.cert, 'utf8')).getDN(), seal.name);
        assert.deepEqual(php, verifyHere(seal.container, seal.crls), seal.name);
      });
    });

    test('a sample seal whose file was changed is refused by both', () => {
      const seal = sampleSeal('B, RSA 3072, RSA-PSS');
      const container = changeFirstFile(seal.container);
      const [php] = verifyInPhp([{ container, crls: seal.crls }], version);
      assert.equal(php?.['valid'], false);
      assert.notEqual(php?.['error'], null);
      assert.equal(verifyHere(container, seal.crls).valid, false);
    });
  });
}
