/**
 * Seals made here, validated by DSS (test/helpers/dss.ts), a validator apart
 * from this library: the sample seals (test/helpers/samples.ts), the same as
 * those of the tests of the PHP library, of the profile XAdES-BASELINE of
 * their level, and a seal whose file was changed, refused. A seal of level
 * LT is validated by the revocation data it embeds; DSS fetches the CRLs of
 * the others at pki.ezxmlseal.test. The cases of DSS proper to this
 * library (a time-stamp of OpenSSL, the offline PKI, the revocation DSS
 * fetches) stay in the files of their subject.
 */

import assert from 'node:assert/strict';
import { before, describe, test } from 'node:test';

import { readZip, writeZip } from '../../dist/seal/zip.js';
import { dssSkip, publishTestCrls, validateWithDss } from '../helpers/dss.ts';
import { SAMPLE_FILES, SAMPLE_SEALS, sampleSeal } from '../helpers/samples.ts';

const ROOT = 'CN=Lothbrok Seal Test,OU=Seal Root CA,O=Lothbrok Ltd,C=DK';
const TSA_ROOT = 'CN=Lothbrok Seal Test,OU=TSA Root CA,O=Lothbrok Ltd,C=DK';
const names = SAMPLE_FILES.map((file) => file.name);

describe('validation by DSS of the sample seals', { skip: dssSkip }, () => {
  before(publishTestCrls);

  for (const name of SAMPLE_SEALS) {
    test(name, async () => {
      const seal = sampleSeal(name);
      const report = await validateWithDss(seal.container);
      assert.equal(report.containerType, 'ASiC-E');
      assert.equal(report.signatures.length, 1);
      const signature = report.signatures[0];
      assert.equal(signature?.format, `XAdES-BASELINE-${seal.level}`);
      assert.deepEqual(signature?.scope, names);
      assert.equal(signature?.signatureIntact, true);
      assert.equal(signature?.references.length, names.length + 1);
      assert.ok(signature?.references.every((r) => r.found && r.intact), JSON.stringify(signature?.references));
      assert.ok(signature?.trusted.includes(ROOT));
      if (seal.level !== 'B') {
        assert.ok(signature?.trusted.includes(TSA_ROOT));
      }
      assert.equal(signature?.indication, 'TOTAL_PASSED', JSON.stringify(signature?.errors));
      assert.deepEqual(signature?.errors, []);
      if (seal.level === 'LT') {
        // The signer, the intermediate and the authority, by what the seal embeds.
        assert.equal(report.revocationOrigins.filter((origin) => origin === 'INPUT_DOCUMENT').length, 3, JSON.stringify(report.revocationOrigins));
      }
    });
  }

  test('a sample seal whose file was changed is refused', async () => {
    const container = writeZip(readZip(sampleSeal('B, RSA 3072, RSA-PSS').container).map((e) => ({
      name: e.name,
      content: e.name === 'contrat final.pdf' ? Buffer.from('%PDF-1.5\n') : e.content,
      stored: e.method === 0,
    })));
    const signature = (await validateWithDss(container)).signatures[0];
    assert.equal(signature?.indication, 'TOTAL_FAILED');
    assert.equal(signature?.subIndication, 'HASH_FAILURE');
  });
});
