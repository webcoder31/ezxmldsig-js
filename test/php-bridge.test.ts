/**
 * The bridge to the PHP library ezxmldsig, which the tests of the
 * interoperability use, and the constants both libraries share.
 */

import assert from 'node:assert/strict';
import { test } from 'node:test';

import * as ezxmldsig from '../dist/index.js';
import { phpSkip, runPhp } from './helpers/php.ts';

const CERTS = 'test/fixtures/certs';

test('the algorithm constants have the values of the PHP library', { skip: phpSkip }, () => {
  const [phpConstants] = runPhp([{ command: 'constants' }]) as [Record<string, unknown>];
  const ours = Object.entries(ezxmldsig).filter(([, value]) => typeof value === 'string' && value.startsWith('http'));

  assert.ok(ours.length > 0);
  for (const [name, value] of ours) {
    if (name === 'XMLDSIG_NS' || name === 'XMLENC_NS') {
      continue;
    }
    assert.equal(value, phpConstants[name], name);
  }
});

test('the PHP library creates and analyzes signed and encrypted tokens', { skip: phpSkip }, () => {
  const sign = {
    signKey: `${CERTS}/sign.key.pem`,
    signCert: `${CERTS}/sign.cert.pem`,
    signKeyPassword: 'signKeyPassword',
  };
  const [signed, encrypted] = runPhp([
    { command: 'create', data: { name: 'Ragnar Lothbrok' }, ...sign },
    { command: 'create', data: { name: 'Ragnar Lothbrok' }, ...sign, cryptCert: `${CERTS}/crypt.cert.pem` },
  ]);
  assert.equal(signed?.['isSignatureValid'], true, String(signed?.['error']));
  assert.equal(encrypted?.['isSignatureValid'], true, String(encrypted?.['error']));

  const trust = { caCertPath: [`${CERTS}/intermediate.cert.pem`, `${CERTS}/root.cert.pem`] };
  const [analyzed, decrypted, untrusted] = runPhp([
    { command: 'analyze', xml: signed?.['xml'], options: trust },
    { command: 'analyze', xml: encrypted?.['xml'], cryptKey: `${CERTS}/crypt.key.pem`, options: trust },
    { command: 'analyze', xml: signed?.['xml'], options: {} },
  ]);
  assert.equal(analyzed?.['isSignatureValid'], true, String(analyzed?.['error']));
  assert.deepEqual(analyzed?.['data'], { name: 'Ragnar Lothbrok' });
  assert.equal(decrypted?.['isSignatureValid'], true, String(decrypted?.['error']));
  assert.deepEqual(decrypted?.['data'], { name: 'Ragnar Lothbrok' });
  assert.equal(untrusted?.['isSignatureValid'], false);
  assert.match(String(untrusted?.['error']), /^No trust anchor!/);
});
