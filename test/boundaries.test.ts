/**
 * The boundaries of the branches of the package: the core imports neither
 * the tokens nor the seals, and the tokens and the seals do not import each
 * other. The imports are read from the sources, not taken from the build;
 * the subpaths are resolved by Node.js itself, through the name of the
 * package.
 */

import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { test } from 'node:test';

const SRC = resolve('src');
const BRANCHES = ['core', 'token', 'seal'];
const ALLOWED: Record<string, string[]> = { core: ['core'], token: ['core', 'token'], seal: ['core', 'seal'] };

function sources(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = join(dir, entry.name);
    return entry.isDirectory() ? sources(path) : entry.name.endsWith('.ts') ? [path] : [];
  });
}

/** The branch of a file of src/, or null if it is in none. */
const branchOf = (path: string) => {
  const [first, ...rest] = relative(SRC, path).split('/');
  return rest.length > 0 && BRANCHES.includes(first as string) ? first as string : null;
};

test('every source is in a branch', () => {
  assert.deepEqual(sources(SRC).filter((path) => branchOf(path) === null).map((path) => relative('.', path)), []);
});

test('each branch imports only the branches it may', () => {
  const crossings: string[] = [];
  for (const path of sources(SRC)) {
    const from = branchOf(path) as string;
    const text = readFileSync(path, 'utf8');
    for (const [, specifier] of text.matchAll(/(?:from|import)\s*\(?\s*'(\.[^']*)'/g)) {
      const to = branchOf(resolve(dirname(path), specifier as string));
      if (to === null || !ALLOWED[from]?.includes(to)) {
        crossings.push(`${relative('.', path)} imports ${specifier}`);
      }
    }
  }
  assert.deepEqual(crossings, []);
});

test('the package exports the three branches, and nothing else', async () => {
  const exports = JSON.parse(readFileSync('package.json', 'utf8')).exports as Record<string, unknown>;
  assert.deepEqual(Object.keys(exports), ['./core', './token', './seal']);
  assert.equal(typeof (await import('@webcoder31/ezxmldsig/core')).X509Cert, 'function');
  assert.equal(typeof (await import('@webcoder31/ezxmldsig/token')).XMLDSigToken, 'function');
  assert.equal(typeof (await import('@webcoder31/ezxmldsig/seal')).verifySeal, 'function');
  for (const specifier of ['@webcoder31/ezxmldsig', '@webcoder31/ezxmldsig/dist/core/der.js', '@webcoder31/ezxmldsig/core/der']) {
    await assert.rejects(import(specifier), { code: 'ERR_PACKAGE_PATH_NOT_EXPORTED' }, specifier);
  }
});
