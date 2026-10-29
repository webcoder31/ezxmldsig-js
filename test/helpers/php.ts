/**
 * Runs requests against the PHP library ezxmldsig, in Docker, through
 * bin/php-ezxmldsig (see test/php/ezxmldsig.php for the requests and their
 * results).
 *
 * The tests that need it are skipped, with the reason, when Docker is not
 * reachable. In continuous integration (CI=true), they fail instead: a run
 * that skipped them has not checked the interoperability.
 */

import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT_DIR = fileURLToPath(new URL('../..', import.meta.url));
const SCRIPT = fileURLToPath(new URL('../../bin/php-ezxmldsig', import.meta.url));

export type PhpRequest = Record<string, unknown> & {
  command: 'create' | 'analyze' | 'cert' | 'forge' | 'attack' | 'attacks' | 'constants' | 'verifySeal';
};

export type PhpResult = Record<string, unknown>;

/** Why the PHP tests are skipped, or false when they run. */
export const phpSkip: string | false = (() => {
  if (process.env['CI'] === 'true') {
    return false;
  }
  const docker = spawnSync('docker', ['info'], { stdio: 'ignore' });
  return docker.status === 0 ? false : 'Docker is not reachable: the PHP library cannot run.';
})();

/** The PHP versions the interoperability is checked with: those the PHP
library supports, its oldest and its latest tested one. */
export const PHP_VERSIONS = ['7.4', '8.3'] as const;

/**
 * Runs the requests in one container, and returns one result per request.
 *
 * @param version The PHP version (default: 8.3, see bin/php-ezxmldsig).
 */
export function runPhp(requests: PhpRequest[], version?: string): PhpResult[] {
  const run = spawnSync(SCRIPT, {
    cwd: ROOT_DIR,
    env: version === undefined ? process.env : { ...process.env, PHP_VERSION: version },
    input: JSON.stringify(requests),
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });
  if (run.status !== 0) {
    throw new Error(`bin/php-ezxmldsig failed (status ${run.status}): ${run.stderr}${run.stdout}`);
  }
  const results: unknown = JSON.parse(run.stdout);
  if (!Array.isArray(results) || results.length !== requests.length) {
    throw new Error(`bin/php-ezxmldsig returned ${results} for ${requests.length} requests.`);
  }
  return results as PhpResult[];
}
