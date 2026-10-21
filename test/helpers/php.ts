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
  command: 'create' | 'analyze' | 'constants';
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

/** Runs the requests in one container, and returns one result per request. */
export function runPhp(requests: PhpRequest[]): PhpResult[] {
  const run = spawnSync(SCRIPT, {
    cwd: ROOT_DIR,
    input: JSON.stringify(requests),
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });
  if (run.status !== 0) {
    throw new Error(`bin/php-ezxmldsig failed (status ${run.status}): ${run.stderr}`);
  }
  const results: unknown = JSON.parse(run.stdout);
  if (!Array.isArray(results) || results.length !== requests.length) {
    throw new Error(`bin/php-ezxmldsig returned ${results} for ${requests.length} requests.`);
  }
  return results as PhpResult[];
}
