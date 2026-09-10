import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const script = path.join(root, 'scripts/run-osv-listing-canary.mjs');

/**
 * @param {string[]} args
 */
function run(args) {
  return spawnSync(process.execPath, [script, ...args], {
    encoding: 'utf8',
    cwd: root,
  });
}

describe('run-osv-listing-canary argv', () => {
  it('rejects unknown arguments and retry/body/pagination options without spawning provider work', () => {
    const unknown = run(['dry-run', '--retry']);
    assert.notEqual(unknown.status, 0);
    const body = run(['execute-one-listing-request', '--body']);
    assert.notEqual(body.status, 0);
    const missingAck = run(['execute-one-listing-request']);
    assert.notEqual(missingAck.status, 0);
  });
});
