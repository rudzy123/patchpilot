import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
import test from 'node:test';

const rootDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const scriptPath = path.join(rootDirectory, 'scripts', 'release-dry-run-summary.mjs');

test('release dry-run summary reports foundation version and no publishing', () => {
  const result = spawnSync(process.execPath, [scriptPath], {
    cwd: rootDirectory,
    env: {
      ...process.env,
      REF_NAME: 'ci/github-workflows',
      SHA: 'abc123',
      RUN_ID: '99',
      RUN_ATTEMPT: '2',
    },
    encoding: 'utf8',
  });

  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /Root package version: 0\.0\.0/);
  assert.match(result.stdout, /does not publish packages/);
  assert.match(result.stdout, /patchpilot-sbom-99-2/);
  assert.doesNotMatch(result.stdout, /ghp_/);
  assert.doesNotMatch(result.stdout, /BEGIN PRIVATE KEY/);
});
