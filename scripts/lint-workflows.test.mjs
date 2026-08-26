import { spawnSync } from 'node:child_process';
import { chmodSync, mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
import test from 'node:test';

const rootDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const scriptPath = path.join(rootDirectory, 'scripts', 'lint-workflows.mjs');

/**
 * @param {string} cacheDirectory
 * @returns {ReturnType<typeof spawnSync>}
 */
function runLintWorkflows(cacheDirectory) {
  return spawnSync(process.execPath, [scriptPath], {
    cwd: rootDirectory,
    env: {
      ...process.env,
      PATCHPILOT_ACTIONLINT_CACHE_DIR: cacheDirectory,
      PATCHPILOT_ACTIONLINT_ALLOW_DOWNLOAD: 'false',
    },
    encoding: 'utf8',
  });
}

test('does not execute a cached actionlint binary that fails SHA-256 verification', () => {
  const cacheRoot = mkdtempSync(path.join(os.tmpdir(), 'patchpilot-actionlint-test-'));
  const binaryDirectory = path.join(cacheRoot, '1.7.12');
  mkdirSync(binaryDirectory, { recursive: true });
  const binaryPath = path.join(binaryDirectory, 'actionlint');
  writeFileSync(binaryPath, 'not-a-trusted-actionlint-binary\n');
  chmodSync(binaryPath, 0o755);

  try {
    const result = runLintWorkflows(cacheRoot);
    const output = `${result.stdout}${result.stderr}`;

    assert.notEqual(result.status, 0, output);
    assert.match(output, /failed SHA-256 verification/);
    assert.match(output, /will not be executed/);
    assert.match(output, /downloads are disabled/);
    assert.doesNotMatch(output, /Exec format error/);
  } finally {
    rmSync(cacheRoot, { recursive: true, force: true });
  }
});

test('does not download or run actionlint when the cache is empty and downloads are disabled', () => {
  const cacheRoot = mkdtempSync(path.join(os.tmpdir(), 'patchpilot-actionlint-empty-'));

  try {
    const result = runLintWorkflows(cacheRoot);
    const output = `${result.stdout}${result.stderr}`;

    assert.notEqual(result.status, 0, output);
    assert.match(output, /Trusted actionlint binary is not available and downloads are disabled/);
  } finally {
    rmSync(cacheRoot, { recursive: true, force: true });
  }
});
