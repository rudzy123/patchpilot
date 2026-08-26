#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { createWriteStream, existsSync, mkdirSync, readFileSync } from 'node:fs';
import { chmod, copyFile, mkdir, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { pipeline } from 'node:stream/promises';
import { fileURLToPath } from 'node:url';
import { spawn, spawnSync } from 'node:child_process';

const ACTIONLINT_VERSION = '1.7.12';

const ARCHIVE_CHECKSUMS = Object.freeze({
  darwin_amd64: '5b44c3bc2255115c9b69e30efc0fecdf498fdb63c5d58e17084fd5f16324c644',
  darwin_arm64: 'aba9ced2dee8d27fecca3dc7feb1a7f9a52caefa1eb46f3271ea66b6e0e6953f',
  linux_amd64: '8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8',
  linux_arm64: '325e971b6ba9bfa504672e29be93c24981eeb1c07576d730e9f7c8805afff0c6',
});

const BINARY_CHECKSUMS = Object.freeze({
  darwin_amd64: 'd1f7cee75ae2873609bd9567b4600bebc5315a5e733e73202987a44fafdd53b2',
  darwin_arm64: '8db11704dc296f096216db4db65d86cd7f0ebfdf4c38453a1da276b137b88388',
  linux_amd64: 'c872d6db8c6bf83a8eaa704fc93999f027d55dffbc63b8a6abdccb47df5f4cd4',
  linux_arm64: 'ac0323433c2853ec3fb978c611430c5b3dc5d43c58d1a1ec031b00ab572beb60',
});

const rootDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const workflowsDirectory = path.join(rootDirectory, '.github', 'workflows');

const REQUIRED_GOVERNANCE_FILES = Object.freeze([
  '.github/CODEOWNERS',
  '.github/dependabot.yml',
  '.github/pull_request_template.md',
  '.github/ISSUE_TEMPLATE/config.yml',
  '.github/ISSUE_TEMPLATE/bug_report.yml',
  '.github/ISSUE_TEMPLATE/feature_request.yml',
  '.github/actions/setup-node-pnpm/action.yml',
  '.github/codeql/codeql-config.yml',
]);

const FORBIDDEN_WORKFLOW_FILES = Object.freeze([
  '.github/workflows/e2e.yml',
  '.github/workflows/container-build.yml',
]);

/**
 * @param {string} message
 * @returns {never}
 */
function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}

/**
 * @returns {void}
 */
function checkGitHubGovernance() {
  for (const relativePath of REQUIRED_GOVERNANCE_FILES) {
    if (!existsSync(path.join(rootDirectory, relativePath))) {
      fail(`Missing required GitHub governance file: ${relativePath}`);
    }
  }

  for (const relativePath of FORBIDDEN_WORKFLOW_FILES) {
    if (existsSync(path.join(rootDirectory, relativePath))) {
      fail(
        `Unexpected workflow ${relativePath}. GitHub-hosted E2E and container-build checks are deferred; do not add placeholder workflows.`,
      );
    }
  }

  const publicVulnerabilityTemplate = path.join(
    rootDirectory,
    '.github',
    'ISSUE_TEMPLATE',
    'security.yml',
  );
  if (existsSync(publicVulnerabilityTemplate)) {
    fail(
      'Do not add a public vulnerability issue template. Use SECURITY.md and private reporting.',
    );
  }

  const dependabotPath = path.join(rootDirectory, '.github', 'dependabot.yml');
  const dependabot = readFileSync(dependabotPath, 'utf8');
  if (/auto-?merge/i.test(dependabot)) {
    fail('dependabot.yml must not enable auto-merge.');
  }
}

/**
 * @returns {void}
 */
function rejectTrackedActionlintCache() {
  const listing = spawnSync(
    'git',
    ['-C', rootDirectory, 'ls-files', '-z', '--', '.cache/actionlint'],
    { encoding: 'buffer' },
  );

  if (listing.error || listing.status !== 0) {
    fail('Unable to check whether .cache/actionlint is tracked in git.');
  }

  if (listing.stdout.length > 0) {
    fail(
      'Tracked files under .cache/actionlint are forbidden. That path is a local tool cache, not source.',
    );
  }
}

/**
 * @returns {boolean}
 */
function downloadsAllowed() {
  return process.env['PATCHPILOT_ACTIONLINT_ALLOW_DOWNLOAD'] !== 'false';
}

/**
 * @returns {keyof typeof ARCHIVE_CHECKSUMS}
 */
function platformArchiveId() {
  const platform = process.platform;
  const arch = process.arch;

  if (platform === 'linux' && arch === 'x64') {
    return 'linux_amd64';
  }
  if (platform === 'linux' && arch === 'arm64') {
    return 'linux_arm64';
  }
  if (platform === 'darwin' && arch === 'x64') {
    return 'darwin_amd64';
  }
  if (platform === 'darwin' && arch === 'arm64') {
    return 'darwin_arm64';
  }

  fail(
    `actionlint ${ACTIONLINT_VERSION} is not provisioned for ${platform}/${arch}. Install actionlint ${ACTIONLINT_VERSION} yourself and re-run.`,
  );
}

/**
 * @param {string} filePath
 * @returns {string}
 */
function sha256File(filePath) {
  const hash = createHash('sha256');
  hash.update(readFileSync(filePath));
  return hash.digest('hex');
}

/**
 * @param {string} url
 * @param {string} destination
 * @returns {Promise<void>}
 */
async function download(url, destination) {
  /** @type {Record<string, string>} */
  const headers = {
    'User-Agent': 'patchpilot-actionlint-bootstrap',
    Accept: 'application/octet-stream',
  };
  const token = process.env['GITHUB_TOKEN'];
  if (typeof token === 'string' && token.length > 0) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const response = await fetch(url, {
    redirect: 'follow',
    headers,
  });

  if (!response.ok || response.body === null) {
    fail(`Failed to download ${url}: HTTP ${response.status}`);
  }

  await pipeline(response.body, createWriteStream(destination));
}

/**
 * @param {string} archivePath
 * @param {string} destinationDirectory
 * @returns {Promise<void>}
 */
async function extractWithSystemTar(archivePath, destinationDirectory) {
  await mkdir(destinationDirectory, { recursive: true });

  const child = spawn('tar', ['-xzf', archivePath, '-C', destinationDirectory, 'actionlint'], {
    stdio: 'inherit',
  });

  await new Promise((resolve, reject) => {
    child.on('error', reject);
    child.on('exit', (code) => {
      if (code === 0) {
        resolve(undefined);
        return;
      }
      reject(new Error(`tar exited with status ${code ?? 1}`));
    });
  });
}

/**
 * @param {string} binaryPath
 * @returns {void}
 */
function runActionlint(binaryPath) {
  if (!existsSync(workflowsDirectory)) {
    fail(`Expected workflow directory at ${workflowsDirectory}`);
  }

  const child = spawn(binaryPath, ['-color'], {
    stdio: 'inherit',
    cwd: rootDirectory,
  });

  child.on('error', (error) => {
    fail(error instanceof Error ? error.message : 'Failed to start actionlint.');
  });

  child.on('exit', (code) => {
    process.exit(code ?? 1);
  });
}

checkGitHubGovernance();
rejectTrackedActionlintCache();

const archiveId = platformArchiveId();
const expectedChecksum = ARCHIVE_CHECKSUMS[archiveId];
const expectedBinaryChecksum = BINARY_CHECKSUMS[archiveId];
if (expectedChecksum === undefined || expectedBinaryChecksum === undefined) {
  fail(`Missing checksum for ${archiveId}.`);
}

const cacheRoot =
  process.env['PATCHPILOT_ACTIONLINT_CACHE_DIR'] ??
  path.join(rootDirectory, '.cache', 'actionlint');
const cacheDirectory = path.join(cacheRoot, ACTIONLINT_VERSION);
const binaryPath = path.join(cacheDirectory, 'actionlint');

if (existsSync(binaryPath) && sha256File(binaryPath) === expectedBinaryChecksum) {
  runActionlint(binaryPath);
} else {
  if (existsSync(binaryPath)) {
    process.stderr.write(
      'Cached actionlint binary failed SHA-256 verification. It will not be executed.\n',
    );
    await rm(cacheDirectory, { recursive: true, force: true });
  }

  if (!downloadsAllowed()) {
    fail('Trusted actionlint binary is not available and downloads are disabled.');
  }

  const archiveName = `actionlint_${ACTIONLINT_VERSION}_${archiveId}.tar.gz`;
  const url = `https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}/${archiveName}`;
  const tempDirectory = path.join(os.tmpdir(), `patchpilot-actionlint-${process.pid}`);
  mkdirSync(tempDirectory, { recursive: true });
  const archivePath = path.join(tempDirectory, archiveName);

  await download(url, archivePath);
  const actualChecksum = sha256File(archivePath);
  if (actualChecksum !== expectedChecksum) {
    await rm(tempDirectory, { recursive: true, force: true });
    fail(
      `Checksum mismatch for ${archiveName}. Expected ${expectedChecksum}, received ${actualChecksum}.`,
    );
  }

  await extractWithSystemTar(archivePath, tempDirectory);
  const extractedBinary = path.join(tempDirectory, 'actionlint');
  if (!existsSync(extractedBinary)) {
    fail('actionlint binary was not present in the verified archive.');
  }

  const extractedBinaryChecksum = sha256File(extractedBinary);
  if (extractedBinaryChecksum !== expectedBinaryChecksum) {
    await rm(tempDirectory, { recursive: true, force: true });
    fail(
      `Checksum mismatch for extracted actionlint. Expected ${expectedBinaryChecksum}, received ${extractedBinaryChecksum}.`,
    );
  }

  mkdirSync(cacheDirectory, { recursive: true });
  await copyFile(extractedBinary, binaryPath);
  await chmod(binaryPath, 0o755);

  if (sha256File(binaryPath) !== expectedBinaryChecksum) {
    await rm(tempDirectory, { recursive: true, force: true });
    fail('Cached actionlint binary did not match the expected SHA-256 after copy.');
  }

  await rm(tempDirectory, { recursive: true, force: true });
  runActionlint(binaryPath);
}
