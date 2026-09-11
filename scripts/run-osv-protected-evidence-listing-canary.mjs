#!/usr/bin/env node

/**
 * Session 13 Batch 3D nonpublic operator entry point for the one-page
 * protected-evidence listing-canary. Not registered in worker, API, or
 * application startup.
 *
 * Usage:
 *   node scripts/run-osv-protected-evidence-listing-canary.mjs dry-run
 *   node scripts/run-osv-protected-evidence-listing-canary.mjs execute-one-listing-request --i-understand-this-sends-one-real-provider-listing-request-and-retains-protected-observation-evidence
 *
 * execute-one-listing-request performs exactly one real HTTPS listing request
 * to the committed GCS JSON Objects endpoint and persists encrypted observation
 * identities. Tests, build, lint, and typecheck must not invoke that command.
 */

import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const rootDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const operatorMain = path.join(
  rootDirectory,
  'packages/database/src/osv-protected-evidence-listing-canary-operator-main.ts',
);
const tsxCli = path.join(rootDirectory, 'node_modules/.bin/tsx');
const developmentPlaceholderUrl =
  'postgresql://patchpilot:patchpilot-dev-not-for-production@127.0.0.1:55432/patchpilot';

const argv = process.argv.slice(2);
const rejected = [
  '--retry',
  '--retries',
  '--body',
  '--paginate',
  '--pagination',
  '--page-token',
  '--page',
  '--prefix',
  '--candidate',
  '--activate',
  '--match',
  '--finding',
  '--endpoint',
  '--url',
  '--enable-osv',
];

/**
 * @param {number} exitCode
 */
function usage(exitCode) {
  process.stderr.write(
    [
      'Nonpublic OSV protected-evidence listing-canary operator command.',
      'Session 13 Batch 3D.',
      'Usage:',
      '  node scripts/run-osv-protected-evidence-listing-canary.mjs dry-run',
      '  node scripts/run-osv-protected-evidence-listing-canary.mjs execute-one-listing-request --i-understand-this-sends-one-real-provider-listing-request-and-retains-protected-observation-evidence',
      '',
      'execute-one-listing-request sends exactly one real provider listing request',
      'and retains encrypted observation evidence. Do not invoke it from tests,',
      'build, lint, typecheck, or application startup.',
      '',
    ].join('\n'),
  );
  process.exit(exitCode);
}

if (argv.some((token) => rejected.includes(token))) {
  usage(1);
}

const isDryRun = argv.length === 1 && argv[0] === 'dry-run';
const isExecute =
  argv.length === 2 &&
  argv[0] === 'execute-one-listing-request' &&
  argv[1] ===
    '--i-understand-this-sends-one-real-provider-listing-request-and-retains-protected-observation-evidence';

if (!isDryRun && !isExecute) {
  usage(1);
}

if (isExecute) {
  process.stderr.write(
    'WARNING: This command performs exactly one real HTTPS listing request to storage.googleapis.com and persists encrypted listing-observation evidence. No retry. No pagination. No body retrieval.\n',
  );
}

const child = spawn(tsxCli, [operatorMain, ...argv], {
  stdio: 'inherit',
  cwd: path.join(rootDirectory, 'packages/database'),
  env: {
    ...process.env,
    DATABASE_URL: process.env['DATABASE_URL'] ?? developmentPlaceholderUrl,
  },
});

child.on('error', (error) => {
  process.stderr.write(error instanceof Error ? `${error.message}\n` : 'operator spawn failed\n');
  process.exit(1);
});

child.on('exit', (code) => {
  process.exit(code === null ? 1 : code);
});
