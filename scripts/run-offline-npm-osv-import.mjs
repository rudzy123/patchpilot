#!/usr/bin/env node

/**
 * Explicit deployment-local entry for offline npm GHSA OSV import.
 * Not registered in API, web, worker, scheduler, queue, seed, or migration startup.
 *
 * Usage:
 *   pnpm offline-npm-osv-import -- help
 *   node scripts/run-offline-npm-osv-import.mjs help
 */

import { existsSync } from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const rootDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const commandMain = path.join(
  rootDirectory,
  'packages/database/dist/offline-npm-osv-import-command-main.js',
);

if (!existsSync(commandMain)) {
  process.stderr.write('offline_npm_osv_import_not_built\n');
  process.exit(1);
}

const child = spawn(process.execPath, [commandMain, ...process.argv.slice(2)], {
  stdio: 'inherit',
  cwd: rootDirectory,
  env: process.env,
});

child.on('error', () => {
  process.stderr.write('offline_npm_osv_import_failed\n');
  process.exit(1);
});

child.on('exit', (code) => {
  process.exit(code === null ? 1 : code);
});
