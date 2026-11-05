#!/usr/bin/env node

/**
 * Explicit deployment-local entry for built-in priority policy publication.
 * Not registered in API, web, worker, scheduler, queue, seed, or migration startup.
 *
 * Usage:
 *   pnpm publish-builtin-priority-policy -- --correlation-id <correlation-id>
 *   pnpm publish-builtin-priority-policy -- help
 */

import { existsSync } from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const rootDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const commandMain = path.join(
  rootDirectory,
  'packages/database/dist/builtin-priority-policy-publication-command-main.js',
);

if (!existsSync(commandMain)) {
  process.stderr.write(
    'Build @patchpilot/database before running the built-in priority policy publication command.\n',
  );
  process.exit(1);
}

const child = spawn(process.execPath, [commandMain, ...process.argv.slice(2)], {
  stdio: 'inherit',
  cwd: rootDirectory,
  env: process.env,
});

child.on('error', () => {
  process.stderr.write('persistence_failure\n');
  process.exit(1);
});

child.on('exit', (code) => {
  process.exit(code === null ? 1 : code);
});
