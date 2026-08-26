#!/usr/bin/env node

import { spawn } from 'node:child_process';

const command = process.argv[2];
const args = process.argv.slice(3);

if (!command) {
  process.stderr.write('Usage: run-with-database-url.mjs <command> [args...]\n');
  process.exit(1);
}

const developmentPlaceholderUrl =
  'postgresql://patchpilot:patchpilot-dev-not-for-production@127.0.0.1:55432/patchpilot';

const child = spawn(command, args, {
  stdio: 'inherit',
  env: {
    ...process.env,
    DATABASE_URL: process.env['DATABASE_URL'] ?? developmentPlaceholderUrl,
  },
});

child.on('error', (error) => {
  process.stderr.write(error instanceof Error ? error.message : 'Failed to run command.\n');
  process.exit(1);
});

child.on('exit', (code) => {
  process.exit(code ?? 1);
});
