#!/usr/bin/env node

import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';

const rootDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const composeFile = path.join(rootDirectory, 'deploy', 'compose', 'compose.yaml');

const command = process.argv[2];

if (command !== 'up' && command !== 'down' && command !== 'logs') {
  process.stderr.write(
    'Usage: pnpm infrastructure:up | pnpm infrastructure:down | pnpm infrastructure:logs\n',
  );
  process.exit(1);
}

if (!existsSync(composeFile)) {
  process.stderr.write(
    [
      'Local infrastructure is not available yet.',
      `Expected Docker Compose file: ${composeFile}`,
      'Create deploy/compose/compose.yaml (PostgreSQL, Redis, MinIO bound to 127.0.0.1) before starting infrastructure.',
      'Install Docker and ensure the daemon is running, then retry.',
    ].join('\n'),
  );
  process.stderr.write('\n');
  process.exit(1);
}

function envFileArguments() {
  const envFile = path.join(rootDirectory, '.env');
  return existsSync(envFile) ? ['--env-file', envFile] : [];
}

const dockerArguments =
  command === 'up'
    ? ['compose', '-f', composeFile, ...envFileArguments(), 'up', '-d', '--wait']
    : command === 'down'
      ? ['compose', '-f', composeFile, ...envFileArguments(), 'down']
      : ['compose', '-f', composeFile, ...envFileArguments(), 'logs', '--follow'];

const child = spawn('docker', dockerArguments, {
  stdio: 'inherit',
  cwd: rootDirectory,
});

child.on('error', (error) => {
  process.stderr.write(
    [
      'Failed to execute Docker Compose.',
      `Command: docker ${dockerArguments.join(' ')}`,
      error instanceof Error ? error.message : 'Unknown error',
      'Install Docker, start the daemon, and ensure you can run `docker compose version`.',
    ].join('\n'),
  );
  process.stderr.write('\n');
  process.exit(1);
});

child.on('exit', (code) => {
  process.exit(code ?? 1);
});
