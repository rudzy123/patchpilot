#!/usr/bin/env node

import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';

const rootDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const databasePackageDirectory = path.join(rootDirectory, 'packages', 'database');
const databasePackageJson = path.join(databasePackageDirectory, 'package.json');

const command = process.argv[2];
const allowedCommands = new Set(['generate', 'validate', 'migrate', 'migrate:deploy', 'reset']);

if (!command || !allowedCommands.has(command)) {
  process.stderr.write(
    'Usage: pnpm db:generate | pnpm db:validate | pnpm db:migrate | pnpm db:migrate:deploy | pnpm db:reset\n',
  );
  process.exit(1);
}

if (command === 'reset') {
  const deploymentEnvironment = process.env['PATCHPILOT_DEPLOYMENT_ENVIRONMENT'];
  if (deploymentEnvironment === 'production' || process.env['NODE_ENV'] === 'production') {
    process.stderr.write(
      'Refusing pnpm db:reset when PATCHPILOT_DEPLOYMENT_ENVIRONMENT or NODE_ENV is production.\n',
    );
    process.exit(1);
  }
}

if (!existsSync(databasePackageJson)) {
  process.stderr.write(
    [
      'The database package is not available yet.',
      `Expected package at: ${databasePackageDirectory}`,
      'Scaffold @patchpilot/database before running Prisma commands.',
    ].join('\n'),
  );
  process.stderr.write('\n');
  process.exit(1);
}

const child = spawn('pnpm', ['--filter', '@patchpilot/database', command], {
  stdio: 'inherit',
  cwd: rootDirectory,
});

child.on('error', (error) => {
  process.stderr.write(
    [
      `Failed to run database command "${command}".`,
      error instanceof Error ? error.message : 'Unknown error',
      'Ensure pnpm is available and @patchpilot/database defines the corresponding script.',
    ].join('\n'),
  );
  process.stderr.write('\n');
  process.exit(1);
});

child.on('exit', (code) => {
  process.exit(code ?? 1);
});
