import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import {
  publishDisposableIntegrationDatabase,
  readIntegrationDatabaseStateFile,
  rememberIntegrationServerTemplate,
  setIntegrationDatabaseStateFile,
} from '@patchpilot/config/integration-test';
import { createFoundationTestEnv } from '@patchpilot/test-utils';

import { redactConnectionSecrets } from './integration-database-cleanup.js';
import type { IntegrationProcessScope } from './integration-database-name.js';

const execFileAsync = promisify(execFile);
const databasePackageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const commandPath = fileURLToPath(new URL('./integration-process-database.ts', import.meta.url));
const resolverPath = fileURLToPath(
  new URL('./integration-typescript-resolver.mjs', import.meta.url),
);
const COMMAND_TIMEOUT_MS = 180_000;

export function createIntegrationProcessHooks(scope: IntegrationProcessScope): {
  setup: () => Promise<void>;
  teardown: () => Promise<void>;
} {
  return {
    setup: async () => {
      rememberIntegrationServerTemplate(createFoundationTestEnv()['DATABASE_URL']);
      const directory = await mkdtemp(path.join(tmpdir(), `patchpilot-it-${scope}-`));
      const stateFile = path.join(directory, 'database.json');
      setIntegrationDatabaseStateFile(stateFile);
      await runIntegrationDatabaseCommand(['prepare', scope, stateFile]);
      const state = JSON.parse(await readFile(stateFile, 'utf8')) as {
        databaseUrl?: unknown;
        databaseName?: unknown;
      };
      if (typeof state.databaseUrl !== 'string' || typeof state.databaseName !== 'string') {
        throw new Error('Disposable integration database state is incomplete.');
      }

      const prefix = `patchpilot_it_${scope}_`;
      if (!state.databaseName.startsWith(prefix) || state.databaseName === 'patchpilot') {
        throw new Error('Disposable integration database name was rejected.');
      }

      publishDisposableIntegrationDatabase(state.databaseUrl);
    },
    teardown: async () => {
      const stateFile = readIntegrationDatabaseStateFile();

      let cleanupError: unknown;
      try {
        await runIntegrationDatabaseCommand(['destroy', scope, stateFile]);
      } catch (error) {
        cleanupError = error;
        const detail = error instanceof Error ? error.message : 'unknown cleanup failure';
        process.stderr.write(`${redactConnectionSecrets(detail)}\n`);
      } finally {
        await rm(path.dirname(stateFile), { recursive: true, force: true }).catch(() => {
          process.stderr.write('integration database state cleanup failed\n');
        });
      }

      if (cleanupError !== undefined) {
        throw cleanupError;
      }
    },
  };
}

export async function reapIntegrationDatabases(): Promise<void> {
  rememberIntegrationServerTemplate(createFoundationTestEnv()['DATABASE_URL']);
  await runIntegrationDatabaseCommand(['reap']);
}

async function runIntegrationDatabaseCommand(args: readonly string[]): Promise<void> {
  try {
    await execFileAsync(
      process.execPath,
      ['--experimental-strip-types', '--import', resolverPath, commandPath, ...args],
      {
        cwd: databasePackageRoot,
        encoding: 'utf8',
        timeout: COMMAND_TIMEOUT_MS,
        maxBuffer: 2 * 1024 * 1024,
      },
    );
  } catch (error) {
    const stderr = readExecBuffer(error, 'stderr');
    const stdout = readExecBuffer(error, 'stdout');
    const detail = redactConnectionSecrets(`${stderr}\n${stdout}`).trim();
    throw new Error(
      detail.length > 0
        ? `integration database command failed: ${detail}`
        : 'integration database command failed',
    );
  }
}

function readExecBuffer(error: unknown, field: 'stdout' | 'stderr'): string {
  if (typeof error !== 'object' || error === null || !(field in error)) {
    return '';
  }

  const value = (error as Record<string, unknown>)[field];
  return typeof value === 'string' ? value : '';
}
