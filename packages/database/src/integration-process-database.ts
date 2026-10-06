import { readFile, writeFile } from 'node:fs/promises';

import { DatabaseCommandSafetyError } from '@patchpilot/config';

import {
  formatCleanupFailure,
  redactConnectionSecrets,
  withCleanupOnFailure,
} from './integration-database-cleanup.js';
import {
  connectIntegrationAdmin,
  createEphemeralDatabase,
  deployMigrations,
  dropOwnedEphemeralDatabase,
  reapStaleEphemeralDatabases,
} from './integration-database.js';
import {
  assertDatabaseOwnedByScope,
  assertIntegrationProcessScope,
  type IntegrationProcessScope,
} from './integration-database-name.js';

export type IntegrationProcessDatabaseState = {
  scope: IntegrationProcessScope;
  databaseName: string;
  databaseUrl: string;
};

export async function prepareIntegrationProcessDatabase(
  scope: IntegrationProcessScope,
  stateFile: string,
): Promise<void> {
  await reapStaleEphemeralDatabases();
  const created = await createEphemeralDatabase('it', { scope });

  try {
    await withCleanupOnFailure(
      async () => {
        await deployMigrations(created.databaseUrl);
        const state: IntegrationProcessDatabaseState = {
          scope,
          databaseName: created.databaseName,
          databaseUrl: created.databaseUrl,
        };
        await writeFile(stateFile, JSON.stringify(state), { mode: 0o600 });
      },
      async () => {
        await dropOwnedEphemeralDatabase(created.admin, created.databaseName);
      },
    );
  } finally {
    await created.admin.$disconnect();
  }
}

export async function destroyIntegrationProcessDatabase(
  scope: IntegrationProcessScope,
  stateFile: string,
): Promise<void> {
  const state = await readIntegrationProcessDatabaseState(stateFile);
  if (state.scope !== scope) {
    throw new DatabaseCommandSafetyError(
      'Refusing to drop a database owned by a different integration process.',
    );
  }

  assertDatabaseOwnedByScope(scope, state.databaseName);
  const admin = await connectIntegrationAdmin();
  try {
    await dropOwnedEphemeralDatabase(admin, state.databaseName);
  } catch (error) {
    process.stderr.write(`${formatCleanupFailure(error)}\n`);
    throw error;
  } finally {
    await admin.$disconnect();
  }
}

export async function readIntegrationProcessDatabaseState(
  stateFile: string,
): Promise<IntegrationProcessDatabaseState> {
  const parsed: unknown = JSON.parse(await readFile(stateFile, 'utf8'));
  if (typeof parsed !== 'object' || parsed === null) {
    throw new DatabaseCommandSafetyError('Integration database state is incomplete.');
  }

  const record = parsed as Record<string, unknown>;
  if (typeof record['scope'] !== 'string' || typeof record['databaseName'] !== 'string') {
    throw new DatabaseCommandSafetyError('Integration database state is incomplete.');
  }

  if (typeof record['databaseUrl'] !== 'string' || record['databaseUrl'].length === 0) {
    throw new DatabaseCommandSafetyError('Integration database state is incomplete.');
  }

  const scope = assertIntegrationProcessScope(record['scope']);
  assertDatabaseOwnedByScope(scope, record['databaseName']);
  return {
    scope,
    databaseName: record['databaseName'],
    databaseUrl: record['databaseUrl'],
  };
}

async function main(): Promise<void> {
  const [command, first, second] = process.argv.slice(2);
  if (command === 'reap') {
    await reapStaleEphemeralDatabases();
    return;
  }

  if (command === 'prepare' && first !== undefined && second !== undefined) {
    await prepareIntegrationProcessDatabase(assertIntegrationProcessScope(first), second);
    return;
  }

  if (command === 'destroy' && first !== undefined && second !== undefined) {
    await destroyIntegrationProcessDatabase(assertIntegrationProcessScope(first), second);
    return;
  }

  throw new Error('Integration database command is not allowed.');
}

const invokedCommand = process.argv[2];
if (invokedCommand === 'prepare' || invokedCommand === 'destroy' || invokedCommand === 'reap') {
  main()
    .then(() => {
      process.exit(0);
    })
    .catch((error: unknown) => {
      const message =
        error instanceof Error ? error.message : 'integration database command failed';
      process.stderr.write(`${redactConnectionSecrets(message)}\n`);
      process.exit(1);
    });
}
