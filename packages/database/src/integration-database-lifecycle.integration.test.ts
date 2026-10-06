import { mkdtemp, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { PrismaClient } from '@prisma/client';
import { describe, expect, it } from 'vitest';

import { withCleanupOnFailure } from './integration-database-cleanup.js';
import {
  connectIntegrationAdmin,
  createEphemeralDatabase,
  deployMigrations,
  dropOwnedEphemeralDatabase,
  EXPECTED_APPLIED_MIGRATIONS,
  integrationServerDatabaseUrl,
  reapStaleEphemeralDatabases,
  withDatabaseName,
} from './integration-database.js';
import { STALE_EPHEMERAL_DATABASE_AGE_MS } from './integration-database-name.js';
import {
  destroyIntegrationProcessDatabase,
  type IntegrationProcessDatabaseState,
} from './integration-process-database.js';

describe('integration database lifecycle', () => {
  it('gives concurrent databases separate rows, migrations, and drop ownership', async () => {
    const persistent = await persistentOrganizationCount();
    const first = await createEphemeralDatabase('it', { scope: 'api' });
    const second = await createEphemeralDatabase('it', { scope: 'worker' });
    const clientA = new PrismaClient({ datasources: { db: { url: first.databaseUrl } } });
    const clientB = new PrismaClient({ datasources: { db: { url: second.databaseUrl } } });

    try {
      expect(first.databaseName).not.toBe(second.databaseName);
      expect(first.databaseName).not.toBe('patchpilot');
      expect(second.databaseName).not.toBe('patchpilot');

      await deployMigrations(first.databaseUrl);
      await deployMigrations(second.databaseUrl);
      await clientA.organization.create({
        data: { slug: 'hermetic-only-a', name: 'Hermetic Only A' },
      });
      expect(await clientA.organization.count()).toBe(1);
      expect(await clientB.organization.count()).toBe(0);

      expect(await appliedMigrationNames(clientA)).toEqual([...EXPECTED_APPLIED_MIGRATIONS]);
      expect(await appliedMigrationNames(clientB)).toEqual([...EXPECTED_APPLIED_MIGRATIONS]);

      await expect(dropOwnedEphemeralDatabase(first.admin, 'patchpilot')).rejects.toThrow(
        /Ephemeral test databases/,
      );
      await dropOwnedEphemeralDatabase(first.admin, first.databaseName);

      expect(await clientB.organization.count()).toBe(0);
      const names = await databaseNames();
      expect(names).not.toContain(first.databaseName);
      expect(names).toContain(second.databaseName);
      expect(names).toContain('patchpilot');
      expect(await persistentOrganizationCount()).toEqual(persistent);
    } finally {
      await clientA.$disconnect();
      await clientB.$disconnect();
      await first.admin.$disconnect();
      await second.admin.$disconnect();
      await dropIfPresent(first.databaseName);
      await dropIfPresent(second.databaseName);
    }
  }, 180_000);

  it('drops the failed operation database and preserves the original error', async () => {
    const persistent = await persistentOrganizationCount();
    const created = await createEphemeralDatabase('it', { scope: 'api' });

    try {
      await expect(
        withCleanupOnFailure(
          async () => {
            throw new Error('original failure');
          },
          async () => {
            await dropOwnedEphemeralDatabase(created.admin, created.databaseName);
          },
        ),
      ).rejects.toThrow('original failure');

      const names = await databaseNames();
      expect(names).not.toContain(created.databaseName);
      expect(names).toContain('patchpilot');
      expect(await persistentOrganizationCount()).toEqual(persistent);
    } finally {
      await created.admin.$disconnect();
      await dropIfPresent(created.databaseName);
    }
  });

  it('reaps a stale disposable database without dropping a live one or the persistent database', async () => {
    const stale = await createEphemeralDatabase('it', {
      scope: 'worker',
      nowMs: Date.now() - STALE_EPHEMERAL_DATABASE_AGE_MS - 60_000,
    });
    const fresh = await createEphemeralDatabase('it', { scope: 'api' });

    try {
      await stale.admin.$disconnect();
      await fresh.admin.$disconnect();
      const result = await reapStaleEphemeralDatabases();
      expect(result.dropped.length).toBeLessThanOrEqual(8);
      expect(result.dropped).not.toContain('patchpilot');
      expect(result.dropped).not.toContain(fresh.databaseName);

      const names = await databaseNames();
      expect(names).toContain('patchpilot');
      expect(names).toContain(fresh.databaseName);
      if (result.dropped.includes(stale.databaseName)) {
        expect(names).not.toContain(stale.databaseName);
      }
    } finally {
      await dropIfPresent(stale.databaseName);
      await dropIfPresent(fresh.databaseName);
    }
  });

  it('refuses to drop another integration process database', async () => {
    const owned = await createEphemeralDatabase('it', { scope: 'api' });
    const foreign = await createEphemeralDatabase('it', { scope: 'worker' });

    try {
      const directory = await mkdtemp(path.join(tmpdir(), 'patchpilot-it-ownership-'));
      const stateFile = path.join(directory, 'database.json');
      const tampered: IntegrationProcessDatabaseState = {
        scope: 'api',
        databaseName: foreign.databaseName,
        databaseUrl: foreign.databaseUrl,
      };
      await writeFile(stateFile, JSON.stringify(tampered), { mode: 0o600 });

      await expect(destroyIntegrationProcessDatabase('api', stateFile)).rejects.toThrow(
        /does not own/,
      );
      const names = await databaseNames();
      expect(names).toContain(owned.databaseName);
      expect(names).toContain(foreign.databaseName);
      expect(names).toContain('patchpilot');
    } finally {
      await owned.admin.$disconnect();
      await foreign.admin.$disconnect();
      await dropIfPresent(owned.databaseName);
      await dropIfPresent(foreign.databaseName);
    }
  });
});

async function dropIfPresent(databaseName: string): Promise<void> {
  const admin = await connectIntegrationAdmin();
  try {
    const rows = await admin.$queryRaw<Array<{ datname: string }>>`
      SELECT datname
      FROM pg_database
      WHERE datname = ${databaseName}
    `;
    if (rows.length > 0) {
      await dropOwnedEphemeralDatabase(admin, databaseName);
    }
  } finally {
    await admin.$disconnect();
  }
}

async function databaseNames(): Promise<string[]> {
  const admin = await connectIntegrationAdmin();
  try {
    const rows = await admin.$queryRaw<Array<{ datname: string }>>`
      SELECT datname
      FROM pg_database
    `;
    return rows.map((row) => row.datname);
  } finally {
    await admin.$disconnect();
  }
}

async function appliedMigrationNames(client: PrismaClient): Promise<string[]> {
  const rows = await client.$queryRaw<Array<{ migration_name: string }>>`
    SELECT migration_name
    FROM _prisma_migrations
    ORDER BY finished_at ASC, migration_name ASC
  `;
  return rows.map((row) => row.migration_name);
}

async function persistentOrganizationCount(): Promise<number | 'absent'> {
  const client = new PrismaClient({
    datasources: { db: { url: withDatabaseName(integrationServerDatabaseUrl(), 'patchpilot') } },
  });
  try {
    const rows = await client.$queryRaw<Array<{ count: bigint }>>`
      SELECT COUNT(*)::bigint AS count
      FROM organization
    `;
    return Number(rows[0]?.count ?? 0);
  } catch (error) {
    const message = error instanceof Error ? error.message : '';
    if (message.includes('42P01') || message.includes('does not exist')) {
      return 'absent';
    }

    throw error;
  } finally {
    await client.$disconnect();
  }
}
