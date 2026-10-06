import type { PrismaClient } from '@prisma/client';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { loadServerConfigFrom } from '@patchpilot/config';
import { createFoundationTestEnv } from '@patchpilot/test-utils';

import { checkDatabaseReady, disconnectPrisma, resetPrismaClientForTests } from './index.js';
import {
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
} from './integration-database.js';

describe('postgresql integration', () => {
  let databaseUrl = '';
  let databaseName = '';
  let admin: PrismaClient | undefined;

  beforeAll(async () => {
    const ephemeral = await createEphemeralDatabase('it', { scope: 'db' });
    databaseUrl = ephemeral.databaseUrl;
    databaseName = ephemeral.databaseName;
    admin = ephemeral.admin;
    await deployMigrations(databaseUrl);
  });

  afterAll(async () => {
    await disconnectPrisma();
    resetPrismaClientForTests();
    if (admin !== undefined && databaseName.length > 0) {
      await dropEphemeralDatabase(admin, databaseName);
    }
  });

  it('reports ready against an isolated PostgreSQL database without leaking the connection string', async () => {
    expect(databaseName.startsWith('patchpilot_it_db_')).toBe(true);
    expect(databaseName).not.toBe('patchpilot');
    resetPrismaClientForTests();
    const config = loadServerConfigFrom({
      ...createFoundationTestEnv(),
      DATABASE_URL: databaseUrl,
    });
    expect(new URL(config.databaseUrl).pathname).toBe(`/${databaseName}`);
    const result = await checkDatabaseReady(config.readinessTimeoutMs, {
      databaseUrl: config.databaseUrl,
    });
    expect(result).toEqual({ ok: true });
    expect(JSON.stringify(result)).not.toContain('postgresql://');
    expect(JSON.stringify(result)).not.toContain('patchpilot-dev-not-for-production');
  });
});
