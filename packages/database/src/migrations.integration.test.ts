import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { PrismaClient } from '@prisma/client';

import {
  applySession3Schema,
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
} from './integration-database.js';

describe('migrations', () => {
  it('applies the tenant model to a clean database and removes SchemaFoundation', async () => {
    const ephemeral = await createEphemeralDatabase('migrate');
    const client = new PrismaClient({
      datasources: { db: { url: ephemeral.databaseUrl } },
    });

    try {
      await deployMigrations(ephemeral.databaseUrl);
      const tables = await client.$queryRaw<Array<{ tablename: string }>>`
        SELECT tablename FROM pg_tables WHERE schemaname = 'public'
      `;
      const names = tables.map((row) => row.tablename);
      expect(names).toContain('organization');
      expect(names).toContain('audit_event');
      expect(names).toContain('outbox_event');
      expect(names).toContain('integration_provider');
      expect(names).toContain('intelligence_source');
      expect(names).not.toContain('SchemaFoundation');
    } finally {
      await client.$disconnect();
      await dropEphemeralDatabase(ephemeral.admin, ephemeral.databaseName);
    }
  });

  it('upgrades a Session 3 SchemaFoundation database and removes the placeholder', async () => {
    const ephemeral = await createEphemeralDatabase('migrate');
    const client = new PrismaClient({
      datasources: { db: { url: ephemeral.databaseUrl } },
    });

    try {
      await applySession3Schema(ephemeral.databaseUrl);
      const before = await client.$queryRaw<Array<{ tablename: string }>>`
        SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename = 'SchemaFoundation'
      `;
      expect(before).toHaveLength(1);

      await deployMigrations(ephemeral.databaseUrl);

      const after = await client.$queryRaw<Array<{ tablename: string }>>`
        SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename = 'SchemaFoundation'
      `;
      expect(after).toHaveLength(0);
      const orgs = await client.$queryRaw<Array<{ tablename: string }>>`
        SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename = 'organization'
      `;
      expect(orgs).toHaveLength(1);
    } finally {
      await client.$disconnect();
      await dropEphemeralDatabase(ephemeral.admin, ephemeral.databaseName);
    }
  });
});

describe('migration helper lifecycle', () => {
  let databaseName: string | undefined;
  let admin: PrismaClient | undefined;

  beforeAll(async () => {
    const ephemeral = await createEphemeralDatabase('it');
    databaseName = ephemeral.databaseName;
    admin = ephemeral.admin;
    await deployMigrations(ephemeral.databaseUrl);
  });

  afterAll(async () => {
    if (admin !== undefined && databaseName !== undefined) {
      await dropEphemeralDatabase(admin, databaseName);
    }
  });

  it('creates an isolated database name for integration work', () => {
    expect(databaseName?.startsWith('patchpilot_it_')).toBe(true);
  });
});
