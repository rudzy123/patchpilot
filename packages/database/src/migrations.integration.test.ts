import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { PrismaClient } from '@prisma/client';

import {
  EXPECTED_APPLIED_MIGRATIONS,
  FROZEN_MIGRATIONS,
  applySession3Schema,
  applyThroughSession5,
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
  frozenMigrationFile,
  sha256File,
} from './integration-database.js';

const PRISMA_TABLES = [
  'organization',
  'user',
  'membership',
  'team',
  'team_membership',
  'environment',
  'asset',
  'asset_owner',
  'asset_tag',
  'asset_external_identifier',
  'repository_connection',
  'sbom',
  'sbom_ingestion',
  'component',
  'component_occurrence',
  'dependency_relationship',
  'vulnerability',
  'vulnerability_alias',
  'vulnerability_source_record',
  'finding',
  'finding_observation',
  'risk_policy',
  'risk_calculation',
  'remediation_task',
  'risk_acceptance',
  'evidence',
  'audit_event',
  'integration_provider',
  'intelligence_source',
  'integration',
  'external_credential',
  'outbox_event',
  'background_job',
  'idempotency_record',
] as const;

const PRISMA_FOREIGN_KEYS = [
  'sbom_ingestion_same_sbom_asset_fkey',
  'component_occurrence_same_sbom_asset_fkey',
  'component_occurrence_same_ingestion_sbom_fkey',
  'finding_occurrence_same_asset_component_fkey',
  'dependency_from_same_ingestion_fkey',
  'dependency_to_same_ingestion_fkey',
  'asset_current_ingestion_same_asset_fkey',
  'vulnerability_source_record_supersedes_revision_fkey',
  'risk_policy_created_by_membership_fkey',
  'finding_organization_id_assigned_membership_id_fkey',
] as const;

const SQL_ONLY_CHECKS = [
  'risk_policy_scope_ownership_chk',
  'risk_policy_status_timestamps_chk',
  'risk_policy_creator_scope_chk',
  'asset_owner_target_chk',
  'evidence_one_target_chk',
  'audit_event_actor_scope_chk',
  'intelligence_source_provider_chk',
  'sbom_sha256_chk',
  'organization_slug_shape_chk',
] as const;

const SQL_ONLY_INDEXES = [
  'asset_owner_org_asset_role_user_uidx',
  'asset_owner_org_asset_role_team_uidx',
  'sbom_ingestion_org_idempotency_uidx',
  'risk_policy_builtin_key_version_uidx',
  'risk_policy_org_key_version_uidx',
  'asset_active_name_org_idx',
] as const;

const SQL_ONLY_TRIGGERS = [
  'audit_event_append_only',
  'finding_observation_append_only',
  'risk_calculation_append_only',
  'vulnerability_source_record_append_only',
  'evidence_append_only',
  'risk_policy_published_immutable',
  'risk_policy_published_delete_forbidden',
  'sbom_identity_immutable',
  'risk_calculation_policy_org_consistency',
  'background_job_outbox_org_consistency',
] as const;

const SQL_ONLY_FUNCTIONS = [
  'patchpilot_forbid_mutation',
  'patchpilot_protect_published_risk_policy',
  'patchpilot_forbid_published_risk_policy_delete',
  'patchpilot_protect_sbom_identity',
  'patchpilot_risk_policy_org_consistency',
  'patchpilot_job_outbox_org_consistency',
] as const;

async function names(client: PrismaClient, sql: string): Promise<string[]> {
  const rows = await client.$queryRawUnsafe<Array<{ name: string }>>(sql);
  return rows.map((row) => row.name);
}

async function assertFinalMigratedSchema(client: PrismaClient): Promise<void> {
  const tables = await names(
    client,
    `SELECT tablename AS name FROM pg_tables WHERE schemaname = 'public'`,
  );
  expect(tables).not.toContain('SchemaFoundation');
  for (const table of PRISMA_TABLES) {
    expect(tables).toContain(table);
  }

  const applied = await names(
    client,
    `SELECT migration_name AS name FROM _prisma_migrations ORDER BY finished_at`,
  );
  expect(applied).toEqual([...EXPECTED_APPLIED_MIGRATIONS]);

  const policyColumns = await names(
    client,
    `SELECT column_name AS name FROM information_schema.columns
     WHERE table_schema = 'public' AND table_name = 'risk_policy'`,
  );
  expect(policyColumns).toContain('created_by_membership_id');
  expect(policyColumns).not.toContain('created_by_user_id');
  expect(policyColumns).toContain('scope');

  const sbomColumns = await names(
    client,
    `SELECT column_name AS name FROM information_schema.columns
     WHERE table_schema = 'public' AND table_name = 'sbom'`,
  );
  expect(sbomColumns).toContain('received_at');
  expect(sbomColumns).toContain('captured_at');
  expect(sbomColumns).toContain('created_at');
  expect(sbomColumns).not.toContain('uploaded_at');

  const evidenceKinds = await names(
    client,
    `SELECT e.enumlabel AS name
     FROM pg_enum e
     JOIN pg_type t ON t.oid = e.enumtypid
     JOIN pg_namespace n ON n.oid = t.typnamespace
     WHERE n.nspname = 'public' AND t.typname = 'evidence_kind'`,
  );
  expect(evidenceKinds).toContain('export_snapshot');

  const policyScopes = await names(
    client,
    `SELECT e.enumlabel AS name
     FROM pg_enum e
     JOIN pg_type t ON t.oid = e.enumtypid
     JOIN pg_namespace n ON n.oid = t.typnamespace
     WHERE n.nspname = 'public' AND t.typname = 'risk_policy_scope'`,
  );
  expect(policyScopes).toEqual(expect.arrayContaining(['builtin', 'organization']));

  const foreignKeys = await names(
    client,
    `SELECT conname AS name FROM pg_constraint WHERE contype = 'f'`,
  );
  for (const key of PRISMA_FOREIGN_KEYS) {
    expect(foreignKeys).toContain(key);
  }

  const checks = await names(
    client,
    `SELECT conname AS name FROM pg_constraint WHERE contype = 'c'`,
  );
  for (const check of SQL_ONLY_CHECKS) {
    expect(checks).toContain(check);
  }

  const indexes = await names(
    client,
    `SELECT indexname AS name FROM pg_indexes WHERE schemaname = 'public'`,
  );
  for (const index of SQL_ONLY_INDEXES) {
    expect(indexes).toContain(index);
  }

  const triggers = await names(
    client,
    `SELECT tgname AS name FROM pg_trigger WHERE NOT tgisinternal`,
  );
  for (const trigger of SQL_ONLY_TRIGGERS) {
    expect(triggers).toContain(trigger);
  }

  const functions = await names(
    client,
    `SELECT p.proname AS name FROM pg_proc p
     JOIN pg_namespace n ON n.oid = p.pronamespace
     WHERE n.nspname = 'public' AND p.proname LIKE 'patchpilot_%'`,
  );
  for (const fn of SQL_ONLY_FUNCTIONS) {
    expect(functions).toContain(fn);
  }

  const searchPaths = await client.$queryRaw<Array<{ proname: string; proconfig: string[] | null }>>`
    SELECT proname, proconfig
    FROM pg_proc
    JOIN pg_namespace n ON n.oid = pg_proc.pronamespace
    WHERE n.nspname = 'public' AND proname LIKE 'patchpilot_%'
  `;
  expect(searchPaths.length).toBeGreaterThan(0);
  for (const fn of searchPaths) {
    expect(fn.proconfig?.some((entry) => entry.includes('search_path=pg_catalog'))).toBe(true);
  }
}

describe('frozen migrations', () => {
  it('keeps Session 3, Session 5, and committed correction SQL byte-stable', async () => {
    for (const frozen of FROZEN_MIGRATIONS) {
      const digest = await sha256File(frozenMigrationFile(frozen.directory));
      expect(digest).toBe(frozen.sha256);
    }
  });

  it('does not keep a separately applied extras SQL source', () => {
    const sqlDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../prisma/sql');
    expect(existsSync(path.join(sqlDir, 'tenant-model-extras.sql'))).toBe(false);
    expect(existsSync(path.join(sqlDir, 'review-corrections-extras.sql'))).toBe(false);
  });
});

describe('migrations', () => {
  it('applies every migration to a clean isolated database', async () => {
    const ephemeral = await createEphemeralDatabase('migrate');
    const client = new PrismaClient({
      datasources: { db: { url: ephemeral.databaseUrl } },
    });

    try {
      await deployMigrations(ephemeral.databaseUrl);
      await assertFinalMigratedSchema(client);
    } finally {
      await client.$disconnect();
      await dropEphemeralDatabase(ephemeral.admin, ephemeral.databaseName);
    }
  });

  it('upgrades a Session 3 SchemaFoundation database through later migrations', async () => {
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
      await assertFinalMigratedSchema(client);
    } finally {
      await client.$disconnect();
      await dropEphemeralDatabase(ephemeral.admin, ephemeral.databaseName);
    }
  });

  it('upgrades an existing Session 5 database through later corrective migrations', async () => {
    const ephemeral = await createEphemeralDatabase('migrate');
    const client = new PrismaClient({
      datasources: { db: { url: ephemeral.databaseUrl } },
    });

    try {
      await applyThroughSession5(ephemeral.databaseUrl);
      const afterSession5 = await names(
        client,
        `SELECT tablename AS name FROM pg_tables WHERE schemaname = 'public'`,
      );
      expect(afterSession5).toContain('organization');
      expect(afterSession5).not.toContain('intelligence_source');
      expect(afterSession5).not.toContain('SchemaFoundation');

      const session5PolicyColumns = await names(
        client,
        `SELECT column_name AS name FROM information_schema.columns
         WHERE table_schema = 'public' AND table_name = 'risk_policy'`,
      );
      expect(session5PolicyColumns).toContain('created_by_user_id');
      expect(session5PolicyColumns).not.toContain('created_by_membership_id');

      await deployMigrations(ephemeral.databaseUrl);
      await assertFinalMigratedSchema(client);
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
