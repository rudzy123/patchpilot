import { existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { PrismaClient } from '@prisma/client';

import {
  EXPECTED_APPLIED_MIGRATIONS,
  FROZEN_MIGRATIONS,
  REVIEWED_SESSION_5_MIGRATIONS,
  SESSION_6_COMPLETE_MIGRATIONS,
  SESSION_6_PREAUTH_MIGRATIONS,
  SESSION_6_THROUGH_ANONYMOUS_MIGRATIONS,
  SESSION_7_ASSET_INVENTORY_CONSTRAINTS,
  SESSION_8_SBOM_INGESTION_GRAPH_PERSISTENCE,
  SESSION_9_KEV_INTELLIGENCE_PERSISTENCE,
  applyMigrationSqlAndResolve,
  applySession3Schema,
  applyThroughAuditActorAnonymous,
  applyThroughPolicyCreatorMembership,
  applyThroughReviewedSession5,
  applyThroughSession5,
  applyThroughSession6,
  applyThroughSession7,
  applyThroughSession8,
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
  'local_credential',
  'session',
  'integration_provider',
  'intelligence_source',
  'integration',
  'external_credential',
  'outbox_event',
  'background_job',
  'idempotency_record',
  'vulnerability_sync_run',
  'vulnerability_provider_snapshot',
  'kev_generation',
  'kev_entry',
  'kev_entry_cwe',
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
  'local_credential_user_id_fkey',
  'session_user_id_fkey',
  'session_active_organization_id_fkey',
  'audit_event_actor_user_id_fkey',
  'intelligence_source_active_generation_id_fkey',
  'vulnerability_sync_run_generation_owned_fkey',
] as const;

const SQL_ONLY_CHECKS = [
  'risk_policy_scope_ownership_chk',
  'risk_policy_status_timestamps_chk',
  'risk_policy_creator_scope_chk',
  'asset_owner_target_chk',
  'evidence_one_target_chk',
  'audit_event_actor_scope_chk',
  'local_credential_revision_chk',
  'local_credential_algorithm_chk',
  'local_credential_phc_chk',
  'session_token_hash_chk',
  'session_csrf_token_hash_chk',
  'session_revision_chk',
  'session_authentication_method_chk',
  'session_absolute_after_created_chk',
  'session_idle_after_created_chk',
  'session_idle_within_absolute_chk',
  'session_last_seen_window_chk',
  'session_revoke_consistency_chk',
  'session_revoke_not_before_created_chk',
  'session_revoke_reason_shape_chk',
  'intelligence_source_provider_chk',
  'sbom_sha256_chk',
  'organization_slug_shape_chk',
  'asset_external_identifier_namespace_shape_chk',
  'asset_external_identifier_value_chk',
  'sbom_ingestion_processing_started_chk',
  'sbom_ingestion_completed_requirements_chk',
  'sbom_ingestion_graph_counts_nonnegative_chk',
  'sbom_ingestion_graph_completeness_counts_chk',
  'sbom_ingestion_non_completed_graph_null_chk',
  'sbom_ingestion_failure_pair_chk',
  'sbom_ingestion_completed_after_started_chk',
  'sbom_ingestion_parser_version_label_chk',
  'sbom_ingestion_normalization_version_label_chk',
  'sbom_parser_version_last_succeeded_label_chk',
  'component_ecosystem_null_or_nonempty_chk',
  'component_occurrence_version_known_chk',
  'idempotency_record_status_response_chk',
  'vulnerability_sync_run_requested_chk',
  'vulnerability_sync_run_fetching_chk',
  'vulnerability_sync_run_retry_wait_chk',
  'vulnerability_sync_run_stored_chk',
  'vulnerability_sync_run_parsing_chk',
  'vulnerability_sync_run_staging_chk',
  'vulnerability_sync_run_activating_chk',
  'vulnerability_sync_run_completed_chk',
  'vulnerability_sync_run_not_modified_chk',
  'vulnerability_sync_run_failed_chk',
  'vulnerability_sync_run_quarantined_chk',
  'vulnerability_provider_snapshot_sha256_chk',
  'vulnerability_provider_snapshot_object_key_chk',
  'kev_generation_complete_chk',
  'kev_generation_active_chk',
  'kev_entry_cve_chk',
  'kev_entry_ransomware_raw_chk',
  'kev_entry_cwe_value_chk',
  'intelligence_source_active_provider_chk',
] as const;

const SQL_ONLY_INDEXES = [
  'asset_owner_org_asset_role_user_uidx',
  'asset_owner_org_asset_role_team_uidx',
  'sbom_ingestion_org_idempotency_uidx',
  'risk_policy_builtin_key_version_uidx',
  'risk_policy_org_key_version_uidx',
  'asset_active_name_org_idx',
  'asset_org_status_name_id_idx',
  'membership_user_active_idx',
  'session_idle_cleanup_idx',
  'session_absolute_cleanup_idx',
  'session_active_org_idx',
  'component_occurrence_org_ingestion_bom_ref_uidx',
  'outbox_event_claimed_lease_idx',
  'background_job_outbox_event_uidx',
  'sbom_ingestion_org_sbom_created_idx',
  'outbox_event_system_dedupe_idx',
  'outbox_event_tenant_dedupe_idx',
  'audit_event_system_replay_idx',
  'audit_event_tenant_replay_idx',
  'vulnerability_provider_snapshot_natural_key',
  'kev_generation_sync_run_uidx',
  'kev_generation_one_active_uidx',
  'vulnerability_sync_run_inflight_uidx',
  'vulnerability_sync_run_retry_wait_idx',
  'kev_entry_generation_cve_uidx',
  'kev_entry_generation_ordinal_uidx',
  'kev_entry_cwe_ordinal_uidx',
  'kev_entry_cwe_value_uidx',
  'kev_generation_incomplete_age_idx',
  'kev_entry_generation_ordinal_id_idx',
] as const;

const SQL_ONLY_TRIGGERS = [
  'audit_event_append_only',
  'audit_event_actor_membership_user',
  'finding_observation_append_only',
  'risk_calculation_append_only',
  'vulnerability_source_record_append_only',
  'evidence_append_only',
  'risk_policy_published_immutable',
  'risk_policy_published_delete_forbidden',
  'sbom_identity_immutable',
  'risk_calculation_policy_org_consistency',
  'background_job_outbox_org_consistency',
  'intelligence_source_active_generation',
  'vulnerability_provider_snapshot_append_only',
  'kev_entry_append_only',
  'kev_entry_cwe_append_only',
] as const;

const SQL_ONLY_FUNCTIONS = [
  'patchpilot_forbid_mutation',
  'patchpilot_protect_published_risk_policy',
  'patchpilot_forbid_published_risk_policy_delete',
  'patchpilot_protect_sbom_identity',
  'patchpilot_risk_policy_org_consistency',
  'patchpilot_job_outbox_org_consistency',
  'patchpilot_audit_actor_membership_user',
  'patchpilot_intelligence_source_active_generation',
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

  const ingestionColumns = await names(
    client,
    `SELECT column_name AS name FROM information_schema.columns
     WHERE table_schema = 'public' AND table_name = 'sbom_ingestion'`,
  );
  expect(ingestionColumns).toContain('graph_completeness');
  expect(ingestionColumns).toContain('normalization_version');
  expect(ingestionColumns).toContain('component_count');
  expect(ingestionColumns).toContain('dependency_edge_count');
  expect(ingestionColumns).toContain('warning_count');

  const occurrenceColumns = await names(
    client,
    `SELECT column_name AS name FROM information_schema.columns
     WHERE table_schema = 'public' AND table_name = 'component_occurrence'`,
  );
  expect(occurrenceColumns).toContain('version_known');

  const ecosystemNullable = await client.$queryRaw<Array<{ is_nullable: string }>>`
    SELECT is_nullable
    FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'component' AND column_name = 'ecosystem'
  `;
  expect(ecosystemNullable[0]?.is_nullable).toBe('YES');

  const graphCompleteness = await names(
    client,
    `SELECT e.enumlabel AS name
     FROM pg_enum e
     JOIN pg_type t ON t.oid = e.enumtypid
     JOIN pg_namespace n ON n.oid = t.typnamespace
     WHERE n.nspname = 'public' AND t.typname = 'sbom_graph_completeness'`,
  );
  expect(graphCompleteness).toEqual(
    expect.arrayContaining(['empty', 'no_dependencies', 'partial', 'complete']),
  );

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

  const auditActorTypes = await names(
    client,
    `SELECT e.enumlabel AS name
     FROM pg_enum e
     JOIN pg_type t ON t.oid = e.enumtypid
     JOIN pg_namespace n ON n.oid = t.typnamespace
     WHERE n.nspname = 'public' AND t.typname = 'audit_actor_type'`,
  );
  expect(auditActorTypes).toEqual(
    expect.arrayContaining(['user', 'system', 'instance_operator', 'anonymous']),
  );

  const hashAlgorithms = await names(
    client,
    `SELECT e.enumlabel AS name
     FROM pg_enum e
     JOIN pg_type t ON t.oid = e.enumtypid
     JOIN pg_namespace n ON n.oid = t.typnamespace
     WHERE n.nspname = 'public' AND t.typname = 'password_hash_algorithm'`,
  );
  expect(hashAlgorithms).toEqual(['argon2id']);

  const sessionMethods = await names(
    client,
    `SELECT e.enumlabel AS name
     FROM pg_enum e
     JOIN pg_type t ON t.oid = e.enumtypid
     JOIN pg_namespace n ON n.oid = t.typnamespace
     WHERE n.nspname = 'public' AND t.typname = 'session_authentication_method'`,
  );
  expect(sessionMethods).toEqual(['password']);

  const auditColumns = await names(
    client,
    `SELECT column_name AS name FROM information_schema.columns
     WHERE table_schema = 'public' AND table_name = 'audit_event'`,
  );
  expect(auditColumns).toContain('actor_user_id');
  expect(auditColumns).toContain('actor_membership_id');

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
  expect(indexes).not.toContain('asset_org_status_idx');

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

  const searchPaths = await client.$queryRaw<
    Array<{ proname: string; proconfig: string[] | null }>
  >`
    SELECT proname, proconfig
    FROM pg_proc
    JOIN pg_namespace n ON n.oid = pg_proc.pronamespace
    WHERE n.nspname = 'public' AND proname LIKE 'patchpilot_%'
  `;
  expect(searchPaths.length).toBeGreaterThan(0);
  for (const fn of searchPaths) {
    expect(fn.proconfig?.some((entry) => entry.includes('search_path=pg_catalog'))).toBe(true);
  }

  const syncRunStates = await names(
    client,
    `SELECT e.enumlabel AS name
     FROM pg_enum e
     JOIN pg_type t ON t.oid = e.enumtypid
     JOIN pg_namespace n ON n.oid = t.typnamespace
     WHERE n.nspname = 'public' AND t.typname = 'intelligence_sync_run_state'
     ORDER BY e.enumsortorder`,
  );
  expect(syncRunStates).toEqual([
    'requested',
    'fetching',
    'retry_wait',
    'stored',
    'parsing',
    'staging',
    'activating',
    'completed',
    'not_modified',
    'failed',
    'quarantined',
  ]);

  const generationStates = await names(
    client,
    `SELECT e.enumlabel AS name
     FROM pg_enum e
     JOIN pg_type t ON t.oid = e.enumtypid
     JOIN pg_namespace n ON n.oid = t.typnamespace
     WHERE n.nspname = 'public' AND t.typname = 'kev_generation_state'
     ORDER BY e.enumsortorder`,
  );
  expect(generationStates).toEqual(['staging', 'complete', 'active', 'superseded', 'abandoned']);

  const sourceColumns = await names(
    client,
    `SELECT column_name AS name FROM information_schema.columns
     WHERE table_schema = 'public' AND table_name = 'intelligence_source'`,
  );
  expect(sourceColumns).toContain('active_generation_id');
  expect(sourceColumns).toContain('last_attempt_at');
  expect(sourceColumns).toContain('last_failure_code');
  expect(sourceColumns).not.toContain('organization_id');

  const newTableColumns = await client.$queryRaw<
    Array<{ table_name: string; column_name: string }>
  >`
    SELECT table_name, column_name
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name IN (
        'vulnerability_sync_run',
        'vulnerability_provider_snapshot',
        'kev_generation',
        'kev_entry',
        'kev_entry_cwe'
      )
  `;
  expect(newTableColumns.some((row) => row.column_name === 'organization_id')).toBe(false);

  const findingFks = await client.$queryRaw<Array<{ conname: string }>>`
    SELECT c.conname
    FROM pg_constraint c
    JOIN pg_class rel ON rel.oid = c.conrelid
    JOIN pg_namespace n ON n.oid = rel.relnamespace
    WHERE n.nspname = 'public'
      AND c.contype = 'f'
      AND rel.relname IN (
        'vulnerability_sync_run',
        'vulnerability_provider_snapshot',
        'kev_generation',
        'kev_entry',
        'kev_entry_cwe'
      )
      AND (
        c.confrelid = 'finding'::regclass
        OR c.confrelid = 'finding_observation'::regclass
        OR c.confrelid = 'organization'::regclass
        OR c.confrelid = 'component'::regclass
        OR c.confrelid = 'vulnerability'::regclass
      )
  `;
  expect(findingFks).toEqual([]);

  const syntheticOrg = await client.$queryRaw<Array<{ slug: string }>>`
    SELECT slug FROM organization WHERE slug IN ('global', 'system', 'intelligence')
  `;
  expect(syntheticOrg).toEqual([]);

  const vulnerabilityColumns = await names(
    client,
    `SELECT column_name AS name FROM information_schema.columns
     WHERE table_schema = 'public' AND table_name = 'vulnerability'`,
  );
  expect(vulnerabilityColumns).toContain('osv_id');
  expect(vulnerabilityColumns).toContain('cve_id');

  const findingColumns = await names(
    client,
    `SELECT column_name AS name FROM information_schema.columns
     WHERE table_schema = 'public' AND table_name = 'finding'`,
  );
  expect(findingColumns).toContain('organization_id');
  expect(findingColumns).toContain('vulnerability_id');
  expect(findingColumns).not.toContain('generation_id');
}

describe('frozen migrations', () => {
  it('keeps Session 3 through Session 9 KEV-persistence SQL byte-stable', async () => {
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

  it('upgrades a reviewed Session 5 database by applying only the policy creator membership migration', async () => {
    const ephemeral = await createEphemeralDatabase('migrate');
    const client = new PrismaClient({
      datasources: { db: { url: ephemeral.databaseUrl } },
    });

    const orgAId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1';
    const orgBId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2';
    const matchedUserId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1';
    const unmatchedUserId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2';
    const builtinUserId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb3';
    const orgBUserId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb4';
    const matchedMembershipId = 'dddddddd-dddd-4ddd-8ddd-ddddddddddd1';
    const builtinPolicyId = 'cccccccc-cccc-4ccc-8ccc-ccccccccccc1';
    const matchedPolicyId = 'cccccccc-cccc-4ccc-8ccc-ccccccccccc2';
    const unmatchedPolicyId = 'cccccccc-cccc-4ccc-8ccc-ccccccccccc3';

    try {
      await applyThroughReviewedSession5(ephemeral.databaseUrl);

      const appliedBefore = await names(
        client,
        `SELECT migration_name AS name FROM _prisma_migrations ORDER BY finished_at`,
      );
      expect(appliedBefore).toEqual([...REVIEWED_SESSION_5_MIGRATIONS]);
      expect(appliedBefore).not.toContain('20260827160000_policy_creator_membership');

      const tablesBefore = await names(
        client,
        `SELECT tablename AS name FROM pg_tables WHERE schemaname = 'public'`,
      );
      expect(tablesBefore).not.toContain('SchemaFoundation');
      expect(tablesBefore).toContain('integration_provider');
      expect(tablesBefore).toContain('intelligence_source');

      const policyColumnsBefore = await names(
        client,
        `SELECT column_name AS name FROM information_schema.columns
         WHERE table_schema = 'public' AND table_name = 'risk_policy'`,
      );
      expect(policyColumnsBefore).toContain('created_by_user_id');
      expect(policyColumnsBefore).not.toContain('created_by_membership_id');
      expect(policyColumnsBefore).toContain('scope');

      const evidenceKindsBefore = await names(
        client,
        `SELECT e.enumlabel AS name
         FROM pg_enum e
         JOIN pg_type t ON t.oid = e.enumtypid
         JOIN pg_namespace n ON n.oid = t.typnamespace
         WHERE n.nspname = 'public' AND t.typname = 'evidence_kind'`,
      );
      expect(evidenceKindsBefore).toContain('export_snapshot');

      const checksBefore = await names(
        client,
        `SELECT conname AS name FROM pg_constraint WHERE contype = 'c'`,
      );
      expect(checksBefore).toContain('risk_policy_scope_ownership_chk');
      expect(checksBefore).toContain('risk_policy_status_timestamps_chk');

      const triggersBefore = await names(
        client,
        `SELECT tgname AS name FROM pg_trigger WHERE NOT tgisinternal`,
      );
      expect(triggersBefore).toContain('risk_policy_published_immutable');
      expect(triggersBefore).toContain('risk_policy_published_delete_forbidden');

      await client.$executeRaw`
        INSERT INTO "organization" ("id", "slug", "name", "updated_at")
        VALUES
          (CAST(${orgAId} AS UUID), 'path4-synthetic-org-a', 'Path 4 Synthetic Org A', CURRENT_TIMESTAMP)
      `;
      await client.$executeRaw`
        INSERT INTO "user" ("id", "email", "display_name", "updated_at")
        VALUES
          (CAST(${matchedUserId} AS UUID), 'path4-matched@synthetic.patchpilot.test', 'Path 4 Matched User', CURRENT_TIMESTAMP),
          (CAST(${unmatchedUserId} AS UUID), 'path4-unmatched@synthetic.patchpilot.test', 'Path 4 Unmatched User', CURRENT_TIMESTAMP),
          (CAST(${builtinUserId} AS UUID), 'path4-builtin@synthetic.patchpilot.test', 'Path 4 Builtin User', CURRENT_TIMESTAMP)
      `;
      await client.$executeRaw`
        INSERT INTO "membership" ("id", "organization_id", "user_id", "role", "updated_at")
        VALUES (
          CAST(${matchedMembershipId} AS UUID),
          CAST(${orgAId} AS UUID),
          CAST(${matchedUserId} AS UUID),
          'owner',
          CURRENT_TIMESTAMP
        )
      `;
      await client.$executeRaw`
        INSERT INTO "risk_policy" (
          "id",
          "organization_id",
          "scope",
          "policy_key",
          "name",
          "version",
          "status",
          "policy_schema_version",
          "definition",
          "created_by_user_id"
        )
        VALUES
          (
            CAST(${builtinPolicyId} AS UUID),
            NULL,
            'builtin',
            'path4.synthetic.builtin',
            'Path 4 synthetic builtin',
            1,
            'draft',
            1,
            '{"schemaVersion":1,"policyKey":"path4.synthetic.builtin","factorCatalog":[],"weights":{}}'::jsonb,
            CAST(${builtinUserId} AS UUID)
          ),
          (
            CAST(${matchedPolicyId} AS UUID),
            CAST(${orgAId} AS UUID),
            'organization',
            'path4.synthetic.org-matched',
            'Path 4 synthetic matched creator',
            1,
            'draft',
            1,
            '{"schemaVersion":1,"policyKey":"path4.synthetic.org-matched","factorCatalog":[],"weights":{}}'::jsonb,
            CAST(${matchedUserId} AS UUID)
          ),
          (
            CAST(${unmatchedPolicyId} AS UUID),
            CAST(${orgAId} AS UUID),
            'organization',
            'path4.synthetic.org-unmatched',
            'Path 4 synthetic unmatched creator',
            1,
            'draft',
            1,
            '{"schemaVersion":1,"policyKey":"path4.synthetic.org-unmatched","factorCatalog":[],"weights":{}}'::jsonb,
            CAST(${unmatchedUserId} AS UUID)
          )
      `;

      const membershipCountBefore = await client.membership.count();
      expect(membershipCountBefore).toBe(1);

      await deployMigrations(ephemeral.databaseUrl);

      const appliedAfter = await names(
        client,
        `SELECT migration_name AS name FROM _prisma_migrations ORDER BY finished_at`,
      );
      expect(appliedAfter.filter((name) => !appliedBefore.includes(name))).toEqual([
        '20260827160000_policy_creator_membership',
        '20260827170000_audit_actor_anonymous',
        '20260827180000_local_credentials_and_sessions',
        SESSION_7_ASSET_INVENTORY_CONSTRAINTS,
        SESSION_8_SBOM_INGESTION_GRAPH_PERSISTENCE,
        SESSION_9_KEV_INTELLIGENCE_PERSISTENCE,
      ]);
      expect(appliedAfter).toEqual([...EXPECTED_APPLIED_MIGRATIONS]);

      await assertFinalMigratedSchema(client);

      const builtin = await client.riskPolicy.findUniqueOrThrow({ where: { id: builtinPolicyId } });
      const matched = await client.riskPolicy.findUniqueOrThrow({ where: { id: matchedPolicyId } });
      const unmatched = await client.riskPolicy.findUniqueOrThrow({
        where: { id: unmatchedPolicyId },
      });
      expect(builtin.createdByMembershipId).toBeNull();
      expect(builtin.organizationId).toBeNull();
      expect(matched.createdByMembershipId).toBe(matchedMembershipId);
      expect(unmatched.createdByMembershipId).toBeNull();
      expect(await client.membership.count()).toBe(membershipCountBefore);

      await client.organization.create({
        data: { id: orgBId, slug: 'path4-synthetic-org-b', name: 'Path 4 Synthetic Org B' },
      });
      await client.user.create({
        data: {
          id: orgBUserId,
          email: 'path4-org-b@synthetic.patchpilot.test',
          displayName: 'Path 4 Org B User',
        },
      });
      const orgBMembership = await client.membership.create({
        data: { organizationId: orgBId, userId: orgBUserId, role: 'member' },
      });

      await expect(
        client.riskPolicy.update({
          where: { id: matchedPolicyId },
          data: { createdByMembershipId: orgBMembership.id },
        }),
      ).rejects.toThrow();
      await expect(
        client.riskPolicy.update({
          where: { id: builtinPolicyId },
          data: { createdByMembershipId: matchedMembershipId },
        }),
      ).rejects.toThrow();
    } finally {
      await client.$disconnect();
      await dropEphemeralDatabase(ephemeral.admin, ephemeral.databaseName);
    }
  });

  it('upgrades a database through policy-creator by applying only the two authentication migrations', async () => {
    const ephemeral = await createEphemeralDatabase('migrate');
    const client = new PrismaClient({
      datasources: { db: { url: ephemeral.databaseUrl } },
    });

    try {
      await applyThroughPolicyCreatorMembership(ephemeral.databaseUrl);
      const appliedBefore = await names(
        client,
        `SELECT migration_name AS name FROM _prisma_migrations ORDER BY finished_at`,
      );
      expect(appliedBefore).toEqual([...SESSION_6_PREAUTH_MIGRATIONS]);

      await deployMigrations(ephemeral.databaseUrl);
      const appliedAfter = await names(
        client,
        `SELECT migration_name AS name FROM _prisma_migrations ORDER BY finished_at`,
      );
      expect(appliedAfter.filter((name) => !appliedBefore.includes(name))).toEqual([
        '20260827170000_audit_actor_anonymous',
        '20260827180000_local_credentials_and_sessions',
        SESSION_7_ASSET_INVENTORY_CONSTRAINTS,
        SESSION_8_SBOM_INGESTION_GRAPH_PERSISTENCE,
        SESSION_9_KEV_INTELLIGENCE_PERSISTENCE,
      ]);
      await assertFinalMigratedSchema(client);
    } finally {
      await client.$disconnect();
      await dropEphemeralDatabase(ephemeral.admin, ephemeral.databaseName);
    }
  });

  it('adds anonymous in migration 170000 without changing the audit actor CHECK', async () => {
    const ephemeral = await createEphemeralDatabase('migrate');
    const client = new PrismaClient({
      datasources: { db: { url: ephemeral.databaseUrl } },
    });

    try {
      await applyThroughPolicyCreatorMembership(ephemeral.databaseUrl);
      const checksBefore = await names(
        client,
        `SELECT pg_get_constraintdef(oid) AS name FROM pg_constraint WHERE conname = 'audit_event_actor_scope_chk'`,
      );
      expect(checksBefore[0]).toContain("actor_type = 'user'");
      expect(checksBefore[0]).not.toContain('anonymous');

      await applyMigrationSqlAndResolve(
        ephemeral.databaseUrl,
        '20260827170000_audit_actor_anonymous',
      );

      const actorTypes = await names(
        client,
        `SELECT e.enumlabel AS name
         FROM pg_enum e
         JOIN pg_type t ON t.oid = e.enumtypid
         JOIN pg_namespace n ON n.oid = t.typnamespace
         WHERE n.nspname = 'public' AND t.typname = 'audit_actor_type'`,
      );
      expect(actorTypes).toContain('anonymous');

      const checksAfter = await names(
        client,
        `SELECT pg_get_constraintdef(oid) AS name FROM pg_constraint WHERE conname = 'audit_event_actor_scope_chk'`,
      );
      expect(checksAfter[0]).toBe(checksBefore[0]);
      expect(checksAfter[0]).not.toContain('anonymous');

      const tables = await names(
        client,
        `SELECT tablename AS name FROM pg_tables WHERE schemaname = 'public'`,
      );
      expect(tables).not.toContain('local_credential');
      expect(tables).not.toContain('session');

      const auditColumns = await names(
        client,
        `SELECT column_name AS name FROM information_schema.columns
         WHERE table_schema = 'public' AND table_name = 'audit_event'`,
      );
      expect(auditColumns).not.toContain('actor_user_id');

      await expect(
        client.$executeRaw`
          INSERT INTO "audit_event" (
            "actor_type", "action", "subject_type", "subject_id",
            "correlation_id", "payload", "schema_version"
          )
          VALUES (
            'anonymous',
            'auth.login_failed',
            'auth',
            '00000000-0000-4000-8000-000000000001',
            'corr-anonymous-170000',
            '{"schemaVersion":1}'::jsonb,
            1
          )
        `,
      ).rejects.toThrow();
    } finally {
      await client.$disconnect();
      await dropEphemeralDatabase(ephemeral.admin, ephemeral.databaseName);
    }
  });

  it('upgrades a database through anonymous actor by applying only the credentials and sessions migration', async () => {
    const ephemeral = await createEphemeralDatabase('migrate');
    const client = new PrismaClient({
      datasources: { db: { url: ephemeral.databaseUrl } },
    });

    try {
      await applyThroughAuditActorAnonymous(ephemeral.databaseUrl);
      const appliedBefore = await names(
        client,
        `SELECT migration_name AS name FROM _prisma_migrations ORDER BY finished_at`,
      );
      expect(appliedBefore).toEqual([...SESSION_6_THROUGH_ANONYMOUS_MIGRATIONS]);

      const actorTypes = await names(
        client,
        `SELECT e.enumlabel AS name
         FROM pg_enum e
         JOIN pg_type t ON t.oid = e.enumtypid
         JOIN pg_namespace n ON n.oid = t.typnamespace
         WHERE n.nspname = 'public' AND t.typname = 'audit_actor_type'`,
      );
      expect(actorTypes).toContain('anonymous');

      const tablesBefore = await names(
        client,
        `SELECT tablename AS name FROM pg_tables WHERE schemaname = 'public'`,
      );
      expect(tablesBefore).not.toContain('local_credential');
      expect(tablesBefore).not.toContain('session');

      const auditColumnsBefore = await names(
        client,
        `SELECT column_name AS name FROM information_schema.columns
         WHERE table_schema = 'public' AND table_name = 'audit_event'`,
      );
      expect(auditColumnsBefore).not.toContain('actor_user_id');

      await deployMigrations(ephemeral.databaseUrl);
      const appliedAfter = await names(
        client,
        `SELECT migration_name AS name FROM _prisma_migrations ORDER BY finished_at`,
      );
      expect(appliedAfter.filter((name) => !appliedBefore.includes(name))).toEqual([
        '20260827180000_local_credentials_and_sessions',
        SESSION_7_ASSET_INVENTORY_CONSTRAINTS,
        SESSION_8_SBOM_INGESTION_GRAPH_PERSISTENCE,
        SESSION_9_KEV_INTELLIGENCE_PERSISTENCE,
      ]);
      await assertFinalMigratedSchema(client);

      const appendOnly = await client.$queryRaw<Array<{ tgenabled: string }>>`
        SELECT tgenabled
        FROM pg_trigger
        WHERE tgname = 'audit_event_append_only' AND NOT tgisinternal
      `;
      expect(appendOnly[0]?.tgenabled).toBe('O');
    } finally {
      await client.$disconnect();
      await dropEphemeralDatabase(ephemeral.admin, ephemeral.databaseName);
    }
  });

  it('upgrades current main (Session 6 complete) by applying only the asset inventory constraints', async () => {
    const ephemeral = await createEphemeralDatabase('migrate');
    const client = new PrismaClient({
      datasources: { db: { url: ephemeral.databaseUrl } },
    });

    try {
      await applyThroughSession6(ephemeral.databaseUrl);
      const appliedBefore = await names(
        client,
        `SELECT migration_name AS name FROM _prisma_migrations ORDER BY finished_at`,
      );
      expect(appliedBefore).toEqual([...SESSION_6_COMPLETE_MIGRATIONS]);

      const indexesBefore = await names(
        client,
        `SELECT indexname AS name FROM pg_indexes WHERE schemaname = 'public'`,
      );
      expect(indexesBefore).toContain('asset_org_status_idx');
      expect(indexesBefore).not.toContain('asset_org_status_name_id_idx');
      expect(indexesBefore).toContain('asset_active_name_org_idx');

      const checksBefore = await names(
        client,
        `SELECT conname AS name FROM pg_constraint WHERE contype = 'c'`,
      );
      expect(checksBefore).not.toContain('asset_external_identifier_namespace_shape_chk');
      expect(checksBefore).not.toContain('asset_external_identifier_value_chk');

      await deployMigrations(ephemeral.databaseUrl);
      const appliedAfter = await names(
        client,
        `SELECT migration_name AS name FROM _prisma_migrations ORDER BY finished_at`,
      );
      expect(appliedAfter.filter((name) => !appliedBefore.includes(name))).toEqual([
        SESSION_7_ASSET_INVENTORY_CONSTRAINTS,
        SESSION_8_SBOM_INGESTION_GRAPH_PERSISTENCE,
        SESSION_9_KEV_INTELLIGENCE_PERSISTENCE,
      ]);
      await assertFinalMigratedSchema(client);
    } finally {
      await client.$disconnect();
      await dropEphemeralDatabase(ephemeral.admin, ephemeral.databaseName);
    }
  });

  it('upgrades a Session 7 database by applying only graph persistence', async () => {
    const ephemeral = await createEphemeralDatabase('migrate');
    const client = new PrismaClient({
      datasources: { db: { url: ephemeral.databaseUrl } },
    });

    try {
      await applyThroughSession7(ephemeral.databaseUrl);
      const appliedBefore = await names(
        client,
        `SELECT migration_name AS name FROM _prisma_migrations ORDER BY finished_at`,
      );
      expect(appliedBefore).toEqual([
        ...SESSION_6_COMPLETE_MIGRATIONS,
        SESSION_7_ASSET_INVENTORY_CONSTRAINTS,
      ]);
      expect(appliedBefore).not.toContain(SESSION_8_SBOM_INGESTION_GRAPH_PERSISTENCE);

      const ingestionColumnsBefore = await names(
        client,
        `SELECT column_name AS name FROM information_schema.columns
         WHERE table_schema = 'public' AND table_name = 'sbom_ingestion'`,
      );
      expect(ingestionColumnsBefore).not.toContain('graph_completeness');
      expect(ingestionColumnsBefore).not.toContain('normalization_version');

      await deployMigrations(ephemeral.databaseUrl);
      const appliedAfter = await names(
        client,
        `SELECT migration_name AS name FROM _prisma_migrations ORDER BY finished_at`,
      );
      expect(appliedAfter.filter((name) => !appliedBefore.includes(name))).toEqual([
        SESSION_8_SBOM_INGESTION_GRAPH_PERSISTENCE,
        SESSION_9_KEV_INTELLIGENCE_PERSISTENCE,
      ]);
      await assertFinalMigratedSchema(client);
    } finally {
      await client.$disconnect();
      await dropEphemeralDatabase(ephemeral.admin, ephemeral.databaseName);
    }
  });

  it('upgrades a Session 8 database by applying only KEV intelligence persistence', async () => {
    const ephemeral = await createEphemeralDatabase('migrate');
    const client = new PrismaClient({
      datasources: { db: { url: ephemeral.databaseUrl } },
    });

    try {
      await applyThroughSession8(ephemeral.databaseUrl);
      const appliedBefore = await names(
        client,
        `SELECT migration_name AS name FROM _prisma_migrations ORDER BY finished_at`,
      );
      expect(appliedBefore).toEqual([
        ...SESSION_6_COMPLETE_MIGRATIONS,
        SESSION_7_ASSET_INVENTORY_CONSTRAINTS,
        SESSION_8_SBOM_INGESTION_GRAPH_PERSISTENCE,
      ]);
      expect(appliedBefore).not.toContain(SESSION_9_KEV_INTELLIGENCE_PERSISTENCE);
      const tablesBefore = await names(
        client,
        `SELECT tablename AS name FROM pg_tables WHERE schemaname = 'public'`,
      );
      expect(tablesBefore).not.toContain('kev_generation');
      expect(tablesBefore).not.toContain('vulnerability_sync_run');

      await deployMigrations(ephemeral.databaseUrl);
      const appliedAfter = await names(
        client,
        `SELECT migration_name AS name FROM _prisma_migrations ORDER BY finished_at`,
      );
      expect(appliedAfter.filter((name) => !appliedBefore.includes(name))).toEqual([
        SESSION_9_KEV_INTELLIGENCE_PERSISTENCE,
      ]);
      await assertFinalMigratedSchema(client);
    } finally {
      await client.$disconnect();
      await dropEphemeralDatabase(ephemeral.admin, ephemeral.databaseName);
    }
  });

  it('creates authentication tables and the final audit actor CHECK in migration 180000', async () => {
    const ephemeral = await createEphemeralDatabase('migrate');
    const client = new PrismaClient({
      datasources: { db: { url: ephemeral.databaseUrl } },
    });

    try {
      await applyThroughPolicyCreatorMembership(ephemeral.databaseUrl);
      await applyMigrationSqlAndResolve(
        ephemeral.databaseUrl,
        '20260827170000_audit_actor_anonymous',
      );
      await applyMigrationSqlAndResolve(
        ephemeral.databaseUrl,
        '20260827180000_local_credentials_and_sessions',
      );
      await applyMigrationSqlAndResolve(
        ephemeral.databaseUrl,
        SESSION_7_ASSET_INVENTORY_CONSTRAINTS,
      );
      await applyMigrationSqlAndResolve(
        ephemeral.databaseUrl,
        SESSION_8_SBOM_INGESTION_GRAPH_PERSISTENCE,
      );
      await applyMigrationSqlAndResolve(
        ephemeral.databaseUrl,
        SESSION_9_KEV_INTELLIGENCE_PERSISTENCE,
      );
      await assertFinalMigratedSchema(client);

      const checkDef = await names(
        client,
        `SELECT pg_get_constraintdef(oid) AS name FROM pg_constraint WHERE conname = 'audit_event_actor_scope_chk'`,
      );
      expect(checkDef[0]).toContain('anonymous');
      expect(checkDef[0]).toContain('actor_user_id');
    } finally {
      await client.$disconnect();
      await dropEphemeralDatabase(ephemeral.admin, ephemeral.databaseName);
    }
  });

  it('backfills actor_user_id from Membership and keeps audit append-only at runtime', async () => {
    const ephemeral = await createEphemeralDatabase('migrate');
    const client = new PrismaClient({
      datasources: { db: { url: ephemeral.databaseUrl } },
    });
    const orgId = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa9';
    const userId = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb9';
    const membershipId = 'dddddddd-dddd-4ddd-8ddd-ddddddddddd9';
    const auditId = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeee9';

    try {
      await applyThroughPolicyCreatorMembership(ephemeral.databaseUrl);
      const appliedBefore = await names(
        client,
        `SELECT migration_name AS name FROM _prisma_migrations ORDER BY finished_at`,
      );
      expect(appliedBefore).toEqual([...SESSION_6_PREAUTH_MIGRATIONS]);
      const auditColumnsBefore = await names(
        client,
        `SELECT column_name AS name FROM information_schema.columns
         WHERE table_schema = 'public' AND table_name = 'audit_event'`,
      );
      expect(auditColumnsBefore).not.toContain('actor_user_id');

      await client.$executeRaw`
        INSERT INTO "organization" ("id", "slug", "name", "updated_at")
        VALUES (CAST(${orgId} AS UUID), 'auth-backfill-org', 'Auth Backfill Org', CURRENT_TIMESTAMP)
      `;
      await client.$executeRaw`
        INSERT INTO "user" ("id", "email", "display_name", "updated_at")
        VALUES (CAST(${userId} AS UUID), 'auth-backfill@synthetic.patchpilot.test', 'Auth Backfill User', CURRENT_TIMESTAMP)
      `;
      await client.$executeRaw`
        INSERT INTO "membership" ("id", "organization_id", "user_id", "role", "updated_at")
        VALUES (
          CAST(${membershipId} AS UUID),
          CAST(${orgId} AS UUID),
          CAST(${userId} AS UUID),
          'owner',
          CURRENT_TIMESTAMP
        )
      `;
      await client.$executeRaw`
        INSERT INTO "audit_event" (
          "id", "organization_id", "actor_membership_id", "actor_type", "action",
          "subject_type", "subject_id", "correlation_id", "payload", "schema_version"
        )
        VALUES (
          CAST(${auditId} AS UUID),
          CAST(${orgId} AS UUID),
          CAST(${membershipId} AS UUID),
          'user',
          'asset.created',
          'asset',
          CAST(${orgId} AS UUID),
          'corr-auth-backfill',
          '{"schemaVersion":1}'::jsonb,
          1
        )
      `;

      await deployMigrations(ephemeral.databaseUrl);
      const appliedAfter = await names(
        client,
        `SELECT migration_name AS name FROM _prisma_migrations ORDER BY finished_at`,
      );
      expect(appliedAfter.filter((name) => !appliedBefore.includes(name))).toEqual([
        '20260827170000_audit_actor_anonymous',
        '20260827180000_local_credentials_and_sessions',
        SESSION_7_ASSET_INVENTORY_CONSTRAINTS,
        SESSION_8_SBOM_INGESTION_GRAPH_PERSISTENCE,
        SESSION_9_KEV_INTELLIGENCE_PERSISTENCE,
      ]);
      await assertFinalMigratedSchema(client);

      const backfilled = await client.auditEvent.findUniqueOrThrow({ where: { id: auditId } });
      expect(backfilled.actorUserId).toBe(userId);
      expect(backfilled.actorMembershipId).toBe(membershipId);
      expect(backfilled.organizationId).toBe(orgId);
      expect(backfilled.actorType).toBe('user');

      await expect(
        client.auditEvent.update({
          where: { id: auditId },
          data: { action: 'asset.mutated' },
        }),
      ).rejects.toThrow();
      await expect(client.auditEvent.delete({ where: { id: auditId } })).rejects.toThrow();
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
