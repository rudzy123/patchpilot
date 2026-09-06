import { execFile } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

import {
  assertDestructiveDatabaseCommandAllowed,
  assertEphemeralTestDatabaseName,
  cloneProcessEnv,
  inspectDatabaseUrl,
} from '@patchpilot/config';
import { PrismaClient } from '@prisma/client';
import { createFoundationTestEnv } from '@patchpilot/test-utils';

const execFileAsync = promisify(execFile);
const databasePackageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const session3Migration = path.join(
  databasePackageRoot,
  'prisma/migrations/20260826120000_schema_foundation/migration.sql',
);

export const FROZEN_MIGRATIONS = [
  {
    directory: '20260826120000_schema_foundation',
    sha256: 'a491754ebff6f34bb1a6c7421bfb5aa6455b02dfc3e794962d57b2a55cdff4c2',
  },
  {
    directory: '20260827120000_tenant_model',
    sha256: '3d0650847debd65e4276419d59c0bc6a12f1be1769b9f17f2d39084149ea162d',
  },
  {
    directory: '20260827140000_review_corrections',
    sha256: 'f18883b5bdd95c7e3872912321b1354d65b318dc2336f95064037be149ffe9cf',
  },
  {
    directory: '20260827150000_evidence_export_snapshot_chk',
    sha256: '745ca5c464309a08ae236848a4a791e248e6403e5de5b1b16c5dfe29a7a3a545',
  },
  {
    directory: '20260827160000_policy_creator_membership',
    sha256: '1b4bdd7217fb31c7bb456cceb419916f0b3312f8fe7dfd78cc97c10115bb1c14',
  },
  {
    directory: '20260827170000_audit_actor_anonymous',
    sha256: 'aad9e6c54e073514638aac6f13c4ba09e9018a7645356aa5d0bc8bc0ce683d5d',
  },
  {
    directory: '20260827180000_local_credentials_and_sessions',
    sha256: '3a5a9adb12dbf0fea656c225056cdef8f2fc048229ad10cf1ba81b14265eedd0',
  },
  {
    directory: '20260828120000_asset_inventory_constraints',
    sha256: '3270a9ec871a5cf8ec522c245ede9a3312aef6182950abd23d08dce342ec6f18',
  },
  {
    directory: '20260830120000_sbom_ingestion_graph_persistence',
    sha256: '920e7e685aeaa69c8515053d373353385e90c1a741404f93b0b1222a0abc2446',
  },
  {
    directory: '20260901120000_kev_intelligence_persistence',
    sha256: '304d31945a6698ae5adaad14cd10336a3e7bc61b85be7ad26918e3867f21a06a',
  },
  {
    directory: '20260902120000_canonical_cve_identity',
    sha256: '2190b5a0d22cf008fa01a180bc9233a68ba56159447bc599a4a2a1dba684b0ba',
  },
  {
    directory: '20260904120000_osv_acquisition_persistence_foundation',
    sha256: 'ac99d96d97074b9ad38064ccbbcd9670321bed0872c20a71c0a679d837704349',
  },
  {
    directory: '20260904180000_osv_parsed_revision_id_check_correction',
    sha256: '43f758f559abc1c936197f6d5944f85cb14ef1cbed2a99bd0f555759ebdc1570',
  },
] as const;

export const SESSION_7_ASSET_INVENTORY_CONSTRAINTS =
  '20260828120000_asset_inventory_constraints' as const;

export const SESSION_8_SBOM_INGESTION_GRAPH_PERSISTENCE =
  '20260830120000_sbom_ingestion_graph_persistence' as const;

export const SESSION_9_KEV_INTELLIGENCE_PERSISTENCE =
  '20260901120000_kev_intelligence_persistence' as const;

export const SESSION_10_CANONICAL_CVE_IDENTITY = '20260902120000_canonical_cve_identity' as const;

export const SESSION_11_OSV_ACQUISITION_PERSISTENCE_FOUNDATION =
  '20260904120000_osv_acquisition_persistence_foundation' as const;

export const SESSION_11_OSV_PARSED_REVISION_ID_CHECK_CORRECTION =
  '20260904180000_osv_parsed_revision_id_check_correction' as const;

export const EXPECTED_APPLIED_MIGRATIONS = [
  '20260826120000_schema_foundation',
  '20260827120000_tenant_model',
  '20260827140000_review_corrections',
  '20260827150000_evidence_export_snapshot_chk',
  '20260827160000_policy_creator_membership',
  '20260827170000_audit_actor_anonymous',
  '20260827180000_local_credentials_and_sessions',
  SESSION_7_ASSET_INVENTORY_CONSTRAINTS,
  SESSION_8_SBOM_INGESTION_GRAPH_PERSISTENCE,
  SESSION_9_KEV_INTELLIGENCE_PERSISTENCE,
  SESSION_10_CANONICAL_CVE_IDENTITY,
  SESSION_11_OSV_ACQUISITION_PERSISTENCE_FOUNDATION,
  SESSION_11_OSV_PARSED_REVISION_ID_CHECK_CORRECTION,
] as const;

export function frozenMigrationFile(directory: string): string {
  return path.join(databasePackageRoot, 'prisma/migrations', directory, 'migration.sql');
}

export async function sha256File(filePath: string): Promise<string> {
  const contents = await readFile(filePath);
  return createHash('sha256').update(contents).digest('hex');
}

export function testDatabaseUrl(): string {
  const env = createFoundationTestEnv();
  const url = env['DATABASE_URL'];
  if (url === undefined) {
    throw new Error('Test DATABASE_URL is missing.');
  }

  return url;
}

export function withDatabaseName(databaseUrl: string, databaseName: string): string {
  const parsed = new URL(databaseUrl);
  parsed.pathname = `/${databaseName}`;
  return parsed.toString();
}

export async function createEphemeralDatabase(label: 'it' | 'migrate'): Promise<{
  databaseName: string;
  databaseUrl: string;
  admin: PrismaClient;
}> {
  const env = createFoundationTestEnv();
  const baseUrl = testDatabaseUrl();
  assertDestructiveDatabaseCommandAllowed(env, baseUrl);

  const databaseName = `patchpilot_${label}_${randomBytes(6).toString('hex')}`;
  assertEphemeralTestDatabaseName(databaseName);

  const admin = new PrismaClient({
    datasources: { db: { url: withDatabaseName(baseUrl, 'postgres') } },
  });

  await admin.$executeRawUnsafe(`CREATE DATABASE "${databaseName}"`);
  return {
    databaseName,
    databaseUrl: withDatabaseName(baseUrl, databaseName),
    admin,
  };
}

export async function dropEphemeralDatabase(
  admin: PrismaClient,
  databaseName: string,
): Promise<void> {
  assertEphemeralTestDatabaseName(databaseName);
  await admin.$executeRawUnsafe(`DROP DATABASE IF EXISTS "${databaseName}" WITH (FORCE)`);
  await admin.$disconnect();
}

export async function deployMigrations(databaseUrl: string): Promise<void> {
  inspectDatabaseUrl(databaseUrl);
  await execFileAsync('pnpm', ['exec', 'prisma', 'migrate', 'deploy'], {
    cwd: databasePackageRoot,
    env: cloneProcessEnv({ DATABASE_URL: databaseUrl }),
  });
}

export async function applySession3Schema(databaseUrl: string): Promise<void> {
  const sql = await readFile(session3Migration, 'utf8');
  const client = new PrismaClient({
    datasources: { db: { url: databaseUrl } },
  });

  try {
    await client.$executeRawUnsafe(sql);
  } finally {
    await client.$disconnect();
  }

  await execFileAsync(
    'pnpm',
    ['exec', 'prisma', 'migrate', 'resolve', '--applied', '20260826120000_schema_foundation'],
    {
      cwd: databasePackageRoot,
      env: cloneProcessEnv({ DATABASE_URL: databaseUrl }),
    },
  );
}

export async function applyMigrationSqlAndResolve(
  databaseUrl: string,
  directory: string,
): Promise<void> {
  inspectDatabaseUrl(databaseUrl);
  await execFileAsync(
    'pnpm',
    [
      'exec',
      'prisma',
      'db',
      'execute',
      '--file',
      path.join('prisma/migrations', directory, 'migration.sql'),
      '--schema',
      'prisma/schema.prisma',
    ],
    {
      cwd: databasePackageRoot,
      env: cloneProcessEnv({ DATABASE_URL: databaseUrl }),
    },
  );
  await execFileAsync('pnpm', ['exec', 'prisma', 'migrate', 'resolve', '--applied', directory], {
    cwd: databasePackageRoot,
    env: cloneProcessEnv({ DATABASE_URL: databaseUrl }),
  });
}

export async function applyThroughSession5(databaseUrl: string): Promise<void> {
  await applySession3Schema(databaseUrl);
  await applyMigrationSqlAndResolve(databaseUrl, '20260827120000_tenant_model');
}

export const REVIEWED_SESSION_5_MIGRATIONS = [
  '20260826120000_schema_foundation',
  '20260827120000_tenant_model',
  '20260827140000_review_corrections',
  '20260827150000_evidence_export_snapshot_chk',
] as const;

export async function applyThroughReviewedSession5(databaseUrl: string): Promise<void> {
  await applySession3Schema(databaseUrl);
  await applyMigrationSqlAndResolve(databaseUrl, '20260827120000_tenant_model');
  await applyMigrationSqlAndResolve(databaseUrl, '20260827140000_review_corrections');
  await applyMigrationSqlAndResolve(databaseUrl, '20260827150000_evidence_export_snapshot_chk');
}

export const SESSION_6_PREAUTH_MIGRATIONS = [
  ...REVIEWED_SESSION_5_MIGRATIONS,
  '20260827160000_policy_creator_membership',
] as const;

export async function applyThroughPolicyCreatorMembership(databaseUrl: string): Promise<void> {
  await applyThroughReviewedSession5(databaseUrl);
  await applyMigrationSqlAndResolve(databaseUrl, '20260827160000_policy_creator_membership');
}

export const SESSION_6_THROUGH_ANONYMOUS_MIGRATIONS = [
  ...SESSION_6_PREAUTH_MIGRATIONS,
  '20260827170000_audit_actor_anonymous',
] as const;

export async function applyThroughAuditActorAnonymous(databaseUrl: string): Promise<void> {
  await applyThroughPolicyCreatorMembership(databaseUrl);
  await applyMigrationSqlAndResolve(databaseUrl, '20260827170000_audit_actor_anonymous');
}

export const SESSION_6_COMPLETE_MIGRATIONS = [
  ...SESSION_6_THROUGH_ANONYMOUS_MIGRATIONS,
  '20260827180000_local_credentials_and_sessions',
] as const;

export async function applyThroughSession6(databaseUrl: string): Promise<void> {
  await applyThroughAuditActorAnonymous(databaseUrl);
  await applyMigrationSqlAndResolve(databaseUrl, '20260827180000_local_credentials_and_sessions');
}

export async function applyThroughSession7(databaseUrl: string): Promise<void> {
  await applyThroughSession6(databaseUrl);
  await applyMigrationSqlAndResolve(databaseUrl, SESSION_7_ASSET_INVENTORY_CONSTRAINTS);
}

export async function applyThroughSession8(databaseUrl: string): Promise<void> {
  await applyThroughSession7(databaseUrl);
  await applyMigrationSqlAndResolve(databaseUrl, SESSION_8_SBOM_INGESTION_GRAPH_PERSISTENCE);
}

export async function applyThroughSession9(databaseUrl: string): Promise<void> {
  await applyThroughSession8(databaseUrl);
  await applyMigrationSqlAndResolve(databaseUrl, SESSION_9_KEV_INTELLIGENCE_PERSISTENCE);
}

export async function applyThroughSession10(databaseUrl: string): Promise<void> {
  await applyThroughSession9(databaseUrl);
  await applyMigrationSqlAndResolve(databaseUrl, SESSION_10_CANONICAL_CVE_IDENTITY);
}

export async function applyThroughSession11(databaseUrl: string): Promise<void> {
  await applyThroughSession10(databaseUrl);
  await applyMigrationSqlAndResolve(databaseUrl, SESSION_11_OSV_ACQUISITION_PERSISTENCE_FOUNDATION);
}
