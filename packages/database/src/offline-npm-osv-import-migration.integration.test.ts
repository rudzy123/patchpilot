/**
 * Disposable PostgreSQL proof for migration 27.
 * Synthetic advisory identities only. No real GHSA body is stored.
 */

import { createHash } from 'node:crypto';
import { Prisma, PrismaClient } from '@prisma/client';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
} from './integration-database.js';

const MODIFIED_AT = '2026-01-01T00:00:00.000Z';
const PUBLISHED_AT = '2025-12-01T00:00:00.000Z';
const RETRIEVED_AT = '2026-11-02T12:00:00.000Z';
const WITHDRAWN_AT = '2026-02-01T00:00:00.000Z';

type Sql = Pick<Prisma.TransactionClient, '$executeRaw'>;

function digest(label: string): string {
  return createHash('sha256').update(label).digest('hex');
}

async function insertFamily(
  tx: Sql,
  input: { readonly id: string; readonly advisoryId: string; readonly label: string },
): Promise<void> {
  await tx.$executeRaw`
    INSERT INTO "advisory_family" (
      "id", "family_schema_version", "source", "advisory_id", "family_digest",
      "source_registry_version"
    ) VALUES (
      ${input.id}::uuid,
      'osv_advisory_family_identity_v1',
      'github_advisory_database'::"advisory_evidence_source",
      ${input.advisoryId},
      ${digest(`${input.label}:family`)},
      'osv_source_license_registry_v1'
    )
  `;
}

async function insertBatch(
  tx: Sql,
  input: { readonly id: string; readonly label: string },
): Promise<void> {
  await tx.$executeRaw`
    INSERT INTO "offline_advisory_import_batch" (
      "id", "manifest_sha256", "source_license_registry_version", "retrieved_at"
    ) VALUES (
      ${input.id}::uuid,
      ${digest(`${input.label}:manifest`)},
      'osv_source_license_registry_v1',
      ${RETRIEVED_AT}::timestamptz
    )
  `;
}

async function insertRevision(
  tx: Sql,
  input: {
    readonly id: string;
    readonly familyId: string;
    readonly advisoryId: string;
    readonly label: string;
    readonly packageName: string;
    readonly packageIdentityKey: string;
    readonly offline: boolean;
    readonly familyLabel?: string;
    readonly disposition?: 'recorded' | 'superseding' | 'withdrawn';
    readonly withdrawal?: 'not_withdrawn' | 'withdrawn';
    readonly supersedesRevisionId?: string;
    readonly supersedesRevisionDigest?: string;
  },
): Promise<void> {
  const disposition = input.disposition ?? 'recorded';
  const withdrawal = input.withdrawal ?? 'not_withdrawn';
  const supersedesDigest = input.supersedesRevisionDigest ?? 'none';
  await tx.$executeRaw`
    INSERT INTO "advisory_revision" (
      "id", "revision_schema_version", "advisory_family_id", "source", "advisory_id",
      "family_digest", "revision_digest", "provider_generation", "content_fingerprint",
      "session14_range_fingerprint", "product_range_fingerprint", "parser_id",
      "parser_resource_policy", "advisory_schema_version", "advisory_schema_commit",
      "source_license_registry_version", "source_license_policy_version", "spdx_license_id",
      "origin", "trust_classification", "revision_disposition", "withdrawal_classification",
      "quarantine_classification", "supersedes_revision_digest", "supersedes_advisory_revision_id",
      "retrieval_classification", "retrieval_evidence_id", "retrieval_policy_id", "ecosystem",
      "package_name", "package_identity_key", "evaluator_version", "matching_policy_id",
      "alias_count", "cve_alias_count", "alias_set_digest", "replay_fingerprint"
    ) VALUES (
      ${input.id}::uuid,
      ${input.offline ? 'offline_npm_advisory_revision_identity_v1' : 'osv_advisory_revision_identity_v1'},
      ${input.familyId}::uuid,
      'github_advisory_database'::"advisory_evidence_source",
      ${input.advisoryId},
      ${digest(`${input.familyLabel ?? input.label}:family`)},
      ${digest(`${input.label}:revision`)},
      ${input.offline ? 'offline-import-v1' : '1'},
      ${digest(`${input.label}:content`)},
      ${digest(`${input.label}:session14`)},
      ${digest(`${input.label}:product`)},
      'osv_advisory_parser_protocol_v1',
      'osv_advisory_parser_resource_policy_v1',
      'v1.9.0',
      'f3f826310aeca8e324baabd195632f2229952abe',
      'osv_source_license_registry_v1',
      'osv_source_license_registry_v1',
      'CC-BY-4.0',
      'provider_derived'::"advisory_evidence_origin",
      'unreviewed'::"advisory_evidence_trust",
      ${disposition}::"advisory_revision_disposition",
      ${withdrawal}::"advisory_withdrawal_classification",
      'not_quarantined'::"advisory_quarantine_classification",
      ${supersedesDigest},
      ${input.supersedesRevisionId ?? null}::uuid,
      ${input.offline ? 'local_not_retrieved' : 'recorded_reference'}::"advisory_retrieval_classification",
      ${input.offline ? 'offline_import_retrieval_not_applicable' : '11111111-1111-4111-8111-111111111111'},
      ${input.offline ? 'offline_osv_import_retrieval_policy_v1' : 'osv_generation_bound_retrieval_policy_v1'},
      'npm',
      ${input.packageName},
      ${input.packageIdentityKey},
      'session_14_batch_2_in_memory',
      'osv_first_ecosystem_matching_architecture_v1',
      0,
      0,
      ${digest(`${input.label}:aliases`)},
      ${digest(`${input.label}:replay`)}
    )
  `;
}

async function insertProvenance(
  tx: Sql,
  input: {
    readonly id: string;
    readonly revisionId: string;
    readonly batchId: string;
    readonly advisoryId: string;
    readonly packageIdentityKey: string;
    readonly label: string;
    readonly withdrawnAt?: string | null;
  },
): Promise<void> {
  await tx.$executeRaw`
    INSERT INTO "advisory_revision_source_provenance" (
      "id", "advisory_revision_id", "source", "source_license_registry_version",
      "advisory_id", "package_identity_key", "raw_content_sha256", "parser_id",
      "parser_resource_policy", "advisory_schema_version", "advisory_schema_commit",
      "normalization_identity", "retrieved_at", "modified_at", "published_at",
      "withdrawn_at", "purl", "license_admission_reason", "offline_advisory_import_batch_id"
    ) VALUES (
      ${input.id}::uuid,
      ${input.revisionId}::uuid,
      'github_advisory_database'::"advisory_evidence_source",
      'osv_source_license_registry_v1',
      ${input.advisoryId},
      ${input.packageIdentityKey},
      ${digest(`${input.label}:raw`)},
      'osv_advisory_parser_protocol_v1',
      'osv_advisory_parser_resource_policy_v1',
      'v1.9.0',
      'f3f826310aeca8e324baabd195632f2229952abe',
      'offline_npm_osv_normalization_v1',
      ${RETRIEVED_AT}::timestamptz,
      ${MODIFIED_AT}::timestamptz,
      ${PUBLISHED_AT}::timestamptz,
      ${input.withdrawnAt ?? null}::timestamptz,
      'pkg:npm/left-pad@1.0.0',
      'approved_source_license',
      ${input.batchId}::uuid
    )
  `;
}

async function insertVersion(
  tx: Sql,
  input: {
    readonly id: string;
    readonly revisionId: string;
    readonly ordinal: number;
    readonly versionText: string;
  },
): Promise<void> {
  await tx.$executeRaw`
    INSERT INTO "advisory_revision_explicit_version" (
      "id", "advisory_revision_id", "ordinal", "version_text"
    ) VALUES (
      ${input.id}::uuid,
      ${input.revisionId}::uuid,
      ${input.ordinal},
      ${input.versionText}
    )
  `;
}

async function insertRange(
  tx: Sql,
  input: { readonly id: string; readonly revisionId: string },
): Promise<void> {
  await tx.$executeRaw`
    INSERT INTO "advisory_revision_range_event" (
      "id", "advisory_revision_id", "range_ordinal", "event_ordinal", "event_name", "event_value"
    ) VALUES (
      ${input.id}::uuid,
      ${input.revisionId}::uuid,
      0,
      0,
      'introduced',
      '0'
    )
  `;
}

describe('offline npm osv import migration', { timeout: 90_000 }, () => {
  let databaseName = '';
  let admin: PrismaClient | undefined;
  let prisma: PrismaClient | undefined;

  beforeAll(async () => {
    const ephemeral = await createEphemeralDatabase('migrate', { scope: 'osv27' });
    databaseName = ephemeral.databaseName;
    admin = ephemeral.admin;
    await deployMigrations(ephemeral.databaseUrl);
    prisma = new PrismaClient({ datasources: { db: { url: ephemeral.databaseUrl } } });
  });

  afterAll(async () => {
    await prisma?.$disconnect();
    if (admin !== undefined) {
      await dropEphemeralDatabase(admin, databaseName);
    }
  });

  function client(): PrismaClient {
    if (prisma === undefined) {
      throw new Error('migration database is not connected');
    }
    return prisma;
  }

  it('keeps a recorded provider revision free of offline provenance', async () => {
    const db = client();
    await db.$transaction(async (tx) => {
      await insertFamily(tx, {
        id: '10000000-0000-4000-8000-000000000001',
        advisoryId: 'GHSA-SYN0-PROV-0001',
        label: 'provider-recorded',
      });
      await insertRevision(tx, {
        id: '10000000-0000-4000-8000-000000000002',
        familyId: '10000000-0000-4000-8000-000000000001',
        advisoryId: 'GHSA-SYN0-PROV-0001',
        label: 'provider-recorded',
        packageName: 'left-pad',
        packageIdentityKey: 'npm/left-pad',
        offline: false,
      });
    });
    const provenance = await db.$queryRaw<Array<{ count: bigint }>>`
      SELECT COUNT(*)::bigint AS count
      FROM "advisory_revision_source_provenance"
      WHERE "advisory_revision_id" = '10000000-0000-4000-8000-000000000002'::uuid
    `;
    expect(Number(provenance[0]?.count)).toBe(0);
  });

  it('commits an offline revision with provenance and one explicit version', async () => {
    const db = client();
    await db.$transaction(async (tx) => {
      await insertBatch(tx, {
        id: '10000000-0000-4000-8000-000000000011',
        label: 'offline-version',
      });
      await insertFamily(tx, {
        id: '10000000-0000-4000-8000-000000000012',
        advisoryId: 'GHSA-SYN0-OFFL-0001',
        label: 'offline-version',
      });
      await insertRevision(tx, {
        id: '10000000-0000-4000-8000-000000000013',
        familyId: '10000000-0000-4000-8000-000000000012',
        advisoryId: 'GHSA-SYN0-OFFL-0001',
        label: 'offline-version',
        packageName: 'left-pad',
        packageIdentityKey: 'npm/left-pad',
        offline: true,
      });
      await insertProvenance(tx, {
        id: '10000000-0000-4000-8000-000000000014',
        revisionId: '10000000-0000-4000-8000-000000000013',
        batchId: '10000000-0000-4000-8000-000000000011',
        advisoryId: 'GHSA-SYN0-OFFL-0001',
        packageIdentityKey: 'npm/left-pad',
        label: 'offline-version',
      });
      await insertVersion(tx, {
        id: '10000000-0000-4000-8000-000000000015',
        revisionId: '10000000-0000-4000-8000-000000000013',
        ordinal: 0,
        versionText: '1.0.0',
      });
    });
    const stored = await db.$queryRaw<
      Array<{ versions: bigint; findings: bigint; vulnerabilities: bigint }>
    >`
      SELECT
        (SELECT COUNT(*) FROM "advisory_revision_explicit_version"
          WHERE "advisory_revision_id" = '10000000-0000-4000-8000-000000000013'::uuid)::bigint AS versions,
        (SELECT COUNT(*) FROM "finding")::bigint AS findings,
        (SELECT COUNT(*) FROM "vulnerability")::bigint AS vulnerabilities
    `;
    expect(Number(stored[0]?.versions)).toBe(1);
    expect(Number(stored[0]?.findings)).toBe(0);
    expect(Number(stored[0]?.vulnerabilities)).toBe(0);
  });

  it('commits an offline revision that has a range and no explicit version', async () => {
    const db = client();
    await db.$transaction(async (tx) => {
      await insertBatch(tx, {
        id: '10000000-0000-4000-8000-000000000021',
        label: 'offline-range',
      });
      await insertFamily(tx, {
        id: '10000000-0000-4000-8000-000000000022',
        advisoryId: 'GHSA-SYN0-OFFL-0002',
        label: 'offline-range',
      });
      await insertRevision(tx, {
        id: '10000000-0000-4000-8000-000000000023',
        familyId: '10000000-0000-4000-8000-000000000022',
        advisoryId: 'GHSA-SYN0-OFFL-0002',
        label: 'offline-range',
        packageName: 'left-pad',
        packageIdentityKey: 'npm/left-pad',
        offline: true,
      });
      await insertProvenance(tx, {
        id: '10000000-0000-4000-8000-000000000024',
        revisionId: '10000000-0000-4000-8000-000000000023',
        batchId: '10000000-0000-4000-8000-000000000021',
        advisoryId: 'GHSA-SYN0-OFFL-0002',
        packageIdentityKey: 'npm/left-pad',
        label: 'offline-range',
      });
      await insertRange(tx, {
        id: '10000000-0000-4000-8000-000000000025',
        revisionId: '10000000-0000-4000-8000-000000000023',
      });
    });
    const versions = await db.$queryRaw<Array<{ count: bigint }>>`
      SELECT COUNT(*)::bigint AS count
      FROM "advisory_revision_explicit_version"
      WHERE "advisory_revision_id" = '10000000-0000-4000-8000-000000000023'::uuid
    `;
    expect(Number(versions[0]?.count)).toBe(0);
  });

  it('rolls back an offline revision that has no provenance', async () => {
    const db = client();
    await expect(
      db.$transaction(async (tx) => {
        await insertBatch(tx, {
          id: '10000000-0000-4000-8000-000000000031',
          label: 'offline-missing-provenance',
        });
        await insertFamily(tx, {
          id: '10000000-0000-4000-8000-000000000032',
          advisoryId: 'GHSA-SYN0-OFFL-0003',
          label: 'offline-missing-provenance',
        });
        await insertRevision(tx, {
          id: '10000000-0000-4000-8000-000000000033',
          familyId: '10000000-0000-4000-8000-000000000032',
          advisoryId: 'GHSA-SYN0-OFFL-0003',
          label: 'offline-missing-provenance',
          packageName: 'left-pad',
          packageIdentityKey: 'npm/left-pad',
          offline: true,
        });
        await insertVersion(tx, {
          id: '10000000-0000-4000-8000-000000000034',
          revisionId: '10000000-0000-4000-8000-000000000033',
          ordinal: 0,
          versionText: '1.0.0',
        });
      }),
    ).rejects.toThrow(/offline advisory provenance is missing/);
    const families = await db.$queryRaw<Array<{ count: bigint }>>`
      SELECT COUNT(*)::bigint AS count
      FROM "advisory_family"
      WHERE "advisory_id" = 'GHSA-SYN0-OFFL-0003'
    `;
    expect(Number(families[0]?.count)).toBe(0);
  });

  it('rolls back explicit versions that skip an ordinal', async () => {
    const db = client();
    await expect(
      db.$transaction(async (tx) => {
        await insertBatch(tx, {
          id: '10000000-0000-4000-8000-000000000041',
          label: 'offline-gap',
        });
        await insertFamily(tx, {
          id: '10000000-0000-4000-8000-000000000042',
          advisoryId: 'GHSA-SYN0-OFFL-0004',
          label: 'offline-gap',
        });
        await insertRevision(tx, {
          id: '10000000-0000-4000-8000-000000000043',
          familyId: '10000000-0000-4000-8000-000000000042',
          advisoryId: 'GHSA-SYN0-OFFL-0004',
          label: 'offline-gap',
          packageName: 'left-pad',
          packageIdentityKey: 'npm/left-pad',
          offline: true,
        });
        await insertProvenance(tx, {
          id: '10000000-0000-4000-8000-000000000044',
          revisionId: '10000000-0000-4000-8000-000000000043',
          batchId: '10000000-0000-4000-8000-000000000041',
          advisoryId: 'GHSA-SYN0-OFFL-0004',
          packageIdentityKey: 'npm/left-pad',
          label: 'offline-gap',
        });
        await insertVersion(tx, {
          id: '10000000-0000-4000-8000-000000000045',
          revisionId: '10000000-0000-4000-8000-000000000043',
          ordinal: 0,
          versionText: '1.0.0',
        });
        await insertVersion(tx, {
          id: '10000000-0000-4000-8000-000000000046',
          revisionId: '10000000-0000-4000-8000-000000000043',
          ordinal: 2,
          versionText: '1.2.0',
        });
      }),
    ).rejects.toThrow(/offline advisory explicit versions are not contiguous/);
  });

  it('rejects a second batch with the same manifest hash and forbids mutation', async () => {
    const db = client();
    await expect(
      db.$executeRaw`
        INSERT INTO "offline_advisory_import_batch" (
          "id", "manifest_sha256", "source_license_registry_version", "retrieved_at"
        ) VALUES (
          '10000000-0000-4000-8000-000000000051'::uuid,
          ${digest('offline-version:manifest')},
          'osv_source_license_registry_v1',
          ${RETRIEVED_AT}::timestamptz
        )
      `,
    ).rejects.toThrow();
    await expect(
      db.$executeRaw`
        UPDATE "offline_advisory_import_batch"
        SET "retrieved_at" = '2026-11-03T00:00:00.000Z'::timestamptz
        WHERE "id" = '10000000-0000-4000-8000-000000000011'::uuid
      `,
    ).rejects.toThrow(/append-only/);
    await expect(
      db.$executeRaw`
        DELETE FROM "advisory_revision_source_provenance"
        WHERE "id" = '10000000-0000-4000-8000-000000000014'::uuid
      `,
    ).rejects.toThrow(/append-only/);
    await expect(
      db.$executeRaw`
        DELETE FROM "advisory_revision_explicit_version"
        WHERE "id" = '10000000-0000-4000-8000-000000000015'::uuid
      `,
    ).rejects.toThrow(/append-only/);
  });

  it('rejects cross-package supersession and commits a same-package successor', async () => {
    const db = client();
    await expect(
      db.$transaction(async (tx) => {
        await insertBatch(tx, {
          id: '10000000-0000-4000-8000-000000000061',
          label: 'offline-cross-package',
        });
        await insertRevision(tx, {
          id: '10000000-0000-4000-8000-000000000063',
          familyId: '10000000-0000-4000-8000-000000000012',
          advisoryId: 'GHSA-SYN0-OFFL-0001',
          label: 'offline-cross-package',
          familyLabel: 'offline-version',
          packageName: 'right-pad',
          packageIdentityKey: 'npm/right-pad',
          offline: true,
          disposition: 'superseding',
          supersedesRevisionId: '10000000-0000-4000-8000-000000000013',
          supersedesRevisionDigest: digest('offline-version:revision'),
        });
        await insertProvenance(tx, {
          id: '10000000-0000-4000-8000-000000000064',
          revisionId: '10000000-0000-4000-8000-000000000063',
          batchId: '10000000-0000-4000-8000-000000000061',
          advisoryId: 'GHSA-SYN0-OFFL-0001',
          packageIdentityKey: 'npm/right-pad',
          label: 'offline-cross-package',
        });
        await insertVersion(tx, {
          id: '10000000-0000-4000-8000-000000000065',
          revisionId: '10000000-0000-4000-8000-000000000063',
          ordinal: 0,
          versionText: '2.0.0',
        });
      }),
    ).rejects.toThrow(/advisory supersession package is inconsistent/);

    await db.$transaction(async (tx) => {
      await insertBatch(tx, {
        id: '10000000-0000-4000-8000-000000000071',
        label: 'offline-same-package',
      });
      await insertRevision(tx, {
        id: '10000000-0000-4000-8000-000000000073',
        familyId: '10000000-0000-4000-8000-000000000012',
        advisoryId: 'GHSA-SYN0-OFFL-0001',
        label: 'offline-same-package',
        familyLabel: 'offline-version',
        packageName: 'left-pad',
        packageIdentityKey: 'npm/left-pad',
        offline: true,
        disposition: 'superseding',
        supersedesRevisionId: '10000000-0000-4000-8000-000000000013',
        supersedesRevisionDigest: digest('offline-version:revision'),
      });
      await insertProvenance(tx, {
        id: '10000000-0000-4000-8000-000000000074',
        revisionId: '10000000-0000-4000-8000-000000000073',
        batchId: '10000000-0000-4000-8000-000000000071',
        advisoryId: 'GHSA-SYN0-OFFL-0001',
        packageIdentityKey: 'npm/left-pad',
        label: 'offline-same-package',
      });
      await insertVersion(tx, {
        id: '10000000-0000-4000-8000-000000000075',
        revisionId: '10000000-0000-4000-8000-000000000073',
        ordinal: 0,
        versionText: '1.0.1',
      });
    });
    const successor = await db.$queryRaw<Array<{ disposition: string }>>`
      SELECT "revision_disposition"::text AS disposition
      FROM "advisory_revision"
      WHERE "id" = '10000000-0000-4000-8000-000000000073'::uuid
    `;
    expect(successor[0]?.disposition).toBe('superseding');
  });

  it('requires a withdrawn timestamp only when the revision is withdrawn', async () => {
    const db = client();
    await expect(
      db.$transaction(async (tx) => {
        await insertBatch(tx, {
          id: '10000000-0000-4000-8000-000000000081',
          label: 'offline-withdrawn-missing',
        });
        await insertFamily(tx, {
          id: '10000000-0000-4000-8000-000000000082',
          advisoryId: 'GHSA-SYN0-OFFL-0005',
          label: 'offline-withdrawn-missing',
        });
        await insertRevision(tx, {
          id: '10000000-0000-4000-8000-000000000083',
          familyId: '10000000-0000-4000-8000-000000000082',
          advisoryId: 'GHSA-SYN0-OFFL-0005',
          label: 'offline-withdrawn-missing',
          packageName: 'left-pad',
          packageIdentityKey: 'npm/left-pad',
          offline: true,
          disposition: 'withdrawn',
          withdrawal: 'withdrawn',
        });
        await insertProvenance(tx, {
          id: '10000000-0000-4000-8000-000000000084',
          revisionId: '10000000-0000-4000-8000-000000000083',
          batchId: '10000000-0000-4000-8000-000000000081',
          advisoryId: 'GHSA-SYN0-OFFL-0005',
          packageIdentityKey: 'npm/left-pad',
          label: 'offline-withdrawn-missing',
          withdrawnAt: null,
        });
        await insertVersion(tx, {
          id: '10000000-0000-4000-8000-000000000085',
          revisionId: '10000000-0000-4000-8000-000000000083',
          ordinal: 0,
          versionText: '9.9.9',
        });
      }),
    ).rejects.toThrow(/offline advisory provenance withdrawal is missing/);

    await db.$transaction(async (tx) => {
      await insertBatch(tx, {
        id: '10000000-0000-4000-8000-000000000091',
        label: 'offline-withdrawn',
      });
      await insertFamily(tx, {
        id: '10000000-0000-4000-8000-000000000092',
        advisoryId: 'GHSA-SYN0-OFFL-0006',
        label: 'offline-withdrawn',
      });
      await insertRevision(tx, {
        id: '10000000-0000-4000-8000-000000000093',
        familyId: '10000000-0000-4000-8000-000000000092',
        advisoryId: 'GHSA-SYN0-OFFL-0006',
        label: 'offline-withdrawn',
        packageName: 'left-pad',
        packageIdentityKey: 'npm/left-pad',
        offline: true,
        disposition: 'withdrawn',
        withdrawal: 'withdrawn',
      });
      await insertProvenance(tx, {
        id: '10000000-0000-4000-8000-000000000094',
        revisionId: '10000000-0000-4000-8000-000000000093',
        batchId: '10000000-0000-4000-8000-000000000091',
        advisoryId: 'GHSA-SYN0-OFFL-0006',
        packageIdentityKey: 'npm/left-pad',
        label: 'offline-withdrawn',
        withdrawnAt: WITHDRAWN_AT,
      });
      await insertVersion(tx, {
        id: '10000000-0000-4000-8000-000000000095',
        revisionId: '10000000-0000-4000-8000-000000000093',
        ordinal: 0,
        versionText: '9.9.9',
      });
    });
  });

  it('stores no organization column and restricts deletes', async () => {
    const db = client();
    const columns = await db.$queryRaw<Array<{ table_name: string }>>`
      SELECT "table_name"
      FROM "information_schema"."columns"
      WHERE "table_schema" = 'public'
        AND "column_name" = 'organization_id'
        AND "table_name" IN (
          'offline_advisory_import_batch',
          'advisory_revision_source_provenance',
          'advisory_revision_explicit_version'
        )
    `;
    expect(columns).toEqual([]);
    const deletes = await db.$queryRaw<Array<{ conname: string }>>`
      SELECT c.conname
      FROM pg_constraint c
      JOIN pg_class rel ON rel.oid = c.conrelid
      JOIN pg_namespace n ON n.oid = rel.relnamespace
      WHERE n.nspname = 'public'
        AND c.contype = 'f'
        AND rel.relname IN (
          'offline_advisory_import_batch',
          'advisory_revision_source_provenance',
          'advisory_revision_explicit_version'
        )
        AND c.confdeltype <> 'r'
    `;
    expect(deletes).toEqual([]);
    await expect(
      insertVersion(db, {
        id: '10000000-0000-4000-8000-000000000096',
        revisionId: '10000000-0000-4000-8000-000000000013',
        ordinal: 1,
        versionText: '1.0.2',
      }),
    ).rejects.toThrow(/offline advisory explicit versions are closed/);
  });
});
