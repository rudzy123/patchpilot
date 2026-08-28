import { randomUUID } from 'node:crypto';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { PrismaClient } from '@prisma/client';

import {
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
} from './integration-database.js';

const ASSET_INDEXES = [
  'asset_pkey',
  'asset_org_id_key',
  'asset_org_environment_idx',
  'asset_org_owning_team_idx',
  'asset_org_last_observed_idx',
  'asset_active_name_org_idx',
  'asset_org_status_name_id_idx',
] as const;

describe('asset inventory constraints', () => {
  let databaseName: string;
  let admin: PrismaClient;
  let prisma: PrismaClient;

  beforeAll(async () => {
    const ephemeral = await createEphemeralDatabase('it');
    databaseName = ephemeral.databaseName;
    admin = ephemeral.admin;
    await deployMigrations(ephemeral.databaseUrl);
    prisma = new PrismaClient({
      datasources: { db: { url: ephemeral.databaseUrl } },
    });
  });

  afterAll(async () => {
    if (prisma !== undefined) {
      await prisma.$disconnect();
    }
    if (admin !== undefined && databaseName !== undefined) {
      await dropEphemeralDatabase(admin, databaseName);
    }
  });

  async function createOrg(slug: string) {
    return prisma.organization.create({
      data: { slug, name: `Org ${slug}` },
    });
  }

  async function createAsset(organizationId: string, name: string) {
    return prisma.asset.create({
      data: { organizationId, name, assetType: 'application' },
    });
  }

  async function insertExternalIdentifier(
    organizationId: string,
    assetId: string,
    namespace: string,
    identifier: string,
  ) {
    return prisma.$executeRaw`
      INSERT INTO "asset_external_identifier" (
        "organization_id", "asset_id", "namespace", "identifier"
      )
      VALUES (
        CAST(${organizationId} AS UUID),
        CAST(${assetId} AS UUID),
        ${namespace},
        ${identifier}
      )
    `;
  }

  it('adds the default active list keyset index and keeps existing filter indexes', async () => {
    const indexes = await prisma.$queryRaw<Array<{ indexname: string; indexdef: string }>>`
      SELECT indexname, indexdef
      FROM pg_indexes
      WHERE schemaname = 'public' AND tablename = 'asset'
      ORDER BY indexname
    `;
    const names = indexes.map((row) => row.indexname).sort();
    expect(names).toEqual([...ASSET_INDEXES].sort());
    expect(names).not.toContain('asset_org_status_idx');

    const listIndex = indexes.find((row) => row.indexname === 'asset_org_status_name_id_idx');
    expect(listIndex?.indexdef).toContain('organization_id');
    expect(listIndex?.indexdef).toContain('lifecycle_status');
    expect(listIndex?.indexdef).toContain('lower((name)::text)');
    expect(listIndex?.indexdef).toContain('id');

    // Environment, owning-team, and exact-tag filters already have covering indexes.
    // asset_type / business_criticality / internet_exposure filters are not indexed:
    // the approved list query uses them only as residual predicates after the
    // org+status+name keyset. No additional filter index is required.
    const tagIndexes = await prisma.$queryRaw<Array<{ indexname: string }>>`
      SELECT indexname FROM pg_indexes
      WHERE schemaname = 'public' AND tablename = 'asset_tag'
    `;
    expect(tagIndexes.map((row) => row.indexname)).toEqual(
      expect.arrayContaining(['asset_tag_org_tag_idx', 'asset_tag_org_asset_tag_key']),
    );
  });

  it('rejects invalid external-identifier namespaces and accepts slug shape', async () => {
    const org = await createOrg(`ns-${randomUUID().slice(0, 8)}`);
    const asset = await createAsset(org.id, `Namespace ${randomUUID().slice(0, 8)}`);

    await insertExternalIdentifier(org.id, asset.id, 'a', 'PAY-0');
    await insertExternalIdentifier(org.id, asset.id, 'cmdb', 'PAY-1');
    await insertExternalIdentifier(org.id, asset.id, 'internal-cmdb', 'PAY-2');
    await insertExternalIdentifier(org.id, asset.id, 'a'.repeat(64), 'PAY-64');

    await expect(insertExternalIdentifier(org.id, asset.id, 'CMDB', 'PAY-3')).rejects.toThrow();
    await expect(insertExternalIdentifier(org.id, asset.id, '', 'PAY-4')).rejects.toThrow();
    await expect(insertExternalIdentifier(org.id, asset.id, 'cmdb_id', 'PAY-5')).rejects.toThrow();
    await expect(insertExternalIdentifier(org.id, asset.id, '-cmdb', 'PAY-6')).rejects.toThrow();
    await expect(insertExternalIdentifier(org.id, asset.id, 'cmdb-', 'PAY-7')).rejects.toThrow();
    await expect(insertExternalIdentifier(org.id, asset.id, 'a--b', 'PAY-8')).rejects.toThrow();
    await expect(
      insertExternalIdentifier(org.id, asset.id, 'a'.repeat(65), 'PAY-9'),
    ).rejects.toThrow();
  });

  it('rejects empty and oversized identifiers and accepts length 256', async () => {
    const org = await createOrg(`len-${randomUUID().slice(0, 8)}`);
    const asset = await createAsset(org.id, `Length ${randomUUID().slice(0, 8)}`);

    await insertExternalIdentifier(org.id, asset.id, 'cmdb', 'x'.repeat(256));
    await expect(insertExternalIdentifier(org.id, asset.id, 'other', '')).rejects.toThrow();
    await expect(
      insertExternalIdentifier(org.id, asset.id, 'toolong', 'x'.repeat(257)),
    ).rejects.toThrow();
  });

  it('accepts NFC letters and opaque URL-shaped identifiers without fetching', async () => {
    const org = await createOrg(`nfc-${randomUUID().slice(0, 8)}`);
    const asset = await createAsset(org.id, `Nfc ${randomUUID().slice(0, 8)}`);
    await insertExternalIdentifier(org.id, asset.id, 'cmdb', 'Café-1');
    const stored = await prisma.assetExternalIdentifier.findFirst({
      where: { organizationId: org.id, assetId: asset.id, namespace: 'cmdb' },
    });
    expect(stored?.identifier).toBe('Café-1');
  });

  it('rejects NUL, C0, and C1 control characters in identifiers', async () => {
    const org = await createOrg(`ctl-${randomUUID().slice(0, 8)}`);
    const asset = await createAsset(org.id, `Controls ${randomUUID().slice(0, 8)}`);

    await expect(
      prisma.$executeRaw`
        INSERT INTO "asset_external_identifier" (
          "organization_id", "asset_id", "namespace", "identifier"
        )
        VALUES (
          CAST(${org.id} AS UUID),
          CAST(${asset.id} AS UUID),
          'nul',
          chr(0)
        )
      `,
    ).rejects.toThrow();
    await expect(
      prisma.$executeRaw`
        INSERT INTO "asset_external_identifier" (
          "organization_id", "asset_id", "namespace", "identifier"
        )
        VALUES (
          CAST(${org.id} AS UUID),
          CAST(${asset.id} AS UUID),
          'c0',
          chr(1)
        )
      `,
    ).rejects.toThrow();
    await expect(
      prisma.$executeRaw`
        INSERT INTO "asset_external_identifier" (
          "organization_id", "asset_id", "namespace", "identifier"
        )
        VALUES (
          CAST(${org.id} AS UUID),
          CAST(${asset.id} AS UUID),
          'del',
          chr(127)
        )
      `,
    ).rejects.toThrow();
    await expect(
      prisma.$executeRaw`
        INSERT INTO "asset_external_identifier" (
          "organization_id", "asset_id", "namespace", "identifier"
        )
        VALUES (
          CAST(${org.id} AS UUID),
          CAST(${asset.id} AS UUID),
          'c1',
          chr(159)
        )
      `,
    ).rejects.toThrow();
    await expect(
      prisma.$executeRaw`
        INSERT INTO "asset_external_identifier" (
          "organization_id", "asset_id", "namespace", "identifier"
        )
        VALUES (
          CAST(${org.id} AS UUID),
          CAST(${asset.id} AS UUID),
          'tab',
          chr(9)
        )
      `,
    ).rejects.toThrow();
    await expect(
      prisma.$executeRaw`
        INSERT INTO "asset_external_identifier" (
          "organization_id", "asset_id", "namespace", "identifier"
        )
        VALUES (
          CAST(${org.id} AS UUID),
          CAST(${asset.id} AS UUID),
          'lf',
          chr(10)
        )
      `,
    ).rejects.toThrow();
  });

  it('stores an opaque URL-like identifier without fetching', async () => {
    const org = await createOrg(`url-${randomUUID().slice(0, 8)}`);
    const asset = await createAsset(org.id, `Url ${randomUUID().slice(0, 8)}`);
    const identifier = 'https://cmdb.synthetic.patchpilot.test/ci/PAY-1?rev=2';

    await insertExternalIdentifier(org.id, asset.id, 'cmdb', identifier);
    const stored = await prisma.assetExternalIdentifier.findFirst({
      where: { organizationId: org.id, assetId: asset.id, namespace: 'cmdb' },
    });
    expect(stored?.identifier).toBe(identifier);
  });

  it('orders the default active list by lower(name), then id for the keyset cursor', async () => {
    const org = await createOrg(`list-${randomUUID().slice(0, 8)}`);
    await createAsset(org.id, 'Zebra');
    const bravo = await createAsset(org.id, 'Bravo');
    await createAsset(org.id, 'alpha');

    const page = await prisma.$queryRaw<Array<{ name: string; id: string }>>`
      SELECT name, id::text AS id
      FROM "asset"
      WHERE organization_id = CAST(${org.id} AS UUID)
        AND lifecycle_status = 'active'
      ORDER BY lower(name), id
    `;
    expect(page.map((row) => row.name)).toEqual(['alpha', 'Bravo', 'Zebra']);

    const afterBravo = await prisma.$queryRaw<Array<{ name: string }>>`
      SELECT name
      FROM "asset"
      WHERE organization_id = CAST(${org.id} AS UUID)
        AND lifecycle_status = 'active'
        AND (lower(name), id) > (lower(${bravo.name}), CAST(${bravo.id} AS UUID))
      ORDER BY lower(name), id
    `;
    expect(afterBravo.map((row) => row.name)).toEqual(['Zebra']);
  });

  it('rejects active case-insensitive duplicate names and allows archived-name reuse', async () => {
    const org = await createOrg(`name-${randomUUID().slice(0, 8)}`);
    const other = await createOrg(`name-b-${randomUUID().slice(0, 8)}`);
    const first = await createAsset(org.id, 'Payments API');

    await expect(createAsset(org.id, 'payments api')).rejects.toThrow();
    await createAsset(other.id, 'Payments API');

    await prisma.asset.update({
      where: { id: first.id },
      data: { lifecycleStatus: 'archived', archivedAt: new Date('2026-08-28T12:00:00.000Z') },
    });
    const reused = await createAsset(org.id, 'Payments API');
    expect(reused.lifecycleStatus).toBe('active');
    expect(reused.name).toBe('Payments API');
  });
});
