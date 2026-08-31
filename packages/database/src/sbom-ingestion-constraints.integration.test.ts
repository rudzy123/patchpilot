import { randomUUID } from 'node:crypto';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { PrismaClient } from '@prisma/client';
import { JSON_SCHEMA_VERSION_V1 } from '@patchpilot/domain';

import {
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
} from './integration-database.js';
import { SHA_A, createAsset, createOrg, createSbom } from './sbom-test-fixture.js';

describe('session 8 graph persistence constraints', () => {
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

  async function seed() {
    const org = await createOrg(prisma, `c-${randomUUID().slice(0, 8)}`);
    const asset = await createAsset(prisma, org.id, 'constraint-asset');
    const sbom = await createSbom(prisma, {
      organizationId: org.id,
      assetId: asset.id,
      sha256: SHA_A,
      receivedAt: new Date('2026-08-30T10:00:00.000Z'),
    });
    return { org, asset, sbom };
  }

  it('accepts completed graph completeness and count combinations', async () => {
    const { org, asset, sbom } = await seed();
    const startedAt = new Date('2026-08-30T12:00:00.000Z');
    await expect(
      prisma.sbomIngestion.create({
        data: {
          organizationId: org.id,
          sbomId: sbom.id,
          assetId: asset.id,
          parserVersion: '1.0.0',
          state: 'completed',
          stage: 'persist_graph',
          startedAt,
          completedAt: new Date('2026-08-30T12:01:00.000Z'),
          graphCompleteness: 'empty',
          componentCount: 0,
          dependencyEdgeCount: 0,
          warningCount: 0,
        },
      }),
    ).resolves.toMatchObject({ graphCompleteness: 'empty' });
  });

  it('rejects completed ingestions missing graph completeness or counts', async () => {
    const { org, asset, sbom } = await seed();
    await expect(
      prisma.sbomIngestion.create({
        data: {
          organizationId: org.id,
          sbomId: sbom.id,
          assetId: asset.id,
          parserVersion: '1.0.0',
          state: 'completed',
          startedAt: new Date(),
          completedAt: new Date(),
        },
      }),
    ).rejects.toThrow();
  });

  it('rejects negative graph counts and completeness mismatches', async () => {
    const { org, asset, sbom } = await seed();
    const startedAt = new Date('2026-08-30T12:00:00.000Z');
    await expect(
      prisma.sbomIngestion.create({
        data: {
          organizationId: org.id,
          sbomId: sbom.id,
          assetId: asset.id,
          parserVersion: '1.0.0',
          state: 'completed',
          startedAt,
          completedAt: new Date('2026-08-30T12:01:00.000Z'),
          graphCompleteness: 'complete',
          componentCount: -1,
          dependencyEdgeCount: 1,
          warningCount: 0,
        },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.sbomIngestion.create({
        data: {
          organizationId: org.id,
          sbomId: sbom.id,
          assetId: asset.id,
          parserVersion: '1.0.0',
          state: 'completed',
          startedAt,
          completedAt: new Date('2026-08-30T12:01:00.000Z'),
          graphCompleteness: 'empty',
          componentCount: 1,
          dependencyEdgeCount: 0,
          warningCount: 0,
        },
      }),
    ).rejects.toThrow();
  });

  it('rejects non-completed rows that carry graph completeness or counts', async () => {
    const { org, asset, sbom } = await seed();
    await expect(
      prisma.sbomIngestion.create({
        data: {
          organizationId: org.id,
          sbomId: sbom.id,
          assetId: asset.id,
          parserVersion: '1.0.0',
          state: 'processing',
          startedAt: new Date(),
          graphCompleteness: 'complete',
          componentCount: 1,
          dependencyEdgeCount: 1,
          warningCount: 0,
        },
      }),
    ).rejects.toThrow();
  });

  it('rejects processing without startedAt and completedAt before startedAt', async () => {
    const { org, asset, sbom } = await seed();
    await expect(
      prisma.sbomIngestion.create({
        data: {
          organizationId: org.id,
          sbomId: sbom.id,
          assetId: asset.id,
          parserVersion: '1.0.0',
          state: 'processing',
        },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.sbomIngestion.create({
        data: {
          organizationId: org.id,
          sbomId: sbom.id,
          assetId: asset.id,
          parserVersion: '1.0.0',
          state: 'completed',
          startedAt: new Date('2026-08-30T12:02:00.000Z'),
          completedAt: new Date('2026-08-30T12:01:00.000Z'),
          graphCompleteness: 'empty',
          componentCount: 0,
          dependencyEdgeCount: 0,
          warningCount: 0,
        },
      }),
    ).rejects.toThrow();
  });

  it('rejects invalid parser and normalization labels', async () => {
    const { org, asset, sbom } = await seed();
    await expect(
      prisma.sbomIngestion.create({
        data: {
          organizationId: org.id,
          sbomId: sbom.id,
          assetId: asset.id,
          parserVersion: '../escape',
        },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.sbom.update({
        where: { id: sbom.id },
        data: { parserVersionLastSucceeded: 'not a label' },
      }),
    ).rejects.toThrow();
  });

  it('persists nullable ecosystem and rejects fabricated empty ecosystem', async () => {
    const org = await createOrg(prisma, `eco-${randomUUID().slice(0, 8)}`);
    const resolved = await prisma.component.create({
      data: {
        organizationId: org.id,
        identityKey: 'purl:pkg:npm/left-pad',
        ecosystem: 'npm',
        name: 'left-pad',
      },
    });
    expect(resolved.ecosystem).toBe('npm');
    const unresolved = await prisma.component.create({
      data: {
        organizationId: org.id,
        identityKey: 'unresolved:unsupported::blob',
        ecosystem: null,
        name: 'blob',
        identityState: 'unsupported',
      },
    });
    expect(unresolved.ecosystem).toBeNull();
    await expect(
      prisma.component.create({
        data: {
          organizationId: org.id,
          identityKey: 'empty-eco',
          ecosystem: '',
          name: 'empty',
        },
      }),
    ).rejects.toThrow();
  });

  it('enforces known and unknown occurrence versions and bom-ref uniqueness', async () => {
    const { org, asset, sbom } = await seed();
    const ingestionA = await prisma.sbomIngestion.create({
      data: {
        organizationId: org.id,
        sbomId: sbom.id,
        assetId: asset.id,
        parserVersion: '1.0.0',
      },
    });
    const ingestionB = await prisma.sbomIngestion.create({
      data: {
        organizationId: org.id,
        sbomId: sbom.id,
        assetId: asset.id,
        parserVersion: '1.0.1',
      },
    });
    const component = await prisma.component.create({
      data: {
        organizationId: org.id,
        identityKey: `npm|${randomUUID()}`,
        ecosystem: 'npm',
        name: 'pkg',
      },
    });
    const known = await prisma.componentOccurrence.create({
      data: {
        organizationId: org.id,
        assetId: asset.id,
        sbomId: sbom.id,
        sbomIngestionId: ingestionA.id,
        componentId: component.id,
        bomRef: 'pkg:npm/pkg',
        version: '1.2.3',
        versionKnown: true,
      },
    });
    expect(known.versionKnown).toBe(true);
    await expect(
      prisma.componentOccurrence.create({
        data: {
          organizationId: org.id,
          assetId: asset.id,
          sbomId: sbom.id,
          sbomIngestionId: ingestionA.id,
          componentId: component.id,
          bomRef: 'pkg:npm/pkg',
          version: '9.9.9',
          versionKnown: true,
        },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.componentOccurrence.create({
        data: {
          organizationId: org.id,
          assetId: asset.id,
          sbomId: sbom.id,
          sbomIngestionId: ingestionA.id,
          componentId: component.id,
          version: '',
          versionKnown: true,
        },
      }),
    ).rejects.toThrow();
    const unknown = await prisma.componentOccurrence.create({
      data: {
        organizationId: org.id,
        assetId: asset.id,
        sbomId: sbom.id,
        sbomIngestionId: ingestionB.id,
        componentId: component.id,
        bomRef: 'pkg:npm/pkg',
        version: '',
        versionKnown: false,
      },
    });
    expect(unknown.versionKnown).toBe(false);
    expect(unknown.version).toBe('');

    const orgB = await createOrg(prisma, `eco-b-${randomUUID().slice(0, 8)}`);
    const assetB = await createAsset(prisma, orgB.id, 'other-asset');
    const sbomB = await createSbom(prisma, {
      organizationId: orgB.id,
      assetId: assetB.id,
      sha256: SHA_A,
      receivedAt: new Date('2026-08-30T10:00:00.000Z'),
    });
    const ingestionC = await prisma.sbomIngestion.create({
      data: {
        organizationId: orgB.id,
        sbomId: sbomB.id,
        assetId: assetB.id,
        parserVersion: '1.0.0',
      },
    });
    const componentB = await prisma.component.create({
      data: {
        organizationId: orgB.id,
        identityKey: 'npm|pkg',
        ecosystem: 'npm',
        name: 'pkg',
      },
    });
    await expect(
      prisma.componentOccurrence.create({
        data: {
          organizationId: orgB.id,
          assetId: assetB.id,
          sbomId: sbomB.id,
          sbomIngestionId: ingestionC.id,
          componentId: componentB.id,
          bomRef: 'pkg:npm/pkg',
          version: '1.0.0',
          versionKnown: true,
        },
      }),
    ).resolves.toMatchObject({ bomRef: 'pkg:npm/pkg' });
  });

  const terminalFailureStates = ['rejected', 'quarantined', 'failed'] as const;
  const terminalCompletedAt = new Date('2026-08-30T12:30:00.000Z');
  const safeFailureByState = {
    rejected: { category: 'validation', code: 'schema_invalid' },
    quarantined: { category: 'timeout', code: 'parser_timeout' },
    failed: { category: 'internal', code: 'processing_failed' },
  } as const;

  it.each(terminalFailureStates)('rejects %s without failureCategory', async (state) => {
    const { org, asset, sbom } = await seed();
    await expect(
      prisma.sbomIngestion.create({
        data: {
          organizationId: org.id,
          sbomId: sbom.id,
          assetId: asset.id,
          parserVersion: '1.0.0',
          normalizationVersion: '1',
          state,
          completedAt: terminalCompletedAt,
          failureCode: safeFailureByState[state].code,
        },
      }),
    ).rejects.toThrow();
  });

  it.each(terminalFailureStates)('rejects %s without failureCode', async (state) => {
    const { org, asset, sbom } = await seed();
    await expect(
      prisma.sbomIngestion.create({
        data: {
          organizationId: org.id,
          sbomId: sbom.id,
          assetId: asset.id,
          parserVersion: '1.0.0',
          normalizationVersion: '1',
          state,
          completedAt: terminalCompletedAt,
          failureCategory: safeFailureByState[state].category,
        },
      }),
    ).rejects.toThrow();
  });

  it.each(terminalFailureStates)(
    'accepts %s when both safe failure fields are present',
    async (state) => {
      const { org, asset, sbom } = await seed();
      const failure = safeFailureByState[state];
      await expect(
        prisma.sbomIngestion.create({
          data: {
            organizationId: org.id,
            sbomId: sbom.id,
            assetId: asset.id,
            parserVersion: '1.0.0',
            normalizationVersion: '1',
            state,
            completedAt: terminalCompletedAt,
            failureCategory: failure.category,
            failureCode: failure.code,
          },
        }),
      ).resolves.toMatchObject({
        state,
        failureCategory: failure.category,
        failureCode: failure.code,
      });
    },
  );

  it('keeps accepted, queued, processing, and completed valid only under their own constraints', async () => {
    const { org, asset, sbom } = await seed();
    const startedAt = new Date('2026-08-30T12:00:00.000Z');
    await expect(
      prisma.sbomIngestion.create({
        data: {
          organizationId: org.id,
          sbomId: sbom.id,
          assetId: asset.id,
          parserVersion: '1.0.0',
          normalizationVersion: '1',
          state: 'accepted',
        },
      }),
    ).resolves.toMatchObject({
      state: 'accepted',
      failureCategory: null,
      failureCode: null,
    });
    await expect(
      prisma.sbomIngestion.create({
        data: {
          organizationId: org.id,
          sbomId: sbom.id,
          assetId: asset.id,
          parserVersion: '1.0.1',
          normalizationVersion: '1',
          state: 'queued',
        },
      }),
    ).resolves.toMatchObject({
      state: 'queued',
      failureCategory: null,
      failureCode: null,
    });
    await expect(
      prisma.sbomIngestion.create({
        data: {
          organizationId: org.id,
          sbomId: sbom.id,
          assetId: asset.id,
          parserVersion: '1.0.2',
          normalizationVersion: '1',
          state: 'processing',
          startedAt,
        },
      }),
    ).resolves.toMatchObject({
      state: 'processing',
      startedAt,
      failureCategory: null,
      failureCode: null,
    });
    await expect(
      prisma.sbomIngestion.create({
        data: {
          organizationId: org.id,
          sbomId: sbom.id,
          assetId: asset.id,
          parserVersion: '1.0.3',
          normalizationVersion: '1',
          state: 'completed',
          startedAt,
          completedAt: new Date('2026-08-30T12:01:00.000Z'),
          graphCompleteness: 'empty',
          componentCount: 0,
          dependencyEdgeCount: 0,
          warningCount: 0,
        },
      }),
    ).resolves.toMatchObject({
      state: 'completed',
      graphCompleteness: 'empty',
      failureCategory: null,
      failureCode: null,
    });
    await expect(
      prisma.sbomIngestion.create({
        data: {
          organizationId: org.id,
          sbomId: sbom.id,
          assetId: asset.id,
          parserVersion: '1.0.4',
          normalizationVersion: '1',
          state: 'completed',
          startedAt,
          completedAt: new Date('2026-08-30T12:01:00.000Z'),
          graphCompleteness: 'empty',
          componentCount: 0,
          dependencyEdgeCount: 0,
          warningCount: 0,
          failureCategory: 'validation',
          failureCode: 'schema_invalid',
        },
      }),
    ).rejects.toThrow();
  });

  it('enforces a generic idempotency status and response matrix', async () => {
    const org = await createOrg(prisma, `idemp-${randomUUID().slice(0, 8)}`);
    const keyHash = 'a'.repeat(64);
    const fingerprint = 'b'.repeat(64);
    const createdAt = new Date('2026-08-30T12:00:00.000Z');
    const expiresAt = new Date('2026-08-30T13:00:00.000Z');
    const completedAt = new Date('2026-08-30T12:30:00.000Z');
    await expect(
      prisma.idempotencyRecord.create({
        data: {
          organizationId: org.id,
          scope: 'generic.test',
          keyHash,
          requestFingerprint: fingerprint,
          status: 'started',
          createdAt,
          expiresAt,
          response: { schemaVersion: JSON_SCHEMA_VERSION_V1 },
        },
      }),
    ).rejects.toThrow();
    await prisma.idempotencyRecord.create({
      data: {
        organizationId: org.id,
        scope: 'generic.test',
        keyHash,
        requestFingerprint: fingerprint,
        status: 'started',
        createdAt,
        expiresAt,
      },
    });
    await expect(
      prisma.idempotencyRecord.create({
        data: {
          organizationId: org.id,
          scope: 'generic.other',
          keyHash: 'c'.repeat(64),
          requestFingerprint: fingerprint,
          status: 'completed',
          createdAt,
          expiresAt,
          completedAt,
          responseStatus: 200,
          response: { schemaVersion: JSON_SCHEMA_VERSION_V1, ok: true },
        },
      }),
    ).resolves.toMatchObject({ status: 'completed', responseStatus: 200 });
    await expect(
      prisma.idempotencyRecord.create({
        data: {
          organizationId: org.id,
          scope: 'generic.missing-schema',
          keyHash: 'd'.repeat(64),
          requestFingerprint: fingerprint,
          status: 'completed',
          createdAt,
          expiresAt,
          completedAt,
          responseStatus: 200,
          response: {},
        },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.idempotencyRecord.create({
        data: {
          organizationId: org.id,
          scope: 'generic.object-without-schema',
          keyHash: 'e'.repeat(64),
          requestFingerprint: fingerprint,
          status: 'completed',
          createdAt,
          expiresAt,
          completedAt,
          responseStatus: 200,
          response: { ok: true },
        },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.idempotencyRecord.create({
        data: {
          organizationId: org.id,
          scope: 'generic.bad-status',
          keyHash: 'f'.repeat(64),
          requestFingerprint: fingerprint,
          status: 'completed',
          createdAt,
          expiresAt,
          completedAt,
          responseStatus: 202,
          response: { schemaVersion: '1' },
        },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.idempotencyRecord.create({
        data: {
          organizationId: org.id,
          scope: 'generic.conflict',
          keyHash: 'e'.repeat(64),
          requestFingerprint: fingerprint,
          status: 'conflict',
          createdAt,
          expiresAt,
        },
      }),
    ).resolves.toMatchObject({ status: 'conflict' });
  });
});
