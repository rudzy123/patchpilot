import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { PrismaClient } from '@prisma/client';

import {
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
} from './integration-database.js';
import {
  CATALOG_VERSION,
  NOW,
  createFetchingSyncRun,
  createSnapshot,
  createStagingGeneration,
  failInflightSyncRuns,
  seedZeroFindingBaseline,
  uniqueKevSha,
} from './intelligence-test-fixture.js';
import { createIntelligenceStatusReader } from './intelligence-status.js';

describe('intelligence status read adapter', () => {
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

  beforeEach(async () => {
    await failInflightSyncRuns(prisma);
    await prisma.intelligenceSource.updateMany({
      where: { providerKey: 'cisa_kev' },
      data: {
        lastSuccessfulSyncAt: null,
        lastAttemptAt: null,
        lastFailureAt: null,
        lastFailureCode: null,
        activeGenerationId: null,
      },
    });
    await prisma.kevGeneration.updateMany({
      where: { state: 'active' },
      data: { state: 'superseded', supersededAt: NOW },
    });
  });

  it('loads one bounded CISA status row joined through the active pointer', async () => {
    const before = await seedZeroFindingBaseline(prisma);
    const findingCount = await prisma.finding.count();
    const observationCount = await prisma.findingObservation.count();
    const generation = await seedActiveGeneration(prisma, {
      lastSuccessfulSyncAt: NOW,
      expectedEntryCount: 3,
    });
    const reader = createIntelligenceStatusReader(prisma);
    const loaded = await reader.loadCisaKevStatus();
    expect(loaded.kind).toBe('found');
    if (loaded.kind === 'found') {
      expect(loaded.snapshot.lastSuccessfulSyncAt).toEqual(NOW);
      expect(loaded.snapshot.generation?.expectedEntryCount).toBe(3);
      expect(loaded.snapshot.generation?.catalogVersion).toBe(CATALOG_VERSION);
      expect(loaded.snapshot.activeGenerationId).toBe(generation.id);
      expect(JSON.stringify(loaded)).not.toContain('organizationId');
    }
    expect(await prisma.finding.count()).toBe(findingCount);
    expect(await prisma.findingObservation.count()).toBe(observationCount);
    expect(await prisma.finding.findUnique({ where: { id: before.finding.id } })).toMatchObject({
      id: before.finding.id,
    });
    expect(await prisma.vulnerability.count({ where: { id: before.vulnerability.id } })).toBe(1);
    expect(await prisma.outboxEvent.count({ where: { eventType: 'finding.recalculate' } })).toBe(0);
    expect(
      await prisma.outboxEvent.count({ where: { eventType: 'intelligence.sync.requested.v1' } }),
    ).toBe(0);
    expect(await prisma.backgroundJob.count()).toBe(0);
    expect(
      await prisma.auditEvent.count({
        where: { action: { startsWith: 'intelligence.status' } },
      }),
    ).toBe(0);
  });

  it('returns missing_source when the CISA IntelligenceSource row is absent', async () => {
    await prisma.intelligenceSource.delete({ where: { providerKey: 'cisa_kev' } });
    const loaded = await createIntelligenceStatusReader(prisma).loadCisaKevStatus();
    expect(loaded).toEqual({ kind: 'missing_source' });
    await prisma.intelligenceSource.create({
      data: {
        providerKey: 'cisa_kev',
        state: 'disabled',
        config: { schemaVersion: 1, refreshIntervalSeconds: null, endpointAllowlist: [] },
      },
    });
  });

  it('returns inconsistent when the active pointer cannot be joined', async () => {
    const reader = createIntelligenceStatusReader({
      intelligenceSource: {
        findUnique: async () => ({
          state: 'enabled',
          lastSuccessfulSyncAt: NOW,
          lastAttemptAt: NOW,
          lastFailureAt: null,
          lastFailureCode: null,
          activeGenerationId: '11111111-1111-4111-8111-111111111111',
          activeGeneration: null,
        }),
      },
    } as never);
    expect(await reader.loadCisaKevStatus()).toEqual({ kind: 'inconsistent' });
  });

  it('returns unavailable on database failure without exposing the error', async () => {
    const reader = createIntelligenceStatusReader({
      intelligenceSource: {
        findUnique: async () => {
          throw new Error('ECONNREFUSED postgresql');
        },
      },
    } as never);
    expect(await reader.loadCisaKevStatus()).toEqual({ kind: 'unavailable' });
  });

  it('does not query OSV, tenant tables, KevEntry counts, or write statements', async () => {
    await prisma.intelligenceSource.update({
      where: { providerKey: 'osv' },
      data: {
        lastAttemptAt: NOW,
        lastFailureAt: NOW,
        lastFailureCode: 'dns_rejected',
      },
    });
    const source = readFileSync(
      path.join(path.dirname(fileURLToPath(import.meta.url)), 'intelligence-status.ts'),
      'utf8',
    );
    expect(source).toContain("where: { providerKey: 'cisa_kev' }");
    expect(source).not.toContain('kevEntry');
    expect(source).not.toContain('_count');
    expect(source).not.toContain('organizationId');
    expect(source).not.toContain('finding');
    const loaded = await createIntelligenceStatusReader(prisma).loadCisaKevStatus();
    expect(loaded.kind).toBe('found');
    if (loaded.kind === 'found') {
      expect(loaded.snapshot.lastFailureCode).toBeNull();
    }
  });
});

async function seedActiveGeneration(
  prisma: PrismaClient,
  input: { lastSuccessfulSyncAt: Date; expectedEntryCount: number },
) {
  const run = await createFetchingSyncRun(prisma);
  const snapshot = await createSnapshot(prisma, run.id, { sha256: uniqueKevSha() });
  const generation = await createStagingGeneration(prisma, {
    syncRunId: run.id,
    snapshotId: snapshot.id,
    expectedEntryCount: input.expectedEntryCount,
  });
  await prisma.kevGeneration.update({
    where: { id: generation.id },
    data: {
      state: 'complete',
      completedAt: NOW,
      stagedEntryCount: input.expectedEntryCount,
      catalogVersion: CATALOG_VERSION,
      catalogReleasedAt: NOW,
    },
  });
  await prisma.kevGeneration.update({
    where: { id: generation.id },
    data: { state: 'active', activatedAt: NOW },
  });
  await prisma.intelligenceSource.update({
    where: { providerKey: 'cisa_kev' },
    data: {
      activeGenerationId: generation.id,
      lastSuccessfulSyncAt: input.lastSuccessfulSyncAt,
      lastAttemptAt: input.lastSuccessfulSyncAt,
    },
  });
  return generation;
}
