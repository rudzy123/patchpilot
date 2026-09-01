import { randomUUID } from 'node:crypto';

import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { PrismaClient } from '@prisma/client';
import {
  intelligenceRedispatchJobId,
  type PersistRequestedIntelligenceSyncResult,
  type Result,
} from '@patchpilot/domain';

import { PrismaBackgroundJobExecution } from './background-job-execution.js';
import {
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
} from './integration-database.js';
import { createIntelligencePersistence } from './intelligence-persistence.js';
import {
  KEV_NORMALIZATION_VERSION,
  KEV_PARSER_VERSION,
  NOW,
  createSnapshot,
  failInflightSyncRuns,
  seedZeroFindingBaseline,
} from './intelligence-test-fixture.js';

function requireOk<T>(result: Result<T>, label: string): T {
  if (!result.ok) {
    throw new Error(`${label}: ${result.error.code} ${result.error.message}`);
  }
  return result.value;
}

function requireCreated(
  result: Result<PersistRequestedIntelligenceSyncResult>,
  label: string,
): Extract<PersistRequestedIntelligenceSyncResult, { outcome: 'created' }> {
  const value = requireOk(result, label);
  if (value.outcome !== 'created') {
    throw new Error(`${label}: expected created, got ${value.outcome}`);
  }
  return value;
}

describe('KEV retry redelivery and enablement persistence', () => {
  let prisma: PrismaClient;
  let admin: PrismaClient;
  let databaseName: string;
  let baseline: {
    findingCount: number;
    observationCount: number;
    vulnerabilityCount: number;
  };

  beforeAll(async () => {
    const ephemeral = await createEphemeralDatabase('it');
    databaseName = ephemeral.databaseName;
    admin = ephemeral.admin;
    await deployMigrations(ephemeral.databaseUrl);
    prisma = new PrismaClient({
      datasources: { db: { url: ephemeral.databaseUrl } },
    });
    await seedZeroFindingBaseline(prisma);
    baseline = {
      findingCount: await prisma.finding.count(),
      observationCount: await prisma.findingObservation.count(),
      vulnerabilityCount: await prisma.vulnerability.count(),
    };
  });

  beforeEach(async () => {
    await failInflightSyncRuns(prisma);
  });

  afterAll(async () => {
    if (prisma !== undefined) {
      await prisma.$disconnect();
    }
    if (admin !== undefined && databaseName !== undefined) {
      await dropEphemeralDatabase(admin, databaseName);
    }
  });

  async function assertZeroFindingUnchanged(): Promise<void> {
    expect(await prisma.finding.count()).toBe(baseline.findingCount);
    expect(await prisma.findingObservation.count()).toBe(baseline.observationCount);
    expect(await prisma.vulnerability.count()).toBe(baseline.vulnerabilityCount);
    expect(await prisma.vulnerabilityAlias.count()).toBe(0);
    expect(await prisma.vulnerabilitySourceRecord.count()).toBe(0);
    expect(await prisma.outboxEvent.count({ where: { eventType: 'finding.recalculate' } })).toBe(0);
  }

  async function seedQueuedRun(input: {
    requestedAt: Date;
    createdAt: Date;
    state: 'requested' | 'fetching' | 'retry_wait' | 'stored' | 'failed' | 'quarantined';
    nextAttemptAt?: Date;
    jobStatus: 'queued' | 'running' | 'failed';
    leaseExpiresAt?: Date;
    workerIdentifier?: string;
    outboxStatus?: 'processed' | 'pending';
  }) {
    const adapters = createIntelligencePersistence(prisma);
    const syncRunId = randomUUID();
    const created = requireCreated(
      await adapters.unitOfWork.requestSync({
        provider: 'cisa_kev',
        sourceIdentifier: 'cisa_kev_json_catalog',
        syncRunId,
        requestedAt: input.requestedAt,
        correlationId: `corr-${syncRunId}`,
        parserVersion: KEV_PARSER_VERSION,
        normalizationVersion: KEV_NORMALIZATION_VERSION,
        dedupeKey: `intelligence.sync.requested.v1|cisa_kev|cisa_kev_json_catalog|token:${syncRunId}`,
      }),
      'seed request',
    );
    const event = await prisma.outboxEvent.findFirstOrThrow({
      where: { aggregateId: created.syncRun.id, eventType: 'intelligence.sync.requested.v1' },
    });
    await prisma.outboxEvent.update({
      where: { id: event.id },
      data: {
        status: input.outboxStatus ?? 'processed',
        processedAt: input.outboxStatus === 'pending' ? null : NOW,
      },
    });
    const syncRunPatch: {
      state: typeof input.state;
      nextAttemptAt: Date | null;
      requestedAt: Date;
      startedAt?: Date;
      completedAt?: Date;
      executionAttempt?: number;
      stage?: 'fetch' | 'store_snapshot';
      snapshotId?: string;
      failureCategory?: string;
      failureCode?: string;
    } = {
      state: input.state,
      nextAttemptAt: input.nextAttemptAt ?? null,
      requestedAt: input.requestedAt,
    };
    if (input.state === 'requested') {
      syncRunPatch.nextAttemptAt = null;
    }
    if (input.state === 'fetching') {
      syncRunPatch.startedAt = NOW;
      syncRunPatch.stage = 'fetch';
      syncRunPatch.executionAttempt = 1;
      syncRunPatch.nextAttemptAt = null;
    }
    if (input.state === 'retry_wait') {
      syncRunPatch.startedAt = NOW;
      syncRunPatch.executionAttempt = 1;
      syncRunPatch.failureCategory = 'timeout';
      syncRunPatch.failureCode = 'connection_timeout';
      syncRunPatch.nextAttemptAt = input.nextAttemptAt ?? NOW;
    }
    if (input.state === 'stored') {
      const snapshot = await createSnapshot(prisma, created.syncRun.id);
      syncRunPatch.startedAt = NOW;
      syncRunPatch.stage = 'store_snapshot';
      syncRunPatch.executionAttempt = 1;
      syncRunPatch.snapshotId = snapshot.id;
      syncRunPatch.nextAttemptAt = null;
    }
    if (input.state === 'failed' || input.state === 'quarantined') {
      syncRunPatch.startedAt = NOW;
      syncRunPatch.completedAt = NOW;
      syncRunPatch.executionAttempt = 1;
      syncRunPatch.failureCategory = 'internal';
      syncRunPatch.failureCode =
        input.state === 'quarantined' ? 'catalog_regression' : 'processing_failed';
      syncRunPatch.nextAttemptAt = null;
    }
    await prisma.vulnerabilitySyncRun.update({
      where: { id: created.syncRun.id },
      data: syncRunPatch,
    });
    const job = await prisma.backgroundJob.create({
      data: {
        organizationId: null,
        outboxEventId: event.id,
        jobType: 'intelligence.sync',
        status: input.jobStatus,
        createdAt: input.createdAt,
        leaseExpiresAt: input.leaseExpiresAt ?? null,
        workerIdentifier: input.workerIdentifier ?? null,
        attempt: input.jobStatus === 'queued' ? 0 : 1,
        startedAt: input.jobStatus === 'running' ? NOW : null,
        completedAt: input.jobStatus === 'failed' ? NOW : null,
        failureCode: input.jobStatus === 'failed' ? 'processing_failed' : null,
        failureCategory: input.jobStatus === 'failed' ? 'internal' : null,
      },
    });
    return { adapters, syncRunId: created.syncRun.id, jobId: job.id };
  }

  async function expectCandidate(listed: boolean, input: Parameters<typeof seedQueuedRun>[0]) {
    const seeded = await seedQueuedRun(input);
    const candidates = await seeded.adapters.redelivery.listDueRedeliveries({
      now: NOW,
      minAgeMs: 15_000,
      limit: 25,
    });
    const ids = candidates.map((row) => row.syncRunId);
    if (listed) {
      expect(ids).toEqual([seeded.syncRunId]);
    } else {
      expect(ids).not.toContain(seeded.syncRunId);
    }
    expect(JSON.stringify(candidates)).not.toMatch(/objectKey|etag|www\.cisa\.gov|CVE-/i);
    await assertZeroFindingUnchanged();
    return seeded;
  }

  it('lists a due retry_wait run', async () => {
    await expectCandidate(true, {
      requestedAt: NOW,
      createdAt: NOW,
      state: 'retry_wait',
      nextAttemptAt: NOW,
      jobStatus: 'queued',
    });
  });

  it('skips retry_wait before nextAttemptAt', async () => {
    await expectCandidate(false, {
      requestedAt: NOW,
      createdAt: NOW,
      state: 'retry_wait',
      nextAttemptAt: new Date(NOW.getTime() + 60_000),
      jobStatus: 'queued',
    });
  });

  it('lists a post-snapshot queued run', async () => {
    await expectCandidate(true, {
      requestedAt: NOW,
      createdAt: NOW,
      state: 'stored',
      jobStatus: 'queued',
    });
  });

  it('lists an expired running lease', async () => {
    await expectCandidate(true, {
      requestedAt: NOW,
      createdAt: NOW,
      state: 'fetching',
      jobStatus: 'running',
      leaseExpiresAt: new Date(NOW.getTime() - 1_000),
      workerIdentifier: 'dead-worker',
    });
  });

  it('skips a foreign unexpired lease', async () => {
    await expectCandidate(false, {
      requestedAt: NOW,
      createdAt: NOW,
      state: 'requested',
      jobStatus: 'running',
      leaseExpiresAt: new Date(NOW.getTime() + 600_000),
      workerIdentifier: 'other-worker',
    });
  });

  it('lists an initial queued job older than the minimum age', async () => {
    await expectCandidate(true, {
      requestedAt: NOW,
      createdAt: new Date(NOW.getTime() - 20_000),
      state: 'requested',
      jobStatus: 'queued',
    });
  });

  it('skips an initial queued job newer than the minimum age', async () => {
    await expectCandidate(false, {
      requestedAt: NOW,
      createdAt: NOW,
      state: 'requested',
      jobStatus: 'queued',
    });
  });

  it('skips terminal failed and quarantined runs', async () => {
    await expectCandidate(false, {
      requestedAt: NOW,
      createdAt: NOW,
      state: 'failed',
      jobStatus: 'failed',
    });
    await failInflightSyncRuns(prisma);
    await expectCandidate(false, {
      requestedAt: NOW,
      createdAt: NOW,
      state: 'quarantined',
      jobStatus: 'failed',
    });
  });

  it('recovers due retry_wait from PostgreSQL without a new SyncRun or OutboxEvent', async () => {
    const beforeRuns = await prisma.vulnerabilitySyncRun.count();
    const beforeEvents = await prisma.outboxEvent.count({
      where: { eventType: 'intelligence.sync.requested.v1' },
    });
    const seeded = await seedQueuedRun({
      requestedAt: NOW,
      createdAt: NOW,
      state: 'retry_wait',
      nextAttemptAt: NOW,
      jobStatus: 'queued',
    });
    const candidates = await seeded.adapters.redelivery.listDueRedeliveries({
      now: NOW,
      minAgeMs: 15_000,
      limit: 25,
    });
    expect(candidates.map((row) => row.syncRunId)).toEqual([seeded.syncRunId]);
    const due = candidates[0];
    if (due === undefined) {
      throw new Error('expected a due retry_wait candidate');
    }
    const jobId = intelligenceRedispatchJobId(due);
    expect(jobId.ok).toBe(true);
    const replayed = await seeded.adapters.redelivery.listDueRedeliveries({
      now: NOW,
      minAgeMs: 15_000,
      limit: 25,
    });
    expect(replayed.map((row) => row.syncRunId)).toEqual([seeded.syncRunId]);
    expect(replayed[0]?.outboxEventId).toBe(due.outboxEventId);
    expect(await prisma.vulnerabilitySyncRun.count()).toBe(beforeRuns + 1);
    expect(
      await prisma.outboxEvent.count({ where: { eventType: 'intelligence.sync.requested.v1' } }),
    ).toBe(beforeEvents + 1);
    await assertZeroFindingUnchanged();
  });

  it('does not claim BackgroundJob from the redelivery query', async () => {
    const jobs = new PrismaBackgroundJobExecution(prisma);
    const seeded = await seedQueuedRun({
      requestedAt: NOW,
      createdAt: NOW,
      state: 'stored',
      jobStatus: 'queued',
    });
    await seeded.adapters.redelivery.listDueRedeliveries({
      now: NOW,
      minAgeMs: 1_000,
      limit: 10,
    });
    const job = await jobs.findById({ organizationId: null, jobId: seeded.jobId });
    expect(job?.status).toBe('queued');
    expect(job?.attempt).toBe(0);
    await assertZeroFindingUnchanged();
  });

  it('reconciles IntelligenceSource enablement without touching OSV or creating Findings', async () => {
    const adapters = createIntelligencePersistence(prisma);
    const osvBefore = await prisma.intelligenceSource.findUniqueOrThrow({
      where: { providerKey: 'osv' },
    });
    const enabled = requireOk(
      await adapters.freshness.reconcileRuntimeEnablement({
        provider: 'cisa_kev',
        enabled: true,
      }),
      'enable',
    );
    expect(enabled.outcome === 'updated' || enabled.outcome === 'unchanged').toBe(true);
    const source = await prisma.intelligenceSource.findUniqueOrThrow({
      where: { providerKey: 'cisa_kev' },
    });
    expect(source.state).toBe('enabled');
    const again = requireOk(
      await adapters.freshness.reconcileRuntimeEnablement({
        provider: 'cisa_kev',
        enabled: true,
      }),
      'enable again',
    );
    expect(again.outcome).toBe('unchanged');
    const disabled = requireOk(
      await adapters.freshness.reconcileRuntimeEnablement({
        provider: 'cisa_kev',
        enabled: false,
      }),
      'disable',
    );
    expect(disabled.outcome).toBe('updated');
    const osvAfter = await prisma.intelligenceSource.findUniqueOrThrow({
      where: { providerKey: 'osv' },
    });
    expect(osvAfter.state).toBe(osvBefore.state);
    expect(osvAfter.version).toBe(osvBefore.version);
    expect(osvAfter.activeGenerationId).toBe(osvBefore.activeGenerationId);
    await assertZeroFindingUnchanged();
  });
});
