import { UnrecoverableError } from 'bullmq';
import { describe, expect, it } from 'vitest';

import {
  JSON_SCHEMA_VERSION_V1,
  ok,
  type BackgroundJobExecutionPort,
  type BackgroundJobRecord,
  type IntelligenceSyncRunRecord,
  type OutboxEventRecord,
} from '@patchpilot/domain';

import { processIntelligenceSyncQueueJob } from './intelligence-sync-processor.js';

const NOW = new Date('2026-09-01T12:00:00.000Z');
const OUTBOX_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const SYNC_RUN_ID = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const JOB_ID = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const WORKER = 'test-worker';
const DEDUPE =
  'intelligence.sync.requested.v1|cisa_kev|cisa_kev_json_catalog|window:2026-09-01T00:00:00Z';

const LOCATOR = {
  organizationId: null,
  outboxEventId: OUTBOX_ID,
  aggregateType: 'intelligence_sync_run',
  aggregateId: SYNC_RUN_ID,
  eventType: 'intelligence.sync.requested.v1',
  dedupeKey: DEDUPE,
};

const silent = {
  info() {
    return;
  },
  warn() {
    return;
  },
};

function jobRecord(overrides?: Partial<BackgroundJobRecord>): BackgroundJobRecord {
  return {
    id: JOB_ID,
    organizationId: null,
    outboxEventId: OUTBOX_ID,
    jobType: 'intelligence.sync',
    status: 'queued',
    attempt: 0,
    startedAt: null,
    leaseExpiresAt: null,
    completedAt: null,
    failureCategory: null,
    failureCode: null,
    workerIdentifier: null,
    createdAt: NOW,
    ...overrides,
  };
}

function eventRecord(): OutboxEventRecord {
  return {
    id: OUTBOX_ID,
    organizationId: null,
    aggregateType: 'intelligence_sync_run',
    aggregateId: SYNC_RUN_ID,
    eventType: 'intelligence.sync.requested.v1',
    eventSchemaVersion: JSON_SCHEMA_VERSION_V1,
    payload: {
      schemaVersion: JSON_SCHEMA_VERSION_V1,
      ids: { syncRunId: SYNC_RUN_ID },
      metadata: { provider: 'cisa_kev', sourceIdentifier: 'cisa_kev_json_catalog' },
    },
    dedupeKey: DEDUPE,
    occurredAt: NOW,
    availableAt: NOW,
    claimedAt: null,
    leaseExpiresAt: null,
    processedAt: NOW,
    attemptCount: 1,
    lastFailureCategory: null,
    lastFailureCode: null,
    status: 'processed',
    createdAt: NOW,
  };
}

function syncRun(overrides?: Partial<IntelligenceSyncRunRecord>): IntelligenceSyncRunRecord {
  return {
    id: SYNC_RUN_ID,
    provider: 'cisa_kev',
    sourceIdentifier: 'cisa_kev_json_catalog',
    state: 'requested',
    stage: null,
    requestedAt: NOW,
    startedAt: null,
    completedAt: null,
    nextAttemptAt: null,
    executionAttempt: 0,
    snapshotId: null,
    generationId: null,
    priorAcceptedGenerationId: null,
    parserVersion: '0.1.0',
    normalizationVersion: '1',
    failureCategory: null,
    failureCode: null,
    acceptedEntryCount: null,
    warningCount: null,
    notModifiedReason: null,
    correlationId: 'corr-1',
    version: 1,
    createdAt: NOW,
    updatedAt: NOW,
    ...overrides,
  };
}

function jobsPort(options: {
  job: BackgroundJobRecord;
  claimOk?: boolean;
  marked?: string[];
  claimed?: number[];
}): BackgroundJobExecutionPort {
  const marked = options.marked ?? [];
  const claimed = options.claimed ?? [];
  return {
    enqueueQueued: async () => ({
      id: options.job.id,
      organizationId: null,
      jobType: 'intelligence.sync',
      status: 'queued' as const,
      attempt: options.job.attempt,
    }),
    findByOutboxEventId: async () => options.job,
    findById: async () => options.job,
    claimExecution: async () => {
      claimed.push(1);
      return options.claimOk === false
        ? { ok: false as const, error: { code: 'conflict' as const, message: 'not claimed' } }
        : ok({
            jobId: options.job.id,
            workerIdentifier: WORKER,
            leaseExpiresAt: new Date(NOW.getTime() + 600_000),
            attempt: options.job.attempt + 1,
          });
    },
    markSucceeded: async () => {
      marked.push('succeeded');
      return ok(undefined);
    },
  } as unknown as BackgroundJobExecutionPort;
}

describe('intelligence sync processor', () => {
  it('rejects an unexpected job name without calling CISA', async () => {
    let executed = 0;
    await expect(
      processIntelligenceSyncQueueJob(
        { name: 'sbom.ingest', id: '1', data: LOCATOR },
        {
          clock: { now: () => NOW },
          jobs: jobsPort({ job: jobRecord() }),
          outbox: { findById: async () => eventRecord() },
          syncRuns: { findById: async () => syncRun() },
          execute: async () => {
            executed += 1;
            return { kind: 'completed', acceptedEntryCount: 1, warningCount: 0 };
          },
          redispatch: {
            add: async () => ({ ok: true, duplicate: false }),
            close: async () => undefined,
          },
          workerIdentifier: WORKER,
          kevJobLeaseMs: 600_000,
          logger: silent,
        },
      ),
    ).rejects.toBeInstanceOf(UnrecoverableError);
    expect(executed).toBe(0);
  });

  it('rejects a poison locator without loading tenant data', async () => {
    let loaded = 0;
    await expect(
      processIntelligenceSyncQueueJob(
        { name: 'intelligence.sync', id: '1', data: { organizationId: 'org' } },
        {
          clock: { now: () => NOW },
          jobs: jobsPort({ job: jobRecord() }),
          outbox: {
            findById: async () => {
              loaded += 1;
              return undefined;
            },
          },
          syncRuns: { findById: async () => undefined },
          execute: async () => {
            throw new Error('must not execute');
          },
          redispatch: {
            add: async () => ({ ok: true, duplicate: false }),
            close: async () => undefined,
          },
          workerIdentifier: WORKER,
          kevJobLeaseMs: 600_000,
          logger: silent,
        },
      ),
    ).rejects.toBeInstanceOf(UnrecoverableError);
    expect(loaded).toBe(0);
  });

  it('returns when a foreign lease is still held', async () => {
    let executed = 0;
    await processIntelligenceSyncQueueJob(
      { name: 'intelligence.sync', id: '1', data: LOCATOR },
      {
        clock: { now: () => NOW },
        jobs: jobsPort({
          job: jobRecord({ status: 'running', workerIdentifier: 'other' }),
          claimOk: false,
        }),
        outbox: { findById: async () => eventRecord() },
        syncRuns: { findById: async () => syncRun() },
        execute: async () => {
          executed += 1;
          return { kind: 'completed', acceptedEntryCount: 1, warningCount: 0 };
        },
        redispatch: {
          add: async () => ({ ok: true, duplicate: false }),
          close: async () => undefined,
        },
        workerIdentifier: WORKER,
        kevJobLeaseMs: 600_000,
        logger: silent,
      },
    );
    expect(executed).toBe(0);
  });

  it('reconciles a terminal job without executing', async () => {
    let executed = 0;
    await processIntelligenceSyncQueueJob(
      { name: 'intelligence.sync', id: '1', data: LOCATOR },
      {
        clock: { now: () => NOW },
        jobs: jobsPort({ job: jobRecord({ status: 'succeeded' }) }),
        outbox: { findById: async () => eventRecord() },
        syncRuns: { findById: async () => syncRun({ state: 'completed' }) },
        execute: async () => {
          executed += 1;
          return { kind: 'completed', acceptedEntryCount: 1, warningCount: 0 };
        },
        redispatch: {
          add: async () => ({ ok: true, duplicate: false }),
          close: async () => undefined,
        },
        workerIdentifier: WORKER,
        kevJobLeaseMs: 600_000,
        logger: silent,
      },
    );
    expect(executed).toBe(0);
  });

  it('marks succeeded after a completed synchronization', async () => {
    const marked: string[] = [];
    const running = jobRecord({
      status: 'running',
      workerIdentifier: WORKER,
      attempt: 1,
    });
    await processIntelligenceSyncQueueJob(
      { name: 'intelligence.sync', id: '1', data: LOCATOR },
      {
        clock: { now: () => NOW },
        jobs: jobsPort({ job: running, marked }),
        outbox: { findById: async () => eventRecord() },
        syncRuns: { findById: async () => syncRun() },
        execute: async (input) => {
          expect(input.syncRunId).toBe(SYNC_RUN_ID);
          expect(input.backgroundJobId).toBe(JOB_ID);
          expect(input.workerIdentifier).toBe(WORKER);
          return { kind: 'completed', acceptedEntryCount: 1, warningCount: 0 };
        },
        redispatch: {
          add: async () => ({ ok: true, duplicate: false }),
          close: async () => undefined,
        },
        workerIdentifier: WORKER,
        kevJobLeaseMs: 600_000,
        logger: silent,
      },
    );
    expect(marked).toEqual(['succeeded']);
  });

  it('redispatches retry_wait without throwing', async () => {
    const added: Array<{ jobId: string; delayMs?: number }> = [];
    const running = jobRecord({ status: 'running', workerIdentifier: WORKER, attempt: 1 });
    await processIntelligenceSyncQueueJob(
      { name: 'intelligence.sync', id: '1', data: LOCATOR },
      {
        clock: { now: () => NOW },
        jobs: jobsPort({ job: running }),
        outbox: { findById: async () => eventRecord() },
        syncRuns: { findById: async () => syncRun({ state: 'retry_wait' }) },
        execute: async () => ({
          kind: 'retry_wait',
          code: 'connection_timeout',
          nextAttemptAt: new Date(NOW.getTime() + 30_000),
        }),
        redispatch: {
          add: async (input) => {
            added.push({
              jobId: input.jobId,
              ...(input.delayMs === undefined ? {} : { delayMs: input.delayMs }),
            });
            return { ok: true, duplicate: false };
          },
          close: async () => undefined,
        },
        workerIdentifier: WORKER,
        kevJobLeaseMs: 600_000,
        logger: silent,
      },
    );
    expect(added).toEqual([
      {
        jobId: `intelligence.sync.requested.v1__${OUTBOX_ID}__retry__1`,
        delayMs: 30_000,
      },
    ]);
  });

  it('does not claim a retry_wait run before nextAttemptAt', async () => {
    const claimed: number[] = [];
    const added: Array<{ jobId: string; delayMs?: number }> = [];
    let executed = 0;
    await processIntelligenceSyncQueueJob(
      { name: 'intelligence.sync', id: '1', data: LOCATOR },
      {
        clock: { now: () => NOW },
        jobs: jobsPort({ job: jobRecord({ attempt: 1 }), claimed }),
        outbox: { findById: async () => eventRecord() },
        syncRuns: {
          findById: async () =>
            syncRun({
              state: 'retry_wait',
              nextAttemptAt: new Date(NOW.getTime() + 45_000),
              failureCode: 'connection_timeout',
            }),
        },
        execute: async () => {
          executed += 1;
          return { kind: 'completed', acceptedEntryCount: 1, warningCount: 0 };
        },
        redispatch: {
          add: async (input) => {
            added.push({
              jobId: input.jobId,
              ...(input.delayMs === undefined ? {} : { delayMs: input.delayMs }),
            });
            return { ok: true, duplicate: false };
          },
          close: async () => undefined,
        },
        workerIdentifier: WORKER,
        kevJobLeaseMs: 600_000,
        logger: silent,
      },
    );
    expect(claimed).toEqual([]);
    expect(executed).toBe(0);
    expect(added).toEqual([
      {
        jobId: `intelligence.sync.requested.v1__${OUTBOX_ID}__retry__1`,
        delayMs: 45_000,
      },
    ]);
  });

  it('does not log provider URLs or CVE lists', async () => {
    const logs: string[] = [];
    const running = jobRecord({ status: 'running', workerIdentifier: WORKER, attempt: 1 });
    await processIntelligenceSyncQueueJob(
      { name: 'intelligence.sync', id: '1', data: LOCATOR },
      {
        clock: { now: () => NOW },
        jobs: jobsPort({ job: running }),
        outbox: { findById: async () => eventRecord() },
        syncRuns: { findById: async () => syncRun() },
        execute: async () => ({ kind: 'failed', code: 'provider_disabled' }),
        redispatch: {
          add: async () => ({ ok: true, duplicate: false }),
          close: async () => undefined,
        },
        workerIdentifier: WORKER,
        kevJobLeaseMs: 600_000,
        logger: {
          info(bindings, message) {
            logs.push(`${message}:${JSON.stringify(bindings)}`);
          },
          warn(bindings, message) {
            logs.push(`${message}:${JSON.stringify(bindings)}`);
          },
        },
      },
    );
    expect(JSON.stringify(logs)).not.toMatch(/https:\/\/|etag|cve-|objectKey|www\.cisa\.gov/i);
  });
});
