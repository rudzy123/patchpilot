import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { JSON_SCHEMA_VERSION_V1 } from '../json-documents.js';
import { err, ok } from '../result.js';
import type { OutboxEventRecord } from '../records.js';
import { SBOM_INGEST_JOB_TYPE, SBOM_INGESTION_REQUESTED_EVENT_TYPE } from './constants.js';
import type {
  BackgroundJobExecutionPort,
  ClaimableOutboxEvent,
  ClaimedOutboxEvent,
  OutboxQueueJob,
  OutboxQueuePublishResult,
  OutboxQueuePublisherPort,
  OutboxRelayPersistencePort,
} from './ports.js';
import { deterministicOutboxQueueJobId } from './ports.js';
import {
  createRelayOutboxBatchUseCase,
  jobTypeForOutboxEvent,
  outboxRetryDelayMs,
} from './relay.js';

const NOW = new Date('2026-08-31T14:00:00.000Z');
const ORG = '11111111-1111-4111-8111-111111111111';
const EVENT_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const EVENT_B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const EVENT_C = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const AGGREGATE_A = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
const AGGREGATE_B = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';

describe('outbox relay use case', () => {
  it('claims, publishes outside any database transaction, then marks processed and reuses BackgroundJob', async () => {
    const harness = createHarness([pendingEvent(EVENT_A, AGGREGATE_A)]);
    const first = await harness.relay.execute();
    expect(harness.operations).toEqual([
      'claimDueBatch',
      'queue.publish',
      'markProcessedAfterQueueAcceptance',
      'enqueueQueued',
      'listProcessedAwaitingBackgroundJob',
    ]);
    expect(harness.transactionOpenDuringPublish).toBe(false);
    expect(first).toEqual({
      claimed: 1,
      published: 1,
      duplicated: 0,
      retried: 0,
      deadLettered: 0,
      reconciledJobs: 0,
    });
    expect(harness.jobs).toHaveLength(1);
    expect(harness.published[0]?.jobId).toBe(
      deterministicOutboxQueueJobId({
        id: EVENT_A,
        eventType: SBOM_INGESTION_REQUESTED_EVENT_TYPE,
      }),
    );
    expect(JSON.stringify(harness.published[0])).not.toMatch(/objectKey|filename|bomFormat/);
    expect(harness.events.get(EVENT_A)?.status).toBe('processed');

    const replay = await harness.relay.execute();
    expect(replay.claimed).toBe(0);
    expect(harness.jobs).toHaveLength(1);
  });

  it('lets competing relays claim disjoint due events', async () => {
    const shared = createStore([
      pendingEvent(EVENT_A, AGGREGATE_A),
      pendingEvent(EVENT_B, AGGREGATE_B),
    ]);
    const left = createHarnessFromStore(shared, { batchLimit: 1 });
    const right = createHarnessFromStore(shared, { batchLimit: 1 });

    const [resultA, resultB] = await Promise.all([left.relay.execute(), right.relay.execute()]);
    const claimedIds = [...left.claimedIds, ...right.claimedIds];
    expect(new Set(claimedIds).size).toBe(2);
    expect(resultA.claimed + resultB.claimed).toBe(2);
    expect(shared.jobs.size).toBe(2);
  });

  it('reclaims an expired relay lease and treats a duplicate queue job as success', async () => {
    const expired = claimedEvent(EVENT_A, AGGREGATE_A, {
      leaseExpiresAt: new Date(NOW.getTime() - 1_000),
      attemptCount: 1,
    });
    const harness = createHarness([expired], {
      publish: async () => ({ ok: true, duplicate: true }),
    });

    const result = await harness.relay.execute();
    expect(result.claimed).toBe(1);
    expect(result.duplicated).toBe(1);
    expect(harness.events.get(EVENT_A)?.status).toBe('processed');
    expect(harness.jobs).toHaveLength(1);
  });

  it('schedules a bounded retry when the queue is unavailable', async () => {
    const harness = createHarness([pendingEvent(EVENT_A, AGGREGATE_A)], {
      publish: async () => ({ ok: false, retryable: true }),
      random: () => 0,
    });
    const result = await harness.relay.execute();
    const row = harness.events.get(EVENT_A);
    expect(result.retried).toBe(1);
    expect(row?.status).toBe('pending');
    expect(row?.availableAt.getTime()).toBeGreaterThan(NOW.getTime());
    expect(row?.lastFailureCode).toBe('queue_unavailable');
    expect(harness.jobs).toHaveLength(0);
    expect(harness.operations).not.toContain('markProcessedAfterQueueAcceptance');
  });

  it('dead-letters after the attempt bound without publishing again', async () => {
    const harness = createHarness([pendingEvent(EVENT_A, AGGREGATE_A, { attemptCount: 5 })], {
      maxAttempts: 5,
    });
    const result = await harness.relay.execute();
    expect(result.deadLettered).toBe(1);
    expect(harness.published).toHaveLength(0);
    expect(harness.events.get(EVENT_A)?.status).toBe('dead_lettered');
  });

  it('does not create a BackgroundJob when the process crashes after queue acceptance', async () => {
    const harness = createHarness([pendingEvent(EVENT_A, AGGREGATE_A)], {
      failMarkProcessed: true,
    });
    const crashed = await harness.relay.execute();
    expect(crashed.published).toBe(1);
    expect(harness.events.get(EVENT_A)?.status).toBe('claimed');
    expect(harness.jobs).toHaveLength(0);

    harness.failMarkProcessed = false;
    harness.events.get(EVENT_A)!.leaseExpiresAt = new Date(NOW.getTime() - 1);
    harness.publishImpl = async () => ({ ok: true, duplicate: true });
    const recovered = await harness.relay.execute();
    expect(recovered.duplicated).toBe(1);
    expect(harness.events.get(EVENT_A)?.status).toBe('processed');
    expect(harness.jobs).toHaveLength(1);
  });

  it('reconciles processed events that are missing a BackgroundJob', async () => {
    const processed = pendingEvent(EVENT_C, AGGREGATE_A);
    processed.status = 'processed';
    processed.processedAt = NOW;
    const harness = createHarness([processed]);
    const result = await harness.relay.execute();
    expect(result.claimed).toBe(0);
    expect(result.reconciledJobs).toBe(1);
    expect(harness.jobs.map((job) => job.outboxEventId)).toEqual([EVENT_C]);
  });

  it('maps ingestion requested events to sbom.ingest and keeps Redis types out of the use case', () => {
    expect(jobTypeForOutboxEvent(SBOM_INGESTION_REQUESTED_EVENT_TYPE)).toBe(SBOM_INGEST_JOB_TYPE);
    expect(jobTypeForOutboxEvent('unknown.event')).toBeUndefined();
    expect(
      outboxRetryDelayMs(1, { retryBaseMs: 5_000, retryCapMs: 900_000, random: () => 1 }),
    ).toBe(5_000);
    const source = readFileSync(join(dirname(fileURLToPath(import.meta.url)), 'relay.ts'), 'utf8');
    expect(source).not.toMatch(/bullmq|ioredis|Prisma|process\.env/);
  });
});

type StoredEvent = ClaimableOutboxEvent & {
  status: OutboxEventRecord['status'];
  claimedAt: Date | null;
  leaseExpiresAt: Date | null;
  processedAt: Date | null;
  lastFailureCategory: string | null;
  lastFailureCode: string | null;
};

type StoredJob = {
  id: string;
  organizationId: string | null;
  outboxEventId: string;
  jobType: string;
  dedupeKey: string;
};

function pendingEvent(
  id: string,
  aggregateId: string,
  overrides: Partial<StoredEvent> = {},
): StoredEvent {
  return {
    id,
    organizationId: ORG,
    aggregateType: 'sbom_ingestion',
    aggregateId,
    eventType: SBOM_INGESTION_REQUESTED_EVENT_TYPE,
    dedupeKey: `${ORG}:sbom.ingest:${aggregateId}:0.1.0`,
    availableAt: new Date(NOW.getTime() - 1_000),
    attemptCount: 0,
    status: 'pending',
    claimedAt: null,
    leaseExpiresAt: null,
    processedAt: null,
    lastFailureCategory: null,
    lastFailureCode: null,
    ...overrides,
  };
}

function claimedEvent(
  id: string,
  aggregateId: string,
  overrides: Partial<StoredEvent>,
): StoredEvent {
  return pendingEvent(id, aggregateId, {
    status: 'claimed',
    claimedAt: new Date(NOW.getTime() - 10_000),
    leaseExpiresAt: new Date(NOW.getTime() + 30_000),
    attemptCount: 1,
    ...overrides,
  });
}

function createHarness(
  seed: StoredEvent[],
  options?: {
    publish?: OutboxQueuePublisherPort['publish'];
    failMarkProcessed?: boolean;
    maxAttempts?: number;
    random?: () => number;
    batchLimit?: number;
  },
) {
  return createHarnessFromStore(createStore(seed), options);
}

function createStore(seed: StoredEvent[]) {
  const events = new Map(seed.map((event) => [event.id, { ...event }]));
  const jobs = new Map<string, StoredJob>();
  let claimChain = Promise.resolve();
  return {
    events,
    jobs,
    claimChain: {
      get: () => claimChain,
      set: (next: Promise<void>) => {
        claimChain = next;
      },
    },
  };
}

function createHarnessFromStore(
  store: ReturnType<typeof createStore>,
  options?: {
    publish?: OutboxQueuePublisherPort['publish'];
    failMarkProcessed?: boolean;
    maxAttempts?: number;
    random?: () => number;
    batchLimit?: number;
  },
) {
  const operations: string[] = [];
  const published: OutboxQueueJob[] = [];
  const claimedIds: string[] = [];
  let transactionOpen = false;
  let transactionOpenDuringPublish = false;
  let failMarkProcessed = options?.failMarkProcessed ?? false;
  let publishImpl: OutboxQueuePublisherPort['publish'] =
    options?.publish ??
    (async (job) => {
      published.push(job);
      return { ok: true, duplicate: false };
    });

  const outbox: OutboxRelayPersistencePort = {
    async claimDueBatch(input) {
      transactionOpen = true;
      const run = store.claimChain.get().then(() => claimUnsafe(store.events, input));
      store.claimChain.set(
        run.then(
          () => undefined,
          () => undefined,
        ),
      );
      const claimed = await run;
      transactionOpen = false;
      operations.push('claimDueBatch');
      claimedIds.push(...claimed.map((event) => event.id));
      return claimed;
    },
    async expireLease() {
      return ok(undefined);
    },
    async markProcessedAfterQueueAcceptance(input) {
      operations.push('markProcessedAfterQueueAcceptance');
      if (failMarkProcessed) {
        return err({ code: 'conflict', message: 'Outbox event was not marked processed.' });
      }
      const row = store.events.get(input.eventId);
      if (row === undefined || row.status !== 'claimed') {
        return err({ code: 'conflict', message: 'Outbox event was not marked processed.' });
      }
      row.status = 'processed';
      row.processedAt = input.acceptedAt;
      row.claimedAt = null;
      row.leaseExpiresAt = null;
      return ok(toRecord(row, NOW));
    },
    async markRetryableDeliveryFailure(input) {
      operations.push('markRetryableDeliveryFailure');
      const row = store.events.get(input.eventId);
      if (row === undefined) {
        return err({ code: 'not_found', message: 'Outbox event was not found.' });
      }
      row.status = 'pending';
      row.claimedAt = null;
      row.leaseExpiresAt = null;
      row.availableAt = input.availableAt;
      row.lastFailureCategory = input.failureCategory;
      row.lastFailureCode = input.failureCode;
      return ok(toRecord(row, NOW));
    },
    async markDeadLetter(input) {
      operations.push('markDeadLetter');
      const row = store.events.get(input.eventId);
      if (row === undefined) {
        return err({ code: 'not_found', message: 'Outbox event was not found.' });
      }
      row.status = 'dead_lettered';
      row.claimedAt = null;
      row.leaseExpiresAt = null;
      row.lastFailureCategory = input.failureCategory;
      row.lastFailureCode = input.failureCode;
      return ok(toRecord(row, NOW));
    },
    async listProcessedAwaitingBackgroundJob(input) {
      operations.push('listProcessedAwaitingBackgroundJob');
      return [...store.events.values()]
        .filter((row) => row.status === 'processed' && !store.jobs.has(row.id))
        .slice(0, input.limit);
    },
  };

  const queue: OutboxQueuePublisherPort = {
    async publish(job) {
      transactionOpenDuringPublish = transactionOpen;
      operations.push('queue.publish');
      return publishImpl(job);
    },
  };

  const backgroundJobs: Pick<BackgroundJobExecutionPort, 'enqueueQueued'> = {
    async enqueueQueued(input) {
      operations.push('enqueueQueued');
      const existing = store.jobs.get(input.outboxEventId);
      if (existing !== undefined) {
        return {
          id: existing.id,
          organizationId: existing.organizationId,
          jobType: existing.jobType,
          status: 'queued' as const,
          attempt: 0,
        };
      }
      const created: StoredJob = {
        id: `job-${input.outboxEventId}`,
        organizationId: input.organizationId,
        outboxEventId: input.outboxEventId,
        jobType: input.jobType,
        dedupeKey: input.dedupeKey,
      };
      store.jobs.set(input.outboxEventId, created);
      return {
        id: created.id,
        organizationId: created.organizationId,
        jobType: created.jobType,
        status: 'queued' as const,
        attempt: 0,
      };
    },
  };

  const relay = createRelayOutboxBatchUseCase({
    clock: { now: () => NOW },
    outbox,
    queue,
    backgroundJobs,
    options: {
      batchLimit: options?.batchLimit ?? 50,
      maxAttempts: options?.maxAttempts ?? 5,
      random: options?.random ?? (() => 0),
    },
  });

  return {
    relay,
    events: store.events,
    get jobs() {
      return [...store.jobs.values()];
    },
    operations,
    published,
    claimedIds,
    get transactionOpenDuringPublish() {
      return transactionOpenDuringPublish;
    },
    set failMarkProcessed(value: boolean) {
      failMarkProcessed = value;
    },
    set publishImpl(value: (job: OutboxQueueJob) => Promise<OutboxQueuePublishResult>) {
      publishImpl = value;
    },
  };
}

function claimUnsafe(
  events: Map<string, StoredEvent>,
  input: { limit: number; now: Date; leaseExpiresAt: Date },
): ClaimedOutboxEvent[] {
  const pending = [...events.values()]
    .filter((row) => row.status === 'pending' && row.availableAt.getTime() <= input.now.getTime())
    .sort(byAvailability);
  const remaining = input.limit - pending.length;
  const expired =
    remaining > 0
      ? [...events.values()]
          .filter(
            (row) =>
              row.status === 'claimed' &&
              row.leaseExpiresAt !== null &&
              row.leaseExpiresAt.getTime() < input.now.getTime(),
          )
          .sort(byAvailability)
          .slice(0, remaining)
      : [];
  const selected = [...pending, ...expired].slice(0, input.limit);
  const claimed: ClaimedOutboxEvent[] = [];
  for (const row of selected) {
    row.status = 'claimed';
    row.claimedAt = input.now;
    row.leaseExpiresAt = input.leaseExpiresAt;
    row.attemptCount += 1;
    claimed.push({
      id: row.id,
      organizationId: row.organizationId,
      aggregateType: row.aggregateType,
      aggregateId: row.aggregateId,
      eventType: row.eventType,
      dedupeKey: row.dedupeKey,
      availableAt: row.availableAt,
      attemptCount: row.attemptCount,
      eventId: row.id,
      claimedAt: input.now,
      leaseExpiresAt: input.leaseExpiresAt,
    });
  }
  return claimed;
}

function byAvailability(left: StoredEvent, right: StoredEvent): number {
  const available = left.availableAt.getTime() - right.availableAt.getTime();
  if (available !== 0) {
    return available;
  }
  return left.id.localeCompare(right.id);
}

function toRecord(row: StoredEvent, now: Date): OutboxEventRecord {
  return {
    id: row.id,
    organizationId: row.organizationId,
    aggregateType: row.aggregateType,
    aggregateId: row.aggregateId,
    eventType: row.eventType,
    eventSchemaVersion: JSON_SCHEMA_VERSION_V1,
    payload: { schemaVersion: JSON_SCHEMA_VERSION_V1, ids: {}, metadata: {} },
    dedupeKey: row.dedupeKey,
    occurredAt: now,
    availableAt: row.availableAt,
    claimedAt: row.claimedAt,
    leaseExpiresAt: row.leaseExpiresAt,
    processedAt: row.processedAt,
    attemptCount: row.attemptCount,
    lastFailureCategory: row.lastFailureCategory,
    lastFailureCode: row.lastFailureCode,
    status: row.status,
    createdAt: now,
  };
}
