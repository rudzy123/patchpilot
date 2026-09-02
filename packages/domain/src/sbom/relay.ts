import {
  INTELLIGENCE_SYNC_JOB_TYPE,
  INTELLIGENCE_SYNC_REQUESTED_EVENT_TYPE,
} from '../intelligence/constants.js';
import type { Clock } from '../clock.js';
import {
  OUTBOX_RELAY_BATCH_LIMIT,
  OUTBOX_RELAY_LEASE_MS,
  OUTBOX_RELAY_MAX_ATTEMPTS,
  OUTBOX_RELAY_RETRY_BASE_MS,
  OUTBOX_RELAY_RETRY_CAP_MS,
  SBOM_INGEST_JOB_TYPE,
  SBOM_INGESTION_REQUESTED_EVENT_TYPE,
} from './constants.js';
import type {
  BackgroundJobExecutionPort,
  ClaimableOutboxEvent,
  ClaimedOutboxEvent,
  OutboxQueueJob,
  OutboxQueuePublisherPort,
  OutboxRelayPersistencePort,
} from './ports.js';
import { deterministicOutboxQueueJobId } from './ports.js';

export type OutboxRelayLogger = {
  warn(bindings: Record<string, unknown>, message: string): void;
};

export type OutboxRelayOptions = {
  batchLimit: number;
  leaseMs: number;
  maxAttempts: number;
  retryBaseMs: number;
  retryCapMs: number;
  random: () => number;
};

export type OutboxRelayDependencies = {
  clock: Clock;
  outbox: OutboxRelayPersistencePort;
  queue: OutboxQueuePublisherPort;
  backgroundJobs: Pick<BackgroundJobExecutionPort, 'enqueueQueued'>;
  options?: Partial<Omit<OutboxRelayOptions, 'random'>> & { random?: () => number };
  logger?: OutboxRelayLogger;
};

export type OutboxRelayBatchResult = {
  claimed: number;
  published: number;
  duplicated: number;
  retried: number;
  deadLettered: number;
  reconciledJobs: number;
};

export const OUTBOX_RELAY_DEFAULTS: Omit<OutboxRelayOptions, 'random'> = {
  batchLimit: OUTBOX_RELAY_BATCH_LIMIT,
  leaseMs: OUTBOX_RELAY_LEASE_MS,
  maxAttempts: OUTBOX_RELAY_MAX_ATTEMPTS,
  retryBaseMs: OUTBOX_RELAY_RETRY_BASE_MS,
  retryCapMs: OUTBOX_RELAY_RETRY_CAP_MS,
};

export function jobTypeForOutboxEvent(eventType: string): string | undefined {
  if (eventType === SBOM_INGESTION_REQUESTED_EVENT_TYPE) {
    return SBOM_INGEST_JOB_TYPE;
  }
  if (eventType === INTELLIGENCE_SYNC_REQUESTED_EVENT_TYPE) {
    return INTELLIGENCE_SYNC_JOB_TYPE;
  }
  return undefined;
}

export function outboxRetryDelayMs(
  attemptCount: number,
  options: Pick<OutboxRelayOptions, 'retryBaseMs' | 'retryCapMs' | 'random'>,
): number {
  const exponent = Math.max(0, attemptCount - 1);
  const exponential = Math.min(options.retryCapMs, options.retryBaseMs * 2 ** exponent);
  const jitter = 0.5 + options.random() * 0.5;
  return Math.min(options.retryCapMs, Math.max(1, Math.floor(exponential * jitter)));
}

export function createRelayOutboxBatchUseCase(dependencies: OutboxRelayDependencies) {
  const options = resolveOptions(dependencies.options);
  return {
    execute(): Promise<OutboxRelayBatchResult> {
      return executeRelayBatch(dependencies, options);
    },
  };
}

async function executeRelayBatch(
  dependencies: OutboxRelayDependencies,
  options: OutboxRelayOptions,
): Promise<OutboxRelayBatchResult> {
  const now = dependencies.clock.now();
  const claimed = await dependencies.outbox.claimDueBatch({
    limit: options.batchLimit,
    now,
    leaseExpiresAt: new Date(now.getTime() + options.leaseMs),
  });

  const result: OutboxRelayBatchResult = {
    claimed: claimed.length,
    published: 0,
    duplicated: 0,
    retried: 0,
    deadLettered: 0,
    reconciledJobs: 0,
  };

  for (const event of claimed) {
    const outcome = await relayClaimedEvent(dependencies, options, event, now);
    result[outcome] += 1;
  }

  const awaiting = await dependencies.outbox.listProcessedAwaitingBackgroundJob({
    limit: options.batchLimit,
  });
  for (const event of awaiting) {
    const jobType = jobTypeForOutboxEvent(event.eventType);
    if (jobType === undefined) {
      continue;
    }
    await dependencies.backgroundJobs.enqueueQueued({
      organizationId: event.organizationId,
      outboxEventId: event.id,
      jobType,
      dedupeKey: event.dedupeKey,
    });
    result.reconciledJobs += 1;
  }

  return result;
}

async function relayClaimedEvent(
  dependencies: OutboxRelayDependencies,
  options: OutboxRelayOptions,
  event: ClaimedOutboxEvent,
  now: Date,
): Promise<'published' | 'duplicated' | 'retried' | 'deadLettered'> {
  const jobType = jobTypeForOutboxEvent(event.eventType);
  if (jobType === undefined || event.attemptCount > options.maxAttempts) {
    await dependencies.outbox.markDeadLetter({
      organizationId: event.organizationId,
      eventId: event.id,
      failureCategory: 'internal',
      failureCode: 'processing_failed',
    });
    dependencies.logger?.warn(
      {
        eventId: event.id,
        organizationId: event.organizationId,
        attemptCount: event.attemptCount,
      },
      'outbox event dead-lettered',
    );
    return 'deadLettered';
  }

  const job = toQueueJob(event, jobType);
  const published = await dependencies.queue.publish(job);
  if (!published.ok) {
    const availableAt = new Date(now.getTime() + outboxRetryDelayMs(event.attemptCount, options));
    await dependencies.outbox.markRetryableDeliveryFailure({
      organizationId: event.organizationId,
      eventId: event.id,
      failureCategory: 'timeout',
      failureCode: 'queue_unavailable',
      availableAt,
    });
    dependencies.logger?.warn(
      {
        eventId: event.id,
        organizationId: event.organizationId,
        attemptCount: event.attemptCount,
      },
      'outbox publish failed; retry scheduled',
    );
    return 'retried';
  }

  const processed = await dependencies.outbox.markProcessedAfterQueueAcceptance({
    organizationId: event.organizationId,
    eventId: event.id,
    acceptedAt: now,
    queueJobId: job.jobId,
  });
  if (!processed.ok) {
    return published.duplicate ? 'duplicated' : 'published';
  }

  await dependencies.backgroundJobs.enqueueQueued({
    organizationId: event.organizationId,
    outboxEventId: event.id,
    jobType,
    dedupeKey: event.dedupeKey,
  });
  return published.duplicate ? 'duplicated' : 'published';
}

function toQueueJob(event: ClaimableOutboxEvent, jobType: string): OutboxQueueJob {
  return {
    jobId: deterministicOutboxQueueJobId(event),
    jobType,
    organizationId: event.organizationId,
    outboxEventId: event.id,
    aggregateType: event.aggregateType,
    aggregateId: event.aggregateId,
    eventType: event.eventType,
    dedupeKey: event.dedupeKey,
  };
}

function resolveOptions(overrides: OutboxRelayDependencies['options']): OutboxRelayOptions {
  return {
    batchLimit: overrides?.batchLimit ?? OUTBOX_RELAY_DEFAULTS.batchLimit,
    leaseMs: overrides?.leaseMs ?? OUTBOX_RELAY_DEFAULTS.leaseMs,
    maxAttempts: overrides?.maxAttempts ?? OUTBOX_RELAY_DEFAULTS.maxAttempts,
    retryBaseMs: overrides?.retryBaseMs ?? OUTBOX_RELAY_DEFAULTS.retryBaseMs,
    retryCapMs: overrides?.retryCapMs ?? OUTBOX_RELAY_DEFAULTS.retryCapMs,
    random: overrides?.random ?? Math.random,
  };
}
