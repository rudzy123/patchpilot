import { UnrecoverableError, type Job } from 'bullmq';

import {
  CISA_KEV_SOURCE_IDENTIFIER,
  INTELLIGENCE_AUDIT_SUBJECT_TYPE,
  INTELLIGENCE_SYNC_JOB_TYPE,
  INTELLIGENCE_SYNC_REQUESTED_EVENT_TYPE,
  intelligenceRedispatchJobId,
  parseIntelligenceSyncJobPayload,
  parsePersistedIntelligenceSyncRequestedOutboxPayload,
  type BackgroundJobExecutionPort,
  type BackgroundJobRecord,
  type Clock,
  type CisaKevSynchronizationOutcome,
  type IntelligenceOutboxLookupPort,
  type IntelligenceSyncJobPayload,
  type IntelligenceSyncRunPersistencePort,
} from '@patchpilot/domain';

import type { IntelligenceJobRedispatch } from './intelligence-job-redispatch.js';

export type IntelligenceSyncProcessorLogger = {
  info(bindings: Record<string, unknown>, message: string): void;
  warn(bindings: Record<string, unknown>, message: string): void;
};

export type IntelligenceSyncProcessorDependencies = {
  clock: Clock;
  jobs: BackgroundJobExecutionPort;
  outbox: IntelligenceOutboxLookupPort;
  syncRuns: Pick<IntelligenceSyncRunPersistencePort, 'findById'>;
  execute: (input: {
    syncRunId: string;
    backgroundJobId: string;
    workerIdentifier: string;
    signal?: AbortSignal;
  }) => Promise<CisaKevSynchronizationOutcome>;
  redispatch: IntelligenceJobRedispatch;
  workerIdentifier: string;
  kevJobLeaseMs: number;
  logger: IntelligenceSyncProcessorLogger;
  signal?: AbortSignal;
};

export async function processIntelligenceSyncQueueJob(
  job: Pick<Job, 'name' | 'id' | 'data'>,
  dependencies: IntelligenceSyncProcessorDependencies,
): Promise<void> {
  if (job.name !== INTELLIGENCE_SYNC_JOB_TYPE) {
    throw new UnrecoverableError('Unsupported intelligence job name.');
  }

  const locator = parseIntelligenceSyncJobPayload(job.data);
  if (!locator.ok) {
    throw new UnrecoverableError('Intelligence sync job locator is invalid.');
  }

  const event = await dependencies.outbox.findById({
    organizationId: null,
    eventId: locator.value.outboxEventId,
  });
  if (event === undefined || event.organizationId !== null) {
    throw new UnrecoverableError('Intelligence sync outbox event was not found.');
  }
  if (event.eventType !== INTELLIGENCE_SYNC_REQUESTED_EVENT_TYPE) {
    throw new UnrecoverableError('Intelligence sync outbox event type is invalid.');
  }
  if (event.aggregateType !== INTELLIGENCE_AUDIT_SUBJECT_TYPE) {
    throw new UnrecoverableError('Intelligence sync outbox aggregate type is invalid.');
  }

  const payload = parsePersistedIntelligenceSyncRequestedOutboxPayload(event.payload);
  if (!payload.ok) {
    throw new UnrecoverableError('Intelligence sync outbox payload is invalid.');
  }
  if (
    payload.value.syncRunId !== locator.value.aggregateId ||
    payload.value.syncRunId !== event.aggregateId ||
    payload.value.provider !== 'cisa_kev' ||
    payload.value.sourceIdentifier !== CISA_KEV_SOURCE_IDENTIFIER
  ) {
    throw new UnrecoverableError('Intelligence sync locator does not match stored records.');
  }

  let backgroundJob = await dependencies.jobs.findByOutboxEventId({
    organizationId: null,
    outboxEventId: locator.value.outboxEventId,
  });
  if (backgroundJob === undefined) {
    await dependencies.jobs.enqueueQueued({
      organizationId: null,
      outboxEventId: locator.value.outboxEventId,
      jobType: INTELLIGENCE_SYNC_JOB_TYPE,
      dedupeKey: locator.value.dedupeKey,
    });
    backgroundJob = await dependencies.jobs.findByOutboxEventId({
      organizationId: null,
      outboxEventId: locator.value.outboxEventId,
    });
  }
  if (backgroundJob === undefined) {
    throw new UnrecoverableError('Intelligence sync background job was not found.');
  }
  if (
    backgroundJob.organizationId !== null ||
    backgroundJob.jobType !== INTELLIGENCE_SYNC_JOB_TYPE
  ) {
    throw new UnrecoverableError('Intelligence sync background job identity is invalid.');
  }

  if (
    backgroundJob.status === 'succeeded' ||
    backgroundJob.status === 'failed' ||
    backgroundJob.status === 'dead_lettered' ||
    backgroundJob.status === 'cancelled'
  ) {
    logSafe(dependencies, locator.value, backgroundJob, 'already_complete');
    return;
  }

  const syncRun = await dependencies.syncRuns.findById(payload.value.syncRunId);
  if (syncRun === undefined) {
    throw new UnrecoverableError('Intelligence sync run was not found.');
  }
  if (syncRun.provider !== 'cisa_kev' || syncRun.sourceIdentifier !== CISA_KEV_SOURCE_IDENTIFIER) {
    throw new UnrecoverableError('Intelligence sync run identity is invalid.');
  }

  const now = dependencies.clock.now();
  if (
    syncRun.state === 'retry_wait' &&
    syncRun.nextAttemptAt !== null &&
    syncRun.nextAttemptAt.getTime() > now.getTime()
  ) {
    await redispatchRetry({
      dependencies,
      locator: locator.value,
      job: backgroundJob,
      delayMs: syncRun.nextAttemptAt.getTime() - now.getTime(),
    });
    const waitCode = syncRun.failureCode;
    if (waitCode === null) {
      logSafe(dependencies, locator.value, backgroundJob, 'retry_wait');
    } else {
      logSafe(dependencies, locator.value, backgroundJob, 'retry_wait', waitCode);
    }
    return;
  }

  const claimed = await dependencies.jobs.claimExecution({
    organizationId: null,
    jobId: backgroundJob.id,
    workerIdentifier: dependencies.workerIdentifier,
    now,
    leaseExpiresAt: new Date(now.getTime() + dependencies.kevJobLeaseMs),
  });
  if (!claimed.ok) {
    logSafe(dependencies, locator.value, backgroundJob, 'ownership_lost');
    return;
  }

  const outcome = await dependencies.execute({
    syncRunId: payload.value.syncRunId,
    backgroundJobId: backgroundJob.id,
    workerIdentifier: dependencies.workerIdentifier,
    ...(dependencies.signal === undefined ? {} : { signal: dependencies.signal }),
  });

  const currentJob = await dependencies.jobs.findById({
    organizationId: null,
    jobId: backgroundJob.id,
  });
  await mapOutcome(dependencies, locator.value, currentJob ?? backgroundJob, outcome);
}

async function mapOutcome(
  dependencies: IntelligenceSyncProcessorDependencies,
  locator: IntelligenceSyncJobPayload,
  job: BackgroundJobRecord,
  outcome: CisaKevSynchronizationOutcome,
): Promise<void> {
  const now = dependencies.clock.now();
  if (
    outcome.kind === 'completed' ||
    outcome.kind === 'not_modified' ||
    outcome.kind === 'already_complete'
  ) {
    if (job.status === 'running' && job.workerIdentifier === dependencies.workerIdentifier) {
      await dependencies.jobs.markSucceeded({
        organizationId: null,
        jobId: job.id,
        workerIdentifier: dependencies.workerIdentifier,
        completedAt: now,
      });
    }
    logSafe(dependencies, locator, job, outcome.kind);
    return;
  }
  if (outcome.kind === 'failed' || outcome.kind === 'quarantined') {
    logSafe(dependencies, locator, job, outcome.kind, outcome.code);
    return;
  }
  if (outcome.kind === 'retry_wait' || outcome.kind === 'job_retry') {
    await redispatchRetry({
      dependencies,
      locator,
      job,
      delayMs: outcome.kind === 'retry_wait' ? outcome.nextAttemptAt.getTime() - now.getTime() : 0,
    });
    logSafe(dependencies, locator, job, outcome.kind, outcome.code);
    return;
  }
  if (outcome.kind === 'rejected') {
    if (outcome.code === 'invalid_provider_source') {
      throw new UnrecoverableError('Intelligence sync job locator is invalid.');
    }
    logSafe(dependencies, locator, job, outcome.kind, outcome.code);
    return;
  }
  logSafe(dependencies, locator, job, outcome.kind);
}

async function redispatchRetry(input: {
  dependencies: IntelligenceSyncProcessorDependencies;
  locator: IntelligenceSyncJobPayload;
  job: BackgroundJobRecord;
  delayMs: number;
}): Promise<void> {
  const jobId = intelligenceRedispatchJobId({
    outboxEventId: input.locator.outboxEventId,
    jobAttempt: input.job.attempt,
  });
  if (!jobId.ok) {
    return;
  }
  const delayMs = Math.max(0, input.delayMs);
  const published = await input.dependencies.redispatch.add({
    jobId: jobId.value,
    payload: input.locator,
    ...(delayMs > 0 ? { delayMs } : {}),
  });
  if (!published.ok) {
    input.dependencies.logger.warn(
      {
        operation: 'intelligence_sync',
        provider: 'cisa_kev',
        sourceIdentifier: CISA_KEV_SOURCE_IDENTIFIER,
        syncRunId: input.locator.aggregateId,
        backgroundJobId: input.job.id,
        outboxEventId: input.locator.outboxEventId,
        outcome: 'redispatch_failed',
      },
      'intelligence sync redispatch failed',
    );
  }
}

function logSafe(
  dependencies: IntelligenceSyncProcessorDependencies,
  locator: IntelligenceSyncJobPayload,
  job: BackgroundJobRecord,
  outcome: string,
  code?: string,
): void {
  const bindings: Record<string, unknown> = {
    operation: 'intelligence_sync',
    provider: 'cisa_kev',
    sourceIdentifier: CISA_KEV_SOURCE_IDENTIFIER,
    syncRunId: locator.aggregateId,
    backgroundJobId: job.id,
    outboxEventId: locator.outboxEventId,
    outcome,
    attempt: job.attempt,
  };
  if (code !== undefined) {
    bindings['code'] = code;
  }
  if (outcome === 'retry_wait' || outcome === 'job_retry' || outcome === 'ownership_lost') {
    dependencies.logger.warn(bindings, 'intelligence sync job finished');
    return;
  }
  dependencies.logger.info(bindings, 'intelligence sync job finished');
}
