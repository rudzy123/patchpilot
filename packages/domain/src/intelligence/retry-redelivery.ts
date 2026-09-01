import { err, ok, type Result } from '../result.js';
import { deterministicOutboxQueueJobId } from '../sbom/ports.js';
import {
  INTELLIGENCE_SYNC_JOB_TYPE,
  INTELLIGENCE_SYNC_REQUESTED_EVENT_TYPE,
  UUID_PATTERN,
  intelligenceSyncRunTerminalStates,
  type IntelligenceSyncRunState,
} from './constants.js';
import { intelligenceValidationError } from './errors.js';
import { isNonNegativeSafeInteger, isPositiveSafeInteger } from './normalize.js';
import type { IntelligenceSyncJobPayload } from './sync-job.js';

export const INTELLIGENCE_RETRY_JOB_ID_MAX_LENGTH = 256;

export type IntelligenceRedeliveryCandidate = {
  syncRunId: string;
  backgroundJobId: string;
  outboxEventId: string;
  jobAttempt: number;
  jobStatus: 'queued' | 'running';
  syncRunState: IntelligenceSyncRunState;
  nextAttemptAt: Date | null;
  leaseExpiresAt: Date | null;
  locator: IntelligenceSyncJobPayload;
};

export function intelligenceInitialQueueJobId(outboxEventId: string): Result<string> {
  if (!UUID_PATTERN.test(outboxEventId)) {
    return err(intelligenceValidationError('Outbox event id must be a UUID.'));
  }
  return ok(
    deterministicOutboxQueueJobId({
      id: outboxEventId,
      eventType: INTELLIGENCE_SYNC_REQUESTED_EVENT_TYPE,
    }),
  );
}

/**
 * Deterministic Redis job id for a later delivery of the same OutboxEvent.
 * Attempt is the persisted BackgroundJob.attempt. Redis job id is not
 * execution authority.
 */
export function intelligenceRetryQueueJobId(input: {
  outboxEventId: string;
  attempt: number;
}): Result<string> {
  if (!UUID_PATTERN.test(input.outboxEventId)) {
    return err(intelligenceValidationError('Outbox event id must be a UUID.'));
  }
  if (!isPositiveSafeInteger(input.attempt)) {
    return err(intelligenceValidationError('Retry job id requires a positive persisted attempt.'));
  }
  const jobId = `${INTELLIGENCE_SYNC_REQUESTED_EVENT_TYPE}__${input.outboxEventId}__retry__${String(input.attempt)}`;
  if (jobId.length > INTELLIGENCE_RETRY_JOB_ID_MAX_LENGTH) {
    return err(intelligenceValidationError('Retry job id exceeds the bounded length.'));
  }
  return ok(jobId);
}

export function intelligenceRedispatchJobId(candidate: {
  outboxEventId: string;
  jobAttempt: number;
}): Result<string> {
  if (!isNonNegativeSafeInteger(candidate.jobAttempt)) {
    return err(intelligenceValidationError('BackgroundJob attempt is not a safe integer.'));
  }
  if (candidate.jobAttempt === 0) {
    return intelligenceInitialQueueJobId(candidate.outboxEventId);
  }
  return intelligenceRetryQueueJobId({
    outboxEventId: candidate.outboxEventId,
    attempt: candidate.jobAttempt,
  });
}

export function isTerminalIntelligenceSyncRunState(state: IntelligenceSyncRunState): boolean {
  return (intelligenceSyncRunTerminalStates as readonly string[]).includes(state);
}

export const INTELLIGENCE_REDELIVERY_JOB_TYPE = INTELLIGENCE_SYNC_JOB_TYPE;
