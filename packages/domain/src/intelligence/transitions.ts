import { assertNever, err, ok, type Result } from '../result.js';
import {
  intelligenceForbiddenSyncStages,
  intelligenceSyncRunStages,
  intelligenceSyncRunTerminalStates,
  type IntelligenceNotModifiedReason,
  type IntelligenceSyncRunStage,
  type IntelligenceSyncRunState,
} from './constants.js';
import {
  INTELLIGENCE_INVALID_TRANSITION,
  INTELLIGENCE_TERMINAL_STATE,
  intelligenceValidationError,
} from './errors.js';
import {
  classifyIntelligenceSafeFailure,
  isIntelligenceQuarantineCategory,
  type IntelligenceSafeFailureCategory,
  type IntelligenceSafeFailureCode,
} from './failures.js';
import { intelligenceFreshnessMayAdvanceForState } from './freshness.js';
import { isNonNegativeSafeInteger, isPositiveSafeInteger } from './normalize.js';

export type IntelligenceSyncRunSnapshot = {
  state: IntelligenceSyncRunState;
  stage: IntelligenceSyncRunStage | null;
  requestedAt: Date;
  startedAt: Date | null;
  completedAt: Date | null;
  nextAttemptAt: Date | null;
  executionAttempt: number;
  snapshotId: string | null;
  generationId: string | null;
  failureCategory: IntelligenceSafeFailureCategory | null;
  failureCode: IntelligenceSafeFailureCode | null;
  acceptedEntryCount: number | null;
  priorAcceptedGenerationId: string | null;
  notModifiedReason: IntelligenceNotModifiedReason | null;
};

export type CreateRequestedSyncRunCommand = {
  type: 'create_requested';
  requestedAt: Date;
};

export type StartFetchingCommand = {
  type: 'start_fetching';
  startedAt: Date;
  executionAttempt: number;
};

export type RecordRetryWaitCommand = {
  type: 'record_retry_wait';
  nextAttemptAt: Date;
  failureCode: IntelligenceSafeFailureCode;
};

export type RecordStoredCommand = {
  type: 'record_stored';
  snapshotId: string;
};

export type StartParsingCommand = {
  type: 'start_parsing';
};

export type StartStagingCommand = {
  type: 'start_staging';
  generationId: string;
};

export type StartActivatingCommand = {
  type: 'start_activating';
  generationComplete: true;
};

export type CompleteSyncRunCommand = {
  type: 'complete';
  completedAt: Date;
  acceptedEntryCount: number;
};

export type CompleteNotModifiedCommand = {
  type: 'complete_not_modified';
  completedAt: Date;
  priorAcceptedGenerationId: string;
  reason: IntelligenceNotModifiedReason;
};

export type FailSyncRunCommand = {
  type: 'fail';
  completedAt: Date;
  failureCode: IntelligenceSafeFailureCode;
};

export type QuarantineSyncRunCommand = {
  type: 'quarantine';
  completedAt: Date;
  failureCode: IntelligenceSafeFailureCode;
};

export type IntelligenceSyncRunCommand =
  | CreateRequestedSyncRunCommand
  | StartFetchingCommand
  | RecordRetryWaitCommand
  | RecordStoredCommand
  | StartParsingCommand
  | StartStagingCommand
  | StartActivatingCommand
  | CompleteSyncRunCommand
  | CompleteNotModifiedCommand
  | FailSyncRunCommand
  | QuarantineSyncRunCommand;

const failableStates = [
  'fetching',
  'retry_wait',
  'stored',
  'parsing',
  'staging',
  'activating',
] as const;

const quarantinableStates = ['fetching', 'stored', 'parsing', 'staging', 'activating'] as const;

export function isIntelligenceSyncRunStage(stage: string): stage is IntelligenceSyncRunStage {
  return (intelligenceSyncRunStages as readonly string[]).includes(stage);
}

export function isIntelligenceForbiddenSyncStage(stage: string): boolean {
  return (intelligenceForbiddenSyncStages as readonly string[]).includes(stage);
}

export function isIntelligenceTerminalSyncRunState(state: IntelligenceSyncRunState): boolean {
  return (intelligenceSyncRunTerminalStates as readonly string[]).includes(state);
}

export function syncRunFreshnessMayAdvance(snapshot: IntelligenceSyncRunSnapshot): boolean {
  if (snapshot.state === 'completed' || snapshot.state === 'not_modified') {
    return intelligenceFreshnessMayAdvanceForState(snapshot.state);
  }
  return false;
}

function requireCurrent(
  current: IntelligenceSyncRunSnapshot | undefined,
): Result<IntelligenceSyncRunSnapshot> {
  if (current === undefined) {
    return err(INTELLIGENCE_INVALID_TRANSITION);
  }
  if (isIntelligenceTerminalSyncRunState(current.state)) {
    return err(INTELLIGENCE_TERMINAL_STATE);
  }
  if (current.stage !== null && isIntelligenceForbiddenSyncStage(current.stage)) {
    return err(intelligenceValidationError('Finding-related stages are not part of Session 9.'));
  }
  return ok(current);
}

function requestedSnapshot(requestedAt: Date): IntelligenceSyncRunSnapshot {
  return {
    state: 'requested',
    stage: null,
    requestedAt,
    startedAt: null,
    completedAt: null,
    nextAttemptAt: null,
    executionAttempt: 0,
    snapshotId: null,
    generationId: null,
    failureCategory: null,
    failureCode: null,
    acceptedEntryCount: null,
    priorAcceptedGenerationId: null,
    notModifiedReason: null,
  };
}

function assertRequestedInvariants(snapshot: IntelligenceSyncRunSnapshot): Result<void> {
  if (
    snapshot.startedAt !== null ||
    snapshot.completedAt !== null ||
    snapshot.snapshotId !== null ||
    snapshot.generationId !== null
  ) {
    return err(
      intelligenceValidationError(
        'requested runs cannot carry start, completion, snapshot, or generation.',
      ),
    );
  }
  return ok(undefined);
}

function commit(next: IntelligenceSyncRunSnapshot): Result<IntelligenceSyncRunSnapshot> {
  const invariants = assertSyncRunStateInvariants(next);
  if (!invariants.ok) {
    return invariants;
  }
  return ok(next);
}

export function applyIntelligenceSyncRunTransition(
  current: IntelligenceSyncRunSnapshot | undefined,
  command: IntelligenceSyncRunCommand,
): Result<IntelligenceSyncRunSnapshot> {
  switch (command.type) {
    case 'create_requested': {
      if (current !== undefined) {
        return err(INTELLIGENCE_INVALID_TRANSITION);
      }
      return commit(requestedSnapshot(command.requestedAt));
    }
    case 'start_fetching': {
      const existing = requireCurrent(current);
      if (!existing.ok) {
        return existing;
      }
      if (existing.value.state !== 'requested' && existing.value.state !== 'retry_wait') {
        return err(INTELLIGENCE_INVALID_TRANSITION);
      }
      if (!isPositiveSafeInteger(command.executionAttempt)) {
        return err(
          intelligenceValidationError('Execution attempt must be a positive safe integer.'),
        );
      }
      if (existing.value.state === 'requested' && command.executionAttempt !== 1) {
        return err(intelligenceValidationError('First fetch attempt must be 1.'));
      }
      if (
        existing.value.state === 'retry_wait' &&
        command.executionAttempt !== existing.value.executionAttempt + 1
      ) {
        return err(
          intelligenceValidationError('Retry fetch attempt must increment the previous attempt.'),
        );
      }
      return commit({
        ...existing.value,
        state: 'fetching',
        stage: 'fetch',
        startedAt: command.startedAt,
        completedAt: null,
        nextAttemptAt: null,
        executionAttempt: command.executionAttempt,
        failureCategory: null,
        failureCode: null,
      });
    }
    case 'record_retry_wait': {
      const existing = requireCurrent(current);
      if (!existing.ok) {
        return existing;
      }
      if (existing.value.state !== 'fetching') {
        return err(INTELLIGENCE_INVALID_TRANSITION);
      }
      const classification = classifyIntelligenceSafeFailure(command.failureCode);
      if (!classification.retryable || classification.disposition !== 'failed') {
        return err(
          intelligenceValidationError(
            'retry_wait requires a retryable failed-disposition safe code.',
          ),
        );
      }
      return commit({
        ...existing.value,
        state: 'retry_wait',
        stage: 'fetch',
        nextAttemptAt: command.nextAttemptAt,
        completedAt: null,
        failureCategory: classification.category,
        failureCode: command.failureCode,
      });
    }
    case 'record_stored': {
      const existing = requireCurrent(current);
      if (!existing.ok) {
        return existing;
      }
      if (existing.value.state !== 'fetching') {
        return err(INTELLIGENCE_INVALID_TRANSITION);
      }
      if (command.snapshotId.length === 0) {
        return err(intelligenceValidationError('stored runs require a snapshotId.'));
      }
      return commit({
        ...existing.value,
        state: 'stored',
        stage: 'store_snapshot',
        snapshotId: command.snapshotId,
        completedAt: null,
        nextAttemptAt: null,
        failureCategory: null,
        failureCode: null,
      });
    }
    case 'start_parsing': {
      const existing = requireCurrent(current);
      if (!existing.ok) {
        return existing;
      }
      if (existing.value.state !== 'stored' || existing.value.snapshotId === null) {
        return err(intelligenceValidationError('parsing requires a stored snapshotId.'));
      }
      return commit({
        ...existing.value,
        state: 'parsing',
        stage: 'parse',
        completedAt: null,
      });
    }
    case 'start_staging': {
      const existing = requireCurrent(current);
      if (!existing.ok) {
        return existing;
      }
      if (existing.value.state !== 'parsing' || existing.value.snapshotId === null) {
        return err(intelligenceValidationError('staging requires parsing with a snapshotId.'));
      }
      if (command.generationId.length === 0) {
        return err(intelligenceValidationError('staging requires a generationId.'));
      }
      return commit({
        ...existing.value,
        state: 'staging',
        stage: 'stage_generation',
        generationId: command.generationId,
        completedAt: null,
      });
    }
    case 'start_activating': {
      const existing = requireCurrent(current);
      if (!existing.ok) {
        return existing;
      }
      if (
        existing.value.state !== 'staging' ||
        existing.value.snapshotId === null ||
        existing.value.generationId === null
      ) {
        return err(intelligenceValidationError('activating requires snapshotId and generationId.'));
      }
      if (command.generationComplete !== true) {
        return err(intelligenceValidationError('activating requires a complete generation.'));
      }
      return commit({
        ...existing.value,
        state: 'activating',
        stage: 'activate_generation',
        completedAt: null,
      });
    }
    case 'complete': {
      const existing = requireCurrent(current);
      if (!existing.ok) {
        return existing;
      }
      if (existing.value.state !== 'activating') {
        return err(INTELLIGENCE_INVALID_TRANSITION);
      }
      if (existing.value.snapshotId === null || existing.value.generationId === null) {
        return err(
          intelligenceValidationError('completed runs require snapshotId and generationId.'),
        );
      }
      if (!isNonNegativeSafeInteger(command.acceptedEntryCount)) {
        return err(
          intelligenceValidationError('completed runs require non-negative safe final counts.'),
        );
      }
      return commit({
        ...existing.value,
        state: 'completed',
        stage: 'finalize',
        completedAt: command.completedAt,
        acceptedEntryCount: command.acceptedEntryCount,
        failureCategory: null,
        failureCode: null,
        nextAttemptAt: null,
      });
    }
    case 'complete_not_modified': {
      const existing = requireCurrent(current);
      if (!existing.ok) {
        return existing;
      }
      if (existing.value.state !== 'fetching') {
        return err(INTELLIGENCE_INVALID_TRANSITION);
      }
      if (existing.value.snapshotId !== null || existing.value.generationId !== null) {
        return err(
          intelligenceValidationError(
            'not_modified runs must not create a new snapshot or generation.',
          ),
        );
      }
      if (command.priorAcceptedGenerationId.length === 0) {
        return err(
          intelligenceValidationError('not_modified requires a prior accepted generation.'),
        );
      }
      return commit({
        ...existing.value,
        state: 'not_modified',
        stage: 'finalize',
        completedAt: command.completedAt,
        priorAcceptedGenerationId: command.priorAcceptedGenerationId,
        notModifiedReason: command.reason,
        snapshotId: null,
        generationId: null,
        failureCategory: null,
        failureCode: null,
        nextAttemptAt: null,
      });
    }
    case 'fail': {
      const existing = requireCurrent(current);
      if (!existing.ok) {
        return existing;
      }
      if (!failableStates.includes(existing.value.state as (typeof failableStates)[number])) {
        return err(INTELLIGENCE_INVALID_TRANSITION);
      }
      const classification = classifyIntelligenceSafeFailure(command.failureCode);
      if (classification.disposition !== 'failed') {
        return err(
          intelligenceValidationError('failed terminal state requires a failed-disposition code.'),
        );
      }
      return commit({
        ...existing.value,
        state: 'failed',
        stage: existing.value.stage,
        completedAt: command.completedAt,
        failureCategory: classification.category,
        failureCode: command.failureCode,
        nextAttemptAt: null,
      });
    }
    case 'quarantine': {
      const existing = requireCurrent(current);
      if (!existing.ok) {
        return existing;
      }
      if (
        !quarantinableStates.includes(existing.value.state as (typeof quarantinableStates)[number])
      ) {
        return err(INTELLIGENCE_INVALID_TRANSITION);
      }
      const classification = classifyIntelligenceSafeFailure(command.failureCode);
      if (classification.disposition !== 'quarantined') {
        return err(
          intelligenceValidationError(
            'quarantined terminal state requires a quarantine-disposition code.',
          ),
        );
      }
      if (!isIntelligenceQuarantineCategory(classification.category)) {
        return err(
          intelligenceValidationError(
            'quarantined runs require a content, integrity, schema, structural, parser, or catalog-regression category.',
          ),
        );
      }
      /**
       * fetching → quarantined is permitted only when no snapshot was stored.
       * That keeps evidence semantics truthful: we do not claim a retained
       * snapshot that was never persisted. Content-type, empty-body, UTF-8,
       * and oversize failures can be known before storage.
       */
      if (existing.value.state === 'fetching' && existing.value.snapshotId !== null) {
        return err(
          intelligenceValidationError(
            'fetching to quarantined is truthful only when no snapshotId has been assigned.',
          ),
        );
      }
      return commit({
        ...existing.value,
        state: 'quarantined',
        stage: existing.value.stage,
        completedAt: command.completedAt,
        failureCategory: classification.category,
        failureCode: command.failureCode,
        nextAttemptAt: null,
      });
    }
    default:
      return assertNever(command);
  }
}

export function assertSyncRunStateInvariants(snapshot: IntelligenceSyncRunSnapshot): Result<void> {
  switch (snapshot.state) {
    case 'requested':
      return assertRequestedInvariants(snapshot);
    case 'fetching':
      if (
        snapshot.startedAt === null ||
        snapshot.stage !== 'fetch' ||
        !isPositiveSafeInteger(snapshot.executionAttempt)
      ) {
        return err(
          intelligenceValidationError(
            'fetching requires startedAt, stage fetch, and a positive attempt.',
          ),
        );
      }
      return ok(undefined);
    case 'retry_wait': {
      if (
        snapshot.nextAttemptAt === null ||
        snapshot.completedAt !== null ||
        snapshot.startedAt === null ||
        snapshot.failureCategory === null ||
        snapshot.failureCode === null ||
        !isPositiveSafeInteger(snapshot.executionAttempt)
      ) {
        return err(
          intelligenceValidationError(
            'retry_wait requires nextAttemptAt, a positive attempt, and a retryable safe failure.',
          ),
        );
      }
      const classification = classifyIntelligenceSafeFailure(snapshot.failureCode);
      if (
        !classification.retryable ||
        classification.disposition !== 'failed' ||
        classification.category !== snapshot.failureCategory
      ) {
        return err(
          intelligenceValidationError(
            'retry_wait requires a retryable failed-disposition safe code.',
          ),
        );
      }
      return ok(undefined);
    }
    case 'stored':
      if (snapshot.snapshotId === null || snapshot.completedAt !== null) {
        return err(
          intelligenceValidationError('stored requires snapshotId and a null completedAt.'),
        );
      }
      return ok(undefined);
    case 'parsing':
      if (snapshot.snapshotId === null) {
        return err(intelligenceValidationError('parsing requires snapshotId.'));
      }
      return ok(undefined);
    case 'staging':
      if (snapshot.snapshotId === null || snapshot.generationId === null) {
        return err(intelligenceValidationError('staging requires snapshotId and generationId.'));
      }
      return ok(undefined);
    case 'activating':
      if (snapshot.snapshotId === null || snapshot.generationId === null) {
        return err(intelligenceValidationError('activating requires snapshotId and generationId.'));
      }
      return ok(undefined);
    case 'completed':
      if (
        snapshot.snapshotId === null ||
        snapshot.generationId === null ||
        snapshot.startedAt === null ||
        snapshot.completedAt === null ||
        snapshot.acceptedEntryCount === null ||
        snapshot.failureCategory !== null ||
        snapshot.failureCode !== null
      ) {
        return err(
          intelligenceValidationError(
            'completed requires snapshot, generation, counts, and timestamps.',
          ),
        );
      }
      return ok(undefined);
    case 'not_modified':
      if (
        snapshot.startedAt === null ||
        snapshot.completedAt === null ||
        snapshot.priorAcceptedGenerationId === null ||
        snapshot.snapshotId !== null ||
        snapshot.generationId !== null ||
        snapshot.notModifiedReason === null
      ) {
        return err(
          intelligenceValidationError(
            'not_modified requires a prior generation, timestamps, and no new snapshot or generation.',
          ),
        );
      }
      return ok(undefined);
    case 'failed':
      if (
        snapshot.completedAt === null ||
        snapshot.failureCategory === null ||
        snapshot.failureCode === null
      ) {
        return err(
          intelligenceValidationError('failed requires completedAt and a safe failure code.'),
        );
      }
      return ok(undefined);
    case 'quarantined':
      if (
        snapshot.completedAt === null ||
        snapshot.failureCategory === null ||
        snapshot.failureCode === null
      ) {
        return err(
          intelligenceValidationError(
            'quarantined requires completedAt and a safe quarantine code.',
          ),
        );
      }
      return ok(undefined);
    default:
      return assertNever(snapshot.state);
  }
}
