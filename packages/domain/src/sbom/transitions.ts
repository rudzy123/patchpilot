import type {
  GraphCompleteness,
  SbomIngestionStage,
  SbomIngestionState,
  Session8IngestionStage,
} from '../lifecycle.js';
import {
  session8IngestionStages,
  session8IngestionTerminalStates,
  session8UnusedIngestionStages,
} from '../lifecycle.js';
import { assertNever, err, ok, type Result } from '../result.js';
import {
  SBOM_COMPLETED_REQUIREMENTS,
  SBOM_DUPLICATE_STATE_FORBIDDEN,
  SBOM_INVALID_TRANSITION,
  SBOM_PROCESSING_REQUIRES_STARTED_AT,
  SBOM_TERMINAL_STATE,
  SBOM_UNSUPPORTED_STAGE,
  sbomValidationError,
} from './errors.js';
import { classifySafeFailure, type SafeFailureCategory, type SafeFailureCode } from './failures.js';
import { graphCompletenessMatchesCounts } from './graph-completeness.js';

export type Session8IngestionSnapshot = {
  state: SbomIngestionState;
  stage: SbomIngestionStage | null;
  startedAt: Date | null;
  completedAt: Date | null;
  graphCompleteness: GraphCompleteness | null;
  componentCount: number | null;
  dependencyEdgeCount: number | null;
  warningCount: number | null;
  failureCategory: SafeFailureCategory | null;
  failureCode: SafeFailureCode | null;
};

export type CreateAcceptedCommand = {
  type: 'create_accepted';
};

export type QueueCommand = {
  type: 'queue';
};

export type StartProcessingCommand = {
  type: 'start_processing';
  startedAt: Date;
  stage: Session8IngestionStage;
};

export type ReleaseForRetryCommand = {
  type: 'release_for_retry';
  failureCode: SafeFailureCode;
};

export type CompleteCommand = {
  type: 'complete';
  completedAt: Date;
  graphCompleteness: GraphCompleteness;
  componentCount: number;
  dependencyEdgeCount: number;
  warningCount: number;
};

export type RejectCommand = {
  type: 'reject';
  completedAt: Date;
  failureCode: SafeFailureCode;
};

export type QuarantineCommand = {
  type: 'quarantine';
  completedAt: Date;
  failureCode: SafeFailureCode;
};

export type FailCommand = {
  type: 'fail';
  completedAt: Date;
  failureCode: SafeFailureCode;
};

export type Session8IngestionCommand =
  | CreateAcceptedCommand
  | QueueCommand
  | StartProcessingCommand
  | ReleaseForRetryCommand
  | CompleteCommand
  | RejectCommand
  | QuarantineCommand
  | FailCommand;

const emptyProgress = {
  startedAt: null,
  completedAt: null,
  graphCompleteness: null,
  componentCount: null,
  dependencyEdgeCount: null,
  warningCount: null,
  failureCategory: null,
  failureCode: null,
} as const;

export function isSession8IngestionStage(
  stage: SbomIngestionStage,
): stage is Session8IngestionStage {
  return (session8IngestionStages as readonly string[]).includes(stage);
}

export function isSession8UnusedIngestionStage(stage: SbomIngestionStage): boolean {
  return (session8UnusedIngestionStages as readonly string[]).includes(stage);
}

export function isSession8TerminalState(state: SbomIngestionState): boolean {
  return (session8IngestionTerminalStates as readonly string[]).includes(state);
}

function rejectUnsupportedStage(stage: SbomIngestionStage | null): Result<void> {
  if (stage !== null && isSession8UnusedIngestionStage(stage)) {
    return err(SBOM_UNSUPPORTED_STAGE);
  }
  return ok(undefined);
}

function requireCurrent(
  current: Session8IngestionSnapshot | undefined,
): Result<Session8IngestionSnapshot> {
  if (current === undefined) {
    return err(SBOM_INVALID_TRANSITION);
  }
  if (current.state === 'duplicate') {
    return err(SBOM_DUPLICATE_STATE_FORBIDDEN);
  }
  if (isSession8TerminalState(current.state)) {
    return err(SBOM_TERMINAL_STATE);
  }
  const stageCheck = rejectUnsupportedStage(current.stage);
  if (!stageCheck.ok) {
    return stageCheck;
  }
  return ok(current);
}

function requireProcessing(current: Session8IngestionSnapshot): Result<Session8IngestionSnapshot> {
  if (current.state !== 'processing') {
    return err(SBOM_INVALID_TRANSITION);
  }
  if (current.startedAt === null) {
    return err(SBOM_PROCESSING_REQUIRES_STARTED_AT);
  }
  return ok(current);
}

function countsAreValid(command: CompleteCommand): boolean {
  return (
    Number.isInteger(command.componentCount) &&
    command.componentCount >= 0 &&
    Number.isInteger(command.dependencyEdgeCount) &&
    command.dependencyEdgeCount >= 0 &&
    Number.isInteger(command.warningCount) &&
    command.warningCount >= 0 &&
    graphCompletenessMatchesCounts(command.graphCompleteness, command)
  );
}

function acceptedSnapshot(): Session8IngestionSnapshot {
  return {
    state: 'accepted',
    stage: null,
    ...emptyProgress,
  };
}

export function applySession8IngestionTransition(
  current: Session8IngestionSnapshot | undefined,
  command: Session8IngestionCommand,
): Result<Session8IngestionSnapshot> {
  switch (command.type) {
    case 'create_accepted': {
      if (current !== undefined) {
        return err(SBOM_INVALID_TRANSITION);
      }
      return ok(acceptedSnapshot());
    }
    case 'queue': {
      const existing = requireCurrent(current);
      if (!existing.ok) {
        return existing;
      }
      if (existing.value.state !== 'accepted') {
        return err(SBOM_INVALID_TRANSITION);
      }
      return ok({
        ...existing.value,
        state: 'queued',
      });
    }
    case 'start_processing': {
      const existing = requireCurrent(current);
      if (!existing.ok) {
        return existing;
      }
      if (existing.value.state !== 'accepted' && existing.value.state !== 'queued') {
        return err(SBOM_INVALID_TRANSITION);
      }
      if (!isSession8IngestionStage(command.stage)) {
        return err(SBOM_UNSUPPORTED_STAGE);
      }
      return ok({
        ...existing.value,
        state: 'processing',
        stage: command.stage,
        startedAt: command.startedAt,
        completedAt: null,
      });
    }
    case 'release_for_retry': {
      const existing = requireCurrent(current);
      if (!existing.ok) {
        return existing;
      }
      const processing = requireProcessing(existing.value);
      if (!processing.ok) {
        return processing;
      }
      if (classifySafeFailure(command.failureCode).outcome !== 'retryable_infrastructure') {
        return err(
          sbomValidationError(
            'Retryable release requires a retryable infrastructure failure code.',
          ),
        );
      }
      return ok({
        ...processing.value,
        state: 'queued',
        startedAt: null,
        failureCategory: null,
        failureCode: null,
      });
    }
    case 'complete': {
      const existing = requireCurrent(current);
      if (!existing.ok) {
        return existing;
      }
      const processing = requireProcessing(existing.value);
      if (!processing.ok) {
        return processing;
      }
      if (
        command.graphCompleteness === undefined ||
        command.componentCount === undefined ||
        command.dependencyEdgeCount === undefined ||
        command.warningCount === undefined ||
        !countsAreValid(command)
      ) {
        return err(SBOM_COMPLETED_REQUIREMENTS);
      }
      return ok({
        ...processing.value,
        state: 'completed',
        stage: 'persist_graph',
        completedAt: command.completedAt,
        graphCompleteness: command.graphCompleteness,
        componentCount: command.componentCount,
        dependencyEdgeCount: command.dependencyEdgeCount,
        warningCount: command.warningCount,
        failureCategory: null,
        failureCode: null,
      });
    }
    case 'reject':
    case 'quarantine':
    case 'fail': {
      const existing = requireCurrent(current);
      if (!existing.ok) {
        return existing;
      }
      const processing = requireProcessing(existing.value);
      if (!processing.ok) {
        return processing;
      }
      const classification = classifySafeFailure(command.failureCode);
      const expectedOutcome =
        command.type === 'reject'
          ? 'rejected'
          : command.type === 'quarantine'
            ? 'quarantined'
            : 'terminal_internal';
      if (classification.outcome !== expectedOutcome) {
        return err(
          sbomValidationError('Failure code does not match the requested terminal outcome.'),
        );
      }
      const state =
        command.type === 'reject'
          ? 'rejected'
          : command.type === 'quarantine'
            ? 'quarantined'
            : 'failed';
      return ok({
        ...processing.value,
        state,
        completedAt: command.completedAt,
        failureCategory: classification.category,
        failureCode: command.failureCode,
      });
    }
    default:
      return assertNever(command);
  }
}
