/**
 * Narrow application boundary for the deployment-local command.
 * Replay, conflict, and audit insertion stay inside the persistence port.
 * This module does not open a database or write an audit event.
 */

import { assertNever } from '../result.js';
import type {
  InstanceAdvisoryAuthorityCommand,
  InstanceAdvisoryAuthorityCommandOutcome,
  InstanceAdvisoryAuthorityCommandResult,
  InstanceAdvisoryAuthorityOperation,
} from './command.js';
import type { InstanceAdvisoryAuthorityCommandPort } from './persistence.js';
import type { InstanceAdvisoryAuthority } from './policy.js';

export const INSTANCE_ADVISORY_AUTHORITY_COMMAND_RESULT_SCHEMA_VERSION =
  'instance_advisory_authority_command_result_v1' as const;

export const INSTANCE_ADVISORY_AUTHORITY_COMMAND_EXIT = {
  mutation: 0,
  internalFailure: 1,
  alreadyApplied: 2,
  invalidCommand: 3,
  notFound: 4,
  conflict: 5,
  rejected: 6,
  databaseUnavailable: 7,
  help: 0,
} as const;

export const INSTANCE_ADVISORY_AUTHORITY_COMMAND_ACKNOWLEDGEMENTS = [
  'committed',
  'replayed',
  'unchanged',
  'uncertain',
] as const;

export type InstanceAdvisoryAuthorityCommandAcknowledgement =
  (typeof INSTANCE_ADVISORY_AUTHORITY_COMMAND_ACKNOWLEDGEMENTS)[number];

export type InstanceAdvisoryAuthorityCommandPresentation = {
  readonly schemaVersion: typeof INSTANCE_ADVISORY_AUTHORITY_COMMAND_RESULT_SCHEMA_VERSION;
  readonly operation: InstanceAdvisoryAuthorityOperation | null;
  readonly outcome: InstanceAdvisoryAuthorityCommandOutcome;
  readonly targetUserId: string | null;
  readonly authority: InstanceAdvisoryAuthority | null;
  readonly grantId: string | null;
  readonly acknowledgement: InstanceAdvisoryAuthorityCommandAcknowledgement;
};

export function executeInstanceAdvisoryAuthorityDeploymentCommand(
  boundary: InstanceAdvisoryAuthorityCommandPort,
  command: InstanceAdvisoryAuthorityCommand,
): Promise<InstanceAdvisoryAuthorityCommandResult> {
  return boundary.execute(command);
}

export function presentInstanceAdvisoryAuthorityCommandResult(
  command: InstanceAdvisoryAuthorityCommand | null,
  result: InstanceAdvisoryAuthorityCommandResult,
): InstanceAdvisoryAuthorityCommandPresentation {
  return Object.freeze({
    schemaVersion: INSTANCE_ADVISORY_AUTHORITY_COMMAND_RESULT_SCHEMA_VERSION,
    operation: command?.operation ?? null,
    outcome: result.outcome,
    targetUserId: command?.targetUserId ?? null,
    authority: authorityOf(command),
    grantId: result.outcome === 'granted' || result.outcome === 'revoked' ? result.grantId : null,
    acknowledgement: instanceAdvisoryAuthorityCommandAcknowledgement(result.outcome),
  });
}

export function instanceAdvisoryAuthorityCommandAcknowledgement(
  outcome: InstanceAdvisoryAuthorityCommandOutcome,
): InstanceAdvisoryAuthorityCommandAcknowledgement {
  switch (outcome) {
    case 'granted':
    case 'revoked':
    case 'user_disabled':
    case 'user_enabled':
      return 'committed';
    case 'already_applied':
      return 'replayed';
    case 'database_unavailable':
    case 'transaction_aborted':
    case 'internal_failure':
      return 'uncertain';
    case 'invalid_command':
    case 'user_absent':
    case 'grant_absent':
    case 'user_inactive':
    case 'active_grant_conflict':
    case 'expected_grant_mismatch':
    case 'active_authority_mismatch':
    case 'authority_required':
    case 'immutable_conflict':
    case 'malformed_persisted_state':
    case 'concurrency_conflict':
      return 'unchanged';
    default:
      return assertNever(outcome);
  }
}

export function instanceAdvisoryAuthorityCommandExitCode(
  outcome: InstanceAdvisoryAuthorityCommandOutcome,
): number {
  switch (outcome) {
    case 'granted':
    case 'revoked':
    case 'user_disabled':
    case 'user_enabled':
      return INSTANCE_ADVISORY_AUTHORITY_COMMAND_EXIT.mutation;
    case 'already_applied':
      return INSTANCE_ADVISORY_AUTHORITY_COMMAND_EXIT.alreadyApplied;
    case 'invalid_command':
      return INSTANCE_ADVISORY_AUTHORITY_COMMAND_EXIT.invalidCommand;
    case 'user_absent':
    case 'grant_absent':
      return INSTANCE_ADVISORY_AUTHORITY_COMMAND_EXIT.notFound;
    case 'active_grant_conflict':
    case 'expected_grant_mismatch':
    case 'active_authority_mismatch':
    case 'immutable_conflict':
    case 'concurrency_conflict':
      return INSTANCE_ADVISORY_AUTHORITY_COMMAND_EXIT.conflict;
    case 'user_inactive':
    case 'authority_required':
      return INSTANCE_ADVISORY_AUTHORITY_COMMAND_EXIT.rejected;
    case 'database_unavailable':
      return INSTANCE_ADVISORY_AUTHORITY_COMMAND_EXIT.databaseUnavailable;
    case 'malformed_persisted_state':
    case 'transaction_aborted':
    case 'internal_failure':
      return INSTANCE_ADVISORY_AUTHORITY_COMMAND_EXIT.internalFailure;
    default:
      return assertNever(outcome);
  }
}

function authorityOf(
  command: InstanceAdvisoryAuthorityCommand | null,
): InstanceAdvisoryAuthority | null {
  if (command?.operation === 'grant') {
    return command.authority;
  }
  if (command?.operation === 'revoke') {
    return command.expectedAuthority;
  }
  return null;
}
