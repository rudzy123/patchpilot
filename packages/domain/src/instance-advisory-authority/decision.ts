/**
 * Future grant, revocation, replay, and user-status decisions.
 * These functions classify a described PostgreSQL snapshot. They do not write.
 * Revoke matches one expected grant. A later replacement is not that grant.
 */

import type { UserStatus } from '../lifecycle.js';
import {
  INSTANCE_ADVISORY_AUTHORITY_COMMAND_SCHEMA_VERSION,
  type InstanceAdvisoryAuthorityCommand,
  type InstanceAdvisoryAuthorityCommandOutcome,
} from './command.js';
import { isCanonicalLowercaseUuid } from './identity.js';
import { isHostileProxy } from './plain.js';
import {
  isInstanceAdvisoryAuthority,
  isInstanceAdvisoryIssuanceClassification,
  type InstanceAdvisoryAuthority,
  type InstanceAdvisoryIssuanceClassification,
} from './policy.js';

export const INSTANCE_ADVISORY_AUTHORITY_SNAPSHOT_SCHEMA_VERSION =
  'instance_advisory_authority_snapshot_v1' as const;

export const INSTANCE_ADVISORY_REGRANT_CONTRACT = {
  requiresNoActiveGrant: true,
  insertsNewGrantId: true,
  assignsNewIssuedAtFromDatabaseClock: true,
  priorRevokedGrantUnchanged: true,
  inPlaceReactivation: false,
  auditEvents: 1,
  preservesActiveGrantUniqueness: true,
  sameAuthorityPermittedAfterRevocation: true,
  otherAuthorityPermittedAfterRevocation: true,
} as const;

export const INSTANCE_ADVISORY_REVOCATION_CONTRACT = {
  revokesExactlyTheExpectedActiveGrant: true,
  revokesADifferentActiveGrant: false,
  revokedAtSource: 'database_clock',
  auditEvents: 1,
  historyPreserved: true,
  deletesGrant: false,
  rewritesSubmittedRevisions: false,
  rewritesApprovals: false,
  invalidatesCommittedApproval: false,
  disablesTenantAccess: false,
} as const;

/**
 * Exact revoke replay is the named grant already revoked, with no active grant.
 * History of some other grant is not that replay. A replacement that is still
 * active is expected_grant_mismatch and is not revoked by the old command.
 */
export const INSTANCE_ADVISORY_REVOCATION_REPLAY = {
  alreadyRevokedOutcome: 'already_applied',
  noGrantRowOutcome: 'grant_absent',
  noGrantRowIsAlreadyApplied: false,
  noActiveGrantIsAlreadyApplied: false,
  expectedGrantIdOnCommand: true,
  expectedAuthorityOnCommand: true,
  callerMintedGrantIdOnCommand: false,
  expectedGrantMismatchOutcome: 'expected_grant_mismatch',
  activeAuthorityMismatchOutcome: 'active_authority_mismatch',
  namedHistoricalAuthorityDisagreementOutcome: 'active_authority_mismatch',
  replacementActiveGrantIsReplay: false,
  replacementActiveGrantIsImplicitlyRevoked: false,
  proofOfPriorRevocation: 'expected_grant_is_revoked_and_no_active_grant',
  correlationDefinesReplay: false,
  secondAuditEvent: false,
  retryRequiresExpectedGrantIdFromEarlierResult: true,
  blindRevokeOfWhateverIsActive: false,
  rereadsAfterFailedRevocationUpdate: 1,
  stillActiveAfterFailedUpdateOutcome: 'concurrency_conflict',
  unboundedRetryLoop: false,
} as const;

export const INSTANCE_ADVISORY_CONCURRENT_GRANT_CONTRACT = {
  newGrants: 1,
  grantAuditEvents: 1,
  grantedResults: 1,
  alreadyAppliedResults: 1,
  unboundedRetryLoop: false,
  unexpectedUniquenessIsAutomaticReplay: false,
  unexpectedUniquenessOutcome: 'concurrency_conflict',
  rereadsAfterActiveGrantUniquenessFailure: 1,
} as const;

export const INSTANCE_ADVISORY_DISABLEMENT_CONTRACT = {
  preventsSuccessfulAuthentication: true,
  preventsActiveAdvisoryActorResolution: true,
  preventsExerciseOfActiveGrant: true,
  retainsAuditAndGrantHistoryReferences: true,
  retainsHistoricalSubmissions: true,
  retainsHistoricalApprovals: true,
  activeGrantRowMayRemain: true,
  authorityUseFailsBecauseUserInactive: true,
  automaticGrantRevocation: false,
  reenablementRestoresAuthorityOnlyIfActiveGrantWasNotRevoked: true,
  alreadyDisabledOutcome: 'already_applied',
  missingUserOutcome: 'user_absent',
  secondAuditEventOnReplay: false,
} as const;

export const INSTANCE_ADVISORY_REENABLEMENT_CONTRACT = {
  appliesOnlyToExistingDisabledUser: true,
  restoresAuthenticationEligibility: true,
  createsAdvisoryGrant: false,
  reactivatesRevokedGrant: false,
  createsMembership: false,
  changesPassword: false,
  bypassesCurrentCredentialRequirements: false,
  alreadyActiveOutcome: 'already_applied',
  isAuthorityGrant: false,
  missingUserOutcome: 'user_absent',
} as const;

export const INSTANCE_ADVISORY_GRANT_LIFECYCLE_MUTATIONS = [
  'insert_new_grant',
  'revoke_active_grant',
  'reactivate_revoked_grant',
  'delete_grant',
  'rewrite_immutable_fields',
] as const;

export type InstanceAdvisoryGrantLifecycleMutation =
  (typeof INSTANCE_ADVISORY_GRANT_LIFECYCLE_MUTATIONS)[number];

export type InstanceAdvisoryGrantLifecycleMutationResult =
  'insert_new_grant' | 'revoke_active_grant' | 'immutable_conflict';

export type InstanceAdvisoryActiveGrantFact = {
  readonly grantId: string;
  readonly userId: string;
  readonly authority: InstanceAdvisoryAuthority;
  readonly issuanceClassification: InstanceAdvisoryIssuanceClassification;
  readonly lifecycle: 'active';
};

export type InstanceAdvisoryRevokedGrantFact = {
  readonly grantId: string;
  readonly userId: string;
  readonly authority: InstanceAdvisoryAuthority;
  readonly issuanceClassification: InstanceAdvisoryIssuanceClassification;
  readonly lifecycle: 'revoked';
};

export type InstanceAdvisoryAuthoritySnapshot = {
  readonly schemaVersion: typeof INSTANCE_ADVISORY_AUTHORITY_SNAPSHOT_SCHEMA_VERSION;
  readonly user:
    | { readonly existence: 'absent' }
    | { readonly existence: 'present'; readonly status: UserStatus };
  readonly activeGrant: InstanceAdvisoryActiveGrantFact | null;
  readonly revokedGrants: readonly InstanceAdvisoryRevokedGrantFact[];
  readonly malformed: boolean;
};

export type InstanceAdvisoryCommandWrite =
  | { readonly kind: 'none' }
  | {
      readonly kind: 'insert_grant';
      readonly grantIdSource: 'database';
      readonly issuedAtSource: 'database_clock';
    }
  | {
      readonly kind: 'revoke_active_grant';
      readonly revokedAtSource: 'database_clock';
      readonly target: 'expected_active_grant';
    }
  | { readonly kind: 'disable_user'; readonly revokesActiveGrant: false }
  | {
      readonly kind: 'enable_user';
      readonly insertsGrant: false;
      readonly reactivatesRevokedGrant: false;
    };

export type InstanceAdvisoryCommandDecision = {
  readonly outcome: InstanceAdvisoryAuthorityCommandOutcome;
  readonly write: InstanceAdvisoryCommandWrite;
  readonly auditEvents: 0 | 1;
  readonly deletesGrant: false;
  readonly reactivatesGrant: false;
  readonly changesIssuedAt: false;
  readonly correlationDefinesReplay: false;
};

export function classifyInstanceAdvisoryGrantLifecycleMutation(
  mutation: string,
): InstanceAdvisoryGrantLifecycleMutationResult {
  if (mutation === 'insert_new_grant') {
    return 'insert_new_grant';
  }
  if (mutation === 'revoke_active_grant') {
    return 'revoke_active_grant';
  }
  return 'immutable_conflict';
}

export function classifyInstanceAdvisoryAuthorityCommand(
  command: InstanceAdvisoryAuthorityCommand,
  snapshot: InstanceAdvisoryAuthoritySnapshot,
): InstanceAdvisoryCommandDecision {
  if (!commandIsClosed(command)) {
    return none('invalid_command');
  }
  if (!snapshotIsTrusted(snapshot, command.targetUserId)) {
    return none('malformed_persisted_state');
  }
  if (snapshot.user.existence === 'absent') {
    return none('user_absent');
  }
  const status = snapshot.user.status;
  switch (command.operation) {
    case 'grant':
      return classifyGrant(command.authority, command.issuanceClassification, status, snapshot);
    case 'revoke':
      return classifyRevoke(command, snapshot);
    case 'disable_user':
      return classifyDisable(status);
    case 'enable_user':
      return classifyEnable(status);
    default:
      return finishUnexpected(command);
  }
}

/**
 * One reread after the active-grant uniqueness failure. This is not a retry loop.
 * A matching committed grant is already_applied. Any other uniqueness failure
 * is concurrency_conflict and is not replay.
 */
export function classifyInstanceAdvisoryConcurrentGrantReread(
  command: Extract<InstanceAdvisoryAuthorityCommand, { readonly operation: 'grant' }>,
  reread: InstanceAdvisoryAuthoritySnapshot,
): InstanceAdvisoryCommandDecision {
  if (!commandIsClosed(command) || !snapshotIsTrusted(reread, command.targetUserId)) {
    return none('malformed_persisted_state');
  }
  if (reread.user.existence === 'absent') {
    return none('malformed_persisted_state');
  }
  const activeGrant = reread.activeGrant;
  if (activeGrant === null) {
    return none('concurrency_conflict');
  }
  if (
    activeGrant.authority === command.authority &&
    activeGrant.issuanceClassification === command.issuanceClassification
  ) {
    return none('already_applied');
  }
  return none('active_grant_conflict');
}

/**
 * One reread after a revocation update matches nothing. This is not a retry loop.
 * A still-active expected grant is concurrency_conflict. A different active grant
 * is not revoked from this reread.
 */
export function classifyInstanceAdvisoryConcurrentRevocationReread(
  command: Extract<InstanceAdvisoryAuthorityCommand, { readonly operation: 'revoke' }>,
  reread: InstanceAdvisoryAuthoritySnapshot,
): InstanceAdvisoryCommandDecision {
  const decision = classifyInstanceAdvisoryAuthorityCommand(command, reread);
  if (decision.outcome === 'user_absent') {
    return none('malformed_persisted_state');
  }
  if (decision.write.kind !== 'none') {
    return none('concurrency_conflict');
  }
  return decision;
}

function classifyGrant(
  authority: InstanceAdvisoryAuthority,
  issuanceClassification: InstanceAdvisoryIssuanceClassification,
  status: UserStatus,
  snapshot: InstanceAdvisoryAuthoritySnapshot,
): InstanceAdvisoryCommandDecision {
  const activeGrant = snapshot.activeGrant;
  // Stored grant identity decides replay and conflict before account status.
  // A disabled user with no active grant cannot receive a new grant.
  if (activeGrant !== null) {
    if (
      activeGrant.authority === authority &&
      activeGrant.issuanceClassification === issuanceClassification
    ) {
      return none('already_applied');
    }
    return none('active_grant_conflict');
  }
  if (status === 'disabled') {
    return none('user_inactive');
  }
  if (status !== 'active') {
    return finishUnexpected(status);
  }
  return {
    outcome: 'granted',
    write: {
      kind: 'insert_grant',
      grantIdSource: 'database',
      issuedAtSource: 'database_clock',
    },
    auditEvents: 1,
    deletesGrant: false,
    reactivatesGrant: false,
    changesIssuedAt: false,
    correlationDefinesReplay: false,
  };
}

function classifyRevoke(
  command: Extract<InstanceAdvisoryAuthorityCommand, { readonly operation: 'revoke' }>,
  snapshot: InstanceAdvisoryAuthoritySnapshot,
): InstanceAdvisoryCommandDecision {
  const activeGrant = snapshot.activeGrant;
  const named = snapshot.revokedGrants.find((grant) => grant.grantId === command.expectedGrantId);
  if (activeGrant !== null && activeGrant.grantId === command.expectedGrantId) {
    if (activeGrant.authority !== command.expectedAuthority) {
      return none('active_authority_mismatch');
    }
    return {
      outcome: 'revoked',
      write: {
        kind: 'revoke_active_grant',
        revokedAtSource: 'database_clock',
        target: 'expected_active_grant',
      },
      auditEvents: 1,
      deletesGrant: false,
      reactivatesGrant: false,
      changesIssuedAt: false,
      correlationDefinesReplay: false,
    };
  }
  if (activeGrant !== null) {
    return none('expected_grant_mismatch');
  }
  if (named === undefined) {
    if (snapshot.revokedGrants.length === 0) {
      return none('grant_absent');
    }
    return none('expected_grant_mismatch');
  }
  if (named.authority !== command.expectedAuthority) {
    return none('active_authority_mismatch');
  }
  return none('already_applied');
}

function classifyDisable(status: UserStatus): InstanceAdvisoryCommandDecision {
  if (status === 'disabled') {
    return none('already_applied');
  }
  if (status !== 'active') {
    return finishUnexpected(status);
  }
  return {
    outcome: 'user_disabled',
    write: { kind: 'disable_user', revokesActiveGrant: false },
    auditEvents: 1,
    deletesGrant: false,
    reactivatesGrant: false,
    changesIssuedAt: false,
    correlationDefinesReplay: false,
  };
}

function classifyEnable(status: UserStatus): InstanceAdvisoryCommandDecision {
  if (status === 'active') {
    return none('already_applied');
  }
  if (status !== 'disabled') {
    return finishUnexpected(status);
  }
  return {
    outcome: 'user_enabled',
    write: { kind: 'enable_user', insertsGrant: false, reactivatesRevokedGrant: false },
    auditEvents: 1,
    deletesGrant: false,
    reactivatesGrant: false,
    changesIssuedAt: false,
    correlationDefinesReplay: false,
  };
}

function commandIsClosed(command: InstanceAdvisoryAuthorityCommand): boolean {
  if (
    command.schemaVersion !== INSTANCE_ADVISORY_AUTHORITY_COMMAND_SCHEMA_VERSION ||
    !isCanonicalLowercaseUuid(command.targetUserId) ||
    !isCanonicalLowercaseUuid(command.correlationId)
  ) {
    return false;
  }
  if (command.operation === 'grant') {
    return (
      isInstanceAdvisoryAuthority(command.authority) &&
      isInstanceAdvisoryIssuanceClassification(command.issuanceClassification)
    );
  }
  if (command.operation === 'revoke') {
    return (
      isCanonicalLowercaseUuid(command.expectedGrantId) &&
      isInstanceAdvisoryAuthority(command.expectedAuthority)
    );
  }
  return command.operation === 'disable_user' || command.operation === 'enable_user';
}

function snapshotIsTrusted(
  snapshot: InstanceAdvisoryAuthoritySnapshot,
  targetUserId: string,
): boolean {
  if (snapshot.schemaVersion !== INSTANCE_ADVISORY_AUTHORITY_SNAPSHOT_SCHEMA_VERSION) {
    return false;
  }
  if (snapshot.malformed || isHostileProxy(snapshot)) {
    return false;
  }
  if (snapshot.user.existence === 'present') {
    if (snapshot.user.status !== 'active' && snapshot.user.status !== 'disabled') {
      return false;
    }
  } else if (snapshot.user.existence !== 'absent') {
    return false;
  }
  const activeGrant = snapshot.activeGrant;
  if (activeGrant !== null) {
    if (snapshot.user.existence === 'absent' || isHostileProxy(activeGrant)) {
      return false;
    }
    if (activeGrant.lifecycle !== 'active') {
      return false;
    }
    if (!grantIdentityIsTrusted(activeGrant, targetUserId)) {
      return false;
    }
  }
  return revokedHistoryIsTrusted(
    snapshot.revokedGrants,
    targetUserId,
    activeGrant === null ? null : activeGrant.grantId,
  );
}

function revokedHistoryIsTrusted(
  grants: readonly InstanceAdvisoryRevokedGrantFact[],
  targetUserId: string,
  activeGrantId: string | null,
): boolean {
  if (!Array.isArray(grants) || isHostileProxy(grants)) {
    return false;
  }
  const seen = new Set<string>();
  for (const grant of grants) {
    if (grant === null || typeof grant !== 'object' || isHostileProxy(grant)) {
      return false;
    }
    if (grant.lifecycle !== 'revoked' || !grantIdentityIsTrusted(grant, targetUserId)) {
      return false;
    }
    if (seen.has(grant.grantId) || grant.grantId === activeGrantId) {
      return false;
    }
    seen.add(grant.grantId);
  }
  return true;
}

function grantIdentityIsTrusted(
  grant: {
    readonly grantId: string;
    readonly userId: string;
    readonly authority: InstanceAdvisoryAuthority;
    readonly issuanceClassification: InstanceAdvisoryIssuanceClassification;
  },
  targetUserId: string,
): boolean {
  return (
    isCanonicalLowercaseUuid(grant.grantId) &&
    isCanonicalLowercaseUuid(grant.userId) &&
    grant.userId === targetUserId &&
    isInstanceAdvisoryAuthority(grant.authority) &&
    isInstanceAdvisoryIssuanceClassification(grant.issuanceClassification)
  );
}

function none(outcome: InstanceAdvisoryAuthorityCommandOutcome): InstanceAdvisoryCommandDecision {
  return {
    outcome,
    write: { kind: 'none' },
    auditEvents: 0,
    deletesGrant: false,
    reactivatesGrant: false,
    changesIssuedAt: false,
    correlationDefinesReplay: false,
  };
}

function finishUnexpected(_operation: never): InstanceAdvisoryCommandDecision {
  return none('internal_failure');
}
