/**
 * Closed instance_advisory_authority_command_v1 parser.
 * The caller names one operation. The caller does not name tenant authority,
 * timestamps, a new grant id, secrets, or a transaction callback.
 * Revoke names the expected existing grant and its authority. That is a
 * precondition, not permission to mint a grant id.
 */

import { isCanonicalLowercaseUuid } from './identity.js';
import { closedRecord, isPlainObject, ownDataProperties, readOwnData } from './plain.js';
import {
  isInstanceAdvisoryAuthority,
  isInstanceAdvisoryIssuanceClassification,
  type InstanceAdvisoryAuthority,
  type InstanceAdvisoryIssuanceClassification,
} from './policy.js';

export const INSTANCE_ADVISORY_AUTHORITY_COMMAND_SCHEMA_VERSION =
  'instance_advisory_authority_command_v1' as const;

export const INSTANCE_ADVISORY_AUTHORITY_OPERATIONS = [
  'grant',
  'revoke',
  'disable_user',
  'enable_user',
] as const;

export type InstanceAdvisoryAuthorityOperation =
  (typeof INSTANCE_ADVISORY_AUTHORITY_OPERATIONS)[number];

export const INSTANCE_ADVISORY_AUTHORITY_COMMAND_OUTCOMES = [
  'granted',
  'revoked',
  'user_disabled',
  'user_enabled',
  'already_applied',
  'invalid_command',
  'user_absent',
  'grant_absent',
  'user_inactive',
  'active_grant_conflict',
  'expected_grant_mismatch',
  'active_authority_mismatch',
  'authority_required',
  'immutable_conflict',
  'malformed_persisted_state',
  'concurrency_conflict',
  'transaction_aborted',
  'database_unavailable',
  'internal_failure',
] as const;

export type InstanceAdvisoryAuthorityCommandOutcome =
  (typeof INSTANCE_ADVISORY_AUTHORITY_COMMAND_OUTCOMES)[number];

/**
 * user_absent is the ADR 0043 name for a missing user.
 * It is acceptable on this deployment-local system command because the command
 * is not a tenant-reachable public transport. Public advisory reads do not use it.
 * grant_absent is a user with no grant row. That is not already_applied.
 */
export const INSTANCE_ADVISORY_USER_ABSENCE_DISCLOSURE = {
  commandOutcome: 'user_absent',
  usesUserNotFoundOutcome: false,
  acceptableOnDeploymentLocalCommand: true,
  reason: 'deployment_local_command_is_not_a_tenant_reachable_public_transport',
  authorizationReadDoesNotDiscloseAbsence: true,
  authorizationReadAbsentUserOutcome: 'authority_required',
  noGrantRowOutcome: 'grant_absent',
  noGrantRowIsAlreadyApplied: false,
} as const;

export type InstanceAdvisoryAuthorityCommandResult =
  | { readonly outcome: 'granted'; readonly grantId: string }
  | { readonly outcome: 'revoked'; readonly grantId: string }
  | {
      readonly outcome: Exclude<InstanceAdvisoryAuthorityCommandOutcome, 'granted' | 'revoked'>;
    };

const GRANT_COMMAND_FIELDS = [
  'schemaVersion',
  'operation',
  'targetUserId',
  'authority',
  'issuanceClassification',
  'correlationId',
] as const;

const REVOKE_COMMAND_FIELDS = [
  'schemaVersion',
  'operation',
  'targetUserId',
  'expectedGrantId',
  'expectedAuthority',
  'correlationId',
] as const;

const USER_COMMAND_FIELDS = [
  'schemaVersion',
  'operation',
  'targetUserId',
  'correlationId',
] as const;

export const INSTANCE_ADVISORY_PROHIBITED_COMMAND_FIELDS = [
  'organizationId',
  'organization_id',
  'membershipId',
  'membership_id',
  'role',
  'tenantRole',
  'tenant_role',
  'permission',
  'tenantPermission',
  'tenant_permission',
  'grantId',
  'grant_id',
  'issuedAt',
  'issued_at',
  'revokedAt',
  'revoked_at',
  'active',
  'auditAction',
  'audit_action',
  'auditActor',
  'actorUserId',
  'actor_user_id',
  'password',
  'passwordHash',
  'password_hash',
  'sessionId',
  'session',
  'sessionState',
  'advisoryRevisionId',
  'advisoryRevision',
  'approvalPurpose',
  'capability',
  'capabilityId',
  'capabilityFields',
  'provider',
  'evaluator',
  'productMatchEvidence',
  'findingId',
  'finding',
  'prisma',
  'sql',
  'transaction',
  'callback',
  'userId',
  'email',
  'displayName',
  'username',
] as const;

type CommandBase = {
  readonly schemaVersion: typeof INSTANCE_ADVISORY_AUTHORITY_COMMAND_SCHEMA_VERSION;
  readonly targetUserId: string;
  readonly correlationId: string;
};

export type InstanceAdvisoryAuthorityGrantCommand = CommandBase & {
  readonly operation: 'grant';
  readonly authority: InstanceAdvisoryAuthority;
  readonly issuanceClassification: InstanceAdvisoryIssuanceClassification;
};

export type InstanceAdvisoryAuthorityRevokeCommand = CommandBase & {
  readonly operation: 'revoke';
  readonly expectedGrantId: string;
  readonly expectedAuthority: InstanceAdvisoryAuthority;
};

export type InstanceAdvisoryAuthorityDisableUserCommand = CommandBase & {
  readonly operation: 'disable_user';
};

export type InstanceAdvisoryAuthorityEnableUserCommand = CommandBase & {
  readonly operation: 'enable_user';
};

export type InstanceAdvisoryAuthorityCommand =
  | InstanceAdvisoryAuthorityGrantCommand
  | InstanceAdvisoryAuthorityRevokeCommand
  | InstanceAdvisoryAuthorityDisableUserCommand
  | InstanceAdvisoryAuthorityEnableUserCommand;

export type InstanceAdvisoryAuthorityCommandParse =
  | { readonly ok: true; readonly command: InstanceAdvisoryAuthorityCommand }
  | { readonly ok: false; readonly outcome: 'invalid_command' };

export function isInstanceAdvisoryAuthorityCommandOutcome(
  value: unknown,
): value is InstanceAdvisoryAuthorityCommandOutcome {
  return (
    typeof value === 'string' &&
    (INSTANCE_ADVISORY_AUTHORITY_COMMAND_OUTCOMES as readonly string[]).includes(value)
  );
}

export function isInstanceAdvisoryAuthorityOperation(
  value: unknown,
): value is InstanceAdvisoryAuthorityOperation {
  return (
    value === 'grant' || value === 'revoke' || value === 'disable_user' || value === 'enable_user'
  );
}

export function parseInstanceAdvisoryAuthorityCommand(
  input: unknown,
): InstanceAdvisoryAuthorityCommandParse {
  if (!isPlainObject(input)) {
    return { ok: false, outcome: 'invalid_command' };
  }
  const owned = ownDataProperties(input);
  if (!owned.ok) {
    return { ok: false, outcome: 'invalid_command' };
  }
  for (const key of owned.keys) {
    if ((INSTANCE_ADVISORY_PROHIBITED_COMMAND_FIELDS as readonly string[]).includes(key)) {
      return { ok: false, outcome: 'invalid_command' };
    }
  }
  const operation = readOwnData(input, 'operation');
  if (!isInstanceAdvisoryAuthorityOperation(operation)) {
    return { ok: false, outcome: 'invalid_command' };
  }
  const allowed =
    operation === 'grant'
      ? GRANT_COMMAND_FIELDS
      : operation === 'revoke'
        ? REVOKE_COMMAND_FIELDS
        : USER_COMMAND_FIELDS;
  const values = closedRecord(input, allowed);
  if (values === null) {
    return { ok: false, outcome: 'invalid_command' };
  }
  if (values.get('schemaVersion') !== INSTANCE_ADVISORY_AUTHORITY_COMMAND_SCHEMA_VERSION) {
    return { ok: false, outcome: 'invalid_command' };
  }
  if (values.get('operation') !== operation) {
    return { ok: false, outcome: 'invalid_command' };
  }
  const targetUserId = values.get('targetUserId');
  const correlationId = values.get('correlationId');
  if (!isCanonicalLowercaseUuid(targetUserId) || !isCanonicalLowercaseUuid(correlationId)) {
    return { ok: false, outcome: 'invalid_command' };
  }
  if (operation === 'grant') {
    const authority = values.get('authority');
    const issuanceClassification = values.get('issuanceClassification');
    if (
      !isInstanceAdvisoryAuthority(authority) ||
      !isInstanceAdvisoryIssuanceClassification(issuanceClassification)
    ) {
      return { ok: false, outcome: 'invalid_command' };
    }
    return {
      ok: true,
      command: Object.freeze({
        schemaVersion: INSTANCE_ADVISORY_AUTHORITY_COMMAND_SCHEMA_VERSION,
        operation,
        targetUserId,
        authority,
        issuanceClassification,
        correlationId,
      }),
    };
  }
  if (operation === 'revoke') {
    const expectedGrantId = values.get('expectedGrantId');
    const expectedAuthority = values.get('expectedAuthority');
    if (
      !isCanonicalLowercaseUuid(expectedGrantId) ||
      !isInstanceAdvisoryAuthority(expectedAuthority)
    ) {
      return { ok: false, outcome: 'invalid_command' };
    }
    return {
      ok: true,
      command: Object.freeze({
        schemaVersion: INSTANCE_ADVISORY_AUTHORITY_COMMAND_SCHEMA_VERSION,
        operation,
        targetUserId,
        expectedGrantId,
        expectedAuthority,
        correlationId,
      }),
    };
  }
  return {
    ok: true,
    command: Object.freeze({
      schemaVersion: INSTANCE_ADVISORY_AUTHORITY_COMMAND_SCHEMA_VERSION,
      operation,
      targetUserId,
      correlationId,
    }),
  };
}
