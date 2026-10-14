/**
 * Audit intent for a future grant command. This module writes no audit row.
 * Exact replay and rollback produce no intent. Correlation does not mint a second event.
 */

import { JSON_SCHEMA_VERSION_V1, type AuditPayloadJson } from '../json-documents.js';
import type { AuditActorType, AuditRetentionCategory } from '../lifecycle.js';
import type { InstanceAdvisoryAuthorityCommand } from './command.js';
import type { InstanceAdvisoryCommandDecision } from './decision.js';
import { isCanonicalLowercaseUuid } from './identity.js';
import type { InstanceAdvisoryAuthority } from './policy.js';

export const INSTANCE_ADVISORY_AUDIT_ACTIONS = {
  granted: 'intelligence.instance_advisory_authority_granted',
  revoked: 'intelligence.instance_advisory_authority_revoked',
  userDisabled: 'auth.user_disabled',
  userReenabled: 'auth.user_reenabled',
} as const;

export type InstanceAdvisoryAuditAction =
  (typeof INSTANCE_ADVISORY_AUDIT_ACTIONS)[keyof typeof INSTANCE_ADVISORY_AUDIT_ACTIONS];

export const INSTANCE_ADVISORY_GRANT_AUDIT_SUBJECT_TYPE =
  'instance_advisory_authority_grant' as const;

export const INSTANCE_ADVISORY_USER_AUDIT_SUBJECT_TYPE = 'user' as const;

export const INSTANCE_ADVISORY_AUDIT_FORBIDDEN_PAYLOAD_FIELDS = [
  'password',
  'passwordHash',
  'sessionToken',
  'session',
  'csrfToken',
  'capabilitySeal',
  'capability',
  'credential',
  'organizationId',
  'membershipId',
  'advisoryDocument',
  'providerPayload',
  'sql',
  'databaseUrl',
  'constraint',
  'trigger',
] as const;

export const INSTANCE_ADVISORY_AUDIT_REPLAY = {
  exactReplayWritesSecondEvent: false,
  differentCorrelationWritesSecondEvent: false,
  rollbackWritesEvent: false,
  actorType: 'system',
  actorUserId: null,
  organizationId: null,
  membershipId: null,
  schemaVersion: JSON_SCHEMA_VERSION_V1,
  retentionCategory: 'security',
  correlationRequiredBecauseOrganizationIsNull: true,
  uniqueIndexIsNotProductReplay: true,
} as const;

export type InstanceAdvisoryAuditIntent = {
  readonly actorType: Extract<AuditActorType, 'system'>;
  readonly actorUserId: null;
  readonly organizationId: null;
  readonly membershipId: null;
  readonly action: InstanceAdvisoryAuditAction;
  readonly subjectType:
    | typeof INSTANCE_ADVISORY_GRANT_AUDIT_SUBJECT_TYPE
    | typeof INSTANCE_ADVISORY_USER_AUDIT_SUBJECT_TYPE;
  readonly subjectId: string;
  readonly correlationId: string;
  readonly schemaVersion: typeof JSON_SCHEMA_VERSION_V1;
  readonly retentionCategory: Extract<AuditRetentionCategory, 'security'>;
  readonly payload: AuditPayloadJson;
};

export function instanceAdvisoryAuditIntent(input: {
  readonly decision: InstanceAdvisoryCommandDecision;
  readonly command: InstanceAdvisoryAuthorityCommand;
  readonly subjectId: string;
  readonly authority: InstanceAdvisoryAuthority | null;
}): InstanceAdvisoryAuditIntent | null {
  if (input.decision.auditEvents !== 1) {
    return null;
  }
  if (!isCanonicalLowercaseUuid(input.subjectId)) {
    return null;
  }
  const action = actionForOutcome(input.decision.outcome);
  if (action === null) {
    return null;
  }
  if (action === INSTANCE_ADVISORY_AUDIT_ACTIONS.granted) {
    return grantIntent(input, action);
  }
  if (action === INSTANCE_ADVISORY_AUDIT_ACTIONS.revoked) {
    return grantIntent(input, action);
  }
  if (input.authority !== null || input.subjectId !== input.command.targetUserId) {
    return null;
  }
  return userIntent(input, action);
}

function grantIntent(
  input: {
    readonly decision: InstanceAdvisoryCommandDecision;
    readonly command: InstanceAdvisoryAuthorityCommand;
    readonly subjectId: string;
    readonly authority: InstanceAdvisoryAuthority | null;
  },
  action:
    typeof INSTANCE_ADVISORY_AUDIT_ACTIONS.granted | typeof INSTANCE_ADVISORY_AUDIT_ACTIONS.revoked,
): InstanceAdvisoryAuditIntent | null {
  if (input.authority === null) {
    return null;
  }
  if (input.command.operation === 'grant' && input.authority !== input.command.authority) {
    return null;
  }
  if (input.command.operation === 'revoke') {
    if (
      input.authority !== input.command.expectedAuthority ||
      input.subjectId !== input.command.expectedGrantId
    ) {
      return null;
    }
  }
  if (input.command.operation !== 'grant' && input.command.operation !== 'revoke') {
    return null;
  }
  return baseIntent(input, action, INSTANCE_ADVISORY_GRANT_AUDIT_SUBJECT_TYPE, {
    targetUserId: input.command.targetUserId,
    authority: input.authority,
    issuanceClassification: 'deployment_local_command',
    correlationId: input.command.correlationId,
  });
}

function userIntent(
  input: {
    readonly command: InstanceAdvisoryAuthorityCommand;
    readonly subjectId: string;
  },
  action:
    | typeof INSTANCE_ADVISORY_AUDIT_ACTIONS.userDisabled
    | typeof INSTANCE_ADVISORY_AUDIT_ACTIONS.userReenabled,
): InstanceAdvisoryAuditIntent {
  return baseIntent(input, action, INSTANCE_ADVISORY_USER_AUDIT_SUBJECT_TYPE, {
    targetUserId: input.command.targetUserId,
    correlationId: input.command.correlationId,
  });
}

function baseIntent(
  input: {
    readonly command: InstanceAdvisoryAuthorityCommand;
    readonly subjectId: string;
  },
  action: InstanceAdvisoryAuditAction,
  subjectType: InstanceAdvisoryAuditIntent['subjectType'],
  metadata: AuditPayloadJson['metadata'],
): InstanceAdvisoryAuditIntent {
  return {
    actorType: 'system',
    actorUserId: null,
    organizationId: null,
    membershipId: null,
    action,
    subjectType,
    subjectId: input.subjectId,
    correlationId: input.command.correlationId,
    schemaVersion: JSON_SCHEMA_VERSION_V1,
    retentionCategory: 'security',
    payload: {
      schemaVersion: JSON_SCHEMA_VERSION_V1,
      metadata,
    },
  };
}

function actionForOutcome(
  outcome: InstanceAdvisoryCommandDecision['outcome'],
): InstanceAdvisoryAuditAction | null {
  switch (outcome) {
    case 'granted':
      return INSTANCE_ADVISORY_AUDIT_ACTIONS.granted;
    case 'revoked':
      return INSTANCE_ADVISORY_AUDIT_ACTIONS.revoked;
    case 'user_disabled':
      return INSTANCE_ADVISORY_AUDIT_ACTIONS.userDisabled;
    case 'user_enabled':
      return INSTANCE_ADVISORY_AUDIT_ACTIONS.userReenabled;
    default:
      return null;
  }
}
