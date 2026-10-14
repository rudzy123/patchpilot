/**
 * Narrow authorization read for later advisory application services.
 * Authority comes from an active User and one exact active grant.
 * Organization, membership, role, and tenant permission are not inputs.
 * This module does not read PostgreSQL.
 */

import { isCanonicalInstanceAdvisoryPrincipalId } from './identity.js';
import { closedRecord } from './plain.js';
import {
  isInstanceAdvisoryAuthority,
  isInstanceAdvisoryIssuanceClassification,
  type InstanceAdvisoryAuthority,
  type InstanceAdvisoryIssuanceClassification,
} from './policy.js';
import type { UserStatus } from '../lifecycle.js';

export const INSTANCE_ADVISORY_AUTHORIZATION_READ_SCHEMA_VERSION =
  'instance_advisory_authorization_read_v1' as const;

export const INSTANCE_ADVISORY_AUTHORIZATION_FACTS_SCHEMA_VERSION =
  'instance_advisory_authorization_facts_v1' as const;

export const INSTANCE_ADVISORY_AUTHORIZATION_READ_OUTCOMES = [
  'authorized',
  'authority_required',
  'user_inactive',
  'malformed_persisted_state',
  'database_unavailable',
  'internal_failure',
] as const;

export type InstanceAdvisoryAuthorizationReadOutcome =
  (typeof INSTANCE_ADVISORY_AUTHORIZATION_READ_OUTCOMES)[number];

export type InstanceAdvisoryAuthorizationReadRequest = {
  readonly schemaVersion: typeof INSTANCE_ADVISORY_AUTHORIZATION_READ_SCHEMA_VERSION;
  readonly userId: string;
  readonly requiredAuthority: InstanceAdvisoryAuthority;
};

export type InstanceAdvisoryAuthorizationReadResult = {
  readonly outcome: InstanceAdvisoryAuthorizationReadOutcome;
};

export type InstanceAdvisoryAuthorizationReadPort = {
  readonly readRequiredAuthority: (
    request: InstanceAdvisoryAuthorizationReadRequest,
  ) => Promise<InstanceAdvisoryAuthorizationReadResult>;
};

export type InstanceAdvisoryAuthorizationFacts = {
  readonly schemaVersion: typeof INSTANCE_ADVISORY_AUTHORIZATION_FACTS_SCHEMA_VERSION;
  readonly availability: 'loaded' | 'database_unavailable' | 'internal_failure';
  readonly userId: string;
  readonly user:
    | { readonly existence: 'absent' }
    | { readonly existence: 'present'; readonly status: UserStatus };
  readonly activeGrant: {
    readonly userId: string;
    readonly authority: InstanceAdvisoryAuthority;
    readonly issuanceClassification: InstanceAdvisoryIssuanceClassification;
  } | null;
  readonly malformed: boolean;
};

/**
 * user_inactive stays available to the in-transaction checker.
 * A later external application boundary collapses it to authority_required
 * so a disabled user is not distinguished from a user without a grant.
 */
export const INSTANCE_ADVISORY_AUTHORIZATION_EXTERNAL_COLLAPSE = {
  user_inactive: 'authority_required',
} as const;

export const INSTANCE_ADVISORY_MUTATION_TRANSACTION_REQUIREMENTS = {
  schemaVersion: 'instance_advisory_mutation_transaction_v1',
  reloadsInsideMutationTransaction: [
    'user_existence',
    'user_active_status',
    'active_advisory_grant',
    'exact_required_authority',
  ],
  priorAuthorizationReadOutsideTransactionSufficient: false,
  implemented: false,
} as const;

export type InstanceAdvisoryAuthorizationReadParse =
  | { readonly ok: true; readonly request: InstanceAdvisoryAuthorizationReadRequest }
  | { readonly ok: false; readonly reason: 'invalid_request' };

const AUTHORIZATION_READ_FIELDS = ['schemaVersion', 'userId', 'requiredAuthority'] as const;

export function parseInstanceAdvisoryAuthorizationReadRequest(
  input: unknown,
): InstanceAdvisoryAuthorizationReadParse {
  const values = closedRecord(input, AUTHORIZATION_READ_FIELDS);
  if (values === null) {
    return { ok: false, reason: 'invalid_request' };
  }
  const userId = values.get('userId');
  const requiredAuthority = values.get('requiredAuthority');
  if (
    values.get('schemaVersion') !== INSTANCE_ADVISORY_AUTHORIZATION_READ_SCHEMA_VERSION ||
    !isCanonicalInstanceAdvisoryPrincipalId(userId) ||
    !isInstanceAdvisoryAuthority(requiredAuthority)
  ) {
    return { ok: false, reason: 'invalid_request' };
  }
  return {
    ok: true,
    request: {
      schemaVersion: INSTANCE_ADVISORY_AUTHORIZATION_READ_SCHEMA_VERSION,
      userId,
      requiredAuthority,
    },
  };
}

export function classifyInstanceAdvisoryAuthorization(
  facts: InstanceAdvisoryAuthorizationFacts,
  request: InstanceAdvisoryAuthorizationReadRequest,
): InstanceAdvisoryAuthorizationReadOutcome {
  if (facts.availability === 'database_unavailable') {
    return 'database_unavailable';
  }
  if (facts.availability === 'internal_failure') {
    return 'internal_failure';
  }
  if (facts.availability !== 'loaded') {
    return 'internal_failure';
  }
  if (
    facts.schemaVersion !== INSTANCE_ADVISORY_AUTHORIZATION_FACTS_SCHEMA_VERSION ||
    request.schemaVersion !== INSTANCE_ADVISORY_AUTHORIZATION_READ_SCHEMA_VERSION ||
    !isCanonicalInstanceAdvisoryPrincipalId(request.userId) ||
    !isInstanceAdvisoryAuthority(request.requiredAuthority)
  ) {
    return 'internal_failure';
  }
  if (
    facts.malformed ||
    !isCanonicalInstanceAdvisoryPrincipalId(facts.userId) ||
    facts.userId !== request.userId
  ) {
    return 'malformed_persisted_state';
  }
  if (facts.user.existence !== 'absent' && facts.user.existence !== 'present') {
    return 'malformed_persisted_state';
  }
  const activeGrant = facts.activeGrant;
  if (activeGrant !== null) {
    if (
      !isCanonicalInstanceAdvisoryPrincipalId(activeGrant.userId) ||
      activeGrant.userId !== facts.userId ||
      !isInstanceAdvisoryAuthority(activeGrant.authority) ||
      !isInstanceAdvisoryIssuanceClassification(activeGrant.issuanceClassification)
    ) {
      return 'malformed_persisted_state';
    }
  }
  if (facts.user.existence === 'absent') {
    if (activeGrant !== null) {
      return 'malformed_persisted_state';
    }
    return 'authority_required';
  }
  if (facts.user.status === 'disabled') {
    return 'user_inactive';
  }
  if (facts.user.status !== 'active') {
    return 'malformed_persisted_state';
  }
  if (activeGrant === null || activeGrant.authority !== request.requiredAuthority) {
    return 'authority_required';
  }
  return 'authorized';
}

export function collapseInstanceAdvisoryAuthorizationForExternalBoundary(
  outcome: InstanceAdvisoryAuthorizationReadOutcome,
): Exclude<InstanceAdvisoryAuthorizationReadOutcome, 'user_inactive'> {
  if (outcome === 'user_inactive') {
    return 'authority_required';
  }
  return outcome;
}
