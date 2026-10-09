/**
 * Trusted tenancy context for a future repeated-observation transaction.
 * A parsed context scopes an actor to one organization.
 * Membership alone is not observation authority.
 */

import {
  FINDING_REPEATED_OBSERVATION_AMBIENT_CLAIMS,
  FINDING_REPEATED_OBSERVATION_TRUSTED_CONTEXT_SCHEMA_VERSION,
  type FindingRepeatedObservationReason,
} from './policy.js';
import { closedRecord, recordHasAmbientKey } from './plain.js';

const UUID_LOWER_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

const CONTEXT_KEYS = [
  'schemaVersion',
  'organizationId',
  'actorId',
  'membershipId',
  'membershipStatus',
] as const;

export type ParsedFindingRepeatedObservationTrustedContext = {
  readonly schemaVersion: typeof FINDING_REPEATED_OBSERVATION_TRUSTED_CONTEXT_SCHEMA_VERSION;
  readonly organizationId: string;
  readonly actorId: string;
  readonly membershipId: string;
  readonly membershipStatus: 'active';
};

export type FindingRepeatedObservationTrustedContextParse =
  | { readonly ok: true; readonly context: ParsedFindingRepeatedObservationTrustedContext }
  | { readonly ok: false; readonly reason: FindingRepeatedObservationReason };

export function parseTrustedFindingRepeatedObservationContext(
  input: unknown,
): FindingRepeatedObservationTrustedContextParse {
  if (recordHasAmbientKey(input, FINDING_REPEATED_OBSERVATION_AMBIENT_CLAIMS)) {
    return { ok: false, reason: 'ambient_authority_rejected' };
  }
  const values = closedRecord(input, CONTEXT_KEYS);
  if (values === null) {
    return { ok: false, reason: 'trusted_context_rejected' };
  }
  const schemaVersion = values.get('schemaVersion');
  const organizationId = values.get('organizationId');
  const actorId = values.get('actorId');
  const membershipId = values.get('membershipId');
  const membershipStatus = values.get('membershipStatus');
  if (
    schemaVersion !== FINDING_REPEATED_OBSERVATION_TRUSTED_CONTEXT_SCHEMA_VERSION ||
    !isUuid(organizationId) ||
    !isUuid(actorId) ||
    !isUuid(membershipId)
  ) {
    return { ok: false, reason: 'trusted_context_rejected' };
  }
  if (membershipStatus !== 'active') {
    return {
      ok: false,
      reason: membershipStatus === 'revoked' ? 'membership_inactive' : 'trusted_context_rejected',
    };
  }
  return {
    ok: true,
    context: Object.freeze({
      schemaVersion: FINDING_REPEATED_OBSERVATION_TRUSTED_CONTEXT_SCHEMA_VERSION,
      organizationId,
      actorId,
      membershipId,
      membershipStatus: 'active',
    }),
  };
}

export function trustedRepeatedObservationContextsMatch(
  left: ParsedFindingRepeatedObservationTrustedContext,
  right: ParsedFindingRepeatedObservationTrustedContext,
): boolean {
  return (
    left.organizationId === right.organizationId &&
    left.actorId === right.actorId &&
    left.membershipId === right.membershipId &&
    left.membershipStatus === right.membershipStatus
  );
}

function isUuid(value: unknown): value is string {
  return typeof value === 'string' && UUID_LOWER_PATTERN.test(value);
}
