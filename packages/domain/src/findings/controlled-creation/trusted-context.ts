/**
 * Trusted tenancy context for a future creation transaction.
 * A parsed context scopes an actor to one organization.
 * It is not Finding authority.
 */

import {
  FINDING_CREATION_AMBIENT_CLAIMS,
  FINDING_CREATION_TRUSTED_CONTEXT_SCHEMA_VERSION,
  type FindingCreationReason,
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

export type ParsedFindingCreationTrustedContext = {
  readonly schemaVersion: typeof FINDING_CREATION_TRUSTED_CONTEXT_SCHEMA_VERSION;
  readonly organizationId: string;
  readonly actorId: string;
  readonly membershipId: string;
  readonly membershipStatus: 'active';
};

export type FindingCreationTrustedContextParse =
  | { readonly ok: true; readonly context: ParsedFindingCreationTrustedContext }
  | { readonly ok: false; readonly reason: FindingCreationReason };

export function parseTrustedFindingCreationContext(
  input: unknown,
): FindingCreationTrustedContextParse {
  if (recordHasAmbientKey(input, FINDING_CREATION_AMBIENT_CLAIMS)) {
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
    schemaVersion !== FINDING_CREATION_TRUSTED_CONTEXT_SCHEMA_VERSION ||
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
      schemaVersion: FINDING_CREATION_TRUSTED_CONTEXT_SCHEMA_VERSION,
      organizationId,
      actorId,
      membershipId,
      membershipStatus: 'active',
    }),
  };
}

export function trustedContextsMatch(
  left: ParsedFindingCreationTrustedContext,
  right: ParsedFindingCreationTrustedContext,
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
