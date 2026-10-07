/**
 * Trusted actor fields for one controlled Finding operation.
 * Organization, actor, and membership come from these fields.
 * A permissions array on the same object is ignored.
 * An explicit membershipStatus other than active is rejected.
 * It is not rewritten to active.
 */

import type { MembershipRole } from '../../lifecycle.js';
import { isPlainObject, ownDataProperties, readOwnData } from '../controlled-creation/plain.js';

const UUID_LOWER_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

const ROLES = new Set<string>(['owner', 'admin', 'member', 'viewer']);

export type ControlledFindingOperatorActor = {
  readonly userId: string;
  readonly sessionId: string;
  readonly organizationId: string | null;
  readonly membershipId: string | null;
  readonly role: MembershipRole | null;
};

export type ParsedControlledFindingOperatorActor = {
  readonly userId: string;
  readonly organizationId: string;
  readonly membershipId: string;
  readonly role: MembershipRole;
};

export function parseControlledFindingOperatorActor(
  input: unknown,
): ParsedControlledFindingOperatorActor | null {
  if (!isPlainObject(input) || !ownDataProperties(input).ok) {
    return null;
  }
  if (!acceptsMembershipStatus(input)) {
    return null;
  }
  const userId = readOwnData(input, 'userId');
  const sessionId = readOwnData(input, 'sessionId');
  const organizationId = readOwnData(input, 'organizationId');
  const membershipId = readOwnData(input, 'membershipId');
  const role = readOwnData(input, 'role');
  if (typeof sessionId !== 'string' || sessionId.length === 0) {
    return null;
  }
  if (!isUuid(userId) || !isUuid(organizationId) || !isUuid(membershipId)) {
    return null;
  }
  if (!isRole(role)) {
    return null;
  }
  return {
    userId,
    organizationId,
    membershipId,
    role,
  };
}

function acceptsMembershipStatus(record: Record<string, unknown>): boolean {
  const descriptor = Object.getOwnPropertyDescriptor(record, 'membershipStatus');
  if (descriptor === undefined) {
    return true;
  }
  if (descriptor.get !== undefined || descriptor.set !== undefined) {
    return false;
  }
  return descriptor.value === 'active';
}

function isRole(value: unknown): value is MembershipRole {
  return typeof value === 'string' && ROLES.has(value);
}

function isUuid(value: unknown): value is string {
  return typeof value === 'string' && UUID_LOWER_PATTERN.test(value);
}
