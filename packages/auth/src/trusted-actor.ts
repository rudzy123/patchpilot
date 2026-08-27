import type {
  AppendAuditEventInput,
  MembershipRecord,
  MembershipRole,
  OrganizationRecord,
} from '@patchpilot/domain';

import { permissionsForRole, type Permission } from './permissions.js';

export type TrustedActor = {
  readonly userId: string;
  readonly sessionId: string;
  readonly organizationId: string | null;
  readonly membershipId: string | null;
  readonly role: MembershipRole | null;
  readonly permissions: readonly Permission[];
};

export type AuditActorFields = Pick<
  AppendAuditEventInput,
  'actorType' | 'actorUserId' | 'organizationId' | 'actorMembershipId'
>;

export const anonymousAuditActorFields: AuditActorFields = {
  actorType: 'anonymous',
};

export function createTrustedActor(input: {
  userId: string;
  sessionId: string;
  organization?: OrganizationRecord;
  membership?: MembershipRecord;
}): TrustedActor {
  const organization = input.organization;
  const membership = input.membership;
  if (
    organization === undefined ||
    membership === undefined ||
    organization.status !== 'active' ||
    membership.status !== 'active' ||
    membership.userId !== input.userId ||
    membership.organizationId !== organization.id
  ) {
    return {
      userId: input.userId,
      sessionId: input.sessionId,
      organizationId: null,
      membershipId: null,
      role: null,
      permissions: [],
    };
  }

  return {
    userId: input.userId,
    sessionId: input.sessionId,
    organizationId: organization.id,
    membershipId: membership.id,
    role: membership.role,
    permissions: permissionsForRole(membership.role),
  };
}

export function auditActorFields(actor: TrustedActor): AuditActorFields {
  if (actor.organizationId === null || actor.membershipId === null) {
    return {
      actorType: 'user',
      actorUserId: actor.userId,
    };
  }

  return {
    actorType: 'user',
    actorUserId: actor.userId,
    organizationId: actor.organizationId,
    actorMembershipId: actor.membershipId,
  };
}
