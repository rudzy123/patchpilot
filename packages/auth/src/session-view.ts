import type { MembershipRole, OrganizationRecord, SessionRecord } from '@patchpilot/domain';

export type PublicAuthUser = {
  id: string;
  displayName: string;
};

export type PublicAuthOrganization = {
  id: string;
  slug: string;
  name: string;
  role: MembershipRole;
};

export function publicAuthOrganization(input: {
  organization: OrganizationRecord;
  role: MembershipRole;
}): PublicAuthOrganization {
  return {
    id: input.organization.id,
    slug: input.organization.slug,
    name: input.organization.name,
    role: input.role,
  };
}

export function sessionExpiresAt(session: SessionRecord): Date {
  return session.idleExpiresAt.getTime() <= session.absoluteExpiresAt.getTime()
    ? session.idleExpiresAt
    : session.absoluteExpiresAt;
}
