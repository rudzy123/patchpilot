import type { PublicAuthOrganization, PublicAuthUser } from '@patchpilot/auth';
import { organizationsResponseSchema, sessionResponseSchema } from '@patchpilot/contracts';
import type { OrganizationsResponse, SessionResponse } from '@patchpilot/contracts';

export function toSessionResponse(input: {
  user: PublicAuthUser;
  organization: PublicAuthOrganization | null;
  csrfToken: string;
  expiresAt: Date;
}): SessionResponse {
  return sessionResponseSchema.parse({
    user: input.user,
    organization: input.organization,
    csrfToken: input.csrfToken,
    expiresAt: input.expiresAt.toISOString(),
  });
}

export function toOrganizationsResponse(
  organizations: ReadonlyArray<PublicAuthOrganization>,
): OrganizationsResponse {
  return organizationsResponseSchema.parse({ organizations });
}
