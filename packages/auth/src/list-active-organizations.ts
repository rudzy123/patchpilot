import type { AuthConfig } from '@patchpilot/config';
import type { Logger } from '@patchpilot/logger';
import { err, ok, type MembershipRole, type Result } from '@patchpilot/domain';
import type {
  LocalCredentialRepository,
  MembershipRepository,
  SessionRepository,
  UserRepository,
} from '@patchpilot/domain';

import type { Clock } from './clock.js';
import { AUTHENTICATION_REQUIRED } from './errors.js';
import { createResolveSessionUseCase } from './resolve-session.js';

export type ListActiveOrganizationsInput = {
  sessionToken: string;
};

export type ActiveOrganizationSummary = {
  organizationId: string;
  name: string;
  slug: string;
  membershipId: string;
  role: MembershipRole;
};

export type ListActiveOrganizationsDependencies = {
  users: UserRepository;
  localCredentials: LocalCredentialRepository;
  sessions: SessionRepository;
  memberships: MembershipRepository;
  clock: Clock;
  auth: AuthConfig;
  logger: Logger;
};

export function createListActiveOrganizationsUseCase(
  dependencies: ListActiveOrganizationsDependencies,
) {
  const resolveSession = createResolveSessionUseCase(dependencies);

  return {
    async execute(
      input: ListActiveOrganizationsInput,
    ): Promise<Result<readonly ActiveOrganizationSummary[]>> {
      const resolved = await resolveSession.execute({ sessionToken: input.sessionToken });
      if (!resolved.ok) {
        return err(AUTHENTICATION_REQUIRED);
      }

      const rows = await dependencies.memberships.listActiveInActiveOrganizationsForUser(
        resolved.value.actor.userId,
      );
      return ok(
        rows.map((row) => ({
          organizationId: row.organization.id,
          name: row.organization.name,
          slug: row.organization.slug,
          membershipId: row.membership.id,
          role: row.membership.role,
        })),
      );
    },
  };
}
