import type { AuthConfig } from '@patchpilot/config';
import type { Logger } from '@patchpilot/logger';
import { err, ok, type Result } from '@patchpilot/domain';
import type {
  LocalCredentialRepository,
  MembershipRepository,
  SessionRepository,
  UserRepository,
} from '@patchpilot/domain';

import { addSeconds, type Clock } from './clock.js';
import { AUTHENTICATION_REQUIRED, ORGANIZATION_NOT_FOUND } from './errors.js';
import type { IssuedSessionTokens } from './login.js';
import { SESSION_TOKEN_BYTES, type RandomTokenGenerator } from './random-token-generator.js';
import { createResolveSessionUseCase, type ResolveSessionResult } from './resolve-session.js';
import {
  publicAuthOrganization,
  sessionExpiresAt,
  type PublicAuthOrganization,
  type PublicAuthUser,
} from './session-view.js';
import { digestCsrfToken, digestSessionToken } from './token-digests.js';
import { createTrustedActor, type TrustedActor } from './trusted-actor.js';

export type SelectOrganizationInput = {
  sessionToken: string;
  organizationId: string;
};

export type SelectOrganizationResult = {
  actor: TrustedActor;
  sessionId: string;
  tokens: IssuedSessionTokens;
  user: PublicAuthUser;
  organization: PublicAuthOrganization;
  expiresAt: Date;
};

export type SelectOrganizationDependencies = {
  users: UserRepository;
  localCredentials: LocalCredentialRepository;
  sessions: SessionRepository;
  memberships: MembershipRepository;
  tokens: RandomTokenGenerator;
  clock: Clock;
  auth: AuthConfig;
  logger: Logger;
};

export function createSelectOrganizationUseCase(dependencies: SelectOrganizationDependencies) {
  const resolveSession = createResolveSessionUseCase(dependencies);

  return {
    async execute(input: SelectOrganizationInput): Promise<Result<SelectOrganizationResult>> {
      const resolved = await resolveSession.execute({ sessionToken: input.sessionToken });
      if (!resolved.ok) {
        return err(AUTHENTICATION_REQUIRED);
      }

      return rotateOntoOrganization(dependencies, resolved.value, input.organizationId);
    },
  };
}

async function rotateOntoOrganization(
  dependencies: SelectOrganizationDependencies,
  resolved: ResolveSessionResult,
  organizationId: string,
): Promise<Result<SelectOrganizationResult>> {
  const bound = await dependencies.memberships.findActiveInActiveOrganization(
    resolved.actor.userId,
    organizationId,
  );
  if (bound === undefined) {
    return err(ORGANIZATION_NOT_FOUND);
  }

  const now = dependencies.clock.now();
  const sessionToken = dependencies.tokens.generate(SESSION_TOKEN_BYTES);
  const csrfToken = dependencies.tokens.generate(SESSION_TOKEN_BYTES);
  const rotated = await dependencies.sessions.rotate({
    currentTokenHash: resolved.session.tokenHash,
    nextTokenHash: digestSessionToken(sessionToken),
    nextCsrfTokenHash: digestCsrfToken(csrfToken),
    lastSeenAt: now,
    idleExpiresAt: addSeconds(now, dependencies.auth.sessionIdleTtlSeconds),
    activeOrganizationId: bound.organization.id,
  });

  if (rotated === undefined) {
    return err(AUTHENTICATION_REQUIRED);
  }

  const actor = createTrustedActor({
    userId: resolved.actor.userId,
    sessionId: rotated.id,
    organization: bound.organization,
    membership: bound.membership,
  });

  dependencies.logger.info(
    {
      event: 'auth.organization_selected',
      userId: actor.userId,
      sessionId: rotated.id,
      organizationId: bound.organization.id,
    },
    'organization selected',
  );

  return ok({
    actor,
    sessionId: rotated.id,
    tokens: { sessionToken, csrfToken },
    user: resolved.user,
    organization: publicAuthOrganization({
      organization: bound.organization,
      role: bound.membership.role,
    }),
    expiresAt: sessionExpiresAt(rotated),
  });
}
