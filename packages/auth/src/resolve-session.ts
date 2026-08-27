import type { AuthConfig } from '@patchpilot/config';
import type { Logger } from '@patchpilot/logger';
import { err, ok, type Result, type SessionRecord } from '@patchpilot/domain';
import type {
  LocalCredentialRepository,
  MembershipRepository,
  SessionRepository,
  UserRepository,
} from '@patchpilot/domain';

import { addSeconds, type Clock } from './clock.js';
import { AUTHENTICATION_REQUIRED } from './errors.js';
import { digestSessionToken } from './token-digests.js';
import { createTrustedActor, type TrustedActor } from './trusted-actor.js';

export type ResolveSessionInput = {
  sessionToken: string;
};

export type ResolveSessionResult = {
  actor: TrustedActor;
  session: SessionRecord;
};

export type ResolveSessionDependencies = {
  users: UserRepository;
  localCredentials: LocalCredentialRepository;
  sessions: SessionRepository;
  memberships: MembershipRepository;
  clock: Clock;
  auth: AuthConfig;
  logger: Logger;
};

export function createResolveSessionUseCase(dependencies: ResolveSessionDependencies) {
  return {
    execute(input: ResolveSessionInput): Promise<Result<ResolveSessionResult>> {
      return executeResolveSession(dependencies, input);
    },
  };
}

async function executeResolveSession(
  dependencies: ResolveSessionDependencies,
  input: ResolveSessionInput,
): Promise<Result<ResolveSessionResult>> {
  if (input.sessionToken.length === 0) {
    return err(AUTHENTICATION_REQUIRED);
  }

  const tokenHash = digestSessionToken(input.sessionToken);
  const session = await dependencies.sessions.findByTokenHash(tokenHash);
  if (session === undefined) {
    return err(AUTHENTICATION_REQUIRED);
  }

  const now = dependencies.clock.now();
  if (session.revokedAt !== null) {
    return err(AUTHENTICATION_REQUIRED);
  }

  if (now.getTime() >= session.idleExpiresAt.getTime()) {
    return err(AUTHENTICATION_REQUIRED);
  }

  if (now.getTime() >= session.absoluteExpiresAt.getTime()) {
    return err(AUTHENTICATION_REQUIRED);
  }

  const user = await dependencies.users.findById(session.userId);
  if (user === undefined || user.status !== 'active') {
    return err(AUTHENTICATION_REQUIRED);
  }

  const credential = await dependencies.localCredentials.findByUserId(session.userId);
  if (credential === undefined || credential.passwordRevision !== session.passwordRevision) {
    return err(AUTHENTICATION_REQUIRED);
  }

  const organizationContext = await resolveOrganizationContext(dependencies, session);
  const actor = createTrustedActor({
    userId: user.id,
    sessionId: session.id,
    ...(organizationContext === undefined
      ? {}
      : {
          organization: organizationContext.organization,
          membership: organizationContext.membership,
        }),
  });

  const updated = await throttleLastSeen(dependencies, session, now);
  const resolvedSession = updated ?? {
    ...session,
    activeOrganizationId: actor.organizationId,
  };

  return ok({ actor, session: resolvedSession });
}

async function resolveOrganizationContext(
  dependencies: ResolveSessionDependencies,
  session: SessionRecord,
) {
  if (session.activeOrganizationId === null) {
    return undefined;
  }

  const bound = await dependencies.memberships.findActiveInActiveOrganization(
    session.userId,
    session.activeOrganizationId,
  );
  if (bound !== undefined) {
    return bound;
  }

  await dependencies.sessions.clearActiveOrganization({
    userId: session.userId,
    organizationId: session.activeOrganizationId,
  });
  return undefined;
}

async function throttleLastSeen(
  dependencies: ResolveSessionDependencies,
  session: SessionRecord,
  now: Date,
): Promise<SessionRecord | undefined> {
  const minLastSeenAt = addSeconds(now, -dependencies.auth.lastSeenMinIntervalSeconds);
  return dependencies.sessions.updateThrottledLastSeen({
    tokenHash: session.tokenHash,
    lastSeenAt: now,
    idleExpiresAt: addSeconds(now, dependencies.auth.sessionIdleTtlSeconds),
    minLastSeenAt,
  });
}
