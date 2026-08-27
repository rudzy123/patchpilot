import type { AuthConfig } from '@patchpilot/config';
import type { Logger } from '@patchpilot/logger';
import { err, ok, type Result, type SessionRecord } from '@patchpilot/domain';
import type {
  LocalCredentialRepository,
  MembershipRepository,
  SessionRepository,
  UserRepository,
} from '@patchpilot/domain';

import type { Clock } from './clock.js';
import { AUTHENTICATION_REQUIRED } from './errors.js';
import { SESSION_TOKEN_BYTES, type RandomTokenGenerator } from './random-token-generator.js';
import { createResolveSessionUseCase } from './resolve-session.js';
import {
  sessionExpiresAt,
  type PublicAuthOrganization,
  type PublicAuthUser,
} from './session-view.js';
import { digestCsrfToken } from './token-digests.js';
import type { TrustedActor } from './trusted-actor.js';

export type ReadSessionInput = {
  sessionToken: string;
};

export type ReadSessionResult = {
  actor: TrustedActor;
  session: SessionRecord;
  user: PublicAuthUser;
  organization: PublicAuthOrganization | null;
  csrfToken: string;
  expiresAt: Date;
};

export type ReadSessionDependencies = {
  users: UserRepository;
  localCredentials: LocalCredentialRepository;
  sessions: SessionRepository;
  memberships: MembershipRepository;
  tokens: RandomTokenGenerator;
  clock: Clock;
  auth: AuthConfig;
  logger: Logger;
};

export function createReadSessionUseCase(dependencies: ReadSessionDependencies) {
  const resolveSession = createResolveSessionUseCase(dependencies);

  return {
    async execute(input: ReadSessionInput): Promise<Result<ReadSessionResult>> {
      const resolved = await resolveSession.execute({ sessionToken: input.sessionToken });
      if (!resolved.ok) {
        return err(AUTHENTICATION_REQUIRED);
      }

      const csrfToken = dependencies.tokens.generate(SESSION_TOKEN_BYTES);
      const replaced = await dependencies.sessions.replaceCsrfToken({
        tokenHash: resolved.value.session.tokenHash,
        nextCsrfTokenHash: digestCsrfToken(csrfToken),
      });
      if (replaced === undefined) {
        return err(AUTHENTICATION_REQUIRED);
      }

      return ok({
        actor: resolved.value.actor,
        session: replaced,
        user: resolved.value.user,
        organization: resolved.value.organization,
        csrfToken,
        expiresAt: sessionExpiresAt(replaced),
      });
    },
  };
}
