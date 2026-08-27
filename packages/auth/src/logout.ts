import type { Logger } from '@patchpilot/logger';
import { ok, type Result } from '@patchpilot/domain';
import type { SessionRepository } from '@patchpilot/domain';

import type { Clock } from './clock.js';
import { digestSessionToken } from './token-digests.js';

export type LogoutInput = {
  sessionToken?: string;
};

export type LogoutResult =
  { revoked: false } | { revoked: true; sessionId: string; userId: string };

export type LogoutDependencies = {
  sessions: SessionRepository;
  clock: Clock;
  logger: Logger;
};

export function createLogoutUseCase(dependencies: LogoutDependencies) {
  return {
    execute(input: LogoutInput): Promise<Result<LogoutResult>> {
      return executeLogout(dependencies, input);
    },
  };
}

async function executeLogout(
  dependencies: LogoutDependencies,
  input: LogoutInput,
): Promise<Result<LogoutResult>> {
  const sessionToken = input.sessionToken;
  if (sessionToken !== undefined && sessionToken.length > 0) {
    const tokenHash = digestSessionToken(sessionToken);
    const revoked = await dependencies.sessions.revokeCurrent({
      tokenHash,
      revokedAt: dependencies.clock.now(),
      revokeReason: 'logout',
    });
    if (revoked !== undefined) {
      dependencies.logger.info(
        { event: 'auth.logout', sessionId: revoked.id, userId: revoked.userId },
        'session revoked',
      );
      return ok({ revoked: true, sessionId: revoked.id, userId: revoked.userId });
    }
  }

  return ok({ revoked: false });
}
