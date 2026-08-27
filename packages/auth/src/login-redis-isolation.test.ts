import { describe, expect, it } from 'vitest';

import { createFakeLoginRateLimiter } from './fake-login-rate-limiter.js';
import { createLogoutUseCase } from './logout.js';
import { createResolveSessionUseCase } from './resolve-session.js';
import {
  createAdjustableClock,
  createCollectingLogger,
  createCredentialRecord,
  createMemoryCredentialRepository,
  createMemoryMembershipRepository,
  createMemorySessionRepository,
  createMemoryUserRepository,
  createSessionRecord,
  createTestAuthConfig,
  createUserRecord,
  RAW_CSRF_TOKEN,
  RAW_SESSION_TOKEN,
} from './test-helper.js';
import { digestCsrfToken, digestSessionToken } from './token-digests.js';

describe('authenticated Session and logout Redis isolation', () => {
  it('resolves an authenticated Session while the login limiter is unavailable', async () => {
    const user = createUserRecord({});
    const tokenHash = digestSessionToken(RAW_SESSION_TOKEN);
    const sessions = createMemorySessionRepository([
      createSessionRecord(user, {
        tokenHash,
        csrfTokenHash: digestCsrfToken(RAW_CSRF_TOKEN),
        activeOrganizationId: null,
      }),
    ]);
    const clock = createAdjustableClock();
    const logs = createCollectingLogger();
    const auth = createTestAuthConfig();
    const limiter = createFakeLoginRateLimiter({
      auth,
      logger: logs.logger,
      clock,
      unavailable: true,
    });
    const resolveSession = createResolveSessionUseCase({
      users: createMemoryUserRepository([user]),
      localCredentials: createMemoryCredentialRepository([createCredentialRecord(user)]),
      sessions,
      memberships: createMemoryMembershipRepository(),
      clock,
      auth,
      logger: logs.logger,
    });

    const result = await resolveSession.execute({ sessionToken: RAW_SESSION_TOKEN });
    expect(result.ok).toBe(true);
    expect(limiter.consumeCalls).toEqual([]);
  });

  it('logs out the current Session while the login limiter is unavailable', async () => {
    const user = createUserRecord({});
    const tokenHash = digestSessionToken(RAW_SESSION_TOKEN);
    const session = createSessionRecord(user, {
      tokenHash,
      csrfTokenHash: digestCsrfToken(RAW_CSRF_TOKEN),
    });
    const sessions = createMemorySessionRepository([session]);
    const clock = createAdjustableClock();
    const logs = createCollectingLogger();
    const limiter = createFakeLoginRateLimiter({
      auth: createTestAuthConfig(),
      logger: logs.logger,
      clock,
      unavailable: true,
    });
    const logout = createLogoutUseCase({
      sessions,
      clock,
      logger: logs.logger,
    });

    const result = await logout.execute({ sessionToken: RAW_SESSION_TOKEN });
    expect(result).toEqual({
      ok: true,
      value: { revoked: true, sessionId: session.id, userId: user.id },
    });
    expect((await sessions.findByTokenHash(tokenHash))?.revokeReason).toBe('logout');
    expect(limiter.consumeCalls).toEqual([]);
  });
});
