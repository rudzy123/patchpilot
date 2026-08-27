import { describe, expect, it } from 'vitest';

import { createLogoutUseCase } from './logout.js';
import { digestCsrfToken, digestSessionToken } from './token-digests.js';
import {
  createAdjustableClock,
  createCollectingLogger,
  createMemorySessionRepository,
  createSessionRecord,
  createUserRecord,
  RAW_CSRF_TOKEN,
  RAW_SESSION_TOKEN,
} from './test-helper.js';

describe('logout use case', () => {
  it('revokes the current Session and is publicly idempotent', async () => {
    const user = createUserRecord({});
    const tokenHash = digestSessionToken(RAW_SESSION_TOKEN);
    const session = createSessionRecord(user, {
      tokenHash,
      csrfTokenHash: digestCsrfToken(RAW_CSRF_TOKEN),
    });
    const sessions = createMemorySessionRepository([session]);
    const logout = createLogoutUseCase({
      sessions,
      clock: createAdjustableClock(),
      logger: createCollectingLogger().logger,
    });

    const first = await logout.execute({ sessionToken: RAW_SESSION_TOKEN });
    const second = await logout.execute({ sessionToken: RAW_SESSION_TOKEN });
    const missing = await logout.execute({ sessionToken: 'unknown-raw-session-token' });
    const empty = await logout.execute({});

    expect(first).toEqual({
      ok: true,
      value: { revoked: true, sessionId: session.id, userId: user.id },
    });
    expect(second).toEqual({ ok: true, value: { revoked: false } });
    expect(missing).toEqual(second);
    expect(empty).toEqual(second);
    const stored = await sessions.findByTokenHash(tokenHash);
    expect(stored?.revokedAt).not.toBeNull();
    expect(stored?.revokeReason).toBe('logout');
  });
});
