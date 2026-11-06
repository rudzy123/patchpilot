import { describe, expect, it } from 'vitest';

import { AUTHENTICATION_REQUIRED } from './errors.js';
import { createReadSessionUseCase } from './read-session.js';
import { digestCsrfToken, digestSessionToken } from './token-digests.js';
import {
  createAdjustableClock,
  createCollectingLogger,
  createCredentialRecord,
  createMemoryCredentialRepository,
  createMemoryMembershipRepository,
  createMemorySessionRepository,
  createMemoryUserRepository,
  createMembershipRecord,
  createOrganizationRecord,
  createQueuedTokenGenerator,
  createSessionRecord,
  createTestAuthConfig,
  createUserRecord,
  RAW_CSRF_TOKEN,
  RAW_SESSION_TOKEN,
  ROTATED_CSRF_TOKEN,
} from './test-helper.js';

describe('read session use case', () => {
  it('reissues CSRF without rotating the Session token', async () => {
    const user = createUserRecord({});
    const organization = createOrganizationRecord({ slug: 'readable', name: 'Readable' });
    const membership = createMembershipRecord(organization, user, { role: 'owner' });
    const tokenHash = digestSessionToken(RAW_SESSION_TOKEN);
    const sessions = createMemorySessionRepository([
      createSessionRecord(user, {
        tokenHash,
        csrfTokenHash: digestCsrfToken(RAW_CSRF_TOKEN),
        activeOrganizationId: organization.id,
      }),
    ]);
    const readSession = createReadSessionUseCase({
      users: createMemoryUserRepository([user]),
      localCredentials: createMemoryCredentialRepository([createCredentialRecord(user)]),
      sessions,
      memberships: createMemoryMembershipRepository([{ organization, membership }]),
      tokens: createQueuedTokenGenerator([ROTATED_CSRF_TOKEN]),
      clock: createAdjustableClock(),
      auth: createTestAuthConfig(),
      logger: createCollectingLogger().logger,
    });

    const result = await readSession.execute({ sessionToken: RAW_SESSION_TOKEN });
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    expect(result.value.csrfToken).toBe(ROTATED_CSRF_TOKEN);
    expect(result.value.user).toEqual({ id: user.id, displayName: user.displayName });
    expect(result.value.organization).toEqual({
      id: organization.id,
      slug: 'readable',
      name: 'Readable',
      role: 'owner',
    });
    expect(result.value.session.tokenHash).toBe(tokenHash);
    expect(result.value.session.csrfTokenHash).toBe(digestCsrfToken(ROTATED_CSRF_TOKEN));
    expect(sessions.replaceCsrfCalls).toHaveLength(1);
    expect(JSON.stringify(sessions.replaceCsrfCalls)).not.toContain(ROTATED_CSRF_TOKEN);
    expect(await sessions.findByTokenHash(tokenHash)).toMatchObject({
      csrfTokenHash: digestCsrfToken(ROTATED_CSRF_TOKEN),
    });
  });

  it('finishes an in-flight CSRF rotation before starting another', async () => {
    const user = createUserRecord({});
    const organization = createOrganizationRecord({ slug: 'readable', name: 'Readable' });
    const membership = createMembershipRecord(organization, user, { role: 'owner' });
    const tokenHash = digestSessionToken(RAW_SESSION_TOKEN);
    const sessions = createMemorySessionRepository([
      createSessionRecord(user, {
        tokenHash,
        csrfTokenHash: digestCsrfToken(RAW_CSRF_TOKEN),
        activeOrganizationId: organization.id,
      }),
    ]);
    let replacements = 0;
    let releaseFirst: () => void = () => undefined;
    const firstEntered = new Promise<void>((resolve) => {
      releaseFirst = resolve;
    });
    let releaseReplacement: () => void = () => undefined;
    const replacementGate = new Promise<void>((resolve) => {
      releaseReplacement = resolve;
    });
    const readSession = createReadSessionUseCase({
      users: createMemoryUserRepository([user]),
      localCredentials: createMemoryCredentialRepository([createCredentialRecord(user)]),
      sessions: {
        ...sessions,
        async replaceCsrfToken(input) {
          replacements += 1;
          if (replacements === 1) {
            releaseFirst();
            await replacementGate;
          }
          return sessions.replaceCsrfToken(input);
        },
      },
      memberships: createMemoryMembershipRepository([{ organization, membership }]),
      tokens: createQueuedTokenGenerator([ROTATED_CSRF_TOKEN, 'second-rotated-csrf-token']),
      clock: createAdjustableClock(),
      auth: createTestAuthConfig(),
      logger: createCollectingLogger().logger,
    });

    const first = readSession.execute({ sessionToken: RAW_SESSION_TOKEN });
    await firstEntered;
    const second = readSession.execute({ sessionToken: RAW_SESSION_TOKEN });
    await Promise.resolve();
    expect(replacements).toBe(1);
    releaseReplacement();
    const [firstResult, secondResult] = await Promise.all([first, second]);
    expect(firstResult.ok && secondResult.ok).toBe(true);
    if (!firstResult.ok || !secondResult.ok) {
      return;
    }
    expect(firstResult.value.csrfToken).toBe(ROTATED_CSRF_TOKEN);
    expect(secondResult.value.csrfToken).toBe('second-rotated-csrf-token');
    expect(await sessions.findByTokenHash(tokenHash)).toMatchObject({
      csrfTokenHash: digestCsrfToken('second-rotated-csrf-token'),
    });
  });

  it('rejects a missing Session', async () => {
    const readSession = createReadSessionUseCase({
      users: createMemoryUserRepository(),
      localCredentials: createMemoryCredentialRepository(),
      sessions: createMemorySessionRepository(),
      memberships: createMemoryMembershipRepository(),
      tokens: createQueuedTokenGenerator([ROTATED_CSRF_TOKEN]),
      clock: createAdjustableClock(),
      auth: createTestAuthConfig(),
      logger: createCollectingLogger().logger,
    });
    await expect(readSession.execute({ sessionToken: RAW_SESSION_TOKEN })).resolves.toEqual({
      ok: false,
      error: AUTHENTICATION_REQUIRED,
    });
  });
});
