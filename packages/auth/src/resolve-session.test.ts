import { describe, expect, it } from 'vitest';

import { addSeconds } from './clock.js';
import { AUTHENTICATION_REQUIRED } from './errors.js';
import { createResolveSessionUseCase } from './resolve-session.js';
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
  createSessionRecord,
  createTestAuthConfig,
  createUserRecord,
  RAW_CSRF_TOKEN,
  RAW_SESSION_TOKEN,
  TEST_NOW_ISO,
} from './test-helper.js';

function resolveHarness(options?: {
  revoked?: boolean;
  idleExpiresAt?: Date;
  absoluteExpiresAt?: Date;
  passwordRevision?: number;
  credentialRevision?: number;
  disabledAfterCreate?: boolean;
  membershipStatus?: 'active' | 'revoked';
  organizationStatus?: 'active' | 'archived';
  activeOrganization?: boolean;
}) {
  const user = createUserRecord({
    status: options?.disabledAfterCreate === true ? 'disabled' : 'active',
  });
  const organization = createOrganizationRecord({
    status: options?.organizationStatus ?? 'active',
  });
  const membership = createMembershipRecord(organization, user, {
    status: options?.membershipStatus ?? 'active',
    role: 'admin',
  });
  const tokenHash = digestSessionToken(RAW_SESSION_TOKEN);
  const session = createSessionRecord(user, {
    tokenHash,
    csrfTokenHash: digestCsrfToken(RAW_CSRF_TOKEN),
    activeOrganizationId: options?.activeOrganization === false ? null : organization.id,
    passwordRevision: options?.passwordRevision ?? 1,
    lastSeenAt: new Date(TEST_NOW_ISO),
    idleExpiresAt: options?.idleExpiresAt ?? addSeconds(new Date(TEST_NOW_ISO), 43_200),
    absoluteExpiresAt: options?.absoluteExpiresAt ?? addSeconds(new Date(TEST_NOW_ISO), 604_800),
    revokedAt: options?.revoked === true ? new Date(TEST_NOW_ISO) : null,
    revokeReason: options?.revoked === true ? 'logout' : null,
  });
  const clock = createAdjustableClock();
  const logs = createCollectingLogger();
  const users = createMemoryUserRepository([user]);
  const credentials = createMemoryCredentialRepository([
    createCredentialRecord(user, { passwordRevision: options?.credentialRevision ?? 1 }),
  ]);
  const sessions = createMemorySessionRepository([session]);
  const memberships = createMemoryMembershipRepository([{ organization, membership }]);
  const resolveSession = createResolveSessionUseCase({
    users,
    localCredentials: credentials,
    sessions,
    memberships,
    clock,
    auth: createTestAuthConfig(),
    logger: logs.logger,
  });
  return { resolveSession, user, organization, membership, session, sessions, clock, logs };
}

describe('resolve session use case', () => {
  it('builds TrustedActor from persisted Membership and throttles lastSeenAt', async () => {
    const harness = resolveHarness();
    const result = await harness.resolveSession.execute({ sessionToken: RAW_SESSION_TOKEN });
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    expect(result.value.actor.userId).toBe(harness.user.id);
    expect(result.value.actor.organizationId).toBe(harness.organization.id);
    expect(result.value.actor.role).toBe('admin');
    expect(result.value.session.lastSeenAt).toEqual(new Date(TEST_NOW_ISO));
    const again = await harness.resolveSession.execute({ sessionToken: RAW_SESSION_TOKEN });
    expect(again.ok).toBe(true);
    if (!again.ok) {
      return;
    }
    expect(again.value.session.lastSeenAt).toEqual(new Date(TEST_NOW_ISO));
  });

  it('rejects a revoked Session', async () => {
    const harness = resolveHarness({ revoked: true });
    await expect(
      harness.resolveSession.execute({ sessionToken: RAW_SESSION_TOKEN }),
    ).resolves.toEqual({ ok: false, error: AUTHENTICATION_REQUIRED });
  });

  it('rejects at the idle-expiration boundary and accepts one millisecond before', async () => {
    const idleExpiresAt = new Date(TEST_NOW_ISO);
    const expired = resolveHarness({ idleExpiresAt });
    await expect(
      expired.resolveSession.execute({ sessionToken: RAW_SESSION_TOKEN }),
    ).resolves.toEqual({ ok: false, error: AUTHENTICATION_REQUIRED });

    const live = resolveHarness({ idleExpiresAt });
    live.clock.advanceMs(-1);
    const result = await live.resolveSession.execute({ sessionToken: RAW_SESSION_TOKEN });
    expect(result.ok).toBe(true);
  });

  it('rejects at the absolute-expiration boundary and accepts one millisecond before', async () => {
    const absoluteExpiresAt = new Date(TEST_NOW_ISO);
    const expired = resolveHarness({
      absoluteExpiresAt,
      idleExpiresAt: addSeconds(new Date(TEST_NOW_ISO), 43_200),
    });
    await expect(
      expired.resolveSession.execute({ sessionToken: RAW_SESSION_TOKEN }),
    ).resolves.toEqual({ ok: false, error: AUTHENTICATION_REQUIRED });

    const live = resolveHarness({
      absoluteExpiresAt,
      idleExpiresAt: addSeconds(new Date(TEST_NOW_ISO), 43_200),
    });
    live.clock.advanceMs(-1);
    const result = await live.resolveSession.execute({ sessionToken: RAW_SESSION_TOKEN });
    expect(result.ok).toBe(true);
  });

  it('rejects a password-revision mismatch', async () => {
    const harness = resolveHarness({ passwordRevision: 1, credentialRevision: 2 });
    await expect(
      harness.resolveSession.execute({ sessionToken: RAW_SESSION_TOKEN }),
    ).resolves.toEqual({ ok: false, error: AUTHENTICATION_REQUIRED });
  });

  it('rejects a User disabled after Session creation', async () => {
    const harness = resolveHarness({ disabledAfterCreate: true });
    await expect(
      harness.resolveSession.execute({ sessionToken: RAW_SESSION_TOKEN }),
    ).resolves.toEqual({ ok: false, error: AUTHENTICATION_REQUIRED });
  });

  it('clears Organization context when Membership is revoked', async () => {
    const harness = resolveHarness({ membershipStatus: 'revoked' });
    const result = await harness.resolveSession.execute({ sessionToken: RAW_SESSION_TOKEN });
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    expect(result.value.actor.organizationId).toBeNull();
    expect(result.value.actor.role).toBeNull();
    expect(
      (await harness.sessions.findByTokenHash(digestSessionToken(RAW_SESSION_TOKEN)))
        ?.activeOrganizationId,
    ).toBeNull();
  });

  it('clears Organization context when the Organization is archived', async () => {
    const harness = resolveHarness({ organizationStatus: 'archived' });
    const result = await harness.resolveSession.execute({ sessionToken: RAW_SESSION_TOKEN });
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    expect(result.value.actor.organizationId).toBeNull();
    expect(
      (await harness.sessions.findByTokenHash(digestSessionToken(RAW_SESSION_TOKEN)))
        ?.activeOrganizationId,
    ).toBeNull();
  });

  it('rejects unknown Session tokens without leaking existence', async () => {
    const harness = resolveHarness();
    await expect(
      harness.resolveSession.execute({ sessionToken: 'unknown-raw-session-token' }),
    ).resolves.toEqual({ ok: false, error: AUTHENTICATION_REQUIRED });
  });
});
