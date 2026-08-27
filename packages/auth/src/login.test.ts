import { describe, expect, it } from 'vitest';

import { addSeconds } from './clock.js';
import { DUMMY_ARGON2ID_PHC } from './dummy-phc.js';
import { LOGIN_UNAVAILABLE, PUBLIC_LOGIN_FAILURE } from './errors.js';
import { createFakeLoginRateLimiter } from './fake-login-rate-limiter.js';
import { createLoginUseCase } from './login.js';
import { digestCsrfToken, digestLoginAccount, digestSessionToken } from './token-digests.js';
import {
  createAdjustableClock,
  createCollectingLogger,
  createCredentialRecord,
  createFakePasswordHasher,
  createMemoryCredentialRepository,
  createMemoryMembershipRepository,
  createMemorySessionRepository,
  createMemoryUserRepository,
  createMembershipRecord,
  createOrganizationRecord,
  createQueuedTokenGenerator,
  createTestAuthConfig,
  createUserRecord,
  RAW_CSRF_TOKEN,
  RAW_SESSION_TOKEN,
  STORED_PASSWORD_HASH,
  TEST_NOW_ISO,
  TEST_PEER_IP,
  VALID_PASSWORD,
  type FakePasswordHasher,
} from './test-helper.js';

function loginHarness(options?: {
  includeUser?: boolean;
  disabled?: boolean;
  needsRehash?: boolean;
  membershipCount?: 0 | 1 | 2;
  limiterUnavailable?: boolean;
}) {
  const user = createUserRecord({
    status: options?.disabled === true ? 'disabled' : 'active',
  });
  const organizations = [
    createOrganizationRecord({ slug: 'org-one', name: 'One' }),
    createOrganizationRecord({ slug: 'org-two', name: 'Two' }),
  ];
  const membershipCount = options?.membershipCount ?? 0;
  const memberships = organizations.slice(0, membershipCount).map((organization, index) => ({
    organization,
    membership: createMembershipRecord(organization, user, {
      role: index === 0 ? 'owner' : 'member',
    }),
  }));
  const hasher = createFakePasswordHasher({ needsRehashResult: options?.needsRehash ?? false });
  const tokens = createQueuedTokenGenerator([RAW_SESSION_TOKEN, RAW_CSRF_TOKEN]);
  const clock = createAdjustableClock();
  const logs = createCollectingLogger();
  const users = createMemoryUserRepository(options?.includeUser === false ? [] : [user]);
  const credentials = createMemoryCredentialRepository(
    options?.includeUser === false ? [] : [createCredentialRecord(user)],
  );
  const sessions = createMemorySessionRepository();
  const membershipRepo = createMemoryMembershipRepository(memberships);
  const auth = createTestAuthConfig();
  const limiter = createFakeLoginRateLimiter({
    auth,
    logger: logs.logger,
    clock,
    ...(options?.limiterUnavailable === true ? { unavailable: true } : {}),
  });
  const login = createLoginUseCase({
    users,
    localCredentials: credentials,
    sessions,
    memberships: membershipRepo,
    hasher,
    tokens,
    clock,
    auth,
    logger: logs.logger,
    limiter,
  });
  return {
    login,
    user,
    hasher,
    tokens,
    clock,
    logs,
    credentials,
    sessions,
    memberships,
    auth,
    organizations,
    limiter,
  };
}

function expectSecretSilence(output: string, hasher: FakePasswordHasher, password: string): void {
  expect(output).not.toContain(password);
  expect(output).not.toContain(DUMMY_ARGON2ID_PHC);
  expect(output).not.toContain(STORED_PASSWORD_HASH);
  expect(output).not.toContain(RAW_SESSION_TOKEN);
  expect(output).not.toContain(RAW_CSRF_TOKEN);
  for (const call of hasher.verifyCalls) {
    expect(output).not.toContain(call.passwordHash);
  }
  for (const hash of hasher.hashCalls) {
    expect(output).not.toContain(hash);
  }
}

describe('login use case', () => {
  it('issues digest-only Session rows for a valid password', async () => {
    const harness = loginHarness({ membershipCount: 1 });
    const result = await harness.login.execute({
      email: harness.user.email,
      password: VALID_PASSWORD,
      peerIp: TEST_PEER_IP,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    expect(result.value.tokens.sessionToken).toBe(RAW_SESSION_TOKEN);
    expect(result.value.tokens.csrfToken).toBe(RAW_CSRF_TOKEN);
    expect(result.value.actor.userId).toBe(harness.user.id);
    expect(result.value.actor.organizationId).toBe(harness.organizations[0]?.id);
    expect(harness.hasher.verifyCalls).toEqual([
      { passwordHash: STORED_PASSWORD_HASH, password: VALID_PASSWORD },
    ]);
    expect(harness.hasher.needsRehashCalls).toEqual([STORED_PASSWORD_HASH]);
    expect(harness.hasher.hashCalls).toEqual([]);
    expect(harness.sessions.createCalls).toHaveLength(1);
    const persisted = harness.sessions.createCalls[0];
    expect(persisted?.tokenHash).toBe(digestSessionToken(RAW_SESSION_TOKEN));
    expect(persisted?.csrfTokenHash).toBe(digestCsrfToken(RAW_CSRF_TOKEN));
    expect(JSON.stringify(persisted)).not.toContain(RAW_SESSION_TOKEN);
    expect(JSON.stringify(persisted)).not.toContain(RAW_CSRF_TOKEN);
    expect(persisted?.lastSeenAt).toEqual(new Date(TEST_NOW_ISO));
    expect(persisted?.idleExpiresAt).toEqual(addSeconds(new Date(TEST_NOW_ISO), 43_200));
    expect(persisted?.absoluteExpiresAt).toEqual(addSeconds(new Date(TEST_NOW_ISO), 604_800));
    expect(persisted?.passwordRevision).toBe(1);
    expectSecretSilence(harness.logs.text(), harness.hasher, VALID_PASSWORD);
  });

  it('performs exactly one dummy verification for an unknown email', async () => {
    const harness = loginHarness({ includeUser: false });
    const result = await harness.login.execute({
      email: 'missing@synthetic.patchpilot.test',
      password: VALID_PASSWORD,
      peerIp: TEST_PEER_IP,
    });
    expect(result).toEqual({ ok: false, error: PUBLIC_LOGIN_FAILURE });
    expect(harness.hasher.verifyCalls).toEqual([
      { passwordHash: DUMMY_ARGON2ID_PHC, password: VALID_PASSWORD },
    ]);
    expect(harness.hasher.needsRehashCalls).toEqual([]);
    expect(harness.sessions.createCalls).toEqual([]);
    expectSecretSilence(harness.logs.text(), harness.hasher, VALID_PASSWORD);
  });

  it('performs exactly one real verification for a wrong password', async () => {
    const harness = loginHarness();
    const result = await harness.login.execute({
      email: harness.user.email,
      password: 'wrong-password-12',
      peerIp: TEST_PEER_IP,
    });
    expect(result).toEqual({ ok: false, error: PUBLIC_LOGIN_FAILURE });
    expect(harness.hasher.verifyCalls).toEqual([
      { passwordHash: STORED_PASSWORD_HASH, password: 'wrong-password-12' },
    ]);
    expect(harness.hasher.needsRehashCalls).toEqual([]);
    expect(harness.sessions.createCalls).toEqual([]);
  });

  it('returns the same public failure for a disabled User after one real verification', async () => {
    const harness = loginHarness({ disabled: true });
    const result = await harness.login.execute({
      email: harness.user.email,
      password: VALID_PASSWORD,
      peerIp: TEST_PEER_IP,
    });
    expect(result).toEqual({ ok: false, error: PUBLIC_LOGIN_FAILURE });
    expect(harness.hasher.verifyCalls).toEqual([
      { passwordHash: STORED_PASSWORD_HASH, password: VALID_PASSWORD },
    ]);
    expect(harness.hasher.needsRehashCalls).toEqual([]);
    expect(harness.sessions.createCalls).toEqual([]);
  });

  it('uses identical public failures for unknown email, wrong password, and disabled User', async () => {
    const unknown = loginHarness({ includeUser: false });
    const wrong = loginHarness();
    const disabled = loginHarness({ disabled: true });
    const unknownResult = await unknown.login.execute({
      email: 'missing@synthetic.patchpilot.test',
      password: VALID_PASSWORD,
      peerIp: TEST_PEER_IP,
    });
    const wrongResult = await wrong.login.execute({
      email: wrong.user.email,
      password: 'wrong-password-12',
      peerIp: TEST_PEER_IP,
    });
    const disabledResult = await disabled.login.execute({
      email: disabled.user.email,
      password: VALID_PASSWORD,
      peerIp: TEST_PEER_IP,
    });
    expect(unknownResult).toEqual(wrongResult);
    expect(wrongResult).toEqual(disabledResult);
    expect(unknownResult).toEqual({ ok: false, error: PUBLIC_LOGIN_FAILURE });
    if (!unknownResult.ok && !wrongResult.ok && !disabledResult.ok) {
      expect(unknownResult.error).toBe(PUBLIC_LOGIN_FAILURE);
      expect(wrongResult.error).toBe(PUBLIC_LOGIN_FAILURE);
      expect(disabledResult.error).toBe(PUBLIC_LOGIN_FAILURE);
    }
  });

  it('rejects passwords below the configured minimum character count before hashing', async () => {
    const harness = loginHarness();
    const result = await harness.login.execute({
      email: harness.user.email,
      password: 'shortpass11',
      peerIp: TEST_PEER_IP,
    });
    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }
    expect(result.error.code).toBe('validation');
    expect(result.error.message).toContain('12');
    expect(harness.hasher.verifyCalls).toEqual([]);
    expect(harness.sessions.createCalls).toEqual([]);
  });

  it('rejects passwords above the maximum UTF-8 byte count before Argon2', async () => {
    const harness = loginHarness();
    const password = 'é'.repeat(65);
    expect(Array.from(password).length).toBe(65);
    expect(Buffer.byteLength(password, 'utf8')).toBe(130);
    const result = await harness.login.execute({
      email: harness.user.email,
      password,
      peerIp: TEST_PEER_IP,
    });
    expect(result.ok).toBe(false);
    if (result.ok) {
      return;
    }
    expect(result.error.code).toBe('validation');
    expect(result.error.message).toContain('128');
    expect(harness.hasher.verifyCalls).toEqual([]);
  });

  it('skips rehash when needsRehash is false', async () => {
    const harness = loginHarness();
    const result = await harness.login.execute({
      email: harness.user.email,
      password: VALID_PASSWORD,
      peerIp: TEST_PEER_IP,
    });
    expect(result.ok).toBe(true);
    expect(harness.hasher.needsRehashCalls).toEqual([STORED_PASSWORD_HASH]);
    expect(harness.hasher.hashCalls).toEqual([]);
    expect(harness.credentials.updateCalls).toEqual([]);
    expect(harness.sessions.createCalls[0]?.passwordRevision).toBe(1);
  });

  it('rehashes and updates passwordRevision only after successful verification', async () => {
    const harness = loginHarness({ needsRehash: true });
    const result = await harness.login.execute({
      email: harness.user.email,
      password: VALID_PASSWORD,
      peerIp: TEST_PEER_IP,
    });
    expect(result.ok).toBe(true);
    expect(harness.hasher.verifyCalls).toHaveLength(1);
    expect(harness.hasher.hashCalls).toEqual([VALID_PASSWORD]);
    expect(harness.credentials.updateCalls).toEqual([
      {
        userId: harness.user.id,
        passwordHash: '$argon2id$v=19$m=8192,p=1,t=1$rehashed-1',
        passwordRevision: 2,
      },
    ]);
    expect(harness.sessions.createCalls[0]?.passwordRevision).toBe(2);
    expect(JSON.stringify(harness.credentials.updateCalls)).not.toContain(VALID_PASSWORD);
  });

  it('leaves Organization null when the User has zero active Memberships', async () => {
    const harness = loginHarness({ membershipCount: 0 });
    const result = await harness.login.execute({
      email: harness.user.email,
      password: VALID_PASSWORD,
      peerIp: TEST_PEER_IP,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    expect(result.value.actor.organizationId).toBeNull();
    expect(harness.sessions.createCalls[0]?.activeOrganizationId).toBeUndefined();
  });

  it('auto-selects Organization when exactly one active Membership exists', async () => {
    const harness = loginHarness({ membershipCount: 1 });
    const result = await harness.login.execute({
      email: harness.user.email,
      password: VALID_PASSWORD,
      peerIp: TEST_PEER_IP,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    expect(result.value.actor.organizationId).toBe(harness.organizations[0]?.id);
    expect(result.value.actor.role).toBe('owner');
    expect(harness.sessions.createCalls[0]?.activeOrganizationId).toBe(
      harness.organizations[0]?.id,
    );
  });

  it('does not auto-select when multiple active Memberships exist', async () => {
    const harness = loginHarness({ membershipCount: 2 });
    const result = await harness.login.execute({
      email: harness.user.email,
      password: VALID_PASSWORD,
      peerIp: TEST_PEER_IP,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    expect(result.value.actor.organizationId).toBeNull();
    expect(harness.sessions.createCalls[0]?.activeOrganizationId).toBeUndefined();
  });

  it('fails closed on limiter outage without revealing account existence', async () => {
    const known = loginHarness({ limiterUnavailable: true });
    const unknown = loginHarness({ includeUser: false, limiterUnavailable: true });
    const knownResult = await known.login.execute({
      email: known.user.email,
      password: VALID_PASSWORD,
      peerIp: TEST_PEER_IP,
    });
    const unknownResult = await unknown.login.execute({
      email: 'missing@synthetic.patchpilot.test',
      password: VALID_PASSWORD,
      peerIp: TEST_PEER_IP,
    });
    expect(knownResult).toEqual(unknownResult);
    expect(knownResult).toEqual({ ok: false, error: LOGIN_UNAVAILABLE });
    expect(known.hasher.verifyCalls).toEqual([]);
    expect(unknown.hasher.verifyCalls).toEqual([]);
    expect(known.sessions.createCalls).toEqual([]);
    expect(JSON.stringify(known.limiter.consumeCalls)).not.toContain(VALID_PASSWORD);
    expect(JSON.stringify(known.limiter.incrementKeys).toLowerCase()).not.toContain(
      known.user.email.toLowerCase(),
    );
  });

  it('does not pass password, Session token, or CSRF token to the limiter', async () => {
    const harness = loginHarness();
    await harness.login.execute({
      email: harness.user.email,
      password: VALID_PASSWORD,
      peerIp: TEST_PEER_IP,
    });
    expect(harness.limiter.consumeCalls).toEqual([
      { peerIp: TEST_PEER_IP, accountDigest: digestLoginAccount(harness.user.email) },
    ]);
    const serialized = JSON.stringify(harness.limiter.consumeCalls);
    expect(serialized).not.toContain(VALID_PASSWORD);
    expect(serialized).not.toContain(RAW_SESSION_TOKEN);
    expect(serialized).not.toContain(RAW_CSRF_TOKEN);
    expect(serialized).not.toContain(harness.user.email);
  });
});
