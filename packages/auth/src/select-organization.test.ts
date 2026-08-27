import { describe, expect, it } from 'vitest';

import { AUTHENTICATION_REQUIRED, ORGANIZATION_NOT_FOUND } from './errors.js';
import { createSelectOrganizationUseCase } from './select-organization.js';
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
  createQueuedTokenGenerator,
  createSessionRecord,
  createTestAuthConfig,
  createUserRecord,
  RAW_CSRF_TOKEN,
  RAW_SESSION_TOKEN,
  ROTATED_CSRF_TOKEN,
  ROTATED_SESSION_TOKEN,
} from './test-helper.js';

function selectHarness(options?: { includeMembership?: boolean }) {
  const user = createUserRecord({});
  const selected = createOrganizationRecord({ slug: 'selectable', name: 'Selectable' });
  const other = createOrganizationRecord({ slug: 'foreign', name: 'Foreign' });
  const membership = createMembershipRecord(selected, user, { role: 'member' });
  const tokenHash = digestSessionToken(RAW_SESSION_TOKEN);
  const session = createSessionRecord(user, {
    tokenHash,
    csrfTokenHash: digestCsrfToken(RAW_CSRF_TOKEN),
    activeOrganizationId: null,
  });
  const clock = createAdjustableClock();
  const logs = createCollectingLogger();
  const auth = createTestAuthConfig();
  const users = createMemoryUserRepository([user]);
  const credentials = createMemoryCredentialRepository([createCredentialRecord(user)]);
  const sessions = createMemorySessionRepository([session]);
  const memberships = createMemoryMembershipRepository(
    options?.includeMembership === false ? [] : [{ organization: selected, membership }],
  );
  const tokens = createQueuedTokenGenerator([
    ROTATED_SESSION_TOKEN,
    ROTATED_CSRF_TOKEN,
    'RAW_LOSER_SESSION_TOKEN_NOT_DIGEST',
    'RAW_LOSER_CSRF_TOKEN_NOT_A_DIGEST',
  ]);
  const shared = {
    users,
    localCredentials: credentials,
    sessions,
    memberships,
    clock,
    auth,
    logger: logs.logger,
  };
  const selectOrganization = createSelectOrganizationUseCase({
    ...shared,
    tokens,
  });
  const resolveSession = createResolveSessionUseCase(shared);
  return {
    selectOrganization,
    resolveSession,
    sessions,
    selected,
    other,
    user,
    membership,
    tokens,
  };
}

describe('select organization use case', () => {
  it('selects an authorized Organization and rotates Session and CSRF tokens', async () => {
    const harness = selectHarness();
    const result = await harness.selectOrganization.execute({
      sessionToken: RAW_SESSION_TOKEN,
      organizationId: harness.selected.id,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    expect(result.value.tokens.sessionToken).toBe(ROTATED_SESSION_TOKEN);
    expect(result.value.tokens.csrfToken).toBe(ROTATED_CSRF_TOKEN);
    expect(result.value.actor.organizationId).toBe(harness.selected.id);
    expect(result.value.actor.role).toBe('member');
    expect(harness.sessions.rotateCalls).toHaveLength(1);
    const rotate = harness.sessions.rotateCalls[0];
    expect(rotate?.currentTokenHash).toBe(digestSessionToken(RAW_SESSION_TOKEN));
    expect(rotate?.nextTokenHash).toBe(digestSessionToken(ROTATED_SESSION_TOKEN));
    expect(rotate?.nextCsrfTokenHash).toBe(digestCsrfToken(ROTATED_CSRF_TOKEN));
    expect(rotate?.activeOrganizationId).toBe(harness.selected.id);
    expect(JSON.stringify(rotate)).not.toContain(RAW_SESSION_TOKEN);
    expect(JSON.stringify(rotate)).not.toContain(ROTATED_SESSION_TOKEN);
    expect(
      await harness.sessions.findByTokenHash(digestSessionToken(RAW_SESSION_TOKEN)),
    ).toBeUndefined();
    expect(
      (await harness.sessions.findByTokenHash(digestSessionToken(ROTATED_SESSION_TOKEN)))
        ?.csrfTokenHash,
    ).toBe(digestCsrfToken(ROTATED_CSRF_TOKEN));
  });

  it('returns tenant-safe not-found for unauthorized Organization selection', async () => {
    const harness = selectHarness();
    const result = await harness.selectOrganization.execute({
      sessionToken: RAW_SESSION_TOKEN,
      organizationId: harness.other.id,
    });
    expect(result).toEqual({ ok: false, error: ORGANIZATION_NOT_FOUND });
    expect(harness.sessions.rotateCalls).toEqual([]);
    expect(
      await harness.sessions.findByTokenHash(digestSessionToken(RAW_SESSION_TOKEN)),
    ).toBeDefined();
  });

  it('rejects the old digest after rotation', async () => {
    const harness = selectHarness();
    const selected = await harness.selectOrganization.execute({
      sessionToken: RAW_SESSION_TOKEN,
      organizationId: harness.selected.id,
    });
    expect(selected.ok).toBe(true);
    await expect(
      harness.resolveSession.execute({ sessionToken: RAW_SESSION_TOKEN }),
    ).resolves.toEqual({ ok: false, error: AUTHENTICATION_REQUIRED });
    const resolved = await harness.resolveSession.execute({
      sessionToken: ROTATED_SESSION_TOKEN,
    });
    expect(resolved.ok).toBe(true);
  });

  it('treats the concurrent rotation loser as unauthenticated', async () => {
    const harness = selectHarness();
    const first = harness.selectOrganization.execute({
      sessionToken: RAW_SESSION_TOKEN,
      organizationId: harness.selected.id,
    });
    const second = harness.selectOrganization.execute({
      sessionToken: RAW_SESSION_TOKEN,
      organizationId: harness.selected.id,
    });
    const [winner, loser] = await Promise.all([first, second]);
    const outcomes = [winner, loser];
    expect(outcomes.filter((outcome) => outcome.ok)).toHaveLength(1);
    expect(outcomes.filter((outcome) => !outcome.ok)).toEqual([
      { ok: false, error: AUTHENTICATION_REQUIRED },
    ]);
    expect(
      await harness.sessions.findByTokenHash(digestSessionToken(RAW_SESSION_TOKEN)),
    ).toBeUndefined();
  });
});
