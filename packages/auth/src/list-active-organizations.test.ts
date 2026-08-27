import { describe, expect, it } from 'vitest';

import { AUTHENTICATION_REQUIRED } from './errors.js';
import { createListActiveOrganizationsUseCase } from './list-active-organizations.js';
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
} from './test-helper.js';

describe('list active organizations use case', () => {
  it('lists only active Memberships in active Organizations for the Session User', async () => {
    const user = createUserRecord({});
    const other = createUserRecord({ email: 'other@synthetic.patchpilot.test' });
    const active = createOrganizationRecord({ slug: 'active-org', name: 'Active' });
    const archived = createOrganizationRecord({
      slug: 'archived-org',
      name: 'Archived',
      status: 'archived',
    });
    const extra = createOrganizationRecord({ slug: 'extra-org', name: 'Extra' });
    const otherOrg = createOrganizationRecord({ slug: 'other-org', name: 'Other' });
    const sessions = createMemorySessionRepository([
      createSessionRecord(user, {
        tokenHash: digestSessionToken(RAW_SESSION_TOKEN),
        csrfTokenHash: digestCsrfToken(RAW_CSRF_TOKEN),
        activeOrganizationId: null,
      }),
    ]);
    const listOrganizations = createListActiveOrganizationsUseCase({
      users: createMemoryUserRepository([user, other]),
      localCredentials: createMemoryCredentialRepository([createCredentialRecord(user)]),
      sessions,
      memberships: createMemoryMembershipRepository([
        {
          organization: active,
          membership: createMembershipRecord(active, user, { role: 'owner' }),
        },
        {
          organization: extra,
          membership: createMembershipRecord(extra, user, { role: 'member', status: 'revoked' }),
        },
        {
          organization: archived,
          membership: createMembershipRecord(archived, user, { role: 'member' }),
        },
        {
          organization: otherOrg,
          membership: createMembershipRecord(otherOrg, other, { role: 'viewer' }),
        },
      ]),
      clock: createAdjustableClock(),
      auth: createTestAuthConfig(),
      logger: createCollectingLogger().logger,
    });

    const result = await listOrganizations.execute({ sessionToken: RAW_SESSION_TOKEN });
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    expect(result.value).toEqual([
      {
        organizationId: active.id,
        name: 'Active',
        slug: 'active-org',
        membershipId: expect.any(String),
        role: 'owner',
      },
    ]);
  });

  it('requires a valid Session', async () => {
    const user = createUserRecord({});
    const listOrganizations = createListActiveOrganizationsUseCase({
      users: createMemoryUserRepository([user]),
      localCredentials: createMemoryCredentialRepository([createCredentialRecord(user)]),
      sessions: createMemorySessionRepository(),
      memberships: createMemoryMembershipRepository(),
      clock: createAdjustableClock(),
      auth: createTestAuthConfig(),
      logger: createCollectingLogger().logger,
    });
    await expect(listOrganizations.execute({ sessionToken: RAW_SESSION_TOKEN })).resolves.toEqual({
      ok: false,
      error: AUTHENTICATION_REQUIRED,
    });
  });
});
