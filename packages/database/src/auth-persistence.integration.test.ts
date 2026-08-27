import { createHash, randomUUID } from 'node:crypto';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { PrismaClient } from '@prisma/client';
import { JSON_SCHEMA_VERSION_V1 } from '@patchpilot/domain';

import {
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
} from './integration-database.js';
import { createRepositories } from './repositories.js';

/** Synthetic Argon2id PHC matching node-argon2 0.45.1 layout. Not a login password. */
const SYNTHETIC_ARGON2ID_PHC =
  '$argon2id$v=19$m=19456,p=1,t=2$c3ludGhldGljc2FsdA$c3ludGhldGljaGFzaGZvcmxvY2FsY3JlZGU';
const AUTH_SUBJECT = '00000000-0000-4000-8000-000000000001';
const CREATED_AT = new Date('2026-01-01T00:00:00.000Z');
const IDLE_EXPIRES_AT = new Date('2026-01-01T12:00:00.000Z');
const ABSOLUTE_EXPIRES_AT = new Date('2026-01-08T00:00:00.000Z');

function sha256Hex(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function uniqueEmail(label: string): string {
  return `${label}-${randomUUID().slice(0, 8)}@synthetic.patchpilot.test`;
}

describe('authentication persistence', () => {
  let databaseName: string;
  let admin: PrismaClient;
  let prisma: PrismaClient;

  beforeAll(async () => {
    const ephemeral = await createEphemeralDatabase('it');
    databaseName = ephemeral.databaseName;
    admin = ephemeral.admin;
    await deployMigrations(ephemeral.databaseUrl);
    prisma = new PrismaClient({
      datasources: { db: { url: ephemeral.databaseUrl } },
    });
  });

  afterAll(async () => {
    if (prisma !== undefined) {
      await prisma.$disconnect();
    }
    if (admin !== undefined && databaseName !== undefined) {
      await dropEphemeralDatabase(admin, databaseName);
    }
  });

  async function createUser(email = uniqueEmail('user')) {
    return prisma.user.create({ data: { email, displayName: email } });
  }

  async function createOrg(slug = `org-${randomUUID().slice(0, 8)}`) {
    return prisma.organization.create({ data: { slug, name: `Org ${slug}` } });
  }

  async function validSessionData(userId: string, suffix: string) {
    return {
      userId,
      tokenHash: sha256Hex(`synth-session-${suffix}`),
      csrfTokenHash: sha256Hex(`synth-csrf-${suffix}`),
      passwordRevision: 1,
      createdAt: CREATED_AT,
      lastSeenAt: CREATED_AT,
      idleExpiresAt: IDLE_EXPIRES_AT,
      absoluteExpiresAt: ABSOLUTE_EXPIRES_AT,
    };
  }

  describe('LocalCredential', () => {
    it('accepts a synthetic Argon2id PHC and rejects invalid hashes and revisions', async () => {
      expect(SYNTHETIC_ARGON2ID_PHC.startsWith('$argon2id$')).toBe(true);
      expect(SYNTHETIC_ARGON2ID_PHC.length).toBeGreaterThanOrEqual(48);

      const user = await createUser();
      const credential = await prisma.localCredential.create({
        data: { userId: user.id, passwordHash: SYNTHETIC_ARGON2ID_PHC },
      });
      expect(credential.algorithm).toBe('argon2id');
      expect(credential.passwordRevision).toBe(1);

      const argon2i = SYNTHETIC_ARGON2ID_PHC.replace('$argon2id$', '$argon2i$');
      await expect(
        prisma.localCredential.create({
          data: {
            userId: (await createUser()).id,
            passwordHash: argon2i,
          },
        }),
      ).rejects.toThrow();
      await expect(
        prisma.localCredential.create({
          data: {
            userId: (await createUser()).id,
            passwordHash: 'not-a-phc-string-but-long-enough-to-look-plausible-xx',
          },
        }),
      ).rejects.toThrow();
      await expect(
        prisma.localCredential.create({
          data: {
            userId: (await createUser()).id,
            passwordHash: SYNTHETIC_ARGON2ID_PHC,
            passwordRevision: 0,
          },
        }),
      ).rejects.toThrow();
    });

    it('allows only one credential per User and restricts User deletion', async () => {
      const user = await createUser();
      await prisma.localCredential.create({
        data: { userId: user.id, passwordHash: SYNTHETIC_ARGON2ID_PHC },
      });
      await expect(
        prisma.localCredential.create({
          data: { userId: user.id, passwordHash: SYNTHETIC_ARGON2ID_PHC },
        }),
      ).rejects.toThrow();
      await expect(prisma.user.delete({ where: { id: user.id } })).rejects.toThrow();
    });
  });

  describe('Session', () => {
    it('accepts lowercase digests and rejects malformed or duplicate hashes', async () => {
      const user = await createUser();
      const data = await validSessionData(user.id, randomUUID());
      const created = await prisma.session.create({ data });
      expect(created.tokenHash).toBe(data.tokenHash);
      expect(created.authenticationMethod).toBe('password');

      await expect(
        prisma.session.create({
          data: {
            ...(await validSessionData((await createUser()).id, randomUUID())),
            tokenHash: 'A'.repeat(64),
          },
        }),
      ).rejects.toThrow();
      await expect(
        prisma.session.create({
          data: {
            ...(await validSessionData((await createUser()).id, randomUUID())),
            tokenHash: 'abc',
          },
        }),
      ).rejects.toThrow();
      await expect(
        prisma.session.create({
          data: {
            ...(await validSessionData((await createUser()).id, randomUUID())),
            tokenHash: `${'g'.repeat(64)}`,
          },
        }),
      ).rejects.toThrow();

      const other = await validSessionData((await createUser()).id, randomUUID());
      await expect(
        prisma.session.create({ data: { ...other, tokenHash: data.tokenHash } }),
      ).rejects.toThrow();
      await expect(
        prisma.session.create({ data: { ...other, csrfTokenHash: data.csrfTokenHash } }),
      ).rejects.toThrow();
    });

    it('enforces revision, expiration windows, and revocation consistency', async () => {
      const user = await createUser();
      await expect(
        prisma.session.create({
          data: { ...(await validSessionData(user.id, randomUUID())), passwordRevision: 0 },
        }),
      ).rejects.toThrow();
      await expect(
        prisma.session.create({
          data: {
            ...(await validSessionData((await createUser()).id, randomUUID())),
            absoluteExpiresAt: CREATED_AT,
          },
        }),
      ).rejects.toThrow();
      await expect(
        prisma.session.create({
          data: {
            ...(await validSessionData((await createUser()).id, randomUUID())),
            idleExpiresAt: CREATED_AT,
          },
        }),
      ).rejects.toThrow();
      await expect(
        prisma.session.create({
          data: {
            ...(await validSessionData((await createUser()).id, randomUUID())),
            idleExpiresAt: new Date('2026-01-09T00:00:00.000Z'),
          },
        }),
      ).rejects.toThrow();
      await expect(
        prisma.session.create({
          data: {
            ...(await validSessionData((await createUser()).id, randomUUID())),
            lastSeenAt: new Date('2025-12-31T23:59:59.000Z'),
          },
        }),
      ).rejects.toThrow();
      await expect(
        prisma.session.create({
          data: {
            ...(await validSessionData((await createUser()).id, randomUUID())),
            lastSeenAt: new Date('2026-01-09T00:00:00.000Z'),
          },
        }),
      ).rejects.toThrow();

      const revocable = await prisma.session.create({
        data: await validSessionData((await createUser()).id, randomUUID()),
      });
      await expect(
        prisma.session.update({
          where: { id: revocable.id },
          data: { revokedAt: new Date('2026-01-02T00:00:00.000Z') },
        }),
      ).rejects.toThrow();
      await expect(
        prisma.session.update({
          where: { id: revocable.id },
          data: { revokeReason: 'logout' },
        }),
      ).rejects.toThrow();
      await expect(
        prisma.session.update({
          where: { id: revocable.id },
          data: { revokedAt: new Date('2026-01-02T00:00:00.000Z'), revokeReason: 'Logout' },
        }),
      ).rejects.toThrow();
      await expect(
        prisma.session.update({
          where: { id: revocable.id },
          data: {
            revokedAt: new Date('2025-12-31T00:00:00.000Z'),
            revokeReason: 'logout',
          },
        }),
      ).rejects.toThrow();
    });

    it('restricts deleting a User or active Organization referenced by a Session', async () => {
      const user = await createUser();
      const org = await createOrg();
      await prisma.session.create({
        data: { ...(await validSessionData(user.id, randomUUID())), activeOrganizationId: org.id },
      });
      await expect(prisma.user.delete({ where: { id: user.id } })).rejects.toThrow();
      await expect(prisma.organization.delete({ where: { id: org.id } })).rejects.toThrow();
    });
  });

  describe('AuditEvent actors', () => {
    async function appendPayload() {
      return {
        action: `test.auth.${randomUUID().slice(0, 8)}`,
        subjectType: 'auth',
        subjectId: AUTH_SUBJECT,
        correlationId: randomUUID(),
        payload: { schemaVersion: JSON_SCHEMA_VERSION_V1, metadata: {} },
        schemaVersion: JSON_SCHEMA_VERSION_V1,
      };
    }

    it('accepts the approved actor truth table and rejects contradictions', async () => {
      const user = await createUser();
      const org = await createOrg();
      const otherOrg = await createOrg();
      const membership = await prisma.membership.create({
        data: { organizationId: org.id, userId: user.id, role: 'member' },
      });
      const otherUser = await createUser();
      const otherMembership = await prisma.membership.create({
        data: { organizationId: otherOrg.id, userId: otherUser.id, role: 'member' },
      });

      await prisma.auditEvent.create({
        data: { actorType: 'anonymous', ...(await appendPayload()) },
      });
      await expect(
        prisma.auditEvent.create({
          data: { actorType: 'anonymous', actorUserId: user.id, ...(await appendPayload()) },
        }),
      ).rejects.toThrow();
      await expect(
        prisma.auditEvent.create({
          data: { actorType: 'anonymous', organizationId: org.id, ...(await appendPayload()) },
        }),
      ).rejects.toThrow();

      await prisma.auditEvent.create({
        data: { actorType: 'user', actorUserId: user.id, ...(await appendPayload()) },
      });
      await expect(
        prisma.auditEvent.create({
          data: { actorType: 'user', ...(await appendPayload()) },
        }),
      ).rejects.toThrow();

      await prisma.auditEvent.create({
        data: {
          actorType: 'user',
          actorUserId: user.id,
          organizationId: org.id,
          actorMembershipId: membership.id,
          ...(await appendPayload()),
        },
      });
      await expect(
        prisma.auditEvent.create({
          data: {
            actorType: 'user',
            actorUserId: user.id,
            organizationId: org.id,
            ...(await appendPayload()),
          },
        }),
      ).rejects.toThrow();
      await expect(
        prisma.auditEvent.create({
          data: {
            actorType: 'user',
            actorUserId: user.id,
            organizationId: org.id,
            actorMembershipId: otherMembership.id,
            ...(await appendPayload()),
          },
        }),
      ).rejects.toThrow();
      await expect(
        prisma.auditEvent.create({
          data: {
            actorType: 'user',
            actorUserId: otherUser.id,
            organizationId: org.id,
            actorMembershipId: membership.id,
            ...(await appendPayload()),
          },
        }),
      ).rejects.toThrow();

      await prisma.auditEvent.create({
        data: { actorType: 'system', ...(await appendPayload()) },
      });
      await prisma.auditEvent.create({
        data: { actorType: 'system', organizationId: org.id, ...(await appendPayload()) },
      });
      await expect(
        prisma.auditEvent.create({
          data: { actorType: 'system', actorUserId: user.id, ...(await appendPayload()) },
        }),
      ).rejects.toThrow();

      await prisma.auditEvent.create({
        data: { actorType: 'instance_operator', ...(await appendPayload()) },
      });
      await expect(
        prisma.auditEvent.create({
          data: {
            actorType: 'instance_operator',
            actorUserId: user.id,
            ...(await appendPayload()),
          },
        }),
      ).rejects.toThrow();
      await expect(
        prisma.auditEvent.create({
          data: {
            actorType: 'instance_operator',
            organizationId: org.id,
            actorMembershipId: membership.id,
            ...(await appendPayload()),
          },
        }),
      ).rejects.toThrow();
    });

    it('rejects audit UPDATE and DELETE', async () => {
      const created = await prisma.auditEvent.create({
        data: {
          actorType: 'anonymous',
          action: 'auth.login_failed',
          subjectType: 'auth',
          subjectId: AUTH_SUBJECT,
          correlationId: randomUUID(),
          payload: { schemaVersion: JSON_SCHEMA_VERSION_V1, metadata: {} },
          schemaVersion: JSON_SCHEMA_VERSION_V1,
        },
      });
      await expect(
        prisma.auditEvent.update({
          where: { id: created.id },
          data: { action: 'auth.mutated' },
        }),
      ).rejects.toThrow();
      await expect(prisma.auditEvent.delete({ where: { id: created.id } })).rejects.toThrow();
    });
  });

  describe('authentication repositories', () => {
    it('normalizes mixed-case email lookup and returns undefined for unknown email', async () => {
      const email = uniqueEmail('Owner');
      const user = await prisma.user.create({
        data: { email: email.toLowerCase(), displayName: 'Owner' },
      });
      const repos = createRepositories(prisma);
      const found = await repos.users.findByNormalizedEmail(` ${email.toUpperCase()} `);
      expect(found?.id).toBe(user.id);
      expect(await repos.users.findByNormalizedEmail(uniqueEmail('missing'))).toBeUndefined();
    });

    it('stores session digests only and rejects invalid digests before persistence', async () => {
      const user = await createUser();
      const rawSession = `raw-session-token-not-stored-${randomUUID()}`;
      const rawCsrf = `raw-csrf-token-not-stored-${randomUUID()}`;
      const repos = createRepositories(prisma);
      const created = await repos.sessions.create({
        userId: user.id,
        tokenHash: sha256Hex(rawSession),
        csrfTokenHash: sha256Hex(rawCsrf),
        passwordRevision: 1,
        lastSeenAt: CREATED_AT,
        idleExpiresAt: IDLE_EXPIRES_AT,
        absoluteExpiresAt: ABSOLUTE_EXPIRES_AT,
      });
      expect(created.tokenHash).toBe(sha256Hex(rawSession));
      expect(created.csrfTokenHash).toBe(sha256Hex(rawCsrf));
      const stored = await prisma.session.findUniqueOrThrow({ where: { id: created.id } });
      expect(JSON.stringify(stored)).not.toContain(rawSession);
      expect(JSON.stringify(stored)).not.toContain(rawCsrf);
      expect(await repos.sessions.findByTokenHash(created.tokenHash)).toEqual(created);
      await expect(repos.sessions.findByTokenHash('ABC')).rejects.toThrow(/64 lowercase/);
      await expect(
        repos.sessions.create({
          userId: user.id,
          tokenHash: 'not-a-digest',
          csrfTokenHash: sha256Hex('other-csrf'),
          passwordRevision: 1,
          lastSeenAt: CREATED_AT,
          idleExpiresAt: IDLE_EXPIRES_AT,
          absoluteExpiresAt: ABSOLUTE_EXPIRES_AT,
        }),
      ).rejects.toThrow(/64 lowercase/);
    });

    it('throttles lastSeen updates, rotates atomically, and revokes by digest or User', async () => {
      const user = await createUser();
      const other = await createUser();
      const org = await createOrg();
      const repos = createRepositories(prisma);
      const firstHash = sha256Hex(`rotate-old-${randomUUID()}`);
      await repos.sessions.create({
        userId: user.id,
        tokenHash: firstHash,
        csrfTokenHash: sha256Hex(`rotate-csrf-${randomUUID()}`),
        passwordRevision: 1,
        lastSeenAt: CREATED_AT,
        idleExpiresAt: IDLE_EXPIRES_AT,
        absoluteExpiresAt: ABSOLUTE_EXPIRES_AT,
        activeOrganizationId: org.id,
      });
      const otherSession = await repos.sessions.create({
        userId: other.id,
        tokenHash: sha256Hex(`other-${randomUUID()}`),
        csrfTokenHash: sha256Hex(`other-csrf-${randomUUID()}`),
        passwordRevision: 1,
        lastSeenAt: CREATED_AT,
        idleExpiresAt: IDLE_EXPIRES_AT,
        absoluteExpiresAt: ABSOLUTE_EXPIRES_AT,
      });

      const seen = new Date('2026-01-01T00:01:00.000Z');
      const firstSeen = await repos.sessions.updateThrottledLastSeen({
        tokenHash: firstHash,
        lastSeenAt: seen,
        idleExpiresAt: new Date('2026-01-01T12:01:00.000Z'),
        minLastSeenAt: seen,
      });
      expect(firstSeen?.lastSeenAt).toEqual(seen);
      const secondSeen = await repos.sessions.updateThrottledLastSeen({
        tokenHash: firstHash,
        lastSeenAt: new Date('2026-01-01T00:01:30.000Z'),
        idleExpiresAt: new Date('2026-01-01T12:01:30.000Z'),
        minLastSeenAt: CREATED_AT,
      });
      expect(secondSeen).toBeUndefined();

      const nextA = sha256Hex(`rotate-a-${randomUUID()}`);
      const nextB = sha256Hex(`rotate-b-${randomUUID()}`);
      const csrfA = sha256Hex(`rotate-csrf-a-${randomUUID()}`);
      const csrfB = sha256Hex(`rotate-csrf-b-${randomUUID()}`);
      const [winner, loser] = await Promise.all([
        repos.sessions.rotate({
          currentTokenHash: firstHash,
          nextTokenHash: nextA,
          nextCsrfTokenHash: csrfA,
          lastSeenAt: seen,
          idleExpiresAt: IDLE_EXPIRES_AT,
        }),
        repos.sessions.rotate({
          currentTokenHash: firstHash,
          nextTokenHash: nextB,
          nextCsrfTokenHash: csrfB,
          lastSeenAt: seen,
          idleExpiresAt: IDLE_EXPIRES_AT,
        }),
      ]);
      const rotated = [winner, loser].filter((row) => row !== undefined);
      expect(rotated).toHaveLength(1);
      const live = rotated[0];
      expect(live).toBeDefined();
      expect(await repos.sessions.findByTokenHash(firstHash)).toBeUndefined();
      expect(await repos.sessions.findByTokenHash(live?.tokenHash ?? '')).toEqual(live);

      const revoked = await repos.sessions.revokeCurrent({
        tokenHash: live?.tokenHash ?? '',
        revokedAt: new Date('2026-01-02T00:00:00.000Z'),
        revokeReason: 'logout',
      });
      expect(revoked?.revokedAt).not.toBeNull();
      expect((await repos.sessions.findByTokenHash(otherSession.tokenHash))?.revokedAt).toBeNull();
      await repos.sessions.create({
        userId: user.id,
        tokenHash: sha256Hex(`still-live-${randomUUID()}`),
        csrfTokenHash: sha256Hex(`still-live-csrf-${randomUUID()}`),
        passwordRevision: 1,
        lastSeenAt: CREATED_AT,
        idleExpiresAt: IDLE_EXPIRES_AT,
        absoluteExpiresAt: ABSOLUTE_EXPIRES_AT,
      });
      const otherLive = await repos.sessions.create({
        userId: other.id,
        tokenHash: sha256Hex(`other-live-${randomUUID()}`),
        csrfTokenHash: sha256Hex(`other-live-csrf-${randomUUID()}`),
        passwordRevision: 1,
        lastSeenAt: CREATED_AT,
        idleExpiresAt: IDLE_EXPIRES_AT,
        absoluteExpiresAt: ABSOLUTE_EXPIRES_AT,
      });
      const revokedCount = await repos.sessions.revokeAllForUser({
        userId: user.id,
        revokedAt: new Date('2026-01-03T00:00:00.000Z'),
        revokeReason: 'user_disabled',
      });
      expect(revokedCount).toBeGreaterThanOrEqual(1);
      expect((await repos.sessions.findByTokenHash(otherLive.tokenHash))?.revokedAt).toBeNull();
    });

    it('clears active Organization context for the matching User only', async () => {
      const user = await createUser();
      const other = await createUser();
      const orgA = await createOrg();
      const orgB = await createOrg();
      const repos = createRepositories(prisma);
      const session = await repos.sessions.create({
        userId: user.id,
        tokenHash: sha256Hex(`clear-a-${randomUUID()}`),
        csrfTokenHash: sha256Hex(`clear-a-csrf-${randomUUID()}`),
        passwordRevision: 1,
        lastSeenAt: CREATED_AT,
        idleExpiresAt: IDLE_EXPIRES_AT,
        absoluteExpiresAt: ABSOLUTE_EXPIRES_AT,
        activeOrganizationId: orgA.id,
      });
      const kept = await repos.sessions.create({
        userId: user.id,
        tokenHash: sha256Hex(`clear-b-${randomUUID()}`),
        csrfTokenHash: sha256Hex(`clear-b-csrf-${randomUUID()}`),
        passwordRevision: 1,
        lastSeenAt: CREATED_AT,
        idleExpiresAt: IDLE_EXPIRES_AT,
        absoluteExpiresAt: ABSOLUTE_EXPIRES_AT,
        activeOrganizationId: orgB.id,
      });
      const otherSession = await repos.sessions.create({
        userId: other.id,
        tokenHash: sha256Hex(`clear-other-${randomUUID()}`),
        csrfTokenHash: sha256Hex(`clear-other-csrf-${randomUUID()}`),
        passwordRevision: 1,
        lastSeenAt: CREATED_AT,
        idleExpiresAt: IDLE_EXPIRES_AT,
        absoluteExpiresAt: ABSOLUTE_EXPIRES_AT,
        activeOrganizationId: orgA.id,
      });
      expect(
        await repos.sessions.clearActiveOrganization({ userId: user.id, organizationId: orgA.id }),
      ).toBe(1);
      expect(
        (await repos.sessions.findByTokenHash(session.tokenHash))?.activeOrganizationId,
      ).toBeNull();
      expect((await repos.sessions.findByTokenHash(kept.tokenHash))?.activeOrganizationId).toBe(
        orgB.id,
      );
      expect(
        (await repos.sessions.findByTokenHash(otherSession.tokenHash))?.activeOrganizationId,
      ).toBe(orgA.id);
    });

    it('lists and resolves only active Memberships in active Organizations for one User', async () => {
      const user = await createUser();
      const other = await createUser();
      const activeOrg = await createOrg(`active-${randomUUID().slice(0, 8)}`);
      const archivedOrg = await prisma.organization.create({
        data: {
          slug: `arch-${randomUUID().slice(0, 8)}`,
          name: 'Archived',
          status: 'archived',
          archivedAt: CREATED_AT,
        },
      });
      const extraOrg = await createOrg(`extra-${randomUUID().slice(0, 8)}`);
      const activeMembership = await prisma.membership.create({
        data: { organizationId: activeOrg.id, userId: user.id, role: 'owner' },
      });
      await prisma.membership.create({
        data: {
          organizationId: extraOrg.id,
          userId: user.id,
          role: 'member',
          status: 'revoked',
          revokedAt: CREATED_AT,
        },
      });
      await prisma.membership.create({
        data: { organizationId: archivedOrg.id, userId: user.id, role: 'member' },
      });
      await prisma.membership.create({
        data: { organizationId: activeOrg.id, userId: other.id, role: 'viewer' },
      });

      const repos = createRepositories(prisma);
      const listed = await repos.memberships.listActiveInActiveOrganizationsForUser(user.id);
      expect(listed).toHaveLength(1);
      expect(listed[0]?.membership.id).toBe(activeMembership.id);
      expect(listed[0]?.organization.id).toBe(activeOrg.id);
      expect(listed.some((row) => row.membership.userId === other.id)).toBe(false);

      const resolved = await repos.memberships.findActiveInActiveOrganization(
        user.id,
        activeOrg.id,
      );
      expect(resolved?.membership.id).toBe(activeMembership.id);
      expect(
        await repos.memberships.findActiveInActiveOrganization(user.id, extraOrg.id),
      ).toBeUndefined();
      expect(
        await repos.memberships.findActiveInActiveOrganization(user.id, archivedOrg.id),
      ).toBeUndefined();
      expect(
        await repos.memberships.findActiveInActiveOrganization(other.id, extraOrg.id),
      ).toBeUndefined();
    });

    it('updates a LocalCredential hash without accepting plaintext', async () => {
      const user = await createUser();
      await prisma.localCredential.create({
        data: { userId: user.id, passwordHash: SYNTHETIC_ARGON2ID_PHC },
      });
      const repos = createRepositories(prisma);
      const updated = await repos.localCredentials.updatePasswordHash({
        userId: user.id,
        passwordHash:
          '$argon2id$v=19$m=19456,p=1,t=2$c3ludGhldGljc2FsdA$bmV4dHJldmlzaW9uaGFzaGZvcmxvY2Fs',
        passwordRevision: 2,
      });
      expect(updated?.passwordRevision).toBe(2);
      expect(updated?.passwordHash.startsWith('$argon2id$')).toBe(true);
      await expect(
        repos.localCredentials.updatePasswordHash({
          userId: user.id,
          passwordHash: 'plaintext-not-allowed-and-long-enough-value',
          passwordRevision: 3,
        }),
      ).rejects.toThrow(/Argon2id PHC/);
    });
  });
});
