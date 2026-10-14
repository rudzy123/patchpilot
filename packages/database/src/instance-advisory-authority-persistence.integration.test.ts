import { createHash, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { Prisma, PrismaClient } from '@prisma/client';
import {
  INSTANCE_ADVISORY_AUDIT_ACTIONS,
  INSTANCE_ADVISORY_AUTHORITY_COMMAND_SCHEMA_VERSION,
  collapseInstanceAdvisoryAuthorizationForExternalBoundary,
  parseInstanceAdvisoryAuthorityCommand,
  type InstanceAdvisoryAuthority,
  type InstanceAdvisoryAuthorityCommand,
} from '@patchpilot/domain/instance-advisory-authority';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { insertOpenFindingForConstraintTest } from './finding-constraint-fixture.js';
import {
  applyMigrationSqlAndResolve,
  applyThroughControlledFindingCreation,
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
} from './integration-database.js';
import {
  createInstanceAdvisoryAuthorizationRead,
  createInstanceAdvisoryAuthorityPersistence,
  reloadInstanceAdvisoryAuthorizationFacts,
  type InstanceAdvisoryAuthorityPersistenceFault,
} from './instance-advisory-authority-persistence.js';

const SYNTHETIC_ARGON2ID_PHC =
  '$argon2id$v=19$m=19456,p=1,t=2$c3ludGhldGljc2FsdA$c3ludGhldGljaGFzaGZvcmxvY2FsY3JlZGU';
const REPEATED_OBSERVATION = '20261009120000_controlled_finding_repeated_observation';
const MIGRATION_26 = '20261014120000_instance_advisory_authority_grant';
const CREATED_AT = new Date('2026-06-01T00:00:00.000Z');
const IDLE_EXPIRES_AT = new Date('2026-06-01T12:00:00.000Z');
const ABSOLUTE_EXPIRES_AT = new Date('2026-06-08T00:00:00.000Z');

type Persistence = ReturnType<typeof createInstanceAdvisoryAuthorityPersistence>;

describe('instance advisory authority PostgreSQL persistence', () => {
  let databaseName: string;
  let databaseUrl: string;
  let admin: PrismaClient;
  let prisma: PrismaClient;
  let persistence: Persistence;
  let authorization: ReturnType<typeof createInstanceAdvisoryAuthorizationRead>;

  beforeAll(async () => {
    const ephemeral = await createEphemeralDatabase('it', { scope: 'iaa' });
    databaseName = ephemeral.databaseName;
    databaseUrl = ephemeral.databaseUrl;
    admin = ephemeral.admin;
    await deployMigrations(ephemeral.databaseUrl);
    prisma = new PrismaClient({ datasources: { db: { url: ephemeral.databaseUrl } } });
    persistence = createInstanceAdvisoryAuthorityPersistence(prisma);
    authorization = createInstanceAdvisoryAuthorizationRead(prisma);
  });

  afterAll(async () => {
    if (prisma !== undefined) {
      await prisma.$disconnect();
    }
    if (admin !== undefined && databaseName !== undefined) {
      await dropEphemeralDatabase(admin, databaseName);
    }
  });

  it('grants submission authority once and replays without a second write', async () => {
    const user = await createUser(prisma, 'submit');
    const before = await counts(prisma);
    const first = await persistence.execute(grant(user.id, 'advisory_submit_local'));
    expect(first.outcome).toBe('granted');
    if (first.outcome !== 'granted') {
      return;
    }
    const stored = await grantRow(prisma, first.grantId);
    const replay = await persistence.execute(grant(user.id, 'advisory_submit_local', randomUUID()));
    expect(replay).toEqual({ outcome: 'already_applied' });
    const afterReplay = await grantRow(prisma, first.grantId);
    expect(afterReplay).toEqual(stored);
    expect(await auditCount(prisma, INSTANCE_ADVISORY_AUDIT_ACTIONS.granted, first.grantId)).toBe(
      1,
    );
    const audit = await prisma.auditEvent.findFirst({
      where: { subjectId: first.grantId, action: INSTANCE_ADVISORY_AUDIT_ACTIONS.granted },
    });
    expect(audit?.actorType).toBe('system');
    expect(audit?.actorUserId).toBeNull();
    expect(audit?.organizationId).toBeNull();
    expect(audit?.actorMembershipId).toBeNull();
    expect(audit?.schemaVersion).toBe(1);
    expect(audit?.retentionCategory).toBe('security');
    const payload = audit?.payload as { schemaVersion: number; metadata: Record<string, string> };
    expect(Object.keys(payload).sort()).toEqual(['metadata', 'schemaVersion']);
    expect(Object.keys(payload.metadata).sort()).toEqual([
      'authority',
      'correlationId',
      'issuanceClassification',
      'targetUserId',
    ]);
    expect(payload.metadata['authority']).toBe('advisory_submit_local');
    expect(payload.metadata['issuanceClassification']).toBe('deployment_local_command');
    const after = await counts(prisma);
    expect(after.organizations).toBe(before.organizations);
    expect(after.memberships).toBe(before.memberships);
    expect(after.advisoryRevisions).toBe(before.advisoryRevisions);
    expect(after.productMatch).toBe(before.productMatch);
    expect(after.findings).toBe(before.findings);
    expect(after.observations).toBe(before.observations);
  });

  it('grants approval authority to a different user and rejects a conflicting authority', async () => {
    const user = await createUser(prisma, 'approve');
    const granted = await persistence.execute(
      grant(user.id, 'advisory_approve_for_product_evaluation'),
    );
    expect(granted.outcome).toBe('granted');
    const conflict = await persistence.execute(grant(user.id, 'advisory_submit_local'));
    expect(conflict).toEqual({ outcome: 'active_grant_conflict' });
    expect(await prisma.instanceAdvisoryAuthorityGrant.count({ where: { userId: user.id } })).toBe(
      1,
    );
  });

  it('converges concurrent identical grants to one row and one audit', async () => {
    const user = await createUser(prisma, 'concurrent-same');
    const other = new PrismaClient({
      datasources: { db: { url: databaseUrl } },
    });
    try {
      const second = createInstanceAdvisoryAuthorityPersistence(other);
      const [left, right] = await Promise.all([
        persistence.execute(grant(user.id, 'advisory_submit_local')),
        second.execute(grant(user.id, 'advisory_submit_local')),
      ]);
      const outcomes = [left.outcome, right.outcome].sort();
      expect(outcomes).toEqual(['already_applied', 'granted']);
      expect(
        await prisma.instanceAdvisoryAuthorityGrant.count({ where: { userId: user.id } }),
      ).toBe(1);
      const audits = await prisma.$queryRaw<Array<{ count: number }>>`
        SELECT COUNT(*)::int AS count
        FROM "audit_event"
        WHERE "action" = ${INSTANCE_ADVISORY_AUDIT_ACTIONS.granted}
          AND "payload"->'metadata'->>'targetUserId' = ${user.id}
      `;
      expect(Number(audits[0]?.count)).toBe(1);
    } finally {
      await other.$disconnect();
    }
  });

  it('converges concurrent conflicting authorities to one active grant', async () => {
    const user = await createUser(prisma, 'concurrent-conflict');
    const other = new PrismaClient({
      datasources: { db: { url: databaseUrl } },
    });
    try {
      const second = createInstanceAdvisoryAuthorityPersistence(other);
      const [left, right] = await Promise.all([
        persistence.execute(grant(user.id, 'advisory_submit_local')),
        second.execute(grant(user.id, 'advisory_approve_for_product_evaluation')),
      ]);
      const outcomes = [left.outcome, right.outcome].sort();
      expect(outcomes).toEqual(['active_grant_conflict', 'granted']);
      const active = await prisma.instanceAdvisoryAuthorityGrant.count({
        where: { userId: user.id, revokedAt: null },
      });
      expect(active).toBe(1);
    } finally {
      await other.$disconnect();
    }
  });

  it('distinguishes revoke replay from never granted, the wrong grant, and a replacement', async () => {
    const absent = await persistence.execute(
      revoke(randomUUID(), randomUUID(), 'advisory_submit_local'),
    );
    expect(absent).toEqual({ outcome: 'user_absent' });
    const user = await createUser(prisma, 'revoke');
    const never = await persistence.execute(revoke(user.id, randomUUID(), 'advisory_submit_local'));
    expect(never).toEqual({ outcome: 'grant_absent' });
    const granted = await persistence.execute(grant(user.id, 'advisory_submit_local'));
    if (granted.outcome !== 'granted') {
      throw new Error('grant did not commit');
    }
    const wrongAuthority = await persistence.execute(
      revoke(user.id, granted.grantId, 'advisory_approve_for_product_evaluation'),
    );
    expect(wrongAuthority).toEqual({ outcome: 'active_authority_mismatch' });
    const wrongGrant = await persistence.execute(
      revoke(user.id, randomUUID(), 'advisory_submit_local'),
    );
    expect(wrongGrant).toEqual({ outcome: 'expected_grant_mismatch' });
    const revoked = await persistence.execute(
      revoke(user.id, granted.grantId, 'advisory_submit_local'),
    );
    expect(revoked).toEqual({ outcome: 'revoked', grantId: granted.grantId });
    const revokedAt = (await grantRow(prisma, granted.grantId))?.revokedAt;
    const replay = await persistence.execute(
      revoke(user.id, granted.grantId, 'advisory_submit_local', randomUUID()),
    );
    expect(replay).toEqual({ outcome: 'already_applied' });
    expect((await grantRow(prisma, granted.grantId))?.revokedAt).toEqual(revokedAt);
    expect(await auditCount(prisma, INSTANCE_ADVISORY_AUDIT_ACTIONS.revoked, granted.grantId)).toBe(
      1,
    );
    const replacement = await persistence.execute(
      grant(user.id, 'advisory_approve_for_product_evaluation'),
    );
    expect(replacement.outcome).toBe('granted');
    if (replacement.outcome !== 'granted') {
      return;
    }
    const oldCommand = await persistence.execute(
      revoke(user.id, granted.grantId, 'advisory_submit_local'),
    );
    expect(oldCommand).toEqual({ outcome: 'expected_grant_mismatch' });
    expect((await grantRow(prisma, replacement.grantId))?.revokedAt).toBeNull();
  });

  it('re-grants either authority as a new row and keeps the revoked row immutable', async () => {
    const user = await createUser(prisma, 'regrant');
    const first = await persistence.execute(grant(user.id, 'advisory_submit_local'));
    if (first.outcome !== 'granted') {
      throw new Error('grant did not commit');
    }
    expect(
      (await persistence.execute(revoke(user.id, first.grantId, 'advisory_submit_local'))).outcome,
    ).toBe('revoked');
    const same = await persistence.execute(grant(user.id, 'advisory_submit_local'));
    expect(same.outcome).toBe('granted');
    if (same.outcome !== 'granted') {
      return;
    }
    expect(same.grantId).not.toBe(first.grantId);
    expect((await grantRow(prisma, first.grantId))?.revokedAt).not.toBeNull();
    expect((await grantRow(prisma, same.grantId))?.revokedAt).toBeNull();
    expect((await grantRow(prisma, same.grantId))?.issuedAt.getTime()).toBeGreaterThan(
      (await grantRow(prisma, first.grantId))?.issuedAt.getTime() ?? Number.POSITIVE_INFINITY,
    );
    expect(
      (await persistence.execute(revoke(user.id, same.grantId, 'advisory_submit_local'))).outcome,
    ).toBe('revoked');
    const other = await persistence.execute(
      grant(user.id, 'advisory_approve_for_product_evaluation'),
    );
    expect(other.outcome).toBe('granted');
    expect(await prisma.instanceAdvisoryAuthorityGrant.count({ where: { userId: user.id } })).toBe(
      3,
    );
  });

  it('rejects direct grant mutation, deletion, and deletion of a referenced user', async () => {
    const user = await createUser(prisma, 'guards');
    const granted = await persistence.execute(grant(user.id, 'advisory_submit_local'));
    if (granted.outcome !== 'granted') {
      throw new Error('grant did not commit');
    }
    await expect(
      prisma.$executeRaw`
        UPDATE "instance_advisory_authority_grant"
        SET "authority" = 'advisory_approve_for_product_evaluation'::"instance_advisory_authority"
        WHERE "id" = ${granted.grantId}::uuid
      `,
    ).rejects.toThrow();
    await expect(
      prisma.$executeRaw`
        INSERT INTO "instance_advisory_authority_grant" (
          "user_id", "authority", "issuance_classification", "command_correlation_id"
        ) VALUES (
          ${user.id}::uuid,
          'advisory_admin'::"instance_advisory_authority",
          'deployment_local_command'::"instance_advisory_issuance_classification",
          ${randomUUID()}::uuid
        )
      `,
    ).rejects.toThrow();
    expect(
      (await persistence.execute(revoke(user.id, granted.grantId, 'advisory_submit_local')))
        .outcome,
    ).toBe('revoked');
    await expect(
      prisma.$transaction(async (tx) => {
        await tx.$queryRaw`SELECT set_config('patchpilot.instance_advisory_authority_grant', 'on', true)`;
        await tx.$executeRaw`
          UPDATE "instance_advisory_authority_grant"
          SET "revoked_at" = NULL
          WHERE "id" = ${granted.grantId}::uuid
        `;
      }),
    ).rejects.toThrow();
    await expect(
      prisma.$transaction(async (tx) => {
        await tx.$queryRaw`SELECT set_config('patchpilot.instance_advisory_authority_grant', 'on', true)`;
        await tx.$executeRaw`
          UPDATE "instance_advisory_authority_grant"
          SET "revoked_at" = CURRENT_TIMESTAMP
          WHERE "id" = ${granted.grantId}::uuid
        `;
      }),
    ).rejects.toThrow();
    await expect(
      prisma.$executeRaw`
        DELETE FROM "instance_advisory_authority_grant" WHERE "id" = ${granted.grantId}::uuid
      `,
    ).rejects.toThrow();
    await expect(prisma.user.delete({ where: { id: user.id } })).rejects.toThrow();
    expect(
      await prisma.instanceAdvisoryAuthorityGrant.count({ where: { id: granted.grantId } }),
    ).toBe(1);
  });

  it('disables an active user without revoking the grant or the session', async () => {
    const user = await createUser(prisma, 'disable');
    const other = await createUser(prisma, 'disable-other');
    const session = await createSession(prisma, user.id, 'live');
    const otherSession = await createSession(prisma, other.id, 'other');
    const granted = await persistence.execute(grant(user.id, 'advisory_submit_local'));
    if (granted.outcome !== 'granted') {
      throw new Error('grant did not commit');
    }
    const disabled = await persistence.execute(userCommand('disable_user', user.id));
    expect(disabled).toEqual({ outcome: 'user_disabled' });
    const account = await prisma.user.findUniqueOrThrow({ where: { id: user.id } });
    expect(account.status).toBe('disabled');
    expect(account.email).toContain('disable');
    expect((await grantRow(prisma, granted.grantId))?.revokedAt).toBeNull();
    expect(
      (await prisma.session.findUniqueOrThrow({ where: { id: session.id } })).revokedAt,
    ).toBeNull();
    expect(
      (await prisma.session.findUniqueOrThrow({ where: { id: otherSession.id } })).revokedAt,
    ).toBeNull();
    expect((await prisma.user.findUniqueOrThrow({ where: { id: other.id } })).status).toBe(
      'active',
    );
    const read = await authorization.readRequiredAuthority({
      schemaVersion: 'instance_advisory_authorization_read_v1',
      userId: user.id,
      requiredAuthority: 'advisory_submit_local',
    });
    expect(read).toEqual({ outcome: 'user_inactive' });
    expect(collapseInstanceAdvisoryAuthorizationForExternalBoundary(read.outcome)).toBe(
      'authority_required',
    );
    const disabledAt = account.disabledAt;
    const replay = await persistence.execute(userCommand('disable_user', user.id));
    expect(replay).toEqual({ outcome: 'already_applied' });
    expect((await prisma.user.findUniqueOrThrow({ where: { id: user.id } })).disabledAt).toEqual(
      disabledAt,
    );
    expect(await auditCount(prisma, INSTANCE_ADVISORY_AUDIT_ACTIONS.userDisabled, user.id)).toBe(1);
    expect((await persistence.execute(userCommand('disable_user', randomUUID()))).outcome).toBe(
      'user_absent',
    );
    const resolver = readFileSync(
      path.resolve(
        path.dirname(fileURLToPath(import.meta.url)),
        '../../auth/src/resolve-session.ts',
      ),
      'utf8',
    );
    expect(resolver).toContain("user.status !== 'active'");
  });

  it('re-enables without creating a grant or restoring a revoked grant', async () => {
    const user = await createUser(prisma, 'enable');
    const granted = await persistence.execute(grant(user.id, 'advisory_submit_local'));
    if (granted.outcome !== 'granted') {
      throw new Error('grant did not commit');
    }
    expect((await persistence.execute(userCommand('disable_user', user.id))).outcome).toBe(
      'user_disabled',
    );
    expect(
      (await persistence.execute(revoke(user.id, granted.grantId, 'advisory_submit_local')))
        .outcome,
    ).toBe('revoked');
    const enabled = await persistence.execute(userCommand('enable_user', user.id));
    expect(enabled).toEqual({ outcome: 'user_enabled' });
    expect((await prisma.user.findUniqueOrThrow({ where: { id: user.id } })).status).toBe('active');
    expect((await grantRow(prisma, granted.grantId))?.revokedAt).not.toBeNull();
    expect(
      await prisma.instanceAdvisoryAuthorityGrant.count({
        where: { userId: user.id, revokedAt: null },
      }),
    ).toBe(0);
    const read = await authorization.readRequiredAuthority({
      schemaVersion: 'instance_advisory_authorization_read_v1',
      userId: user.id,
      requiredAuthority: 'advisory_submit_local',
    });
    expect(read).toEqual({ outcome: 'authority_required' });
    const replay = await persistence.execute(userCommand('enable_user', user.id));
    expect(replay).toEqual({ outcome: 'already_applied' });
    expect(await auditCount(prisma, INSTANCE_ADVISORY_AUDIT_ACTIONS.userReenabled, user.id)).toBe(
      1,
    );
  });

  it('authorizes only an active user with the exact active grant', async () => {
    const user = await createUser(prisma, 'read');
    const missing = await authorization.readRequiredAuthority({
      schemaVersion: 'instance_advisory_authorization_read_v1',
      userId: user.id,
      requiredAuthority: 'advisory_submit_local',
    });
    expect(missing).toEqual({ outcome: 'authority_required' });
    const granted = await persistence.execute(grant(user.id, 'advisory_submit_local'));
    if (granted.outcome !== 'granted') {
      throw new Error('grant did not commit');
    }
    expect(
      await authorization.readRequiredAuthority({
        schemaVersion: 'instance_advisory_authorization_read_v1',
        userId: user.id,
        requiredAuthority: 'advisory_submit_local',
      }),
    ).toEqual({ outcome: 'authorized' });
    expect(
      await authorization.readRequiredAuthority({
        schemaVersion: 'instance_advisory_authorization_read_v1',
        userId: user.id,
        requiredAuthority: 'advisory_approve_for_product_evaluation',
      }),
    ).toEqual({ outcome: 'authority_required' });
    const facts = await prisma.$transaction((tx) =>
      reloadInstanceAdvisoryAuthorizationFacts(tx, {
        schemaVersion: 'instance_advisory_authorization_read_v1',
        userId: user.id,
        requiredAuthority: 'advisory_submit_local',
      }),
    );
    expect(facts.activeGrant?.authority).toBe('advisory_submit_local');
    expect(facts.user).toEqual({ existence: 'present', status: 'active' });
    expect(JSON.stringify(facts)).not.toContain('password');
  });

  it('treats two active grants as malformed when the uniqueness index is removed inside a rolled-back transaction', async () => {
    const user = await createUser(prisma, 'malformed');
    await expect(
      prisma.$transaction(async (tx) => {
        await tx.$executeRaw`
          DROP INDEX "instance_advisory_authority_grant_one_active_user_idx"
        `;
        await tx.$queryRaw`SELECT set_config('patchpilot.instance_advisory_authority_grant', 'on', true)`;
        await tx.$executeRaw`
          INSERT INTO "instance_advisory_authority_grant" (
            "user_id", "authority", "issuance_classification", "issued_at", "command_correlation_id"
          ) VALUES (
            ${user.id}::uuid,
            'advisory_submit_local'::"instance_advisory_authority",
            'deployment_local_command'::"instance_advisory_issuance_classification",
            CURRENT_TIMESTAMP,
            ${randomUUID()}::uuid
          )
        `;
        await tx.$executeRaw`
          INSERT INTO "instance_advisory_authority_grant" (
            "user_id", "authority", "issuance_classification", "issued_at", "command_correlation_id"
          ) VALUES (
            ${user.id}::uuid,
            'advisory_approve_for_product_evaluation'::"instance_advisory_authority",
            'deployment_local_command'::"instance_advisory_issuance_classification",
            CURRENT_TIMESTAMP,
            ${randomUUID()}::uuid
          )
        `;
        const facts = await reloadInstanceAdvisoryAuthorizationFacts(tx, {
          schemaVersion: 'instance_advisory_authorization_read_v1',
          userId: user.id,
          requiredAuthority: 'advisory_submit_local',
        });
        expect(facts.malformed).toBe(true);
        throw new Error('rollback malformed fixture');
      }),
    ).rejects.toThrow('rollback malformed fixture');
    const indexes = await prisma.$queryRaw<Array<{ indexname: string }>>`
      SELECT indexname FROM pg_indexes
      WHERE indexname = 'instance_advisory_authority_grant_one_active_user_idx'
    `;
    expect(indexes).toHaveLength(1);
    expect(await prisma.instanceAdvisoryAuthorityGrant.count({ where: { userId: user.id } })).toBe(
      0,
    );
  });

  it('rolls back grant, revocation, status, and audit failures without partial state', async () => {
    const user = await createUser(prisma, 'fault');
    const faults: InstanceAdvisoryAuthorityPersistenceFault[] = [
      'before_user_lock',
      'before_active_grant_load',
      'before_grant_insert',
      'before_audit_insert',
      'before_stored_state_validation',
      'skip_audit_insert',
    ];
    for (const fault of faults) {
      const result = await persistence.execute(grant(user.id, 'advisory_submit_local'), { fault });
      expect(result.outcome).toBe('transaction_aborted');
      expect(
        await prisma.instanceAdvisoryAuthorityGrant.count({ where: { userId: user.id } }),
      ).toBe(0);
    }
    const granted = await persistence.execute(grant(user.id, 'advisory_submit_local'));
    if (granted.outcome !== 'granted') {
      throw new Error('grant did not commit');
    }
    for (const fault of [
      'before_revocation_update',
      'before_audit_insert',
      'skip_audit_insert',
    ] as const) {
      const result = await persistence.execute(
        revoke(user.id, granted.grantId, 'advisory_submit_local'),
        { fault },
      );
      expect(result.outcome).toBe('transaction_aborted');
      expect((await grantRow(prisma, granted.grantId))?.revokedAt).toBeNull();
    }
    const beforeDisable = await prisma.user.findUniqueOrThrow({ where: { id: user.id } });
    for (const fault of [
      'before_user_status_update',
      'before_audit_insert',
      'skip_audit_insert',
    ] as const) {
      const result = await persistence.execute(userCommand('disable_user', user.id), { fault });
      expect(result.outcome).toBe('transaction_aborted');
      const account = await prisma.user.findUniqueOrThrow({ where: { id: user.id } });
      expect(account.status).toBe('active');
      expect(account.updatedAt).toEqual(beforeDisable.updatedAt);
    }
    const committed = await persistence.execute(grant(user.id, 'advisory_submit_local'));
    expect(committed).toEqual({ outcome: 'already_applied' });
    expect(await auditCount(prisma, INSTANCE_ADVISORY_AUDIT_ACTIONS.granted, granted.grantId)).toBe(
      1,
    );
  });

  it('gives an organization owner no advisory authority', async () => {
    const user = await createUser(prisma, 'owner');
    const org = await prisma.organization.create({
      data: { slug: `owner-${randomUUID().slice(0, 8)}`, name: 'Owner org' },
    });
    const membership = await prisma.membership.create({
      data: { organizationId: org.id, userId: user.id, role: 'owner', joinedAt: CREATED_AT },
    });
    const read = await authorization.readRequiredAuthority({
      schemaVersion: 'instance_advisory_authorization_read_v1',
      userId: user.id,
      requiredAuthority: 'advisory_approve_for_product_evaluation',
    });
    expect(read).toEqual({ outcome: 'authority_required' });
    expect(await prisma.instanceAdvisoryAuthorityGrant.count({ where: { userId: user.id } })).toBe(
      0,
    );
    await prisma.membership.update({
      where: { id: membership.id },
      data: { role: 'admin' },
    });
    expect(
      await authorization.readRequiredAuthority({
        schemaVersion: 'instance_advisory_authorization_read_v1',
        userId: user.id,
        requiredAuthority: 'advisory_approve_for_product_evaluation',
      }),
    ).toEqual({ outcome: 'authority_required' });
  });

  it('rejects a grant for a disabled user and restores only a still-active grant', async () => {
    const inactive = await createUser(prisma, 'inactive-grant');
    expect((await persistence.execute(userCommand('disable_user', inactive.id))).outcome).toBe(
      'user_disabled',
    );
    expect(
      (await persistence.execute(grant(inactive.id, 'advisory_submit_local'))).outcome,
    ).toEqual('user_inactive');
    expect(
      await prisma.instanceAdvisoryAuthorityGrant.count({ where: { userId: inactive.id } }),
    ).toBe(0);
    const user = await createUser(prisma, 'restore-grant');
    await prisma.localCredential.create({
      data: { userId: user.id, passwordHash: SYNTHETIC_ARGON2ID_PHC },
    });
    const granted = await persistence.execute(grant(user.id, 'advisory_submit_local'));
    if (granted.outcome !== 'granted') {
      throw new Error('grant did not commit');
    }
    expect((await persistence.execute(userCommand('disable_user', user.id))).outcome).toBe(
      'user_disabled',
    );
    expect((await persistence.execute(grant(user.id, 'advisory_submit_local'))).outcome).toEqual(
      'already_applied',
    );
    expect(
      (await persistence.execute(grant(user.id, 'advisory_approve_for_product_evaluation')))
        .outcome,
    ).toEqual('active_grant_conflict');
    const credential = await prisma.localCredential.findUniqueOrThrow({
      where: { userId: user.id },
    });
    expect(credential.passwordHash).toBe(SYNTHETIC_ARGON2ID_PHC);
    expect(credential.passwordRevision).toBe(1);
    expect((await persistence.execute(userCommand('enable_user', user.id))).outcome).toBe(
      'user_enabled',
    );
    expect((await grantRow(prisma, granted.grantId))?.revokedAt).toBeNull();
    expect(
      await authorization.readRequiredAuthority({
        schemaVersion: 'instance_advisory_authorization_read_v1',
        userId: user.id,
        requiredAuthority: 'advisory_submit_local',
      }),
    ).toEqual({ outcome: 'authorized' });
  });

  it('serializes a concurrent revoke and conflicting grant to one authority', async () => {
    const user = await createUser(prisma, 'grant-revoke');
    const granted = await persistence.execute(grant(user.id, 'advisory_submit_local'));
    if (granted.outcome !== 'granted') {
      throw new Error('grant did not commit');
    }
    const other = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
    try {
      const second = createInstanceAdvisoryAuthorityPersistence(other);
      const [revocation, challenger] = await Promise.all([
        persistence.execute(revoke(user.id, granted.grantId, 'advisory_submit_local')),
        second.execute(grant(user.id, 'advisory_approve_for_product_evaluation')),
      ]);
      expect(revocation).toEqual({ outcome: 'revoked', grantId: granted.grantId });
      expect(['active_grant_conflict', 'granted']).toContain(challenger.outcome);
      const active = await prisma.instanceAdvisoryAuthorityGrant.findMany({
        where: { userId: user.id, revokedAt: null },
      });
      if (challenger.outcome === 'granted') {
        expect(active).toHaveLength(1);
        expect(active[0]?.authority).toBe('advisory_approve_for_product_evaluation');
      } else {
        expect(active).toHaveLength(0);
      }
      expect((await grantRow(prisma, granted.grantId))?.revokedAt).not.toBeNull();
    } finally {
      await other.$disconnect();
    }
  });

  it('sees a committed disable from the in-transaction authorization reload', async () => {
    const user = await createUser(prisma, 'lock-disable');
    const granted = await persistence.execute(grant(user.id, 'advisory_submit_local'));
    if (granted.outcome !== 'granted') {
      throw new Error('grant did not commit');
    }
    const holder = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
    const reader = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
    let locked!: () => void;
    const lockedPromise = new Promise<void>((resolve) => {
      locked = resolve;
    });
    let readerStarted!: () => void;
    const readerStartedPromise = new Promise<void>((resolve) => {
      readerStarted = resolve;
    });
    const correlationId = randomUUID();
    try {
      const disabling = holder.$transaction(
        async (tx) => {
          await tx.$queryRaw`SELECT set_config('patchpilot.instance_advisory_user_status', 'on', true)`;
          await tx.$queryRaw`SELECT "id" FROM "user" WHERE "id" = ${user.id}::uuid FOR UPDATE`;
          locked();
          await readerStartedPromise;
          await tx.$executeRaw`
            UPDATE "user"
            SET "status" = 'disabled'::"user_status",
                "disabled_at" = CURRENT_TIMESTAMP,
                "updated_at" = CURRENT_TIMESTAMP,
                "version" = "version" + 1
            WHERE "id" = ${user.id}::uuid
              AND "status" = 'active'::"user_status"
          `;
          await insertSystemAudit(tx, {
            action: 'auth.user_disabled',
            subjectType: 'user',
            subjectId: user.id,
            correlationId,
            metadata: { correlationId, targetUserId: user.id },
          });
        },
        { timeout: 15_000 },
      );
      await lockedPromise;
      const reading = reader.$transaction(
        async (tx) => {
          readerStarted();
          return reloadInstanceAdvisoryAuthorizationFacts(tx, {
            schemaVersion: 'instance_advisory_authorization_read_v1',
            userId: user.id,
            requiredAuthority: 'advisory_submit_local',
          });
        },
        { timeout: 15_000 },
      );
      const [, facts] = await Promise.all([disabling, reading]);
      expect(facts.user).toEqual({ existence: 'present', status: 'disabled' });
      expect(facts.activeGrant?.authority).toBe('advisory_submit_local');
      expect(facts.malformed).toBe(false);
      expect(
        await authorization.readRequiredAuthority({
          schemaVersion: 'instance_advisory_authorization_read_v1',
          userId: user.id,
          requiredAuthority: 'advisory_submit_local',
        }),
      ).toEqual({ outcome: 'user_inactive' });
    } finally {
      await holder.$disconnect();
      await reader.$disconnect();
    }
  });

  it('rejects hostile grant rows and keeps the mutation setting inside the transaction', async () => {
    const user = await createUser(prisma, 'hostile');
    const legal = await persistence.execute(grant(user.id, 'advisory_submit_local'));
    if (legal.outcome !== 'granted') {
      throw new Error('grant did not commit');
    }
    await expect(
      prisma.$executeRaw`
        INSERT INTO "instance_advisory_authority_grant" (
          "user_id", "authority", "issuance_classification", "command_correlation_id"
        ) VALUES (
          ${user.id}::uuid,
          'ADVISORY_SUBMIT_LOCAL'::"instance_advisory_authority",
          'deployment_local_command'::"instance_advisory_issuance_classification",
          ${randomUUID()}::uuid
        )
      `,
    ).rejects.toThrow();
    await expect(
      prisma.$executeRaw`
        INSERT INTO "instance_advisory_authority_grant" (
          "user_id", "authority", "issuance_classification", "command_correlation_id"
        ) VALUES (
          ${user.id}::uuid,
          ''::"instance_advisory_authority",
          'deployment_local_command'::"instance_advisory_issuance_classification",
          ${randomUUID()}::uuid
        )
      `,
    ).rejects.toThrow();
    await expect(
      prisma.$executeRaw`
        INSERT INTO "instance_advisory_authority_grant" (
          "user_id", "authority", "issuance_classification", "command_correlation_id"
        ) VALUES (
          ${user.id}::uuid,
          '*'::"instance_advisory_authority",
          'deployment_local_command'::"instance_advisory_issuance_classification",
          ${randomUUID()}::uuid
        )
      `,
    ).rejects.toThrow();
    await expect(
      prisma.$executeRaw`
        INSERT INTO "instance_advisory_authority_grant" (
          "user_id", "authority", "issuance_classification", "command_correlation_id"
        ) VALUES (
          ${user.id}::uuid,
          'advisory_submit_local'::"instance_advisory_authority",
          'seed'::"instance_advisory_issuance_classification",
          ${randomUUID()}::uuid
        )
      `,
    ).rejects.toThrow();
    await expect(
      prisma.$executeRaw`
        INSERT INTO "instance_advisory_authority_grant" (
          "user_id", "authority", "issuance_classification", "command_correlation_id"
        ) VALUES (
          ${randomUUID()}::uuid,
          'advisory_submit_local'::"instance_advisory_authority",
          'deployment_local_command'::"instance_advisory_issuance_classification",
          ${randomUUID()}::uuid
        )
      `,
    ).rejects.toThrow();
    await expect(
      prisma.$executeRaw`
        INSERT INTO "instance_advisory_authority_grant" (
          "user_id", "organization_id", "authority", "issuance_classification", "command_correlation_id"
        ) VALUES (
          ${user.id}::uuid,
          ${randomUUID()}::uuid,
          'advisory_submit_local'::"instance_advisory_authority",
          'deployment_local_command'::"instance_advisory_issuance_classification",
          ${randomUUID()}::uuid
        )
      `,
    ).rejects.toThrow();
    await expect(
      prisma.$transaction(async (tx) => {
        await tx.$queryRaw`SELECT set_config('patchpilot.instance_advisory_authority_grant', 'on', true)`;
        await tx.$executeRaw`
          INSERT INTO "instance_advisory_authority_grant" (
            "user_id", "authority", "issuance_classification", "issued_at", "command_correlation_id"
          ) VALUES (
            ${user.id}::uuid,
            'advisory_approve_for_product_evaluation'::"instance_advisory_authority",
            'deployment_local_command'::"instance_advisory_issuance_classification",
            TIMESTAMPTZ '2020-01-01T00:00:00Z',
            ${randomUUID()}::uuid
          )
        `;
      }),
    ).rejects.toThrow();
    await expect(
      prisma.$transaction(async (tx) => {
        await tx.$queryRaw`SELECT set_config('patchpilot.instance_advisory_authority_grant', 'on', true)`;
        await tx.$executeRaw`
          INSERT INTO "instance_advisory_authority_grant" (
            "user_id", "authority", "issuance_classification", "issued_at", "revoked_at",
            "command_correlation_id"
          ) VALUES (
            ${user.id}::uuid,
            'advisory_approve_for_product_evaluation'::"instance_advisory_authority",
            'deployment_local_command'::"instance_advisory_issuance_classification",
            CURRENT_TIMESTAMP,
            CURRENT_TIMESTAMP,
            ${randomUUID()}::uuid
          )
        `;
      }),
    ).rejects.toThrow();
    await expect(
      prisma.$transaction(async (tx) => {
        await tx.$queryRaw`SELECT set_config('patchpilot.instance_advisory_user_status', 'on', true)`;
        await tx.$executeRaw`
          UPDATE "user"
          SET "email" = ${`changed-${user.id.slice(0, 8)}@synthetic.patchpilot.test`},
              "status" = 'disabled'::"user_status",
              "disabled_at" = CURRENT_TIMESTAMP,
              "updated_at" = CURRENT_TIMESTAMP,
              "version" = "version" + 1
          WHERE "id" = ${user.id}::uuid
        `;
      }),
    ).rejects.toThrow();
    const org = await prisma.organization.create({
      data: { slug: `hostile-${randomUUID().slice(0, 8)}`, name: 'Hostile org' },
    });
    await prisma
      .$transaction(async (tx) => {
        await tx.$queryRaw`SELECT set_config('patchpilot.instance_advisory_authority_grant', 'on', true)`;
        await tx.$executeRaw`
        UPDATE "organization" SET "name" = 'Hostile org renamed' WHERE "id" = ${org.id}::uuid
      `;
        throw new Error('rollback organization probe');
      })
      .catch((error: unknown) => {
        if (!(error instanceof Error) || !error.message.includes('rollback organization probe')) {
          throw error;
        }
      });
    expect((await prisma.organization.findUniqueOrThrow({ where: { id: org.id } })).name).toBe(
      'Hostile org',
    );
    expect(await prisma.instanceAdvisoryAuthorityGrant.count({ where: { userId: user.id } })).toBe(
      1,
    );
    expect((await prisma.user.findUniqueOrThrow({ where: { id: user.id } })).status).toBe('active');
    const dedicated = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
    try {
      await dedicated.$transaction(async (tx) => {
        await tx.$queryRaw`SELECT set_config('patchpilot.instance_advisory_authority_grant', 'on', true)`;
      });
      const visible = await dedicated.$queryRaw<Array<{ value: string | null }>>`
        SELECT current_setting('patchpilot.instance_advisory_authority_grant', true) AS value
      `;
      expect(visible[0]?.value ?? '').not.toBe('on');
    } finally {
      await dedicated.$disconnect();
    }
  });

  it('lets the active-grant index reject a second direct insert', async () => {
    const user = await createUser(prisma, 'direct-race');
    const left = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
    const right = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
    try {
      const [first, second] = await Promise.all([
        tryDirectActiveGrant(left, user.id, 'advisory_submit_local'),
        tryDirectActiveGrant(right, user.id, 'advisory_approve_for_product_evaluation'),
      ]);
      const inserted = [first, second].filter((result) => result === 'inserted');
      expect([first, second], [first, second].join('\n')).toHaveLength(2);
      expect(inserted, [first, second].join('\n')).toHaveLength(1);
      expect(
        await prisma.instanceAdvisoryAuthorityGrant.count({
          where: { userId: user.id, revokedAt: null },
        }),
      ).toBe(1);
      expect(
        await prisma.auditEvent.count({
          where: {
            action: INSTANCE_ADVISORY_AUDIT_ACTIONS.granted,
            payload: { path: ['metadata', 'targetUserId'], equals: user.id },
          },
        }),
      ).toBe(1);
    } finally {
      await left.$disconnect();
      await right.$disconnect();
    }
  });
});

describe('instance advisory authority migration compatibility', () => {
  it('preserves the 25-migration baseline and seeds no grant', async () => {
    const ephemeral = await createEphemeralDatabase('migrate', { scope: 'iaa25' });
    const client = new PrismaClient({ datasources: { db: { url: ephemeral.databaseUrl } } });
    try {
      await applyThroughControlledFindingCreation(ephemeral.databaseUrl);
      await applyMigrationSqlAndResolve(ephemeral.databaseUrl, REPEATED_OBSERVATION);
      const user = await client.user.create({
        data: { email: uniqueEmail('baseline'), displayName: 'Baseline user' },
      });
      const org = await client.organization.create({
        data: { slug: `base-${randomUUID().slice(0, 8)}`, name: 'Baseline org' },
      });
      const membership = await client.membership.create({
        data: { organizationId: org.id, userId: user.id, role: 'admin', joinedAt: CREATED_AT },
      });
      const asset = await client.asset.create({
        data: { organizationId: org.id, name: 'baseline', assetType: 'application' },
      });
      const vulnerability = await client.vulnerability.create({
        data: { osvId: `PATCHPILOT-SYNTH-${randomUUID().slice(0, 8)}` },
      });
      const component = await client.component.create({
        data: {
          organizationId: org.id,
          identityKey: `npm|baseline-${randomUUID().slice(0, 8)}`,
          ecosystem: 'npm',
          name: 'baseline',
        },
      });
      const { finding } = await insertOpenFindingForConstraintTest(client, {
        organizationId: org.id,
        assetId: asset.id,
        vulnerabilityId: vulnerability.id,
        componentId: component.id,
      });
      await client.auditEvent.create({
        data: {
          actorType: 'system',
          action: 'organization.created',
          subjectType: 'organization',
          subjectId: org.id,
          correlationId: randomUUID(),
          payload: { schemaVersion: 1, metadata: { source: 'baseline' } },
          schemaVersion: 1,
          retentionCategory: 'security',
        },
      });
      const before = await baseline(client, user.id, membership.id, finding.id, false);
      await applyMigrationSqlAndResolve(ephemeral.databaseUrl, MIGRATION_26);
      const after = await baseline(client, user.id, membership.id, finding.id, true);
      expect(after.user).toEqual(before.user);
      expect(after.membership).toEqual(before.membership);
      expect(after.finding).toEqual(before.finding);
      expect(after.advisoryRevisions).toBe(before.advisoryRevisions);
      expect(after.capabilities).toBe(before.capabilities);
      expect(after.audits).toBe(before.audits);
      expect(after.grants).toBe(0);
      expect(before.advisoryRevisions).toBeGreaterThan(0);
      expect(before.capabilities).toBeGreaterThan(0);
    } finally {
      await client.$disconnect();
      await dropEphemeralDatabase(ephemeral.admin, ephemeral.databaseName);
    }
  }, 120_000);
});

function grant(
  userId: string,
  authority: InstanceAdvisoryAuthority,
  correlationId = randomUUID(),
): InstanceAdvisoryAuthorityCommand {
  return parseCommand({
    schemaVersion: INSTANCE_ADVISORY_AUTHORITY_COMMAND_SCHEMA_VERSION,
    operation: 'grant',
    targetUserId: userId,
    authority,
    issuanceClassification: 'deployment_local_command',
    correlationId,
  });
}

function revoke(
  userId: string,
  expectedGrantId: string,
  expectedAuthority: InstanceAdvisoryAuthority,
  correlationId = randomUUID(),
): InstanceAdvisoryAuthorityCommand {
  return parseCommand({
    schemaVersion: INSTANCE_ADVISORY_AUTHORITY_COMMAND_SCHEMA_VERSION,
    operation: 'revoke',
    targetUserId: userId,
    expectedGrantId,
    expectedAuthority,
    correlationId,
  });
}

function userCommand(
  operation: 'disable_user' | 'enable_user',
  userId: string,
): InstanceAdvisoryAuthorityCommand {
  return parseCommand({
    schemaVersion: INSTANCE_ADVISORY_AUTHORITY_COMMAND_SCHEMA_VERSION,
    operation,
    targetUserId: userId,
    correlationId: randomUUID(),
  });
}

function parseCommand(input: unknown): InstanceAdvisoryAuthorityCommand {
  const parsed = parseInstanceAdvisoryAuthorityCommand(input);
  if (!parsed.ok) {
    throw new Error('test command was rejected');
  }
  return parsed.command;
}

function uniqueEmail(label: string): string {
  return `${label}-${randomUUID().slice(0, 8)}@synthetic.patchpilot.test`;
}

async function createUser(prisma: PrismaClient, label: string) {
  return prisma.user.create({
    data: { email: uniqueEmail(label), displayName: `${label} user` },
  });
}

async function createSession(prisma: PrismaClient, userId: string, label: string) {
  const digest = (value: string) => createHash('sha256').update(value).digest('hex');
  return prisma.session.create({
    data: {
      userId,
      tokenHash: digest(`session-${label}-${randomUUID()}`),
      csrfTokenHash: digest(`csrf-${label}-${randomUUID()}`),
      passwordRevision: 1,
      createdAt: CREATED_AT,
      lastSeenAt: CREATED_AT,
      idleExpiresAt: IDLE_EXPIRES_AT,
      absoluteExpiresAt: ABSOLUTE_EXPIRES_AT,
    },
  });
}

async function grantRow(prisma: PrismaClient, id: string) {
  return prisma.instanceAdvisoryAuthorityGrant.findUnique({ where: { id } });
}

async function auditCount(
  prisma: PrismaClient,
  action: string,
  subjectId: string,
): Promise<number> {
  return prisma.auditEvent.count({ where: { action, subjectId } });
}

async function counts(prisma: PrismaClient) {
  const [organizations, memberships, advisoryRevisions, productMatch, findings, observations] =
    await Promise.all([
      prisma.organization.count(),
      prisma.membership.count(),
      prisma.advisoryRevision.count(),
      prisma.productMatchEvaluationEvidence.count(),
      prisma.finding.count(),
      prisma.findingObservation.count(),
    ]);
  return { organizations, memberships, advisoryRevisions, productMatch, findings, observations };
}

async function insertSystemAudit(
  tx: Prisma.TransactionClient,
  input: {
    readonly action: string;
    readonly subjectType: string;
    readonly subjectId: string;
    readonly correlationId: string;
    readonly metadata: Record<string, string>;
  },
): Promise<void> {
  const metadata = JSON.stringify(input.metadata);
  await tx.$executeRaw`
    INSERT INTO "audit_event" (
      "organization_id",
      "actor_user_id",
      "actor_membership_id",
      "actor_type",
      "action",
      "subject_type",
      "subject_id",
      "occurred_at",
      "correlation_id",
      "payload",
      "schema_version",
      "retention_category"
    ) VALUES (
      NULL,
      NULL,
      NULL,
      'system'::"audit_actor_type",
      ${input.action},
      ${input.subjectType},
      ${input.subjectId}::uuid,
      CURRENT_TIMESTAMP,
      ${input.correlationId},
      jsonb_build_object(
        'schemaVersion', 1,
        'metadata', ${metadata}::jsonb
      ),
      1,
      'security'::"audit_retention_category"
    )
  `;
}

async function tryDirectActiveGrant(
  client: PrismaClient,
  userId: string,
  authority: InstanceAdvisoryAuthority,
): Promise<string> {
  const correlationId = randomUUID();
  try {
    await client.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT set_config('patchpilot.instance_advisory_authority_grant', 'on', true)`;
      const inserted = await tx.$queryRaw<Array<{ id: string }>>`
        INSERT INTO "instance_advisory_authority_grant" (
          "user_id",
          "authority",
          "issuance_classification",
          "issued_at",
          "command_correlation_id"
        ) VALUES (
          ${userId}::uuid,
          ${authority}::"instance_advisory_authority",
          'deployment_local_command'::"instance_advisory_issuance_classification",
          CURRENT_TIMESTAMP,
          ${correlationId}::uuid
        )
        RETURNING "id"::text AS id
      `;
      const grantId = inserted[0]?.id;
      if (grantId === undefined) {
        throw new Error('direct grant did not return an id');
      }
      await insertSystemAudit(tx, {
        action: INSTANCE_ADVISORY_AUDIT_ACTIONS.granted,
        subjectType: 'instance_advisory_authority_grant',
        subjectId: grantId,
        correlationId,
        metadata: {
          authority,
          correlationId,
          issuanceClassification: 'deployment_local_command',
          targetUserId: userId,
        },
      });
    });
    return 'inserted';
  } catch (error) {
    return error instanceof Error ? error.message : 'rejected';
  }
}

async function baseline(
  client: PrismaClient,
  userId: string,
  membershipId: string,
  findingId: string,
  grantTableExists: boolean,
) {
  const user = await client.user.findUniqueOrThrow({ where: { id: userId } });
  const membership = await client.membership.findUniqueOrThrow({ where: { id: membershipId } });
  const finding = await client.finding.findFirstOrThrow({ where: { id: findingId } });
  const [advisoryRevisions, capabilities, audits, grants] = await Promise.all([
    client.advisoryRevision.count(),
    client.reviewerCapabilityIssuance.count(),
    client.auditEvent.count(),
    grantTableExists
      ? client.$queryRaw<Array<{ count: number }>>`
          SELECT COUNT(*)::int AS count FROM "instance_advisory_authority_grant"
        `.then((rows) => Number(rows[0]?.count ?? 0))
      : Promise.resolve(0),
  ]);
  return {
    user: {
      email: user.email,
      status: user.status,
      version: user.version,
      disabledAt: user.disabledAt,
    },
    membership: { role: membership.role, status: membership.status },
    finding: { state: finding.state, version: finding.version },
    advisoryRevisions,
    capabilities,
    audits,
    grants,
  };
}
