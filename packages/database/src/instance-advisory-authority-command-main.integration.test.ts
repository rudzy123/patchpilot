import { randomUUID } from 'node:crypto';

import { PrismaClient } from '@prisma/client';
import {
  INSTANCE_ADVISORY_AUDIT_ACTIONS,
  INSTANCE_ADVISORY_AUTHORIZATION_READ_SCHEMA_VERSION,
} from '@patchpilot/domain/instance-advisory-authority';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
} from './integration-database.js';
import {
  openInstanceAdvisoryAuthorityCommandBoundary,
  runInstanceAdvisoryAuthorityCommand,
  type InstanceAdvisoryAuthorityCommandSession,
} from './instance-advisory-authority-command-main.js';
import {
  createInstanceAdvisoryAuthorizationRead,
  createInstanceAdvisoryAuthorityPersistence,
} from './instance-advisory-authority-persistence.js';
import { disconnectPrisma } from './client.js';

class MemoryStream {
  public text = '';

  public write(chunk: string): void {
    this.text += chunk;
  }
}

describe('instance advisory authority deployment command PostgreSQL path', () => {
  let databaseName: string;
  let databaseUrl: string;
  let admin: PrismaClient;
  let prisma: PrismaClient;

  beforeAll(async () => {
    const ephemeral = await createEphemeralDatabase('it', { scope: 'iaacmd' });
    databaseName = ephemeral.databaseName;
    databaseUrl = ephemeral.databaseUrl;
    admin = ephemeral.admin;
    await deployMigrations(databaseUrl);
    prisma = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
  });

  afterAll(async () => {
    if (prisma !== undefined) {
      await prisma.$disconnect();
    }
    await disconnectPrisma();
    if (admin !== undefined && databaseName !== undefined) {
      await dropEphemeralDatabase(admin, databaseName);
    }
  });

  it('grants, replays, conflicts, revokes, and re-grants through the command', async () => {
    const before = await counts(prisma);
    const submitter = await createUser(prisma, 'submit');
    const approver = await createUser(prisma, 'approve');
    const correlation = randomUUID();
    const first = await invoke(
      databaseUrl,
      grantArgv(submitter.id, 'advisory_submit_local', correlation),
    );
    expect(first.exitCode).toBe(0);
    expect(first.body).toMatchObject({
      operation: 'grant',
      outcome: 'granted',
      targetUserId: submitter.id,
      authority: 'advisory_submit_local',
      acknowledgement: 'committed',
    });
    const grantId = first.body['grantId'];
    expect(typeof grantId).toBe('string');
    expect(first.stdout).not.toContain(databaseUrl);
    expect(first.stdout).not.toContain(submitter.email);
    expect(first.stderr).toBe('');

    const replay = await invoke(
      databaseUrl,
      grantArgv(submitter.id, 'advisory_submit_local', randomUUID()),
    );
    expect(replay.exitCode).toBe(2);
    expect(replay.body).toMatchObject({ outcome: 'already_applied', acknowledgement: 'replayed' });
    expect(await auditCount(prisma, INSTANCE_ADVISORY_AUDIT_ACTIONS.granted, String(grantId))).toBe(
      1,
    );

    const conflict = await invoke(
      databaseUrl,
      grantArgv(submitter.id, 'advisory_approve_for_product_evaluation', randomUUID()),
    );
    expect(conflict.exitCode).toBe(5);
    expect(conflict.body).toMatchObject({ outcome: 'active_grant_conflict' });
    expect(
      await prisma.instanceAdvisoryAuthorityGrant.count({ where: { userId: submitter.id } }),
    ).toBe(1);

    const approval = await invoke(
      databaseUrl,
      grantArgv(approver.id, 'advisory_approve_for_product_evaluation', randomUUID()),
    );
    expect(approval.body).toMatchObject({
      outcome: 'granted',
      authority: 'advisory_approve_for_product_evaluation',
    });

    const never = await invoke(
      databaseUrl,
      revokeArgv(submitter.id, randomUUID(), 'advisory_submit_local'),
    );
    expect(never.exitCode).toBe(5);
    expect(never.body['outcome']).toBe('expected_grant_mismatch');
    expect(never.body['outcome']).not.toBe('already_applied');

    const absentUser = await invoke(
      databaseUrl,
      revokeArgv(randomUUID(), String(grantId), 'advisory_submit_local'),
    );
    expect(absentUser.exitCode).toBe(4);
    expect(absentUser.body).toMatchObject({ outcome: 'user_absent' });

    const noRow = await createUser(prisma, 'none');
    const absentGrant = await invoke(
      databaseUrl,
      revokeArgv(noRow.id, randomUUID(), 'advisory_submit_local'),
    );
    expect(absentGrant.exitCode).toBe(4);
    expect(absentGrant.body).toMatchObject({
      outcome: 'grant_absent',
      acknowledgement: 'unchanged',
    });

    const revoked = await invoke(
      databaseUrl,
      revokeArgv(submitter.id, String(grantId), 'advisory_submit_local'),
    );
    expect(revoked.exitCode).toBe(0);
    expect(revoked.body).toMatchObject({ outcome: 'revoked', grantId });
    const revokeReplay = await invoke(
      databaseUrl,
      revokeArgv(submitter.id, String(grantId), 'advisory_submit_local'),
    );
    expect(revokeReplay.exitCode).toBe(2);
    expect(revokeReplay.body).toMatchObject({ outcome: 'already_applied' });
    expect(await auditCount(prisma, INSTANCE_ADVISORY_AUDIT_ACTIONS.revoked, String(grantId))).toBe(
      1,
    );

    const regrant = await invoke(
      databaseUrl,
      grantArgv(submitter.id, 'advisory_submit_local', randomUUID()),
    );
    expect(regrant.exitCode).toBe(0);
    expect(regrant.body['grantId']).not.toBe(grantId);
    const replaced = await invoke(
      databaseUrl,
      revokeArgv(submitter.id, String(grantId), 'advisory_submit_local'),
    );
    expect(replaced.exitCode).toBe(5);
    expect(replaced.body).toMatchObject({ outcome: 'expected_grant_mismatch' });
    expect(replaced.body['outcome']).not.toBe('already_applied');

    const audit = await prisma.auditEvent.findFirst({
      where: { subjectId: String(grantId), action: INSTANCE_ADVISORY_AUDIT_ACTIONS.granted },
    });
    expect(audit?.actorType).toBe('system');
    expect(audit?.actorUserId).toBeNull();
    expect(audit?.organizationId).toBeNull();
    expect(audit?.actorMembershipId).toBeNull();
    expect(JSON.stringify(audit?.payload)).toContain(correlation);
    expect(JSON.stringify(audit?.payload)).not.toContain('password');

    const after = await counts(prisma);
    expect(after.organizations).toBe(before.organizations);
    expect(after.memberships).toBe(before.memberships);
    expect(after.advisoryRevisions).toBe(before.advisoryRevisions);
    expect(after.approvals).toBe(before.approvals);
    expect(after.capabilities).toBe(before.capabilities);
    expect(after.productMatch).toBe(before.productMatch);
    expect(after.findings).toBe(before.findings);
    expect(after.observations).toBe(before.observations);
  });

  it('disables and re-enables a user without granting authority', async () => {
    const user = await createUser(prisma, 'status');
    const granted = await invoke(
      databaseUrl,
      grantArgv(user.id, 'advisory_submit_local', randomUUID()),
    );
    expect(granted.body['outcome']).toBe('granted');
    const authorization = createInstanceAdvisoryAuthorizationRead(prisma);
    expect(
      await authorization.readRequiredAuthority({
        schemaVersion: INSTANCE_ADVISORY_AUTHORIZATION_READ_SCHEMA_VERSION,
        userId: user.id,
        requiredAuthority: 'advisory_submit_local',
      }),
    ).toEqual({ outcome: 'authorized' });

    const grantsBefore = await prisma.instanceAdvisoryAuthorityGrant.count({
      where: { userId: user.id },
    });
    const disabled = await invoke(databaseUrl, userArgv('disable-user', user.id));
    expect(disabled.exitCode).toBe(0);
    expect(disabled.body).toMatchObject({
      operation: 'disable_user',
      outcome: 'user_disabled',
      authority: null,
      grantId: null,
      acknowledgement: 'committed',
    });
    expect((await prisma.user.findUnique({ where: { id: user.id } }))?.status).toBe('disabled');
    const disabledGrant = await prisma.instanceAdvisoryAuthorityGrant.findFirst({
      where: { userId: user.id },
    });
    expect(disabledGrant?.revokedAt).toBeNull();
    expect(await prisma.instanceAdvisoryAuthorityGrant.count({ where: { userId: user.id } })).toBe(
      grantsBefore,
    );
    expect(
      await authorization.readRequiredAuthority({
        schemaVersion: INSTANCE_ADVISORY_AUTHORIZATION_READ_SCHEMA_VERSION,
        userId: user.id,
        requiredAuthority: 'advisory_submit_local',
      }),
    ).toEqual({ outcome: 'user_inactive' });

    const enabled = await invoke(databaseUrl, userArgv('enable-user', user.id));
    expect(enabled.exitCode).toBe(0);
    expect(enabled.body).toMatchObject({ operation: 'enable_user', outcome: 'user_enabled' });
    expect(enabled.stdout).not.toContain('advisory_submit_local');
    expect(enabled.stdout).not.toContain('"granted"');
    expect(await prisma.instanceAdvisoryAuthorityGrant.count({ where: { userId: user.id } })).toBe(
      grantsBefore,
    );
    expect((await prisma.user.findUnique({ where: { id: user.id } }))?.status).toBe('active');
    const replay = await invoke(databaseUrl, userArgv('enable-user', user.id));
    expect(replay.body).toMatchObject({ outcome: 'already_applied', acknowledgement: 'replayed' });
    expect(await auditCount(prisma, INSTANCE_ADVISORY_AUDIT_ACTIONS.userReenabled, user.id)).toBe(
      1,
    );
    expect(
      await authorization.readRequiredAuthority({
        schemaVersion: INSTANCE_ADVISORY_AUTHORIZATION_READ_SCHEMA_VERSION,
        userId: user.id,
        requiredAuthority: 'advisory_submit_local',
      }),
    ).toEqual({ outcome: 'authorized' });
  });

  it('treats a lost acknowledgement as uncertain and converges on exact rerun', async () => {
    const user = await createUser(prisma, 'uncertain');
    const argv = grantArgv(user.id, 'advisory_submit_local', randomUUID());
    let lost = false;
    const first = await invoke(databaseUrl, argv, async () => {
      const client = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
      const persistence = createInstanceAdvisoryAuthorityPersistence(client);
      const session: InstanceAdvisoryAuthorityCommandSession = {
        port: {
          async execute(command) {
            const result = await persistence.execute(command);
            if (!lost && result.outcome === 'granted') {
              lost = true;
              throw new Error(`acknowledgement lost ${databaseUrl}`);
            }
            return result;
          },
        },
        close: () => client.$disconnect(),
      };
      return session;
    });
    expect(first.exitCode).toBe(1);
    expect(first.body).toMatchObject({
      outcome: 'internal_failure',
      acknowledgement: 'uncertain',
    });
    expect(first.stdout).not.toContain(databaseUrl);
    expect(first.stdout).not.toContain('acknowledgement lost');
    expect(await prisma.instanceAdvisoryAuthorityGrant.count({ where: { userId: user.id } })).toBe(
      1,
    );

    const retry = await invoke(databaseUrl, argv);
    expect(retry.exitCode).toBe(2);
    expect(retry.body).toMatchObject({ outcome: 'already_applied' });
    const grant = await prisma.instanceAdvisoryAuthorityGrant.findFirst({
      where: { userId: user.id },
    });
    expect(await auditCount(prisma, INSTANCE_ADVISORY_AUDIT_ACTIONS.granted, grant?.id ?? '')).toBe(
      1,
    );
  });

  it('rejects organization input and a malformed user before any grant write', async () => {
    const before = await prisma.instanceAdvisoryAuthorityGrant.count();
    const rejected = await invoke(databaseUrl, [
      'grant',
      '--user-id',
      randomUUID(),
      '--organization-id',
      randomUUID(),
      '--authority',
      'advisory_submit_local',
      '--correlation-id',
      randomUUID(),
    ]);
    expect(rejected.exitCode).toBe(3);
    expect(rejected.body).toMatchObject({ outcome: 'invalid_command', targetUserId: null });
    expect(await prisma.instanceAdvisoryAuthorityGrant.count()).toBe(before);
  });

  it('converges concurrent identical command grants to one row and one audit', async () => {
    const user = await createUser(prisma, 'concurrent');
    const [left, right] = await Promise.all([
      invoke(databaseUrl, grantArgv(user.id, 'advisory_submit_local', randomUUID())),
      invoke(databaseUrl, grantArgv(user.id, 'advisory_submit_local', randomUUID())),
    ]);
    expect([left.body['outcome'], right.body['outcome']].sort()).toEqual([
      'already_applied',
      'granted',
    ]);
    expect(await prisma.instanceAdvisoryAuthorityGrant.count({ where: { userId: user.id } })).toBe(
      1,
    );
    const grant = await prisma.instanceAdvisoryAuthorityGrant.findFirstOrThrow({
      where: { userId: user.id },
    });
    expect(await auditCount(prisma, INSTANCE_ADVISORY_AUDIT_ACTIONS.granted, grant.id)).toBe(1);
    expect(`${left.stdout}${right.stdout}${left.stderr}${right.stderr}`).not.toContain(databaseUrl);
  });

  it('keeps disable, revocation, and re-enable distinct through the command', async () => {
    const user = await createUser(prisma, 'lifecycle');
    const granted = await invoke(
      databaseUrl,
      grantArgv(user.id, 'advisory_submit_local', randomUUID()),
    );
    expect(granted.body['outcome']).toBe('granted');
    const grantId = String(granted.body['grantId']);
    const disabled = await invoke(databaseUrl, userArgv('disable-user', user.id));
    expect(disabled.body).toMatchObject({ outcome: 'user_disabled', grantId: null });
    const disableReplay = await invoke(databaseUrl, userArgv('disable-user', user.id));
    expect(disableReplay.exitCode).toBe(2);
    expect(disableReplay.body).toMatchObject({
      outcome: 'already_applied',
      acknowledgement: 'replayed',
    });
    expect(await auditCount(prisma, INSTANCE_ADVISORY_AUDIT_ACTIONS.userDisabled, user.id)).toBe(1);
    expect(
      (await prisma.instanceAdvisoryAuthorityGrant.findUnique({ where: { id: grantId } }))
        ?.revokedAt,
    ).toBeNull();
    const sameWhileDisabled = await invoke(
      databaseUrl,
      grantArgv(user.id, 'advisory_submit_local', randomUUID()),
    );
    expect(sameWhileDisabled.exitCode).toBe(2);
    expect(sameWhileDisabled.body['outcome']).toBe('already_applied');
    const otherWhileDisabled = await invoke(
      databaseUrl,
      grantArgv(user.id, 'advisory_approve_for_product_evaluation', randomUUID()),
    );
    expect(otherWhileDisabled.exitCode).toBe(5);
    expect(otherWhileDisabled.body['outcome']).toBe('active_grant_conflict');
    const wrongAuthority = await invoke(
      databaseUrl,
      revokeArgv(user.id, grantId, 'advisory_approve_for_product_evaluation'),
    );
    expect(wrongAuthority.exitCode).toBe(5);
    expect(wrongAuthority.body).toMatchObject({
      outcome: 'active_authority_mismatch',
      acknowledgement: 'unchanged',
    });
    expect(wrongAuthority.body['acknowledgement']).not.toBe('replayed');
    const revoked = await invoke(
      databaseUrl,
      revokeArgv(user.id, grantId, 'advisory_submit_local'),
    );
    expect(revoked.body).toMatchObject({ outcome: 'revoked', grantId });
    const enabled = await invoke(databaseUrl, userArgv('enable-user', user.id));
    expect(enabled.exitCode).toBe(0);
    expect(enabled.body).toMatchObject({
      operation: 'enable_user',
      outcome: 'user_enabled',
      authority: null,
      grantId: null,
    });
    expect(enabled.stdout).not.toContain('advisory_submit_local');
    expect(enabled.stdout).not.toContain('"granted"');
    expect(
      (await prisma.instanceAdvisoryAuthorityGrant.findUnique({ where: { id: grantId } }))
        ?.revokedAt,
    ).not.toBeNull();
    expect(
      await prisma.instanceAdvisoryAuthorityGrant.count({
        where: { userId: user.id, revokedAt: null },
      }),
    ).toBe(0);
    const other = await invoke(
      databaseUrl,
      grantArgv(user.id, 'advisory_approve_for_product_evaluation', randomUUID()),
    );
    expect(other.exitCode).toBe(0);
    expect(other.body).toMatchObject({
      outcome: 'granted',
      authority: 'advisory_approve_for_product_evaluation',
    });
    expect(other.body['grantId']).not.toBe(grantId);
    expect(
      (await prisma.instanceAdvisoryAuthorityGrant.findUnique({ where: { id: grantId } }))
        ?.revokedAt,
    ).not.toBeNull();
  });

  it('rejects a new grant for a disabled user with no active grant', async () => {
    const user = await createUser(prisma, 'inactive-grant');
    expect((await invoke(databaseUrl, userArgv('disable-user', user.id))).body['outcome']).toBe(
      'user_disabled',
    );
    const denied = await invoke(
      databaseUrl,
      grantArgv(user.id, 'advisory_submit_local', randomUUID()),
    );
    expect(denied.exitCode).toBe(6);
    expect(denied.body).toMatchObject({
      outcome: 'user_inactive',
      acknowledgement: 'unchanged',
    });
    expect(await prisma.instanceAdvisoryAuthorityGrant.count({ where: { userId: user.id } })).toBe(
      0,
    );
  });

  it('hides database credentials when PostgreSQL is unreachable or authentication fails', async () => {
    const before = await prisma.instanceAdvisoryAuthorityGrant.count();
    const captured: string[] = [];
    const stderrWrite = process.stderr.write.bind(process.stderr);
    const stdoutWrite = process.stdout.write.bind(process.stdout);
    process.stderr.write = ((chunk: string | Uint8Array): boolean => {
      captured.push(String(chunk));
      return true;
    }) as typeof process.stderr.write;
    process.stdout.write = ((chunk: string | Uint8Array): boolean => {
      captured.push(String(chunk));
      return true;
    }) as typeof process.stdout.write;
    const secret = 'command-review-secret';
    try {
      const refused = new URL(databaseUrl);
      refused.hostname = '127.0.0.1';
      refused.port = '1';
      refused.password = secret;
      const down = await invoke(
        refused.toString(),
        grantArgv(randomUUID(), 'advisory_submit_local', randomUUID()),
      );
      expect([1, 7]).toContain(down.exitCode);
      expect(['database_unavailable', 'internal_failure']).toContain(down.body['outcome']);
      expect(down.body['acknowledgement']).toBe('uncertain');
      expect(`${down.stdout}${down.stderr}`).not.toContain(secret);

      const rejected = new URL(databaseUrl);
      rejected.password = secret;
      const auth = await invoke(
        rejected.toString(),
        grantArgv(randomUUID(), 'advisory_submit_local', randomUUID()),
      );
      expect(auth.exitCode).not.toBe(0);
      expect(auth.exitCode).not.toBe(2);
      expect(['database_unavailable', 'internal_failure']).toContain(auth.body['outcome']);
      expect(`${auth.stdout}${auth.stderr}`).not.toContain(secret);
      const leaked = captured.join('');
      expect(leaked).not.toContain(secret);
      expect(leaked).not.toContain(refused.toString());
      expect(leaked).not.toContain(rejected.toString());
    } finally {
      process.stderr.write = stderrWrite;
      process.stdout.write = stdoutWrite;
    }
    expect(await prisma.instanceAdvisoryAuthorityGrant.count()).toBe(before);
  });

  it('opens the production boundary for one explicit command', async () => {
    const user = await createUser(prisma, 'production-boundary');
    await disconnectPrisma();
    const result = await invoke(
      databaseUrl,
      userArgv('disable-user', user.id),
      openInstanceAdvisoryAuthorityCommandBoundary,
    );
    expect(result.exitCode).toBe(0);
    expect(result.body).toMatchObject({ outcome: 'user_disabled', targetUserId: user.id });
    expect(result.stdout).not.toContain(databaseUrl);
    expect((await prisma.user.findUnique({ where: { id: user.id } }))?.status).toBe('disabled');
  });
});

async function invoke(
  databaseUrl: string,
  argv: readonly string[],
  openBoundary: (
    databaseUrl: string,
  ) => Promise<InstanceAdvisoryAuthorityCommandSession> = openReal,
): Promise<{
  readonly exitCode: number;
  readonly stdout: string;
  readonly stderr: string;
  readonly body: Record<string, unknown>;
}> {
  const stdout = new MemoryStream();
  const stderr = new MemoryStream();
  const exitCode = await runInstanceAdvisoryAuthorityCommand({
    argv,
    stdout,
    stderr,
    loadDatabaseUrl: () => databaseUrl,
    openBoundary,
  });
  return {
    exitCode,
    stdout: stdout.text,
    stderr: stderr.text,
    body: JSON.parse(stdout.text) as Record<string, unknown>,
  };
}

function openReal(databaseUrl: string): Promise<InstanceAdvisoryAuthorityCommandSession> {
  const client = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
  const persistence = createInstanceAdvisoryAuthorityPersistence(client);
  return Promise.resolve({
    port: {
      execute(command) {
        return persistence.execute(command);
      },
    },
    close: () => client.$disconnect(),
  });
}

function grantArgv(userId: string, authority: string, correlationId: string): string[] {
  return [
    'grant',
    '--user-id',
    userId,
    '--authority',
    authority,
    '--correlation-id',
    correlationId,
  ];
}

function revokeArgv(userId: string, grantId: string, authority: string): string[] {
  return [
    'revoke',
    '--user-id',
    userId,
    '--expected-grant-id',
    grantId,
    '--expected-authority',
    authority,
    '--correlation-id',
    randomUUID(),
  ];
}

function userArgv(operation: 'disable-user' | 'enable-user', userId: string): string[] {
  return [operation, '--user-id', userId, '--correlation-id', randomUUID()];
}

async function createUser(prisma: PrismaClient, label: string) {
  return prisma.user.create({
    data: {
      email: `${label}-${randomUUID().slice(0, 8)}@synthetic.patchpilot.test`,
      displayName: `${label} user`,
    },
  });
}

async function auditCount(
  prisma: PrismaClient,
  action: string,
  subjectId: string,
): Promise<number> {
  return prisma.auditEvent.count({ where: { action, subjectId } });
}

async function counts(prisma: PrismaClient) {
  const [
    organizations,
    memberships,
    advisoryRevisions,
    approvals,
    capabilities,
    productMatch,
    findings,
    observations,
  ] = await Promise.all([
    prisma.organization.count(),
    prisma.membership.count(),
    prisma.advisoryRevision.count(),
    prisma.maintainerReviewedAdvisoryApproval.count(),
    prisma.reviewerCapabilityIssuance.count(),
    prisma.productMatchEvaluationEvidence.count(),
    prisma.finding.count(),
    prisma.findingObservation.count(),
  ]);
  return {
    organizations,
    memberships,
    advisoryRevisions,
    approvals,
    capabilities,
    productMatch,
    findings,
    observations,
  };
}
