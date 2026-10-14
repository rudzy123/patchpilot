/**
 * Disposable PostgreSQL proof for uncomposed local advisory submission.
 * Synthetic identities only. No provider, evaluator, or Finding writes.
 */

import { createHash, randomUUID } from 'node:crypto';
import { PrismaClient } from '@prisma/client';
import {
  INSTANCE_ADVISORY_AUTHORITY_COMMAND_SCHEMA_VERSION,
  parseInstanceAdvisoryAuthorityCommand,
  type InstanceAdvisoryAuthority,
  type InstanceAdvisoryAuthorityCommand,
} from '@patchpilot/domain/instance-advisory-authority';
import {
  EXACT_MAPPING_METHOD,
  MAINTAINER_REVIEWED_ACCEPTED_SPDX,
  MAINTAINER_REVIEWED_ADVISORY_SCHEMA_VERSION,
  MAINTAINER_REVIEWED_SOURCE_LICENSE_POLICY_ID,
  MAINTAINER_REVIEWED_SOURCE_LICENSE_POLICY_VERSION,
  VULNERABILITY_MAPPING_POLICY_ID,
} from '@patchpilot/vulnerability-intelligence';
import {
  MAINTAINER_REVIEWED_ADVISORY_SUBMISSION_AUDIT_ACTION,
  MAINTAINER_REVIEWED_ADVISORY_SUBMISSION_BINDING,
  MAINTAINER_REVIEWED_ADVISORY_SUBMISSION_UNAPPROVED_REVISION,
  localMaintainerReviewedVulnerabilityLabel,
  parseMaintainerReviewedAdvisorySubmissionCommand,
  prepareMaintainerReviewedAdvisorySubmission,
  toMaintainerReviewedAdvisorySubmissionPersistenceCommand,
  type MaintainerReviewedAdvisorySubmissionPersistenceCommand,
} from '@patchpilot/vulnerability-intelligence/maintainer-reviewed-advisory-submission';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
} from './integration-database.js';
import { createInstanceAdvisoryAuthorityPersistence } from './instance-advisory-authority-persistence.js';
import {
  createMaintainerReviewedAdvisorySubmissionPersistence,
  type MaintainerReviewedAdvisorySubmissionPersistenceFault,
} from './maintainer-reviewed-advisory-submission-persistence.js';

const PINS = MAINTAINER_REVIEWED_ADVISORY_SUBMISSION_UNAPPROVED_REVISION;
const BINDING = MAINTAINER_REVIEWED_ADVISORY_SUBMISSION_BINDING;
const CREATED_AT = new Date('2026-06-01T00:00:00.000Z');

type Persistence = ReturnType<typeof createMaintainerReviewedAdvisorySubmissionPersistence>;
type Counts = {
  readonly revisions: number;
  readonly bindings: number;
  readonly audits: number;
  readonly vulnerabilities: number;
  readonly approvals: number;
  readonly capabilities: number;
  readonly productMatch: number;
  readonly matchEvidence: number;
  readonly findings: number;
  readonly observations: number;
  readonly organizations: number;
  readonly memberships: number;
  readonly sourceRecords: number;
};

describe('maintainer-reviewed advisory submission PostgreSQL persistence', () => {
  let databaseUrl = '';
  let databaseName = '';
  let admin: Awaited<ReturnType<typeof createEphemeralDatabase>>['admin'];
  let prisma: PrismaClient;
  let persistence: Persistence;
  let authority: ReturnType<typeof createInstanceAdvisoryAuthorityPersistence>;
  let sequence = 0;

  beforeAll(async () => {
    const ephemeral = await createEphemeralDatabase('it', { scope: 'mras' });
    databaseUrl = ephemeral.databaseUrl;
    databaseName = ephemeral.databaseName;
    admin = ephemeral.admin;
    await deployMigrations(databaseUrl);
    prisma = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
    persistence = createMaintainerReviewedAdvisorySubmissionPersistence(prisma);
    authority = createInstanceAdvisoryAuthorityPersistence(prisma);
  });

  afterAll(async () => {
    if (prisma !== undefined) {
      await prisma.$disconnect();
    }
    if (admin !== undefined && databaseName !== '') {
      await dropEphemeralDatabase(admin, databaseName);
    }
  });

  it('submits one unapproved revision, binding, and audit, then replays without writes', async () => {
    const user = await authorizedUser('submit');
    const org = await prisma.organization.create({
      data: { slug: `sub-${randomUUID().slice(0, 8)}`, name: 'Submission org' },
    });
    const membership = await prisma.membership.create({
      data: { organizationId: org.id, userId: user.id, role: 'owner', joinedAt: CREATED_AT },
    });
    const command = submission(user.id);
    const before = await counts();
    const submitted = await persistence.submit(command);
    expect(submitted.outcome).toBe('submitted');
    if (submitted.outcome !== 'submitted') {
      return;
    }
    const after = await counts();
    expect(after.revisions).toBe(before.revisions + 1);
    expect(after.bindings).toBe(before.bindings + 1);
    expect(after.audits).toBe(before.audits + 1);
    expect(after.vulnerabilities).toBe(before.vulnerabilities + 1);
    expect(after.approvals).toBe(before.approvals);
    expect(after.capabilities).toBe(before.capabilities);
    expect(after.productMatch).toBe(before.productMatch);
    expect(after.matchEvidence).toBe(before.matchEvidence);
    expect(after.findings).toBe(before.findings);
    expect(after.observations).toBe(before.observations);
    expect(after.organizations).toBe(before.organizations);
    expect(after.memberships).toBe(before.memberships);
    expect(after.sourceRecords).toBe(before.sourceRecords);
    const revision = await prisma.advisoryRevision.findUniqueOrThrow({
      where: { id: submitted.revisionId },
    });
    expect(revision.origin).toBe('maintainer_reviewed_advisory');
    expect(revision.trustClassification).toBe('unreviewed');
    expect(revision.authorIdentity).toBe(user.id);
    expect(revision.replayFingerprint).toHaveLength(64);
    const rangeEvents = await prisma.advisoryRevisionRangeEvent.findMany({
      where: { advisoryRevisionId: submitted.revisionId },
      orderBy: [{ rangeOrdinal: 'asc' }, { eventOrdinal: 'asc' }],
    });
    expect(
      rangeEvents.map((event) => ({
        rangeOrdinal: event.rangeOrdinal,
        eventOrdinal: event.eventOrdinal,
        eventName: event.eventName,
        eventValue: event.eventValue,
      })),
    ).toEqual([
      { rangeOrdinal: 0, eventOrdinal: 0, eventName: 'introduced', eventValue: '1.0.0' },
      { rangeOrdinal: 0, eventOrdinal: 1, eventName: 'fixed', eventValue: '1.2.0' },
    ]);
    const vulnerability = await prisma.vulnerability.findUniqueOrThrow({
      where: { id: await revisionBindingVulnerability(submitted.revisionId) },
    });
    expect(vulnerability.osvId).toBe(localMaintainerReviewedVulnerabilityLabel(vulnerability.id));
    expect(vulnerability.cveId).toBeNull();
    const audit = await prisma.auditEvent.findFirstOrThrow({
      where: {
        action: MAINTAINER_REVIEWED_ADVISORY_SUBMISSION_AUDIT_ACTION,
        subjectId: submitted.revisionId,
      },
    });
    expect(audit.actorType).toBe('user');
    expect(audit.actorUserId).toBe(user.id);
    expect(audit.organizationId).toBeNull();
    expect(audit.actorMembershipId).toBeNull();
    expect(audit.schemaVersion).toBe(1);
    expect(audit.retentionCategory).toBe('security');
    const payload = JSON.stringify(audit.payload);
    expect(payload).toContain('sha256');
    expect(payload).toContain('maintainer_reviewed_advisory');
    expect(payload).not.toContain('left-pad');
    expect(payload).not.toContain('introduced');
    expect(payload).not.toContain('SELECT');
    expect(payload).not.toContain(membership.id);
    const replay = await persistence.submit(command);
    expect(replay).toEqual({ outcome: 'already_applied', revisionId: submitted.revisionId });
    const alias = command.document.aliases[0];
    if (alias === undefined) {
      throw new Error('expected alias');
    }
    const otherCorrelation = submission(user.id, {
      family: command.document.advisoryFamilyId,
      vulnerabilityId: command.document.vulnerabilityId,
      alias,
      correlationId: randomUUID(),
    });
    expect(await persistence.submit(otherCorrelation)).toEqual({
      outcome: 'already_applied',
      revisionId: submitted.revisionId,
    });
    expect(await counts()).toEqual(after);
    expect(
      await prisma.advisoryRevisionRangeEvent.count({
        where: { advisoryRevisionId: submitted.revisionId },
      }),
    ).toBe(2);
  });

  it('submits a zero-alias revision without a provider identity', async () => {
    const user = await authorizedUser('no-alias');
    const command = submission(user.id, { withoutAlias: true });
    const submitted = await persistence.submit(command);
    expect(submitted.outcome).toBe('submitted');
    if (submitted.outcome !== 'submitted') {
      return;
    }
    const revision = await prisma.advisoryRevision.findUniqueOrThrow({
      where: { id: submitted.revisionId },
    });
    expect(revision.aliasCount).toBe(0);
    expect(revision.cveAliasCount).toBe(0);
    const binding = await prisma.advisoryVulnerabilityBinding.findUniqueOrThrow({
      where: { advisoryRevisionId: submitted.revisionId },
    });
    expect(binding.bindingClassification).toBe('provider_native_without_cve');
    expect(
      await prisma.vulnerabilitySourceRecord.count({
        where: { vulnerabilityId: command.document.vulnerabilityId },
      }),
    ).toBe(0);
    expect(await persistence.submit(command)).toEqual({
      outcome: 'already_applied',
      revisionId: submitted.revisionId,
    });
  });

  it('reuses a matching local vulnerability and conflicts when the identity disagrees', async () => {
    const user = await authorizedUser('vulnerability');
    const reusable = submission(user.id);
    const vulnerabilityId = reusable.document.vulnerabilityId;
    const created = await prisma.vulnerability.create({
      data: {
        id: vulnerabilityId,
        osvId: localMaintainerReviewedVulnerabilityLabel(vulnerabilityId),
      },
    });
    const before = await counts();
    const submitted = await persistence.submit(reusable);
    expect(submitted.outcome).toBe('submitted');
    const stored = await prisma.vulnerability.findUniqueOrThrow({ where: { id: vulnerabilityId } });
    expect(stored.osvId).toBe(created.osvId);
    expect(stored.updatedAt.getTime()).toBe(created.updatedAt.getTime());
    expect((await counts()).vulnerabilities).toBe(before.vulnerabilities);

    const occupied = submission(user.id);
    await prisma.vulnerability.create({
      data: {
        id: occupied.document.vulnerabilityId,
        osvId: `SYNTHETIC-${occupied.document.advisoryFamilyId}`,
      },
    });
    const occupiedBefore = await counts();
    expect(await persistence.submit(occupied)).toEqual({ outcome: 'immutable_conflict' });
    expect(await counts()).toEqual(occupiedBefore);

    const labeled = submission(user.id);
    await prisma.vulnerability.create({
      data: { osvId: localMaintainerReviewedVulnerabilityLabel(labeled.document.vulnerabilityId) },
    });
    const labeledBefore = await counts();
    expect(await persistence.submit(labeled)).toEqual({ outcome: 'immutable_conflict' });
    expect(await counts()).toEqual(labeledBefore);
  });

  it('conflicts when another authorized author or an immutable pin differs', async () => {
    const first = await authorizedUser('author-a');
    const second = await authorizedUser('author-b');
    const original = submission(first.id);
    const submitted = await persistence.submit(original);
    expect(submitted.outcome).toBe('submitted');
    const before = await counts();
    const otherAuthor = submission(second.id, {
      family: original.document.advisoryFamilyId,
      vulnerabilityId: randomUUID(),
      alias: nextAlias(),
    });
    expect(await persistence.submit(otherAuthor)).toEqual({ outcome: 'immutable_conflict' });
    const changed = submission(first.id, {
      family: original.document.advisoryFamilyId,
      packageName: 'changed-pad',
    });
    expect(await persistence.submit(changed)).toEqual({ outcome: 'immutable_conflict' });
    expect(await counts()).toEqual(before);
  });

  it('classifies stored range, source, binding, and origin defects without writes', async () => {
    const user = await authorizedUser('stored');
    const rangeCommand = submission(user.id);
    await insertRevision(rangeCommand, { rangeFingerprint: digest('range-only') });
    const rangeBefore = await counts();
    expect(await persistence.submit(rangeCommand)).toEqual({ outcome: 'immutable_conflict' });
    expect(await counts()).toEqual(rangeBefore);

    const sourceCommand = submission(user.id);
    await insertRevision(sourceCommand, { familyDigest: digest('source-only') });
    const sourceBefore = await counts();
    expect(await persistence.submit(sourceCommand)).toEqual({
      outcome: 'malformed_persisted_state',
    });
    expect(await counts()).toEqual(sourceBefore);

    const missing = submission(user.id);
    await insertRevision(missing, { binding: 'none', aliases: false });
    const missingBefore = await counts();
    expect(await persistence.submit(missing)).toEqual({ outcome: 'malformed_persisted_state' });
    expect(await counts()).toEqual(missingBefore);

    const conflicting = submission(user.id);
    await insertRevision(conflicting, { binding: 'other' });
    const conflictingBefore = await counts();
    expect(await persistence.submit(conflicting)).toEqual({ outcome: 'malformed_persisted_state' });
    expect(await counts()).toEqual(conflictingBefore);

    const duplicate = submission(user.id);
    await insertRevision(duplicate, {
      binding: 'none',
      aliases: false,
      revisionDigest: digest('dup-a'),
    });
    await insertRevision(duplicate, {
      binding: 'none',
      aliases: false,
      revisionDigest: digest('dup-b'),
    });
    const duplicateBefore = await counts();
    expect(await persistence.submit(duplicate)).toEqual({ outcome: 'malformed_persisted_state' });
    expect(await counts()).toEqual(duplicateBefore);

    const origin = submission(user.id);
    await withoutRevisionChecks(async () => {
      const hostileId = await insertRevision(origin, {
        origin: 'synthetic_fixture',
        binding: 'none',
        aliases: false,
        revisionDigest: digest(`hostile:${origin.document.advisoryFamilyId}`),
      });
      try {
        const originBefore = await counts();
        expect(await persistence.submit(origin)).toEqual({ outcome: 'unsupported_origin' });
        expect(await counts()).toEqual(originBefore);
      } finally {
        await deleteRevision(hostileId);
      }
    });

    const unequal = submission(user.id);
    await withoutRevisionChecks(async () => {
      const unequalId = await insertUnequalRanges(unequal);
      try {
        const unequalBefore = await counts();
        expect(await persistence.submit(unequal)).toEqual({ outcome: 'malformed_persisted_state' });
        expect(await counts()).toEqual(unequalBefore);
      } finally {
        await deleteRevision(unequalId);
      }
    });
  });

  it('rejects replay when stored range events, schema pins, or the submission audit are incomplete', async () => {
    const user = await authorizedUser('envelope');
    const missingRanges = submission(user.id);
    await insertRevision(missingRanges, { ranges: false });
    const missingBefore = await counts();
    expect(await persistence.submit(missingRanges)).toEqual({
      outcome: 'malformed_persisted_state',
    });
    expect(await counts()).toEqual(missingBefore);

    const schema = submission(user.id);
    await withoutRevisionChecks(async () => {
      const schemaId = await insertRevision(schema, { parserId: 'hostile-parser' });
      try {
        const schemaBefore = await counts();
        expect(await persistence.submit(schema)).toEqual({ outcome: 'malformed_persisted_state' });
        expect(await counts()).toEqual(schemaBefore);
      } finally {
        await deleteRevision(schemaId);
      }
    });

    const audited = submission(user.id);
    const submitted = await persistence.submit(audited);
    expect(submitted.outcome).toBe('submitted');
    if (submitted.outcome !== 'submitted') {
      return;
    }
    const before = await counts();
    await prisma.$executeRaw`
      ALTER TABLE "audit_event" DISABLE TRIGGER "audit_event_append_only"
    `;
    try {
      await prisma.$executeRaw`
        DELETE FROM "audit_event"
        WHERE "action" = ${MAINTAINER_REVIEWED_ADVISORY_SUBMISSION_AUDIT_ACTION}
          AND "subject_id" = ${submitted.revisionId}::uuid
      `;
      expect(await persistence.submit(audited)).toEqual({ outcome: 'malformed_persisted_state' });
      expect(await counts()).toEqual({ ...before, audits: before.audits - 1 });
    } finally {
      await prisma.$executeRaw`
        ALTER TABLE "audit_event" ENABLE TRIGGER "audit_event_append_only"
      `;
    }
  });

  it('treats a second binding as malformed when the uniqueness index is removed', async () => {
    const user = await authorizedUser('duplicate-binding');
    const command = submission(user.id);
    const revisionId = await insertRevision(command, { binding: 'matching' });
    await prisma.$executeRaw`
      DROP INDEX "advisory_vulnerability_binding_revision_uidx"
    `;
    try {
      const other = await prisma.vulnerability.create({
        data: { osvId: `SYNTHETIC-BIND-${command.document.advisoryFamilyId}` },
        select: { id: true },
      });
      await prisma.advisoryVulnerabilityBinding.create({
        data: bindingData(revisionId, other.id, digest('second-binding')),
      });
      const before = await counts();
      expect(await persistence.submit(command)).toEqual({ outcome: 'malformed_persisted_state' });
      expect(await counts()).toEqual(before);
    } finally {
      await prisma.$executeRaw`
        ALTER TABLE "advisory_vulnerability_binding"
        DISABLE TRIGGER "advisory_vulnerability_binding_append_only"
      `;
      await prisma.$executeRaw`
        DELETE FROM "advisory_vulnerability_binding"
        WHERE "advisory_revision_id" = ${revisionId}::uuid
          AND "replay_fingerprint" = ${digest('second-binding')}
      `;
      await prisma.$executeRaw`
        ALTER TABLE "advisory_vulnerability_binding"
        ENABLE TRIGGER "advisory_vulnerability_binding_append_only"
      `;
      await prisma.$executeRaw`
        CREATE UNIQUE INDEX "advisory_vulnerability_binding_revision_uidx"
        ON "advisory_vulnerability_binding" ("advisory_revision_id")
      `;
    }
  });

  it('reloads submission authority and ignores tenant membership', async () => {
    const active = await createUser('no-grant');
    const org = await prisma.organization.create({
      data: { slug: `none-${randomUUID().slice(0, 8)}`, name: 'No grant org' },
    });
    await prisma.membership.create({
      data: { organizationId: org.id, userId: active.id, role: 'admin', joinedAt: CREATED_AT },
    });
    const before = await counts();
    expect(await persistence.submit(submission(active.id))).toEqual({
      outcome: 'authority_rejected',
    });
    expect(await counts()).toEqual(before);

    const approver = await authorizedUser(
      'approve-only',
      'advisory_approve_for_product_evaluation',
    );
    expect(await persistence.submit(submission(approver.id))).toEqual({
      outcome: 'authority_rejected',
    });

    const disabled = await authorizedUser('disabled');
    const disabledCommand = disableUser(disabled.id);
    expect((await authority.execute(disabledCommand)).outcome).toBe('user_disabled');
    expect(await persistence.submit(submission(disabled.id))).toEqual({
      outcome: 'authority_rejected',
    });

    expect(await persistence.submit(submission(randomUUID()))).toEqual({
      outcome: 'authority_rejected',
    });
    const legalPrincipal = submission(active.id);
    expect(
      await persistence.submit({ ...legalPrincipal, trustedSubmitterUserId: 'not-a-principal' }),
    ).toEqual({ outcome: 'authority_required' });

    const revoked = await authorizedUser('revoked');
    const grants = await prisma.instanceAdvisoryAuthorityGrant.findMany({
      where: { userId: revoked.id, revokedAt: null },
    });
    const grant = grants[0];
    if (grant === undefined) {
      throw new Error('expected grant');
    }
    expect(
      (await authority.execute(revokeGrant(revoked.id, grant.id, 'advisory_submit_local'))).outcome,
    ).toBe('revoked');
    const revokedBefore = await counts();
    expect(await persistence.submit(submission(revoked.id))).toEqual({
      outcome: 'authority_rejected',
    });
    expect(await counts()).toEqual(revokedBefore);
  });

  it('fails closed when two active grants bypass the uniqueness index', async () => {
    const user = await authorizedUser('two-grants');
    const first = await prisma.instanceAdvisoryAuthorityGrant.findFirstOrThrow({
      where: { userId: user.id, revokedAt: null },
    });
    await prisma.$executeRaw`DROP INDEX "instance_advisory_authority_grant_one_active_user_idx"`;
    let secondId = '';
    try {
      secondId = await insertSecondGrant(user.id);
      const before = await counts();
      expect(await persistence.submit(submission(user.id))).toEqual({
        outcome: 'malformed_persisted_state',
      });
      expect(await counts()).toEqual(before);
    } finally {
      await revokeGrantRow(first.id, user.id, 'advisory_submit_local');
      if (secondId !== '') {
        await revokeGrantRow(secondId, user.id, 'advisory_approve_for_product_evaluation');
      }
      await prisma.$executeRaw`
        CREATE UNIQUE INDEX "instance_advisory_authority_grant_one_active_user_idx"
        ON "instance_advisory_authority_grant" ("user_id")
        WHERE "revoked_at" IS NULL
      `;
    }
  });

  it('rolls back every fault before commit and retries the same command exactly once', async () => {
    const faults: readonly MaintainerReviewedAdvisorySubmissionPersistenceFault[] = [
      'before_user_lock',
      'before_grant_lock',
      'before_natural_identity_lock',
      'before_replay_load',
      'before_vulnerability_resolution',
      'before_vulnerability_insert',
      'before_revision_insert',
      'before_binding_insert',
      'before_audit_insert',
      'before_stored_state_validation',
      'skip_alias_insert',
      'skip_audit_insert',
      'fail_stored_state_validation',
    ];
    for (const fault of faults) {
      const user = await authorizedUser(fault);
      const command = submission(user.id);
      const before = await counts();
      expect(await persistence.submit(command, { fault })).toEqual({
        outcome: 'transaction_aborted',
      });
      expect(await counts()).toEqual(before);
      const retried = await persistence.submit(command);
      expect(retried.outcome).toBe('submitted');
    }
  });

  it('treats a lost commit acknowledgment as an exact replay on retry', async () => {
    const user = await authorizedUser('uncertain');
    const command = submission(user.id);
    const before = await counts();
    expect(await persistence.submit(command, { fault: 'lose_acknowledgment' })).toEqual({
      outcome: 'transaction_aborted',
    });
    const committed = await counts();
    expect(committed.revisions).toBe(before.revisions + 1);
    expect(committed.bindings).toBe(before.bindings + 1);
    expect(committed.audits).toBe(before.audits + 1);
    const replay = await persistence.submit(command);
    expect(replay.outcome).toBe('already_applied');
    expect(await counts()).toEqual(committed);
  });

  it('converges concurrent identical and conflicting submissions', async () => {
    const user = await authorizedUser('concurrent-same');
    const command = submission(user.id);
    const firstClient = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
    const secondClient = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
    try {
      const [left, right] = await Promise.all([
        createMaintainerReviewedAdvisorySubmissionPersistence(firstClient).submit(command),
        createMaintainerReviewedAdvisorySubmissionPersistence(secondClient).submit(command),
      ]);
      const outcomes = [left.outcome, right.outcome].sort();
      expect(outcomes).toEqual(['already_applied', 'submitted']);
      const revisionId =
        left.outcome === 'submitted'
          ? left.revisionId
          : right.outcome === 'submitted'
            ? right.revisionId
            : '';
      expect(
        await prisma.advisoryRevision.count({
          where: { advisoryId: command.document.advisoryFamilyId },
        }),
      ).toBe(1);
      expect(
        await prisma.advisoryVulnerabilityBinding.count({
          where: { advisoryRevisionId: revisionId },
        }),
      ).toBe(1);
      expect(
        await prisma.auditEvent.count({
          where: {
            action: MAINTAINER_REVIEWED_ADVISORY_SUBMISSION_AUDIT_ACTION,
            subjectId: revisionId,
          },
        }),
      ).toBe(1);
    } finally {
      await firstClient.$disconnect();
      await secondClient.$disconnect();
    }

    const authorA = await authorizedUser('concurrent-a');
    const authorB = await authorizedUser('concurrent-b');
    const family = nextFamily();
    const leftCommand = submission(authorA.id, { family });
    const rightCommand = submission(authorB.id, {
      family,
      vulnerabilityId: randomUUID(),
      alias: nextAlias(),
    });
    const authorLeft = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
    const authorRight = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
    try {
      const [left, right] = await Promise.all([
        createMaintainerReviewedAdvisorySubmissionPersistence(authorLeft).submit(leftCommand),
        createMaintainerReviewedAdvisorySubmissionPersistence(authorRight).submit(rightCommand),
      ]);
      expect([left.outcome, right.outcome].sort()).toEqual(['immutable_conflict', 'submitted']);
      expect(await prisma.advisoryRevision.count({ where: { advisoryId: family } })).toBe(1);
      expect(
        await prisma.auditEvent.count({
          where: {
            action: MAINTAINER_REVIEWED_ADVISORY_SUBMISSION_AUDIT_ACTION,
            subjectType: 'advisory_revision',
            subjectId: {
              in: (
                await prisma.advisoryRevision.findMany({
                  where: { advisoryId: family },
                  select: { id: true },
                })
              ).map((row) => row.id),
            },
          },
        }),
      ).toBe(1);
    } finally {
      await authorLeft.$disconnect();
      await authorRight.$disconnect();
    }
  });

  it('lets a committed user disablement or grant revocation win the user lock', async () => {
    const disabled = await authorizedUser('race-disable');
    const disableCommand = submission(disabled.id);
    const holder = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
    let userLocked!: () => void;
    const userLockedPromise = new Promise<void>((resolve) => {
      userLocked = resolve;
    });
    try {
      const disabling = holder.$transaction(
        async (tx) => {
          await tx.$queryRaw`SELECT set_config('patchpilot.instance_advisory_user_status', 'on', true)`;
          await tx.$queryRaw`SELECT "id" FROM "user" WHERE "id" = ${disabled.id}::uuid FOR UPDATE`;
          userLocked();
          await waitForUngrantedLock(prisma);
          const correlationId = randomUUID();
          await tx.$executeRaw`
            UPDATE "user"
            SET "status" = 'disabled'::"user_status",
                "disabled_at" = CURRENT_TIMESTAMP,
                "updated_at" = CURRENT_TIMESTAMP,
                "version" = "version" + 1
            WHERE "id" = ${disabled.id}::uuid
          `;
          await insertSystemAudit(tx, {
            action: 'auth.user_disabled',
            subjectType: 'user',
            subjectId: disabled.id,
            correlationId,
            metadata: { correlationId, targetUserId: disabled.id },
          });
        },
        { timeout: 15_000 },
      );
      await userLockedPromise;
      const before = await counts();
      const [, result] = await Promise.all([disabling, persistence.submit(disableCommand)]);
      expect(result).toEqual({ outcome: 'authority_rejected' });
      expect((await counts()).revisions).toBe(before.revisions);
    } finally {
      await holder.$disconnect();
    }

    const revoked = await authorizedUser('race-revoke');
    const grant = await prisma.instanceAdvisoryAuthorityGrant.findFirstOrThrow({
      where: { userId: revoked.id, revokedAt: null },
    });
    const revokeHolder = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
    let grantLocked!: () => void;
    const grantLockedPromise = new Promise<void>((resolve) => {
      grantLocked = resolve;
    });
    try {
      const before = await counts();
      const revoking = revokeHolder.$transaction(
        async (tx) => {
          await tx.$queryRaw`SELECT set_config('patchpilot.instance_advisory_authority_grant', 'on', true)`;
          await tx.$queryRaw`SELECT "id" FROM "user" WHERE "id" = ${revoked.id}::uuid FOR UPDATE`;
          grantLocked();
          await waitForUngrantedLock(prisma);
          await tx.$executeRaw`
            UPDATE "instance_advisory_authority_grant"
            SET "revoked_at" = CURRENT_TIMESTAMP
            WHERE "id" = ${grant.id}::uuid
          `;
          const correlationId = randomUUID();
          await insertSystemAudit(tx, {
            action: 'intelligence.instance_advisory_authority_revoked',
            subjectType: 'instance_advisory_authority_grant',
            subjectId: grant.id,
            correlationId,
            metadata: {
              authority: 'advisory_submit_local',
              correlationId,
              issuanceClassification: 'deployment_local_command',
              targetUserId: revoked.id,
            },
          });
        },
        { timeout: 15_000 },
      );
      await grantLockedPromise;
      const [, result] = await Promise.all([revoking, persistence.submit(submission(revoked.id))]);
      expect(result).toEqual({ outcome: 'authority_rejected' });
      expect(await counts()).toEqual(before);
    } finally {
      await revokeHolder.$disconnect();
    }
  });

  it('reports database unavailability without a persistence row', async () => {
    const dead = new PrismaClient({
      datasources: {
        db: { url: 'postgresql://patchpilot:patchpilot@127.0.0.1:1/none?connect_timeout=1' },
      },
    });
    try {
      const user = await authorizedUser('offline');
      const result = await createMaintainerReviewedAdvisorySubmissionPersistence(dead).submit(
        submission(user.id),
      );
      expect(result).toEqual({ outcome: 'database_unavailable' });
      expect(JSON.stringify(result)).not.toContain('postgresql');
    } finally {
      await dead.$disconnect();
    }
  });

  async function authorizedUser(
    label: string,
    grantAuthority: InstanceAdvisoryAuthority = 'advisory_submit_local',
  ) {
    const user = await createUser(label);
    const granted = await authority.execute(grantCommand(user.id, grantAuthority));
    if (granted.outcome !== 'granted') {
      throw new Error(`grant failed: ${granted.outcome}`);
    }
    return user;
  }

  async function createUser(label: string) {
    return prisma.user.create({
      data: {
        email: `${label}-${randomUUID().slice(0, 8)}@synthetic.patchpilot.test`,
        displayName: `${label} user`,
      },
    });
  }

  function submission(
    userId: string,
    overrides: {
      readonly family?: string;
      readonly packageName?: string;
      readonly vulnerabilityId?: string;
      readonly correlationId?: string;
      readonly alias?: string;
      readonly withoutAlias?: boolean;
    } = {},
  ): MaintainerReviewedAdvisorySubmissionPersistenceCommand {
    sequence += 1;
    const parsed = parseMaintainerReviewedAdvisorySubmissionCommand({
      schemaVersion: MAINTAINER_REVIEWED_ADVISORY_SCHEMA_VERSION,
      advisoryFamilyId: overrides.family ?? nextFamily(),
      revisionNumber: 1,
      vulnerabilityId: overrides.vulnerabilityId ?? randomUUID(),
      aliases: overrides.withoutAlias === true ? [] : [overrides.alias ?? nextAlias()],
      packageEcosystem: 'npm',
      packageName: overrides.packageName ?? 'left-pad',
      packageUrl: null,
      affectedRanges: [{ type: 'SEMVER', events: [{ introduced: '1.0.0' }, { fixed: '1.2.0' }] }],
      withdrawal: 'not_withdrawn',
      supersedesRevisionId: null,
      sourceLicenseDecision: {
        policyId: MAINTAINER_REVIEWED_SOURCE_LICENSE_POLICY_ID,
        policyVersion: MAINTAINER_REVIEWED_SOURCE_LICENSE_POLICY_VERSION,
        spdxLicenseId: MAINTAINER_REVIEWED_ACCEPTED_SPDX,
        productUse: 'permitted_for_internal_matching',
        modification: 'permitted',
        redistribution: 'permitted',
        notice: 'required',
        contentProvenance: 'maintainer_original',
        decision: 'accepted',
      },
      authorIdentity: userId,
      submissionCorrelationId: overrides.correlationId ?? randomUUID(),
    });
    if (!parsed.ok) {
      throw new Error(`command rejected: ${parsed.outcome}`);
    }
    const prepared = prepareMaintainerReviewedAdvisorySubmission(userId, parsed.command);
    if (!prepared.ok) {
      throw new Error(`preparation rejected: ${prepared.outcome}`);
    }
    return toMaintainerReviewedAdvisorySubmissionPersistenceCommand(prepared.prepared);
  }

  function nextFamily(): string {
    return `FAMILY${String(sequence).padStart(4, '0')}${randomUUID().replaceAll('-', '').slice(0, 8).toUpperCase()}`;
  }

  function nextAlias(): string {
    return `CVE-2026-${String(10000 + sequence)}`;
  }

  async function counts(): Promise<Counts> {
    const [
      revisions,
      bindings,
      audits,
      vulnerabilities,
      approvals,
      capabilities,
      productMatch,
      matchEvidence,
      findings,
      observations,
      organizations,
      memberships,
      sourceRecords,
    ] = await Promise.all([
      prisma.advisoryRevision.count(),
      prisma.advisoryVulnerabilityBinding.count(),
      prisma.auditEvent.count({
        where: { action: MAINTAINER_REVIEWED_ADVISORY_SUBMISSION_AUDIT_ACTION },
      }),
      prisma.vulnerability.count(),
      prisma.maintainerReviewedAdvisoryApproval.count(),
      prisma.reviewerCapabilityIssuance.count(),
      prisma.productMatchEvaluationEvidence.count(),
      prisma.matchEvaluationEvidence.count(),
      prisma.finding.count(),
      prisma.findingObservation.count(),
      prisma.organization.count(),
      prisma.membership.count(),
      prisma.vulnerabilitySourceRecord.count(),
    ]);
    return {
      revisions,
      bindings,
      audits,
      vulnerabilities,
      approvals,
      capabilities,
      productMatch,
      matchEvidence,
      findings,
      observations,
      organizations,
      memberships,
      sourceRecords,
    };
  }

  async function revisionBindingVulnerability(revisionId: string): Promise<string> {
    const binding = await prisma.advisoryVulnerabilityBinding.findUniqueOrThrow({
      where: { advisoryRevisionId: revisionId },
    });
    return binding.vulnerabilityId;
  }

  async function insertRevision(
    command: MaintainerReviewedAdvisorySubmissionPersistenceCommand,
    options: {
      readonly rangeFingerprint?: string;
      readonly familyDigest?: string;
      readonly revisionDigest?: string;
      readonly binding?: 'matching' | 'other' | 'none';
      readonly aliases?: boolean;
      readonly ranges?: boolean;
      readonly origin?: 'maintainer_reviewed_advisory' | 'synthetic_fixture';
      readonly parserId?: string;
    } = {},
  ): Promise<string> {
    const document = command.document;
    const fingerprints = command.fingerprints;
    const familyDigest = options.familyDigest ?? fingerprints.familyDigest;
    const rangeFingerprint = options.rangeFingerprint ?? fingerprints.rangeFingerprint;
    const includeAliases = options.aliases !== false;
    const family = await prisma.advisoryFamily.upsert({
      where: {
        source_advisoryId: {
          source: 'maintainer_reviewed_advisory',
          advisoryId: document.advisoryFamilyId,
        },
      },
      update: {},
      create: {
        familySchemaVersion: PINS.familySchema,
        source: 'maintainer_reviewed_advisory',
        advisoryId: document.advisoryFamilyId,
        familyDigest,
        sourceRegistryVersion: PINS.sourceRegistry,
      },
    });
    const vulnerabilityId = options.binding === 'other' ? randomUUID() : document.vulnerabilityId;
    if (options.binding !== 'none') {
      await prisma.vulnerability.upsert({
        where: { id: vulnerabilityId },
        update: {},
        create: {
          id: vulnerabilityId,
          osvId:
            options.binding === 'matching'
              ? localMaintainerReviewedVulnerabilityLabel(vulnerabilityId)
              : `SYNTHETIC-${vulnerabilityId}`,
        },
      });
    }
    const revision = await prisma.advisoryRevision.create({
      data: {
        revisionSchemaVersion: PINS.revisionSchema,
        advisoryFamilyId: family.id,
        source: 'maintainer_reviewed_advisory',
        advisoryId: document.advisoryFamilyId,
        familyDigest,
        revisionDigest: options.revisionDigest ?? fingerprints.revisionDigest,
        providerGeneration: PINS.providerGeneration,
        contentFingerprint: fingerprints.contentFingerprint,
        session14RangeFingerprint: rangeFingerprint,
        productRangeFingerprint: rangeFingerprint,
        parserId: options.parserId ?? PINS.parserId,
        parserResourcePolicy: PINS.parserResourcePolicy,
        advisorySchemaVersion: PINS.documentSchema,
        advisorySchemaCommit: PINS.schemaCommit,
        sourceLicenseRegistryVersion: PINS.sourceRegistry,
        sourceLicensePolicyVersion: '1',
        spdxLicenseId: MAINTAINER_REVIEWED_ACCEPTED_SPDX,
        origin: options.origin ?? 'maintainer_reviewed_advisory',
        trustClassification: 'unreviewed',
        revisionDisposition: 'recorded',
        withdrawalClassification: 'not_withdrawn',
        quarantineClassification: 'not_quarantined',
        supersedesRevisionDigest: 'none',
        retrievalClassification: 'local_not_retrieved',
        retrievalEvidenceId: PINS.retrievalEvidence,
        retrievalPolicyId: PINS.retrievalPolicy,
        ecosystem: 'npm',
        packageName: document.packageName,
        packageIdentityKey: document.packageIdentityKey,
        evaluatorVersion: PINS.evaluatorVersion,
        matchingPolicyId: PINS.matchingPolicyId,
        aliasCount: includeAliases ? document.aliases.length : 0,
        cveAliasCount: includeAliases ? document.aliases.length : 0,
        aliasSetDigest: digest(
          `aliases:${document.advisoryFamilyId}:${options.revisionDigest ?? 'one'}`,
        ),
        replayFingerprint: digest(
          `replay:${document.advisoryFamilyId}:${options.revisionDigest ?? rangeFingerprint}`,
        ),
        authorIdentity: command.trustedSubmitterUserId,
        ...(includeAliases
          ? {
              aliases: {
                create: document.aliases.map((alias, index) => ({
                  ordinal: index + 1,
                  aliasType: 'canonical_cve' as const,
                  aliasValue: alias,
                  aliasPolicyVersion: BINDING.aliasPolicyVersion,
                  sourceClassification: 'maintainer_reviewed_advisory' as const,
                  reviewClassification: 'unreviewed' as const,
                  replayFingerprint: digest(
                    `alias:${alias}:${options.revisionDigest ?? document.advisoryFamilyId}`,
                  ),
                })),
              },
            }
          : {}),
        ...(options.binding === 'none'
          ? {}
          : {
              binding: {
                create: bindingData(
                  '',
                  vulnerabilityId,
                  digest(
                    `binding:${document.advisoryFamilyId}:${options.revisionDigest ?? rangeFingerprint}`,
                  ),
                ),
              },
            }),
      },
    });
    if (options.ranges !== false) {
      await prisma.advisoryRevisionRangeEvent.createMany({
        data: document.affectedRanges.flatMap((range, rangeOrdinal) =>
          range.events.flatMap((event, eventOrdinal) => {
            const eventName = Object.keys(event)[0];
            const eventValue =
              eventName === undefined ? undefined : event[eventName as keyof typeof event];
            if (eventName === undefined || typeof eventValue !== 'string') {
              return [];
            }
            return [
              {
                advisoryRevisionId: revision.id,
                rangeOrdinal,
                eventOrdinal,
                eventName,
                eventValue,
              },
            ];
          }),
        ),
      });
    }
    return revision.id;
  }

  async function insertUnequalRanges(
    command: MaintainerReviewedAdvisorySubmissionPersistenceCommand,
  ): Promise<string> {
    const document = command.document;
    const family = await prisma.advisoryFamily
      .findFirstOrThrow({
        where: { source: 'maintainer_reviewed_advisory', advisoryId: document.advisoryFamilyId },
      })
      .catch(async () =>
        prisma.advisoryFamily.create({
          data: {
            familySchemaVersion: PINS.familySchema,
            source: 'maintainer_reviewed_advisory',
            advisoryId: document.advisoryFamilyId,
            familyDigest: command.fingerprints.familyDigest,
            sourceRegistryVersion: PINS.sourceRegistry,
          },
        }),
      );
    await prisma.vulnerability.create({
      data: {
        id: document.vulnerabilityId,
        osvId: localMaintainerReviewedVulnerabilityLabel(document.vulnerabilityId),
      },
    });
    const revision = await prisma.advisoryRevision.create({
      data: {
        revisionSchemaVersion: PINS.revisionSchema,
        advisoryFamilyId: family.id,
        source: 'maintainer_reviewed_advisory',
        advisoryId: document.advisoryFamilyId,
        familyDigest: command.fingerprints.familyDigest,
        revisionDigest: digest(`unequal:${document.advisoryFamilyId}`),
        providerGeneration: PINS.providerGeneration,
        contentFingerprint: command.fingerprints.contentFingerprint,
        session14RangeFingerprint: command.fingerprints.rangeFingerprint,
        productRangeFingerprint: digest('product-disagrees'),
        parserId: PINS.parserId,
        parserResourcePolicy: PINS.parserResourcePolicy,
        advisorySchemaVersion: PINS.documentSchema,
        advisorySchemaCommit: PINS.schemaCommit,
        sourceLicenseRegistryVersion: PINS.sourceRegistry,
        sourceLicensePolicyVersion: '1',
        spdxLicenseId: MAINTAINER_REVIEWED_ACCEPTED_SPDX,
        origin: 'maintainer_reviewed_advisory',
        trustClassification: 'unreviewed',
        revisionDisposition: 'recorded',
        withdrawalClassification: 'not_withdrawn',
        quarantineClassification: 'not_quarantined',
        supersedesRevisionDigest: 'none',
        retrievalClassification: 'local_not_retrieved',
        retrievalEvidenceId: PINS.retrievalEvidence,
        retrievalPolicyId: PINS.retrievalPolicy,
        ecosystem: 'npm',
        packageName: document.packageName,
        packageIdentityKey: document.packageIdentityKey,
        evaluatorVersion: PINS.evaluatorVersion,
        matchingPolicyId: PINS.matchingPolicyId,
        aliasCount: 0,
        cveAliasCount: 0,
        aliasSetDigest: digest(`unequal-aliases:${document.advisoryFamilyId}`),
        replayFingerprint: digest(`unequal-replay:${document.advisoryFamilyId}`),
        authorIdentity: command.trustedSubmitterUserId,
      },
    });
    await prisma.advisoryVulnerabilityBinding.create({
      data: {
        ...bindingData(
          revision.id,
          document.vulnerabilityId,
          digest(`unequal-binding:${document.advisoryFamilyId}`),
        ),
        bindingClassification: 'provider_native_without_cve',
      },
    });
    return revision.id;
  }

  async function withoutRevisionChecks<T>(run: () => Promise<T>): Promise<T> {
    const names = [
      'advisory_revision_pin_chk',
      'advisory_revision_classification_chk',
      'advisory_revision_author_chk',
    ];
    const definitions = new Map<string, string>();
    for (const name of names) {
      const rows = await prisma.$queryRaw<Array<{ definition: string }>>`
        SELECT pg_get_constraintdef(oid) AS definition
        FROM pg_constraint
        WHERE conname = ${name}
      `;
      const definition = rows[0]?.definition;
      if (definition === undefined) {
        throw new Error(`missing ${name}`);
      }
      definitions.set(name, definition);
      await prisma.$executeRawUnsafe(`ALTER TABLE "advisory_revision" DROP CONSTRAINT "${name}"`);
    }
    try {
      return await run();
    } finally {
      for (const name of names) {
        const definition = definitions.get(name);
        await prisma.$executeRawUnsafe(
          `ALTER TABLE "advisory_revision" ADD CONSTRAINT "${name}" ${definition ?? ''}`,
        );
      }
    }
  }

  async function deleteRevision(revisionId: string): Promise<void> {
    await prisma.$executeRaw`
      ALTER TABLE "advisory_revision_range_event" DISABLE TRIGGER "advisory_revision_range_event_append_only"
    `;
    await prisma.$executeRaw`
      ALTER TABLE "advisory_vulnerability_binding" DISABLE TRIGGER "advisory_vulnerability_binding_append_only"
    `;
    await prisma.$executeRaw`
      ALTER TABLE "advisory_revision_alias" DISABLE TRIGGER "advisory_revision_alias_append_only"
    `;
    await prisma.$executeRaw`
      ALTER TABLE "advisory_revision" DISABLE TRIGGER "advisory_revision_append_only"
    `;
    try {
      await prisma.$executeRaw`
        DELETE FROM "advisory_revision_range_event" WHERE "advisory_revision_id" = ${revisionId}::uuid
      `;
      await prisma.$executeRaw`
        DELETE FROM "advisory_vulnerability_binding" WHERE "advisory_revision_id" = ${revisionId}::uuid
      `;
      await prisma.$executeRaw`
        DELETE FROM "advisory_revision_alias" WHERE "advisory_revision_id" = ${revisionId}::uuid
      `;
      await prisma.$executeRaw`DELETE FROM "advisory_revision" WHERE "id" = ${revisionId}::uuid`;
    } finally {
      await prisma.$executeRaw`
        ALTER TABLE "advisory_revision" ENABLE TRIGGER "advisory_revision_append_only"
      `;
      await prisma.$executeRaw`
        ALTER TABLE "advisory_revision_alias" ENABLE TRIGGER "advisory_revision_alias_append_only"
      `;
      await prisma.$executeRaw`
        ALTER TABLE "advisory_vulnerability_binding" ENABLE TRIGGER "advisory_vulnerability_binding_append_only"
      `;
      await prisma.$executeRaw`
        ALTER TABLE "advisory_revision_range_event" ENABLE TRIGGER "advisory_revision_range_event_append_only"
      `;
    }
  }

  async function insertSecondGrant(userId: string): Promise<string> {
    const correlationId = randomUUID();
    const rows = await prisma.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT set_config('patchpilot.instance_advisory_authority_grant', 'on', true)`;
      const inserted = await tx.$queryRaw<Array<{ id: string }>>`
        INSERT INTO "instance_advisory_authority_grant" (
          "user_id", "authority", "issuance_classification", "issued_at", "command_correlation_id"
        ) VALUES (
          ${userId}::uuid,
          'advisory_approve_for_product_evaluation'::"instance_advisory_authority",
          'deployment_local_command'::"instance_advisory_issuance_classification",
          CURRENT_TIMESTAMP,
          ${correlationId}::uuid
        )
        RETURNING "id"::text AS id
      `;
      const id = inserted[0]?.id;
      if (id === undefined) {
        throw new Error('second grant was not inserted');
      }
      await insertSystemAudit(tx, {
        action: 'intelligence.instance_advisory_authority_granted',
        subjectType: 'instance_advisory_authority_grant',
        subjectId: id,
        correlationId,
        metadata: {
          authority: 'advisory_approve_for_product_evaluation',
          correlationId,
          issuanceClassification: 'deployment_local_command',
          targetUserId: userId,
        },
      });
      return inserted;
    });
    const id = rows[0]?.id;
    if (id === undefined) {
      throw new Error('second grant was not inserted');
    }
    return id;
  }

  async function revokeGrantRow(
    grantId: string,
    userId: string,
    grantAuthority: InstanceAdvisoryAuthority,
  ): Promise<void> {
    const correlationId = randomUUID();
    await prisma.$transaction(async (tx) => {
      await tx.$queryRaw`SELECT set_config('patchpilot.instance_advisory_authority_grant', 'on', true)`;
      await tx.$executeRaw`
        UPDATE "instance_advisory_authority_grant"
        SET "revoked_at" = CURRENT_TIMESTAMP
        WHERE "id" = ${grantId}::uuid AND "revoked_at" IS NULL
      `;
      await insertSystemAudit(tx, {
        action: 'intelligence.instance_advisory_authority_revoked',
        subjectType: 'instance_advisory_authority_grant',
        subjectId: grantId,
        correlationId,
        metadata: {
          authority: grantAuthority,
          correlationId,
          issuanceClassification: 'deployment_local_command',
          targetUserId: userId,
        },
      });
    });
  }
});

function bindingData(revisionId: string, vulnerabilityId: string, replayFingerprint: string) {
  return {
    ...(revisionId === '' ? {} : { advisoryRevisionId: revisionId }),
    bindingSchemaVersion: BINDING.schemaVersion,
    vulnerabilityId,
    mappingPolicyId: VULNERABILITY_MAPPING_POLICY_ID,
    mappingMethod: EXACT_MAPPING_METHOD,
    mappingEvidenceFingerprint: digest(`mapping:${replayFingerprint}`),
    mappingReviewState: BINDING.mappingReviewState,
    mappingSourceClassification: BINDING.mappingSourceClassification,
    conflictClassification: BINDING.conflictClassification,
    bindingClassification: 'one_cve_alias_evidence' as const,
    replayFingerprint,
  };
}

function digest(label: string): string {
  return createHash('sha256').update(label).digest('hex');
}

function grantCommand(
  userId: string,
  authority: InstanceAdvisoryAuthority,
): InstanceAdvisoryAuthorityCommand {
  return parseAuthority({
    schemaVersion: INSTANCE_ADVISORY_AUTHORITY_COMMAND_SCHEMA_VERSION,
    operation: 'grant',
    targetUserId: userId,
    authority,
    issuanceClassification: 'deployment_local_command',
    correlationId: randomUUID(),
  });
}

function revokeGrant(
  userId: string,
  expectedGrantId: string,
  expectedAuthority: InstanceAdvisoryAuthority,
): InstanceAdvisoryAuthorityCommand {
  return parseAuthority({
    schemaVersion: INSTANCE_ADVISORY_AUTHORITY_COMMAND_SCHEMA_VERSION,
    operation: 'revoke',
    targetUserId: userId,
    expectedGrantId,
    expectedAuthority,
    correlationId: randomUUID(),
  });
}

function disableUser(userId: string): InstanceAdvisoryAuthorityCommand {
  return parseAuthority({
    schemaVersion: INSTANCE_ADVISORY_AUTHORITY_COMMAND_SCHEMA_VERSION,
    operation: 'disable_user',
    targetUserId: userId,
    correlationId: randomUUID(),
  });
}

function parseAuthority(input: unknown): InstanceAdvisoryAuthorityCommand {
  const parsed = parseInstanceAdvisoryAuthorityCommand(input);
  if (!parsed.ok) {
    throw new Error('authority command was rejected');
  }
  return parsed.command;
}

async function insertSystemAudit(
  tx: PrismaClient | Parameters<Parameters<PrismaClient['$transaction']>[0]>[0],
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
      jsonb_build_object('schemaVersion', 1, 'metadata', ${metadata}::jsonb),
      1,
      'security'::"audit_retention_category"
    )
  `;
}

async function waitForUngrantedLock(client: PrismaClient): Promise<void> {
  const started = Date.now();
  while (Date.now() - started < 8_000) {
    const rows = await client.$queryRaw<Array<{ waiting: number }>>`
      SELECT COUNT(*)::int AS waiting
      FROM pg_locks
      WHERE NOT granted
    `;
    if (Number(rows[0]?.waiting ?? 0) > 0) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error('submission did not wait for the user lock');
}
