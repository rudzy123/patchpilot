/**
 * Disposable PostgreSQL proof for uncomposed local advisory approval.
 * Synthetic identities only. No provider, evaluator, or Finding writes.
 */

import { randomUUID } from 'node:crypto';

import { PrismaClient } from '@prisma/client';
import {
  INSTANCE_ADVISORY_AUTHORITY_COMMAND_SCHEMA_VERSION,
  parseInstanceAdvisoryAuthorityCommand,
  type InstanceAdvisoryAuthority,
  type InstanceAdvisoryAuthorityCommand,
} from '@patchpilot/domain/instance-advisory-authority';
import {
  MAINTAINER_REVIEWED_ACCEPTED_SPDX,
  MAINTAINER_REVIEWED_ADVISORY_SCHEMA_VERSION,
  MAINTAINER_REVIEWED_SOURCE_LICENSE_POLICY_ID,
  MAINTAINER_REVIEWED_SOURCE_LICENSE_POLICY_VERSION,
} from '@patchpilot/vulnerability-intelligence';
import { MAINTAINER_REVIEWED_ADVISORY_APPROVAL_AUDIT_ACTION } from '@patchpilot/vulnerability-intelligence/maintainer-reviewed-advisory-approval-application';
import {
  parseMaintainerReviewedAdvisorySubmissionCommand,
  prepareMaintainerReviewedAdvisorySubmission,
  toMaintainerReviewedAdvisorySubmissionPersistenceCommand,
  type MaintainerReviewedAdvisorySubmissionPersistenceCommand,
} from '@patchpilot/vulnerability-intelligence/maintainer-reviewed-advisory-submission';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
  createMaintainerReviewedAdvisoryApprovalApplicationPersistence,
  type MaintainerReviewedAdvisoryApprovalPersistenceFault,
} from './maintainer-reviewed-advisory-approval-application-persistence.js';
import { createMaintainerReviewedAdvisorySubmissionPersistence } from './maintainer-reviewed-advisory-submission-persistence.js';
import { createInstanceAdvisoryAuthorityPersistence } from './instance-advisory-authority-persistence.js';
import {
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
} from './integration-database.js';

const CREATED_AT = new Date('2026-06-01T00:00:00.000Z');

type ApprovalPersistence = ReturnType<
  typeof createMaintainerReviewedAdvisoryApprovalApplicationPersistence
>;

describe('maintainer-reviewed advisory approval PostgreSQL persistence', () => {
  let databaseUrl = '';
  let databaseName = '';
  let admin: Awaited<ReturnType<typeof createEphemeralDatabase>>['admin'];
  let prisma: PrismaClient;
  let approval: ApprovalPersistence;
  let submission: ReturnType<typeof createMaintainerReviewedAdvisorySubmissionPersistence>;
  let authority: ReturnType<typeof createInstanceAdvisoryAuthorityPersistence>;
  let sequence = 0;

  beforeAll(async () => {
    const ephemeral = await createEphemeralDatabase('it', { scope: 'mraa' });
    databaseUrl = ephemeral.databaseUrl;
    databaseName = ephemeral.databaseName;
    admin = ephemeral.admin;
    await deployMigrations(databaseUrl);
    prisma = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
    approval = createMaintainerReviewedAdvisoryApprovalApplicationPersistence(prisma);
    submission = createMaintainerReviewedAdvisorySubmissionPersistence(prisma);
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

  it('approves one local revision and replays without a second write', async () => {
    const author = await authorizedUser('author', 'advisory_submit_local');
    const reviewer = await authorizedUser('reviewer', 'advisory_approve_for_product_evaluation');
    const org = await prisma.organization.create({
      data: { slug: `apr-${randomUUID().slice(0, 8)}`, name: 'Approval org' },
    });
    await prisma.membership.create({
      data: { organizationId: org.id, userId: reviewer.id, role: 'owner', joinedAt: CREATED_AT },
    });
    const revisionId = await submit(author.id);
    const before = await counts();
    const first = await approval.approve(approvalCommand(reviewer.id, revisionId));
    expect(first).toEqual({ outcome: 'approved', revisionId });
    const after = await counts();
    expect(after.approvals).toBe(before.approvals + 1);
    expect(after.capabilities).toBe(before.capabilities + 1);
    expect(after.observations).toBe(before.observations + 1);
    expect(after.approvalAudits).toBe(before.approvalAudits + 1);
    expect(after.productMatch).toBe(before.productMatch);
    expect(after.findings).toBe(before.findings);
    expect(after.findingObservations).toBe(before.findingObservations);
    expect(after.organizations).toBe(before.organizations);
    expect(after.memberships).toBe(before.memberships);
    const storedRevision = await prisma.advisoryRevision.findUniqueOrThrow({
      where: { id: revisionId },
    });
    expect(storedRevision.trustClassification).toBe('unreviewed');
    expect(storedRevision.authorIdentity).toBe(author.id);
    const storedApproval = await prisma.maintainerReviewedAdvisoryApproval.findUniqueOrThrow({
      where: { advisoryRevisionId: revisionId },
    });
    expect(storedApproval.reviewerIdentity).toBe(reviewer.id);
    expect(storedApproval.authorIdentity).toBe(author.id);
    expect(storedApproval.approvalPurpose).toBe(
      'approve_maintainer_reviewed_advisory_for_product_evaluation',
    );
    const capability = await prisma.reviewerCapabilityIssuance.findFirstOrThrow({
      where: { advisoryRevisionId: revisionId },
    });
    expect(capability.reviewerIdentity).toBe(reviewer.id);
    expect(capability.advisoryRevisionId).toBe(revisionId);
    expect(capability.contentFingerprint).toBe(storedRevision.contentFingerprint);
    expect(capability.affectedRangeFingerprint).toBe(storedRevision.session14RangeFingerprint);
    expect(capability.advisoryFamilyIdentity).toBe(storedRevision.familyDigest);
    expect(capability.expiresAt.getTime() - capability.issuedAt.getTime()).toBe(900_000);
    expect(capability.issuedAt.getTime()).toBeLessThan(capability.expiresAt.getTime());
    const observation = await prisma.reviewerCapabilityLifecycleObservation.findUniqueOrThrow({
      where: { capabilityIssuanceId: capability.id },
    });
    expect(observation.observationClassification).toBe('consumed');
    expect(observation.approvalId).toBe(storedApproval.id);
    const audit = await prisma.auditEvent.findFirstOrThrow({
      where: {
        action: MAINTAINER_REVIEWED_ADVISORY_APPROVAL_AUDIT_ACTION,
        subjectId: revisionId,
      },
    });
    expect(audit.actorType).toBe('user');
    expect(audit.actorUserId).toBe(reviewer.id);
    expect(audit.organizationId).toBeNull();
    expect(audit.actorMembershipId).toBeNull();
    const payload = JSON.stringify(audit.payload);
    expect(payload).not.toContain('pp-reviewer-capability-secret');
    expect(payload).not.toContain('left-pad');
    expect(payload).toContain('sha256');
    const createdAt = storedApproval.createdAt.toISOString();
    const issuedAt = capability.issuedAt.toISOString();
    const replay = await approval.approve(approvalCommand(reviewer.id, revisionId, randomUUID()));
    expect(replay).toEqual({ outcome: 'already_applied', revisionId });
    expect(await counts()).toEqual(after);
    const replayed = await prisma.maintainerReviewedAdvisoryApproval.findUniqueOrThrow({
      where: { advisoryRevisionId: revisionId },
    });
    const replayedCapability = await prisma.reviewerCapabilityIssuance.findFirstOrThrow({
      where: { advisoryRevisionId: revisionId },
    });
    expect(replayed.createdAt.toISOString()).toBe(createdAt);
    expect(replayedCapability.issuedAt.toISOString()).toBe(issuedAt);
  });

  it('rejects self-approval, the submission grant, and a missing revision without writes', async () => {
    const author = await authorizedUser('self', 'advisory_submit_local');
    const revisionId = await submit(author.id);
    const submitGrant = await prisma.instanceAdvisoryAuthorityGrant.findFirstOrThrow({
      where: { userId: author.id, revokedAt: null },
    });
    expect(
      (await authority.execute(revokeGrant(author.id, submitGrant.id, 'advisory_submit_local')))
        .outcome,
    ).toBe('revoked');
    expect(
      (await authority.execute(grantCommand(author.id, 'advisory_approve_for_product_evaluation')))
        .outcome,
    ).toBe('granted');
    const reviewerOnlySubmit = await authorizedUser('submit-only', 'advisory_submit_local');
    const member = await createUser('member');
    const org = await prisma.organization.create({
      data: { slug: `mem-${randomUUID().slice(0, 8)}`, name: 'Member org' },
    });
    await prisma.membership.create({
      data: { organizationId: org.id, userId: member.id, role: 'owner', joinedAt: CREATED_AT },
    });
    const reviewer = await authorizedUser(
      'missing-target',
      'advisory_approve_for_product_evaluation',
    );
    await prisma.user.update({
      where: { id: author.id },
      data: {
        email: `renamed-${randomUUID().slice(0, 8)}@synthetic.patchpilot.test`,
        displayName: 'Renamed author',
      },
    });
    const secondOrg = await prisma.organization.create({
      data: { slug: `self-${randomUUID().slice(0, 8)}`, name: 'Second author org' },
    });
    await prisma.membership.create({
      data: {
        organizationId: secondOrg.id,
        userId: author.id,
        role: 'admin',
        joinedAt: CREATED_AT,
      },
    });
    const before = await counts();
    expect(await approval.approve(approvalCommand(author.id, revisionId))).toEqual({
      outcome: 'separation_of_duties_required',
    });
    expect(await approval.approve(approvalCommand(reviewerOnlySubmit.id, revisionId))).toEqual({
      outcome: 'authority_rejected',
    });
    expect(await approval.approve(approvalCommand(member.id, revisionId))).toEqual({
      outcome: 'authority_rejected',
    });
    expect(await approval.approve(approvalCommand(reviewer.id, randomUUID()))).toEqual({
      outcome: 'not_found',
    });
    expect(await approval.approve(approvalCommand('not-a-user', revisionId))).toEqual({
      outcome: 'authority_required',
    });
    expect(await counts()).toEqual(before);
  });

  it('rejects a disabled reviewer and still approves a revision whose author is disabled', async () => {
    const author = await authorizedUser('disabled-author', 'advisory_submit_local');
    const otherAuthor = await authorizedUser('other-author', 'advisory_submit_local');
    const reviewer = await authorizedUser(
      'live-reviewer',
      'advisory_approve_for_product_evaluation',
    );
    const revisionId = await submit(author.id);
    const other = await submit(otherAuthor.id);
    expect((await authority.execute(disableUser(author.id))).outcome).toBe('user_disabled');
    const approved = await approval.approve(approvalCommand(reviewer.id, revisionId));
    expect(approved).toEqual({ outcome: 'approved', revisionId });
    const disabledReviewer = await authorizedUser(
      'disabled-reviewer',
      'advisory_approve_for_product_evaluation',
    );
    expect((await authority.execute(disableUser(disabledReviewer.id))).outcome).toBe(
      'user_disabled',
    );
    const before = await counts();
    expect(await approval.approve(approvalCommand(disabledReviewer.id, other))).toEqual({
      outcome: 'authority_rejected',
    });
    expect(await counts()).toEqual(before);
  });

  it('rejects synthetic origin and a malformed range envelope without writes', async () => {
    const author = await authorizedUser('origin-author', 'advisory_submit_local');
    const reviewer = await authorizedUser(
      'origin-reviewer',
      'advisory_approve_for_product_evaluation',
    );
    const synthetic = await submit(author.id);
    const malformed = await submit(author.id);
    await prisma.$executeRaw`ALTER TABLE "advisory_revision" DISABLE TRIGGER "advisory_revision_append_only"`;
    await prisma.$executeRaw`ALTER TABLE "advisory_revision_range_event" DISABLE TRIGGER "advisory_revision_range_event_append_only"`;
    try {
      await prisma.$executeRaw`
        UPDATE "advisory_revision"
        SET "origin" = 'synthetic_fixture'::"advisory_evidence_origin",
            "source" = 'synthetic_fixture'::"advisory_evidence_source",
            "author_identity" = NULL,
            "trust_classification" = 'not_applicable_synthetic'::"advisory_evidence_trust",
            "revision_disposition" = 'synthetic'::"advisory_revision_disposition",
            "spdx_license_id" = NULL,
            "retrieval_classification" = 'synthetic_not_retrieved'::"advisory_retrieval_classification",
            "retrieval_evidence_id" = 'synthetic_retrieval_not_applicable',
            "provider_generation" = 'synthetic_not_a_provider_generation',
            "revision_schema_version" = 'osv_advisory_revision_identity_v1',
            "parser_id" = 'osv_advisory_parser_protocol_v1',
            "parser_resource_policy" = 'osv_advisory_parser_resource_policy_v1',
            "advisory_schema_version" = 'v1.9.0',
            "advisory_schema_commit" = 'f3f826310aeca8e324baabd195632f2229952abe',
            "source_license_registry_version" = 'osv_source_license_registry_v1',
            "source_license_policy_version" = 'osv_source_license_registry_v1',
            "retrieval_policy_id" = 'osv_generation_bound_retrieval_policy_v1'
        WHERE "id" = ${synthetic}::uuid
      `;
      await prisma.$executeRaw`
        DELETE FROM "advisory_revision_range_event"
        WHERE "advisory_revision_id" = ${malformed}::uuid
      `;
    } finally {
      await prisma.$executeRaw`ALTER TABLE "advisory_revision_range_event" ENABLE TRIGGER "advisory_revision_range_event_append_only"`;
      await prisma.$executeRaw`ALTER TABLE "advisory_revision" ENABLE TRIGGER "advisory_revision_append_only"`;
    }
    const before = await counts();
    expect(await approval.approve(approvalCommand(reviewer.id, synthetic))).toEqual({
      outcome: 'unsupported_origin',
    });
    expect(await approval.approve(approvalCommand(reviewer.id, malformed))).toEqual({
      outcome: 'malformed_persisted_state',
    });
    expect(await counts()).toEqual(before);
  });

  it('treats a different reviewer as an immutable conflict', async () => {
    const author = await authorizedUser('conflict-author', 'advisory_submit_local');
    const first = await authorizedUser('conflict-first', 'advisory_approve_for_product_evaluation');
    const second = await authorizedUser(
      'conflict-second',
      'advisory_approve_for_product_evaluation',
    );
    const revisionId = await submit(author.id);
    expect(await approval.approve(approvalCommand(first.id, revisionId))).toEqual({
      outcome: 'approved',
      revisionId,
    });
    const before = await counts();
    expect(await approval.approve(approvalCommand(second.id, revisionId))).toEqual({
      outcome: 'immutable_conflict',
    });
    expect(await approval.approve(approvalCommand(author.id, revisionId))).toEqual({
      outcome: 'authority_rejected',
    });
    expect(await counts()).toEqual(before);
  });

  it('rejects replay when the consumed capability package no longer matches the approval', async () => {
    const author = await authorizedUser('lineage-author', 'advisory_submit_local');
    const reviewer = await authorizedUser(
      'lineage-reviewer',
      'advisory_approve_for_product_evaluation',
    );
    const revisionId = await submit(author.id);
    expect(await approval.approve(approvalCommand(reviewer.id, revisionId))).toEqual({
      outcome: 'approved',
      revisionId,
    });
    await prisma.$executeRaw`ALTER TABLE "reviewer_capability_issuance" DISABLE TRIGGER "reviewer_capability_issuance_append_only"`;
    try {
      await prisma.$executeRaw`
        UPDATE "reviewer_capability_issuance"
        SET "npm_package_identity" = ${'npm\u001f\u001fright-pad'}
        WHERE "advisory_revision_id" = ${revisionId}::uuid
      `;
    } finally {
      await prisma.$executeRaw`ALTER TABLE "reviewer_capability_issuance" ENABLE TRIGGER "reviewer_capability_issuance_append_only"`;
    }
    const before = await counts();
    expect(await approval.approve(approvalCommand(reviewer.id, revisionId, randomUUID()))).toEqual({
      outcome: 'malformed_persisted_state',
    });
    expect(await counts()).toEqual(before);
    expect(
      await prisma.maintainerReviewedAdvisoryApproval.count({
        where: { advisoryRevisionId: revisionId },
      }),
    ).toBe(1);
  });

  it('rolls back capability, approval, and audit when a later step fails', async () => {
    const author = await authorizedUser('rollback-author', 'advisory_submit_local');
    const reviewer = await authorizedUser(
      'rollback-reviewer',
      'advisory_approve_for_product_evaluation',
    );
    for (const fault of [
      'before_capability_issuance',
      'before_capability_validation',
      'before_approval_insert',
      'before_capability_consumption',
      'before_audit_insert',
      'skip_audit_insert',
      'fail_stored_state_validation',
      'force_capability_expired',
    ] as const satisfies readonly MaintainerReviewedAdvisoryApprovalPersistenceFault[]) {
      const revisionId = await submit(author.id);
      const before = await counts();
      const result = await approval.approve(approvalCommand(reviewer.id, revisionId), { fault });
      expect(result.outcome === 'approved' || result.outcome === 'already_applied').toBe(false);
      expect(await counts()).toEqual(before);
      expect(JSON.stringify(result)).not.toContain('reviewer_capability');
      expect(JSON.stringify(result)).not.toContain('SQL');
    }
  });

  it('classifies a lost acknowledgement as replay on the next call', async () => {
    const author = await authorizedUser('ack-author', 'advisory_submit_local');
    const reviewer = await authorizedUser(
      'ack-reviewer',
      'advisory_approve_for_product_evaluation',
    );
    const revisionId = await submit(author.id);
    const lost = await approval.approve(approvalCommand(reviewer.id, revisionId), {
      fault: 'lose_acknowledgment',
    });
    expect(lost).toEqual({ outcome: 'transaction_aborted' });
    const stored = await counts();
    const replay = await approval.approve(approvalCommand(reviewer.id, revisionId, randomUUID()));
    expect(replay).toEqual({ outcome: 'already_applied', revisionId });
    expect(await counts()).toEqual(stored);
  });

  it('converges concurrent identical and different-reviewer approvals', async () => {
    const author = await authorizedUser('race-author', 'advisory_submit_local');
    const reviewer = await authorizedUser(
      'race-reviewer',
      'advisory_approve_for_product_evaluation',
    );
    const other = await authorizedUser('race-other', 'advisory_approve_for_product_evaluation');
    const identicalRevision = await submit(author.id);
    const conflictRevision = await submit(author.id);
    const left = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
    const right = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
    try {
      const identical = await Promise.all([
        createMaintainerReviewedAdvisoryApprovalApplicationPersistence(left).approve(
          approvalCommand(reviewer.id, identicalRevision),
        ),
        createMaintainerReviewedAdvisoryApprovalApplicationPersistence(right).approve(
          approvalCommand(reviewer.id, identicalRevision),
        ),
      ]);
      expect(identical.filter((result) => result.outcome === 'approved')).toHaveLength(1);
      expect(identical.filter((result) => result.outcome === 'already_applied')).toHaveLength(1);
      expect(
        await prisma.maintainerReviewedAdvisoryApproval.count({
          where: { advisoryRevisionId: identicalRevision },
        }),
      ).toBe(1);
      expect(
        await prisma.reviewerCapabilityIssuance.count({
          where: { advisoryRevisionId: identicalRevision },
        }),
      ).toBe(1);
      const differed = await Promise.all([
        createMaintainerReviewedAdvisoryApprovalApplicationPersistence(left).approve(
          approvalCommand(reviewer.id, conflictRevision),
        ),
        createMaintainerReviewedAdvisoryApprovalApplicationPersistence(right).approve(
          approvalCommand(other.id, conflictRevision),
        ),
      ]);
      expect(differed.filter((result) => result.outcome === 'approved')).toHaveLength(1);
      expect(differed.filter((result) => result.outcome === 'immutable_conflict')).toHaveLength(1);
      expect(
        await prisma.reviewerCapabilityIssuance.count({
          where: { advisoryRevisionId: conflictRevision },
        }),
      ).toBe(1);
      expect(
        await prisma.auditEvent.count({
          where: {
            action: MAINTAINER_REVIEWED_ADVISORY_APPROVAL_AUDIT_ACTION,
            subjectId: conflictRevision,
          },
        }),
      ).toBe(1);
    } finally {
      await left.$disconnect();
      await right.$disconnect();
    }
  });

  it('honors a reviewer disablement or grant revocation that wins the user lock', async () => {
    const author = await authorizedUser('lock-author', 'advisory_submit_local');
    const disabled = await authorizedUser(
      'lock-disabled',
      'advisory_approve_for_product_evaluation',
    );
    const revisionId = await submit(author.id);
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
      const [, result] = await Promise.all([
        disabling,
        approval.approve(approvalCommand(disabled.id, revisionId)),
      ]);
      expect(result).toEqual({ outcome: 'authority_rejected' });
      expect(await counts()).toEqual(before);
    } finally {
      await holder.$disconnect();
    }

    const revoked = await authorizedUser('lock-revoked', 'advisory_approve_for_product_evaluation');
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
          const correlationId = randomUUID();
          await tx.$executeRaw`
            UPDATE "instance_advisory_authority_grant"
            SET "revoked_at" = CURRENT_TIMESTAMP
            WHERE "id" = ${grant.id}::uuid
          `;
          await insertSystemAudit(tx, {
            action: 'intelligence.instance_advisory_authority_revoked',
            subjectType: 'instance_advisory_authority_grant',
            subjectId: grant.id,
            correlationId,
            metadata: {
              authority: 'advisory_approve_for_product_evaluation',
              correlationId,
              issuanceClassification: 'deployment_local_command',
              targetUserId: revoked.id,
            },
          });
        },
        { timeout: 15_000 },
      );
      await grantLockedPromise;
      const [, result] = await Promise.all([
        revoking,
        approval.approve(approvalCommand(revoked.id, revisionId)),
      ]);
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
      const reviewer = await authorizedUser('offline', 'advisory_approve_for_product_evaluation');
      const result = await createMaintainerReviewedAdvisoryApprovalApplicationPersistence(
        dead,
      ).approve(approvalCommand(reviewer.id, randomUUID()));
      expect(result).toEqual({ outcome: 'database_unavailable' });
      expect(JSON.stringify(result)).not.toContain('postgresql');
    } finally {
      await dead.$disconnect();
    }
  });

  async function authorizedUser(label: string, grantAuthority: InstanceAdvisoryAuthority) {
    const user = await createUser(label);
    const granted = await authority.execute(grantCommand(user.id, grantAuthority));
    if (granted.outcome !== 'granted' && granted.outcome !== 'already_applied') {
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

  async function submit(userId: string): Promise<string> {
    const submitted = await submission.submit(submissionCommand(userId));
    if (submitted.outcome !== 'submitted') {
      throw new Error(`submission failed: ${submitted.outcome}`);
    }
    return submitted.revisionId;
  }

  function submissionCommand(
    userId: string,
  ): MaintainerReviewedAdvisorySubmissionPersistenceCommand {
    sequence += 1;
    const parsed = parseMaintainerReviewedAdvisorySubmissionCommand({
      schemaVersion: MAINTAINER_REVIEWED_ADVISORY_SCHEMA_VERSION,
      advisoryFamilyId: `FAMILY${String(sequence).padStart(4, '0')}${randomUUID().replaceAll('-', '').slice(0, 8).toUpperCase()}`,
      revisionNumber: 1,
      vulnerabilityId: randomUUID(),
      aliases: [`CVE-2026-${String(10000 + sequence)}`],
      packageEcosystem: 'npm',
      packageName: 'left-pad',
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
      submissionCorrelationId: randomUUID(),
    });
    if (!parsed.ok) {
      throw new Error(`submission command rejected: ${parsed.outcome}`);
    }
    const prepared = prepareMaintainerReviewedAdvisorySubmission(userId, parsed.command);
    if (!prepared.ok) {
      throw new Error(`submission preparation rejected: ${prepared.outcome}`);
    }
    return toMaintainerReviewedAdvisorySubmissionPersistenceCommand(prepared.prepared);
  }

  function approvalCommand(reviewerId: string, revisionId: string, correlationId = randomUUID()) {
    return {
      commandName: 'approve_maintainer_reviewed_advisory_v1' as const,
      trustedReviewerUserId: reviewerId,
      advisoryRevisionId: revisionId,
      correlationId,
    };
  }

  async function counts() {
    const [
      approvals,
      capabilities,
      observations,
      approvalAudits,
      productMatch,
      findings,
      findingObservations,
      organizations,
      memberships,
    ] = await Promise.all([
      prisma.maintainerReviewedAdvisoryApproval.count(),
      prisma.reviewerCapabilityIssuance.count(),
      prisma.reviewerCapabilityLifecycleObservation.count(),
      prisma.auditEvent.count({
        where: { action: MAINTAINER_REVIEWED_ADVISORY_APPROVAL_AUDIT_ACTION },
      }),
      prisma.productMatchEvaluationEvidence.count(),
      prisma.finding.count(),
      prisma.findingObservation.count(),
      prisma.organization.count(),
      prisma.membership.count(),
    ]);
    return {
      approvals,
      capabilities,
      observations,
      approvalAudits,
      productMatch,
      findings,
      findingObservations,
      organizations,
      memberships,
    };
  }
});

function grantCommand(
  userId: string,
  grantAuthority: InstanceAdvisoryAuthority,
): InstanceAdvisoryAuthorityCommand {
  return parseAuthority({
    schemaVersion: INSTANCE_ADVISORY_AUTHORITY_COMMAND_SCHEMA_VERSION,
    operation: 'grant',
    targetUserId: userId,
    authority: grantAuthority,
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
      jsonb_build_object(
        'schemaVersion', 1,
        'metadata', ${metadata}::jsonb
      ),
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
  throw new Error('approval did not wait for the user lock');
}
