/**
 * Disposable PostgreSQL proof for durable reviewer-capability issuance
 * and atomic approval consumption. Synthetic identities only.
 */

import { createHash, randomUUID } from 'node:crypto';
import { PrismaClient } from '@prisma/client';
import {
  DURABLE_REVIEWER_CAPABILITY_INSPECTION_SCHEMA_VERSION,
  DURABLE_REVIEWER_CAPABILITY_ZERO_EFFECTS,
  EXACT_MAPPING_METHOD,
  MAINTAINER_REVIEWED_APPROVAL_COMMAND_SCHEMA_VERSION,
  MAINTAINER_REVIEWED_APPROVAL_PINS,
  MAINTAINER_REVIEWED_BINDING_SCHEMA_VERSION,
  MAINTAINER_REVIEWED_FAMILY_SCHEMA_VERSION,
  MAINTAINER_REVIEWED_REVISION_SCHEMA_VERSION,
  REVIEWER_CAPABILITY_CANCELLATION_PURPOSE,
  REVIEWER_CAPABILITY_ISSUANCE_REQUEST_SCHEMA_VERSION,
  REVIEWER_CAPABILITY_LICENSE_CLASSIFICATION,
  REVIEWER_CAPABILITY_LICENSE_POLICY_ID,
  REVIEWER_CAPABILITY_LICENSE_POLICY_VERSION,
  REVIEWER_CAPABILITY_POLICY_ID,
  REVIEWER_CAPABILITY_POLICY_VERSION,
  REVIEWER_CAPABILITY_REVOCATION_PURPOSE,
  REVIEWER_CAPABILITY_SOURCE_CLASSIFICATION,
  SELECTED_FIRST_ECOSYSTEM,
  VULNERABILITY_MAPPING_POLICY_ID,
  classifyNpmPackageIdentityFromParts,
  maintainerReviewedApprovalReplayFingerprint,
  parseReviewerCapabilityIssuanceRequest,
  prepareDurableApprovalConsumption,
  prepareDurableReviewerCapabilityCancellation,
  prepareDurableReviewerCapabilityIssuance,
  prepareDurableReviewerCapabilityRevocation,
} from '@patchpilot/vulnerability-intelligence';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
  applyThroughProductMatchEvaluation,
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
  EXPECTED_APPLIED_MIGRATIONS,
  PRODUCT_MATCH_EVIDENCE_BATCH_3_EVALUATION,
  REVIEWER_CAPABILITY_ISSUANCE,
} from './integration-database.js';
import { createDurableReviewerApprovalCapabilityPersistence } from './reviewer-capability-persistence.js';
import {
  sealDurableIssuerAuthority,
  sealDurableLifecycleAuthority,
} from './reviewer-capability-test-seam.js';
import { createMaintainerReviewedAdvisoryApprovalPersistence } from './maintainer-reviewed-advisory-approval-persistence.js';

const PACKAGE_NAME = 'synth-cap-pkg';

type ParentRecord = {
  readonly familyId: string;
  readonly revisionId: string;
  readonly familyDigest: string;
  readonly contentFingerprint: string;
  readonly rangeFingerprint: string;
  readonly packageIdentityKey: string;
  readonly vulnerabilityId: string;
  readonly authorIdentity: string;
};

function digest(label: string): string {
  return createHash('sha256').update(label).digest('hex');
}

function packageIdentityKey(name = PACKAGE_NAME): string {
  const identity = classifyNpmPackageIdentityFromParts({
    ecosystem: SELECTED_FIRST_ECOSYSTEM,
    observedNamespace: null,
    observedName: name,
    observedIdentity: name,
  });
  if (identity.classification !== 'valid') {
    throw new Error('synthetic package identity was rejected');
  }
  return identity.identityKey;
}

describe('durable reviewer capability PostgreSQL persistence', () => {
  let databaseUrl = '';
  let databaseName = '';
  let admin: Awaited<ReturnType<typeof createEphemeralDatabase>>['admin'];
  let prisma: PrismaClient;
  let port: ReturnType<typeof createDurableReviewerApprovalCapabilityPersistence>;
  let findingCount = 0;
  let matchCount = 0;

  beforeAll(async () => {
    const ephemeral = await createEphemeralDatabase('it');
    databaseUrl = ephemeral.databaseUrl;
    databaseName = ephemeral.databaseName;
    admin = ephemeral.admin;
    await deployMigrations(databaseUrl);
    prisma = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
    port = createDurableReviewerApprovalCapabilityPersistence(prisma);
    findingCount = await prisma.finding.count();
    matchCount = await prisma.productMatchEvaluationEvidence.count();
    expect(await prisma.reviewerCapabilityIssuance.count()).toBe(0);
    expect(await prisma.reviewerCapabilityLifecycleObservation.count()).toBe(0);
    expect(await prisma.maintainerReviewedAdvisoryApproval.count()).toBe(0);
  });

  afterAll(async () => {
    if (prisma !== undefined) {
      expect(await prisma.finding.count()).toBe(findingCount);
      expect(await prisma.productMatchEvaluationEvidence.count()).toBe(matchCount);
      expect(await prisma.findingObservation.count()).toBe(0);
      await prisma.$disconnect();
    }
    if (admin !== undefined) {
      await dropEphemeralDatabase(admin, databaseName);
    }
  });

  async function insertParent(withdrawn = false): Promise<ParentRecord> {
    const advisoryId = `SYNTHCAP${digest(randomUUID()).slice(0, 12).toUpperCase()}`;
    const familyDigest = digest(`family:${advisoryId}`);
    const contentFingerprint = digest(`content:${advisoryId}`);
    const rangeFingerprint = digest(`range:${advisoryId}`);
    const authorIdentity = 'author.one';
    const vulnerability = await prisma.vulnerability.create({
      data: { osvId: `SYNTHETIC-${advisoryId}` },
      select: { id: true },
    });
    const family = await prisma.advisoryFamily.create({
      data: {
        familySchemaVersion: MAINTAINER_REVIEWED_FAMILY_SCHEMA_VERSION,
        source: 'maintainer_reviewed_advisory',
        advisoryId,
        familyDigest,
        sourceRegistryVersion: MAINTAINER_REVIEWED_APPROVAL_PINS.licensePolicyId,
      },
      select: { id: true },
    });
    const revision = await prisma.advisoryRevision.create({
      data: {
        revisionSchemaVersion: MAINTAINER_REVIEWED_REVISION_SCHEMA_VERSION,
        advisoryFamilyId: family.id,
        source: 'maintainer_reviewed_advisory',
        advisoryId,
        familyDigest,
        revisionDigest: digest(`revision:${advisoryId}`),
        providerGeneration: MAINTAINER_REVIEWED_APPROVAL_PINS.providerGeneration,
        contentFingerprint,
        session14RangeFingerprint: rangeFingerprint,
        productRangeFingerprint: rangeFingerprint,
        parserId: MAINTAINER_REVIEWED_APPROVAL_PINS.documentSchema,
        parserResourcePolicy: MAINTAINER_REVIEWED_APPROVAL_PINS.canonicalization,
        advisorySchemaVersion: MAINTAINER_REVIEWED_APPROVAL_PINS.documentSchema,
        advisorySchemaCommit: MAINTAINER_REVIEWED_APPROVAL_PINS.schemaCommit,
        sourceLicenseRegistryVersion: MAINTAINER_REVIEWED_APPROVAL_PINS.licensePolicyId,
        sourceLicensePolicyVersion: '1',
        spdxLicenseId: 'CC-BY-4.0',
        origin: 'maintainer_reviewed_advisory',
        trustClassification: 'unreviewed',
        revisionDisposition: withdrawn ? 'withdrawn' : 'recorded',
        withdrawalClassification: withdrawn ? 'withdrawn' : 'not_withdrawn',
        quarantineClassification: 'not_quarantined',
        supersedesRevisionDigest: 'none',
        retrievalClassification: MAINTAINER_REVIEWED_APPROVAL_PINS.retrieval,
        retrievalEvidenceId: MAINTAINER_REVIEWED_APPROVAL_PINS.retrievalEvidence,
        retrievalPolicyId: MAINTAINER_REVIEWED_APPROVAL_PINS.retrievalPolicy,
        ecosystem: 'npm',
        packageName: PACKAGE_NAME,
        packageIdentityKey: packageIdentityKey(),
        evaluatorVersion: 'session_14_batch_2_in_memory',
        matchingPolicyId: 'osv_first_ecosystem_matching_architecture_v1',
        aliasCount: 0,
        cveAliasCount: 0,
        aliasSetDigest: digest(`aliases:${advisoryId}`),
        replayFingerprint: digest(`replay:${advisoryId}`),
        authorIdentity,
      },
      select: { id: true },
    });
    if (!withdrawn) {
      await prisma.advisoryVulnerabilityBinding.create({
        data: {
          bindingSchemaVersion: MAINTAINER_REVIEWED_BINDING_SCHEMA_VERSION,
          advisoryRevisionId: revision.id,
          vulnerabilityId: vulnerability.id,
          mappingPolicyId: VULNERABILITY_MAPPING_POLICY_ID,
          mappingMethod: EXACT_MAPPING_METHOD,
          mappingEvidenceFingerprint: digest(`mapping:${advisoryId}`),
          mappingReviewState: 'reviewed',
          mappingSourceClassification: 'explicit_reviewed_binding',
          conflictClassification: 'none',
          bindingClassification: 'provider_native_without_cve',
          replayFingerprint: digest(`binding:${advisoryId}`),
        },
      });
    }
    return {
      familyId: family.id,
      revisionId: revision.id,
      familyDigest,
      contentFingerprint,
      rangeFingerprint,
      packageIdentityKey: packageIdentityKey(),
      vulnerabilityId: vulnerability.id,
      authorIdentity,
    };
  }

  function approvalCommand(parent: ParentRecord, overrides: Record<string, unknown> = {}) {
    const fields = {
      commandSchemaVersion: MAINTAINER_REVIEWED_APPROVAL_COMMAND_SCHEMA_VERSION,
      advisoryRevisionId: parent.revisionId,
      expectedAdvisoryFamilyIdentity: parent.familyDigest,
      expectedSourceClassification: MAINTAINER_REVIEWED_APPROVAL_PINS.origin,
      expectedContentFingerprint: parent.contentFingerprint,
      expectedRangeFingerprint: parent.rangeFingerprint,
      expectedNpmPackageIdentity: parent.packageIdentityKey,
      expectedVulnerabilityId: parent.vulnerabilityId,
      authorIdentity: parent.authorIdentity,
      reviewerIdentity: 'reviewer.two',
      reviewerAuthorityClassification: MAINTAINER_REVIEWED_APPROVAL_PINS.reviewerClassification,
      approvalPolicyId: MAINTAINER_REVIEWED_APPROVAL_PINS.approvalPolicyId,
      approvalPolicyVersion: MAINTAINER_REVIEWED_APPROVAL_PINS.approvalPolicyVersion,
      approvalPurpose: MAINTAINER_REVIEWED_APPROVAL_PINS.approvalPurpose,
      sourceLicensePolicyId: MAINTAINER_REVIEWED_APPROVAL_PINS.licensePolicyId,
      sourceLicensePolicyVersion: MAINTAINER_REVIEWED_APPROVAL_PINS.licensePolicyVersion,
      approvedLicenseClassification: MAINTAINER_REVIEWED_APPROVAL_PINS.licenseClassification,
      correlationId: randomUUID(),
      ...overrides,
    };
    return {
      ...fields,
      approvalReplayFingerprint: maintainerReviewedApprovalReplayFingerprint({
        advisoryRevisionId: String(fields.advisoryRevisionId),
        familyDigest: String(fields.expectedAdvisoryFamilyIdentity),
        approvalPolicyId: String(fields.approvalPolicyId),
        approvalPolicyVersion: Number(fields.approvalPolicyVersion),
        approvalPurpose: String(fields.approvalPurpose),
        sourceClassification: String(fields.expectedSourceClassification),
        authorIdentity: String(fields.authorIdentity),
        reviewerIdentity: String(fields.reviewerIdentity),
        reviewerClassification: String(fields.reviewerAuthorityClassification),
        contentFingerprint: String(fields.expectedContentFingerprint),
        rangeFingerprint: String(fields.expectedRangeFingerprint),
        packageIdentityKey: String(fields.expectedNpmPackageIdentity),
        vulnerabilityId: String(fields.expectedVulnerabilityId),
        sourceLicensePolicyId: String(fields.sourceLicensePolicyId),
        sourceLicensePolicyVersion: Number(fields.sourceLicensePolicyVersion),
        approvedLicenseClassification: String(fields.approvedLicenseClassification),
        licenseDecisionCanonical: MAINTAINER_REVIEWED_APPROVAL_PINS.licenseCanonical,
      }),
    };
  }

  function issuanceRequest(parent: ParentRecord, correlationId: string, reviewer = 'reviewer.two') {
    const parsed = parseReviewerCapabilityIssuanceRequest({
      issuanceRequestSchemaVersion: REVIEWER_CAPABILITY_ISSUANCE_REQUEST_SCHEMA_VERSION,
      capabilityPolicyId: REVIEWER_CAPABILITY_POLICY_ID,
      capabilityPolicyVersion: REVIEWER_CAPABILITY_POLICY_VERSION,
      approvalPolicyId: MAINTAINER_REVIEWED_APPROVAL_PINS.approvalPolicyId,
      approvalPolicyVersion: MAINTAINER_REVIEWED_APPROVAL_PINS.approvalPolicyVersion,
      approvalPurpose: MAINTAINER_REVIEWED_APPROVAL_PINS.approvalPurpose,
      advisoryFamilyIdentity: parent.familyDigest,
      advisoryRevisionId: parent.revisionId,
      contentFingerprint: parent.contentFingerprint,
      affectedRangeFingerprint: parent.rangeFingerprint,
      npmPackageIdentity: parent.packageIdentityKey,
      vulnerabilityId: parent.vulnerabilityId,
      sourceLicensePolicyId: REVIEWER_CAPABILITY_LICENSE_POLICY_ID,
      sourceLicensePolicyVersion: REVIEWER_CAPABILITY_LICENSE_POLICY_VERSION,
      approvedLicenseClassification: REVIEWER_CAPABILITY_LICENSE_CLASSIFICATION,
      authorIdentity: parent.authorIdentity,
      reviewerIdentity: reviewer,
      correlationId,
      sourceClassification: REVIEWER_CAPABILITY_SOURCE_CLASSIFICATION,
    });
    if (!parsed.accepted) {
      throw new Error(parsed.code);
    }
    return parsed.request;
  }

  async function issue(
    parent: ParentRecord,
    correlationId = randomUUID(),
    authorizationId = randomUUID(),
  ) {
    const request = issuanceRequest(parent, correlationId);
    const issuer = sealDurableIssuerAuthority({ request, authorizationId });
    if (!issuer.accepted) {
      throw new Error(issuer.code);
    }
    const prepared = prepareDurableReviewerCapabilityIssuance({
      request,
      issuerAuthority: issuer.issuerAuthority,
    });
    if (!prepared.accepted) {
      throw new Error(prepared.code);
    }
    return { request, issuer, prepared, authorizationId, correlationId };
  }

  it('rejects caller authority and issues one exact capability with database time', async () => {
    const parent = await insertParent();
    const bare = createMaintainerReviewedAdvisoryApprovalPersistence(prisma);
    const denied = await bare.recordMaintainerReviewedAdvisoryApproval(approvalCommand(parent));
    expect(denied).toMatchObject({ kind: 'rejected', code: 'capability_authority_required' });
    expect(await prisma.maintainerReviewedAdvisoryApproval.count()).toBe(0);
    const first = await issue(parent);
    const issued = await port.issueDurableReviewerApprovalCapability(first.prepared.command);
    expect(issued.kind).toBe('issued');
    if (issued.kind !== 'issued') {
      return;
    }
    expect(issued.effects.inserts).toBe(1);
    expect(issued.effects.authorityRenewals).toBe(0);
    expect(issued.projection.reusableAuthority).toBe(false);
    const row = await prisma.reviewerCapabilityIssuance.findUniqueOrThrow({
      where: { id: issued.projection.capabilityPublicId },
    });
    expect(row.expiresAt.getTime() - row.issuedAt.getTime()).toBe(900_000);
    const boundary = await prisma.$queryRaw<Array<{ at_expiry: boolean; before_expiry: boolean }>>`
      SELECT patchpilot_reviewer_capability_is_expired("expires_at", "expires_at") AS at_expiry,
             patchpilot_reviewer_capability_is_expired(
               "expires_at",
               "expires_at" - interval '1 microsecond'
             ) AS before_expiry
      FROM "reviewer_capability_issuance"
      WHERE "id" = ${row.id}::uuid
    `;
    expect(boundary[0]?.at_expiry).toBe(true);
    expect(boundary[0]?.before_expiry).toBe(false);
    const replay = await port.issueDurableReviewerApprovalCapability(first.prepared.command);
    expect(replay.kind).toBe('already_issued');
    if (replay.kind !== 'already_issued') {
      return;
    }
    expect(replay.effects).toEqual(DURABLE_REVIEWER_CAPABILITY_ZERO_EFFECTS);
    expect(replay.projection.issuedAt).toBe(issued.projection.issuedAt);
    expect(replay.projection.expiresAt).toBe(issued.projection.expiresAt);
    const otherIssuer = await issue(parent, first.correlationId);
    const conflict = await port.issueDurableReviewerApprovalCapability(
      otherIssuer.prepared.command,
    );
    expect(conflict.kind).toBe('immutable_conflict');
    expect(
      await prisma.reviewerCapabilityIssuance.count({
        where: { advisoryRevisionId: parent.revisionId },
      }),
    ).toBe(1);
    const inspected = await port.inspectDurableReviewerApprovalCapability({
      inspectionSchemaVersion: DURABLE_REVIEWER_CAPABILITY_INSPECTION_SCHEMA_VERSION,
      capabilityIssuanceId: issued.projection.capabilityPublicId,
    });
    expect(inspected.kind).toBe('found');
    if (inspected.kind === 'found') {
      const text = JSON.stringify(inspected.projection);
      expect(text).not.toContain(parent.authorIdentity);
      expect(text).not.toContain('reviewer.two');
      expect(text).not.toContain(first.authorizationId);
      expect(inspected.projection.reusableAuthority).toBe(false);
    }
  });

  it('consumes one capability atomically with approval and replays without renewal', async () => {
    const parent = await insertParent();
    const correlationId = randomUUID();
    const issuedBundle = await issue(parent, correlationId);
    const issued = await port.issueDurableReviewerApprovalCapability(issuedBundle.prepared.command);
    expect(issued.kind).toBe('issued');
    if (issued.kind !== 'issued') {
      return;
    }
    const command = approvalCommand(parent, { correlationId });
    const consumption = prepareDurableApprovalConsumption({
      approvalCommand: command,
      capabilityIssuanceId: issued.projection.capabilityPublicId,
    });
    expect(consumption.accepted).toBe(true);
    if (!consumption.accepted) {
      return;
    }
    const beforeFindings = await prisma.finding.count();
    const recorded = await port.persistMaintainerReviewedAdvisoryApprovalWithCapability(
      consumption.command,
    );
    expect(recorded.kind).toBe('recorded');
    if (recorded.kind !== 'recorded') {
      return;
    }
    expect(recorded.effects.inserts).toBe(2);
    expect(recorded.effects.evaluatorCalls).toBe(0);
    expect(recorded.effects.matchEvidenceWrites).toBe(0);
    expect(recorded.effects.findingWrites).toBe(0);
    expect(recorded.capability.lifecycleClassification).toBe('consumed');
    expect(recorded.capability.reusableAuthority).toBe(false);
    expect(await prisma.finding.count()).toBe(beforeFindings);
    const createdAt = recorded.projection.createdAt;
    const replay = await port.persistMaintainerReviewedAdvisoryApprovalWithCapability(
      consumption.command,
    );
    expect(replay.kind).toBe('already_applied');
    if (replay.kind === 'already_applied') {
      expect(replay.projection.createdAt).toBe(createdAt);
      expect(replay.effects.inserts).toBe(0);
      expect(replay.effects.timestampChanges).toBe(0);
      expect(replay.effects.authorityRenewals).toBe(0);
    }
    expect(
      await prisma.reviewerCapabilityLifecycleObservation.count({
        where: { capabilityIssuanceId: issued.projection.capabilityPublicId },
      }),
    ).toBe(1);
    const other = await issue(parent, randomUUID(), randomUUID());
    const cross = prepareDurableApprovalConsumption({
      approvalCommand: approvalCommand(await insertParent(), {
        correlationId: other.correlationId,
      }),
      capabilityIssuanceId: issued.projection.capabilityPublicId,
    });
    expect(cross.accepted).toBe(true);
    if (!cross.accepted) {
      return;
    }
    const reused = await port.persistMaintainerReviewedAdvisoryApprovalWithCapability(
      cross.command,
    );
    expect(reused.kind === 'rejected' || reused.kind === 'immutable_conflict').toBe(true);
    expect(
      await prisma.maintainerReviewedAdvisoryApproval.count({
        where: { advisoryRevisionId: parent.revisionId },
      }),
    ).toBe(1);
  });

  it('rolls back approval when the parent or the consumption observation fails', async () => {
    const withdrawn = await insertParent(true);
    const withdrawnIssue = await issue(withdrawn);
    const withdrawnRow = await port.issueDurableReviewerApprovalCapability(
      withdrawnIssue.prepared.command,
    );
    expect(withdrawnRow.kind).toBe('issued');
    if (withdrawnRow.kind !== 'issued') {
      return;
    }
    const withdrawnCommand = prepareDurableApprovalConsumption({
      approvalCommand: approvalCommand(withdrawn, { correlationId: withdrawnIssue.correlationId }),
      capabilityIssuanceId: withdrawnRow.projection.capabilityPublicId,
    });
    if (!withdrawnCommand.accepted) {
      throw new Error(withdrawnCommand.code);
    }
    const failedParent = await port.persistMaintainerReviewedAdvisoryApprovalWithCapability(
      withdrawnCommand.command,
    );
    expect(failedParent).toMatchObject({ kind: 'rejected', code: 'withdrawn_revision' });
    expect(
      await prisma.reviewerCapabilityLifecycleObservation.count({
        where: { capabilityIssuanceId: withdrawnRow.projection.capabilityPublicId },
      }),
    ).toBe(0);
    const parent = await insertParent();
    const bundle = await issue(parent);
    const issued = await port.issueDurableReviewerApprovalCapability(bundle.prepared.command);
    expect(issued.kind).toBe('issued');
    if (issued.kind !== 'issued') {
      return;
    }
    await prisma.$executeRaw`
      CREATE OR REPLACE FUNCTION patchpilot_test_fail_capability_observation()
      RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN
        RAISE EXCEPTION 'test observation failure' USING ERRCODE = '23514';
      END;
      $$
    `;
    await prisma.$executeRaw`
      CREATE TRIGGER test_fail_capability_observation
      BEFORE INSERT ON "reviewer_capability_lifecycle_observation"
      FOR EACH ROW EXECUTE FUNCTION patchpilot_test_fail_capability_observation()
    `;
    try {
      const command = prepareDurableApprovalConsumption({
        approvalCommand: approvalCommand(parent, { correlationId: bundle.correlationId }),
        capabilityIssuanceId: issued.projection.capabilityPublicId,
      });
      if (!command.accepted) {
        throw new Error(command.code);
      }
      const failed = await port.persistMaintainerReviewedAdvisoryApprovalWithCapability(
        command.command,
      );
      expect(failed.kind).toBe('rejected');
      expect(
        await prisma.maintainerReviewedAdvisoryApproval.count({
          where: { advisoryRevisionId: parent.revisionId },
        }),
      ).toBe(0);
      expect(
        await prisma.reviewerCapabilityLifecycleObservation.count({
          where: { capabilityIssuanceId: issued.projection.capabilityPublicId },
        }),
      ).toBe(0);
    } finally {
      await prisma.$executeRaw`DROP TRIGGER IF EXISTS test_fail_capability_observation ON "reviewer_capability_lifecycle_observation"`;
      await prisma.$executeRaw`DROP FUNCTION IF EXISTS patchpilot_test_fail_capability_observation()`;
    }
    const command = prepareDurableApprovalConsumption({
      approvalCommand: approvalCommand(parent, { correlationId: bundle.correlationId }),
      capabilityIssuanceId: issued.projection.capabilityPublicId,
    });
    if (!command.accepted) {
      throw new Error(command.code);
    }
    const recovered = await port.persistMaintainerReviewedAdvisoryApprovalWithCapability(
      command.command,
    );
    expect(recovered.kind).toBe('recorded');
  });

  it('blocks revoked, cancelled, and expired capabilities without erasing approvals', async () => {
    const revokedParent = await insertParent();
    const revokedBundle = await issue(revokedParent);
    const revokedIssued = await port.issueDurableReviewerApprovalCapability(
      revokedBundle.prepared.command,
    );
    expect(revokedIssued.kind).toBe('issued');
    if (revokedIssued.kind !== 'issued') {
      return;
    }
    const lifecycle = sealDurableLifecycleAuthority({
      lifecyclePurpose: REVIEWER_CAPABILITY_REVOCATION_PURPOSE,
      authorizationId: randomUUID(),
      request: revokedBundle.request,
    });
    expect(lifecycle.accepted).toBe(true);
    if (!lifecycle.accepted) {
      return;
    }
    const revocation = prepareDurableReviewerCapabilityRevocation({
      capabilityIssuanceId: revokedIssued.projection.capabilityPublicId,
      lifecycleAuthority: lifecycle.lifecycleAuthority,
      request: revokedBundle.request,
    });
    expect(revocation.accepted).toBe(true);
    if (!revocation.accepted) {
      return;
    }
    const revoked = await port.revokeDurableReviewerApprovalCapability(revocation.command);
    expect(revoked.kind).toBe('recorded');
    const revokedReplay = await port.revokeDurableReviewerApprovalCapability(revocation.command);
    expect(revokedReplay.kind).toBe('already_recorded');
    if (revoked.kind === 'recorded' && revokedReplay.kind === 'already_recorded') {
      expect(revokedReplay.projection.issuedAt).toBe(revoked.projection.issuedAt);
      expect(revokedReplay.effects.inserts).toBe(0);
    }
    const revokedApproval = prepareDurableApprovalConsumption({
      approvalCommand: approvalCommand(revokedParent, {
        correlationId: revokedBundle.correlationId,
      }),
      capabilityIssuanceId: revokedIssued.projection.capabilityPublicId,
    });
    if (!revokedApproval.accepted) {
      throw new Error(revokedApproval.code);
    }
    expect(
      await port.persistMaintainerReviewedAdvisoryApprovalWithCapability(revokedApproval.command),
    ).toMatchObject({
      kind: 'rejected',
      code: 'authority_revoked',
    });
    const cancelledParent = await insertParent();
    const cancelledBundle = await issue(cancelledParent);
    const cancelledIssued = await port.issueDurableReviewerApprovalCapability(
      cancelledBundle.prepared.command,
    );
    expect(cancelledIssued.kind).toBe('issued');
    if (cancelledIssued.kind !== 'issued') {
      return;
    }
    const cancelSeal = sealDurableLifecycleAuthority({
      lifecyclePurpose: REVIEWER_CAPABILITY_CANCELLATION_PURPOSE,
      authorizationId: randomUUID(),
      request: cancelledBundle.request,
    });
    if (!cancelSeal.accepted) {
      throw new Error(cancelSeal.code);
    }
    const cancellation = prepareDurableReviewerCapabilityCancellation({
      capabilityIssuanceId: cancelledIssued.projection.capabilityPublicId,
      lifecycleAuthority: cancelSeal.lifecycleAuthority,
      request: cancelledBundle.request,
    });
    if (!cancellation.accepted) {
      throw new Error(cancellation.code);
    }
    expect((await port.cancelDurableReviewerApprovalCapability(cancellation.command)).kind).toBe(
      'recorded',
    );
    const cancelledApproval = prepareDurableApprovalConsumption({
      approvalCommand: approvalCommand(cancelledParent, {
        correlationId: cancelledBundle.correlationId,
      }),
      capabilityIssuanceId: cancelledIssued.projection.capabilityPublicId,
    });
    if (!cancelledApproval.accepted) {
      throw new Error(cancelledApproval.code);
    }
    expect(
      await port.persistMaintainerReviewedAdvisoryApprovalWithCapability(cancelledApproval.command),
    ).toMatchObject({
      kind: 'rejected',
      code: 'authority_cancelled',
    });
    const expiredParent = await insertParent();
    const expiredBundle = await issue(expiredParent);
    const expiredIssued = await port.issueDurableReviewerApprovalCapability(
      expiredBundle.prepared.command,
    );
    expect(expiredIssued.kind).toBe('issued');
    if (expiredIssued.kind !== 'issued') {
      return;
    }
    await prisma.$executeRaw`ALTER TABLE "reviewer_capability_issuance" DISABLE TRIGGER "reviewer_capability_issuance_guard"`;
    await prisma.$executeRaw`ALTER TABLE "reviewer_capability_issuance" DISABLE TRIGGER "reviewer_capability_issuance_append_only"`;
    try {
      await prisma.$executeRaw`
        UPDATE "reviewer_capability_issuance" AS issuance
        SET "issued_at" = clock.now - interval '900 seconds',
            "expires_at" = clock.now
        FROM (SELECT clock_timestamp() AS now) AS clock
        WHERE issuance."id" = ${expiredIssued.projection.capabilityPublicId}::uuid
      `;
    } finally {
      await prisma.$executeRaw`ALTER TABLE "reviewer_capability_issuance" ENABLE TRIGGER "reviewer_capability_issuance_append_only"`;
      await prisma.$executeRaw`ALTER TABLE "reviewer_capability_issuance" ENABLE TRIGGER "reviewer_capability_issuance_guard"`;
    }
    const expiredApproval = prepareDurableApprovalConsumption({
      approvalCommand: approvalCommand(expiredParent, {
        correlationId: expiredBundle.correlationId,
      }),
      capabilityIssuanceId: expiredIssued.projection.capabilityPublicId,
    });
    if (!expiredApproval.accepted) {
      throw new Error(expiredApproval.code);
    }
    expect(
      await port.persistMaintainerReviewedAdvisoryApprovalWithCapability(expiredApproval.command),
    ).toMatchObject({
      kind: 'rejected',
      code: 'authority_expired',
    });
    expect(
      await prisma.maintainerReviewedAdvisoryApproval.count({
        where: { advisoryRevisionId: expiredParent.revisionId },
      }),
    ).toBe(0);
  });

  it('settles concurrent issuance and single consumption without a second winner', async () => {
    const parent = await insertParent();
    const correlationId = randomUUID();
    const left = await issue(parent, correlationId);
    const right = await issue(parent, correlationId);
    const other = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
    const otherPort = createDurableReviewerApprovalCapabilityPersistence(other);
    try {
      const identicalParent = await insertParent();
      const identical = await issue(identicalParent);
      const identicalRace = await Promise.all([
        port.issueDurableReviewerApprovalCapability(identical.prepared.command),
        otherPort.issueDurableReviewerApprovalCapability(identical.prepared.command),
      ]);
      expect(identicalRace.filter((result) => result.kind === 'issued')).toHaveLength(1);
      expect(identicalRace.filter((result) => result.kind === 'already_issued')).toHaveLength(1);
      const raced = await Promise.all([
        port.issueDurableReviewerApprovalCapability(left.prepared.command),
        otherPort.issueDurableReviewerApprovalCapability(right.prepared.command),
      ]);
      expect(raced.filter((result) => result.kind === 'issued')).toHaveLength(1);
      expect(raced.filter((result) => result.kind === 'immutable_conflict')).toHaveLength(1);
      expect(
        await prisma.reviewerCapabilityIssuance.count({
          where: { advisoryRevisionId: parent.revisionId },
        }),
      ).toBe(1);
      const winner = raced.find((result) => result.kind === 'issued');
      if (winner?.kind !== 'issued') {
        return;
      }
      const command = approvalCommand(parent, { correlationId });
      const consumption = prepareDurableApprovalConsumption({
        approvalCommand: command,
        capabilityIssuanceId: winner.projection.capabilityPublicId,
      });
      if (!consumption.accepted) {
        throw new Error(consumption.code);
      }
      const consumed = await Promise.all([
        port.persistMaintainerReviewedAdvisoryApprovalWithCapability(consumption.command),
        otherPort.persistMaintainerReviewedAdvisoryApprovalWithCapability(consumption.command),
      ]);
      expect(consumed.filter((result) => result.kind === 'recorded')).toHaveLength(1);
      expect(consumed.filter((result) => result.kind === 'already_applied')).toHaveLength(1);
      expect(
        await prisma.reviewerCapabilityLifecycleObservation.count({
          where: { capabilityIssuanceId: winner.projection.capabilityPublicId },
        }),
      ).toBe(1);
      expect(
        await prisma.maintainerReviewedAdvisoryApproval.count({
          where: { advisoryRevisionId: parent.revisionId },
        }),
      ).toBe(1);
    } finally {
      await other.$disconnect();
    }
  });

  it('upgrades the prior frozen head once and repeats without changes', async () => {
    const ephemeral = await createEphemeralDatabase('it');
    const client = new PrismaClient({ datasources: { db: { url: ephemeral.databaseUrl } } });
    try {
      await applyThroughProductMatchEvaluation(ephemeral.databaseUrl);
      const appliedBefore = await client.$queryRaw<Array<{ name: string }>>`
        SELECT migration_name AS name FROM _prisma_migrations ORDER BY finished_at
      `;
      const beforeNames = appliedBefore.map((row) => row.name);
      expect(beforeNames.at(-1)).toBe(PRODUCT_MATCH_EVIDENCE_BATCH_3_EVALUATION);
      expect(beforeNames).not.toContain(REVIEWER_CAPABILITY_ISSUANCE);
      expect(EXPECTED_APPLIED_MIGRATIONS.filter((name) => !beforeNames.includes(name))).toEqual([
        REVIEWER_CAPABILITY_ISSUANCE,
      ]);
      await deployMigrations(ephemeral.databaseUrl);
      const appliedAfter = await client.$queryRaw<Array<{ name: string }>>`
        SELECT migration_name AS name FROM _prisma_migrations ORDER BY finished_at
      `;
      expect(appliedAfter.map((row) => row.name)).toEqual([...EXPECTED_APPLIED_MIGRATIONS]);
      const counts = async () => {
        const rows = await client.$queryRaw<
          Array<{
            capabilities: bigint;
            observations: bigint;
            approvals: bigint;
            findings: bigint;
            matches: bigint;
          }>
        >`
          SELECT
            (SELECT COUNT(*) FROM "reviewer_capability_issuance")::bigint AS capabilities,
            (SELECT COUNT(*) FROM "reviewer_capability_lifecycle_observation")::bigint AS observations,
            (SELECT COUNT(*) FROM "maintainer_reviewed_advisory_approval")::bigint AS approvals,
            (SELECT COUNT(*) FROM "finding")::bigint AS findings,
            (SELECT COUNT(*) FROM "product_match_evaluation_evidence")::bigint AS matches
        `;
        return rows[0];
      };
      const first = await counts();
      expect(Number(first?.capabilities)).toBe(0);
      expect(Number(first?.observations)).toBe(0);
      expect(Number(first?.approvals)).toBe(0);
      expect(Number(first?.findings)).toBe(0);
      expect(Number(first?.matches)).toBe(0);
      await deployMigrations(ephemeral.databaseUrl);
      const appliedTwice = await client.$queryRaw<Array<{ name: string }>>`
        SELECT migration_name AS name FROM _prisma_migrations ORDER BY finished_at
      `;
      expect(appliedTwice.map((row) => row.name)).toEqual(appliedAfter.map((row) => row.name));
      const second = await counts();
      expect(Number(second?.capabilities)).toBe(0);
      expect(Number(second?.observations)).toBe(0);
      expect(Number(second?.approvals)).toBe(0);
      expect(Number(second?.findings)).toBe(0);
      expect(Number(second?.matches)).toBe(0);
    } finally {
      await client.$disconnect();
      await dropEphemeralDatabase(ephemeral.admin, ephemeral.databaseName);
    }
  }, 120_000);

  it('rejects updates, deletes, and parent cascades', async () => {
    const parent = await insertParent();
    const bundle = await issue(parent);
    const issued = await port.issueDurableReviewerApprovalCapability(bundle.prepared.command);
    expect(issued.kind).toBe('issued');
    if (issued.kind !== 'issued') {
      return;
    }
    await expect(
      prisma.reviewerCapabilityIssuance.update({
        where: { id: issued.projection.capabilityPublicId },
        data: { reviewerIdentity: 'reviewer.three' },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.reviewerCapabilityIssuance.delete({
        where: { id: issued.projection.capabilityPublicId },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.reviewerCapabilityIssuance.updateMany({
        where: { id: issued.projection.capabilityPublicId },
        data: { reviewerIdentity: 'reviewer.four' },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.advisoryRevision.delete({ where: { id: parent.revisionId } }),
    ).rejects.toThrow();
    await expect(
      prisma.vulnerability.delete({ where: { id: parent.vulnerabilityId } }),
    ).rejects.toThrow();
    const command = prepareDurableApprovalConsumption({
      approvalCommand: approvalCommand(parent, { correlationId: bundle.correlationId }),
      capabilityIssuanceId: issued.projection.capabilityPublicId,
    });
    if (!command.accepted) {
      throw new Error(command.code);
    }
    const recorded = await port.persistMaintainerReviewedAdvisoryApprovalWithCapability(
      command.command,
    );
    expect(recorded.kind).toBe('recorded');
    if (recorded.kind !== 'recorded') {
      return;
    }
    await expect(
      prisma.maintainerReviewedAdvisoryApproval.delete({
        where: { id: recorded.projection.approvalId },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.reviewerCapabilityLifecycleObservation.deleteMany({
        where: { capabilityIssuanceId: issued.projection.capabilityPublicId },
      }),
    ).rejects.toThrow();
    const after = await prisma.maintainerReviewedAdvisoryApproval.findUnique({
      where: { id: recorded.projection.approvalId },
    });
    expect(after).not.toBeNull();
  });

  it('hides an uncommitted issuance, loses the connection, and settles a revocation race', async () => {
    const parent = await insertParent();
    const bundle = await issue(parent);
    let release: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let entered: (() => void) | undefined;
    const enteredGate = new Promise<void>((resolve) => {
      entered = resolve;
    });
    let capabilityId = '';
    let transactionError: unknown;
    const pending = prisma
      .$transaction(async (tx) => {
        const created = await tx.reviewerCapabilityIssuance.create({
          data: {
            issuanceSchemaVersion: bundle.prepared.command.issuanceSchemaVersion,
            capabilityPolicyId: bundle.request.capabilityPolicyId,
            capabilityPolicyVersion: bundle.request.capabilityPolicyVersion,
            approvalPolicyId: bundle.request.approvalPolicyId,
            approvalPolicyVersion: bundle.request.approvalPolicyVersion,
            approvalPurpose: bundle.request.approvalPurpose,
            issuerAuthorizationId: bundle.prepared.command.issuerAuthorizationId,
            issuerDecisionFingerprint: bundle.prepared.command.issuerDecisionFingerprint,
            approvalClaimFingerprint: bundle.prepared.command.approvalClaimFingerprint,
            advisoryFamilyIdentity: bundle.request.advisoryFamilyIdentity,
            advisoryRevisionId: bundle.request.advisoryRevisionId,
            contentFingerprint: bundle.request.contentFingerprint,
            affectedRangeFingerprint: bundle.request.affectedRangeFingerprint,
            npmPackageIdentity: bundle.request.npmPackageIdentity,
            vulnerabilityId: bundle.request.vulnerabilityId,
            sourceLicensePolicyId: bundle.request.sourceLicensePolicyId,
            sourceLicensePolicyVersion: bundle.request.sourceLicensePolicyVersion,
            approvedLicenseClassification: bundle.request.approvedLicenseClassification,
            licenseDecisionCanonical: bundle.request.licenseDecisionCanonical,
            sourceClassification: bundle.request.sourceClassification,
            authorIdentity: bundle.request.authorIdentity,
            reviewerIdentity: bundle.request.reviewerIdentity,
            correlationId: bundle.request.correlationId,
          },
          select: { id: true },
        });
        capabilityId = created.id;
        entered?.();
        await gate;
      })
      .catch((error: unknown) => {
        transactionError = error;
        entered?.();
      });
    await enteredGate;
    if (transactionError !== undefined) {
      throw transactionError;
    }
    const hidden = await port.inspectDurableReviewerApprovalCapability({
      inspectionSchemaVersion: DURABLE_REVIEWER_CAPABILITY_INSPECTION_SCHEMA_VERSION,
      capabilityIssuanceId: capabilityId,
    });
    expect(hidden.kind).toBe('not_found');
    release?.();
    await pending;
    const visible = await port.inspectDurableReviewerApprovalCapability({
      inspectionSchemaVersion: DURABLE_REVIEWER_CAPABILITY_INSPECTION_SCHEMA_VERSION,
      capabilityIssuanceId: capabilityId,
    });
    expect(visible.kind).toBe('found');

    const lostParent = await insertParent();
    const lostBundle = await issue(lostParent);
    const lostIssued = await port.issueDurableReviewerApprovalCapability(
      lostBundle.prepared.command,
    );
    expect(lostIssued.kind).toBe('issued');
    if (lostIssued.kind !== 'issued') {
      return;
    }
    const lostCommand = prepareDurableApprovalConsumption({
      approvalCommand: approvalCommand(lostParent, { correlationId: lostBundle.correlationId }),
      capabilityIssuanceId: lostIssued.projection.capabilityPublicId,
    });
    if (!lostCommand.accepted) {
      throw new Error(lostCommand.code);
    }
    const broken = new URL(databaseUrl);
    broken.port = '1';
    const unreachable = new PrismaClient({ datasources: { db: { url: broken.toString() } } });
    try {
      const isolated = createDurableReviewerApprovalCapabilityPersistence(unreachable);
      const lost = await isolated.persistMaintainerReviewedAdvisoryApprovalWithCapability(
        lostCommand.command,
      );
      expect(lost).toMatchObject({ kind: 'rejected', code: 'database_unavailable' });
      expect(JSON.stringify(lost)).not.toContain(databaseUrl);
    } finally {
      await unreachable.$disconnect();
    }
    expect(
      await prisma.reviewerCapabilityLifecycleObservation.count({
        where: { capabilityIssuanceId: lostIssued.projection.capabilityPublicId },
      }),
    ).toBe(0);
    expect(
      await prisma.maintainerReviewedAdvisoryApproval.count({
        where: { advisoryRevisionId: lostParent.revisionId },
      }),
    ).toBe(0);

    const raceParent = await insertParent();
    const raceBundle = await issue(raceParent);
    const raceIssued = await port.issueDurableReviewerApprovalCapability(
      raceBundle.prepared.command,
    );
    expect(raceIssued.kind).toBe('issued');
    if (raceIssued.kind !== 'issued') {
      return;
    }
    const lifecycle = sealDurableLifecycleAuthority({
      lifecyclePurpose: REVIEWER_CAPABILITY_REVOCATION_PURPOSE,
      authorizationId: randomUUID(),
      request: raceBundle.request,
    });
    expect(lifecycle.accepted).toBe(true);
    if (!lifecycle.accepted) {
      return;
    }
    const revocation = prepareDurableReviewerCapabilityRevocation({
      capabilityIssuanceId: raceIssued.projection.capabilityPublicId,
      lifecycleAuthority: lifecycle.lifecycleAuthority,
      request: raceBundle.request,
    });
    const consumption = prepareDurableApprovalConsumption({
      approvalCommand: approvalCommand(raceParent, { correlationId: raceBundle.correlationId }),
      capabilityIssuanceId: raceIssued.projection.capabilityPublicId,
    });
    expect(revocation.accepted && consumption.accepted).toBe(true);
    if (!revocation.accepted || !consumption.accepted) {
      return;
    }
    const other = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
    try {
      const otherPort = createDurableReviewerApprovalCapabilityPersistence(other);
      const [revoked, approved] = await Promise.all([
        port.revokeDurableReviewerApprovalCapability(revocation.command),
        otherPort.persistMaintainerReviewedAdvisoryApprovalWithCapability(consumption.command),
      ]);
      expect(
        await prisma.reviewerCapabilityLifecycleObservation.count({
          where: { capabilityIssuanceId: raceIssued.projection.capabilityPublicId },
        }),
      ).toBe(1);
      if (approved.kind === 'recorded') {
        expect(revoked).toMatchObject({ kind: 'rejected', code: 'authority_consumed' });
        expect(
          await prisma.maintainerReviewedAdvisoryApproval.count({
            where: { advisoryRevisionId: raceParent.revisionId },
          }),
        ).toBe(1);
      } else {
        expect(revoked.kind).toBe('recorded');
        expect(approved).toMatchObject({ kind: 'rejected', code: 'authority_revoked' });
        expect(
          await prisma.maintainerReviewedAdvisoryApproval.count({
            where: { advisoryRevisionId: raceParent.revisionId },
          }),
        ).toBe(0);
      }
    } finally {
      await other.$disconnect();
    }
  }, 60_000);

  it('rejects direct SQL that forges a package, a self-approval, or a mismatched consumption', async () => {
    const parent = await insertParent();
    const bundle = await issue(parent);
    const issued = await port.issueDurableReviewerApprovalCapability(bundle.prepared.command);
    expect(issued.kind).toBe('issued');
    if (issued.kind !== 'issued') {
      return;
    }
    const before = await prisma.reviewerCapabilityIssuance.count();
    const forgedFingerprint = digest('forged-claim');
    await expect(
      prisma.$executeRaw`
        INSERT INTO "reviewer_capability_issuance" (
          "issuance_schema_version",
          "capability_policy_id",
          "capability_policy_version",
          "approval_policy_id",
          "approval_policy_version",
          "approval_purpose",
          "issuer_authorization_id",
          "issuer_decision_fingerprint",
          "approval_claim_fingerprint",
          "advisory_family_identity",
          "advisory_revision_id",
          "content_fingerprint",
          "affected_range_fingerprint",
          "npm_package_identity",
          "vulnerability_id",
          "source_license_policy_id",
          "source_license_policy_version",
          "approved_license_classification",
          "license_decision_canonical",
          "source_classification",
          "author_identity",
          "reviewer_identity",
          "correlation_id"
        )
        SELECT
          issuance."issuance_schema_version",
          issuance."capability_policy_id",
          issuance."capability_policy_version",
          issuance."approval_policy_id",
          issuance."approval_policy_version",
          issuance."approval_purpose",
          ${randomUUID()}::uuid,
          issuance."issuer_decision_fingerprint",
          ${forgedFingerprint},
          issuance."advisory_family_identity",
          issuance."advisory_revision_id",
          issuance."content_fingerprint",
          issuance."affected_range_fingerprint",
          'not-a-package',
          issuance."vulnerability_id",
          issuance."source_license_policy_id",
          issuance."source_license_policy_version",
          issuance."approved_license_classification",
          issuance."license_decision_canonical",
          issuance."source_classification",
          issuance."author_identity",
          issuance."reviewer_identity",
          ${randomUUID()}::uuid
        FROM "reviewer_capability_issuance" issuance
        WHERE issuance."id" = ${issued.projection.capabilityPublicId}::uuid
      `,
    ).rejects.toThrow();
    await expect(
      prisma.$executeRaw`
        INSERT INTO "reviewer_capability_issuance" (
          "issuance_schema_version",
          "capability_policy_id",
          "capability_policy_version",
          "approval_policy_id",
          "approval_policy_version",
          "approval_purpose",
          "issuer_authorization_id",
          "issuer_decision_fingerprint",
          "approval_claim_fingerprint",
          "advisory_family_identity",
          "advisory_revision_id",
          "content_fingerprint",
          "affected_range_fingerprint",
          "npm_package_identity",
          "vulnerability_id",
          "source_license_policy_id",
          "source_license_policy_version",
          "approved_license_classification",
          "license_decision_canonical",
          "source_classification",
          "author_identity",
          "reviewer_identity",
          "correlation_id"
        )
        SELECT
          issuance."issuance_schema_version",
          issuance."capability_policy_id",
          issuance."capability_policy_version",
          issuance."approval_policy_id",
          issuance."approval_policy_version",
          issuance."approval_purpose",
          ${randomUUID()}::uuid,
          issuance."issuer_decision_fingerprint",
          ${digest('self-approval-claim')},
          issuance."advisory_family_identity",
          issuance."advisory_revision_id",
          issuance."content_fingerprint",
          issuance."affected_range_fingerprint",
          issuance."npm_package_identity",
          issuance."vulnerability_id",
          issuance."source_license_policy_id",
          issuance."source_license_policy_version",
          issuance."approved_license_classification",
          issuance."license_decision_canonical",
          issuance."source_classification",
          issuance."author_identity",
          issuance."author_identity",
          ${randomUUID()}::uuid
        FROM "reviewer_capability_issuance" issuance
        WHERE issuance."id" = ${issued.projection.capabilityPublicId}::uuid
      `,
    ).rejects.toThrow();
    expect(await prisma.reviewerCapabilityIssuance.count()).toBe(before);
    const consumption = prepareDurableApprovalConsumption({
      approvalCommand: approvalCommand(parent, { correlationId: bundle.correlationId }),
      capabilityIssuanceId: issued.projection.capabilityPublicId,
    });
    if (!consumption.accepted) {
      throw new Error(consumption.code);
    }
    const recorded = await port.persistMaintainerReviewedAdvisoryApprovalWithCapability(
      consumption.command,
    );
    expect(recorded.kind).toBe('recorded');
    if (recorded.kind !== 'recorded') {
      return;
    }
    const otherParent = await insertParent();
    const otherBundle = await issue(otherParent);
    const otherIssued = await port.issueDurableReviewerApprovalCapability(
      otherBundle.prepared.command,
    );
    expect(otherIssued.kind).toBe('issued');
    if (otherIssued.kind !== 'issued') {
      return;
    }
    await expect(
      prisma.$executeRaw`
        INSERT INTO "reviewer_capability_lifecycle_observation" (
          "capability_issuance_id",
          "observation_classification",
          "approval_id"
        ) VALUES (
          ${otherIssued.projection.capabilityPublicId}::uuid,
          'consumed',
          ${recorded.projection.approvalId}::uuid
        )
      `,
    ).rejects.toThrow();
    expect(
      await prisma.reviewerCapabilityLifecycleObservation.count({
        where: { capabilityIssuanceId: otherIssued.projection.capabilityPublicId },
      }),
    ).toBe(0);
    expect(
      await prisma.maintainerReviewedAdvisoryApproval.count({
        where: { id: recorded.projection.approvalId },
      }),
    ).toBe(1);
    const text = JSON.stringify({ recorded, otherIssued });
    expect(text).not.toContain('not-a-package');
    expect(text).not.toContain(databaseUrl);
  });

  it('lets cancellation win the issuance lock and keeps approval uncommitted', async () => {
    const parent = await insertParent();
    const bundle = await issue(parent);
    const issued = await port.issueDurableReviewerApprovalCapability(bundle.prepared.command);
    expect(issued.kind).toBe('issued');
    if (issued.kind !== 'issued') {
      return;
    }
    const capabilityId = issued.projection.capabilityPublicId;
    let release: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let entered: (() => void) | undefined;
    const enteredGate = new Promise<void>((resolve) => {
      entered = resolve;
    });
    const holder = prisma.$transaction(async (tx) => {
      await tx.$queryRaw`
        SELECT "id" FROM "reviewer_capability_issuance"
        WHERE "id" = ${capabilityId}::uuid
        FOR UPDATE
      `;
      entered?.();
      await gate;
      await tx.$executeRaw`
        INSERT INTO "reviewer_capability_lifecycle_observation" (
          "capability_issuance_id",
          "observation_classification",
          "lifecycle_authorization_id",
          "decision_fingerprint"
        ) VALUES (
          ${capabilityId}::uuid,
          'cancelled',
          ${randomUUID()}::uuid,
          ${bundle.prepared.command.issuerDecisionFingerprint}
        )
      `;
    });
    await enteredGate;
    const consumption = prepareDurableApprovalConsumption({
      approvalCommand: approvalCommand(parent, { correlationId: bundle.correlationId }),
      capabilityIssuanceId: capabilityId,
    });
    if (!consumption.accepted) {
      release?.();
      throw new Error(consumption.code);
    }
    const approval = port.persistMaintainerReviewedAdvisoryApprovalWithCapability(
      consumption.command,
    );
    try {
      await waitForDatabaseWait(prisma, ['tuple', 'transactionid']);
      const deleter = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
      try {
        await expect(
          deleter.$transaction(async (tx) => {
            await tx.$executeRaw`SET LOCAL lock_timeout = '400ms'`;
            await tx.$executeRaw`
              DELETE FROM "advisory_revision" WHERE "id" = ${parent.revisionId}::uuid
            `;
          }),
        ).rejects.toThrow();
      } finally {
        await deleter.$disconnect();
      }
      expect(await prisma.advisoryRevision.count({ where: { id: parent.revisionId } })).toBe(1);
      release?.();
      const [cancelled, approved] = await Promise.all([holder, approval]);
      expect(cancelled).toBeUndefined();
      expect(approved).toMatchObject({ kind: 'rejected', code: 'authority_cancelled' });
      expect(
        await prisma.maintainerReviewedAdvisoryApproval.count({
          where: { advisoryRevisionId: parent.revisionId },
        }),
      ).toBe(0);
      expect(
        await prisma.reviewerCapabilityLifecycleObservation.count({
          where: { capabilityIssuanceId: capabilityId, observationClassification: 'cancelled' },
        }),
      ).toBe(1);
    } finally {
      release?.();
      await holder.catch(() => undefined);
      await approval.catch(() => undefined);
    }
  }, 60_000);

  it('rolls approval back when database time reaches expiry before consumption commits', async () => {
    const parent = await insertParent();
    const bundle = await issue(parent);
    const issued = await port.issueDurableReviewerApprovalCapability(bundle.prepared.command);
    expect(issued.kind).toBe('issued');
    if (issued.kind !== 'issued') {
      return;
    }
    const capabilityId = issued.projection.capabilityPublicId;
    const lockKey = 88_003_204;
    const locker = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
    await prisma.$executeRaw`
      CREATE OR REPLACE FUNCTION patchpilot_test_pause_capability_observation()
      RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN
        PERFORM pg_advisory_lock(88003204);
        RETURN NEW;
      END;
      $$
    `;
    await prisma.$executeRaw`
      CREATE TRIGGER aaa_pause_capability_observation
      BEFORE INSERT ON "reviewer_capability_lifecycle_observation"
      FOR EACH ROW EXECUTE FUNCTION patchpilot_test_pause_capability_observation()
    `;
    await locker.$executeRaw`SELECT pg_advisory_lock(${lockKey})`;
    let pending: Promise<unknown> | undefined;
    try {
      const consumption = prepareDurableApprovalConsumption({
        approvalCommand: approvalCommand(parent, { correlationId: bundle.correlationId }),
        capabilityIssuanceId: capabilityId,
      });
      if (!consumption.accepted) {
        throw new Error(consumption.code);
      }
      await prisma.$executeRaw`ALTER TABLE "reviewer_capability_issuance" DISABLE TRIGGER "reviewer_capability_issuance_guard"`;
      await prisma.$executeRaw`ALTER TABLE "reviewer_capability_issuance" DISABLE TRIGGER "reviewer_capability_issuance_append_only"`;
      try {
        await prisma.$executeRaw`
          UPDATE "reviewer_capability_issuance" AS issuance
          SET "issued_at" = clock.now + interval '2 seconds' - interval '900 seconds',
              "expires_at" = clock.now + interval '2 seconds'
          FROM (SELECT clock_timestamp() AS now) AS clock
          WHERE issuance."id" = ${capabilityId}::uuid
        `;
      } finally {
        await prisma.$executeRaw`ALTER TABLE "reviewer_capability_issuance" ENABLE TRIGGER "reviewer_capability_issuance_append_only"`;
        await prisma.$executeRaw`ALTER TABLE "reviewer_capability_issuance" ENABLE TRIGGER "reviewer_capability_issuance_guard"`;
      }
      pending = port.persistMaintainerReviewedAdvisoryApprovalWithCapability(consumption.command);
      await waitForDatabaseWait(prisma, ['advisory']);
      await waitUntilDatabaseTimeReachesExpiry(prisma, capabilityId);
      await locker.$executeRaw`SELECT pg_advisory_unlock(${lockKey})`;
      const result = await pending;
      expect(result).toMatchObject({ kind: 'rejected', code: 'authority_expired' });
      expect(
        await prisma.maintainerReviewedAdvisoryApproval.count({
          where: { advisoryRevisionId: parent.revisionId },
        }),
      ).toBe(0);
      expect(
        await prisma.reviewerCapabilityLifecycleObservation.count({
          where: { capabilityIssuanceId: capabilityId },
        }),
      ).toBe(0);
    } finally {
      await locker.$executeRaw`SELECT pg_advisory_unlock_all()`.catch(() => undefined);
      await pending?.catch(() => undefined);
      await locker.$disconnect();
      await prisma.$executeRaw`DROP TRIGGER IF EXISTS aaa_pause_capability_observation ON "reviewer_capability_lifecycle_observation"`;
      await prisma.$executeRaw`DROP FUNCTION IF EXISTS patchpilot_test_pause_capability_observation()`;
    }
  }, 90_000);
});

async function waitForDatabaseWait(
  client: PrismaClient,
  waitEvents: readonly string[],
): Promise<void> {
  const deadline = Date.now() + 8_000;
  const first = waitEvents[0] ?? '';
  const second = waitEvents[1] ?? first;
  while (Date.now() < deadline) {
    const rows = await client.$queryRaw<Array<{ waiting: number }>>`
      SELECT COUNT(*)::int AS waiting
      FROM pg_stat_activity
      WHERE datname = current_database()
        AND pid <> pg_backend_pid()
        AND (wait_event = ${first} OR wait_event = ${second})
    `;
    if ((rows[0]?.waiting ?? 0) > 0) {
      return;
    }
    await new Promise((resolve) => {
      setTimeout(resolve, 25);
    });
  }
  throw new Error(`database session did not reach wait event ${waitEvents.join(',')}`);
}

async function waitUntilDatabaseTimeReachesExpiry(
  client: PrismaClient,
  capabilityId: string,
): Promise<void> {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    const rows = await client.$queryRaw<Array<{ expired: boolean }>>`
      SELECT patchpilot_reviewer_capability_is_expired("expires_at", clock_timestamp()) AS expired
      FROM "reviewer_capability_issuance"
      WHERE "id" = ${capabilityId}::uuid
    `;
    if (rows[0]?.expired === true) {
      return;
    }
    await new Promise((resolve) => {
      setTimeout(resolve, 50);
    });
  }
  throw new Error('database time did not reach capability expiry');
}
