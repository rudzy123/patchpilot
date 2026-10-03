/**
 * Disposable PostgreSQL proof for immutable maintainer-reviewed approvals.
 * Synthetic identities only. No evaluator, match evidence, or Finding writes.
 */

import { createHash, randomUUID } from 'node:crypto';
import { PrismaClient } from '@prisma/client';
import {
  ADVISORY_REVISION_INSPECTION_SCHEMA_VERSION,
  EXACT_MAPPING_METHOD,
  MAINTAINER_REVIEWED_APPROVAL_COMMAND_SCHEMA_VERSION,
  MAINTAINER_REVIEWED_APPROVAL_INSPECTION_SCHEMA_VERSION,
  MAINTAINER_REVIEWED_APPROVAL_PINS,
  MAINTAINER_REVIEWED_APPROVAL_SCHEMA_VERSION,
  DURABLE_REVIEWER_CAPABILITY_ZERO_EFFECTS,
  MAINTAINER_REVIEWED_BINDING_SCHEMA_VERSION,
  MAINTAINER_REVIEWED_FAMILY_SCHEMA_VERSION,
  MAINTAINER_REVIEWED_REVISION_SCHEMA_VERSION,
  SELECTED_FIRST_ECOSYSTEM,
  VULNERABILITY_MAPPING_POLICY_ID,
  classifyNpmPackageIdentityFromParts,
  maintainerReviewedApprovalReplayFingerprint,
} from '@patchpilot/vulnerability-intelligence';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
} from './integration-database.js';
import { createAdvisoryRevisionPersistence } from './advisory-revision-persistence.js';
import { createApprovalCapabilityHarness } from './reviewer-capability-approval-harness.js';
import { createDurableReviewerApprovalCapabilityPersistence } from './reviewer-capability-persistence.js';
import { createMaintainerReviewedAdvisoryApprovalPersistence } from './maintainer-reviewed-advisory-approval-persistence.js';

const PACKAGE_NAME = 'synth-maint-pkg';

type ParentShape = 'recorded' | 'withdrawn' | 'quarantined' | 'superseding' | 'unbound';

type ParentRecord = {
  readonly familyId: string;
  readonly revisionId: string;
  readonly revisionDigest: string;
  readonly familyDigest: string;
  readonly contentFingerprint: string;
  readonly rangeFingerprint: string;
  readonly packageIdentityKey: string;
  readonly vulnerabilityId: string;
  readonly bindingId: string;
  readonly authorIdentity: string;
};

function digest(label: string): string {
  return createHash('sha256').update(label).digest('hex');
}

function packageIdentityKey(): string {
  const identity = classifyNpmPackageIdentityFromParts({
    ecosystem: SELECTED_FIRST_ECOSYSTEM,
    observedNamespace: null,
    observedName: PACKAGE_NAME,
    observedIdentity: PACKAGE_NAME,
  });
  if (identity.classification !== 'valid') {
    throw new Error('synthetic package identity was rejected');
  }
  return identity.identityKey;
}

function approvalCommand(
  parent: ParentRecord,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
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
  const replay = maintainerReviewedApprovalReplayFingerprint({
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
  });
  return {
    ...fields,
    approvalReplayFingerprint:
      overrides['approvalReplayFingerprint'] === undefined
        ? replay
        : overrides['approvalReplayFingerprint'],
  };
}

describe('maintainer-reviewed advisory approval PostgreSQL persistence', () => {
  let databaseUrl = '';
  let databaseName = '';
  let admin: Awaited<ReturnType<typeof createEphemeralDatabase>>['admin'];
  let prisma: PrismaClient;
  let port: ReturnType<typeof createMaintainerReviewedAdvisoryApprovalPersistence>;
  let harness: ReturnType<typeof createApprovalCapabilityHarness>;
  let findingCount = 0;
  let matchCount = 0;

  beforeAll(async () => {
    const ephemeral = await createEphemeralDatabase('it');
    databaseUrl = ephemeral.databaseUrl;
    databaseName = ephemeral.databaseName;
    admin = ephemeral.admin;
    await deployMigrations(databaseUrl);
    prisma = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
    port = createMaintainerReviewedAdvisoryApprovalPersistence(prisma);
    harness = createApprovalCapabilityHarness(prisma);
    findingCount = await prisma.finding.count();
    matchCount = await prisma.matchEvaluationEvidence.count();
    expect(await prisma.maintainerReviewedAdvisoryApproval.count()).toBe(0);
  });

  afterAll(async () => {
    if (prisma !== undefined) {
      expect(await prisma.finding.count()).toBe(findingCount);
      expect(await prisma.matchEvaluationEvidence.count()).toBe(matchCount);
      expect(await prisma.findingObservation.count()).toBe(0);
      await prisma.$disconnect();
    }
    if (admin !== undefined) {
      await dropEphemeralDatabase(admin, databaseName);
    }
  });

  async function insertParent(shape: ParentShape = 'recorded'): Promise<ParentRecord> {
    const advisoryId = `SYNTHMAINT${digest(randomUUID()).slice(0, 12).toUpperCase()}`;
    const familyDigest = digest(`family:${advisoryId}`);
    const contentFingerprint = digest(`content:${advisoryId}`);
    const rangeFingerprint = digest(`range:${advisoryId}`);
    const revisionDigest = digest(`revision:${advisoryId}`);
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
        revisionDigest,
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
        revisionDisposition: shape === 'unbound' ? 'recorded' : shape,
        withdrawalClassification: shape === 'withdrawn' ? 'withdrawn' : 'not_withdrawn',
        quarantineClassification: shape === 'quarantined' ? 'quarantined' : 'not_quarantined',
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
    let bindingId = '';
    if (shape === 'recorded' || shape === 'superseding') {
      const binding = await prisma.advisoryVulnerabilityBinding.create({
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
        select: { id: true },
      });
      bindingId = binding.id;
    }
    return {
      familyId: family.id,
      revisionId: revision.id,
      revisionDigest,
      familyDigest,
      contentFingerprint,
      rangeFingerprint,
      packageIdentityKey: packageIdentityKey(),
      vulnerabilityId: vulnerability.id,
      bindingId,
      authorIdentity,
    };
  }

  it('persists one approval, replays it without writes, and keeps inspection safe', async () => {
    const parent = await insertParent();
    const beforeMatches = await prisma.matchEvaluationEvidence.count();
    const beforeFindings = await prisma.finding.count();
    const first = await harness.approve(approvalCommand(parent));
    expect(first.kind).toBe('recorded');
    if (first.kind !== 'recorded') {
      return;
    }
    expect(first.effects.inserts).toBe(2);
    expect(first.effects.updates).toBe(0);
    expect(first.effects.deletes).toBe(0);
    expect(first.effects.timestampChanges).toBe(0);
    expect(first.effects.authorityRenewals).toBe(0);
    expect(first.effects.evaluatorCalls).toBe(0);
    expect(first.effects.matchEvidenceWrites).toBe(0);
    expect(first.effects.findingWrites).toBe(0);
    expect(first.projection.reusableAuthority).toBe(false);
    expect(first.projection.findingCreation).toBe('unavailable');
    expect(JSON.stringify(first)).not.toContain(parent.authorIdentity);
    expect(JSON.stringify(first)).not.toContain('reviewer.two');
    expect(JSON.stringify(first)).not.toContain(parent.contentFingerprint);
    const second = await harness.approve(approvalCommand(parent));
    expect(second.kind).toBe('already_applied');
    if (second.kind !== 'already_applied') {
      return;
    }
    expect(second.effects).toEqual(DURABLE_REVIEWER_CAPABILITY_ZERO_EFFECTS);
    expect(second.projection.createdAt).toBe(first.projection.createdAt);
    expect(second.projection.approvalId).toBe(first.projection.approvalId);
    const row = await prisma.maintainerReviewedAdvisoryApproval.findUniqueOrThrow({
      where: { id: first.projection.approvalId },
    });
    expect(row.approvalSchemaVersion).toBe(MAINTAINER_REVIEWED_APPROVAL_SCHEMA_VERSION);
    expect(row.authorIdentity).toBe(parent.authorIdentity);
    expect(row.reviewerIdentity).toBe('reviewer.two');
    expect(row.contentFingerprint).toBe(parent.contentFingerprint);
    expect(row.rangeFingerprint).toBe(parent.rangeFingerprint);
    expect(row.packageIdentityKey).toBe(parent.packageIdentityKey);
    expect(row.vulnerabilityId).toBe(parent.vulnerabilityId);
    expect(row.licenseDecisionCanonical).toBe(MAINTAINER_REVIEWED_APPROVAL_PINS.licenseCanonical);
    expect(
      await prisma.maintainerReviewedAdvisoryApproval.count({
        where: { advisoryRevisionId: parent.revisionId },
      }),
    ).toBe(1);
    const inspected = await port.inspectMaintainerReviewedAdvisoryApproval({
      inspectionSchemaVersion: MAINTAINER_REVIEWED_APPROVAL_INSPECTION_SCHEMA_VERSION,
      approvalId: first.projection.approvalId,
    });
    expect(inspected.kind).toBe('found');
    if (inspected.kind === 'found') {
      expect(JSON.stringify(inspected)).not.toContain('reviewer.two');
      expect(JSON.stringify(inspected)).not.toContain(parent.vulnerabilityId);
    }
    expect(await prisma.matchEvaluationEvidence.count()).toBe(beforeMatches);
    expect(await prisma.finding.count()).toBe(beforeFindings);
  });

  it('rejects conflicts, self-approval, and parent mismatches without overwrite', async () => {
    const parent = await insertParent();
    const recorded = await harness.approve(approvalCommand(parent));
    expect(recorded.kind).toBe('recorded');
    const createdAt =
      recorded.kind === 'recorded' || recorded.kind === 'already_applied'
        ? recorded.projection.createdAt
        : '';
    const conflict = await harness.approve(
      approvalCommand(parent, { reviewerIdentity: 'reviewer.three' }),
    );
    expect(conflict.kind).toBe('immutable_conflict');
    if (conflict.kind === 'immutable_conflict') {
      expect(conflict.effects).toEqual(DURABLE_REVIEWER_CAPABILITY_ZERO_EFFECTS);
    }
    const stored = await prisma.maintainerReviewedAdvisoryApproval.findUniqueOrThrow({
      where: { advisoryRevisionId: parent.revisionId },
    });
    expect(stored.reviewerIdentity).toBe('reviewer.two');
    expect(stored.createdAt.toISOString()).toBe(createdAt);
    const self = await harness.approve(
      approvalCommand(await insertParent(), { reviewerIdentity: 'author.one' }),
    );
    expect(self).toMatchObject({ kind: 'rejected', code: 'self_approval' });
    const folded = await harness.approve(
      approvalCommand(await insertParent(), { reviewerIdentity: 'Author.One' }),
    );
    expect(folded).toMatchObject({ kind: 'rejected', code: 'self_approval' });
    const wrongFamily = await harness.approve(
      approvalCommand(parent, { expectedAdvisoryFamilyIdentity: digest('other-family') }),
    );
    expect(wrongFamily).toMatchObject({ kind: 'immutable_conflict' });
    const wrongContent = await harness.approve(
      approvalCommand(await insertParent(), {
        expectedContentFingerprint: digest('wrong-content'),
      }),
    );
    expect(wrongContent).toMatchObject({ kind: 'rejected', code: 'content_fingerprint_mismatch' });
    const wrongRange = await harness.approve(
      approvalCommand(await insertParent(), { expectedRangeFingerprint: digest('wrong-range') }),
    );
    expect(wrongRange).toMatchObject({ kind: 'rejected', code: 'range_fingerprint_mismatch' });
    const otherPackage = classifyNpmPackageIdentityFromParts({
      ecosystem: SELECTED_FIRST_ECOSYSTEM,
      observedNamespace: null,
      observedName: 'other-synth-pkg',
      observedIdentity: 'other-synth-pkg',
    });
    if (otherPackage.classification !== 'valid') {
      throw new Error('package');
    }
    const wrongPackage = await harness.approve(
      approvalCommand(await insertParent(), {
        expectedNpmPackageIdentity: otherPackage.identityKey,
      }),
    );
    expect(wrongPackage).toMatchObject({ kind: 'rejected', code: 'package_mismatch' });
    const extraVulnerability = await prisma.vulnerability.create({
      data: { osvId: `SYNTHETIC-extra-${randomUUID()}` },
      select: { id: true },
    });
    const wrongVulnerability = await harness.approve(
      approvalCommand(await insertParent(), { expectedVulnerabilityId: extraVulnerability.id }),
    );
    expect(wrongVulnerability).toMatchObject({ kind: 'rejected', code: 'vulnerability_mismatch' });
    const license = await harness.approve(
      approvalCommand(await insertParent(), { approvedLicenseClassification: 'MIT' }),
    );
    expect(license).toMatchObject({ kind: 'rejected', code: 'license_rejected' });
    expect(license.kind === 'rejected' ? license.effects.inserts : 1).toBe(0);
  });

  it('rejects withdrawn, quarantined, superseded, and synthetic parents', async () => {
    const withdrawn = await harness.approve(approvalCommand(await insertParent('withdrawn')));
    expect(withdrawn).toMatchObject({ kind: 'rejected', code: 'withdrawn_revision' });
    const quarantined = await harness.approve(approvalCommand(await insertParent('quarantined')));
    expect(quarantined).toMatchObject({ kind: 'rejected', code: 'quarantined_revision' });
    const prior = await insertParent();
    await prisma.advisoryRevision.create({
      data: {
        revisionSchemaVersion: MAINTAINER_REVIEWED_REVISION_SCHEMA_VERSION,
        advisoryFamilyId: prior.familyId,
        source: 'maintainer_reviewed_advisory',
        advisoryId: (
          await prisma.advisoryFamily.findUniqueOrThrow({
            where: { id: prior.familyId },
            select: { advisoryId: true },
          })
        ).advisoryId,
        familyDigest: prior.familyDigest,
        revisionDigest: digest(`successor:${prior.revisionId}`),
        providerGeneration: MAINTAINER_REVIEWED_APPROVAL_PINS.providerGeneration,
        contentFingerprint: digest(`successor-content:${prior.revisionId}`),
        session14RangeFingerprint: prior.rangeFingerprint,
        productRangeFingerprint: prior.rangeFingerprint,
        parserId: MAINTAINER_REVIEWED_APPROVAL_PINS.documentSchema,
        parserResourcePolicy: MAINTAINER_REVIEWED_APPROVAL_PINS.canonicalization,
        advisorySchemaVersion: MAINTAINER_REVIEWED_APPROVAL_PINS.documentSchema,
        advisorySchemaCommit: MAINTAINER_REVIEWED_APPROVAL_PINS.schemaCommit,
        sourceLicenseRegistryVersion: MAINTAINER_REVIEWED_APPROVAL_PINS.licensePolicyId,
        sourceLicensePolicyVersion: '1',
        spdxLicenseId: 'CC-BY-4.0',
        origin: 'maintainer_reviewed_advisory',
        trustClassification: 'unreviewed',
        revisionDisposition: 'superseding',
        withdrawalClassification: 'not_withdrawn',
        quarantineClassification: 'not_quarantined',
        supersedesRevisionDigest: prior.revisionDigest,
        supersedesAdvisoryRevisionId: prior.revisionId,
        retrievalClassification: MAINTAINER_REVIEWED_APPROVAL_PINS.retrieval,
        retrievalEvidenceId: MAINTAINER_REVIEWED_APPROVAL_PINS.retrievalEvidence,
        retrievalPolicyId: MAINTAINER_REVIEWED_APPROVAL_PINS.retrievalPolicy,
        ecosystem: 'npm',
        packageName: PACKAGE_NAME,
        packageIdentityKey: prior.packageIdentityKey,
        evaluatorVersion: 'session_14_batch_2_in_memory',
        matchingPolicyId: 'osv_first_ecosystem_matching_architecture_v1',
        aliasCount: 0,
        cveAliasCount: 0,
        aliasSetDigest: digest(`successor-aliases:${prior.revisionId}`),
        replayFingerprint: digest(`successor-replay:${prior.revisionId}`),
        authorIdentity: prior.authorIdentity,
      },
    });
    const superseded = await harness.approve(approvalCommand(prior));
    expect(superseded).toMatchObject({ kind: 'rejected', code: 'superseded_revision' });
    const syntheticFamily = await prisma.advisoryFamily.create({
      data: {
        familySchemaVersion: 'osv_advisory_family_identity_v1',
        source: 'synthetic_fixture',
        advisoryId: 'SYNTHETICADVMAINT1',
        familyDigest: digest('synthetic-family'),
        sourceRegistryVersion: 'osv_source_license_registry_v1',
      },
      select: { id: true },
    });
    const synthetic = await prisma.advisoryRevision.create({
      data: {
        revisionSchemaVersion: 'osv_advisory_revision_identity_v1',
        advisoryFamilyId: syntheticFamily.id,
        source: 'synthetic_fixture',
        advisoryId: 'SYNTHETICADVMAINT1',
        familyDigest: digest('synthetic-family'),
        revisionDigest: digest('synthetic-revision'),
        providerGeneration: 'synthetic_not_a_provider_generation',
        contentFingerprint: digest('synthetic-content'),
        session14RangeFingerprint: digest('synthetic-range'),
        productRangeFingerprint: digest('synthetic-product-range'),
        parserId: 'osv_advisory_parser_protocol_v1',
        parserResourcePolicy: 'osv_advisory_parser_resource_policy_v1',
        advisorySchemaVersion: 'v1.9.0',
        advisorySchemaCommit: 'f3f826310aeca8e324baabd195632f2229952abe',
        sourceLicenseRegistryVersion: 'osv_source_license_registry_v1',
        sourceLicensePolicyVersion: 'osv_source_license_registry_v1',
        origin: 'synthetic_fixture',
        trustClassification: 'not_applicable_synthetic',
        revisionDisposition: 'synthetic',
        withdrawalClassification: 'not_withdrawn',
        quarantineClassification: 'not_quarantined',
        supersedesRevisionDigest: 'none',
        retrievalClassification: 'synthetic_not_retrieved',
        retrievalEvidenceId: 'synthetic_retrieval_not_applicable',
        retrievalPolicyId: 'osv_generation_bound_retrieval_policy_v1',
        ecosystem: 'npm',
        packageName: PACKAGE_NAME,
        packageIdentityKey: packageIdentityKey(),
        evaluatorVersion: 'session_14_batch_2_in_memory',
        matchingPolicyId: 'osv_first_ecosystem_matching_architecture_v1',
        aliasCount: 0,
        cveAliasCount: 0,
        aliasSetDigest: digest('synthetic-aliases'),
        replayFingerprint: digest('synthetic-replay'),
      },
      select: { id: true },
    });
    const launder = await harness.approve(
      approvalCommand({
        ...(await insertParent()),
        revisionId: synthetic.id,
      }),
    );
    expect(launder).toMatchObject({ kind: 'rejected', code: 'source_mismatch' });
    expect(
      await prisma.maintainerReviewedAdvisoryApproval.count({
        where: { advisoryRevisionId: synthetic.id },
      }),
    ).toBe(0);
  });

  it('rejects update, delete, and parent cascade, and rolls back a failed insert', async () => {
    const parent = await insertParent();
    const recorded = await harness.approve(approvalCommand(parent));
    expect(recorded.kind).toBe('recorded');
    if (recorded.kind !== 'recorded') {
      return;
    }
    await expect(
      prisma.maintainerReviewedAdvisoryApproval.update({
        where: { id: recorded.projection.approvalId },
        data: { reviewerIdentity: 'reviewer.four' },
      }),
    ).rejects.toThrow(/23001|append-only/);
    await expect(
      prisma.maintainerReviewedAdvisoryApproval.delete({
        where: { id: recorded.projection.approvalId },
      }),
    ).rejects.toThrow(/23001|append-only/);
    await expect(
      prisma.advisoryRevision.delete({ where: { id: parent.revisionId } }),
    ).rejects.toThrow();
    await expect(
      prisma.advisoryFamily.delete({ where: { id: parent.familyId } }),
    ).rejects.toThrow();
    await expect(
      prisma.vulnerability.delete({ where: { id: parent.vulnerabilityId } }),
    ).rejects.toThrow();
    await expect(
      prisma.advisoryVulnerabilityBinding.delete({ where: { id: parent.bindingId } }),
    ).rejects.toThrow();
    expect(
      await prisma.maintainerReviewedAdvisoryApproval.findUnique({
        where: { id: recorded.projection.approvalId },
      }),
    ).not.toBeNull();
    const fresh = await insertParent();
    const before = await prisma.maintainerReviewedAdvisoryApproval.count();
    await expect(
      prisma.$transaction(async (tx) => {
        await tx.maintainerReviewedAdvisoryApproval.create({
          data: {
            approvalSchemaVersion: MAINTAINER_REVIEWED_APPROVAL_SCHEMA_VERSION,
            advisoryRevisionId: fresh.revisionId,
            advisoryFamilyId: fresh.familyId,
            familyDigest: fresh.familyDigest,
            approvalPolicyId: MAINTAINER_REVIEWED_APPROVAL_PINS.approvalPolicyId,
            approvalPolicyVersion: 1,
            approvalPurpose: MAINTAINER_REVIEWED_APPROVAL_PINS.approvalPurpose,
            sourceClassification: MAINTAINER_REVIEWED_APPROVAL_PINS.origin,
            authorIdentity: fresh.authorIdentity,
            reviewerIdentity: 'reviewer.two',
            reviewerClassification: MAINTAINER_REVIEWED_APPROVAL_PINS.reviewerClassification,
            contentFingerprint: fresh.contentFingerprint,
            rangeFingerprint: fresh.rangeFingerprint,
            packageIdentityKey: fresh.packageIdentityKey,
            vulnerabilityId: fresh.vulnerabilityId,
            advisoryVulnerabilityBindingId: fresh.bindingId,
            sourceLicensePolicyId: MAINTAINER_REVIEWED_APPROVAL_PINS.licensePolicyId,
            sourceLicensePolicyVersion: 1,
            approvedLicenseClassification: 'CC-BY-4.0',
            licenseDecisionCanonical: 'rejected-license',
            replayFingerprint: digest(`bad-license:${fresh.revisionId}`),
          },
        });
      }),
    ).rejects.toThrow();
    expect(await prisma.maintainerReviewedAdvisoryApproval.count()).toBe(before);
  });

  it('settles concurrent identical and conflicting approvals without overwrite', async () => {
    const parent = await insertParent();
    const command = approvalCommand(parent);
    const other = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
    const durable = createDurableReviewerApprovalCapabilityPersistence(prisma);
    const otherDurable = createDurableReviewerApprovalCapabilityPersistence(other);
    try {
      const prepared = await harness.issueConsumption(command);
      expect(prepared.accepted).toBe(true);
      if (!prepared.accepted) {
        return;
      }
      const raced = await Promise.all([
        durable.persistMaintainerReviewedAdvisoryApprovalWithCapability(prepared.command),
        otherDurable.persistMaintainerReviewedAdvisoryApprovalWithCapability(prepared.command),
      ]);
      const kinds = raced.map((result) => result.kind).sort();
      expect(kinds).toEqual(['already_applied', 'recorded']);
      const recorded = raced.find((result) => result.kind === 'recorded');
      const replay = raced.find((result) => result.kind === 'already_applied');
      if (recorded?.kind === 'recorded' && replay?.kind === 'already_applied') {
        expect(replay.projection.createdAt).toBe(recorded.projection.createdAt);
        expect(replay.effects.inserts).toBe(0);
        expect(replay.effects.timestampChanges).toBe(0);
      }
      expect(
        await prisma.maintainerReviewedAdvisoryApproval.count({
          where: { advisoryRevisionId: parent.revisionId },
        }),
      ).toBe(1);
      const conflictParent = await insertParent();
      const left = approvalCommand(conflictParent, { reviewerIdentity: 'reviewer.left' });
      const right = approvalCommand(conflictParent, { reviewerIdentity: 'reviewer.right' });
      const leftPrepared = await harness.issueConsumption(left);
      const rightPrepared = await harness.issueConsumption(right);
      expect(leftPrepared.accepted).toBe(true);
      expect(rightPrepared.accepted).toBe(true);
      if (!leftPrepared.accepted || !rightPrepared.accepted) {
        return;
      }
      const conflicted = await Promise.all([
        durable.persistMaintainerReviewedAdvisoryApprovalWithCapability(leftPrepared.command),
        otherDurable.persistMaintainerReviewedAdvisoryApprovalWithCapability(rightPrepared.command),
      ]);
      expect(conflicted.some((result) => result.kind === 'recorded')).toBe(true);
      expect(conflicted.some((result) => result.kind === 'immutable_conflict')).toBe(true);
      expect(
        await prisma.maintainerReviewedAdvisoryApproval.count({
          where: { advisoryRevisionId: conflictParent.revisionId },
        }),
      ).toBe(1);
      const winner = await prisma.maintainerReviewedAdvisoryApproval.findUniqueOrThrow({
        where: { advisoryRevisionId: conflictParent.revisionId },
      });
      expect(['reviewer.left', 'reviewer.right']).toContain(winner.reviewerIdentity);
      const selfParent = await insertParent();
      const [valid, denied] = await Promise.all([
        harness.approve(approvalCommand(selfParent)),
        harness.approve(approvalCommand(selfParent, { reviewerIdentity: 'author.one' })),
      ]);
      expect(valid.kind).toBe('recorded');
      expect(denied).toMatchObject({ kind: 'rejected', code: 'self_approval' });
    } finally {
      await other.$disconnect();
    }
  });

  it('hides an uncommitted approval and fails closed when the database is unreachable', async () => {
    const parent = await insertParent();
    let release: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let entered: (() => void) | undefined;
    const enteredGate = new Promise<void>((resolve) => {
      entered = resolve;
    });
    let approvalId = '';
    const pending = prisma.$transaction(async (tx) => {
      const created = await tx.maintainerReviewedAdvisoryApproval.create({
        data: {
          approvalSchemaVersion: MAINTAINER_REVIEWED_APPROVAL_SCHEMA_VERSION,
          advisoryRevisionId: parent.revisionId,
          advisoryFamilyId: parent.familyId,
          familyDigest: parent.familyDigest,
          approvalPolicyId: MAINTAINER_REVIEWED_APPROVAL_PINS.approvalPolicyId,
          approvalPolicyVersion: 1,
          approvalPurpose: MAINTAINER_REVIEWED_APPROVAL_PINS.approvalPurpose,
          sourceClassification: MAINTAINER_REVIEWED_APPROVAL_PINS.origin,
          authorIdentity: parent.authorIdentity,
          reviewerIdentity: 'reviewer.two',
          reviewerClassification: MAINTAINER_REVIEWED_APPROVAL_PINS.reviewerClassification,
          contentFingerprint: parent.contentFingerprint,
          rangeFingerprint: parent.rangeFingerprint,
          packageIdentityKey: parent.packageIdentityKey,
          vulnerabilityId: parent.vulnerabilityId,
          advisoryVulnerabilityBindingId: parent.bindingId,
          sourceLicensePolicyId: MAINTAINER_REVIEWED_APPROVAL_PINS.licensePolicyId,
          sourceLicensePolicyVersion: 1,
          approvedLicenseClassification: 'CC-BY-4.0',
          licenseDecisionCanonical: MAINTAINER_REVIEWED_APPROVAL_PINS.licenseCanonical,
          replayFingerprint: digest(`held:${parent.revisionId}`),
        },
        select: { id: true },
      });
      approvalId = created.id;
      entered?.();
      await gate;
    });
    await enteredGate;
    const hidden = await port.inspectMaintainerReviewedAdvisoryApproval({
      inspectionSchemaVersion: MAINTAINER_REVIEWED_APPROVAL_INSPECTION_SCHEMA_VERSION,
      approvalId,
    });
    expect(hidden.kind).toBe('not_found');
    release?.();
    await pending;
    const visible = await port.inspectMaintainerReviewedAdvisoryApproval({
      inspectionSchemaVersion: MAINTAINER_REVIEWED_APPROVAL_INSPECTION_SCHEMA_VERSION,
      approvalId,
    });
    expect(visible.kind).toBe('found');
    const broken = new URL(databaseUrl);
    broken.port = '1';
    const unreachable = new PrismaClient({ datasources: { db: { url: broken.toString() } } });
    try {
      const unreachableParent = await insertParent();
      const unreachableCommand = approvalCommand(unreachableParent);
      const prepared = await harness.issueConsumption(unreachableCommand);
      expect(prepared.accepted).toBe(true);
      if (!prepared.accepted) {
        return;
      }
      const isolated = createDurableReviewerApprovalCapabilityPersistence(unreachable);
      const result = await isolated.persistMaintainerReviewedAdvisoryApprovalWithCapability(
        prepared.command,
      );
      expect(result.kind).toBe('rejected');
      if (result.kind === 'rejected') {
        expect(result.code).toBe('database_unavailable');
        expect(result.effects).toEqual(DURABLE_REVIEWER_CAPABILITY_ZERO_EFFECTS);
        expect(JSON.stringify(result)).not.toContain(databaseUrl);
      }
    } finally {
      await unreachable.$disconnect();
    }
  });

  it('does not project a maintainer revision through the provider revision reader', async () => {
    const parent = await insertParent();
    const reader = createAdvisoryRevisionPersistence(prisma);
    const inspected = await reader.inspectImmutableAdvisoryRevision({
      inspectionSchemaVersion: ADVISORY_REVISION_INSPECTION_SCHEMA_VERSION,
      revisionDigest: parent.revisionDigest,
    });
    expect(inspected).toMatchObject({ kind: 'rejected', code: 'malformed_persisted_state' });
    expect(JSON.stringify(inspected)).not.toContain(parent.authorIdentity);
  });

  it('rejects source splits, self-approval SQL, mutations, and a lost connection', async () => {
    const parent = await insertParent();
    const beforeApprovals = await prisma.maintainerReviewedAdvisoryApproval.count();
    const beforeMatches = await prisma.matchEvaluationEvidence.count();
    const beforeFindings = await prisma.finding.count();
    const revisionBefore = await prisma.advisoryRevision.findUniqueOrThrow({
      where: { id: parent.revisionId },
      select: { authorIdentity: true, origin: true, contentFingerprint: true },
    });
    const recorded = await harness.approve(approvalCommand(parent));
    expect(recorded.kind).toBe('recorded');
    if (recorded.kind !== 'recorded') {
      return;
    }
    const revisionAfter = await prisma.advisoryRevision.findUniqueOrThrow({
      where: { id: parent.revisionId },
      select: { authorIdentity: true, origin: true, contentFingerprint: true },
    });
    expect(revisionAfter).toEqual(revisionBefore);
    const ambient = await harness.approve(
      approvalCommand(await insertParent(), {
        reviewerAuthorityClassification: 'administrator',
      }),
    );
    expect(ambient).toMatchObject({ kind: 'rejected', code: 'reviewer_authority_mismatch' });
    const owner = await harness.approve(
      approvalCommand(await insertParent(), {
        reviewerAuthorityClassification: 'repository_owner',
      }),
    );
    expect(owner).toMatchObject({ kind: 'rejected', code: 'reviewer_authority_mismatch' });
    const gitAuthor = await harness.approve(
      approvalCommand(await insertParent(), { reviewerAuthorityClassification: 'git_author' }),
    );
    expect(gitAuthor).toMatchObject({ kind: 'rejected', code: 'reviewer_authority_mismatch' });
    const purpose = await harness.approve(
      approvalCommand(await insertParent(), { approvalPurpose: 'approve' }),
    );
    expect(purpose).toMatchObject({ kind: 'rejected', code: 'purpose_mismatch' });
    const missingReviewer = await harness.approve(
      approvalCommand(await insertParent(), { reviewerIdentity: '' }),
    );
    expect(missingReviewer).toMatchObject({ kind: 'rejected', code: 'invalid_command' });
    const selfParent = await insertParent();
    await expect(
      prisma.maintainerReviewedAdvisoryApproval.create({
        data: {
          approvalSchemaVersion: MAINTAINER_REVIEWED_APPROVAL_SCHEMA_VERSION,
          advisoryRevisionId: selfParent.revisionId,
          advisoryFamilyId: selfParent.familyId,
          familyDigest: selfParent.familyDigest,
          approvalPolicyId: MAINTAINER_REVIEWED_APPROVAL_PINS.approvalPolicyId,
          approvalPolicyVersion: 1,
          approvalPurpose: MAINTAINER_REVIEWED_APPROVAL_PINS.approvalPurpose,
          sourceClassification: MAINTAINER_REVIEWED_APPROVAL_PINS.origin,
          authorIdentity: selfParent.authorIdentity,
          reviewerIdentity: selfParent.authorIdentity,
          reviewerClassification: MAINTAINER_REVIEWED_APPROVAL_PINS.reviewerClassification,
          contentFingerprint: selfParent.contentFingerprint,
          rangeFingerprint: selfParent.rangeFingerprint,
          packageIdentityKey: selfParent.packageIdentityKey,
          vulnerabilityId: selfParent.vulnerabilityId,
          advisoryVulnerabilityBindingId: selfParent.bindingId,
          sourceLicensePolicyId: MAINTAINER_REVIEWED_APPROVAL_PINS.licensePolicyId,
          sourceLicensePolicyVersion: 1,
          approvedLicenseClassification: 'CC-BY-4.0',
          licenseDecisionCanonical: MAINTAINER_REVIEWED_APPROVAL_PINS.licenseCanonical,
          replayFingerprint: digest(`self-sql:${selfParent.revisionId}`),
        },
      }),
    ).rejects.toThrow();
    expect(
      await prisma.maintainerReviewedAdvisoryApproval.count({
        where: { advisoryRevisionId: selfParent.revisionId },
      }),
    ).toBe(0);
    const splitId = `SYNTHSPLIT${digest(randomUUID()).slice(0, 10).toUpperCase()}`;
    const splitDigest = digest(`split-family:${splitId}`);
    const splitFamily = await prisma.advisoryFamily.create({
      data: {
        familySchemaVersion: MAINTAINER_REVIEWED_FAMILY_SCHEMA_VERSION,
        source: 'maintainer_reviewed_advisory',
        advisoryId: splitId,
        familyDigest: splitDigest,
        sourceRegistryVersion: MAINTAINER_REVIEWED_APPROVAL_PINS.licensePolicyId,
      },
      select: { id: true },
    });
    await expect(
      prisma.advisoryRevision.create({
        data: {
          revisionSchemaVersion: 'osv_advisory_revision_identity_v1',
          advisoryFamilyId: splitFamily.id,
          source: 'maintainer_reviewed_advisory',
          advisoryId: splitId,
          familyDigest: splitDigest,
          revisionDigest: digest(`split-revision:${splitId}`),
          providerGeneration: '1',
          contentFingerprint: digest(`split-content:${splitId}`),
          session14RangeFingerprint: digest(`split-range:${splitId}`),
          productRangeFingerprint: digest(`split-product:${splitId}`),
          parserId: 'osv_advisory_parser_protocol_v1',
          parserResourcePolicy: 'osv_advisory_parser_resource_policy_v1',
          advisorySchemaVersion: 'v1.9.0',
          advisorySchemaCommit: 'f3f826310aeca8e324baabd195632f2229952abe',
          sourceLicenseRegistryVersion: 'osv_source_license_registry_v1',
          sourceLicensePolicyVersion: 'osv_source_license_registry_v1',
          spdxLicenseId: 'CC-BY-4.0',
          origin: 'provider_derived',
          trustClassification: 'reviewed',
          revisionDisposition: 'recorded',
          withdrawalClassification: 'not_withdrawn',
          quarantineClassification: 'not_quarantined',
          supersedesRevisionDigest: 'none',
          retrievalClassification: 'recorded_reference',
          retrievalEvidenceId: randomUUID(),
          retrievalPolicyId: 'osv_generation_bound_retrieval_policy_v1',
          ecosystem: 'npm',
          packageName: PACKAGE_NAME,
          packageIdentityKey: packageIdentityKey(),
          evaluatorVersion: 'session_14_batch_2_in_memory',
          matchingPolicyId: 'osv_first_ecosystem_matching_architecture_v1',
          aliasCount: 0,
          cveAliasCount: 0,
          aliasSetDigest: digest(`split-aliases:${splitId}`),
          replayFingerprint: digest(`split-replay:${splitId}`),
        },
      }),
    ).rejects.toThrow();
    const renamed = await prisma.advisoryRevision.create({
      data: {
        revisionSchemaVersion: 'osv_advisory_revision_identity_v1',
        advisoryFamilyId: (
          await prisma.advisoryFamily.create({
            data: {
              familySchemaVersion: 'osv_advisory_family_identity_v1',
              source: 'synthetic_fixture',
              advisoryId: 'SYNTHCOPIEDMAINT1',
              familyDigest: digest('copied-synthetic-family'),
              sourceRegistryVersion: 'osv_source_license_registry_v1',
            },
            select: { id: true },
          })
        ).id,
        source: 'synthetic_fixture',
        advisoryId: 'SYNTHCOPIEDMAINT1',
        familyDigest: digest('copied-synthetic-family'),
        revisionDigest: digest('copied-synthetic-revision'),
        providerGeneration: 'synthetic_not_a_provider_generation',
        contentFingerprint: parent.contentFingerprint,
        session14RangeFingerprint: parent.rangeFingerprint,
        productRangeFingerprint: digest('copied-synthetic-product'),
        parserId: 'osv_advisory_parser_protocol_v1',
        parserResourcePolicy: 'osv_advisory_parser_resource_policy_v1',
        advisorySchemaVersion: 'v1.9.0',
        advisorySchemaCommit: 'f3f826310aeca8e324baabd195632f2229952abe',
        sourceLicenseRegistryVersion: 'osv_source_license_registry_v1',
        sourceLicensePolicyVersion: 'osv_source_license_registry_v1',
        origin: 'synthetic_fixture',
        trustClassification: 'not_applicable_synthetic',
        revisionDisposition: 'synthetic',
        withdrawalClassification: 'not_withdrawn',
        quarantineClassification: 'not_quarantined',
        supersedesRevisionDigest: 'none',
        retrievalClassification: 'synthetic_not_retrieved',
        retrievalEvidenceId: 'synthetic_retrieval_not_applicable',
        retrievalPolicyId: 'osv_generation_bound_retrieval_policy_v1',
        ecosystem: 'npm',
        packageName: PACKAGE_NAME,
        packageIdentityKey: parent.packageIdentityKey,
        evaluatorVersion: 'session_14_batch_2_in_memory',
        matchingPolicyId: 'osv_first_ecosystem_matching_architecture_v1',
        aliasCount: 0,
        cveAliasCount: 0,
        aliasSetDigest: digest('copied-synthetic-aliases'),
        replayFingerprint: digest('copied-synthetic-replay'),
      },
      select: { id: true, origin: true },
    });
    const copied = await harness.approve(approvalCommand({ ...parent, revisionId: renamed.id }));
    expect(copied).toMatchObject({ kind: 'rejected', code: 'source_mismatch' });
    expect(copied.kind === 'rejected' ? copied.effects.inserts : 1).toBe(0);
    await expect(
      prisma.advisoryRevision.update({
        where: { id: renamed.id },
        data: { origin: 'maintainer_reviewed_advisory' },
      }),
    ).rejects.toThrow();
    expect(
      (
        await prisma.advisoryRevision.findUniqueOrThrow({
          where: { id: renamed.id },
          select: { origin: true },
        })
      ).origin,
    ).toBe('synthetic_fixture');
    const conflictedParent = await insertParent('unbound');
    await expect(
      prisma.advisoryVulnerabilityBinding.create({
        data: {
          bindingSchemaVersion: MAINTAINER_REVIEWED_BINDING_SCHEMA_VERSION,
          advisoryRevisionId: conflictedParent.revisionId,
          vulnerabilityId: conflictedParent.vulnerabilityId,
          mappingPolicyId: VULNERABILITY_MAPPING_POLICY_ID,
          mappingMethod: EXACT_MAPPING_METHOD,
          mappingEvidenceFingerprint: digest('conflicted-mapping'),
          mappingReviewState: 'reviewed',
          mappingSourceClassification: 'explicit_reviewed_binding',
          conflictClassification: 'conflicted',
          bindingClassification: 'provider_native_without_cve',
          replayFingerprint: digest(`conflicted-binding:${conflictedParent.revisionId}`),
        },
      }),
    ).rejects.toThrow();
    const approvalId = recorded.projection.approvalId;
    for (const column of [
      'author_identity',
      'reviewer_identity',
      'approval_purpose',
      'approval_policy_id',
      'approval_policy_version',
      'advisory_revision_id',
      'content_fingerprint',
      'range_fingerprint',
      'package_identity_key',
      'vulnerability_id',
      'approved_license_classification',
      'license_decision_canonical',
      'created_at',
      'replay_fingerprint',
      'source_classification',
    ]) {
      await expect(
        prisma.$executeRawUnsafe(
          `UPDATE "maintainer_reviewed_advisory_approval" SET "${column}" = "${column}" WHERE "id" = $1::uuid`,
          approvalId,
        ),
      ).rejects.toThrow(/23001|append-only/);
    }
    await expect(
      prisma.maintainerReviewedAdvisoryApproval.updateMany({
        where: { id: approvalId },
        data: { reviewerIdentity: 'reviewer.five' },
      }),
    ).rejects.toThrow(/23001|append-only/);
    await expect(
      prisma.maintainerReviewedAdvisoryApproval.deleteMany({ where: { id: approvalId } }),
    ).rejects.toThrow(/23001|append-only/);
    await expect(
      prisma.$executeRaw`DELETE FROM "maintainer_reviewed_advisory_approval" WHERE "id" = ${approvalId}::uuid`,
    ).rejects.toThrow(/23001|append-only/);
    const deleteActions = await prisma.$queryRaw<Array<{ name: string; action: string }>>`
      SELECT con.conname AS name, con.confdeltype AS action
      FROM pg_constraint con
      WHERE con.contype = 'f'
        AND (
          con.conrelid = '"maintainer_reviewed_advisory_approval"'::regclass
          OR con.confrelid = '"maintainer_reviewed_advisory_approval"'::regclass
        )
    `;
    expect(deleteActions.length).toBeGreaterThan(0);
    expect(deleteActions.every((row) => row.action === 'r')).toBe(true);
    const stored = await prisma.maintainerReviewedAdvisoryApproval.findUniqueOrThrow({
      where: { id: approvalId },
    });
    expect(stored.reviewerIdentity).toBe('reviewer.two');
    expect(stored.authorIdentity).toBe(parent.authorIdentity);
    expect(stored.createdAt.toISOString()).toBe(recorded.projection.createdAt);
    const fresh = await insertParent();
    const loser = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
    let release: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let entered: (() => void) | undefined;
    const enteredGate = new Promise<void>((resolve) => {
      entered = resolve;
    });
    let backendPid = 0;
    const pending = loser.$transaction(async (tx) => {
      const backends = await tx.$queryRaw<Array<{ pid: number }>>`
        SELECT pg_backend_pid()::int AS pid
      `;
      backendPid = backends[0]?.pid ?? 0;
      await tx.maintainerReviewedAdvisoryApproval.create({
        data: {
          approvalSchemaVersion: MAINTAINER_REVIEWED_APPROVAL_SCHEMA_VERSION,
          advisoryRevisionId: fresh.revisionId,
          advisoryFamilyId: fresh.familyId,
          familyDigest: fresh.familyDigest,
          approvalPolicyId: MAINTAINER_REVIEWED_APPROVAL_PINS.approvalPolicyId,
          approvalPolicyVersion: 1,
          approvalPurpose: MAINTAINER_REVIEWED_APPROVAL_PINS.approvalPurpose,
          sourceClassification: MAINTAINER_REVIEWED_APPROVAL_PINS.origin,
          authorIdentity: fresh.authorIdentity,
          reviewerIdentity: 'reviewer.two',
          reviewerClassification: MAINTAINER_REVIEWED_APPROVAL_PINS.reviewerClassification,
          contentFingerprint: fresh.contentFingerprint,
          rangeFingerprint: fresh.rangeFingerprint,
          packageIdentityKey: fresh.packageIdentityKey,
          vulnerabilityId: fresh.vulnerabilityId,
          advisoryVulnerabilityBindingId: fresh.bindingId,
          sourceLicensePolicyId: MAINTAINER_REVIEWED_APPROVAL_PINS.licensePolicyId,
          sourceLicensePolicyVersion: 1,
          approvedLicenseClassification: 'CC-BY-4.0',
          licenseDecisionCanonical: MAINTAINER_REVIEWED_APPROVAL_PINS.licenseCanonical,
          replayFingerprint: digest(`terminated:${fresh.revisionId}`),
        },
      });
      entered?.();
      await gate;
    });
    await enteredGate;
    const terminated = await prisma.$queryRaw<Array<{ terminated: boolean }>>`
      SELECT pg_terminate_backend(${backendPid}::integer) AS terminated
    `;
    expect(terminated[0]?.terminated).toBe(true);
    release?.();
    await expect(pending).rejects.toThrow();
    await loser.$disconnect().catch(() => undefined);
    expect(
      await prisma.maintainerReviewedAdvisoryApproval.count({
        where: { advisoryRevisionId: fresh.revisionId },
      }),
    ).toBe(0);
    expect(await prisma.maintainerReviewedAdvisoryApproval.count()).toBeGreaterThan(
      beforeApprovals,
    );
    expect(await prisma.matchEvaluationEvidence.count()).toBe(beforeMatches);
    expect(await prisma.finding.count()).toBe(beforeFindings);
  }, 60_000);
});
