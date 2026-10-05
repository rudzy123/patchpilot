/**
 * Disposable PostgreSQL proof for one legal non-synthetic npm affected evaluation.
 * No provider contact. No Finding writes.
 */

import { createHash, randomUUID } from 'node:crypto';
import { PrismaClient } from '@prisma/client';
import {
  EXACT_MAPPING_METHOD,
  MAINTAINER_REVIEWED_APPROVAL_COMMAND_SCHEMA_VERSION,
  MAINTAINER_REVIEWED_APPROVAL_PINS,
  MAINTAINER_REVIEWED_BINDING_SCHEMA_VERSION,
  MAINTAINER_REVIEWED_FAMILY_SCHEMA_VERSION,
  MAINTAINER_REVIEWED_REVISION_SCHEMA_VERSION,
  PRODUCT_MATCH_EVALUATION_COMMAND_SCHEMA_VERSION,
  PRODUCT_MATCH_EVALUATION_POLICY_ID,
  PRODUCT_MATCH_EVALUATION_POLICY_VERSION,
  PRODUCT_MATCH_EVALUATOR_ID,
  PRODUCT_MATCH_EVALUATOR_VERSION,
  PRODUCT_MATCH_MATCHING_POLICY_ID,
  PRODUCT_MATCH_MATCHING_POLICY_VERSION,
  SELECTED_FIRST_ECOSYSTEM,
  VULNERABILITY_MAPPING_POLICY_ID,
  classifyNpmPackageIdentityFromParts,
  componentEvidenceFingerprint,
  createProductMatchEvaluationComposition,
  parseProductMatchEvaluationCommand,
  maintainerReviewedApprovalReplayFingerprint,
  session14RangeFingerprint,
} from '@patchpilot/vulnerability-intelligence';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { createApprovalCapabilityHarness } from './reviewer-capability-approval-harness.js';
import {
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
} from './integration-database.js';
import { createProductMatchEvaluationPersistence } from './product-match-evaluation-persistence.js';
import {
  createAsset,
  createOrg,
  createProcessingIngestion,
  createSbom,
  resolvedComponent,
} from './sbom-test-fixture.js';

const PACKAGE_NAME = 'reviewed-npm-widget';
const OBSERVED_VERSION = '1.1.0';
const RANGES = [
  {
    type: 'SEMVER' as const,
    events: [
      { name: 'introduced' as const, value: '1.0.0' },
      { name: 'fixed' as const, value: '2.0.0' },
    ],
  },
];

function digest(label: string): string {
  return createHash('sha256').update(label).digest('hex');
}

function occurrenceReads(queries: readonly string[]): string[] {
  return queries.filter((query) => /from\s+(?:"public"\.)?"component_occurrence"/i.test(query));
}

async function settledOccurrenceReads(
  queries: readonly string[],
  expectedCount: number,
): Promise<string[]> {
  const deadline = Date.now() + 2_000;
  let reads = occurrenceReads(queries);
  while (reads.length < expectedCount && Date.now() < deadline) {
    await new Promise((resolve) => {
      setTimeout(resolve, 10);
    });
    reads = occurrenceReads(queries);
  }
  return reads;
}

function whereClause(query: string): string {
  const normalized = query.toLowerCase().replace(/\s+/g, ' ');
  const index = normalized.lastIndexOf(' where ');
  return index === -1 ? '' : normalized.slice(index);
}

function scopedByOrganization(query: string): boolean {
  const where = whereClause(query);
  return where.includes('organization_id') && where.includes('"id"');
}

function closedRejection() {
  return {
    kind: 'rejected' as const,
    code: 'component_occurrence_missing' as const,
    evaluatorCalls: 0 as const,
    providerCalls: 0 as const,
    parserCalls: 0 as const,
    findingWrites: 0 as const,
    inserts: 0 as const,
  };
}

function packageIdentity(): string {
  const identity = classifyNpmPackageIdentityFromParts({
    ecosystem: SELECTED_FIRST_ECOSYSTEM,
    observedNamespace: null,
    observedName: PACKAGE_NAME,
    observedIdentity: PACKAGE_NAME,
  });
  if (identity.classification !== 'valid') {
    throw new Error('package identity was rejected');
  }
  return identity.identityKey;
}

describe('product match evaluation PostgreSQL persistence', () => {
  let databaseUrl = '';
  let databaseName = '';
  let admin: Awaited<ReturnType<typeof createEphemeralDatabase>>['admin'];
  let prisma: PrismaClient;

  beforeAll(async () => {
    const ephemeral = await createEphemeralDatabase('it');
    databaseUrl = ephemeral.databaseUrl;
    databaseName = ephemeral.databaseName;
    admin = ephemeral.admin;
    await deployMigrations(databaseUrl);
    prisma = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
  });

  afterAll(async () => {
    if (prisma !== undefined) {
      await prisma.$disconnect();
    }
    if (admin !== undefined) {
      await dropEphemeralDatabase(admin, databaseName);
    }
  });

  async function seedLegal(label: string) {
    const rangeFingerprint = session14RangeFingerprint(RANGES, []);
    const contentFingerprint = digest(`content:${label}:${randomUUID()}`);
    const advisoryId = `REVIEWNPM${digest(label).slice(0, 8).toUpperCase()}`;
    const familyDigest = digest(`family:${advisoryId}`);
    const revisionDigest = digest(`revision:${advisoryId}`);
    const authorIdentity = 'author.one';
    const vulnerability = await prisma.vulnerability.create({
      data: { osvId: `REVIEWED-${advisoryId}` },
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
        revisionDisposition: 'recorded',
        withdrawalClassification: 'not_withdrawn',
        quarantineClassification: 'not_quarantined',
        supersedesRevisionDigest: 'none',
        retrievalClassification: MAINTAINER_REVIEWED_APPROVAL_PINS.retrieval,
        retrievalEvidenceId: MAINTAINER_REVIEWED_APPROVAL_PINS.retrievalEvidence,
        retrievalPolicyId: MAINTAINER_REVIEWED_APPROVAL_PINS.retrievalPolicy,
        ecosystem: 'npm',
        packageName: PACKAGE_NAME,
        packageIdentityKey: packageIdentity(),
        evaluatorVersion: PRODUCT_MATCH_EVALUATOR_VERSION,
        matchingPolicyId: PRODUCT_MATCH_MATCHING_POLICY_ID,
        aliasCount: 0,
        cveAliasCount: 0,
        aliasSetDigest: digest(`aliases:${advisoryId}`),
        replayFingerprint: digest(`replay:${advisoryId}`),
        authorIdentity,
      },
      select: { id: true },
    });
    await prisma.advisoryRevisionRangeEvent.createMany({
      data: [
        {
          advisoryRevisionId: revision.id,
          rangeOrdinal: 0,
          eventOrdinal: 0,
          eventName: 'introduced',
          eventValue: '1.0.0',
        },
        {
          advisoryRevisionId: revision.id,
          rangeOrdinal: 0,
          eventOrdinal: 1,
          eventName: 'fixed',
          eventValue: '2.0.0',
        },
      ],
    });
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
      select: { id: true },
    });
    const approvalCommand = {
      commandSchemaVersion: MAINTAINER_REVIEWED_APPROVAL_COMMAND_SCHEMA_VERSION,
      advisoryRevisionId: revision.id,
      expectedAdvisoryFamilyIdentity: familyDigest,
      expectedSourceClassification: MAINTAINER_REVIEWED_APPROVAL_PINS.origin,
      expectedContentFingerprint: contentFingerprint,
      expectedRangeFingerprint: rangeFingerprint,
      expectedNpmPackageIdentity: packageIdentity(),
      expectedVulnerabilityId: vulnerability.id,
      authorIdentity,
      reviewerIdentity: 'reviewer.two',
      reviewerAuthorityClassification: MAINTAINER_REVIEWED_APPROVAL_PINS.reviewerClassification,
      approvalPolicyId: MAINTAINER_REVIEWED_APPROVAL_PINS.approvalPolicyId,
      approvalPolicyVersion: MAINTAINER_REVIEWED_APPROVAL_PINS.approvalPolicyVersion,
      approvalPurpose: MAINTAINER_REVIEWED_APPROVAL_PINS.approvalPurpose,
      sourceLicensePolicyId: MAINTAINER_REVIEWED_APPROVAL_PINS.licensePolicyId,
      sourceLicensePolicyVersion: MAINTAINER_REVIEWED_APPROVAL_PINS.licensePolicyVersion,
      approvedLicenseClassification: MAINTAINER_REVIEWED_APPROVAL_PINS.licenseClassification,
      correlationId: randomUUID(),
    };
    const approvalReplayFingerprint = maintainerReviewedApprovalReplayFingerprint({
      advisoryRevisionId: revision.id,
      familyDigest,
      approvalPolicyId: MAINTAINER_REVIEWED_APPROVAL_PINS.approvalPolicyId,
      approvalPolicyVersion: MAINTAINER_REVIEWED_APPROVAL_PINS.approvalPolicyVersion,
      approvalPurpose: MAINTAINER_REVIEWED_APPROVAL_PINS.approvalPurpose,
      sourceClassification: MAINTAINER_REVIEWED_APPROVAL_PINS.origin,
      authorIdentity,
      reviewerIdentity: 'reviewer.two',
      reviewerClassification: MAINTAINER_REVIEWED_APPROVAL_PINS.reviewerClassification,
      contentFingerprint,
      rangeFingerprint,
      packageIdentityKey: packageIdentity(),
      vulnerabilityId: vulnerability.id,
      sourceLicensePolicyId: MAINTAINER_REVIEWED_APPROVAL_PINS.licensePolicyId,
      sourceLicensePolicyVersion: MAINTAINER_REVIEWED_APPROVAL_PINS.licensePolicyVersion,
      approvedLicenseClassification: MAINTAINER_REVIEWED_APPROVAL_PINS.licenseClassification,
      licenseDecisionCanonical: MAINTAINER_REVIEWED_APPROVAL_PINS.licenseCanonical,
    });
    const approval = await createApprovalCapabilityHarness(prisma).approve({
      ...approvalCommand,
      approvalReplayFingerprint,
    });
    if (approval.kind !== 'recorded') {
      throw new Error(`approval was ${approval.kind}`);
    }
    const org = await createOrg(prisma, `${label}-${randomUUID().slice(0, 8)}`);
    const asset = await createAsset(prisma, org.id, `asset-${label}`);
    const sbomSha = digest(`sbom:${label}`);
    const sbom = await createSbom(prisma, {
      organizationId: org.id,
      assetId: asset.id,
      sha256: sbomSha,
      receivedAt: new Date('2026-10-02T12:00:00.000Z'),
    });
    const ingestion = await createProcessingIngestion(prisma, {
      organizationId: org.id,
      sbomId: sbom.id,
      assetId: asset.id,
    });
    const componentInput = resolvedComponent({
      name: PACKAGE_NAME,
      bomRef: 'component-1',
      version: OBSERVED_VERSION,
    });
    const component = await prisma.component.create({
      data: {
        organizationId: org.id,
        identityKey: componentInput.identityKey,
        purl: componentInput.versionlessPurl,
        ecosystem: 'npm',
        namespace: null,
        name: PACKAGE_NAME,
        identityState: 'resolved',
      },
    });
    const occurrence = await prisma.componentOccurrence.create({
      data: {
        organizationId: org.id,
        assetId: asset.id,
        sbomId: sbom.id,
        sbomIngestionId: ingestion.id,
        componentId: component.id,
        bomRef: 'component-1',
        version: OBSERVED_VERSION,
        versionKnown: true,
        isDirect: true,
      },
    });
    const evaluationCommand = {
      commandSchemaVersion: PRODUCT_MATCH_EVALUATION_COMMAND_SCHEMA_VERSION,
      organizationId: org.id,
      componentOccurrenceId: occurrence.id,
      expectedComponentEvidenceFingerprint: componentEvidenceFingerprint({
        organizationId: org.id,
        componentOccurrenceId: occurrence.id,
        assetId: asset.id,
        sbomId: sbom.id,
        sbomIngestionId: ingestion.id,
        componentId: component.id,
        componentIdentityKey: component.identityKey,
        ecosystem: 'npm',
        namespace: null,
        name: PACKAGE_NAME,
        rawObservedVersion: OBSERVED_VERSION,
        versionKnown: true,
        sbomSha256: sbomSha,
      }),
      expectedNpmPackageIdentity: packageIdentity(),
      expectedRawObservedVersion: OBSERVED_VERSION,
      advisoryRevisionId: revision.id,
      approvalEvidenceId: approval.projection.approvalId,
      expectedContentFingerprint: contentFingerprint,
      expectedRangeFingerprint: rangeFingerprint,
      expectedVulnerabilityId: vulnerability.id,
      evaluatorId: PRODUCT_MATCH_EVALUATOR_ID,
      evaluatorVersion: PRODUCT_MATCH_EVALUATOR_VERSION,
      matchingPolicyId: PRODUCT_MATCH_MATCHING_POLICY_ID,
      matchingPolicyVersion: PRODUCT_MATCH_MATCHING_POLICY_VERSION,
      productEvidencePolicyId: PRODUCT_MATCH_EVALUATION_POLICY_ID,
      productEvidencePolicyVersion: PRODUCT_MATCH_EVALUATION_POLICY_VERSION,
      correlationId: randomUUID(),
    };
    return {
      evaluationCommand,
      organizationId: org.id,
      assetId: asset.id,
      componentId: component.id,
      componentIdentityKey: component.identityKey,
      familyId: family.id,
      familyDigest,
      revisionId: revision.id,
      revisionDigest,
      vulnerabilityId: vulnerability.id,
      approvalId: approval.projection.approvalId,
      contentFingerprint,
      rangeFingerprint,
      advisoryId,
      authorIdentity,
      packageIdentityKey: packageIdentity(),
    };
  }

  async function occurrenceOnAsset(
    seeded: Awaited<ReturnType<typeof seedLegal>>,
    label: string,
    assetId: string,
    bomRef: string,
  ) {
    const sbomSha = digest(`sbom:${label}:${randomUUID()}`);
    const sbom = await createSbom(prisma, {
      organizationId: seeded.organizationId,
      assetId,
      sha256: sbomSha,
      receivedAt: new Date('2026-10-05T12:00:00.000Z'),
    });
    const ingestion = await createProcessingIngestion(prisma, {
      organizationId: seeded.organizationId,
      sbomId: sbom.id,
      assetId,
    });
    const occurrence = await prisma.componentOccurrence.create({
      data: {
        organizationId: seeded.organizationId,
        assetId,
        sbomId: sbom.id,
        sbomIngestionId: ingestion.id,
        componentId: seeded.componentId,
        bomRef,
        version: OBSERVED_VERSION,
        versionKnown: true,
        isDirect: true,
      },
    });
    return {
      ...seeded.evaluationCommand,
      componentOccurrenceId: occurrence.id,
      expectedComponentEvidenceFingerprint: componentEvidenceFingerprint({
        organizationId: seeded.organizationId,
        componentOccurrenceId: occurrence.id,
        assetId,
        sbomId: sbom.id,
        sbomIngestionId: ingestion.id,
        componentId: seeded.componentId,
        componentIdentityKey: seeded.componentIdentityKey,
        ecosystem: 'npm',
        namespace: null,
        name: PACKAGE_NAME,
        rawObservedVersion: OBSERVED_VERSION,
        versionKnown: true,
        sbomSha256: sbomSha,
      }),
      correlationId: randomUUID(),
    };
  }

  async function approveSuccessor(seeded: Awaited<ReturnType<typeof seedLegal>>) {
    const contentFingerprint = digest(`successor-content:${randomUUID()}`);
    const revisionDigest = digest(`successor-revision:${randomUUID()}`);
    const successor = await prisma.advisoryRevision.create({
      data: {
        revisionSchemaVersion: MAINTAINER_REVIEWED_REVISION_SCHEMA_VERSION,
        advisoryFamilyId: seeded.familyId,
        source: 'maintainer_reviewed_advisory',
        advisoryId: seeded.advisoryId,
        familyDigest: seeded.familyDigest,
        revisionDigest,
        providerGeneration: MAINTAINER_REVIEWED_APPROVAL_PINS.providerGeneration,
        contentFingerprint,
        session14RangeFingerprint: seeded.rangeFingerprint,
        productRangeFingerprint: seeded.rangeFingerprint,
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
        supersedesRevisionDigest: seeded.revisionDigest,
        supersedesAdvisoryRevisionId: seeded.revisionId,
        retrievalClassification: MAINTAINER_REVIEWED_APPROVAL_PINS.retrieval,
        retrievalEvidenceId: MAINTAINER_REVIEWED_APPROVAL_PINS.retrievalEvidence,
        retrievalPolicyId: MAINTAINER_REVIEWED_APPROVAL_PINS.retrievalPolicy,
        ecosystem: 'npm',
        packageName: PACKAGE_NAME,
        packageIdentityKey: seeded.packageIdentityKey,
        evaluatorVersion: PRODUCT_MATCH_EVALUATOR_VERSION,
        matchingPolicyId: PRODUCT_MATCH_MATCHING_POLICY_ID,
        aliasCount: 0,
        cveAliasCount: 0,
        aliasSetDigest: digest(`successor-aliases:${randomUUID()}`),
        replayFingerprint: digest(`successor-replay:${randomUUID()}`),
        authorIdentity: seeded.authorIdentity,
      },
      select: { id: true },
    });
    await prisma.advisoryRevisionRangeEvent.createMany({
      data: [
        {
          advisoryRevisionId: successor.id,
          rangeOrdinal: 0,
          eventOrdinal: 0,
          eventName: 'introduced',
          eventValue: '1.0.0',
        },
        {
          advisoryRevisionId: successor.id,
          rangeOrdinal: 0,
          eventOrdinal: 1,
          eventName: 'fixed',
          eventValue: '2.0.0',
        },
      ],
    });
    const binding = await prisma.advisoryVulnerabilityBinding.create({
      data: {
        bindingSchemaVersion: MAINTAINER_REVIEWED_BINDING_SCHEMA_VERSION,
        advisoryRevisionId: successor.id,
        vulnerabilityId: seeded.vulnerabilityId,
        mappingPolicyId: VULNERABILITY_MAPPING_POLICY_ID,
        mappingMethod: EXACT_MAPPING_METHOD,
        mappingEvidenceFingerprint: digest(`successor-mapping:${randomUUID()}`),
        mappingReviewState: 'reviewed',
        mappingSourceClassification: 'explicit_reviewed_binding',
        conflictClassification: 'none',
        bindingClassification: 'provider_native_without_cve',
        replayFingerprint: digest(`successor-binding:${randomUUID()}`),
      },
      select: { id: true },
    });
    const approvalReplayFingerprint = maintainerReviewedApprovalReplayFingerprint({
      advisoryRevisionId: successor.id,
      familyDigest: seeded.familyDigest,
      approvalPolicyId: MAINTAINER_REVIEWED_APPROVAL_PINS.approvalPolicyId,
      approvalPolicyVersion: MAINTAINER_REVIEWED_APPROVAL_PINS.approvalPolicyVersion,
      approvalPurpose: MAINTAINER_REVIEWED_APPROVAL_PINS.approvalPurpose,
      sourceClassification: MAINTAINER_REVIEWED_APPROVAL_PINS.origin,
      authorIdentity: seeded.authorIdentity,
      reviewerIdentity: 'reviewer.two',
      reviewerClassification: MAINTAINER_REVIEWED_APPROVAL_PINS.reviewerClassification,
      contentFingerprint,
      rangeFingerprint: seeded.rangeFingerprint,
      packageIdentityKey: seeded.packageIdentityKey,
      vulnerabilityId: seeded.vulnerabilityId,
      sourceLicensePolicyId: MAINTAINER_REVIEWED_APPROVAL_PINS.licensePolicyId,
      sourceLicensePolicyVersion: MAINTAINER_REVIEWED_APPROVAL_PINS.licensePolicyVersion,
      approvedLicenseClassification: MAINTAINER_REVIEWED_APPROVAL_PINS.licenseClassification,
      licenseDecisionCanonical: MAINTAINER_REVIEWED_APPROVAL_PINS.licenseCanonical,
    });
    const approval = await createApprovalCapabilityHarness(prisma).approve({
      commandSchemaVersion: MAINTAINER_REVIEWED_APPROVAL_COMMAND_SCHEMA_VERSION,
      advisoryRevisionId: successor.id,
      expectedAdvisoryFamilyIdentity: seeded.familyDigest,
      expectedSourceClassification: MAINTAINER_REVIEWED_APPROVAL_PINS.origin,
      expectedContentFingerprint: contentFingerprint,
      expectedRangeFingerprint: seeded.rangeFingerprint,
      expectedNpmPackageIdentity: seeded.packageIdentityKey,
      expectedVulnerabilityId: seeded.vulnerabilityId,
      authorIdentity: seeded.authorIdentity,
      reviewerIdentity: 'reviewer.two',
      reviewerAuthorityClassification: MAINTAINER_REVIEWED_APPROVAL_PINS.reviewerClassification,
      approvalPolicyId: MAINTAINER_REVIEWED_APPROVAL_PINS.approvalPolicyId,
      approvalPolicyVersion: MAINTAINER_REVIEWED_APPROVAL_PINS.approvalPolicyVersion,
      approvalPurpose: MAINTAINER_REVIEWED_APPROVAL_PINS.approvalPurpose,
      sourceLicensePolicyId: MAINTAINER_REVIEWED_APPROVAL_PINS.licensePolicyId,
      sourceLicensePolicyVersion: MAINTAINER_REVIEWED_APPROVAL_PINS.licensePolicyVersion,
      approvedLicenseClassification: MAINTAINER_REVIEWED_APPROVAL_PINS.licenseClassification,
      approvalReplayFingerprint,
      correlationId: randomUUID(),
    });
    if (approval.kind !== 'recorded') {
      throw new Error(`successor approval was ${approval.kind}`);
    }
    return {
      revisionId: successor.id,
      approvalId: approval.projection.approvalId,
      contentFingerprint,
      bindingId: binding.id,
      evaluationCommand: {
        ...seeded.evaluationCommand,
        advisoryRevisionId: successor.id,
        approvalEvidenceId: approval.projection.approvalId,
        expectedContentFingerprint: contentFingerprint,
        correlationId: randomUUID(),
      },
    };
  }

  function service() {
    return createProductMatchEvaluationComposition({
      port: createProductMatchEvaluationPersistence(prisma),
    });
  }

  it('persists one affected evaluation, replays it, and rejects a conflicting fingerprint', async () => {
    const findingBefore = await prisma.finding.count();
    const syntheticMatchesBefore = await prisma.matchEvaluationEvidence.count();
    const seeded = await seedLegal('happy');
    const composition = service();
    const first = await composition.execute(seeded.evaluationCommand);
    expect(first.kind === 'rejected' ? first.code : first.kind).toBe('recorded');
    if (first.kind !== 'recorded') {
      return;
    }
    expect(first.projection.outcome).toBe('affected');
    expect(first.projection.explanationCodes).toEqual(['affected_within_introduced_fixed_range']);
    expect(first.projection.productOrigin).toBe('maintainer_reviewed_advisory');
    expect(first.projection.findingAuthority).toBe(false);
    expect(first.projection.findingCreation).toBe('unavailable');
    expect(first.projection.suppressionAuthority).toBe(false);
    expect(first.evaluatorCalls).toBe(1);
    expect(first.providerCalls).toBe(0);
    expect(first.findingWrites).toBe(0);
    expect(first.inserts).toBe(1);
    expect(JSON.stringify(first)).not.toContain('author.one');
    expect(JSON.stringify(first)).not.toContain('reviewer.two');
    const stored = await prisma.productMatchEvaluationEvidence.findFirstOrThrow({
      where: { id: first.projection.matchEvidenceId, organizationId: seeded.organizationId },
      select: { createdAt: true, findingCreation: true, suppressionAuthority: true },
    });
    const replay = await composition.execute({
      ...seeded.evaluationCommand,
      correlationId: randomUUID(),
    });
    expect(replay.kind).toBe('already_applied');
    if (replay.kind !== 'already_applied') {
      return;
    }
    expect(replay.evaluatorCalls).toBe(0);
    expect(replay.inserts).toBe(0);
    expect(replay.projection.createdAt).toBe(stored.createdAt.toISOString());
    expect(await prisma.productMatchEvaluationEvidence.count()).toBe(1);
    const conflict = await composition.execute({
      ...seeded.evaluationCommand,
      expectedContentFingerprint: digest('changed-content'),
      correlationId: randomUUID(),
    });
    expect(conflict.kind).toBe('immutable_conflict');
    if (conflict.kind === 'immutable_conflict') {
      expect(conflict.evaluatorCalls).toBe(0);
      expect(conflict.inserts).toBe(0);
    }
    expect(stored.findingCreation).toBe('unavailable');
    expect(stored.suppressionAuthority).toBe(false);
    await expect(
      prisma.productMatchEvaluationEvidence.update({
        where: { id: first.projection.matchEvidenceId },
        data: { outcome: 'unknown' },
      }),
    ).rejects.toThrow();
    const otherOrg = await createOrg(prisma, `other-${randomUUID().slice(0, 8)}`);
    const hidden = await composition.inspect({
      organizationId: otherOrg.id,
      evidenceId: first.projection.matchEvidenceId,
    });
    const absentEvidence = await composition.inspect({
      organizationId: seeded.organizationId,
      evidenceId: randomUUID(),
    });
    const malformedEvidence = await composition.inspect({
      organizationId: seeded.organizationId,
      evidenceId: 'not-a-uuid',
    });
    const sameRequesterAbsent = await composition.inspect({
      organizationId: otherOrg.id,
      evidenceId: randomUUID(),
    });
    expect(hidden).toEqual({ kind: 'not_found' });
    expect(absentEvidence).toEqual(hidden);
    expect(sameRequesterAbsent).toEqual(hidden);
    const foreignEvaluation = await composition.execute({
      ...seeded.evaluationCommand,
      organizationId: otherOrg.id,
      correlationId: randomUUID(),
    });
    const absentEvaluation = await composition.execute({
      ...seeded.evaluationCommand,
      organizationId: otherOrg.id,
      componentOccurrenceId: randomUUID(),
      correlationId: randomUUID(),
    });
    expect(foreignEvaluation).toEqual(closedRejection());
    expect(absentEvaluation).toEqual(foreignEvaluation);
    expect(JSON.stringify(foreignEvaluation)).not.toContain(first.projection.matchEvidenceId);
    expect(malformedEvidence).toEqual({ kind: 'rejected', code: 'invalid_command' });
    expect(malformedEvidence).not.toEqual(hidden);
    expect(JSON.stringify(hidden)).not.toContain(first.projection.matchEvidenceId);
    expect(JSON.stringify(hidden)).not.toContain(otherOrg.id);
    expect(JSON.stringify(hidden)).not.toContain(seeded.organizationId);
    const visible = await composition.inspect({
      organizationId: seeded.organizationId,
      evidenceId: first.projection.matchEvidenceId,
    });
    expect(visible.kind).toBe('found');
    expect(await prisma.finding.count()).toBe(findingBefore);
    expect(await prisma.matchEvaluationEvidence.count()).toBe(syntheticMatchesBefore);
  });

  it('keeps foreign and absent tenant resources publicly indistinguishable', async () => {
    const seeded = await seedLegal('tenant');
    const other = await createOrg(prisma, `cross-${randomUUID().slice(0, 8)}`);
    const before = await prisma.productMatchEvaluationEvidence.count();
    const findingsBefore = await prisma.finding.count();
    const absentOccurrenceId = randomUUID();
    const port = createProductMatchEvaluationPersistence(prisma);
    const authorized = await port.inspectComponent({
      organizationId: seeded.organizationId,
      componentOccurrenceId: seeded.evaluationCommand.componentOccurrenceId,
    });
    expect(authorized.kind).toBe('found');
    if (authorized.kind === 'found') {
      expect(authorized.snapshot.organizationId).toBe(seeded.organizationId);
      expect(authorized.snapshot.componentOccurrenceId).toBe(
        seeded.evaluationCommand.componentOccurrenceId,
      );
    }
    const foreign = await port.inspectComponent({
      organizationId: other.id,
      componentOccurrenceId: seeded.evaluationCommand.componentOccurrenceId,
    });
    const absent = await port.inspectComponent({
      organizationId: seeded.organizationId,
      componentOccurrenceId: absentOccurrenceId,
    });
    expect(foreign).toEqual({ kind: 'not_found' });
    expect(absent).toEqual(foreign);
    expect(JSON.stringify(foreign)).not.toContain(other.id);
    expect(JSON.stringify(foreign)).not.toContain(seeded.organizationId);
    expect(JSON.stringify(foreign)).not.toContain(seeded.evaluationCommand.componentOccurrenceId);
    const malformed = await port.inspectComponent({
      organizationId: seeded.organizationId,
      componentOccurrenceId: 'not-a-uuid',
    });
    expect(malformed).toEqual({ kind: 'malformed' });
    expect(malformed).not.toEqual(foreign);

    const closed = closedRejection();
    const composition = service();
    const foreignCommand = await composition.execute({
      ...seeded.evaluationCommand,
      organizationId: other.id,
      correlationId: randomUUID(),
    });
    const absentCommand = await composition.execute({
      ...seeded.evaluationCommand,
      componentOccurrenceId: absentOccurrenceId,
      correlationId: randomUUID(),
    });
    expect(foreignCommand).toEqual(closed);
    expect(absentCommand).toEqual(closed);
    expect(JSON.stringify(foreignCommand)).not.toContain(other.id);
    expect(JSON.stringify(foreignCommand)).not.toContain(
      seeded.evaluationCommand.componentOccurrenceId,
    );

    const parsedForeign = parseProductMatchEvaluationCommand({
      ...seeded.evaluationCommand,
      organizationId: other.id,
      correlationId: randomUUID(),
    });
    const parsedAbsent = parseProductMatchEvaluationCommand({
      ...seeded.evaluationCommand,
      componentOccurrenceId: randomUUID(),
      correlationId: randomUUID(),
    });
    expect(parsedForeign.accepted).toBe(true);
    expect(parsedAbsent.accepted).toBe(true);
    if (!parsedForeign.accepted || !parsedAbsent.accepted) {
      return;
    }
    expect(await port.commit({ command: parsedForeign.command })).toEqual(closed);
    expect(await port.commit({ command: parsedAbsent.command })).toEqual(closed);

    const queries: string[] = [];
    const logging = new PrismaClient({
      datasources: { db: { url: databaseUrl } },
      log: [{ emit: 'event', level: 'query' }],
    });
    logging.$on('query', (event) => {
      queries.push(event.query);
    });
    const loggingPort = createProductMatchEvaluationPersistence(logging);
    try {
      queries.length = 0;
      expect(
        await loggingPort.inspectComponent({
          organizationId: seeded.organizationId,
          componentOccurrenceId: 'not-a-uuid',
        }),
      ).toEqual({ kind: 'malformed' });
      expect(queries).toEqual([]);

      queries.length = 0;
      expect(
        await loggingPort.inspectComponent({
          organizationId: other.id,
          componentOccurrenceId: seeded.evaluationCommand.componentOccurrenceId,
        }),
      ).toEqual({ kind: 'not_found' });
      const foreignReads = await settledOccurrenceReads(queries, 1);
      expect(foreignReads.length).toBe(1);
      expect(foreignReads.every(scopedByOrganization)).toBe(true);

      queries.length = 0;
      expect(
        await loggingPort.inspectComponent({
          organizationId: seeded.organizationId,
          componentOccurrenceId: randomUUID(),
        }),
      ).toEqual({ kind: 'not_found' });
      const absentReads = await settledOccurrenceReads(queries, 1);
      expect(absentReads.length).toBe(1);
      expect(absentReads.every(scopedByOrganization)).toBe(true);

      queries.length = 0;
      expect(await loggingPort.commit({ command: parsedForeign.command })).toEqual(closed);
      const commitReads = await settledOccurrenceReads(queries, 1);
      expect(commitReads.length).toBe(1);
      expect(commitReads.every(scopedByOrganization)).toBe(true);

      queries.length = 0;
      const absentEvidence = await loggingPort.inspect({
        organizationId: seeded.organizationId,
        evidenceId: randomUUID(),
      });
      const foreignEvidence = await loggingPort.inspect({
        organizationId: other.id,
        evidenceId: randomUUID(),
      });
      expect(absentEvidence).toEqual({ kind: 'not_found' });
      expect(foreignEvidence).toEqual(absentEvidence);
      const evidenceReads = queries.filter((query) =>
        query.toLowerCase().includes('product_match_evaluation_evidence'),
      );
      expect(evidenceReads.length).toBe(2);
      expect(evidenceReads.every(scopedByOrganization)).toBe(true);
      const queriesBeforeMalformedEvidence = queries.length;
      expect(
        await loggingPort.inspect({
          organizationId: 'not-a-uuid',
          evidenceId: randomUUID(),
        }),
      ).toEqual({ kind: 'rejected', code: 'invalid_command' });
      expect(queries.length).toBe(queriesBeforeMalformedEvidence);
    } finally {
      await logging.$disconnect();
    }

    expect(await prisma.productMatchEvaluationEvidence.count()).toBe(before);
    expect(await prisma.finding.count()).toBe(findingsBefore);
  });

  it('lets one concurrent duplicate win and keeps one row', async () => {
    const seeded = await seedLegal('race');
    const before = await prisma.productMatchEvaluationEvidence.count();
    const limitedUrl = `${databaseUrl}${databaseUrl.includes('?') ? '&' : '?'}connection_limit=2`;
    const limited = new PrismaClient({ datasources: { db: { url: limitedUrl } } });
    const limitedService = createProductMatchEvaluationComposition({
      port: createProductMatchEvaluationPersistence(limited),
    });
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const pending = [0, 1].map(async () => {
      await gate;
      return limitedService.execute({
        ...seeded.evaluationCommand,
        correlationId: randomUUID(),
      });
    });
    release();
    let results: Awaited<ReturnType<typeof limitedService.execute>>[];
    try {
      results = await Promise.all(pending);
    } finally {
      await limited.$disconnect();
    }
    const recorded = results.filter((result) => result.kind === 'recorded');
    const replayed = results.filter((result) => result.kind === 'already_applied');
    expect(recorded).toHaveLength(1);
    expect(replayed).toHaveLength(1);
    expect(recorded[0]?.evaluatorCalls).toBe(1);
    expect(replayed[0]?.evaluatorCalls).toBe(0);
    expect(await prisma.productMatchEvaluationEvidence.count()).toBe(before + 1);
  });

  it('keeps one row when concurrent commands disagree with stored evidence', async () => {
    const seeded = await seedLegal('conflict-race');
    const composition = service();
    const first = await composition.execute(seeded.evaluationCommand);
    expect(first.kind === 'rejected' ? first.code : first.kind).toBe('recorded');
    const before = await prisma.productMatchEvaluationEvidence.count();
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const pending = [0, 1].map(async () => {
      await gate;
      return service().execute({
        ...seeded.evaluationCommand,
        expectedContentFingerprint: digest(`race-content-${randomUUID()}`),
        correlationId: randomUUID(),
      });
    });
    release();
    const results = await Promise.all(pending);
    expect(results.every((result) => result.kind === 'immutable_conflict')).toBe(true);
    expect(results.every((result) => result.evaluatorCalls === 0 && result.inserts === 0)).toBe(
      true,
    );
    expect(await prisma.productMatchEvaluationEvidence.count()).toBe(before);
  });

  it('keeps a locked or deleted foreign occurrence indistinguishable from absence', async () => {
    const seeded = await seedLegal('locked-foreign');
    const attacker = await createOrg(prisma, `locked-${randomUUID().slice(0, 8)}`);
    const occurrenceId = seeded.evaluationCommand.componentOccurrenceId;
    const absentOccurrenceId = randomUUID();
    const queries: string[] = [];
    const logging = new PrismaClient({
      datasources: { db: { url: databaseUrl } },
      log: [{ emit: 'event', level: 'query' }],
    });
    logging.$on('query', (event) => {
      queries.push(event.query);
    });
    const port = createProductMatchEvaluationPersistence(logging);
    let release: (() => void) | undefined;
    let markEntered: (() => void) | undefined;
    const entered = new Promise<void>((resolve) => {
      markEntered = resolve;
    });
    let holderFailed = false;
    const holder = prisma
      .$transaction(
        async (tx) => {
          await tx.$queryRaw`
            SELECT "id" FROM "component_occurrence"
            WHERE "id" = ${occurrenceId}::uuid
            FOR UPDATE
          `;
          markEntered?.();
          await new Promise<void>((resolve) => {
            release = resolve;
          });
        },
        { maxWait: 5_000, timeout: 20_000 },
      )
      .catch((error: unknown) => {
        holderFailed = true;
        markEntered?.();
        throw error;
      });
    await entered;
    expect(holderFailed).toBe(false);
    let commitTimer: ReturnType<typeof setTimeout> | undefined;
    let foreignCommitPromise: Promise<unknown> = Promise.resolve();
    try {
      await logging.$queryRaw`SELECT 1`;
      queries.length = 0;
      const foreign = await port.inspectComponent({
        organizationId: attacker.id,
        componentOccurrenceId: occurrenceId,
      });
      const foreignReads = await settledOccurrenceReads(queries, 1);
      queries.length = 0;
      const absent = await port.inspectComponent({
        organizationId: attacker.id,
        componentOccurrenceId: absentOccurrenceId,
      });
      const absentReads = await settledOccurrenceReads(queries, 1);
      expect(foreign).toEqual({ kind: 'not_found' });
      expect(absent).toEqual(foreign);
      expect(foreignReads).toEqual(absentReads);
      expect(foreignReads).toHaveLength(1);
      expect(foreignReads.every(scopedByOrganization)).toBe(true);
      expect(foreignReads.join('\n')).not.toContain(occurrenceId);
      expect(foreignReads.join('\n')).not.toContain(attacker.id);

      const parsedForeign = parseProductMatchEvaluationCommand({
        ...seeded.evaluationCommand,
        organizationId: attacker.id,
        correlationId: randomUUID(),
      });
      const parsedAbsent = parseProductMatchEvaluationCommand({
        ...seeded.evaluationCommand,
        organizationId: attacker.id,
        componentOccurrenceId: absentOccurrenceId,
        correlationId: randomUUID(),
      });
      expect(parsedForeign.accepted).toBe(true);
      expect(parsedAbsent.accepted).toBe(true);
      if (!parsedForeign.accepted || !parsedAbsent.accepted) {
        return;
      }
      queries.length = 0;
      foreignCommitPromise = port.commit({ command: parsedForeign.command });
      const foreignCommit = await Promise.race([
        foreignCommitPromise,
        new Promise<never>((_resolve, reject) => {
          commitTimer = setTimeout(() => {
            reject(new Error('foreign commit waited on the owner lock'));
          }, 5_000);
        }),
      ]);
      const foreignCommitReads = await settledOccurrenceReads(queries, 1);
      queries.length = 0;
      const absentCommit = await port.commit({ command: parsedAbsent.command });
      const absentCommitReads = await settledOccurrenceReads(queries, 1);
      expect(foreignCommit).toEqual(closedRejection());
      expect(absentCommit).toEqual(foreignCommit);
      expect(foreignCommitReads).toEqual(absentCommitReads);
      expect(foreignCommitReads.every(scopedByOrganization)).toBe(true);
      expect(JSON.stringify(foreignCommit)).not.toContain(occurrenceId);
      expect(JSON.stringify(foreignCommit)).not.toContain(seeded.organizationId);
      expect(JSON.stringify(foreignCommit)).not.toContain(attacker.id);
    } finally {
      if (commitTimer !== undefined) {
        clearTimeout(commitTimer);
      }
      release?.();
      await holder.catch(() => undefined);
      await foreignCommitPromise.catch(() => undefined);
      await logging.$disconnect();
    }

    const current = await prisma.componentOccurrence.findFirstOrThrow({
      where: { id: occurrenceId, organizationId: seeded.organizationId },
    });
    const deletedId = randomUUID();
    await prisma.componentOccurrence.create({
      data: {
        id: deletedId,
        organizationId: current.organizationId,
        assetId: current.assetId,
        sbomId: current.sbomId,
        sbomIngestionId: current.sbomIngestionId,
        componentId: current.componentId,
        bomRef: `deleted-${deletedId.slice(0, 8)}`,
        version: '9.9.9',
        versionKnown: true,
        isDirect: false,
      },
    });
    await prisma.componentOccurrence.delete({ where: { id: deletedId } });
    const ownerPort = createProductMatchEvaluationPersistence(prisma);
    const deletedForOwner = await ownerPort.inspectComponent({
      organizationId: seeded.organizationId,
      componentOccurrenceId: deletedId,
    });
    const deletedForAttacker = await ownerPort.inspectComponent({
      organizationId: attacker.id,
      componentOccurrenceId: deletedId,
    });
    const neverCreated = await ownerPort.inspectComponent({
      organizationId: attacker.id,
      componentOccurrenceId: randomUUID(),
    });
    expect(deletedForOwner).toEqual({ kind: 'not_found' });
    expect(deletedForAttacker).toEqual(deletedForOwner);
    expect(neverCreated).toEqual(deletedForOwner);
    const authorized = await ownerPort.inspectComponent({
      organizationId: seeded.organizationId,
      componentOccurrenceId: occurrenceId,
    });
    expect(authorized.kind).toBe('found');
  });

  it('keeps separate evidence for many occurrences, revisions, and assets', async () => {
    const findingsBefore = await prisma.finding.count();
    const seeded = await seedLegal('cardinality');
    const composition = service();
    const first = await composition.execute(seeded.evaluationCommand);
    expect(first.kind).toBe('recorded');
    if (first.kind !== 'recorded') {
      return;
    }
    const stored = await prisma.productMatchEvaluationEvidence.findFirstOrThrow({
      where: { id: first.projection.matchEvidenceId, organizationId: seeded.organizationId },
      select: { createdAt: true, outcome: true, advisoryRevisionId: true, assetId: true },
    });
    const explanationsBefore = await prisma.productMatchEvaluationExplanation.count({
      where: { productMatchEvaluationEvidenceId: first.projection.matchEvidenceId },
    });
    expect(explanationsBefore).toBeGreaterThan(0);

    const secondAsset = await createAsset(
      prisma,
      seeded.organizationId,
      `asset-two-${randomUUID()}`,
    );
    const secondCommand = await occurrenceOnAsset(
      seeded,
      'second-asset',
      secondAsset.id,
      'component-2',
    );
    const second = await composition.execute(secondCommand);
    expect(second.kind).toBe('recorded');
    if (second.kind !== 'recorded') {
      return;
    }
    expect(second.projection.matchEvidenceId).not.toBe(first.projection.matchEvidenceId);
    expect(second.providerCalls).toBe(0);
    expect(second.findingWrites).toBe(0);
    const secondRow = await prisma.productMatchEvaluationEvidence.findFirstOrThrow({
      where: { id: second.projection.matchEvidenceId, organizationId: seeded.organizationId },
      select: { assetId: true, advisoryRevisionId: true, componentOccurrenceId: true },
    });
    expect(secondRow.assetId).toBe(secondAsset.id);
    expect(secondRow.assetId).not.toBe(stored.assetId);
    expect(secondRow.advisoryRevisionId).toBe(stored.advisoryRevisionId);
    expect(secondRow.componentOccurrenceId).not.toBe(
      seeded.evaluationCommand.componentOccurrenceId,
    );

    const sameAssetCommand = await occurrenceOnAsset(
      seeded,
      'same-asset',
      seeded.assetId,
      'component-3',
    );
    const third = await composition.execute(sameAssetCommand);
    expect(third.kind).toBe('recorded');

    const successor = await approveSuccessor(seeded);
    const historicalReplay = await composition.execute({
      ...seeded.evaluationCommand,
      correlationId: randomUUID(),
    });
    expect(historicalReplay.kind).toBe('already_applied');
    if (historicalReplay.kind === 'already_applied') {
      expect(historicalReplay.evaluatorCalls).toBe(0);
      expect(historicalReplay.inserts).toBe(0);
      expect(historicalReplay.projection.createdAt).toBe(stored.createdAt.toISOString());
    }
    const supersededAttempt = await composition.execute(successor.evaluationCommand);
    expect(
      supersededAttempt.kind === 'rejected' ? supersededAttempt.code : supersededAttempt.kind,
    ).toBe('recorded');
    if (supersededAttempt.kind !== 'recorded') {
      return;
    }
    const afterSuccessor = await prisma.productMatchEvaluationEvidence.findFirstOrThrow({
      where: { id: first.projection.matchEvidenceId, organizationId: seeded.organizationId },
      select: { createdAt: true, outcome: true, advisoryRevisionId: true },
    });
    expect(afterSuccessor.createdAt.toISOString()).toBe(stored.createdAt.toISOString());
    expect(afterSuccessor.outcome).toBe(stored.outcome);
    expect(afterSuccessor.advisoryRevisionId).toBe(stored.advisoryRevisionId);
    expect(
      await prisma.productMatchEvaluationExplanation.count({
        where: { productMatchEvaluationEvidenceId: first.projection.matchEvidenceId },
      }),
    ).toBe(explanationsBefore);
    await expect(
      prisma.productMatchEvaluationEvidence.update({
        where: { id: first.projection.matchEvidenceId },
        data: { outcome: 'unknown' },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.productMatchEvaluationEvidence.delete({
        where: { id: first.projection.matchEvidenceId },
      }),
    ).rejects.toThrow();

    const fresh = await occurrenceOnAsset(seeded, 'after-successor', seeded.assetId, 'component-4');
    const rejectedHistorical = await composition.execute({
      ...fresh,
      advisoryRevisionId: seeded.revisionId,
      approvalEvidenceId: seeded.approvalId,
      expectedContentFingerprint: seeded.contentFingerprint,
      correlationId: randomUUID(),
    });
    expect(rejectedHistorical.kind).toBe('rejected');
    if (rejectedHistorical.kind === 'rejected') {
      expect(rejectedHistorical.code).toBe('superseded_revision');
      expect(rejectedHistorical.inserts).toBe(0);
    }

    const applicability = await createProductMatchEvaluationPersistence(
      prisma,
    ).readCurrentApplicability({
      organizationId: seeded.organizationId,
      componentOccurrenceId: seeded.evaluationCommand.componentOccurrenceId,
      advisoryFamilyId: seeded.familyId,
      vulnerabilityId: seeded.vulnerabilityId,
      evaluatorId: seeded.evaluationCommand.evaluatorId,
      evaluatorVersion: seeded.evaluationCommand.evaluatorVersion,
      matchingPolicyId: seeded.evaluationCommand.matchingPolicyId,
      matchingPolicyVersion: seeded.evaluationCommand.matchingPolicyVersion,
      productEvidencePolicyId: seeded.evaluationCommand.productEvidencePolicyId,
      productEvidencePolicyVersion: String(seeded.evaluationCommand.productEvidencePolicyVersion),
    });
    expect(applicability.kind).toBe('classified');
    if (applicability.kind === 'classified') {
      expect(applicability.currentEvidenceId).toBe(supersededAttempt.projection.matchEvidenceId);
      expect(applicability.historicalEvidenceIds).toEqual([first.projection.matchEvidenceId]);
    }
    const foreignApplicability = await createProductMatchEvaluationPersistence(
      prisma,
    ).readCurrentApplicability({
      organizationId: (await createOrg(prisma, `foreign-app-${randomUUID().slice(0, 8)}`)).id,
      componentOccurrenceId: seeded.evaluationCommand.componentOccurrenceId,
      advisoryFamilyId: seeded.familyId,
      vulnerabilityId: seeded.vulnerabilityId,
      evaluatorId: seeded.evaluationCommand.evaluatorId,
      evaluatorVersion: seeded.evaluationCommand.evaluatorVersion,
      matchingPolicyId: seeded.evaluationCommand.matchingPolicyId,
      matchingPolicyVersion: seeded.evaluationCommand.matchingPolicyVersion,
      productEvidencePolicyId: seeded.evaluationCommand.productEvidencePolicyId,
      productEvidencePolicyVersion: String(seeded.evaluationCommand.productEvidencePolicyVersion),
    });
    const absentApplicability = await createProductMatchEvaluationPersistence(
      prisma,
    ).readCurrentApplicability({
      organizationId: seeded.organizationId,
      componentOccurrenceId: randomUUID(),
      advisoryFamilyId: seeded.familyId,
      vulnerabilityId: seeded.vulnerabilityId,
      evaluatorId: seeded.evaluationCommand.evaluatorId,
      evaluatorVersion: seeded.evaluationCommand.evaluatorVersion,
      matchingPolicyId: seeded.evaluationCommand.matchingPolicyId,
      matchingPolicyVersion: seeded.evaluationCommand.matchingPolicyVersion,
      productEvidencePolicyId: seeded.evaluationCommand.productEvidencePolicyId,
      productEvidencePolicyVersion: String(seeded.evaluationCommand.productEvidencePolicyVersion),
    });
    expect(foreignApplicability).toEqual({
      kind: 'classified',
      currentEvidenceId: null,
      historicalEvidenceIds: [],
    });
    expect(absentApplicability).toEqual(foreignApplicability);
    expect(await prisma.finding.count()).toBe(findingsBefore);
    expect(third.kind).toBe('recorded');
  });

  it('scopes replay uniqueness to the organization', async () => {
    const indexes = await prisma.$queryRaw<Array<{ index_name: string; index_def: string }>>`
      SELECT i.relname AS index_name, pg_get_indexdef(ix.indexrelid) AS index_def
      FROM pg_index ix
      JOIN pg_class i ON i.oid = ix.indexrelid
      JOIN pg_class t ON t.oid = ix.indrelid
      WHERE t.relname = 'product_match_evaluation_evidence'
    `;
    const names = indexes.map((index) => index.index_name);
    expect(names).not.toContain('product_match_evaluation_evidence_occurrence_uidx');
    expect(names).not.toContain('product_match_evaluation_evidence_revision_uidx');
    expect(names).not.toContain('product_match_evaluation_evidence_replay_uidx');
    expect(names).toContain('product_match_evaluation_evidence_occurrence_idx');
    expect(names).toContain('product_match_evaluation_evidence_revision_idx');
    const replay = indexes.find(
      (index) => index.index_name === 'product_match_evaluation_evidence_org_replay_uidx',
    );
    const evaluation = indexes.find(
      (index) => index.index_name === 'product_match_evaluation_evidence_evaluation_uidx',
    );
    expect(replay?.index_def).toContain('UNIQUE');
    expect(replay?.index_def).toContain('organization_id');
    expect(replay?.index_def).toContain('replay_fingerprint');
    expect(evaluation?.index_def).toContain('component_occurrence_id');
    expect(evaluation?.index_def).toContain('advisory_revision_id');
    expect(evaluation?.index_def).toContain('approval_id');
    expect(evaluation?.index_def).toContain('evaluator_id');
    expect(evaluation?.index_def).toContain('evaluator_version');
    expect(evaluation?.index_def).toContain('matching_policy_id');
    expect(evaluation?.index_def).toContain('matching_policy_version');
    expect(evaluation?.index_def).toContain('product_evidence_policy_id');
    expect(evaluation?.index_def).toContain('product_evidence_policy_version');

    const owner = await seedLegal('replay-owner');
    const other = await seedLegal('replay-other');
    const composition = service();
    const owned = await composition.execute(owner.evaluationCommand);
    const foreign = await composition.execute(other.evaluationCommand);
    expect(owned.kind).toBe('recorded');
    expect(foreign.kind).toBe('recorded');
    if (owned.kind !== 'recorded' || foreign.kind !== 'recorded') {
      return;
    }
    const ownedRow = await prisma.productMatchEvaluationEvidence.findFirstOrThrow({
      where: { id: owned.projection.matchEvidenceId },
    });
    const otherOccurrence = await occurrenceOnAsset(
      other,
      'replay-probe',
      other.assetId,
      'component-probe',
    );
    const before = await prisma.productMatchEvaluationEvidence.count();
    const findingsBefore = await prisma.finding.count();
    const sameOrganization = await probeReplayFingerprint(prisma, {
      sourceEvidenceId: owned.projection.matchEvidenceId,
      organizationId: owner.organizationId,
      componentOccurrenceId: (
        await occurrenceOnAsset(owner, 'replay-owner-probe', owner.assetId, 'component-probe')
      ).componentOccurrenceId,
      assetId: owner.assetId,
      replayFingerprint: ownedRow.replayFingerprint,
    });
    expect(sameOrganization).toBe('unique_violation');
    const otherOccurrenceRow = await prisma.componentOccurrence.findFirstOrThrow({
      where: { id: otherOccurrence.componentOccurrenceId, organizationId: other.organizationId },
    });
    const crossOrganization = await probeReplayFingerprint(prisma, {
      sourceEvidenceId: owned.projection.matchEvidenceId,
      organizationId: other.organizationId,
      componentOccurrenceId: otherOccurrenceRow.id,
      assetId: otherOccurrenceRow.assetId,
      sbomId: otherOccurrenceRow.sbomId,
      sbomIngestionId: otherOccurrenceRow.sbomIngestionId,
      componentId: otherOccurrenceRow.componentId,
      replayFingerprint: ownedRow.replayFingerprint,
    });
    expect(crossOrganization).toBe('rolled_back');
    expect(await prisma.productMatchEvaluationEvidence.count()).toBe(before);
    expect(await prisma.finding.count()).toBe(findingsBefore);
  });
});

function assertProbeUuid(value: string): string {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value)) {
    throw new Error('probe identity was not a uuid');
  }
  return value;
}

async function probeReplayFingerprint(
  client: PrismaClient,
  input: {
    readonly sourceEvidenceId: string;
    readonly organizationId: string;
    readonly componentOccurrenceId: string;
    readonly assetId: string;
    readonly sbomId?: string;
    readonly sbomIngestionId?: string;
    readonly componentId?: string;
    readonly replayFingerprint: string;
  },
): Promise<'unique_violation' | 'rolled_back'> {
  const sourceEvidenceId = assertProbeUuid(input.sourceEvidenceId);
  const organizationId = assertProbeUuid(input.organizationId);
  const componentOccurrenceId = assertProbeUuid(input.componentOccurrenceId);
  const assetId = assertProbeUuid(input.assetId);
  if (!/^[a-f0-9]{64}$/.test(input.replayFingerprint)) {
    throw new Error('probe fingerprint was not a digest');
  }
  const occurrence = await client.componentOccurrence.findFirstOrThrow({
    where: { id: componentOccurrenceId, organizationId },
  });
  const sbomId = assertProbeUuid(input.sbomId ?? occurrence.sbomId);
  const sbomIngestionId = assertProbeUuid(input.sbomIngestionId ?? occurrence.sbomIngestionId);
  const componentId = assertProbeUuid(input.componentId ?? occurrence.componentId);
  const sql = `
    DO $probe$
    DECLARE
      new_id uuid := '${randomUUID()}';
    BEGIN
      INSERT INTO "product_match_evaluation_evidence" (
        "id", "organization_id", "component_occurrence_id", "asset_id", "sbom_id",
        "sbom_ingestion_id", "component_id", "sbom_sha256", "component_identity_key",
        "component_evidence_fingerprint", "evidence_schema_version", "package_identity_key",
        "raw_observed_version", "raw_observed_version_sha256", "advisory_family_id",
        "advisory_revision_id", "approval_id", "content_fingerprint", "range_fingerprint",
        "vulnerability_id", "evaluator_id", "evaluator_version", "matching_policy_id",
        "matching_policy_version", "product_evidence_policy_id", "product_evidence_policy_version",
        "outcome", "product_origin", "replay_fingerprint", "finding_creation", "suppression_authority"
      )
      SELECT
        new_id, '${organizationId}'::uuid, '${componentOccurrenceId}'::uuid, '${assetId}'::uuid,
        '${sbomId}'::uuid, '${sbomIngestionId}'::uuid, '${componentId}'::uuid,
        "sbom_sha256", "component_identity_key", "component_evidence_fingerprint",
        "evidence_schema_version", "package_identity_key", "raw_observed_version",
        "raw_observed_version_sha256", "advisory_family_id", "advisory_revision_id", "approval_id",
        "content_fingerprint", "range_fingerprint", "vulnerability_id", "evaluator_id",
        "evaluator_version", "matching_policy_id", "matching_policy_version",
        "product_evidence_policy_id", "product_evidence_policy_version", "outcome",
        "product_origin", '${input.replayFingerprint}', "finding_creation", "suppression_authority"
      FROM "product_match_evaluation_evidence"
      WHERE "id" = '${sourceEvidenceId}'::uuid;
      IF NOT FOUND THEN
        RAISE EXCEPTION 'cardinality_probe_missing';
      END IF;
      INSERT INTO "product_match_evaluation_explanation" (
        "id", "organization_id", "product_match_evaluation_evidence_id", "ordinal", "explanation_code"
      )
      SELECT gen_random_uuid(), '${organizationId}'::uuid, new_id, "ordinal", "explanation_code"
      FROM "product_match_evaluation_explanation"
      WHERE "product_match_evaluation_evidence_id" = '${sourceEvidenceId}'::uuid;
      RAISE EXCEPTION 'cardinality_probe_rollback';
    END
    $probe$;
  `;
  try {
    await client.$executeRawUnsafe(sql);
    throw new Error('probe insert committed');
  } catch (error) {
    const message = error instanceof Error ? error.message : '';
    if (message.includes('cardinality_probe_rollback')) {
      return 'rolled_back';
    }
    if (message.includes('23505') || message.toLowerCase().includes('unique')) {
      return 'unique_violation';
    }
    throw error;
  }
}
