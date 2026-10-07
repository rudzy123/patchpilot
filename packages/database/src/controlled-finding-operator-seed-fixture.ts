/**
 * Disposable evidence seed for controlled Finding operator tests.
 * The evaluator runs only while preparing Product Match Evidence.
 * This fixture does not create a Finding and is not a production constructor.
 */

import { createHash, randomUUID } from 'node:crypto';

import type { PrismaClient } from '@prisma/client';
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
  maintainerReviewedApprovalReplayFingerprint,
  session14RangeFingerprint,
} from '@patchpilot/vulnerability-intelligence';

import { createProductMatchEvaluationPersistence } from './product-match-evaluation-persistence.js';
import { createApprovalCapabilityHarness } from './reviewer-capability-approval-harness.js';
import {
  createAsset,
  createProcessingIngestion,
  createSbom,
  resolvedComponent,
} from './sbom-test-fixture.js';

const PACKAGE_NAME = 'reviewed-npm-widget';
const RANGES = [
  {
    type: 'SEMVER' as const,
    events: [
      { name: 'introduced' as const, value: '1.0.0' },
      { name: 'fixed' as const, value: '2.0.0' },
    ],
  },
];

export type ControlledFindingSeedEvidence = {
  readonly evidenceId: string;
  readonly outcome: string;
  readonly version: string;
};

export type ControlledFindingSeedTarget = {
  readonly assetId: string;
  readonly componentId: string;
  readonly vulnerabilityId: string;
  readonly ingestionId: string;
  readonly evidence: readonly ControlledFindingSeedEvidence[];
};

export async function seedControlledFindingEvidence(
  prisma: PrismaClient,
  input: {
    readonly label: string;
    readonly organizationId: string;
    readonly versions: readonly { readonly version: string; readonly bomRef: string }[];
  },
): Promise<ControlledFindingSeedTarget> {
  if (input.versions.length === 0) {
    throw new Error('controlled finding seed requires a version');
  }
  const rangeFingerprint = session14RangeFingerprint(RANGES, []);
  const contentFingerprint = digest(`content:${input.label}:${randomUUID()}`);
  const advisoryId = `REVIEWNPM${digest(input.label).slice(0, 8).toUpperCase()}`;
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
  });
  const approval = await createApprovalCapabilityHarness(prisma).approve({
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
    approvalReplayFingerprint: maintainerReviewedApprovalReplayFingerprint({
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
    }),
  });
  if (approval.kind !== 'recorded') {
    throw new Error(`approval was ${approval.kind}`);
  }
  const asset = await createAsset(prisma, input.organizationId, `asset-${input.label}`);
  const sbomSha = digest(`sbom:${input.label}:${randomUUID()}`);
  const sbom = await createSbom(prisma, {
    organizationId: input.organizationId,
    assetId: asset.id,
    sha256: sbomSha,
    receivedAt: new Date('2026-10-02T12:00:00.000Z'),
  });
  const ingestion = await createProcessingIngestion(prisma, {
    organizationId: input.organizationId,
    sbomId: sbom.id,
    assetId: asset.id,
  });
  const first = input.versions[0];
  if (first === undefined) {
    throw new Error('controlled finding seed requires a version');
  }
  const componentInput = resolvedComponent({
    name: PACKAGE_NAME,
    bomRef: first.bomRef,
    version: first.version,
  });
  const component = await prisma.component.create({
    data: {
      organizationId: input.organizationId,
      identityKey: componentInput.identityKey,
      purl: componentInput.versionlessPurl,
      ecosystem: 'npm',
      namespace: null,
      name: PACKAGE_NAME,
      identityState: 'resolved',
    },
  });
  const evidence: ControlledFindingSeedEvidence[] = [];
  const composition = createProductMatchEvaluationComposition({
    port: createProductMatchEvaluationPersistence(prisma),
  });
  for (const version of input.versions) {
    const occurrence = await prisma.componentOccurrence.create({
      data: {
        organizationId: input.organizationId,
        assetId: asset.id,
        sbomId: sbom.id,
        sbomIngestionId: ingestion.id,
        componentId: component.id,
        bomRef: version.bomRef,
        version: version.version,
        versionKnown: true,
        isDirect: true,
      },
    });
    const executed = await composition.execute({
      commandSchemaVersion: PRODUCT_MATCH_EVALUATION_COMMAND_SCHEMA_VERSION,
      organizationId: input.organizationId,
      componentOccurrenceId: occurrence.id,
      expectedComponentEvidenceFingerprint: componentEvidenceFingerprint({
        organizationId: input.organizationId,
        componentOccurrenceId: occurrence.id,
        assetId: asset.id,
        sbomId: sbom.id,
        sbomIngestionId: ingestion.id,
        componentId: component.id,
        componentIdentityKey: component.identityKey,
        ecosystem: 'npm',
        namespace: null,
        name: PACKAGE_NAME,
        rawObservedVersion: version.version,
        versionKnown: true,
        sbomSha256: sbomSha,
      }),
      expectedNpmPackageIdentity: packageIdentity(),
      expectedRawObservedVersion: version.version,
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
    });
    if (executed.kind !== 'recorded') {
      throw new Error(`evaluation was ${executed.kind}`);
    }
    evidence.push({
      evidenceId: executed.projection.matchEvidenceId,
      outcome: executed.projection.outcome,
      version: version.version,
    });
  }
  await prisma.sbomIngestion.update({
    where: { id: ingestion.id },
    data: {
      state: 'completed',
      normalizationVersion: '2',
      completedAt: new Date('2026-10-02T13:00:00.000Z'),
      graphCompleteness: 'no_dependencies',
      componentCount: input.versions.length,
      dependencyEdgeCount: 0,
      warningCount: 0,
      stage: null,
    },
  });
  await prisma.asset.update({
    where: { id: asset.id },
    data: { lastSuccessfulSbomIngestionId: ingestion.id },
  });
  return {
    assetId: asset.id,
    componentId: component.id,
    vulnerabilityId: vulnerability.id,
    ingestionId: ingestion.id,
    evidence,
  };
}

function digest(label: string): string {
  return createHash('sha256').update(label).digest('hex');
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
