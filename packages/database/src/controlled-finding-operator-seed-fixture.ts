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

const DEFAULT_PACKAGE_NAME = 'reviewed-npm-widget';
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
  readonly componentIdentityKey: string;
  readonly packageName: string;
  readonly vulnerabilityId: string;
  readonly revisionId: string;
  readonly approvalId: string;
  readonly contentFingerprint: string;
  readonly rangeFingerprint: string;
  readonly ingestionId: string;
  readonly sbomId: string;
  readonly sbomSha256: string;
  readonly evidence: readonly ControlledFindingSeedEvidence[];
};

export type LaterControlledFindingIngestion = {
  readonly ingestionId: string;
  readonly sbomId: string;
  readonly graphCompleteness: 'empty' | 'no_dependencies' | 'partial' | 'complete';
  readonly componentCount: number;
  readonly dependencyEdgeCount: number;
  readonly occurrenceCardinality: number;
  readonly evidence: readonly {
    readonly evidenceId: string;
    readonly outcome: string;
    readonly occurrenceId: string;
    readonly version: string;
  }[];
  readonly unknownVersionOccurrenceIds: readonly string[];
};

export async function seedControlledFindingEvidence(
  prisma: PrismaClient,
  input: {
    readonly label: string;
    readonly organizationId: string;
    readonly versions: readonly { readonly version: string; readonly bomRef: string }[];
    readonly packageName?: string;
    readonly attach?: {
      readonly assetId: string;
      readonly sbomId: string;
      readonly ingestionId: string;
      readonly sbomSha256: string;
    };
  },
): Promise<ControlledFindingSeedTarget> {
  if (input.versions.length === 0) {
    throw new Error('controlled finding seed requires a version');
  }
  const packageName = input.packageName ?? DEFAULT_PACKAGE_NAME;
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
      packageName,
      packageIdentityKey: packageIdentity(packageName),
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
    expectedNpmPackageIdentity: packageIdentity(packageName),
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
      packageIdentityKey: packageIdentity(packageName),
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
  const asset =
    input.attach === undefined
      ? await createAsset(prisma, input.organizationId, `asset-${input.label}`)
      : { id: input.attach.assetId };
  const sbomSha = input.attach?.sbomSha256 ?? digest(`sbom:${input.label}:${randomUUID()}`);
  const sbom =
    input.attach === undefined
      ? await createSbom(prisma, {
          organizationId: input.organizationId,
          assetId: asset.id,
          sha256: sbomSha,
          receivedAt: new Date('2026-10-02T12:00:00.000Z'),
        })
      : { id: input.attach.sbomId };
  const ingestion =
    input.attach === undefined
      ? await createProcessingIngestion(prisma, {
          organizationId: input.organizationId,
          sbomId: sbom.id,
          assetId: asset.id,
        })
      : { id: input.attach.ingestionId };
  const first = input.versions[0];
  if (first === undefined) {
    throw new Error('controlled finding seed requires a version');
  }
  const componentInput = resolvedComponent({
    name: packageName,
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
      name: packageName,
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
        name: packageName,
        rawObservedVersion: version.version,
        versionKnown: true,
        sbomSha256: sbomSha,
      }),
      expectedNpmPackageIdentity: packageIdentity(packageName),
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
  if (input.attach === undefined) {
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
  }
  await prisma.asset.update({
    where: { id: asset.id },
    data: { lastSuccessfulSbomIngestionId: ingestion.id },
  });
  return {
    assetId: asset.id,
    componentId: component.id,
    componentIdentityKey: component.identityKey,
    packageName,
    vulnerabilityId: vulnerability.id,
    revisionId: revision.id,
    approvalId: approval.projection.approvalId,
    contentFingerprint,
    rangeFingerprint,
    ingestionId: ingestion.id,
    sbomId: sbom.id,
    sbomSha256: sbomSha,
    evidence,
  };
}

export async function seedLaterControlledFindingIngestion(
  prisma: PrismaClient,
  input: {
    readonly label: string;
    readonly organizationId: string;
    readonly target: ControlledFindingSeedTarget;
    readonly receivedAt: Date;
    readonly versions?: readonly { readonly version: string; readonly bomRef: string }[];
    readonly unknownVersions?: readonly { readonly version: string; readonly bomRef: string }[];
    readonly otherComponent?: {
      readonly name: string;
      readonly version: string;
      readonly bomRef: string;
    };
    readonly state?:
      | 'accepted'
      | 'queued'
      | 'processing'
      | 'completed'
      | 'rejected'
      | 'quarantined'
      | 'failed'
      | 'duplicate';
    readonly normalizationVersion?: '1' | '2';
    readonly graphCompleteness?: 'empty' | 'no_dependencies' | 'partial' | 'complete';
    readonly componentCount?: number;
    readonly dependencyEdgeCount?: number;
    readonly moveLatestPointer?: boolean;
  },
): Promise<LaterControlledFindingIngestion> {
  const versions = input.versions ?? [];
  const unknownVersions = input.unknownVersions ?? [];
  const sbomSha = digest(`later-sbom:${input.label}:${randomUUID()}`);
  const sbom = await createSbom(prisma, {
    organizationId: input.organizationId,
    assetId: input.target.assetId,
    sha256: sbomSha,
    receivedAt: input.receivedAt,
  });
  const ingestion = await createProcessingIngestion(prisma, {
    organizationId: input.organizationId,
    sbomId: sbom.id,
    assetId: input.target.assetId,
  });
  const evidence: LaterControlledFindingIngestion['evidence'][number][] = [];
  const unknownVersionOccurrenceIds: string[] = [];
  const composition = createProductMatchEvaluationComposition({
    port: createProductMatchEvaluationPersistence(prisma),
  });
  for (const version of versions) {
    const occurrence = await prisma.componentOccurrence.create({
      data: {
        organizationId: input.organizationId,
        assetId: input.target.assetId,
        sbomId: sbom.id,
        sbomIngestionId: ingestion.id,
        componentId: input.target.componentId,
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
        assetId: input.target.assetId,
        sbomId: sbom.id,
        sbomIngestionId: ingestion.id,
        componentId: input.target.componentId,
        componentIdentityKey: input.target.componentIdentityKey,
        ecosystem: 'npm',
        namespace: null,
        name: input.target.packageName,
        rawObservedVersion: version.version,
        versionKnown: true,
        sbomSha256: sbomSha,
      }),
      expectedNpmPackageIdentity: packageIdentity(input.target.packageName),
      expectedRawObservedVersion: version.version,
      advisoryRevisionId: input.target.revisionId,
      approvalEvidenceId: input.target.approvalId,
      expectedContentFingerprint: input.target.contentFingerprint,
      expectedRangeFingerprint: input.target.rangeFingerprint,
      expectedVulnerabilityId: input.target.vulnerabilityId,
      evaluatorId: PRODUCT_MATCH_EVALUATOR_ID,
      evaluatorVersion: PRODUCT_MATCH_EVALUATOR_VERSION,
      matchingPolicyId: PRODUCT_MATCH_MATCHING_POLICY_ID,
      matchingPolicyVersion: PRODUCT_MATCH_MATCHING_POLICY_VERSION,
      productEvidencePolicyId: PRODUCT_MATCH_EVALUATION_POLICY_ID,
      productEvidencePolicyVersion: PRODUCT_MATCH_EVALUATION_POLICY_VERSION,
      correlationId: randomUUID(),
    });
    if (executed.kind !== 'recorded') {
      throw new Error(`later evaluation was ${executed.kind}`);
    }
    evidence.push({
      evidenceId: executed.projection.matchEvidenceId,
      outcome: executed.projection.outcome,
      occurrenceId: occurrence.id,
      version: version.version,
    });
  }
  for (const version of unknownVersions) {
    const occurrence = await prisma.componentOccurrence.create({
      data: {
        organizationId: input.organizationId,
        assetId: input.target.assetId,
        sbomId: sbom.id,
        sbomIngestionId: ingestion.id,
        componentId: input.target.componentId,
        bomRef: version.bomRef,
        version: '',
        versionKnown: false,
        isDirect: false,
      },
    });
    unknownVersionOccurrenceIds.push(occurrence.id);
  }
  if (input.otherComponent !== undefined) {
    const other = resolvedComponent({
      name: input.otherComponent.name,
      bomRef: input.otherComponent.bomRef,
      version: input.otherComponent.version,
    });
    const component = await prisma.component.create({
      data: {
        organizationId: input.organizationId,
        identityKey: other.identityKey,
        purl: other.versionlessPurl,
        ecosystem: 'npm',
        namespace: null,
        name: input.otherComponent.name,
        identityState: 'resolved',
      },
    });
    await prisma.componentOccurrence.create({
      data: {
        organizationId: input.organizationId,
        assetId: input.target.assetId,
        sbomId: sbom.id,
        sbomIngestionId: ingestion.id,
        componentId: component.id,
        bomRef: input.otherComponent.bomRef,
        version: input.otherComponent.version,
        versionKnown: true,
        isDirect: true,
      },
    });
  }
  const occurrenceCardinality =
    versions.length + unknownVersions.length + (input.otherComponent === undefined ? 0 : 1);
  const completed = input.state === undefined || input.state === 'completed';
  const graphCompleteness = input.graphCompleteness ?? 'no_dependencies';
  const componentCount = input.componentCount ?? occurrenceCardinality;
  const dependencyEdgeCount = input.dependencyEdgeCount ?? 0;
  await prisma.sbomIngestion.update({
    where: { id: ingestion.id },
    data: {
      state: input.state ?? 'completed',
      normalizationVersion: input.normalizationVersion ?? '2',
      completedAt: completed ? input.receivedAt : null,
      graphCompleteness: completed ? graphCompleteness : null,
      componentCount: completed ? componentCount : null,
      dependencyEdgeCount: completed ? dependencyEdgeCount : null,
      warningCount: completed ? 0 : null,
      stage: completed ? null : 'persist_graph',
    },
  });
  if (
    input.moveLatestPointer !== false &&
    (input.state === undefined || input.state === 'completed')
  ) {
    await prisma.asset.update({
      where: { id: input.target.assetId },
      data: { lastSuccessfulSbomIngestionId: ingestion.id },
    });
  }
  return {
    ingestionId: ingestion.id,
    sbomId: sbom.id,
    graphCompleteness,
    componentCount,
    dependencyEdgeCount,
    occurrenceCardinality,
    evidence,
    unknownVersionOccurrenceIds,
  };
}

function digest(label: string): string {
  return createHash('sha256').update(label).digest('hex');
}

function packageIdentity(packageName: string): string {
  const identity = classifyNpmPackageIdentityFromParts({
    ecosystem: SELECTED_FIRST_ECOSYSTEM,
    observedNamespace: null,
    observedName: packageName,
    observedIdentity: packageName,
  });
  if (identity.classification !== 'valid') {
    throw new Error('package identity was rejected');
  }
  return identity.identityKey;
}
