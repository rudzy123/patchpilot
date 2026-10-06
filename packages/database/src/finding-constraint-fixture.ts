import { createHash, randomUUID } from 'node:crypto';

import type { PrismaClient } from '@prisma/client';
import {
  FINDING_CREATION_AUTHORIZATION_SCHEMA_VERSION,
  FINDING_CREATION_COMMAND_SCHEMA_VERSION,
  FINDING_CREATION_POLICY_ID,
  FINDING_CREATION_POLICY_VERSION,
  FINDING_CREATION_PURPOSE,
  FINDING_CREATION_TRUSTED_CONTEXT_SCHEMA_VERSION,
} from '@patchpilot/domain';
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

import {
  issueFindingCreationAuthorization,
  openFindingCreationCommand,
} from '../../domain/dist/findings/controlled-creation/authorization.js';
import { createControlledFindingCreationPersistence } from './controlled-finding-creation-persistence.js';
import { createProductMatchEvaluationPersistence } from './product-match-evaluation-persistence.js';
import { createApprovalCapabilityHarness } from './reviewer-capability-approval-harness.js';
import { createProcessingIngestion, createSbom, resolvedComponent } from './sbom-test-fixture.js';

const PACKAGE_NAME = 'reviewed-npm-widget';
const AFFECTED_VERSION = '1.1.0';
const RANGES = [
  {
    type: 'SEMVER' as const,
    events: [
      { name: 'introduced' as const, value: '1.0.0' },
      { name: 'fixed' as const, value: '2.0.0' },
    ],
  },
];

/**
 * Legal open Finding for constraint tests that need a parent row.
 * The insert uses the controlled creation transaction, so the Finding,
 * creation observation, evidence link, and audit event commit together.
 * Production startup does not call this helper.
 */
export async function insertOpenFindingForConstraintTest(
  prisma: PrismaClient,
  input: {
    readonly organizationId: string;
    readonly assetId: string;
    readonly vulnerabilityId: string;
    readonly componentId: string;
  },
) {
  const label = `constraint-${randomUUID()}`;
  const rangeFingerprint = session14RangeFingerprint(RANGES, []);
  const contentFingerprint = digest(`content:${label}`);
  const advisoryId = `REVIEWNPM${digest(label).slice(0, 8).toUpperCase()}`;
  const familyDigest = digest(`family:${advisoryId}`);
  const revisionDigest = digest(`revision:${advisoryId}`);
  const authorIdentity = 'author.one';
  const packageKey = packageIdentity();
  const componentInput = resolvedComponent({
    name: PACKAGE_NAME,
    bomRef: 'component-1',
    version: AFFECTED_VERSION,
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
      packageIdentityKey: packageKey,
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
      vulnerabilityId: input.vulnerabilityId,
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
    expectedNpmPackageIdentity: packageKey,
    expectedVulnerabilityId: input.vulnerabilityId,
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
      packageIdentityKey: packageKey,
      vulnerabilityId: input.vulnerabilityId,
      sourceLicensePolicyId: MAINTAINER_REVIEWED_APPROVAL_PINS.licensePolicyId,
      sourceLicensePolicyVersion: MAINTAINER_REVIEWED_APPROVAL_PINS.licensePolicyVersion,
      approvedLicenseClassification: MAINTAINER_REVIEWED_APPROVAL_PINS.licenseClassification,
      licenseDecisionCanonical: MAINTAINER_REVIEWED_APPROVAL_PINS.licenseCanonical,
    }),
  });
  if (approval.kind !== 'recorded') {
    throw new Error(`constraint approval was ${approval.kind}`);
  }
  const user = await prisma.user.create({
    data: {
      email: `${label}@synthetic.patchpilot.test`,
      displayName: label,
    },
  });
  const membership = await prisma.membership.create({
    data: { organizationId: input.organizationId, userId: user.id, role: 'member' },
  });
  const component = await prisma.component.update({
    where: { id: input.componentId },
    data: {
      identityKey: componentInput.identityKey,
      purl: componentInput.versionlessPurl,
      ecosystem: 'npm',
      namespace: null,
      name: PACKAGE_NAME,
      identityState: 'resolved',
    },
  });
  const sbomSha = digest(`sbom:${label}`);
  const sbom = await createSbom(prisma, {
    organizationId: input.organizationId,
    assetId: input.assetId,
    sha256: sbomSha,
    receivedAt: new Date('2026-10-02T12:00:00.000Z'),
  });
  const ingestion = await createProcessingIngestion(prisma, {
    organizationId: input.organizationId,
    sbomId: sbom.id,
    assetId: input.assetId,
  });
  const occurrence = await prisma.componentOccurrence.create({
    data: {
      organizationId: input.organizationId,
      assetId: input.assetId,
      sbomId: sbom.id,
      sbomIngestionId: ingestion.id,
      componentId: component.id,
      bomRef: 'component-1',
      version: AFFECTED_VERSION,
      versionKnown: true,
      isDirect: true,
    },
  });
  const executed = await createProductMatchEvaluationComposition({
    port: createProductMatchEvaluationPersistence(prisma),
  }).execute({
    commandSchemaVersion: PRODUCT_MATCH_EVALUATION_COMMAND_SCHEMA_VERSION,
    organizationId: input.organizationId,
    componentOccurrenceId: occurrence.id,
    expectedComponentEvidenceFingerprint: componentEvidenceFingerprint({
      organizationId: input.organizationId,
      componentOccurrenceId: occurrence.id,
      assetId: input.assetId,
      sbomId: sbom.id,
      sbomIngestionId: ingestion.id,
      componentId: component.id,
      componentIdentityKey: component.identityKey,
      ecosystem: 'npm',
      namespace: null,
      name: PACKAGE_NAME,
      rawObservedVersion: AFFECTED_VERSION,
      versionKnown: true,
      sbomSha256: sbomSha,
    }),
    expectedNpmPackageIdentity: packageKey,
    expectedRawObservedVersion: AFFECTED_VERSION,
    advisoryRevisionId: revision.id,
    approvalEvidenceId: approval.projection.approvalId,
    expectedContentFingerprint: contentFingerprint,
    expectedRangeFingerprint: rangeFingerprint,
    expectedVulnerabilityId: input.vulnerabilityId,
    evaluatorId: PRODUCT_MATCH_EVALUATOR_ID,
    evaluatorVersion: PRODUCT_MATCH_EVALUATOR_VERSION,
    matchingPolicyId: PRODUCT_MATCH_MATCHING_POLICY_ID,
    matchingPolicyVersion: PRODUCT_MATCH_MATCHING_POLICY_VERSION,
    productEvidencePolicyId: PRODUCT_MATCH_EVALUATION_POLICY_ID,
    productEvidencePolicyVersion: PRODUCT_MATCH_EVALUATION_POLICY_VERSION,
    correlationId: randomUUID(),
  });
  if (executed.kind !== 'recorded' || executed.projection.outcome !== 'affected') {
    throw new Error(
      `constraint evaluation was ${executed.kind}${executed.kind === 'recorded' ? `:${executed.projection.outcome}` : ''}`,
    );
  }
  await prisma.sbomIngestion.update({
    where: { id: ingestion.id },
    data: {
      state: 'completed',
      normalizationVersion: '2',
      completedAt: new Date('2026-10-02T13:00:00.000Z'),
      graphCompleteness: 'no_dependencies',
      componentCount: 1,
      dependencyEdgeCount: 0,
      warningCount: 0,
      stage: null,
    },
  });
  await prisma.asset.update({
    where: { id: input.assetId },
    data: { lastSuccessfulSbomIngestionId: ingestion.id },
  });
  const evidenceId = executed.projection.matchEvidenceId;
  const correlationId = randomUUID();
  const trustedContext = {
    schemaVersion: FINDING_CREATION_TRUSTED_CONTEXT_SCHEMA_VERSION,
    organizationId: input.organizationId,
    actorId: user.id,
    membershipId: membership.id,
    membershipStatus: 'active' as const,
  };
  const issued = issueFindingCreationAuthorization({
    schemaVersion: FINDING_CREATION_AUTHORIZATION_SCHEMA_VERSION,
    trustedContext,
    purpose: FINDING_CREATION_PURPOSE,
    policyId: FINDING_CREATION_POLICY_ID,
    policyVersion: FINDING_CREATION_POLICY_VERSION,
    assetId: input.assetId,
    componentId: input.componentId,
    vulnerabilityId: input.vulnerabilityId,
    sbomIngestionId: ingestion.id,
    productMatchEvidenceIds: [evidenceId],
    correlationId,
  });
  if (issued.status !== 'authorized') {
    throw new Error(`constraint authorization was ${issued.status}`);
  }
  const opened = openFindingCreationCommand({
    schemaVersion: FINDING_CREATION_COMMAND_SCHEMA_VERSION,
    purpose: FINDING_CREATION_PURPOSE,
    policyId: FINDING_CREATION_POLICY_ID,
    policyVersion: FINDING_CREATION_POLICY_VERSION,
    expectedAssetId: input.assetId,
    expectedComponentId: input.componentId,
    expectedVulnerabilityId: input.vulnerabilityId,
    expectedSbomIngestionId: ingestion.id,
    expectedProductMatchEvidenceIds: [evidenceId],
    correlationId,
    authorization: issued.authorization,
  });
  if (opened.status !== 'authorized') {
    throw new Error(`constraint command was ${opened.status}`);
  }
  const created = await createControlledFindingCreationPersistence(prisma).apply({
    trustedContext,
    command: opened.command,
  });
  if (created.status !== 'created') {
    throw new Error(`constraint finding was ${created.status}`);
  }
  const finding = await prisma.finding.findFirstOrThrow({
    where: {
      organizationId: input.organizationId,
      assetId: input.assetId,
      componentId: input.componentId,
      vulnerabilityId: input.vulnerabilityId,
    },
  });
  const observation = await prisma.findingObservation.findFirstOrThrow({
    where: { organizationId: input.organizationId, findingId: finding.id },
  });
  return { finding, observation };
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

function digest(label: string): string {
  return createHash('sha256').update(label).digest('hex');
}
