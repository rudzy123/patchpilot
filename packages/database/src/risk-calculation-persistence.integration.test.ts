/**
 * Disposable PostgreSQL proof for uncomposed priority calculation.
 * Synthetic CVE-2099-* rows only. This file does not call cisa.gov or osv.dev.
 * The policy engine is the real package. This file does not reimplement scoring.
 */

import { createHash, randomUUID } from 'node:crypto';

import { PrismaClient } from '@prisma/client';
import {
  FINDING_CREATION_AUTHORIZATION_SCHEMA_VERSION,
  FINDING_CREATION_COMMAND_SCHEMA_VERSION,
  FINDING_CREATION_POLICY_ID,
  FINDING_CREATION_POLICY_VERSION,
  FINDING_CREATION_PURPOSE,
  FINDING_CREATION_TRUSTED_CONTEXT_SCHEMA_VERSION,
  createCalculateFindingRiskUseCase,
  createPublishOrganizationPriorityOverrideUseCase,
  createQueryActiveKevMembershipUseCase,
  createReadCurrentFindingRiskUseCase,
  type StoredRiskCalculation,
} from '@patchpilot/domain';
import {
  BUILTIN_PRIORITY_POLICY_DEFINITION,
  POLICY_ENGINE_VERSION,
  canonicalJson,
  evaluatePriority,
  parseFactInput,
  validatePolicyDefinition,
  validatePolicyOverride,
  type KevListedFact,
  type PriorityFactInput,
  type ValidatedPriorityPolicyDefinition,
} from '@patchpilot/policy-engine';
import { createFoundationTestEnv } from '@patchpilot/test-utils';
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
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  issueFindingCreationAuthorization,
  openFindingCreationCommand,
} from '../../domain/dist/findings/controlled-creation/authorization.js';
import { projectFindingInspection } from '../../domain/dist/findings/controlled-inspection/projection.js';
import { createActiveKevMembershipPersistence } from './active-kev-membership.js';
import { createControlledFindingCreationPersistence } from './controlled-finding-creation-persistence.js';
import {
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
} from './integration-database.js';
import {
  createFetchingSyncRun,
  createSnapshot,
  createStagingGeneration,
  failInflightSyncRuns,
  uniqueKevSha,
} from './intelligence-test-fixture.js';
import { createProductMatchEvaluationPersistence } from './product-match-evaluation-persistence.js';
import { createRiskCalculationApplicationPersistence } from './risk-calculation-application-persistence.js';
import { createRiskCalculationPersistence } from './risk-calculation-persistence.js';
import { createApprovalCapabilityHarness } from './reviewer-capability-approval-harness.js';
import {
  developmentSeedIds,
  ensurePublishedBuiltinPriorityPolicy,
  seedDevelopmentData,
} from './seed/development.js';
import {
  createAsset,
  createOrg,
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
const EMPTY_BUILTIN_V1 = {
  schemaVersion: 1,
  policyKey: 'patchpilot.builtin.v0',
  factorCatalog: [],
  weights: {},
};
const TIE_ID = 'ffffffff-ffff-8fff-bfff-ffffffffffff';
const SESSION_ID = 'risk-calculation-session';

type VersionRequest = {
  readonly version: string;
  readonly bomRef: string;
};

type SeededEvidence = {
  readonly evidenceId: string;
  readonly outcome: string;
  readonly occurrenceId: string;
  readonly version: string;
};

type SeededTarget = {
  readonly organizationId: string;
  readonly actorId: string;
  readonly membershipId: string;
  readonly assetId: string;
  readonly componentId: string;
  readonly vulnerabilityId: string;
  readonly sbomId: string;
  readonly ingestionId: string;
  readonly evidence: readonly SeededEvidence[];
};

type PreparedFinding = {
  readonly organizationId: string;
  readonly userId: string;
  readonly membershipId: string;
  readonly assetId: string;
  readonly findingId: string;
};

type ActorRole = 'owner' | 'admin' | 'member' | 'viewer';

let prisma: PrismaClient;
let database: Awaited<ReturnType<typeof createEphemeralDatabase>>;
let services: {
  readonly calculate: ReturnType<typeof createCalculateFindingRiskUseCase>;
  readonly read: ReturnType<typeof createReadCurrentFindingRiskUseCase>;
  readonly publish: ReturnType<typeof createPublishOrganizationPriorityOverrideUseCase>;
};
let cveSerial = 21_000;
let catalogSerial = 0;

function digest(label: string): string {
  return createHash('sha256').update(label).digest('hex');
}

function sha256(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

function seedCanonical(value: unknown): string {
  const result = canonicalJson(value);
  if (!result.ok) {
    throw new Error(result.error.code);
  }
  return result.value;
}

function nextCve(): string {
  cveSerial += 1;
  return `CVE-2099-${cveSerial}`;
}

function nextCatalogVersion(): string {
  catalogSerial += 1;
  return `2099.11.${String(catalogSerial).padStart(2, '0')}`;
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

function compareUuid(left: string, right: string): number {
  if (left < right) {
    return -1;
  }
  if (left > right) {
    return 1;
  }
  return 0;
}

function writer() {
  return createControlledFindingCreationPersistence(prisma);
}

function composition() {
  return createProductMatchEvaluationComposition({
    port: createProductMatchEvaluationPersistence(prisma),
  });
}

function affectedIds(seeded: SeededTarget): string[] {
  return seeded.evidence
    .filter((row) => row.outcome === 'affected')
    .map((row) => row.evidenceId)
    .sort(compareUuid);
}

async function completeIngestion(
  ingestionId: string,
  assetId: string,
  componentCount: number,
): Promise<void> {
  await prisma.sbomIngestion.update({
    where: { id: ingestionId },
    data: {
      state: 'completed',
      normalizationVersion: '2',
      completedAt: new Date('2026-10-02T13:00:00.000Z'),
      graphCompleteness: 'no_dependencies',
      componentCount,
      dependencyEdgeCount: 0,
      warningCount: 0,
      stage: null,
    },
  });
  await prisma.asset.update({
    where: { id: assetId },
    data: { lastSuccessfulSbomIngestionId: ingestionId },
  });
}

async function seedTarget(
  label: string,
  versions: readonly VersionRequest[],
  canonicalCve?: string,
): Promise<SeededTarget> {
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
  const revisionData = {
    revisionSchemaVersion: MAINTAINER_REVIEWED_REVISION_SCHEMA_VERSION,
    advisoryFamilyId: family.id,
    source: 'maintainer_reviewed_advisory' as const,
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
    origin: 'maintainer_reviewed_advisory' as const,
    trustClassification: 'unreviewed' as const,
    revisionDisposition: 'recorded' as const,
    withdrawalClassification: 'not_withdrawn' as const,
    quarantineClassification: 'not_quarantined' as const,
    supersedesRevisionDigest: 'none',
    retrievalClassification: MAINTAINER_REVIEWED_APPROVAL_PINS.retrieval,
    retrievalEvidenceId: MAINTAINER_REVIEWED_APPROVAL_PINS.retrievalEvidence,
    retrievalPolicyId: MAINTAINER_REVIEWED_APPROVAL_PINS.retrievalPolicy,
    ecosystem: 'npm' as const,
    packageName: PACKAGE_NAME,
    packageIdentityKey: packageIdentity(),
    evaluatorVersion: PRODUCT_MATCH_EVALUATOR_VERSION,
    matchingPolicyId: PRODUCT_MATCH_MATCHING_POLICY_ID,
    aliasCount: canonicalCve === undefined ? 0 : 1,
    cveAliasCount: canonicalCve === undefined ? 0 : 1,
    aliasSetDigest: digest(`aliases:${advisoryId}`),
    replayFingerprint: digest(`replay:${advisoryId}`),
    authorIdentity,
  };
  const revisionId =
    canonicalCve === undefined
      ? (
          await prisma.advisoryRevision.create({
            data: revisionData,
            select: { id: true },
          })
        ).id
      : await prisma.$transaction(async (tx) => {
          const revision = await tx.advisoryRevision.create({
            data: revisionData,
            select: { id: true },
          });
          await tx.advisoryRevisionAlias.create({
            data: {
              advisoryRevisionId: revision.id,
              ordinal: 1,
              aliasType: 'canonical_cve',
              aliasValue: canonicalCve,
              aliasPolicyVersion: 'osv_advisory_alias_policy_v1',
              sourceClassification: 'maintainer_reviewed_advisory',
              reviewClassification: 'unreviewed',
              replayFingerprint: digest(`alias:${advisoryId}:${canonicalCve}`),
            },
          });
          return revision.id;
        });
  await prisma.advisoryRevisionRangeEvent.createMany({
    data: [
      {
        advisoryRevisionId: revisionId,
        rangeOrdinal: 0,
        eventOrdinal: 0,
        eventName: 'introduced',
        eventValue: '1.0.0',
      },
      {
        advisoryRevisionId: revisionId,
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
      advisoryRevisionId: revisionId,
      vulnerabilityId: vulnerability.id,
      mappingPolicyId: VULNERABILITY_MAPPING_POLICY_ID,
      mappingMethod: EXACT_MAPPING_METHOD,
      mappingEvidenceFingerprint: digest(`mapping:${advisoryId}`),
      mappingReviewState: 'reviewed',
      mappingSourceClassification: 'explicit_reviewed_binding',
      conflictClassification: 'none',
      bindingClassification:
        canonicalCve === undefined ? 'provider_native_without_cve' : 'one_cve_alias_evidence',
      replayFingerprint: digest(`binding:${advisoryId}`),
    },
  });
  const approval = await createApprovalCapabilityHarness(prisma).approve({
    commandSchemaVersion: MAINTAINER_REVIEWED_APPROVAL_COMMAND_SCHEMA_VERSION,
    advisoryRevisionId: revisionId,
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
      advisoryRevisionId: revisionId,
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
  const org = await createOrg(prisma, `${label}-${randomUUID().slice(0, 8)}`);
  const user = await prisma.user.create({
    data: {
      email: `${label}-${randomUUID().slice(0, 8)}@synthetic.patchpilot.test`,
      displayName: label,
    },
  });
  const membership = await prisma.membership.create({
    data: { organizationId: org.id, userId: user.id, role: 'owner' },
  });
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
    bomRef: versions[0]?.bomRef ?? 'component-1',
    version: versions[0]?.version ?? '1.1.0',
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
  const evidence: SeededEvidence[] = [];
  for (const version of versions) {
    const occurrence = await prisma.componentOccurrence.create({
      data: {
        organizationId: org.id,
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
    const executed = await composition().execute({
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
        rawObservedVersion: version.version,
        versionKnown: true,
        sbomSha256: sbomSha,
      }),
      expectedNpmPackageIdentity: packageIdentity(),
      expectedRawObservedVersion: version.version,
      advisoryRevisionId: revisionId,
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
      occurrenceId: occurrence.id,
      version: version.version,
    });
  }
  await completeIngestion(ingestion.id, asset.id, versions.length);
  return {
    organizationId: org.id,
    actorId: user.id,
    membershipId: membership.id,
    assetId: asset.id,
    componentId: component.id,
    vulnerabilityId: vulnerability.id,
    sbomId: sbom.id,
    ingestionId: ingestion.id,
    evidence,
  };
}

function seal(seeded: SeededTarget, evidenceIds: readonly string[]) {
  const correlationId = randomUUID();
  const trustedContext = {
    schemaVersion: FINDING_CREATION_TRUSTED_CONTEXT_SCHEMA_VERSION,
    organizationId: seeded.organizationId,
    actorId: seeded.actorId,
    membershipId: seeded.membershipId,
    membershipStatus: 'active' as const,
  };
  const issued = issueFindingCreationAuthorization({
    schemaVersion: FINDING_CREATION_AUTHORIZATION_SCHEMA_VERSION,
    trustedContext,
    purpose: FINDING_CREATION_PURPOSE,
    policyId: FINDING_CREATION_POLICY_ID,
    policyVersion: FINDING_CREATION_POLICY_VERSION,
    assetId: seeded.assetId,
    componentId: seeded.componentId,
    vulnerabilityId: seeded.vulnerabilityId,
    sbomIngestionId: seeded.ingestionId,
    productMatchEvidenceIds: [...evidenceIds],
    correlationId,
  });
  if (issued.status !== 'authorized') {
    throw new Error(`authorization was ${issued.status}`);
  }
  const opened = openFindingCreationCommand({
    schemaVersion: FINDING_CREATION_COMMAND_SCHEMA_VERSION,
    purpose: FINDING_CREATION_PURPOSE,
    policyId: FINDING_CREATION_POLICY_ID,
    policyVersion: FINDING_CREATION_POLICY_VERSION,
    expectedAssetId: seeded.assetId,
    expectedComponentId: seeded.componentId,
    expectedVulnerabilityId: seeded.vulnerabilityId,
    expectedSbomIngestionId: seeded.ingestionId,
    expectedProductMatchEvidenceIds: [...evidenceIds],
    correlationId,
    authorization: issued.authorization,
  });
  if (opened.status !== 'authorized') {
    throw new Error(`command was ${opened.status}`);
  }
  return { trustedContext, command: opened.command };
}

async function prepareFinding(label: string, canonicalCve?: string): Promise<PreparedFinding> {
  await ensureBuiltin();
  const seeded = await seedTarget(
    `${label}-${randomUUID().slice(0, 8)}`,
    [{ version: '1.1.0', bomRef: 'component-1' }],
    canonicalCve,
  );
  const evidenceIds = affectedIds(seeded);
  if (evidenceIds.length !== 1) {
    throw new Error(`expected one affected evidence row, saw ${String(evidenceIds.length)}`);
  }
  const created = await writer().apply(seal(seeded, evidenceIds));
  if (created.status !== 'created') {
    throw new Error(`finding was ${created.status}`);
  }
  return {
    organizationId: seeded.organizationId,
    userId: seeded.actorId,
    membershipId: seeded.membershipId,
    assetId: seeded.assetId,
    findingId: created.findingId,
  };
}

function envelope(
  prepared: PreparedFinding,
  role: ActorRole = 'owner',
  findingId = prepared.findingId,
) {
  return {
    actor: {
      userId: prepared.userId,
      sessionId: SESSION_ID,
      organizationId: prepared.organizationId,
      membershipId: prepared.membershipId,
      role,
    },
    command: { findingId },
  };
}

function publishEnvelope(prepared: PreparedFinding, definition: Record<string, unknown>) {
  return {
    actor: envelope(prepared).actor,
    command: { definition },
  };
}

function weightOverride(sourceSeverity: number, kevListed: number): Record<string, unknown> {
  const definition = structuredClone(BUILTIN_PRIORITY_POLICY_DEFINITION) as {
    weights: { source_severity: number; kev_listed: number };
  };
  definition.weights.source_severity = sourceSeverity;
  definition.weights.kev_listed = kevListed;
  return definition;
}

async function ensureBuiltin(): Promise<void> {
  const result = await ensurePublishedBuiltinPriorityPolicy({
    client: prisma,
    definition: BUILTIN_PRIORITY_POLICY_DEFINITION,
    canonicalJson: seedCanonical,
  });
  if (result.outcome === 'immutable_conflict') {
    throw new Error('builtin priority policy is immutable_conflict');
  }
}

async function calculationCount(organizationId: string, findingId?: string): Promise<number> {
  return prisma.riskCalculation.count({
    where: findingId === undefined ? { organizationId } : { organizationId, findingId },
  });
}

async function auditCount(organizationId: string, action: string): Promise<number> {
  return prisma.auditEvent.count({ where: { organizationId, action } });
}

async function markProductionInternetFacing(
  organizationId: string,
  assetId: string,
): Promise<void> {
  const suffix = randomUUID().slice(0, 8);
  const environment = await prisma.environment.create({
    data: {
      organizationId,
      name: `Production ${suffix}`,
      slug: `prod-${suffix}`,
      sensitivityClass: 'production',
    },
  });
  await prisma.asset.update({
    where: { id: assetId },
    data: { environmentId: environment.id, internetExposure: 'internet_facing' },
  });
}

async function setFindingUserTriggers(
  table: 'finding_observation' | 'finding_creation_evidence_link',
  enabled: boolean,
): Promise<void> {
  const statement = enabled ? 'ENABLE TRIGGER USER' : 'DISABLE TRIGGER USER';
  if (table === 'finding_observation') {
    await prisma.$executeRawUnsafe(`ALTER TABLE "finding_observation" ${statement}`);
    return;
  }
  await prisma.$executeRawUnsafe(`ALTER TABLE "finding_creation_evidence_link" ${statement}`);
}

async function removeCreationEvidenceLinks(findingId: string): Promise<void> {
  await setFindingUserTriggers('finding_creation_evidence_link', false);
  try {
    await prisma.findingCreationEvidenceLink.deleteMany({ where: { findingId } });
  } finally {
    await setFindingUserTriggers('finding_creation_evidence_link', true);
  }
}

async function removeObservations(findingId: string): Promise<void> {
  await setFindingUserTriggers('finding_observation', false);
  try {
    await prisma.findingObservation.deleteMany({ where: { findingId } });
  } finally {
    await setFindingUserTriggers('finding_observation', true);
  }
}

async function findingGate(prepared: PreparedFinding) {
  const finding = await prisma.finding.findFirstOrThrow({
    where: { id: prepared.findingId, organizationId: prepared.organizationId },
  });
  const evidence = await prisma.productMatchEvaluationEvidence.count({
    where: { organizationId: prepared.organizationId },
  });
  return {
    state: finding.state,
    version: finding.version,
    currentRiskCalculationId: finding.currentRiskCalculationId,
    dueAt: finding.dueAt,
    updatedAt: finding.updatedAt,
    evidence,
  };
}

async function persistInitialCopy(
  prepared: PreparedFinding,
  source: StoredRiskCalculation,
  label: string,
) {
  return createRiskCalculationPersistence(prisma).persist({
    organizationId: prepared.organizationId,
    actorUserId: prepared.userId,
    membershipId: prepared.membershipId,
    findingId: prepared.findingId,
    riskPolicyId: source.riskPolicyId,
    policyDefinitionSha256: source.policyDefinitionSha256,
    inputFingerprint: digest(label),
    calculationReason: 'initial',
    factors: source.factors,
    result: source.result,
    correlationId: randomUUID(),
    calculatedAt: source.calculatedAt,
  });
}

async function expectFindingUntouched(organizationId: string, findingId: string): Promise<void> {
  const finding = await prisma.finding.findFirstOrThrow({
    where: { id: findingId, organizationId },
  });
  expect(finding.state).toBe('open');
  expect(finding.version).toBe(1);
  expect(finding.currentRiskCalculationId).toBeNull();
  expect(finding.dueAt).toBeNull();
}

async function rowSnapshot(id: string) {
  const row = await prisma.riskCalculation.findUniqueOrThrow({ where: { id } });
  return {
    id: row.id,
    inputFingerprint: row.inputFingerprint.trim(),
    policyDefinitionSha256: row.policyDefinitionSha256.trim(),
    riskPolicyId: row.riskPolicyId,
    policyVersion: row.policyVersion,
    calculationReason: row.calculationReason,
    calculatedAt: row.calculatedAt.toISOString(),
    result: row.result,
    factors: row.factors,
  };
}

function factor(calculation: StoredRiskCalculation, factorId: string) {
  const row = calculation.factors.factors.find((item) => item.factorId === factorId);
  if (row === undefined) {
    throw new Error(`missing factor ${factorId}`);
  }
  return row;
}

function priorityFacts(
  age: number,
  kev: KevListedFact,
  internet: 'unknown' | 'internet_facing',
  environment: 'unavailable' | 'production' = 'unavailable',
): PriorityFactInput {
  return {
    source_severity: { state: 'unavailable' },
    kev_listed: kev,
    environment_sensitivity:
      environment === 'production'
        ? { state: 'observed', value: 'production' }
        : { state: 'unavailable' },
    internet_exposure:
      internet === 'unknown'
        ? { state: 'unknown', value: 'unknown' }
        : { state: 'observed', value: 'internet_facing' },
    business_criticality: { state: 'unknown', value: 'unspecified' },
    asset_data_classification: { state: 'unknown', value: 'unspecified' },
    direct_dependency: { state: 'observed', value: 'direct' },
    fix_available: { state: 'unavailable' },
    finding_age_days: { state: 'observed', value: age },
    advisory_withdrawn: { state: 'observed', value: 'not_withdrawn' },
  };
}

async function factsFor(
  calculation: StoredRiskCalculation,
  kev: KevListedFact,
  internet: 'unknown' | 'internet_facing',
  environment: 'unavailable' | 'production' = 'unavailable',
): Promise<PriorityFactInput> {
  const finding = await prisma.finding.findFirstOrThrow({
    where: { id: calculation.findingId, organizationId: calculation.organizationId },
    select: { firstObservedAt: true },
  });
  const age = Math.floor(
    (calculation.calculatedAt.getTime() - finding.firstObservedAt.getTime()) / 86_400_000,
  );
  return priorityFacts(age, kev, internet, environment);
}

function validatedBuiltin(): ValidatedPriorityPolicyDefinition {
  const validated = validatePolicyDefinition(BUILTIN_PRIORITY_POLICY_DEFINITION);
  if (!validated.ok) {
    throw new Error('builtin definition was rejected');
  }
  return validated.value;
}

function assertMatchesEngine(
  calculation: StoredRiskCalculation,
  definition: ValidatedPriorityPolicyDefinition,
  facts: PriorityFactInput,
): void {
  const parsed = parseFactInput(facts);
  expect(parsed.ok, JSON.stringify(parsed)).toBe(true);
  if (!parsed.ok) {
    return;
  }
  const evaluation = evaluatePriority(definition, parsed.value);
  expect(evaluation.ok, JSON.stringify(evaluation)).toBe(true);
  if (!evaluation.ok) {
    return;
  }
  expect(calculation.result.priority).toBe(evaluation.value.priority);
  expect(calculation.result.priorityBand).toBe(evaluation.value.priorityBand);
  expect(calculation.result.dueDateRecommendationDays).toBe(
    evaluation.value.dueDateRecommendationDays,
  );
  expect(calculation.result.escalationRecommendation).toBe(evaluation.value.escalation.recommended);
  expect(calculation.factors.escalationReasons).toEqual(evaluation.value.escalation.reasons);
  expect(Object.keys(calculation.result).sort()).toEqual([
    'dueDateRecommendationDays',
    'escalationRecommendation',
    'priority',
    'priorityBand',
    'schemaVersion',
  ]);
  expect(calculation.calculationEngineVersion).toBe(POLICY_ENGINE_VERSION);
  const definitionJson = canonicalJson(definition);
  expect(definitionJson.ok).toBe(true);
  if (!definitionJson.ok) {
    return;
  }
  const policyHash = sha256(definitionJson.value);
  expect(calculation.policyDefinitionSha256).toBe(policyHash);
  const material = canonicalJson({
    engineVersion: POLICY_ENGINE_VERSION,
    policyDefinitionSha256: policyHash,
    facts: parsed.value,
  });
  expect(material.ok).toBe(true);
  if (!material.ok) {
    return;
  }
  expect(calculation.inputFingerprint).toBe(sha256(material.value));
}

function evaluatedPriority(
  definition: ValidatedPriorityPolicyDefinition,
  facts: PriorityFactInput,
): { readonly priority: number; readonly explanationCode: string | undefined } {
  const parsed = parseFactInput(facts);
  if (!parsed.ok) {
    throw new Error(JSON.stringify(parsed.error));
  }
  const evaluation = evaluatePriority(definition, parsed.value);
  if (!evaluation.ok) {
    throw new Error(JSON.stringify(evaluation.error));
  }
  return {
    priority: evaluation.value.priority,
    explanationCode: evaluation.value.rules.find((row) => row.ruleId === 'kev_minimum_band')
      ?.explanationCode,
  };
}

async function currentCalculationId(organizationId: string, findingId: string): Promise<string> {
  const rows = await prisma.$queryRaw<Array<{ id: string }>>`
    SELECT "id"::text AS id
    FROM "risk_calculation"
    WHERE "organization_id" = ${organizationId}::uuid
      AND "finding_id" = ${findingId}::uuid
    ORDER BY "calculated_at" DESC, "id" DESC
    LIMIT 1
  `;
  const id = rows[0]?.id;
  if (id === undefined) {
    throw new Error('missing calculation');
  }
  return id;
}

async function race<T>(left: () => Promise<T>, right: () => Promise<T>): Promise<[T, T]> {
  let release!: () => void;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const pending = [
    (async () => {
      await gate;
      return left();
    })(),
    (async () => {
      await gate;
      return right();
    })(),
  ] as const;
  release();
  return Promise.all(pending);
}

async function completeGeneration(
  generationId: string,
  input: { catalogVersion: string; expectedEntryCount: number; catalogReleasedAt: Date },
) {
  await prisma.kevGeneration.update({
    where: { id: generationId },
    data: {
      state: 'complete',
      completedAt: input.catalogReleasedAt,
      stagedEntryCount: input.expectedEntryCount,
      catalogVersion: input.catalogVersion,
      catalogReleasedAt: input.catalogReleasedAt,
    },
  });
}

async function activateGeneration(generationId: string, activatedAt: Date) {
  await prisma.kevGeneration.update({
    where: { id: generationId },
    data: { state: 'active', activatedAt },
  });
}

async function supersedeGeneration(generationId: string) {
  await prisma.kevGeneration.update({
    where: { id: generationId },
    data: { state: 'superseded', supersededAt: new Date() },
  });
}

async function clearActivePointer() {
  await prisma.intelligenceSource.update({
    where: { providerKey: 'cisa_kev' },
    data: {
      activeGenerationId: null,
      lastSuccessfulSyncAt: null,
      lastAttemptAt: null,
    },
  });
}

async function pointAtGeneration(generationId: string, lastSuccessfulSyncAt: Date) {
  await prisma.intelligenceSource.update({
    where: { providerKey: 'cisa_kev' },
    data: {
      activeGenerationId: generationId,
      lastSuccessfulSyncAt,
      lastAttemptAt: lastSuccessfulSyncAt,
    },
  });
}

async function activateCatalog(cves: readonly string[]): Promise<{ generationId: string }> {
  await clearActivePointer();
  const active = await prisma.kevGeneration.findMany({
    where: { state: 'active' },
    select: { id: true },
  });
  for (const generation of active) {
    await supersedeGeneration(generation.id);
  }
  const run = await createFetchingSyncRun(prisma);
  const snapshot = await createSnapshot(prisma, run.id, { sha256: uniqueKevSha() });
  const generation = await createStagingGeneration(prisma, {
    syncRunId: run.id,
    snapshotId: snapshot.id,
    expectedEntryCount: cves.length,
  });
  for (const [ordinal, normalizedCve] of cves.entries()) {
    await prisma.kevEntry.create({
      data: {
        generationId: generation.id,
        ordinal,
        normalizedCve,
        vendorProject: 'Synthetic Vendor',
        product: 'Synthetic Product',
        vulnerabilityName: 'Synthetic KEV entry',
        dateAdded: '2099-01-15',
        shortDescription: 'Synthetic short description',
        requiredAction: 'Apply the vendor patch',
        dueDate: '2099-02-15',
        knownRansomwareCampaignUse: 'unknown',
      },
    });
  }
  const releasedAt = new Date();
  await completeGeneration(generation.id, {
    catalogVersion: nextCatalogVersion(),
    expectedEntryCount: cves.length,
    catalogReleasedAt: releasedAt,
  });
  await activateGeneration(generation.id, releasedAt);
  await pointAtGeneration(generation.id, releasedAt);
  await prisma.vulnerabilitySyncRun.update({
    where: { id: run.id },
    data: {
      state: 'failed',
      completedAt: releasedAt,
      executionAttempt: 1,
      failureCategory: 'internal',
      failureCode: 'processing_failed',
      nextAttemptAt: null,
    },
  });
  return { generationId: generation.id };
}

beforeAll(async () => {
  database = await createEphemeralDatabase('it');
  await deployMigrations(database.databaseUrl);
  prisma = new PrismaClient({ datasources: { db: { url: database.databaseUrl } } });
  await seedDevelopmentData({ env: createFoundationTestEnv(), client: prisma });
  const persistence = createRiskCalculationApplicationPersistence(prisma, {
    bindKevMembership: (client, asOf) =>
      createQueryActiveKevMembershipUseCase({
        membership: createActiveKevMembershipPersistence(client),
        kevEnabled: true,
        staleThresholdSeconds: 259_200,
        now: () => asOf,
      }),
  });
  const engine = {
    parseFactInput,
    evaluatePriority,
    validatePolicyDefinition,
    validatePolicyOverride,
    canonicalJson,
  };
  services = {
    calculate: createCalculateFindingRiskUseCase({
      engine,
      persistence,
      builtinDefinition: BUILTIN_PRIORITY_POLICY_DEFINITION,
    }),
    read: createReadCurrentFindingRiskUseCase({ persistence }),
    publish: createPublishOrganizationPriorityOverrideUseCase({
      engine,
      persistence,
      builtinDefinition: BUILTIN_PRIORITY_POLICY_DEFINITION,
    }),
  };
});

afterAll(async () => {
  await prisma.$disconnect();
  await dropEphemeralDatabase(database.admin, database.databaseName);
});

beforeEach(async () => {
  await failInflightSyncRuns(prisma);
  await clearActivePointer();
  const active = await prisma.kevGeneration.findMany({
    where: { state: 'active' },
    select: { id: true },
  });
  for (const generation of active) {
    await supersedeGeneration(generation.id);
  }
});

describe('risk calculation persistence', () => {
  it('publishes builtin version 2, replays it, and rejects a conflicting definition', async () => {
    const inserted = await ensurePublishedBuiltinPriorityPolicy({
      client: prisma,
      definition: BUILTIN_PRIORITY_POLICY_DEFINITION,
      canonicalJson: seedCanonical,
    });
    expect(inserted.outcome).toBe('inserted');
    if (inserted.outcome !== 'inserted') {
      return;
    }
    expect(inserted.policy.id).toBe(developmentSeedIds.builtinPriorityPolicyVersion2);
    expect(inserted.policy.version).toBe(2);
    const storedCanonical = seedCanonical(inserted.policy.definition);
    expect(storedCanonical).toBe(seedCanonical(BUILTIN_PRIORITY_POLICY_DEFINITION));

    const replayed = await ensurePublishedBuiltinPriorityPolicy({
      client: prisma,
      definition: BUILTIN_PRIORITY_POLICY_DEFINITION,
      canonicalJson: seedCanonical,
    });
    expect(replayed.outcome).toBe('already_applied');

    const conflict = await ensurePublishedBuiltinPriorityPolicy({
      client: prisma,
      definition: weightOverride(35, 25),
      canonicalJson: seedCanonical,
    });
    expect(conflict.outcome).toBe('immutable_conflict');
    const version2 = await prisma.riskPolicy.findMany({
      where: { policyKey: 'patchpilot.builtin.v0', version: 2 },
    });
    expect(version2).toHaveLength(1);
    expect(seedCanonical(version2[0]?.definition)).toBe(storedCanonical);
    expect(version2[0]?.id).toBe(developmentSeedIds.builtinPriorityPolicyVersion2);
    expect(version2[0]?.organizationId).toBeNull();
    expect(version2[0]?.createdByMembershipId).toBeNull();

    const version1 = await prisma.riskPolicy.findUniqueOrThrow({
      where: { id: developmentSeedIds.builtinRiskPolicy },
    });
    expect(version1.version).toBe(1);
    expect(version1.organizationId).toBeNull();
    expect(version1.createdByMembershipId).toBeNull();
    expect(version1.definition).toEqual(EMPTY_BUILTIN_V1);
  });

  it('calculates one priority for an eligible finding and leaves the Finding unchanged', async () => {
    const prepared = await prepareFinding('eligible');
    const evidenceBefore = await prisma.productMatchEvaluationEvidence.count({
      where: { organizationId: prepared.organizationId },
    });
    const createdAuditsBefore = await auditCount(prepared.organizationId, 'finding.created');
    const outboxBefore = await prisma.outboxEvent.count({
      where: { eventType: 'finding.recalculate' },
    });
    const result = await services.calculate.execute(envelope(prepared));
    expect(result.kind).toBe('calculated');
    if (result.kind !== 'calculated') {
      return;
    }
    expect(result.calculation.calculationReason).toBe('initial');
    expect(result.calculation.riskPolicyId).toBe(developmentSeedIds.builtinPriorityPolicyVersion2);
    expect(result.calculation.policyVersion).toBe(2);
    expect(result.calculation.factors.schemaVersion).toBe(2);
    expect(result.calculation.result.schemaVersion).toBe(1);
    expect(factor(result.calculation, 'source_severity').inputState).toBe('unavailable');
    expect(factor(result.calculation, 'fix_available').inputState).toBe('unavailable');
    const kev = factor(result.calculation, 'kev_listed');
    expect(kev.inputState).toBe('unavailable');
    expect(kev.observedValue).toBeNull();
    expect(kev.explanationCode).toBe('kev_unavailable_no_canonical_cve');
    assertMatchesEngine(
      result.calculation,
      validatedBuiltin(),
      await factsFor(
        result.calculation,
        { state: 'unavailable', reason: 'no_canonical_cve' },
        'unknown',
      ),
    );
    expect(await calculationCount(prepared.organizationId, prepared.findingId)).toBe(1);
    expect(await auditCount(prepared.organizationId, 'priority.calculated')).toBe(1);
    expect(await auditCount(prepared.organizationId, 'finding.created')).toBe(createdAuditsBefore);
    expect(createdAuditsBefore).toBe(1);
    expect(
      await prisma.productMatchEvaluationEvidence.count({
        where: { organizationId: prepared.organizationId },
      }),
    ).toBe(evidenceBefore);
    expect(await prisma.outboxEvent.count({ where: { eventType: 'finding.recalculate' } })).toBe(
      outboxBefore,
    );
    const audit = await prisma.auditEvent.findFirstOrThrow({
      where: { organizationId: prepared.organizationId, action: 'priority.calculated' },
    });
    expect(audit.subjectType).toBe('finding');
    expect(audit.subjectId).toBe(prepared.findingId);
    await expectFindingUntouched(prepared.organizationId, prepared.findingId);
  });

  it('stores listed and not-listed KEV facts and keeps the engine floor', async () => {
    const listedCve = nextCve();
    const otherCve = nextCve();
    const listedFinding = await prepareFinding('listed', listedCve);
    await markProductionInternetFacing(listedFinding.organizationId, listedFinding.assetId);
    await activateCatalog([listedCve]);
    const listed = await services.calculate.execute(envelope(listedFinding));
    expect(listed.kind).toBe('calculated');
    if (listed.kind !== 'calculated') {
      return;
    }
    const listedKev = factor(listed.calculation, 'kev_listed');
    expect(listedKev.inputState).toBe('observed');
    expect(listedKev.observedValue).toBe('listed_catalog_current');
    const listedFacts = await factsFor(
      listed.calculation,
      { state: 'observed', value: 'listed_catalog_current' },
      'internet_facing',
      'production',
    );
    assertMatchesEngine(listed.calculation, validatedBuiltin(), listedFacts);
    const quietFacts: PriorityFactInput = {
      ...listedFacts,
      kev_listed: { state: 'observed', value: 'not_listed_catalog_current' },
    };
    const raised = evaluatedPriority(validatedBuiltin(), listedFacts);
    const quiet = evaluatedPriority(validatedBuiltin(), quietFacts);
    expect(raised.priority).toBeGreaterThan(quiet.priority);
    expect(raised.explanationCode).toBe('kev_minimum_band_raised');
    expect(listed.calculation.result.priority).toBe(raised.priority);
    expect(listed.calculation.factors.escalationReasons).toEqual([
      'kev_production',
      'kev_internet_facing',
    ]);
    expect(listed.calculation.factors.rules.map((row) => row.ruleId)).toEqual([
      'kev_minimum_band',
      'kev_escalation',
    ]);
    expect(listed.calculation.result.escalationRecommendation).toBe(true);
    expect(listed.calculation.result).not.toHaveProperty('escalationReasons');
    const calculationsBeforeRejection = await calculationCount(
      listedFinding.organizationId,
      listedFinding.findingId,
    );
    const auditsBeforeRejection = await auditCount(
      listedFinding.organizationId,
      'priority.calculated',
    );
    const rejectedReason = await createRiskCalculationPersistence(prisma).persist({
      organizationId: listedFinding.organizationId,
      actorUserId: listedFinding.userId,
      membershipId: listedFinding.membershipId,
      findingId: listedFinding.findingId,
      riskPolicyId: listed.calculation.riskPolicyId,
      policyDefinitionSha256: listed.calculation.policyDefinitionSha256,
      inputFingerprint: digest(`unknown-reason:${listed.calculation.id}`),
      calculationReason: 'rescan',
      factors: {
        ...listed.calculation.factors,
        escalationReasons: ['kev_production', 'vendor says escalate'],
      },
      result: listed.calculation.result,
      correlationId: randomUUID(),
      calculatedAt: listed.calculation.calculatedAt,
    });
    expect(rejectedReason).toEqual({ kind: 'rejected', reason: 'malformed_document' });
    expect(await calculationCount(listedFinding.organizationId, listedFinding.findingId)).toBe(
      calculationsBeforeRejection,
    );
    expect(await auditCount(listedFinding.organizationId, 'priority.calculated')).toBe(
      auditsBeforeRejection,
    );
    expect(JSON.stringify(listed.calculation)).not.toContain(listedCve);
    const audit = await prisma.auditEvent.findFirstOrThrow({
      where: { organizationId: listedFinding.organizationId, action: 'priority.calculated' },
    });
    expect(JSON.stringify(audit.payload)).not.toContain(listedCve);

    const quietFinding = await prepareFinding('not-listed', otherCve);
    await activateCatalog([listedCve]);
    const absent = await services.calculate.execute(envelope(quietFinding));
    expect(absent.kind).toBe('calculated');
    if (absent.kind !== 'calculated') {
      return;
    }
    const absentKev = factor(absent.calculation, 'kev_listed');
    expect(absentKev.inputState).toBe('observed');
    expect(absentKev.observedValue).toBe('not_listed_catalog_current');
    assertMatchesEngine(
      absent.calculation,
      validatedBuiltin(),
      await factsFor(
        absent.calculation,
        { state: 'observed', value: 'not_listed_catalog_current' },
        'unknown',
      ),
    );
    await expectFindingUntouched(listedFinding.organizationId, listedFinding.findingId);
    await expectFindingUntouched(quietFinding.organizationId, quietFinding.findingId);
  });

  it('stores unavailable KEV when the active generation or canonical CVE is absent', async () => {
    const cve = nextCve();
    const prepared = await prepareFinding('no-generation', cve);
    const result = await services.calculate.execute(envelope(prepared));
    expect(result.kind).toBe('calculated');
    if (result.kind !== 'calculated') {
      return;
    }
    const kev = factor(result.calculation, 'kev_listed');
    expect(kev.inputState).toBe('unavailable');
    expect(kev.observedValue).toBeNull();
    expect(kev.explanationCode).toBe('kev_unavailable_no_active_generation');
    assertMatchesEngine(
      result.calculation,
      validatedBuiltin(),
      await factsFor(
        result.calculation,
        { state: 'unavailable', reason: 'no_active_generation' },
        'unknown',
      ),
    );
    expect(await calculationCount(prepared.organizationId, prepared.findingId)).toBe(1);
  });

  it('writes nothing when KEV membership is missing or inconsistent', async () => {
    const missingCve = nextCve();
    const missing = await prepareFinding('source-missing', missingCve);
    await prisma.intelligenceSource.delete({ where: { providerKey: 'cisa_kev' } });
    try {
      const result = await services.calculate.execute(envelope(missing));
      expect(result).toEqual({
        kind: 'kev_membership_error',
        error: { code: 'source_missing' },
      });
      expect(await calculationCount(missing.organizationId, missing.findingId)).toBe(0);
      expect(await auditCount(missing.organizationId, 'priority.calculated')).toBe(0);
    } finally {
      await prisma.intelligenceSource.create({
        data: {
          providerKey: 'cisa_kev',
          state: 'disabled',
          config: { schemaVersion: 1, refreshIntervalSeconds: null, endpointAllowlist: [] },
        },
      });
    }

    const inconsistentCve = nextCve();
    const inconsistent = await prepareFinding('inconsistent', inconsistentCve);
    const catalog = await activateCatalog([inconsistentCve]);
    await supersedeGeneration(catalog.generationId);
    const result = await services.calculate.execute(envelope(inconsistent));
    expect(result).toEqual({
      kind: 'kev_membership_error',
      error: { code: 'inconsistent_active_generation' },
    });
    expect(await calculationCount(inconsistent.organizationId, inconsistent.findingId)).toBe(0);
    expect(await auditCount(inconsistent.organizationId, 'priority.calculated')).toBe(0);
  });

  it('replays an exact fingerprint without a second row or audit', async () => {
    const prepared = await prepareFinding('replay');
    const first = await services.calculate.execute(envelope(prepared));
    expect(first.kind).toBe('calculated');
    if (first.kind !== 'calculated') {
      return;
    }
    const calculations = await calculationCount(prepared.organizationId, prepared.findingId);
    const audits = await auditCount(prepared.organizationId, 'priority.calculated');
    const second = await services.calculate.execute(envelope(prepared));
    expect(second.kind).toBe('replayed');
    if (second.kind !== 'replayed') {
      return;
    }
    expect(second.calculation.id).toBe(first.calculation.id);
    expect(second.calculation.inputFingerprint).toBe(first.calculation.inputFingerprint);
    expect(await calculationCount(prepared.organizationId, prepared.findingId)).toBe(calculations);
    expect(await auditCount(prepared.organizationId, 'priority.calculated')).toBe(audits);
    expect(calculations).toBe(1);
    expect(audits).toBe(1);
  });

  it('refuses insert without a creation observation or an affected evidence link', async () => {
    const stored = await prepareFinding('stored-fingerprint');
    const calculated = await services.calculate.execute(envelope(stored));
    expect(calculated.kind).toBe('calculated');
    if (calculated.kind !== 'calculated') {
      return;
    }
    const storedEvidence = await prisma.productMatchEvaluationEvidence.count({
      where: { organizationId: stored.organizationId },
    });
    await removeCreationEvidenceLinks(stored.findingId);
    expect(
      await prisma.findingCreationEvidenceLink.count({ where: { findingId: stored.findingId } }),
    ).toBe(0);
    const replay = await createRiskCalculationPersistence(prisma).persist({
      organizationId: stored.organizationId,
      actorUserId: stored.userId,
      membershipId: stored.membershipId,
      findingId: stored.findingId,
      riskPolicyId: calculated.calculation.riskPolicyId,
      policyDefinitionSha256: calculated.calculation.policyDefinitionSha256,
      inputFingerprint: calculated.calculation.inputFingerprint,
      calculationReason: calculated.calculation.calculationReason,
      factors: calculated.calculation.factors,
      result: calculated.calculation.result,
      correlationId: randomUUID(),
      calculatedAt: calculated.calculation.calculatedAt,
    });
    expect(replay.kind).toBe('replay');
    if (replay.kind === 'replay') {
      expect(replay.calculation.id).toBe(calculated.calculation.id);
    }
    expect(await calculationCount(stored.organizationId, stored.findingId)).toBe(1);
    expect(await auditCount(stored.organizationId, 'priority.calculated')).toBe(1);

    const freshOnStored = await persistInitialCopy(
      stored,
      calculated.calculation,
      'stored-without-links',
    );
    expect(freshOnStored.kind).toBe('ineligible');
    expect(await calculationCount(stored.organizationId, stored.findingId)).toBe(1);
    expect(await auditCount(stored.organizationId, 'priority.calculated')).toBe(1);
    expect(
      await prisma.productMatchEvaluationEvidence.count({
        where: { organizationId: stored.organizationId },
      }),
    ).toBe(storedEvidence);

    const missingLinks = await prepareFinding('missing-links');
    const linksBefore = await findingGate(missingLinks);
    await removeCreationEvidenceLinks(missingLinks.findingId);
    expect(
      await prisma.findingObservation.count({ where: { findingId: missingLinks.findingId } }),
    ).toBe(1);
    expect(
      await prisma.findingCreationEvidenceLink.count({
        where: { findingId: missingLinks.findingId },
      }),
    ).toBe(0);
    const linksRefused = await persistInitialCopy(
      missingLinks,
      calculated.calculation,
      'missing-links',
    );
    expect(linksRefused.kind).toBe('ineligible');
    expect(await calculationCount(missingLinks.organizationId, missingLinks.findingId)).toBe(0);
    expect(await auditCount(missingLinks.organizationId, 'priority.calculated')).toBe(0);
    expect(await findingGate(missingLinks)).toEqual(linksBefore);

    const missingObservation = await prepareFinding('missing-observation');
    const observationBefore = await findingGate(missingObservation);
    await removeCreationEvidenceLinks(missingObservation.findingId);
    await removeObservations(missingObservation.findingId);
    expect(
      await prisma.findingObservation.count({ where: { findingId: missingObservation.findingId } }),
    ).toBe(0);
    expect(
      await prisma.findingCreationEvidenceLink.count({
        where: { findingId: missingObservation.findingId },
      }),
    ).toBe(0);
    const observationRefused = await persistInitialCopy(
      missingObservation,
      calculated.calculation,
      'missing-observation',
    );
    expect(observationRefused.kind).toBe('ineligible');
    expect(
      await calculationCount(missingObservation.organizationId, missingObservation.findingId),
    ).toBe(0);
    expect(await auditCount(missingObservation.organizationId, 'priority.calculated')).toBe(0);
    expect(await findingGate(missingObservation)).toEqual(observationBefore);
  }, 120_000);

  it('appends an asset_change row and leaves the first row unchanged', async () => {
    const prepared = await prepareFinding('asset');
    const first = await services.calculate.execute(envelope(prepared));
    expect(first.kind).toBe('calculated');
    if (first.kind !== 'calculated') {
      return;
    }
    const before = await rowSnapshot(first.calculation.id);
    await prisma.asset.update({
      where: { id: prepared.assetId },
      data: { internetExposure: 'internet_facing' },
    });
    const second = await services.calculate.execute(envelope(prepared));
    expect(second.kind).toBe('calculated');
    if (second.kind !== 'calculated') {
      return;
    }
    expect(second.calculation.calculationReason).toBe('asset_change');
    expect(second.calculation.id).not.toBe(first.calculation.id);
    expect(await rowSnapshot(first.calculation.id)).toEqual(before);
    expect(factor(second.calculation, 'internet_exposure').observedValue).toBe('internet_facing');
    expect(factor(first.calculation, 'internet_exposure').inputState).toBe('unknown');
    assertMatchesEngine(
      second.calculation,
      validatedBuiltin(),
      await factsFor(
        second.calculation,
        { state: 'unavailable', reason: 'no_canonical_cve' },
        'internet_facing',
      ),
    );
    expect(await calculationCount(prepared.organizationId, prepared.findingId)).toBe(2);
    await expectFindingUntouched(prepared.organizationId, prepared.findingId);
  });

  it('appends a policy_change row for a valid override and rejects an out-of-bounds override', async () => {
    const prepared = await prepareFinding('policy');
    const first = await services.calculate.execute(envelope(prepared));
    expect(first.kind).toBe('calculated');
    if (first.kind !== 'calculated') {
      return;
    }
    const before = await rowSnapshot(first.calculation.id);
    const rejectedDefinition = weightOverride(51, 9);
    expect(validatePolicyOverride(BUILTIN_PRIORITY_POLICY_DEFINITION, rejectedDefinition).ok).toBe(
      false,
    );
    const rejected = await services.publish.execute(publishEnvelope(prepared, rejectedDefinition));
    expect(rejected).toEqual({ kind: 'override_rejected', reason: 'invalid' });
    expect(
      await prisma.riskPolicy.count({
        where: { organizationId: prepared.organizationId, policyKey: 'patchpilot.builtin.v0' },
      }),
    ).toBe(0);
    expect(await auditCount(prepared.organizationId, 'risk_policy.published')).toBe(0);
    expect(await calculationCount(prepared.organizationId, prepared.findingId)).toBe(1);

    const acceptedDefinition = weightOverride(35, 25);
    const checked = validatePolicyOverride(BUILTIN_PRIORITY_POLICY_DEFINITION, acceptedDefinition);
    expect(checked.ok, JSON.stringify(checked)).toBe(true);
    if (!checked.ok) {
      return;
    }
    const published = await services.publish.execute(publishEnvelope(prepared, acceptedDefinition));
    expect(published.kind).toBe('published');
    if (published.kind !== 'published') {
      return;
    }
    expect(published.policy.version).toBe(1);
    expect(await auditCount(prepared.organizationId, 'risk_policy.published')).toBe(1);
    const second = await services.calculate.execute(envelope(prepared));
    expect(second.kind).toBe('calculated');
    if (second.kind !== 'calculated') {
      return;
    }
    expect(second.calculation.calculationReason).toBe('policy_change');
    expect(second.calculation.riskPolicyId).toBe(published.policy.id);
    expect(second.calculation.policyVersion).toBe(1);
    expect(await rowSnapshot(first.calculation.id)).toEqual(before);
    assertMatchesEngine(
      second.calculation,
      checked.value,
      await factsFor(
        second.calculation,
        { state: 'unavailable', reason: 'no_canonical_cve' },
        'unknown',
      ),
    );
    expect(seedCanonical(BUILTIN_PRIORITY_POLICY_DEFINITION)).toBe(
      seedCanonical(validatedBuiltin()),
    );
    const builtin = await prisma.riskPolicy.findUniqueOrThrow({
      where: { id: developmentSeedIds.builtinPriorityPolicyVersion2 },
    });
    expect(seedCanonical(builtin.definition)).toBe(
      seedCanonical(BUILTIN_PRIORITY_POLICY_DEFINITION),
    );
    await expectFindingUntouched(prepared.organizationId, prepared.findingId);
  });

  it('writes nothing for a foreign Finding or an unauthorized actor', async () => {
    const prepared = await prepareFinding('isolated');
    const member = await services.calculate.execute(envelope(prepared, 'member'));
    expect(member.kind).toBe('unauthorized');
    const memberRead = await services.read.execute(envelope(prepared, 'member'));
    expect(memberRead.kind).toBe('unauthorized');
    expect(await calculationCount(prepared.organizationId, prepared.findingId)).toBe(0);
    expect(await auditCount(prepared.organizationId, 'priority.calculated')).toBe(0);

    const foreignOrg = await createOrg(prisma, `foreign-${randomUUID().slice(0, 8)}`);
    const foreignUser = await prisma.user.create({
      data: {
        email: `foreign-${randomUUID().slice(0, 8)}@synthetic.patchpilot.test`,
        displayName: 'Foreign owner',
      },
    });
    const foreignMembership = await prisma.membership.create({
      data: { organizationId: foreignOrg.id, userId: foreignUser.id, role: 'owner' },
    });
    const foreignInput = {
      actor: {
        userId: foreignUser.id,
        sessionId: SESSION_ID,
        organizationId: foreignOrg.id,
        membershipId: foreignMembership.id,
        role: 'owner' as const,
      },
      command: { findingId: prepared.findingId },
    };
    expect((await services.calculate.execute(foreignInput)).kind).toBe('not_found');
    expect((await services.read.execute(foreignInput)).kind).toBe('not_found');
    expect(await calculationCount(prepared.organizationId, prepared.findingId)).toBe(0);
    expect(await calculationCount(foreignOrg.id)).toBe(0);
    expect(await auditCount(prepared.organizationId, 'priority.calculated')).toBe(0);
    expect(await auditCount(foreignOrg.id, 'priority.calculated')).toBe(0);
  });

  it('writes nothing for a non-active membership and does not publish an override', async () => {
    const prepared = await prepareFinding('revoked-membership');
    await prisma.membership.update({
      where: { id: prepared.membershipId },
      data: { status: 'revoked', revokedAt: new Date('2026-11-03T00:00:00.000Z') },
    });
    const calculated = await services.calculate.execute(envelope(prepared));
    expect(calculated).toEqual({ kind: 'unauthorized' });
    expect(await calculationCount(prepared.organizationId, prepared.findingId)).toBe(0);
    expect(await auditCount(prepared.organizationId, 'priority.calculated')).toBe(0);

    const published = await services.publish.execute(
      publishEnvelope(prepared, weightOverride(35, 25)),
    );
    expect(published).toEqual({ kind: 'membership_not_found' });
    expect(
      await prisma.riskPolicy.count({
        where: { organizationId: prepared.organizationId, policyKey: 'patchpilot.builtin.v0' },
      }),
    ).toBe(0);
    expect(await auditCount(prepared.organizationId, 'risk_policy.published')).toBe(0);
    expect(await calculationCount(prepared.organizationId, prepared.findingId)).toBe(0);
    expect(await auditCount(prepared.organizationId, 'priority.calculated')).toBe(0);
  });

  it('keeps one row when identical evaluations race', async () => {
    const prepared = await prepareFinding('race');
    const input = envelope(prepared);
    const [left, right] = await race(
      () => services.calculate.execute(input),
      () => services.calculate.execute(input),
    );
    expect([left.kind, right.kind].sort(), JSON.stringify([left, right])).toEqual([
      'calculated',
      'replayed',
    ]);
    expect(await calculationCount(prepared.organizationId, prepared.findingId)).toBe(1);
    expect(await auditCount(prepared.organizationId, 'priority.calculated')).toBe(1);
    const row = await prisma.riskCalculation.findFirstOrThrow({
      where: { organizationId: prepared.organizationId, findingId: prepared.findingId },
    });
    expect(row.calculationReason).toBe('initial');
    await expectFindingUntouched(prepared.organizationId, prepared.findingId);
  });

  it('rejects update and delete and leaves no partial audit on fingerprint conflict', async () => {
    const prepared = await prepareFinding('append-only');
    const calculated = await services.calculate.execute(envelope(prepared));
    expect(calculated.kind).toBe('calculated');
    if (calculated.kind !== 'calculated') {
      return;
    }
    const before = await rowSnapshot(calculated.calculation.id);
    await expect(
      prisma.riskCalculation.update({
        where: { id: calculated.calculation.id },
        data: { policyVersion: calculated.calculation.policyVersion },
      }),
    ).rejects.toThrow(/append-only/);
    await expect(
      prisma.riskCalculation.delete({ where: { id: calculated.calculation.id } }),
    ).rejects.toThrow(/append-only/);
    expect(await rowSnapshot(calculated.calculation.id)).toEqual(before);

    const calculations = await calculationCount(prepared.organizationId, prepared.findingId);
    const audits = await auditCount(prepared.organizationId, 'priority.calculated');
    const mutated = JSON.parse(JSON.stringify(calculated.calculation.result)) as {
      priority: number;
    };
    mutated.priority =
      calculated.calculation.result.priority === 0 ? 1 : calculated.calculation.result.priority - 1;
    const conflict = await createRiskCalculationPersistence(prisma).persist({
      organizationId: prepared.organizationId,
      actorUserId: prepared.userId,
      membershipId: prepared.membershipId,
      findingId: prepared.findingId,
      riskPolicyId: calculated.calculation.riskPolicyId,
      policyDefinitionSha256: calculated.calculation.policyDefinitionSha256,
      inputFingerprint: calculated.calculation.inputFingerprint,
      calculationReason: calculated.calculation.calculationReason,
      factors: calculated.calculation.factors,
      result: mutated,
      correlationId: randomUUID(),
      calculatedAt: calculated.calculation.calculatedAt,
    });
    expect(conflict.kind).toBe('immutable_conflict');
    expect(await calculationCount(prepared.organizationId, prepared.findingId)).toBe(calculations);
    expect(await auditCount(prepared.organizationId, 'priority.calculated')).toBe(audits);
    expect(await rowSnapshot(calculated.calculation.id)).toEqual(before);
  });

  it('rolls back the calculation when the priority audit insert fails', async () => {
    const prepared = await prepareFinding('audit-rollback');
    const calculations = await calculationCount(prepared.organizationId, prepared.findingId);
    const audits = await auditCount(prepared.organizationId, 'priority.calculated');
    await prisma.$executeRawUnsafe(`
      ALTER TABLE "audit_event"
      ADD CONSTRAINT "priority_calculated_audit_rollback"
      CHECK ("action" <> 'priority.calculated') NOT VALID
    `);
    try {
      const result = await services.calculate.execute(envelope(prepared));
      expect(result.kind === 'unavailable' || result.kind === 'internal_failure').toBe(true);
      expect(await calculationCount(prepared.organizationId, prepared.findingId)).toBe(
        calculations,
      );
      expect(await auditCount(prepared.organizationId, 'priority.calculated')).toBe(audits);
      await expectFindingUntouched(prepared.organizationId, prepared.findingId);
    } finally {
      await prisma.$executeRawUnsafe(`
        ALTER TABLE "audit_event"
        DROP CONSTRAINT IF EXISTS "priority_calculated_audit_rollback"
      `);
    }
  });

  it('appends a second calculation when a new KEV generation corrects membership', async () => {
    const cve = nextCve();
    const replacement = nextCve();
    const prepared = await prepareFinding('corrected', cve);
    await activateCatalog([cve]);
    const first = await services.calculate.execute(envelope(prepared));
    expect(first.kind).toBe('calculated');
    if (first.kind !== 'calculated') {
      return;
    }
    expect(factor(first.calculation, 'kev_listed').observedValue).toBe('listed_catalog_current');
    const before = await rowSnapshot(first.calculation.id);
    await activateCatalog([replacement]);
    const second = await services.calculate.execute(envelope(prepared));
    expect(second.kind).toBe('calculated');
    if (second.kind !== 'calculated') {
      return;
    }
    expect(second.calculation.calculationReason).toBe('intel_refresh');
    expect(factor(second.calculation, 'kev_listed').observedValue).toBe(
      'not_listed_catalog_current',
    );
    expect(await rowSnapshot(first.calculation.id)).toEqual(before);
    assertMatchesEngine(
      second.calculation,
      validatedBuiltin(),
      await factsFor(
        second.calculation,
        { state: 'observed', value: 'not_listed_catalog_current' },
        'unknown',
      ),
    );
    expect(await calculationCount(prepared.organizationId, prepared.findingId)).toBe(2);
    await expectFindingUntouched(prepared.organizationId, prepared.findingId);
  });

  it('reads the latest calculation by calculatedAt then id without writing', async () => {
    const prepared = await prepareFinding('current');
    const emptyAudits = await auditCount(prepared.organizationId, 'priority.calculated');
    const absent = await services.read.execute(envelope(prepared));
    expect(absent.kind).toBe('not_found');
    expect(await calculationCount(prepared.organizationId, prepared.findingId)).toBe(0);
    expect(await auditCount(prepared.organizationId, 'priority.calculated')).toBe(emptyAudits);

    const first = await services.calculate.execute(envelope(prepared));
    expect(first.kind).toBe('calculated');
    await prisma.asset.update({
      where: { id: prepared.assetId },
      data: { internetExposure: 'internet_facing' },
    });
    const second = await services.calculate.execute(envelope(prepared));
    expect(second.kind).toBe('calculated');
    if (second.kind !== 'calculated') {
      return;
    }
    const audits = await auditCount(prepared.organizationId, 'priority.calculated');
    const calculations = await calculationCount(prepared.organizationId, prepared.findingId);
    const expectedId = await currentCalculationId(prepared.organizationId, prepared.findingId);
    const current = await services.read.execute(envelope(prepared));
    expect(current.kind).toBe('found');
    if (current.kind !== 'found') {
      return;
    }
    expect(current.calculation.id).toBe(expectedId);
    expect(current.calculation.id).toBe(second.calculation.id);
    expect(await auditCount(prepared.organizationId, 'priority.calculated')).toBe(audits);
    expect(await calculationCount(prepared.organizationId, prepared.findingId)).toBe(calculations);

    await prisma.$executeRaw`
      INSERT INTO "risk_calculation" (
        "id",
        "organization_id",
        "finding_id",
        "risk_policy_id",
        "policy_version",
        "policy_definition_sha256",
        "calculated_at",
        "factors",
        "result",
        "calculation_engine_version",
        "calculation_reason",
        "input_fingerprint"
      )
      SELECT
        ${TIE_ID}::uuid,
        "organization_id",
        "finding_id",
        "risk_policy_id",
        "policy_version",
        "policy_definition_sha256",
        "calculated_at",
        "factors",
        "result",
        "calculation_engine_version",
        'rescan'::"risk_calculation_reason",
        ${digest(`tie:${prepared.findingId}`)}
      FROM "risk_calculation"
      WHERE "id" = ${second.calculation.id}::uuid
    `;
    expect(await currentCalculationId(prepared.organizationId, prepared.findingId)).toBe(TIE_ID);
    const tied = await services.read.execute(envelope(prepared));
    expect(tied.kind).toBe('found');
    if (tied.kind !== 'found') {
      return;
    }
    expect(tied.calculation.id).toBe(TIE_ID);
    expect(await auditCount(prepared.organizationId, 'priority.calculated')).toBe(audits);
    expect(await calculationCount(prepared.organizationId, prepared.findingId)).toBe(
      calculations + 1,
    );
  });

  it('projects inspection when the calculation count is positive and the pointer is null', () => {
    const projection = projectFindingInspection(inspectionBundle(2), INSPECTION_FINDING_ID);
    expect(projection.status).toBe('found');
    if (projection.status !== 'found') {
      return;
    }
    expect(projection.projection.state).toBe('open');
    expect(projection.projection).not.toHaveProperty('priority');
    expect(projection.projection).not.toHaveProperty('priorityBand');
    expect(projection.projection).not.toHaveProperty('riskCalculationCount');
    expect(projection.projection).not.toHaveProperty('currentRiskCalculationId');
    expect(projection.projection).not.toHaveProperty('dueAt');
  });
});

const INSPECTION_FINDING_ID = '11111111-1111-4111-8111-111111111111';
const INSPECTION_ASSET_ID = '22222222-2222-4222-8222-222222222222';
const INSPECTION_COMPONENT_ID = '33333333-3333-4333-8333-333333333333';
const INSPECTION_VULNERABILITY_ID = '44444444-4444-4444-8444-444444444444';
const INSPECTION_OBSERVATION_ID = '55555555-5555-4555-8555-555555555555';
const INSPECTION_INGESTION_ID = '66666666-6666-4666-8666-666666666666';

function inspectionLink(index: number, version: string) {
  const suffix = index.toString(16).padStart(12, '0');
  return {
    evidenceId: `77777777-7777-4777-8777-${suffix}`,
    findingObservationId: INSPECTION_OBSERVATION_ID,
    assetId: INSPECTION_ASSET_ID,
    componentId: INSPECTION_COMPONENT_ID,
    vulnerabilityId: INSPECTION_VULNERABILITY_ID,
    sbomIngestionId: INSPECTION_INGESTION_ID,
    componentOccurrenceId: `88888888-8888-4888-8888-${suffix}`,
    linkOutcome: 'affected' as const,
    evidencePresent: true,
    evidenceTargetAligned: true,
    evidenceOutcome: 'affected' as const,
    productOrigin: 'maintainer_reviewed_advisory' as const,
    evaluatorId: 'osv_first_ecosystem_affected_version_evaluator_v1',
    evaluatorVersion: 'session_14_batch_2_in_memory',
    matchingPolicyId: 'osv_first_ecosystem_matching_architecture_v1',
    matchingPolicyVersion: 'osv_first_ecosystem_matching_architecture_v1',
    productEvidencePolicyId: 'product_match_evaluation_policy_v1',
    productEvidencePolicyVersion: 1,
    evidenceSchemaVersion: 'product_match_evaluation_evidence_v1',
    findingCreation: 'unavailable' as const,
    suppressionAuthority: false,
    rawObservedVersion: version,
    occurrencePresent: true,
    occurrenceVersion: version,
    occurrenceVersionKnown: true,
    occurrenceAssetId: INSPECTION_ASSET_ID,
    occurrenceComponentId: INSPECTION_COMPONENT_ID,
    occurrenceIngestionId: INSPECTION_INGESTION_ID,
    revisionPresent: true,
    withdrawal: 'not_withdrawn' as const,
    quarantine: 'not_quarantined' as const,
    hasSuccessor: false,
    approvalPresent: true,
    approvalPurpose: 'approve_maintainer_reviewed_advisory_for_product_evaluation',
    approvalRevisionMatches: true,
    approvalVulnerabilityMatches: true,
    bindingPresent: true,
    bindingReviewed: true,
    normalizationVersion: '2',
    ingestionState: 'completed' as const,
    ingestionPresent: true,
    explanationCodes: ['affected_within_introduced_fixed_range' as const],
  };
}

function inspectionBundle(riskCalculationCount: number) {
  const links = ['1.2.0'].map((version, index) => inspectionLink(index + 1, version));
  return {
    findingId: INSPECTION_FINDING_ID,
    state: 'open' as const,
    createdAt: '2026-10-06T16:00:00.000Z',
    assetId: INSPECTION_ASSET_ID,
    componentId: INSPECTION_COMPONENT_ID,
    vulnerabilityId: INSPECTION_VULNERABILITY_ID,
    componentOccurrenceId: null,
    resolvedAt: null,
    reopenedAt: null,
    assignedMembershipId: null,
    assignedTeamId: null,
    dueAt: null,
    currentRiskCalculationId: null,
    version: 1,
    assetPresent: true,
    assetDisplayName: 'asset <untrusted>',
    assetCurrentIngestionId: INSPECTION_INGESTION_ID,
    componentPresent: true,
    componentEcosystem: 'npm' as const,
    componentNamespace: null,
    componentName: 'widget <untrusted>',
    vulnerabilityPresent: true,
    vulnerabilityPublicId: 'REVIEWED-NPM-1',
    remediationTaskCount: 0,
    riskAcceptanceCount: 0,
    riskCalculationCount,
    genericEvidenceCount: 0,
    creationIngestionOccurrenceCount: links.length,
    otherOccurrenceCount: 0,
    observations: [
      {
        id: INSPECTION_OBSERVATION_ID,
        sbomIngestionId: INSPECTION_INGESTION_ID,
        occurrenceId: null,
        result: 'present' as const,
        method: 'controlled_finding_creation' as const,
        transitionClassification: 'initial_creation' as const,
        creationPurpose: 'create_finding_from_product_match_evidence' as const,
        creationPolicyId: 'finding_creation_policy_v1',
        creationPolicyVersion: 1,
        affectedEvidenceCount: links.length,
        replayAgrees: true,
        evidenceRecordAgrees: true,
      },
    ],
    links,
  };
}
