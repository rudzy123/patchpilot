/**
 * Disposable PostgreSQL proof for controlled Finding creation.
 * The evaluator runs only while seeding Product Match Evidence.
 * The creation transaction does not call a provider or an evaluator.
 */

import { createHash, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { PrismaClient } from '@prisma/client';
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
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
  issueFindingCreationAuthorization,
  openFindingCreationCommand,
} from '../../domain/dist/findings/controlled-creation/authorization.js';
import { createControlledFindingCreationPersistence } from './controlled-finding-creation-persistence.js';
import {
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
} from './integration-database.js';
import { createProductMatchEvaluationPersistence } from './product-match-evaluation-persistence.js';
import { createApprovalCapabilityHarness } from './reviewer-capability-approval-harness.js';
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

let prisma: PrismaClient;
let database: Awaited<ReturnType<typeof createEphemeralDatabase>>;

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

async function lineage(organizationId: string) {
  const [findings, observations, links, audits, evidence] = await Promise.all([
    prisma.finding.count({ where: { organizationId } }),
    prisma.findingObservation.count({ where: { organizationId } }),
    prisma.findingCreationEvidenceLink.count({ where: { organizationId } }),
    prisma.auditEvent.count({ where: { organizationId, action: 'finding.created' } }),
    prisma.productMatchEvaluationEvidence.count({ where: { organizationId } }),
  ]);
  return { findings, observations, links, audits, evidence };
}

async function completeIngestion(
  ingestionId: string,
  assetId: string,
  normalizationVersion: '1' | '2',
  componentCount: number,
): Promise<void> {
  await prisma.sbomIngestion.update({
    where: { id: ingestionId },
    data: {
      state: 'completed',
      normalizationVersion,
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
  normalizationVersion: '1' | '2' = '2',
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
  const org = await createOrg(prisma, `${label}-${randomUUID().slice(0, 8)}`);
  const user = await prisma.user.create({
    data: {
      email: `${label}-${randomUUID().slice(0, 8)}@synthetic.patchpilot.test`,
      displayName: label,
    },
  });
  const membership = await prisma.membership.create({
    data: { organizationId: org.id, userId: user.id, role: 'member' },
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
      occurrenceId: occurrence.id,
      version: version.version,
    });
  }
  await completeIngestion(ingestion.id, asset.id, normalizationVersion, versions.length);
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

function affectedIds(seeded: SeededTarget): string[] {
  return seeded.evidence
    .filter((row) => row.outcome === 'affected')
    .map((row) => row.evidenceId)
    .sort(compareUuid);
}

function seal(
  seeded: Pick<
    SeededTarget,
    | 'organizationId'
    | 'actorId'
    | 'membershipId'
    | 'assetId'
    | 'componentId'
    | 'vulnerabilityId'
    | 'ingestionId'
  >,
  evidenceIds: readonly string[],
  correlationId = randomUUID(),
  ingestionId = seeded.ingestionId,
) {
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
    sbomIngestionId: ingestionId,
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
    expectedSbomIngestionId: ingestionId,
    expectedProductMatchEvidenceIds: [...evidenceIds],
    correlationId,
    authorization: issued.authorization,
  });
  if (opened.status !== 'authorized') {
    throw new Error(`command was ${opened.status}`);
  }
  return { trustedContext, command: opened.command };
}

beforeAll(async () => {
  database = await createEphemeralDatabase('migrate');
  await deployMigrations(database.databaseUrl);
  prisma = new PrismaClient({ datasources: { db: { url: database.databaseUrl } } });
});

afterAll(async () => {
  await prisma.$disconnect();
  await dropEphemeralDatabase(database.admin, database.databaseName);
});

describe('controlled finding creation persistence', () => {
  it('creates one open Finding, one observation, one link, and one audit event', async () => {
    const seeded = await seedTarget('one', [{ version: '1.1.0', bomRef: 'component-1' }]);
    const before = await lineage(seeded.organizationId);
    const sealed = seal(seeded, affectedIds(seeded));
    const created = await writer().apply(sealed);
    expect(created).toMatchObject({
      status: 'created',
      writesPerformed: true,
      observationAdded: true,
      auditEventAdded: true,
      timestampChanged: false,
      foreignResourceRevealed: false,
      authorityCreated: false,
    });
    expect(created).not.toHaveProperty('findingId');
    const after = await lineage(seeded.organizationId);
    expect(after).toEqual({
      findings: 1,
      observations: 1,
      links: 1,
      audits: 1,
      evidence: before.evidence,
    });
    const finding = await prisma.finding.findFirstOrThrow({
      where: { organizationId: seeded.organizationId },
    });
    expect(finding.state).toBe('open');
    expect(finding.componentOccurrenceId).toBeNull();
    expect(finding.resolvedAt).toBeNull();
    expect(finding.reopenedAt).toBeNull();
    expect(finding.assignedMembershipId).toBeNull();
    expect(finding.assignedTeamId).toBeNull();
    expect(finding.dueAt).toBeNull();
    expect(finding.currentRiskCalculationId).toBeNull();
    expect(finding.version).toBe(1);
    expect(finding.firstObservedAt.toISOString()).toBe(finding.createdAt.toISOString());
    expect(finding.lastObservedAt.toISOString()).toBe(finding.createdAt.toISOString());
    expect(finding.updatedAt.toISOString()).toBe(finding.createdAt.toISOString());
    const observation = await prisma.findingObservation.findFirstOrThrow({
      where: { organizationId: seeded.organizationId, findingId: finding.id },
    });
    expect(observation.method).toBe('controlled_finding_creation');
    expect(observation.occurrenceId).toBeNull();
    expect(observation.transitionClassification).toBe('initial_creation');
    expect(observation.observedAt.toISOString()).toBe(finding.createdAt.toISOString());
    const evidence = observation.evidence as Record<string, unknown>;
    expect(evidence['schemaVersion']).toBe('finding_creation_observation_v1');
    expect(evidence).not.toHaveProperty('risk');
    expect(evidence).not.toHaveProperty('priority');
    expect(evidence).not.toHaveProperty('explanation');
    const links = await prisma.findingCreationEvidenceLink.findMany({
      where: { organizationId: seeded.organizationId },
    });
    expect(links.map((link) => link.productMatchEvaluationEvidenceId)).toEqual(affectedIds(seeded));
    expect(links.every((link) => link.outcome === 'affected')).toBe(true);
  });

  it('links every affected version to one Finding and leaves an unaffected version unlinked', async () => {
    const seeded = await seedTarget('versions', [
      { version: '1.1.0', bomRef: 'component-1' },
      { version: '1.2.0', bomRef: 'component-2' },
      { version: '3.0.0', bomRef: 'component-3' },
    ]);
    expect(seeded.evidence.map((row) => row.outcome).sort()).toEqual([
      'affected',
      'affected',
      'unaffected',
    ]);
    const mixed = await writer().apply(
      seal(seeded, seeded.evidence.map((row) => row.evidenceId).sort(compareUuid)),
    );
    expect(mixed.status).toBe('evidence_not_affected');
    expect((await lineage(seeded.organizationId)).findings).toBe(0);
    const created = await writer().apply(seal(seeded, affectedIds(seeded)));
    expect(created.status).toBe('created');
    const counts = await lineage(seeded.organizationId);
    expect(counts.findings).toBe(1);
    expect(counts.links).toBe(2);
    expect(counts.evidence).toBe(3);
  });

  it('creates two Findings when the same Component is on two assets', async () => {
    const first = await seedTarget('asset-a', [{ version: '1.1.0', bomRef: 'component-1' }]);
    const secondAsset = await createAsset(prisma, first.organizationId, 'asset-b');
    const sbomSha = digest(`sbom:asset-b:${randomUUID()}`);
    const sbom = await createSbom(prisma, {
      organizationId: first.organizationId,
      assetId: secondAsset.id,
      sha256: sbomSha,
      receivedAt: new Date('2026-10-03T12:00:00.000Z'),
    });
    const ingestion = await createProcessingIngestion(prisma, {
      organizationId: first.organizationId,
      sbomId: sbom.id,
      assetId: secondAsset.id,
    });
    const occurrence = await prisma.componentOccurrence.create({
      data: {
        organizationId: first.organizationId,
        assetId: secondAsset.id,
        sbomId: sbom.id,
        sbomIngestionId: ingestion.id,
        componentId: first.componentId,
        bomRef: 'component-1',
        version: '1.1.0',
        versionKnown: true,
        isDirect: true,
      },
    });
    const firstEvidenceId = first.evidence[0]?.evidenceId;
    if (firstEvidenceId === undefined) {
      throw new Error('first evidence missing');
    }
    const firstEvidence = await prisma.productMatchEvaluationEvidence.findFirstOrThrow({
      where: { id: firstEvidenceId },
    });
    const executed = await composition().execute({
      commandSchemaVersion: PRODUCT_MATCH_EVALUATION_COMMAND_SCHEMA_VERSION,
      organizationId: first.organizationId,
      componentOccurrenceId: occurrence.id,
      expectedComponentEvidenceFingerprint: componentEvidenceFingerprint({
        organizationId: first.organizationId,
        componentOccurrenceId: occurrence.id,
        assetId: secondAsset.id,
        sbomId: sbom.id,
        sbomIngestionId: ingestion.id,
        componentId: first.componentId,
        componentIdentityKey: firstEvidence.componentIdentityKey,
        ecosystem: 'npm',
        namespace: null,
        name: PACKAGE_NAME,
        rawObservedVersion: '1.1.0',
        versionKnown: true,
        sbomSha256: sbomSha,
      }),
      expectedNpmPackageIdentity: packageIdentity(),
      expectedRawObservedVersion: '1.1.0',
      advisoryRevisionId: firstEvidence.advisoryRevisionId,
      approvalEvidenceId: firstEvidence.approvalId,
      expectedContentFingerprint: firstEvidence.contentFingerprint,
      expectedRangeFingerprint: firstEvidence.rangeFingerprint,
      expectedVulnerabilityId: first.vulnerabilityId,
      evaluatorId: PRODUCT_MATCH_EVALUATOR_ID,
      evaluatorVersion: PRODUCT_MATCH_EVALUATOR_VERSION,
      matchingPolicyId: PRODUCT_MATCH_MATCHING_POLICY_ID,
      matchingPolicyVersion: PRODUCT_MATCH_MATCHING_POLICY_VERSION,
      productEvidencePolicyId: PRODUCT_MATCH_EVALUATION_POLICY_ID,
      productEvidencePolicyVersion: PRODUCT_MATCH_EVALUATION_POLICY_VERSION,
      correlationId: randomUUID(),
    });
    if (executed.kind !== 'recorded') {
      throw new Error(`second asset evaluation was ${executed.kind}`);
    }
    await completeIngestion(ingestion.id, secondAsset.id, '2', 1);
    const second = {
      ...first,
      assetId: secondAsset.id,
      ingestionId: ingestion.id,
      evidence: [
        {
          evidenceId: executed.projection.matchEvidenceId,
          outcome: executed.projection.outcome,
          occurrenceId: occurrence.id,
          version: '1.1.0',
        },
      ],
    };
    expect((await writer().apply(seal(first, affectedIds(first)))).status).toBe('created');
    expect((await writer().apply(seal(second, affectedIds(second)))).status).toBe('created');
    expect(await prisma.finding.count({ where: { organizationId: first.organizationId } })).toBe(2);
  });

  it('replays an exact command with zero writes, including a different correlation', async () => {
    const seeded = await seedTarget('replay', [{ version: '1.1.0', bomRef: 'component-1' }]);
    const sealed = seal(seeded, affectedIds(seeded));
    expect((await writer().apply(sealed)).status).toBe('created');
    const before = await lineage(seeded.organizationId);
    const finding = await prisma.finding.findFirstOrThrow({
      where: { organizationId: seeded.organizationId },
    });
    const replay = await writer().apply(sealed);
    expect(replay).toMatchObject({
      status: 'already_applied',
      writesPerformed: false,
      observationAdded: false,
      auditEventAdded: false,
      timestampChanged: false,
    });
    const otherCorrelation = seal(seeded, affectedIds(seeded), randomUUID());
    expect((await writer().apply(otherCorrelation)).status).toBe('already_applied');
    expect(await lineage(seeded.organizationId)).toEqual(before);
    const stored = await prisma.finding.findFirstOrThrow({ where: { id: finding.id } });
    expect(stored.updatedAt.toISOString()).toBe(finding.updatedAt.toISOString());
    expect(stored.createdAt.toISOString()).toBe(finding.createdAt.toISOString());
  });

  it('converges concurrent identical commands and keeps a conflicting command from writing', async () => {
    const seeded = await seedTarget('concurrent', [
      { version: '1.1.0', bomRef: 'component-1' },
      { version: '1.2.0', bomRef: 'component-2' },
    ]);
    const full = seal(seeded, affectedIds(seeded));
    const duplicate = seal(seeded, affectedIds(seeded));
    const [first, second] = await Promise.all([writer().apply(full), writer().apply(duplicate)]);
    expect([first.status, second.status].sort()).toEqual(['already_applied', 'created']);
    const subset = seal(seeded, affectedIds(seeded).slice(0, 1));
    const conflict = await writer().apply(subset);
    expect(conflict.status).toBe('immutable_conflict');
    expect(conflict.writesPerformed).toBe(false);
    const counts = await lineage(seeded.organizationId);
    expect(counts).toMatchObject({ findings: 1, observations: 1, links: 2, audits: 1 });
  });

  it('classifies an existing Finding under another ingestion without writing', async () => {
    const seeded = await seedTarget('other-ingestion', [
      { version: '1.1.0', bomRef: 'component-1' },
    ]);
    expect((await writer().apply(seal(seeded, affectedIds(seeded)))).status).toBe('created');
    const before = await lineage(seeded.organizationId);
    const other = seal(seeded, affectedIds(seeded), randomUUID(), randomUUID());
    const result = await writer().apply(other);
    expect(result.status).toBe('finding_already_exists');
    expect(result.writesPerformed).toBe(false);
    expect(await lineage(seeded.organizationId)).toEqual(before);
  });

  it('returns the same not_found result for foreign and absent evidence', async () => {
    const local = await seedTarget('local', [{ version: '1.1.0', bomRef: 'component-1' }]);
    const foreign = await seedTarget('foreign', [{ version: '1.1.0', bomRef: 'component-1' }]);
    const foreignId = foreign.evidence[0]?.evidenceId;
    if (foreignId === undefined) {
      throw new Error('foreign evidence missing');
    }
    const foreignResult = await writer().apply(seal(local, [foreignId].sort(compareUuid)));
    const absentResult = await writer().apply(seal(local, [randomUUID()]));
    expect(foreignResult).toEqual(absentResult);
    expect(foreignResult.status).toBe('not_found');
    expect(JSON.stringify(foreignResult)).not.toContain(foreign.organizationId);
    expect(await lineage(local.organizationId)).toMatchObject({ findings: 0, audits: 0 });
    expect(await lineage(foreign.organizationId)).toMatchObject({ findings: 0 });
  });

  it('rejects an incomplete set, a stale ingestion, normalization version 1, and malformed evidence', async () => {
    const pair = await seedTarget('incomplete', [
      { version: '1.1.0', bomRef: 'component-1' },
      { version: '1.2.0', bomRef: 'component-2' },
    ]);
    const incomplete = await writer().apply(seal(pair, affectedIds(pair).slice(0, 1)));
    expect(incomplete.status).toBe('evidence_set_mismatch');
    expect((await lineage(pair.organizationId)).findings).toBe(0);

    const stale = await seedTarget('stale', [{ version: '1.1.0', bomRef: 'component-1' }]);
    const later = await createProcessingIngestion(prisma, {
      organizationId: stale.organizationId,
      sbomId: stale.sbomId,
      assetId: stale.assetId,
    });
    await completeIngestion(later.id, stale.assetId, '2', 1);
    expect((await writer().apply(seal(stale, affectedIds(stale)))).status).toBe(
      'evidence_not_current',
    );
    expect((await lineage(stale.organizationId)).findings).toBe(0);

    const legacy = await seedTarget('norm-1', [{ version: '1.1.0', bomRef: 'component-1' }], '1');
    expect((await writer().apply(seal(legacy, affectedIds(legacy)))).status).toBe(
      'evidence_not_eligible',
    );

    const malformed = await seedTarget('malformed', [{ version: '1.1.0', bomRef: 'component-1' }]);
    const malformedOccurrenceId = malformed.evidence[0]?.occurrenceId;
    if (malformedOccurrenceId === undefined) {
      throw new Error('malformed occurrence missing');
    }
    await prisma.componentOccurrence.update({
      where: { id: malformedOccurrenceId },
      data: { versionKnown: false, version: '' },
    });
    expect((await writer().apply(seal(malformed, affectedIds(malformed)))).status).toBe(
      'malformed_persisted_state',
    );
    expect((await lineage(malformed.organizationId)).findings).toBe(0);
  });

  it('rolls back every insert stage and a deferred incomplete evidence set', async () => {
    const seeded = await seedTarget('rollback', [
      { version: '1.1.0', bomRef: 'component-1' },
      { version: '1.2.0', bomRef: 'component-2' },
    ]);
    for (const fault of [
      'before_finding_insert',
      'before_observation_insert',
      'before_evidence_link_insert',
      'before_audit_insert',
    ] as const) {
      const result = await writer().apply({ ...seal(seeded, affectedIds(seeded)), fault });
      expect(result.status).toBe('transaction_aborted');
      expect(await lineage(seeded.organizationId)).toMatchObject({
        findings: 0,
        observations: 0,
        links: 0,
        audits: 0,
      });
    }
    const ids = affectedIds(seeded);
    const one = ids[0];
    if (one === undefined) {
      throw new Error('evidence missing');
    }
    const evidenceRow = await prisma.productMatchEvaluationEvidence.findFirstOrThrow({
      where: { id: one },
    });
    await expect(
      prisma.$transaction(async (tx) => {
        await tx.$queryRaw`SELECT set_config('patchpilot.controlled_finding_creation', 'on', true)`;
        const inserted = await tx.$queryRaw<Array<{ id: string }>>`
          INSERT INTO "finding" (
            "organization_id", "asset_id", "vulnerability_id", "component_id", "state",
            "first_observed_at", "last_observed_at", "version", "created_at", "updated_at"
          ) VALUES (
            ${seeded.organizationId}::uuid, ${seeded.assetId}::uuid, ${seeded.vulnerabilityId}::uuid,
            ${seeded.componentId}::uuid, 'open', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 1,
            CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
          ) RETURNING "id"::text AS id
        `;
        const findingId = inserted[0]?.id;
        const fingerprint = 'ab'.repeat(32);
        const observation = await tx.$queryRaw<Array<{ id: string }>>`
          INSERT INTO "finding_observation" (
            "organization_id", "finding_id", "sbom_id", "sbom_ingestion_id", "occurrence_id",
            "result", "method", "observed_at", "evidence", "created_at",
            "transition_classification", "creation_purpose", "creation_policy_id",
            "creation_policy_version", "actor_membership_id", "correlation_id",
            "replay_fingerprint", "affected_evidence_count"
          ) VALUES (
            ${seeded.organizationId}::uuid, ${findingId}::uuid, ${evidenceRow.sbomId}::uuid,
            ${seeded.ingestionId}::uuid, NULL, 'present', 'controlled_finding_creation',
            CURRENT_TIMESTAMP,
            jsonb_build_object(
              'schemaVersion', 'finding_creation_observation_v1',
              'transition', 'initial_creation',
              'purpose', 'create_finding_from_product_match_evidence',
              'policyId', 'finding_creation_policy_v1',
              'policyVersion', 1,
              'affectedEvidenceCount', 1,
              'evidenceSetFingerprint', ${fingerprint}
            ),
            CURRENT_TIMESTAMP, 'initial_creation', 'create_finding_from_product_match_evidence',
            'finding_creation_policy_v1', 1, ${seeded.membershipId}::uuid, ${randomUUID()}::uuid,
            ${fingerprint}, 1
          ) RETURNING "id"::text AS id
        `;
        await tx.$executeRaw`
          INSERT INTO "finding_creation_evidence_link" (
            "organization_id", "finding_id", "finding_observation_id",
            "product_match_evaluation_evidence_id", "asset_id", "component_id",
            "vulnerability_id", "sbom_ingestion_id", "component_occurrence_id", "outcome",
            "created_at"
          ) VALUES (
            ${seeded.organizationId}::uuid, ${findingId}::uuid, ${observation[0]?.id}::uuid,
            ${one}::uuid, ${seeded.assetId}::uuid, ${seeded.componentId}::uuid,
            ${seeded.vulnerabilityId}::uuid, ${seeded.ingestionId}::uuid,
            ${evidenceRow.componentOccurrenceId}::uuid, 'affected', CURRENT_TIMESTAMP
          )
        `;
        await tx.$executeRaw`
          INSERT INTO "audit_event" (
            "organization_id", "actor_user_id", "actor_membership_id", "actor_type",
            "action", "subject_type", "subject_id", "correlation_id", "payload", "schema_version"
          ) VALUES (
            ${seeded.organizationId}::uuid, ${seeded.actorId}::uuid, ${seeded.membershipId}::uuid,
            'user', 'finding.created', 'finding', ${findingId}::uuid, ${randomUUID()},
            jsonb_build_object('schemaVersion', 1), 1
          )
        `;
      }),
    ).rejects.toThrow();
    expect(await lineage(seeded.organizationId)).toMatchObject({
      findings: 0,
      observations: 0,
      links: 0,
      audits: 0,
    });
  });

  it('rejects a caller timestamp and then replays after a skipped existing-row lookup', async () => {
    const seeded = await seedTarget('timestamp', [{ version: '1.1.0', bomRef: 'component-1' }]);
    await expect(
      prisma.$transaction(async (tx) => {
        await tx.$queryRaw`SELECT set_config('patchpilot.controlled_finding_creation', 'on', true)`;
        await tx.$executeRaw`
          INSERT INTO "finding" (
            "organization_id", "asset_id", "vulnerability_id", "component_id", "state",
            "first_observed_at", "last_observed_at", "version", "created_at", "updated_at"
          ) VALUES (
            ${seeded.organizationId}::uuid, ${seeded.assetId}::uuid, ${seeded.vulnerabilityId}::uuid,
            ${seeded.componentId}::uuid, 'open', '2020-01-01T00:00:00.000Z', CURRENT_TIMESTAMP, 1,
            CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
          )
        `;
      }),
    ).rejects.toThrow();
    expect((await lineage(seeded.organizationId)).findings).toBe(0);
    const sealed = seal(seeded, affectedIds(seeded));
    expect((await writer().apply(sealed)).status).toBe('created');
    const before = await lineage(seeded.organizationId);
    const uncertain = await writer().apply({ ...sealed, fault: 'skip_existing_lookup' });
    expect(uncertain.status).toBe('already_applied');
    expect(uncertain.writesPerformed).toBe(false);
    expect(await lineage(seeded.organizationId)).toEqual(before);
  });

  it('rejects Finding updates and deletes and keeps observations and links append-only', async () => {
    const seeded = await seedTarget('immutable', [{ version: '1.1.0', bomRef: 'component-1' }]);
    expect((await writer().apply(seal(seeded, affectedIds(seeded)))).status).toBe('created');
    const finding = await prisma.finding.findFirstOrThrow({
      where: { organizationId: seeded.organizationId },
    });
    const observation = await prisma.findingObservation.findFirstOrThrow({
      where: { findingId: finding.id },
    });
    const link = await prisma.findingCreationEvidenceLink.findFirstOrThrow({
      where: { findingId: finding.id },
    });
    await expect(
      prisma.finding.update({ where: { id: finding.id }, data: { version: 2 } }),
    ).rejects.toThrow();
    await expect(prisma.finding.delete({ where: { id: finding.id } })).rejects.toThrow();
    await expect(
      prisma.findingObservation.update({
        where: { id: observation.id },
        data: { method: 'exact_purl' },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.findingObservation.delete({ where: { id: observation.id } }),
    ).rejects.toThrow();
    await expect(
      prisma.findingCreationEvidenceLink.update({
        where: { id: link.id },
        data: { outcome: 'affected' },
      }),
    ).rejects.toThrow();
    await expect(
      prisma.findingCreationEvidenceLink.delete({ where: { id: link.id } }),
    ).rejects.toThrow();
    expect((await lineage(seeded.organizationId)).findings).toBe(1);
  });

  it('does not call a provider or evaluator and does not write Product Match Evidence', async () => {
    const source = readFileSync(
      path.join(
        path.dirname(fileURLToPath(import.meta.url)),
        'controlled-finding-creation-persistence.ts',
      ),
      'utf8',
    );
    expect(source).not.toContain('@patchpilot/vulnerability-intelligence');
    expect(source).not.toContain('fetch(');
    expect(source).not.toContain('evaluateReviewed');
    const seeded = await seedTarget('quiet', [{ version: '1.1.0', bomRef: 'component-1' }]);
    const before = await prisma.productMatchEvaluationEvidence.count();
    expect((await writer().apply(seal(seeded, affectedIds(seeded)))).status).toBe('created');
    expect(await prisma.productMatchEvaluationEvidence.count()).toBe(before);
  });

  it('rejects a Finding that has no creation observation and a later non-creation observation', async () => {
    const seeded = await seedTarget('bare', [{ version: '1.1.0', bomRef: 'component-1' }]);
    await expect(
      prisma.$transaction(async (tx) => {
        await tx.$queryRaw`SELECT set_config('patchpilot.controlled_finding_creation', 'on', true)`;
        await tx.$executeRaw`
          INSERT INTO "finding" (
            "organization_id", "asset_id", "vulnerability_id", "component_id", "state",
            "first_observed_at", "last_observed_at", "version", "created_at", "updated_at"
          ) VALUES (
            ${seeded.organizationId}::uuid, ${seeded.assetId}::uuid, ${seeded.vulnerabilityId}::uuid,
            ${seeded.componentId}::uuid, 'open', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 1,
            CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
          )
        `;
      }),
    ).rejects.toThrow();
    expect((await lineage(seeded.organizationId)).findings).toBe(0);
    expect((await writer().apply(seal(seeded, affectedIds(seeded)))).status).toBe('created');
    const finding = await prisma.finding.findFirstOrThrow({
      where: { organizationId: seeded.organizationId },
    });
    const observation = await prisma.findingObservation.findFirstOrThrow({
      where: { findingId: finding.id },
    });
    const before = await lineage(seeded.organizationId);
    await expect(
      prisma.findingObservation.create({
        data: {
          organizationId: seeded.organizationId,
          findingId: finding.id,
          sbomId: observation.sbomId,
          sbomIngestionId: observation.sbomIngestionId,
          result: 'present',
          method: 'exact_purl',
          observedAt: new Date(),
          evidence: { schemaVersion: 1 },
        },
      }),
    ).rejects.toThrow();
    expect(await lineage(seeded.organizationId)).toEqual(before);
    const replay = await writer().apply(seal(seeded, affectedIds(seeded)));
    expect(replay.status).toBe('already_applied');
    expect(replay.writesPerformed).toBe(false);
  });

  it('rejects creation without the sealed authorization', async () => {
    const seeded = await seedTarget('unsealed', [{ version: '1.1.0', bomRef: 'component-1' }]);
    const result = await writer().apply({
      trustedContext: {
        schemaVersion: FINDING_CREATION_TRUSTED_CONTEXT_SCHEMA_VERSION,
        organizationId: seeded.organizationId,
        actorId: seeded.actorId,
        membershipId: seeded.membershipId,
        membershipStatus: 'active',
        role: 'admin',
      },
      command: { role: 'admin', administrator: true },
    });
    expect(result.status).not.toBe('created');
    expect(result.writesPerformed).toBe(false);
    expect((await lineage(seeded.organizationId)).findings).toBe(0);
  });
});
