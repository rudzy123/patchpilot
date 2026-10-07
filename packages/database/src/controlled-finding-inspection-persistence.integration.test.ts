/**
 * Disposable PostgreSQL proof for controlled Finding inspection.
 * The read is organization scoped and does not mutate Finding lineage.
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
  FINDING_INSPECTION_AFFECTED_VERSION_DISPLAY_LIMIT,
  FINDING_INSPECTION_COMMAND_SCHEMA_VERSION,
  FINDING_INSPECTION_RESULT_SCHEMA_VERSION,
  FINDING_INSPECTION_TRUSTED_CONTEXT_SCHEMA_VERSION,
  openFindingInspection,
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
import { createControlledFindingInspectionPersistence } from './controlled-finding-inspection-persistence.js';
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

type VersionRequest = { readonly version: string; readonly bomRef: string };

type SeededTarget = {
  readonly organizationId: string;
  readonly actorId: string;
  readonly membershipId: string;
  readonly assetId: string;
  readonly assetName: string;
  readonly componentId: string;
  readonly vulnerabilityId: string;
  readonly vulnerabilityPublicId: string;
  readonly sbomId: string;
  readonly ingestionId: string;
  readonly revisionId: string;
  readonly findingId: string;
  readonly evidence: readonly { readonly evidenceId: string; readonly version: string }[];
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

function composition() {
  return createProductMatchEvaluationComposition({
    port: createProductMatchEvaluationPersistence(prisma),
  });
}

async function completeIngestion(ingestionId: string, assetId: string, componentCount: number) {
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
  unlinked: readonly VersionRequest[] = [],
): Promise<SeededTarget> {
  await restoreInspectionTriggers();
  const rangeFingerprint = session14RangeFingerprint(RANGES, []);
  const contentFingerprint = digest(`content:${label}:${randomUUID()}`);
  const advisoryId = `REVIEWNPM${digest(label).slice(0, 8).toUpperCase()}`;
  const familyDigest = digest(`family:${advisoryId}`);
  const revisionDigest = digest(`revision:${advisoryId}`);
  const authorIdentity = 'author.one';
  const vulnerabilityPublicId = `REVIEWED-${advisoryId}`;
  const vulnerability = await prisma.vulnerability.create({
    data: { osvId: vulnerabilityPublicId },
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
  const assetName = `asset-${label}`;
  const asset = await createAsset(prisma, org.id, assetName);
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
  const evidence: { evidenceId: string; version: string }[] = [];
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
    if (executed.kind !== 'recorded' || executed.projection.outcome !== 'affected') {
      throw new Error(`evaluation was ${executed.kind}`);
    }
    evidence.push({ evidenceId: executed.projection.matchEvidenceId, version: version.version });
  }
  for (const version of unlinked) {
    await prisma.componentOccurrence.create({
      data: {
        organizationId: org.id,
        assetId: asset.id,
        sbomId: sbom.id,
        sbomIngestionId: ingestion.id,
        componentId: component.id,
        bomRef: version.bomRef,
        version: version.version,
        versionKnown: true,
        isDirect: false,
      },
    });
  }
  await completeIngestion(ingestion.id, asset.id, versions.length + unlinked.length);
  const evidenceIds = evidence.map((row) => row.evidenceId).sort(compareUuid);
  const correlationId = randomUUID();
  const trustedContext = {
    schemaVersion: FINDING_CREATION_TRUSTED_CONTEXT_SCHEMA_VERSION,
    organizationId: org.id,
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
    assetId: asset.id,
    componentId: component.id,
    vulnerabilityId: vulnerability.id,
    sbomIngestionId: ingestion.id,
    productMatchEvidenceIds: evidenceIds,
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
    expectedAssetId: asset.id,
    expectedComponentId: component.id,
    expectedVulnerabilityId: vulnerability.id,
    expectedSbomIngestionId: ingestion.id,
    expectedProductMatchEvidenceIds: evidenceIds,
    correlationId,
    authorization: issued.authorization,
  });
  if (opened.status !== 'authorized') {
    throw new Error(`command was ${opened.status}`);
  }
  const created = await createControlledFindingCreationPersistence(prisma).apply({
    trustedContext,
    command: opened.command,
  });
  if (created.status !== 'created') {
    throw new Error(`finding was ${created.status}`);
  }
  const finding = await prisma.finding.findFirstOrThrow({
    where: { organizationId: org.id, assetId: asset.id },
  });
  return {
    organizationId: org.id,
    actorId: user.id,
    membershipId: membership.id,
    assetId: asset.id,
    assetName,
    componentId: component.id,
    vulnerabilityId: vulnerability.id,
    vulnerabilityPublicId,
    sbomId: sbom.id,
    ingestionId: ingestion.id,
    revisionId: revision.id,
    findingId: finding.id,
    evidence,
  };
}

function median(values: readonly number[]): number {
  const sorted = [...values].sort((left, right) => left - right);
  const middle = Math.floor(sorted.length / 2);
  const upper = sorted[middle];
  const lower = sorted[middle - 1];
  if (upper === undefined) {
    return 0;
  }
  if (sorted.length % 2 === 1 || lower === undefined) {
    return upper;
  }
  return (lower + upper) / 2;
}

type RowStamp = {
  readonly table_name: string;
  readonly id: string;
  readonly xmin: string;
  readonly stamp: Date;
};

async function stamps(organizationId: string): Promise<RowStamp[]> {
  return prisma.$queryRaw<RowStamp[]>`
    SELECT 'finding'::text AS table_name, "id"::text AS id, "xmin"::text AS xmin, "updated_at" AS stamp
    FROM "finding"
    WHERE "organization_id" = ${organizationId}::uuid
    UNION ALL
    SELECT 'finding_observation', "id"::text, "xmin"::text, "created_at"
    FROM "finding_observation"
    WHERE "organization_id" = ${organizationId}::uuid
    UNION ALL
    SELECT 'finding_creation_evidence_link', "id"::text, "xmin"::text, "created_at"
    FROM "finding_creation_evidence_link"
    WHERE "organization_id" = ${organizationId}::uuid
    UNION ALL
    SELECT 'product_match_evaluation_evidence', "id"::text, "xmin"::text, "created_at"
    FROM "product_match_evaluation_evidence"
    WHERE "organization_id" = ${organizationId}::uuid
    UNION ALL
    SELECT 'audit_event', "id"::text, "xmin"::text, "occurred_at"
    FROM "audit_event"
    WHERE "organization_id" = ${organizationId}::uuid
    UNION ALL
    SELECT 'asset', "id"::text, "xmin"::text, "updated_at"
    FROM "asset"
    WHERE "organization_id" = ${organizationId}::uuid
    UNION ALL
    SELECT 'component_occurrence', "id"::text, "xmin"::text, "created_at"
    FROM "component_occurrence"
    WHERE "organization_id" = ${organizationId}::uuid
    UNION ALL
    SELECT 'sbom_ingestion', "id"::text, "xmin"::text, "created_at"
    FROM "sbom_ingestion"
    WHERE "organization_id" = ${organizationId}::uuid
    ORDER BY table_name, id
  `;
}

function findingSelects(queries: readonly string[]): string[] {
  return queries.filter((query) => {
    const normalized = query.toLowerCase().replace(/\s+/g, ' ');
    return normalized.includes('"finding"') && normalized.includes('select');
  });
}

function scopedFindingWhere(query: string): boolean {
  const normalized = query.toLowerCase().replace(/\s+/g, ' ');
  const index = normalized.lastIndexOf(' where ');
  if (index === -1) {
    return false;
  }
  const where = normalized.slice(index);
  return where.includes('organization_id') && where.includes('"id"');
}

function inspect(organizationId: string, findingId: string) {
  return openFindingInspection(createControlledFindingInspectionPersistence(prisma)).inspect({
    schemaVersion: FINDING_INSPECTION_COMMAND_SCHEMA_VERSION,
    trustedContext: {
      schemaVersion: FINDING_INSPECTION_TRUSTED_CONTEXT_SCHEMA_VERSION,
      organizationId,
    },
    findingId,
  });
}

async function lineage(organizationId: string) {
  const [findings, observations, links, evidence, audits] = await Promise.all([
    prisma.finding.findMany({ where: { organizationId }, orderBy: { id: 'asc' } }),
    prisma.findingObservation.findMany({ where: { organizationId }, orderBy: { id: 'asc' } }),
    prisma.findingCreationEvidenceLink.findMany({
      where: { organizationId },
      orderBy: { id: 'asc' },
    }),
    prisma.productMatchEvaluationEvidence.findMany({
      where: { organizationId },
      orderBy: { id: 'asc' },
    }),
    prisma.auditEvent.findMany({ where: { organizationId }, orderBy: { id: 'asc' } }),
  ]);
  return { findings, observations, links, evidence, audits };
}

async function setUserTriggers(
  table:
    | 'advisory_revision'
    | 'finding'
    | 'finding_observation'
    | 'finding_creation_evidence_link'
    | 'product_match_evaluation_evidence',
  enabled: boolean,
): Promise<void> {
  const statement = enabled ? 'ENABLE TRIGGER USER' : 'DISABLE TRIGGER USER';
  switch (table) {
    case 'advisory_revision':
      await prisma.$executeRawUnsafe(`ALTER TABLE "advisory_revision" ${statement}`);
      return;
    case 'finding':
      await prisma.$executeRawUnsafe(`ALTER TABLE "finding" ${statement}`);
      return;
    case 'finding_observation':
      await prisma.$executeRawUnsafe(`ALTER TABLE "finding_observation" ${statement}`);
      return;
    case 'finding_creation_evidence_link':
      await prisma.$executeRawUnsafe(`ALTER TABLE "finding_creation_evidence_link" ${statement}`);
      return;
    case 'product_match_evaluation_evidence':
      await prisma.$executeRawUnsafe(
        `ALTER TABLE "product_match_evaluation_evidence" ${statement}`,
      );
      return;
    default:
      return;
  }
}

async function disableUser(table: Parameters<typeof setUserTriggers>[0]): Promise<void> {
  await setUserTriggers(table, false);
}

async function restoreInspectionTriggers(): Promise<void> {
  await setUserTriggers('advisory_revision', true);
  await setUserTriggers('finding', true);
  await setUserTriggers('finding_observation', true);
  await setUserTriggers('finding_creation_evidence_link', true);
  await setUserTriggers('product_match_evaluation_evidence', true);
}

beforeAll(async () => {
  database = await createEphemeralDatabase('it');
  await deployMigrations(database.databaseUrl);
  prisma = new PrismaClient({ datasources: { db: { url: database.databaseUrl } } });
});

afterAll(async () => {
  await prisma.$disconnect();
  await dropEphemeralDatabase(database.admin, database.databaseName);
});

describe('controlled finding inspection', () => {
  it('projects a current finding and writes nothing', async () => {
    const seeded = await seedTarget('current', [{ version: '1.1.0', bomRef: 'component-1' }]);
    const before = await lineage(seeded.organizationId);
    const result = await inspect(seeded.organizationId, seeded.findingId);
    expect(result.status).toBe('found');
    if (result.status !== 'found') {
      return;
    }
    expect(result.projection).toMatchObject({
      findingId: seeded.findingId,
      state: 'open',
      asset: { id: seeded.assetId, displayName: seeded.assetName },
      component: { id: seeded.componentId, ecosystem: 'npm', namespace: null, name: PACKAGE_NAME },
      vulnerability: { id: seeded.vulnerabilityId, publicId: seeded.vulnerabilityPublicId },
      affectedVersions: {
        values: ['1.1.0'],
        truncated: false,
        omittedDistinctCount: 0,
        distinctCount: 1,
      },
      affectedOccurrenceCount: 1,
      otherOccurrenceCount: 0,
      otherOccurrenceClassification: 'no_other_occurrences_in_creation_ingestion',
      creationEvidenceApplicability: 'current',
      creationObservationPolicy: { policyId: 'finding_creation_policy_v1', policyVersion: 1 },
    });
    expect(result.projection.explanationCodes).toEqual([
      'finding_created_from_affected_product_match_evidence',
      'maintainer_reviewed_advisory_source',
      'independent_reviewer_approval',
      'affected_within_introduced_fixed_range',
    ]);
    expect(result.projection.createdAt).toBe(before.findings[0]?.createdAt.toISOString());
    expect(await lineage(seeded.organizationId)).toEqual(before);
  });

  it('keeps every affected version in deterministic order', async () => {
    const seeded = await seedTarget('versions', [
      { version: '1.2.0', bomRef: 'component-b' },
      { version: '1.10.0', bomRef: 'component-c' },
      { version: '1.1.0', bomRef: 'component-a' },
    ]);
    const before = await lineage(seeded.organizationId);
    const result = await inspect(seeded.organizationId, seeded.findingId);
    expect(result.status).toBe('found');
    if (result.status !== 'found') {
      return;
    }
    expect(result.projection.affectedVersions.values).toEqual(['1.1.0', '1.10.0', '1.2.0']);
    expect(result.projection.affectedOccurrenceCount).toBe(3);
    expect(result.projection.explanationCodes).toContain('several_affected_occurrences');
    expect(await lineage(seeded.organizationId)).toEqual(before);
  });

  it('counts an unlinked occurrence without labeling it unaffected', async () => {
    const seeded = await seedTarget(
      'other',
      [{ version: '1.1.0', bomRef: 'component-affected' }],
      [{ version: '9.9.9', bomRef: 'component-other' }],
    );
    const result = await inspect(seeded.organizationId, seeded.findingId);
    expect(result.status).toBe('found');
    if (result.status !== 'found') {
      return;
    }
    expect(result.projection.affectedOccurrenceCount).toBe(1);
    expect(result.projection.otherOccurrenceCount).toBe(1);
    expect(result.projection.otherOccurrenceClassification).toBe(
      'other_occurrences_not_in_creation_evidence',
    );
    expect(result.projection.explanationCodes).toContain(
      'other_occurrences_not_in_creation_evidence',
    );
    expect(JSON.stringify(result)).not.toContain('unaffected');
    expect(JSON.stringify(result)).not.toContain('9.9.9');
  });

  it('truncates the displayed version list and preserves the occurrence count', async () => {
    const versions = Array.from(
      { length: FINDING_INSPECTION_AFFECTED_VERSION_DISPLAY_LIMIT + 1 },
      (_, index) => ({
        version: `1.0.${String(index + 1)}`,
        bomRef: `component-${String(index + 1)}`,
      }),
    );
    const seeded = await seedTarget('truncate', versions);
    const result = await inspect(seeded.organizationId, seeded.findingId);
    expect(result.status).toBe('found');
    if (result.status !== 'found') {
      return;
    }
    expect(result.projection.affectedVersions.truncated).toBe(true);
    expect(result.projection.affectedVersions.omittedDistinctCount).toBe(1);
    expect(result.projection.affectedVersions.values).toHaveLength(
      FINDING_INSPECTION_AFFECTED_VERSION_DISPLAY_LIMIT,
    );
    expect(result.projection.affectedOccurrenceCount).toBe(versions.length);
  }, 120_000);

  it('classifies a newer asset ingestion as historical without changing the finding', async () => {
    const seeded = await seedTarget('ingestion', [{ version: '1.1.0', bomRef: 'component-1' }]);
    const next = await createProcessingIngestion(prisma, {
      organizationId: seeded.organizationId,
      sbomId: seeded.sbomId,
      assetId: seeded.assetId,
    });
    await completeIngestion(next.id, seeded.assetId, 1);
    const before = await lineage(seeded.organizationId);
    const result = await inspect(seeded.organizationId, seeded.findingId);
    expect(result.status).toBe('found');
    if (result.status !== 'found') {
      return;
    }
    expect(result.projection.creationEvidenceApplicability).toBe('historical');
    expect(result.projection.explanationCodes).toContain('creation_evidence_historical');
    expect(await lineage(seeded.organizationId)).toEqual(before);
    expect(before.findings[0]?.updatedAt.toISOString()).toBe(
      before.findings[0]?.createdAt.toISOString(),
    );
  });

  it('classifies a withdrawn revision as historical', async () => {
    const seeded = await seedTarget('withdrawn', [{ version: '1.1.0', bomRef: 'component-1' }]);
    await disableUser('advisory_revision');
    await prisma.advisoryRevision.update({
      where: { id: seeded.revisionId },
      data: {
        withdrawalClassification: 'withdrawn',
        revisionDisposition: 'withdrawn',
      },
    });
    const before = await lineage(seeded.organizationId);
    const result = await inspect(seeded.organizationId, seeded.findingId);
    expect(result.status).toBe('found');
    if (result.status === 'found') {
      expect(result.projection.creationEvidenceApplicability).toBe('historical');
    }
    expect(await lineage(seeded.organizationId)).toEqual(before);
  });

  it('classifies a quarantined revision as historical', async () => {
    const seeded = await seedTarget('quarantine', [{ version: '1.1.0', bomRef: 'component-1' }]);
    await disableUser('advisory_revision');
    await prisma.advisoryRevision.update({
      where: { id: seeded.revisionId },
      data: {
        quarantineClassification: 'quarantined',
        revisionDisposition: 'quarantined',
      },
    });
    const result = await inspect(seeded.organizationId, seeded.findingId);
    expect(result.status).toBe('found');
    if (result.status === 'found') {
      expect(result.projection.creationEvidenceApplicability).toBe('historical');
      expect(result.projection.explanationCodes).toContain('creation_evidence_historical');
    }
  });

  it('classifies a successor revision as historical', async () => {
    const seeded = await seedTarget('successor', [{ version: '1.1.0', bomRef: 'component-1' }]);
    const prior = await prisma.advisoryRevision.findUniqueOrThrow({
      where: { id: seeded.revisionId },
    });
    await prisma.advisoryRevision.create({
      data: {
        revisionSchemaVersion: prior.revisionSchemaVersion,
        advisoryFamilyId: prior.advisoryFamilyId,
        source: prior.source,
        advisoryId: prior.advisoryId,
        familyDigest: prior.familyDigest,
        revisionDigest: digest(`successor:${randomUUID()}`),
        providerGeneration: prior.providerGeneration,
        contentFingerprint: digest(`successor-content:${randomUUID()}`),
        session14RangeFingerprint: prior.session14RangeFingerprint,
        productRangeFingerprint: prior.productRangeFingerprint,
        parserId: prior.parserId,
        parserResourcePolicy: prior.parserResourcePolicy,
        advisorySchemaVersion: prior.advisorySchemaVersion,
        advisorySchemaCommit: prior.advisorySchemaCommit,
        sourceLicenseRegistryVersion: prior.sourceLicenseRegistryVersion,
        sourceLicensePolicyVersion: prior.sourceLicensePolicyVersion,
        spdxLicenseId: prior.spdxLicenseId,
        origin: prior.origin,
        trustClassification: prior.trustClassification,
        revisionDisposition: 'superseding',
        withdrawalClassification: 'not_withdrawn',
        quarantineClassification: 'not_quarantined',
        supersedesRevisionDigest: prior.revisionDigest,
        supersedesAdvisoryRevisionId: prior.id,
        retrievalClassification: prior.retrievalClassification,
        retrievalEvidenceId: prior.retrievalEvidenceId,
        retrievalPolicyId: prior.retrievalPolicyId,
        ecosystem: prior.ecosystem,
        packageName: prior.packageName,
        packageIdentityKey: prior.packageIdentityKey,
        evaluatorVersion: prior.evaluatorVersion,
        matchingPolicyId: prior.matchingPolicyId,
        aliasCount: 0,
        cveAliasCount: 0,
        aliasSetDigest: digest(`successor-aliases:${randomUUID()}`),
        replayFingerprint: digest(`successor-replay:${randomUUID()}`),
        authorIdentity: prior.authorIdentity,
      },
    });
    const before = await lineage(seeded.organizationId);
    const result = await inspect(seeded.organizationId, seeded.findingId);
    expect(result.status).toBe('found');
    if (result.status === 'found') {
      expect(result.projection.creationEvidenceApplicability).toBe('historical');
    }
    expect(await lineage(seeded.organizationId)).toEqual(before);
  });

  it('equates a foreign finding with an absent finding', async () => {
    const left = await seedTarget('tenant-a', [{ version: '1.1.0', bomRef: 'component-1' }]);
    const right = await seedTarget('tenant-b', [{ version: '1.1.0', bomRef: 'component-1' }]);
    const own = await inspect(left.organizationId, left.findingId);
    const foreign = await inspect(left.organizationId, right.findingId);
    const absent = await inspect(left.organizationId, 'abababab-abab-4bab-8bab-abababababab');
    expect(own.status).toBe('found');
    expect(foreign).toEqual(absent);
    expect(foreign).toEqual({
      schemaVersion: FINDING_INSPECTION_RESULT_SCHEMA_VERSION,
      status: 'not_found',
    });
    expect(JSON.stringify(foreign)).toBe(JSON.stringify(absent));
    expect(JSON.stringify(foreign)).not.toContain(right.findingId);
    expect(JSON.stringify(foreign)).not.toContain(right.organizationId);
    const other = await inspect(right.organizationId, right.findingId);
    expect(other.status).toBe('found');
    if (own.status === 'found' && other.status === 'found') {
      expect(own.projection.asset.id).toBe(left.assetId);
      expect(other.projection.asset.id).toBe(right.assetId);
      expect(own.projection.component.name).toBe(PACKAGE_NAME);
      expect(other.projection.component.name).toBe(PACKAGE_NAME);
    }
  });

  it('fails closed when the finding has no creation observation', async () => {
    const seeded = await seedTarget('missing-observation', [
      { version: '1.1.0', bomRef: 'component-1' },
    ]);
    await disableUser('finding_creation_evidence_link');
    await prisma.findingCreationEvidenceLink.deleteMany({ where: { findingId: seeded.findingId } });
    await disableUser('finding_observation');
    await prisma.findingObservation.deleteMany({ where: { findingId: seeded.findingId } });
    const before = await lineage(seeded.organizationId);
    const result = await inspect(seeded.organizationId, seeded.findingId);
    expect(result).toEqual({
      schemaVersion: FINDING_INSPECTION_RESULT_SCHEMA_VERSION,
      status: 'malformed_persisted_state',
    });
    expect(await lineage(seeded.organizationId)).toEqual(before);
  });

  it('fails closed when an evidence link is removed', async () => {
    const seeded = await seedTarget('incomplete', [
      { version: '1.1.0', bomRef: 'component-a' },
      { version: '1.2.0', bomRef: 'component-b' },
    ]);
    const link = await prisma.findingCreationEvidenceLink.findFirstOrThrow({
      where: { findingId: seeded.findingId },
    });
    await disableUser('finding_creation_evidence_link');
    await prisma.findingCreationEvidenceLink.delete({ where: { id: link.id } });
    const result = await inspect(seeded.organizationId, seeded.findingId);
    expect(result.status).toBe('malformed_persisted_state');
  });

  it('fails closed when linked evidence is no longer affected', async () => {
    const seeded = await seedTarget('contradiction', [{ version: '1.1.0', bomRef: 'component-1' }]);
    const evidenceId = seeded.evidence[0]?.evidenceId;
    if (evidenceId === undefined) {
      throw new Error('missing evidence');
    }
    await disableUser('product_match_evaluation_evidence');
    await prisma.productMatchEvaluationEvidence.update({
      where: { id: evidenceId },
      data: { outcome: 'unaffected' },
    });
    const result = await inspect(seeded.organizationId, seeded.findingId);
    expect(result.status).toBe('malformed_persisted_state');
  });

  it('fails closed on an unsupported evaluator', async () => {
    const seeded = await seedTarget('evaluator', [{ version: '1.1.0', bomRef: 'component-1' }]);
    const evidenceId = seeded.evidence[0]?.evidenceId;
    if (evidenceId === undefined) {
      throw new Error('missing evidence');
    }
    await disableUser('product_match_evaluation_evidence');
    await prisma.$executeRaw`ALTER TABLE "product_match_evaluation_evidence" DROP CONSTRAINT "product_match_evaluation_evidence_closed_chk"`;
    await prisma.productMatchEvaluationEvidence.update({
      where: { id: evidenceId },
      data: { evaluatorId: 'untrusted_evaluator' },
    });
    const result = await inspect(seeded.organizationId, seeded.findingId);
    expect(result.status).toBe('malformed_persisted_state');
    expect(JSON.stringify(result)).not.toContain('untrusted_evaluator');
  });

  it('fails closed on unexpected lifecycle rows and a non-open state', async () => {
    const seeded = await seedTarget('lifecycle', [{ version: '1.1.0', bomRef: 'component-1' }]);
    await prisma.remediationTask.create({
      data: {
        organizationId: seeded.organizationId,
        findingId: seeded.findingId,
        title: 'withheld',
      },
    });
    const withTask = await inspect(seeded.organizationId, seeded.findingId);
    expect(withTask.status).toBe('malformed_persisted_state');
    await prisma.remediationTask.deleteMany({ where: { findingId: seeded.findingId } });
    await disableUser('finding');
    await prisma.$executeRaw`ALTER TABLE "finding" DROP CONSTRAINT "finding_creation_initial_state_chk"`;
    await prisma.finding.update({
      where: { id: seeded.findingId },
      data: { state: 'resolved', resolvedAt: new Date('2026-10-06T00:00:00.000Z') },
    });
    const resolved = await inspect(seeded.organizationId, seeded.findingId);
    expect(resolved.status).toBe('malformed_persisted_state');
  });

  it('returns database_unavailable without echoing the driver failure', async () => {
    const brokenUrl = new URL(database.databaseUrl);
    brokenUrl.port = '1';
    const unreachable = new PrismaClient({ datasources: { db: { url: brokenUrl.toString() } } });
    try {
      const result = await openFindingInspection(
        createControlledFindingInspectionPersistence(unreachable),
      ).inspect({
        schemaVersion: FINDING_INSPECTION_COMMAND_SCHEMA_VERSION,
        trustedContext: {
          schemaVersion: FINDING_INSPECTION_TRUSTED_CONTEXT_SCHEMA_VERSION,
          organizationId: '12121212-1212-4121-8121-121212121212',
        },
        findingId: '34343434-3434-4343-8343-343434343434',
      });
      expect(result).toEqual({
        schemaVersion: FINDING_INSPECTION_RESULT_SCHEMA_VERSION,
        status: 'database_unavailable',
      });
      expect(JSON.stringify(result)).not.toContain('postgres://');
    } finally {
      await unreachable.$disconnect();
    }
  });

  it('does not call a provider or evaluator', () => {
    const source = readFileSync(
      path.join(
        path.dirname(fileURLToPath(import.meta.url)),
        'controlled-finding-inspection-persistence.ts',
      ),
      'utf8',
    );
    expect(source).not.toContain('@patchpilot/vulnerability-intelligence');
    expect(source).not.toContain('fetch(');
    expect(source).not.toContain('evaluateReviewed');
    expect(source).not.toMatch(
      /\.(finding|findingObservation|findingCreationEvidenceLink|productMatchEvaluationEvidence)\s*\.\s*(create|update|delete|upsert)\(/,
    );
  });

  it('uses one organization-scoped query for a foreign finding and an absent finding', async () => {
    const seeded = await seedTarget('oracle', [{ version: '1.1.0', bomRef: 'component-1' }]);
    const trustedOrganizationId = '12121212-1212-4121-8121-121212121212';
    const absentId = 'abababab-abab-4bab-8bab-abababababab';
    const queries: string[] = [];
    const logging = new PrismaClient({
      datasources: { db: { url: database.databaseUrl } },
      log: [{ emit: 'event', level: 'query' }],
    });
    logging.$on('query', (event) => {
      queries.push(event.query);
    });
    const reader = openFindingInspection(createControlledFindingInspectionPersistence(logging));
    const request = (findingId: string) => ({
      schemaVersion: FINDING_INSPECTION_COMMAND_SCHEMA_VERSION,
      trustedContext: {
        schemaVersion: FINDING_INSPECTION_TRUSTED_CONTEXT_SCHEMA_VERSION,
        organizationId: trustedOrganizationId,
      },
      findingId,
    });
    try {
      await logging.$queryRaw`SELECT 1`;
      queries.length = 0;
      const foreign = await reader.inspect(request(seeded.findingId));
      const foreignSql = findingSelects(queries);
      queries.length = 0;
      const absent = await reader.inspect(request(absentId));
      const absentSql = findingSelects(queries);
      expect(foreign).toEqual(absent);
      expect(foreignSql).toEqual(absentSql);
      expect(foreignSql.length).toBeGreaterThan(0);
      expect(foreignSql.every(scopedFindingWhere)).toBe(true);
      expect(JSON.stringify(foreign)).not.toContain(seeded.findingId);
      expect(JSON.stringify(foreign)).not.toContain(seeded.organizationId);
      const repeatedForeign = await reader.inspect(request(seeded.findingId));
      const repeatedAbsent = await reader.inspect(request(absentId));
      expect(repeatedForeign).toEqual(repeatedAbsent);
      expect(repeatedForeign).toEqual(foreign);
    } finally {
      await logging.$disconnect();
    }

    const explain = (findingId: string) =>
      prisma.$queryRaw<Array<Record<string, unknown>>>`
        EXPLAIN (FORMAT JSON)
        SELECT "id"
        FROM "finding"
        WHERE "organization_id" = ${trustedOrganizationId}::uuid
          AND "id" = ${findingId}::uuid
      `;
    const foreignPlan = redactPlan(JSON.stringify(await explain(seeded.findingId)));
    const absentPlan = redactPlan(JSON.stringify(await explain(absentId)));
    expect(foreignPlan).toBe(absentPlan);
    expect(foreignPlan).toContain('organization_id');
    expect(foreignPlan).toContain('finding_alignment_key');
    expect(foreignPlan).not.toContain('finding_pkey');

    const foreignTimes: number[] = [];
    const absentTimes: number[] = [];
    for (let index = 0; index < 8; index += 1) {
      await inspect(trustedOrganizationId, seeded.findingId);
      await inspect(trustedOrganizationId, absentId);
    }
    for (let index = 0; index < 21; index += 1) {
      const foreignStarted = performance.now();
      await inspect(trustedOrganizationId, seeded.findingId);
      foreignTimes.push(performance.now() - foreignStarted);
      const absentStarted = performance.now();
      await inspect(trustedOrganizationId, absentId);
      absentTimes.push(performance.now() - absentStarted);
    }
    const foreignMedian = median(foreignTimes);
    const absentMedian = median(absentTimes);
    const ratio =
      Math.max(foreignMedian, absentMedian) /
      Math.max(0.001, Math.min(foreignMedian, absentMedian));
    expect(foreignMedian).toBeGreaterThan(0);
    expect(absentMedian).toBeGreaterThan(0);
    expect(
      ratio,
      `foreignMedianMs=${foreignMedian.toFixed(3)} absentMedianMs=${absentMedian.toFixed(3)}`,
    ).toBeLessThan(8);
  }, 120_000);

  it('hides reviewer, actor, and fingerprint values from the projection', async () => {
    const seeded = await seedTarget('confidential', [{ version: '1.1.0', bomRef: 'component-1' }]);
    await prisma.asset.update({
      where: { id: seeded.assetId },
      data: { name: 'asset <untrusted>' },
    });
    await prisma.component.update({
      where: { id: seeded.componentId },
      data: { name: 'widget <untrusted>' },
    });
    const observation = await prisma.findingObservation.findFirstOrThrow({
      where: { organizationId: seeded.organizationId, findingId: seeded.findingId },
    });
    const approval = await prisma.maintainerReviewedAdvisoryApproval.findFirstOrThrow({
      where: { advisoryRevisionId: seeded.revisionId },
    });
    const before = await stamps(seeded.organizationId);
    const result = await inspect(seeded.organizationId, seeded.findingId);
    expect(result.status).toBe('found');
    if (result.status === 'found') {
      expect(result.projection.asset.displayName).toBe('asset <untrusted>');
      expect(result.projection.component.name).toBe('widget <untrusted>');
      expect(JSON.stringify(result)).not.toContain('safeToRender');
    }
    const encoded = JSON.stringify(result);
    expect(encoded).not.toContain(approval.reviewerIdentity);
    expect(encoded).not.toContain(seeded.membershipId);
    expect(encoded).not.toContain(seeded.actorId);
    expect(observation.replayFingerprint).not.toBeNull();
    if (observation.replayFingerprint !== null) {
      expect(encoded).not.toContain(observation.replayFingerprint);
    }
    expect(await stamps(seeded.organizationId)).toEqual(before);
  });

  it('fails closed when the linked ingestion is no longer completed', async () => {
    const seeded = await seedTarget('ingestion-failed', [
      { version: '1.1.0', bomRef: 'component-1' },
    ]);
    await prisma.sbomIngestion.update({
      where: { id: seeded.ingestionId },
      data: {
        state: 'failed',
        failureCategory: 'validation',
        failureCode: 'closed',
        graphCompleteness: null,
        componentCount: null,
        dependencyEdgeCount: null,
        warningCount: null,
      },
    });
    const before = await stamps(seeded.organizationId);
    const result = await inspect(seeded.organizationId, seeded.findingId);
    expect(result.status).toBe('malformed_persisted_state');
    expect(JSON.stringify(result)).not.toContain('failed');
    expect(await stamps(seeded.organizationId)).toEqual(before);
    const stored = await prisma.finding.findFirstOrThrow({
      where: { organizationId: seeded.organizationId, id: seeded.findingId },
    });
    expect(stored.state).toBe('open');
  });

  it('fails closed when normalization is not version 2', async () => {
    const seeded = await seedTarget('normalization', [{ version: '1.1.0', bomRef: 'component-1' }]);
    await prisma.sbomIngestion.update({
      where: { id: seeded.ingestionId },
      data: { normalizationVersion: '1' },
    });
    const result = await inspect(seeded.organizationId, seeded.findingId);
    expect(result.status).toBe('malformed_persisted_state');
    const stored = await prisma.finding.findFirstOrThrow({
      where: { organizationId: seeded.organizationId, id: seeded.findingId },
    });
    expect(stored.state).toBe('open');
    expect(stored.resolvedAt).toBeNull();
  });

  it('fails closed when the observed version disagrees with the evidence version', async () => {
    const seeded = await seedTarget('version-mismatch', [
      { version: '1.1.0', bomRef: 'component-1' },
    ]);
    const occurrence = await prisma.componentOccurrence.findFirstOrThrow({
      where: { organizationId: seeded.organizationId, sbomIngestionId: seeded.ingestionId },
    });
    await prisma.componentOccurrence.update({
      where: { id: occurrence.id },
      data: { version: '9.9.9' },
    });
    const before = await stamps(seeded.organizationId);
    const result = await inspect(seeded.organizationId, seeded.findingId);
    expect(result.status).toBe('malformed_persisted_state');
    expect(JSON.stringify(result)).not.toContain('9.9.9');
    expect(await stamps(seeded.organizationId)).toEqual(before);
  });

  it('classifies a binding that is no longer reviewed as historical without writing', async () => {
    const seeded = await seedTarget('binding', [{ version: '1.1.0', bomRef: 'component-1' }]);
    await prisma.$executeRawUnsafe(
      'ALTER TABLE "advisory_vulnerability_binding" DISABLE TRIGGER USER',
    );
    await prisma.$executeRawUnsafe(
      'ALTER TABLE "advisory_vulnerability_binding" DROP CONSTRAINT "advisory_vulnerability_binding_shape_chk"',
    );
    try {
      await prisma.advisoryVulnerabilityBinding.update({
        where: { advisoryRevisionId: seeded.revisionId },
        data: { conflictClassification: 'recorded_conflict' },
      });
      const before = await stamps(seeded.organizationId);
      const result = await inspect(seeded.organizationId, seeded.findingId);
      expect(result.status).toBe('found');
      if (result.status === 'found') {
        expect(result.projection.creationEvidenceApplicability).toBe('historical');
        expect(result.projection.state).toBe('open');
        expect(JSON.stringify(result)).not.toContain('recorded_conflict');
      }
      expect(await stamps(seeded.organizationId)).toEqual(before);
    } finally {
      await prisma.$executeRawUnsafe(
        'ALTER TABLE "advisory_vulnerability_binding" ENABLE TRIGGER USER',
      );
    }
  });

  it('fails closed when evidence in the organization no longer matches the finding target', async () => {
    const seeded = await seedTarget('retarget', [{ version: '1.1.0', bomRef: 'component-1' }]);
    const evidenceId = seeded.evidence[0]?.evidenceId;
    if (evidenceId === undefined) {
      throw new Error('missing evidence');
    }
    const other = await prisma.vulnerability.create({
      data: { osvId: `REVIEWED-OTHER-${randomUUID()}` },
      select: { id: true, osvId: true },
    });
    await disableUser('product_match_evaluation_evidence');
    await prisma.$executeRawUnsafe(
      'ALTER TABLE "finding_creation_evidence_link" DROP CONSTRAINT "finding_creation_evidence_link_evidence_fkey"',
    );
    try {
      await prisma.productMatchEvaluationEvidence.update({
        where: { id: evidenceId },
        data: { vulnerabilityId: other.id },
      });
      const before = await stamps(seeded.organizationId);
      const result = await inspect(seeded.organizationId, seeded.findingId);
      expect(result.status).toBe('malformed_persisted_state');
      const encoded = JSON.stringify(result);
      expect(encoded).not.toContain(other.id);
      expect(encoded).not.toContain(other.osvId);
      expect(await stamps(seeded.organizationId)).toEqual(before);
      const stored = await prisma.finding.findFirstOrThrow({
        where: { organizationId: seeded.organizationId, id: seeded.findingId },
      });
      expect(stored.state).toBe('open');
      expect(stored.vulnerabilityId).toBe(seeded.vulnerabilityId);
    } finally {
      await restoreInspectionTriggers();
    }
  });
});

function redactPlan(plan: string): string {
  return planIdentity(plan).replace(
    /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/g,
    'uuid',
  );
}

function planIdentity(plan: string): string {
  return plan.replace(
    /"(?:Actual [^"]+|Planning Time|Execution Time|I\/O Read Time|I\/O Write Time)":\s*[-0-9.]+/g,
    '"$time":0',
  );
}
