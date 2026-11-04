/**
 * Disposable PostgreSQL proof for one asset-scoped Product Match candidate page.
 * The read writes no evidence, no Finding, and no audit row.
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
  PRODUCT_MATCH_EVALUATION_POLICY_ID,
  PRODUCT_MATCH_EVALUATION_POLICY_VERSION,
  PRODUCT_MATCH_EVALUATOR_ID,
  PRODUCT_MATCH_EVALUATOR_VERSION,
  PRODUCT_MATCH_FINDING_CREATION,
  PRODUCT_MATCH_MATCHING_POLICY_ID,
  PRODUCT_MATCH_MATCHING_POLICY_VERSION,
  PRODUCT_MATCH_SUPPRESSION_AUTHORITY,
  SELECTED_FIRST_ECOSYSTEM,
  VULNERABILITY_MAPPING_POLICY_ID,
  classifyNpmPackageIdentityFromParts,
  maintainerReviewedApprovalReplayFingerprint,
  session14RangeFingerprint,
} from '@patchpilot/vulnerability-intelligence';
import {
  DELIBERATE_PRODUCT_MATCH_EVALUATION_AUDIT_ACTION,
  DELIBERATE_PRODUCT_MATCH_EVALUATION_COMMAND_SCHEMA_VERSION,
  DELIBERATE_PRODUCT_MATCH_EVALUATION_EXPLICIT_VERSIONS_USED,
  DELIBERATE_PRODUCT_MATCH_EVALUATION_FINDING_WRITES,
  DELIBERATE_PRODUCT_MATCH_EVALUATION_LOCK_TIMEOUT_MS,
  DELIBERATE_PRODUCT_MATCH_EVALUATION_MAX_WAIT_MS,
  DELIBERATE_PRODUCT_MATCH_EVALUATION_NORMALIZATION_VERSION,
  DELIBERATE_PRODUCT_MATCH_EVALUATION_OCCURRENCE_CAP,
  DELIBERATE_PRODUCT_MATCH_EVALUATION_OCCURRENCE_ORDER,
  DELIBERATE_PRODUCT_MATCH_EVALUATION_POLICY_ID,
  DELIBERATE_PRODUCT_MATCH_EVALUATION_POLICY_VERSION,
  DELIBERATE_PRODUCT_MATCH_EVALUATION_PROVIDER_CALLS,
  DELIBERATE_PRODUCT_MATCH_EVALUATION_PURPOSE,
  DELIBERATE_PRODUCT_MATCH_EVALUATION_REQUIRED_ROLE,
  DELIBERATE_PRODUCT_MATCH_EVALUATION_SELECTION_PROBE,
  DELIBERATE_PRODUCT_MATCH_EVALUATION_STATEMENT_TIMEOUT_MS,
  DELIBERATE_PRODUCT_MATCH_EVALUATION_TRANSACTION_TIMEOUT_MS,
  assessDeliberateProductMatchAdvisory,
  classifyDeliberateIngestionPointer,
  classifyDeliberateOccurrenceVersion,
  classifyDeliberateSelectionCount,
  deliberateAdvisoryFailureStatus,
  deliberateProductMatchEvaluationLockIdentity,
  planDeliberateProductMatchEvaluationAudit,
  type DeliberateProductMatchEvaluationCommand,
  type DeliberateProductMatchEvaluationDecisions,
} from '@patchpilot/vulnerability-intelligence/deliberate-product-match-evaluation';
import type { ProductMatchCandidateDecisions } from '@patchpilot/vulnerability-intelligence/product-match-candidates';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { createDeliberateProductMatchEvaluationPersistence } from './deliberate-product-match-evaluation-persistence.js';
import {
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
} from './integration-database.js';
import { createProductMatchCandidatePersistence } from './product-match-candidate-persistence.js';
import { createApprovalCapabilityHarness } from './reviewer-capability-approval-harness.js';
import {
  createAsset,
  createOrg,
  createProcessingIngestion,
  createSbom,
  resolvedComponent,
} from './sbom-test-fixture.js';

const PACKAGE_NAME = 'reviewed-npm-widget';
const CVE_ALIAS = 'CVE-2024-51515';
const RANGES = [
  {
    type: 'SEMVER' as const,
    events: [
      { name: 'introduced' as const, value: '1.0.0' },
      { name: 'fixed' as const, value: '2.0.0' },
    ],
  },
];

const EVALUATION_DECISIONS: DeliberateProductMatchEvaluationDecisions = {
  assessAdvisory: assessDeliberateProductMatchAdvisory,
  advisoryFailureStatus: deliberateAdvisoryFailureStatus,
  classifyOccurrenceVersion: classifyDeliberateOccurrenceVersion,
  classifyIngestion: classifyDeliberateIngestionPointer,
  classifySelectionCount: classifyDeliberateSelectionCount,
  planAudit: planDeliberateProductMatchEvaluationAudit,
  lockIdentity: deliberateProductMatchEvaluationLockIdentity,
  occurrenceOrder: DELIBERATE_PRODUCT_MATCH_EVALUATION_OCCURRENCE_ORDER,
  statementTimeoutMs: DELIBERATE_PRODUCT_MATCH_EVALUATION_STATEMENT_TIMEOUT_MS,
  lockTimeoutMs: DELIBERATE_PRODUCT_MATCH_EVALUATION_LOCK_TIMEOUT_MS,
  maxWaitMs: DELIBERATE_PRODUCT_MATCH_EVALUATION_MAX_WAIT_MS,
  transactionTimeoutMs: DELIBERATE_PRODUCT_MATCH_EVALUATION_TRANSACTION_TIMEOUT_MS,
};

const CANDIDATE_DECISIONS: ProductMatchCandidateDecisions = {
  assessAdvisory: assessDeliberateProductMatchAdvisory,
  classifyIdentity: classifyNpmPackageIdentityFromParts,
  classifyIngestion: classifyDeliberateIngestionPointer,
};

type AdvisoryRecord = {
  readonly revisionId: string;
  readonly contentFingerprint: string;
  readonly vulnerabilityId: string;
};

type SeededAsset = {
  readonly organizationId: string;
  readonly assetId: string;
  readonly userId: string;
  readonly membershipId: string;
  readonly ingestionId: string;
  readonly sbomId: string;
};

function digest(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function packageIdentity(packageName = PACKAGE_NAME): string {
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

describe('product match candidate PostgreSQL persistence', () => {
  let databaseName = '';
  let admin: Awaited<ReturnType<typeof createEphemeralDatabase>>['admin'];
  let prisma: PrismaClient;
  let advisory: AdvisoryRecord;

  beforeAll(async () => {
    const ephemeral = await createEphemeralDatabase('it');
    databaseName = ephemeral.databaseName;
    admin = ephemeral.admin;
    await deployMigrations(ephemeral.databaseUrl);
    prisma = new PrismaClient({ datasources: { db: { url: ephemeral.databaseUrl } } });
    advisory = await insertRevision(prisma, 'shared', {
      approve: true,
      canonicalCve: CVE_ALIAS,
    });
  });

  afterAll(async () => {
    if (prisma !== undefined) {
      await prisma.$disconnect();
    }
    if (admin !== undefined) {
      await dropEphemeralDatabase(admin, databaseName);
    }
  });

  it('returns one eligible candidate and withholds the CVE alias', async () => {
    const seeded = await seedAsset(prisma, 'visible', {
      occurrences: [
        { version: '1.1.0', bomRef: 'known' },
        { version: 'not-a-version', bomRef: 'unknown' },
      ],
    });
    await insertRevision(prisma, 'unapproved', { approve: false });
    await insertRevision(prisma, 'other-package', {
      approve: true,
      packageName: 'other-npm-widget',
    });
    await insertSyntheticRevision(prisma, 'synthetic');
    const beforeAudit = await prisma.auditEvent.count({
      where: { organizationId: seeded.organizationId },
    });
    const page = await readPage(prisma, seeded);
    expect(page.status).toBe('page');
    if (page.status !== 'page') {
      return;
    }
    expect(page.ingestionId).toBe(seeded.ingestionId);
    expect(page.candidates).toEqual([
      {
        advisoryRevisionId: advisory.revisionId,
        ecosystem: 'npm',
        packageNamespace: null,
        packageName: PACKAGE_NAME,
        matchedOccurrenceCount: 2,
        evaluationState: 'not_evaluated',
      },
    ]);
    const serialized = JSON.stringify(page);
    expect(serialized).not.toContain(CVE_ALIAS);
    expect(serialized).not.toContain(advisory.contentFingerprint);
    expect(serialized).not.toContain('author.one');
    expect(serialized).not.toContain('reviewer.two');
    expect(serialized).not.toContain(advisory.vulnerabilityId);
    expect(
      await prisma.auditEvent.count({ where: { organizationId: seeded.organizationId } }),
    ).toBe(beforeAudit);
    expect(await prisma.finding.count({ where: { organizationId: seeded.organizationId } })).toBe(
      0,
    );
  });

  it('keeps another organization evidence invisible and writes no audit on a later read', async () => {
    const owner = await seedAsset(prisma, 'owner-evidence');
    const other = await seedAsset(prisma, 'other-evidence');
    const evaluated = await runEvaluation(prisma, other, advisory.revisionId);
    if (typeof evaluated !== 'object' || evaluated === null || !('status' in evaluated)) {
      throw new Error('evaluation result was not an object');
    }
    expect(evaluated.status).toBe('evaluated');
    const ownerPage = await readPage(prisma, owner);
    const otherPage = await readPage(prisma, other);
    expect(ownerPage).toMatchObject({
      status: 'page',
      candidates: [{ advisoryRevisionId: advisory.revisionId, evaluationState: 'not_evaluated' }],
    });
    expect(otherPage).toMatchObject({
      status: 'page',
      candidates: [{ advisoryRevisionId: advisory.revisionId, evaluationState: 'evaluated' }],
    });
    const auditsBefore = await prisma.auditEvent.count({
      where: {
        organizationId: other.organizationId,
        action: DELIBERATE_PRODUCT_MATCH_EVALUATION_AUDIT_ACTION,
      },
    });
    await readPage(prisma, other);
    expect(
      await prisma.auditEvent.count({
        where: {
          organizationId: other.organizationId,
          action: DELIBERATE_PRODUCT_MATCH_EVALUATION_AUDIT_ACTION,
        },
      }),
    ).toBe(auditsBefore);
  });

  it('returns not_found for a foreign asset and an absent asset', async () => {
    const seeded = await seedAsset(prisma, 'tenant');
    const foreign = await seedAsset(prisma, 'foreign');
    const missing = await readPage(prisma, seeded, randomUUID());
    const other = await readPage(prisma, seeded, foreign.assetId);
    expect(missing).toEqual({ status: 'not_found' });
    expect(other).toEqual({ status: 'not_found' });
  });

  it('rejects an admin and an ingestion that is not normalization version 2', async () => {
    const adminAsset = await seedAsset(prisma, 'admin', { role: 'admin' });
    const old = await seedAsset(prisma, 'version-one', { normalizationVersion: '1' });
    expect(await readPage(prisma, adminAsset)).toEqual({ status: 'authority_rejected' });
    expect(await readPage(prisma, old)).toEqual({
      status: 'page',
      ingestionId: null,
      candidates: [],
      nextCursor: null,
    });
  });

  it('rejects a cursor bound to an older ingestion', async () => {
    const seeded = await seedAsset(prisma, 'cursor');
    const replacement = await createProcessingIngestion(prisma, {
      organizationId: seeded.organizationId,
      sbomId: seeded.sbomId,
      assetId: seeded.assetId,
    });
    await prisma.sbomIngestion.update({
      where: { id: replacement.id },
      data: {
        state: 'completed',
        normalizationVersion: '2',
        completedAt: new Date('2026-10-03T12:00:00.000Z'),
        graphCompleteness: 'no_dependencies',
        componentCount: 0,
        dependencyEdgeCount: 0,
        warningCount: 0,
        stage: null,
      },
    });
    await prisma.asset.update({
      where: { id: seeded.assetId },
      data: { lastSuccessfulSbomIngestionId: replacement.id },
    });
    const stale = await readPage(prisma, seeded, seeded.assetId, {
      ingestionId: seeded.ingestionId,
      packageNamespace: null,
      packageName: PACKAGE_NAME,
      advisoryRevisionId: advisory.revisionId,
    });
    expect(stale).toEqual({ status: 'stale_cursor' });
  });
});

async function readPage(
  client: PrismaClient,
  seeded: SeededAsset,
  assetId = seeded.assetId,
  cursor: {
    readonly ingestionId: string;
    readonly packageNamespace: string | null;
    readonly packageName: string;
    readonly advisoryRevisionId: string;
  } | null = null,
) {
  return createProductMatchCandidatePersistence(client).read(
    {
      organizationId: seeded.organizationId,
      membershipId: seeded.membershipId,
      actorUserId: seeded.userId,
      assetId,
      limit: 10,
      cursor,
    },
    CANDIDATE_DECISIONS,
  );
}

async function runEvaluation(
  client: PrismaClient,
  seeded: SeededAsset,
  advisoryRevisionId: string,
) {
  const command = commandFor(seeded, advisoryRevisionId);
  return createDeliberateProductMatchEvaluationPersistence(client).evaluate(
    command,
    EVALUATION_DECISIONS,
  );
}

function commandFor(
  seeded: SeededAsset,
  advisoryRevisionId: string,
): DeliberateProductMatchEvaluationCommand {
  return {
    schemaVersion: DELIBERATE_PRODUCT_MATCH_EVALUATION_COMMAND_SCHEMA_VERSION,
    organizationId: seeded.organizationId,
    assetId: seeded.assetId,
    advisoryRevisionId,
    actorUserId: seeded.userId,
    membershipId: seeded.membershipId,
    role: DELIBERATE_PRODUCT_MATCH_EVALUATION_REQUIRED_ROLE,
    requestId: randomUUID(),
    correlationId: randomUUID(),
    operationCorrelationId: randomUUID(),
    policyId: DELIBERATE_PRODUCT_MATCH_EVALUATION_POLICY_ID,
    policyVersion: DELIBERATE_PRODUCT_MATCH_EVALUATION_POLICY_VERSION,
    purpose: DELIBERATE_PRODUCT_MATCH_EVALUATION_PURPOSE,
    evaluatorId: PRODUCT_MATCH_EVALUATOR_ID,
    evaluatorVersion: PRODUCT_MATCH_EVALUATOR_VERSION,
    matchingPolicyId: PRODUCT_MATCH_MATCHING_POLICY_ID,
    matchingPolicyVersion: PRODUCT_MATCH_MATCHING_POLICY_VERSION,
    productEvidencePolicyId: PRODUCT_MATCH_EVALUATION_POLICY_ID,
    productEvidencePolicyVersion: PRODUCT_MATCH_EVALUATION_POLICY_VERSION,
    findingCreation: PRODUCT_MATCH_FINDING_CREATION,
    suppressionAuthority: PRODUCT_MATCH_SUPPRESSION_AUTHORITY,
    explicitVersionsUsed: DELIBERATE_PRODUCT_MATCH_EVALUATION_EXPLICIT_VERSIONS_USED,
    normalizationVersion: DELIBERATE_PRODUCT_MATCH_EVALUATION_NORMALIZATION_VERSION,
    occurrenceCap: DELIBERATE_PRODUCT_MATCH_EVALUATION_OCCURRENCE_CAP,
    selectionProbe: DELIBERATE_PRODUCT_MATCH_EVALUATION_SELECTION_PROBE,
    findingWrites: DELIBERATE_PRODUCT_MATCH_EVALUATION_FINDING_WRITES,
    providerCalls: DELIBERATE_PRODUCT_MATCH_EVALUATION_PROVIDER_CALLS,
  };
}

async function seedAsset(
  client: PrismaClient,
  label: string,
  options: {
    readonly role?: 'owner' | 'admin';
    readonly normalizationVersion?: string;
    readonly occurrences?: readonly { version: string; bomRef: string }[];
  } = {},
): Promise<SeededAsset> {
  const slug = `pmc-${randomUUID().slice(0, 8)}`;
  const org = await createOrg(client, slug);
  const user = await client.user.create({
    data: {
      email: `${label}-${randomUUID().slice(0, 8)}@synthetic.patchpilot.test`.toLowerCase(),
      displayName: label.slice(0, 80),
    },
  });
  const membership = await client.membership.create({
    data: { organizationId: org.id, userId: user.id, role: options.role ?? 'owner' },
  });
  const asset = await createAsset(client, org.id, `asset-${label}`.slice(0, 80));
  const sbomSha256 = digest(`sbom:${label}:${asset.id}`);
  const sbom = await createSbom(client, {
    organizationId: org.id,
    assetId: asset.id,
    sha256: sbomSha256,
    receivedAt: new Date('2026-10-02T12:00:00.000Z'),
  });
  const ingestion = await createProcessingIngestion(client, {
    organizationId: org.id,
    sbomId: sbom.id,
    assetId: asset.id,
  });
  const specs = options.occurrences ?? [{ version: '1.1.0', bomRef: 'component-1' }];
  const components = new Map<string, string>();
  for (const spec of specs) {
    let componentId = components.get(PACKAGE_NAME);
    if (componentId === undefined) {
      const resolved = resolvedComponent({
        name: PACKAGE_NAME,
        bomRef: spec.bomRef,
        version: '0.0.0',
      });
      const created = await client.component.create({
        data: {
          organizationId: org.id,
          identityKey: resolved.identityKey,
          purl: resolved.versionlessPurl,
          ecosystem: 'npm',
          namespace: null,
          name: PACKAGE_NAME,
          identityState: 'resolved',
        },
      });
      componentId = created.id;
      components.set(PACKAGE_NAME, componentId);
    }
    await client.componentOccurrence.create({
      data: {
        organizationId: org.id,
        assetId: asset.id,
        sbomId: sbom.id,
        sbomIngestionId: ingestion.id,
        componentId,
        bomRef: spec.bomRef,
        version: spec.version,
        versionKnown: spec.version.length > 0,
        isDirect: true,
      },
    });
  }
  await client.sbomIngestion.update({
    where: { id: ingestion.id },
    data: {
      state: 'completed',
      normalizationVersion: options.normalizationVersion ?? '2',
      completedAt: new Date('2026-10-02T12:00:00.000Z'),
      graphCompleteness: 'no_dependencies',
      componentCount: components.size,
      dependencyEdgeCount: 0,
      warningCount: 0,
      stage: null,
    },
  });
  await client.asset.update({
    where: { id: asset.id },
    data: { lastSuccessfulSbomIngestionId: ingestion.id },
  });
  return {
    organizationId: org.id,
    assetId: asset.id,
    userId: user.id,
    membershipId: membership.id,
    ingestionId: ingestion.id,
    sbomId: sbom.id,
  };
}

async function insertRevision(
  client: PrismaClient,
  label: string,
  options: {
    readonly approve: boolean;
    readonly packageName?: string;
    readonly canonicalCve?: string;
  },
): Promise<AdvisoryRecord> {
  const packageName = options.packageName ?? PACKAGE_NAME;
  const rangeFingerprint = session14RangeFingerprint(RANGES, []);
  const contentFingerprint = digest(`content:${label}:${randomUUID()}`);
  const advisoryId = `REVIEWNPM${digest(`${label}:${randomUUID()}`).slice(0, 8).toUpperCase()}`;
  const familyDigest = digest(`family:${advisoryId}:${randomUUID()}`);
  const revisionDigest = digest(`revision:${advisoryId}:${randomUUID()}`);
  const authorIdentity = 'author.one';
  const vulnerability = await client.vulnerability.create({
    data: {
      osvId: `REVIEWED-${digest(label).slice(0, 16).toUpperCase()}-${randomUUID().slice(0, 8)}`,
    },
    select: { id: true },
  });
  const family = await client.advisoryFamily.create({
    data: {
      familySchemaVersion: MAINTAINER_REVIEWED_FAMILY_SCHEMA_VERSION,
      source: 'maintainer_reviewed_advisory',
      advisoryId,
      familyDigest,
      sourceRegistryVersion: MAINTAINER_REVIEWED_APPROVAL_PINS.licensePolicyId,
    },
    select: { id: true },
  });
  const revision = await client.advisoryRevision.create({
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
      aliasCount: options.canonicalCve === undefined ? 0 : 1,
      cveAliasCount: options.canonicalCve === undefined ? 0 : 1,
      aliasSetDigest: digest(`aliases:${revisionDigest}`),
      replayFingerprint: digest(`replay:${revisionDigest}`),
      authorIdentity,
    },
    select: { id: true },
  });
  if (options.canonicalCve !== undefined) {
    await client.advisoryRevisionAlias.create({
      data: {
        advisoryRevisionId: revision.id,
        ordinal: 1,
        aliasType: 'canonical_cve',
        aliasValue: options.canonicalCve,
        aliasPolicyVersion: 'osv_advisory_alias_policy_v1',
        sourceClassification: 'maintainer_reviewed_advisory',
        reviewClassification: 'unreviewed',
        replayFingerprint: digest(`alias:${advisoryId}:${options.canonicalCve}`),
      },
    });
  }
  await client.advisoryRevisionRangeEvent.createMany({
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
  await client.advisoryVulnerabilityBinding.create({
    data: {
      bindingSchemaVersion: MAINTAINER_REVIEWED_BINDING_SCHEMA_VERSION,
      advisoryRevisionId: revision.id,
      vulnerabilityId: vulnerability.id,
      mappingPolicyId: VULNERABILITY_MAPPING_POLICY_ID,
      mappingMethod: EXACT_MAPPING_METHOD,
      mappingEvidenceFingerprint: digest(`mapping:${revisionDigest}`),
      mappingReviewState: 'reviewed',
      mappingSourceClassification: 'explicit_reviewed_binding',
      conflictClassification: 'none',
      bindingClassification: 'provider_native_without_cve',
      replayFingerprint: digest(`binding:${revisionDigest}`),
    },
  });
  if (options.approve) {
    const approval = await createApprovalCapabilityHarness(client).approve(
      approvalCommand({
        revisionId: revision.id,
        familyDigest,
        contentFingerprint,
        rangeFingerprint,
        vulnerabilityId: vulnerability.id,
        authorIdentity,
        packageName,
      }),
    );
    if (approval.kind !== 'recorded') {
      throw new Error(`approval for ${label} was ${approval.kind}`);
    }
  }
  return {
    revisionId: revision.id,
    contentFingerprint,
    vulnerabilityId: vulnerability.id,
  };
}

async function insertSyntheticRevision(client: PrismaClient, label: string): Promise<void> {
  const familyDigest = digest(`synthetic-family:${label}:${randomUUID()}`);
  const revisionDigest = digest(`synthetic-revision:${label}:${randomUUID()}`);
  const advisoryId = `SYNTHETIC${digest(label).slice(0, 8).toUpperCase()}`;
  const family = await client.advisoryFamily.create({
    data: {
      familySchemaVersion: 'osv_advisory_family_identity_v1',
      source: 'synthetic_fixture',
      advisoryId,
      familyDigest,
      sourceRegistryVersion: 'osv_source_license_registry_v1',
    },
    select: { id: true },
  });
  await client.advisoryRevision.create({
    data: {
      revisionSchemaVersion: 'osv_advisory_revision_identity_v1',
      advisoryFamilyId: family.id,
      source: 'synthetic_fixture',
      advisoryId,
      familyDigest,
      revisionDigest,
      providerGeneration: 'synthetic_not_a_provider_generation',
      contentFingerprint: digest(`synthetic-content:${label}`),
      session14RangeFingerprint: digest(`synthetic-range:${label}`),
      productRangeFingerprint: digest(`synthetic-range:${label}`),
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
      packageIdentityKey: packageIdentity(),
      evaluatorVersion: PRODUCT_MATCH_EVALUATOR_VERSION,
      matchingPolicyId: PRODUCT_MATCH_MATCHING_POLICY_ID,
      aliasCount: 0,
      cveAliasCount: 0,
      aliasSetDigest: digest(`synthetic-aliases:${revisionDigest}`),
      replayFingerprint: digest(`synthetic-replay:${revisionDigest}`),
    },
  });
}

function approvalCommand(input: {
  readonly revisionId: string;
  readonly familyDigest: string;
  readonly contentFingerprint: string;
  readonly rangeFingerprint: string;
  readonly vulnerabilityId: string;
  readonly authorIdentity: string;
  readonly packageName: string;
}) {
  const identity = packageIdentity(input.packageName);
  const approvalReplayFingerprint = maintainerReviewedApprovalReplayFingerprint({
    advisoryRevisionId: input.revisionId,
    familyDigest: input.familyDigest,
    approvalPolicyId: MAINTAINER_REVIEWED_APPROVAL_PINS.approvalPolicyId,
    approvalPolicyVersion: MAINTAINER_REVIEWED_APPROVAL_PINS.approvalPolicyVersion,
    approvalPurpose: MAINTAINER_REVIEWED_APPROVAL_PINS.approvalPurpose,
    sourceClassification: MAINTAINER_REVIEWED_APPROVAL_PINS.origin,
    authorIdentity: input.authorIdentity,
    reviewerIdentity: 'reviewer.two',
    reviewerClassification: MAINTAINER_REVIEWED_APPROVAL_PINS.reviewerClassification,
    contentFingerprint: input.contentFingerprint,
    rangeFingerprint: input.rangeFingerprint,
    packageIdentityKey: identity,
    vulnerabilityId: input.vulnerabilityId,
    sourceLicensePolicyId: MAINTAINER_REVIEWED_APPROVAL_PINS.licensePolicyId,
    sourceLicensePolicyVersion: MAINTAINER_REVIEWED_APPROVAL_PINS.licensePolicyVersion,
    approvedLicenseClassification: MAINTAINER_REVIEWED_APPROVAL_PINS.licenseClassification,
    licenseDecisionCanonical: MAINTAINER_REVIEWED_APPROVAL_PINS.licenseCanonical,
  });
  return {
    commandSchemaVersion: MAINTAINER_REVIEWED_APPROVAL_COMMAND_SCHEMA_VERSION,
    advisoryRevisionId: input.revisionId,
    expectedAdvisoryFamilyIdentity: input.familyDigest,
    expectedSourceClassification: MAINTAINER_REVIEWED_APPROVAL_PINS.origin,
    expectedContentFingerprint: input.contentFingerprint,
    expectedRangeFingerprint: input.rangeFingerprint,
    expectedNpmPackageIdentity: identity,
    expectedVulnerabilityId: input.vulnerabilityId,
    authorIdentity: input.authorIdentity,
    reviewerIdentity: 'reviewer.two',
    reviewerAuthorityClassification: MAINTAINER_REVIEWED_APPROVAL_PINS.reviewerClassification,
    approvalPolicyId: MAINTAINER_REVIEWED_APPROVAL_PINS.approvalPolicyId,
    approvalPolicyVersion: MAINTAINER_REVIEWED_APPROVAL_PINS.approvalPolicyVersion,
    approvalPurpose: MAINTAINER_REVIEWED_APPROVAL_PINS.approvalPurpose,
    sourceLicensePolicyId: MAINTAINER_REVIEWED_APPROVAL_PINS.licensePolicyId,
    sourceLicensePolicyVersion: MAINTAINER_REVIEWED_APPROVAL_PINS.licensePolicyVersion,
    approvedLicenseClassification: MAINTAINER_REVIEWED_APPROVAL_PINS.licenseClassification,
    correlationId: randomUUID(),
    approvalReplayFingerprint,
  };
}
