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
  maintainerReviewedApprovalReplayFingerprint,
  session14RangeFingerprint,
} from '@patchpilot/vulnerability-intelligence';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { createMaintainerReviewedAdvisoryApprovalPersistence } from './maintainer-reviewed-advisory-approval-persistence.js';
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
    const approval = await createMaintainerReviewedAdvisoryApprovalPersistence(
      prisma,
    ).recordMaintainerReviewedAdvisoryApproval({
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
    return { evaluationCommand, organizationId: org.id };
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
    expect(hidden.kind).toBe('not_found');
    const visible = await composition.inspect({
      organizationId: seeded.organizationId,
      evidenceId: first.projection.matchEvidenceId,
    });
    expect(visible.kind).toBe('found');
    expect(await prisma.finding.count()).toBe(findingBefore);
    expect(await prisma.matchEvaluationEvidence.count()).toBe(syntheticMatchesBefore);
  });

  it('rejects another tenant occurrence before evaluation or persistence', async () => {
    const seeded = await seedLegal('tenant');
    const other = await createOrg(prisma, `cross-${randomUUID().slice(0, 8)}`);
    const before = await prisma.productMatchEvaluationEvidence.count();
    const findingsBefore = await prisma.finding.count();
    const composition = service();
    const result = await composition.execute({
      ...seeded.evaluationCommand,
      organizationId: other.id,
      correlationId: randomUUID(),
    });
    expect(result.kind).toBe('rejected');
    if (result.kind === 'rejected') {
      expect(result.code).toBe('tenant_mismatch');
      expect(result.evaluatorCalls).toBe(0);
      expect(result.inserts).toBe(0);
      expect(result.findingWrites).toBe(0);
    }
    expect(await prisma.productMatchEvaluationEvidence.count()).toBe(before);
    expect(await prisma.finding.count()).toBe(findingsBefore);
  });

  it('lets one concurrent duplicate win and keeps one row', async () => {
    const seeded = await seedLegal('race');
    const before = await prisma.productMatchEvaluationEvidence.count();
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const pending = [0, 1].map(async () => {
      await gate;
      return service().execute({
        ...seeded.evaluationCommand,
        correlationId: randomUUID(),
      });
    });
    release();
    const results = await Promise.all(pending);
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
});
