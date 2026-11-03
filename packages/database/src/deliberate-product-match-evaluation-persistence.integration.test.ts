/**
 * Disposable PostgreSQL proof for one deliberate Product Match Evidence evaluation.
 * The command writes immutable npm evidence and one audit row, or neither.
 * Finding writes stay zero. Provider calls stay zero. No migration.
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
  buildComponentIdentityKey,
} from '@patchpilot/domain';
import {
  EXACT_MAPPING_METHOD,
  MAINTAINER_REVIEWED_APPROVAL_COMMAND_SCHEMA_VERSION,
  MAINTAINER_REVIEWED_APPROVAL_PINS,
  MAINTAINER_REVIEWED_BINDING_SCHEMA_VERSION,
  MAINTAINER_REVIEWED_FAMILY_SCHEMA_VERSION,
  MAINTAINER_REVIEWED_REVISION_SCHEMA_VERSION,
  PRODUCT_MATCH_EVALUATION_ORIGIN,
  PRODUCT_MATCH_EVALUATION_POLICY_ID,
  PRODUCT_MATCH_EVALUATION_POLICY_VERSION,
  PRODUCT_MATCH_EVALUATOR_ID,
  PRODUCT_MATCH_FINDING_CREATION,
  PRODUCT_MATCH_SUPPRESSION_AUTHORITY,
  PRODUCT_MATCH_EVALUATOR_VERSION,
  PRODUCT_MATCH_MATCHING_POLICY_ID,
  PRODUCT_MATCH_MATCHING_POLICY_VERSION,
  SELECTED_FIRST_ECOSYSTEM,
  VULNERABILITY_MAPPING_POLICY_ID,
  classifyNpmPackageIdentityFromParts,
  componentEvidenceFingerprint,
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
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
  issueFindingCreationAuthorization,
  openFindingCreationCommand,
} from '../../domain/dist/findings/controlled-creation/authorization.js';
import { createControlledFindingCreationPersistence } from './controlled-finding-creation-persistence.js';
import { createControlledFindingDiscoveryPersistence } from './controlled-finding-discovery-persistence.js';
import {
  createDeliberateProductMatchEvaluationPersistence,
  type DeliberateProductMatchEvaluationFault,
} from './deliberate-product-match-evaluation-persistence.js';
import {
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
} from './integration-database.js';
import { writeProductMatchEvaluationEvidence } from './product-match-evaluation-persistence.js';
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

const DECISIONS: DeliberateProductMatchEvaluationDecisions = {
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

type AdvisoryRecord = {
  readonly revisionId: string;
  readonly approvalId: string | null;
  readonly vulnerabilityId: string;
  readonly familyId: string;
  readonly familyDigest: string;
  readonly advisoryId: string;
  readonly contentFingerprint: string;
  readonly rangeFingerprint: string;
  readonly packageIdentityKey: string;
  readonly revisionDigest: string;
  readonly authorIdentity: string;
};

type OccurrenceSpec = {
  readonly version: string;
  readonly bomRef: string;
  readonly versionKnown?: boolean;
  readonly isDirect?: boolean | null;
  readonly name?: string;
  readonly ecosystem?: string | null;
  readonly identityState?: 'resolved' | 'ambiguous' | 'unsupported';
};

type SeededOccurrence = {
  readonly occurrenceId: string;
  readonly componentId: string;
  readonly identityKey: string;
  readonly version: string;
  readonly versionKnown: boolean;
  readonly isDirect: boolean | null;
  readonly name: string;
  readonly ecosystem: string | null;
  readonly purl: string | null;
};

type SeededAsset = {
  readonly organizationId: string;
  readonly assetId: string;
  readonly userId: string;
  readonly membershipId: string;
  readonly ingestionId: string;
  readonly sbomId: string;
  readonly sbomSha256: string;
  readonly occurrences: readonly SeededOccurrence[];
};

type SeedOptions = {
  readonly occurrences?: readonly OccurrenceSpec[];
  readonly role?: 'owner' | 'admin' | 'member' | 'viewer';
  readonly normalizationVersion?: string;
  readonly ingestionState?: 'completed' | 'processing';
  readonly setPointer?: boolean;
};

function digest(label: string): string {
  return createHash('sha256').update(label).digest('hex');
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

function compareUuid(left: string, right: string): number {
  if (left < right) {
    return -1;
  }
  if (left > right) {
    return 1;
  }
  return 0;
}

describe('deliberate product match evaluation PostgreSQL persistence', () => {
  let databaseUrl = '';
  let databaseName = '';
  let admin: Awaited<ReturnType<typeof createEphemeralDatabase>>['admin'];
  let prisma: PrismaClient;
  let advisory: AdvisoryRecord;

  beforeAll(async () => {
    const ephemeral = await createEphemeralDatabase('it');
    databaseUrl = ephemeral.databaseUrl;
    databaseName = ephemeral.databaseName;
    admin = ephemeral.admin;
    await deployMigrations(databaseUrl);
    prisma = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
    advisory = await insertApprovedRevision(prisma, 'shared');
  });

  afterAll(async () => {
    if (prisma !== undefined) {
      await prisma.$disconnect();
    }
    if (admin !== undefined) {
      await dropEphemeralDatabase(admin, databaseName);
    }
  });

  it('persists affected, unaffected, and unknown rows and skips the rest once', async () => {
    const seeded = await seedAsset(prisma, advisory, 'mixed', {
      occurrences: [
        { version: '1.1.0', bomRef: 'direct-affected', isDirect: true },
        { version: '1.2.0', bomRef: 'indirect-affected', isDirect: false },
        { version: '3.0.0', bomRef: 'unaffected' },
        { version: 'not-a-version', bomRef: 'unknown' },
        { version: '', bomRef: 'versionless', versionKnown: false },
        { version: '1.2.3\n', bomRef: 'unrepresentable' },
        { version: '1.1.0', bomRef: 'other-name', name: 'other-npm-widget' },
        { version: '1.1.0', bomRef: 'other-ecosystem', ecosystem: 'pypi' },
        { version: '1.1.0', bomRef: 'display-name', name: 'reviewed-npm-widget-display' },
      ],
    });
    const evaluated = await runEvaluation(prisma, seeded, advisory.revisionId);
    expect(evaluated.result).toMatchObject({
      status: 'evaluated',
      selectedCount: 6,
      evaluatedCount: 4,
      insertedCount: 4,
      replayedCount: 0,
      skippedCount: 2,
      skippedByReason: { version_not_known: 1, version_unrepresentable: 1 },
      outcomeCounts: { affected: 2, unaffected: 1, unknown: 1 },
      findingCreation: 'unavailable',
    });
    const evidence = await prisma.productMatchEvaluationEvidence.findMany({
      where: { organizationId: seeded.organizationId },
      select: { outcome: true, rawObservedVersion: true, componentOccurrenceId: true },
    });
    expect(evidence).toHaveLength(4);
    expect(evidence.map((row) => row.outcome).sort()).toEqual([
      'affected',
      'affected',
      'unaffected',
      'unknown',
    ]);
    const indirect = seeded.occurrences.find((row) => row.version === '1.2.0');
    expect(indirect?.isDirect).toBe(false);
    expect(evidence.some((row) => row.componentOccurrenceId === indirect?.occurrenceId)).toBe(true);
    expect(evidence.some((row) => row.rawObservedVersion === '')).toBe(false);
    expect(evidence.some((row) => row.rawObservedVersion.includes('\n'))).toBe(false);
    expect(await matchAuditCount(prisma, seeded.organizationId)).toBe(1);
    expect(await prisma.finding.count({ where: { organizationId: seeded.organizationId } })).toBe(
      0,
    );
    expect(
      await prisma.riskCalculation.count({ where: { organizationId: seeded.organizationId } }),
    ).toBe(0);
    expect(await prisma.instanceAdvisoryAuthorityGrant.count()).toBe(0);
    const audit = await prisma.auditEvent.findFirstOrThrow({
      where: {
        organizationId: seeded.organizationId,
        action: DELIBERATE_PRODUCT_MATCH_EVALUATION_AUDIT_ACTION,
      },
    });
    expect(audit.actorType).toBe('user');
    expect(audit.subjectType).toBe('asset');
    expect(audit.subjectId).toBe(seeded.assetId);
    expect(audit.correlationId).toBe(evaluated.command.correlationId);
    const payload = JSON.stringify(audit.payload);
    expect(payload).not.toContain(PACKAGE_NAME);
    expect(payload).not.toContain('1.1.0');
    expect(payload).not.toContain('1.2.0');
    expect(payload).not.toContain('3.0.0');
    expect(payload).not.toContain('not-a-version');
    expect(payload).not.toContain('affected_within');
    expect(payload).not.toContain('unknown_invalid');
    expect(payload).not.toContain('unaffected_at_or_after');
    expect(payload).not.toContain(advisory.vulnerabilityId);
    expect(payload).not.toContain(advisory.contentFingerprint);
    expect(payload).not.toContain(advisory.rangeFingerprint);
    expect(payload).not.toContain('GHSA');
    expect(payload).not.toContain('CVE');
    for (const row of evidence) {
      expect(payload).not.toContain(row.componentOccurrenceId);
    }
    const discovery = await createControlledFindingDiscoveryPersistence(prisma).read({
      organizationId: seeded.organizationId,
      membershipId: seeded.membershipId,
      actorId: seeded.userId,
      assetId: seeded.assetId,
      cursor: null,
    });
    expect(discovery.status).toBe('ready');
    if (discovery.status !== 'ready') {
      return;
    }
    const versions = discovery.pairs.flatMap((pair) => pair.qualifying.map((row) => row.version));
    expect(versions.sort()).toEqual(['1.1.0', '1.2.0']);
  });

  it('replays one evidence set and writes no second audit', async () => {
    const seeded = await seedAsset(prisma, advisory, 'replay');
    const first = await runEvaluation(prisma, seeded, advisory.revisionId);
    expect(first.result.status).toBe('evaluated');
    const second = await runEvaluation(prisma, seeded, advisory.revisionId);
    expect(second.result).toMatchObject({
      status: 'already_applied',
      insertedCount: 0,
      replayedCount: 1,
    });
    expect(await evidenceCount(prisma, seeded.organizationId)).toBe(1);
    expect(await matchAuditCount(prisma, seeded.organizationId)).toBe(1);
  });

  it('rejects a conflicting stored body and writes nothing new', async () => {
    const seeded = await seedAsset(prisma, advisory, 'conflict');
    const occurrence = seeded.occurrences[0];
    if (occurrence === undefined) {
      throw new Error('conflict seed has no occurrence');
    }
    const realFingerprint = componentEvidenceFingerprint({
      organizationId: seeded.organizationId,
      componentOccurrenceId: occurrence.occurrenceId,
      assetId: seeded.assetId,
      sbomId: seeded.sbomId,
      sbomIngestionId: seeded.ingestionId,
      componentId: occurrence.componentId,
      componentIdentityKey: occurrence.identityKey,
      ecosystem: 'npm',
      namespace: null,
      name: PACKAGE_NAME,
      rawObservedVersion: occurrence.version,
      versionKnown: true,
      sbomSha256: seeded.sbomSha256,
    });
    const tampered = `${realFingerprint.startsWith('a') ? 'b' : 'a'}${realFingerprint.slice(1)}`;
    if (advisory.approvalId === null) {
      throw new Error('shared advisory has no approval');
    }
    await prisma.$transaction((tx) =>
      writeProductMatchEvaluationEvidence(tx, {
        snapshot: {
          organizationId: seeded.organizationId,
          componentOccurrenceId: occurrence.occurrenceId,
          assetId: seeded.assetId,
          sbomId: seeded.sbomId,
          sbomIngestionId: seeded.ingestionId,
          componentId: occurrence.componentId,
          componentIdentityKey: occurrence.identityKey,
          sbomSha256: seeded.sbomSha256,
          ecosystem: 'npm',
          namespace: null,
          name: PACKAGE_NAME,
          purl: occurrence.purl,
          rawObservedVersion: occurrence.version,
          versionKnown: true,
          identityState: 'resolved',
        },
        familyId: advisory.familyId,
        body: {
          organizationId: seeded.organizationId,
          componentOccurrenceId: occurrence.occurrenceId,
          componentEvidenceFingerprint: tampered,
          packageIdentityKey: advisory.packageIdentityKey,
          rawObservedVersion: occurrence.version,
          advisoryRevisionId: advisory.revisionId,
          approvalEvidenceId: advisory.approvalId ?? '',
          contentFingerprint: advisory.contentFingerprint,
          rangeFingerprint: advisory.rangeFingerprint,
          vulnerabilityId: advisory.vulnerabilityId,
          evaluatorId: PRODUCT_MATCH_EVALUATOR_ID,
          evaluatorVersion: PRODUCT_MATCH_EVALUATOR_VERSION,
          matchingPolicyId: PRODUCT_MATCH_MATCHING_POLICY_ID,
          matchingPolicyVersion: PRODUCT_MATCH_MATCHING_POLICY_VERSION,
          productEvidencePolicyId: PRODUCT_MATCH_EVALUATION_POLICY_ID,
          productEvidencePolicyVersion: String(PRODUCT_MATCH_EVALUATION_POLICY_VERSION),
          productOrigin: PRODUCT_MATCH_EVALUATION_ORIGIN,
          outcome: 'affected',
          explanationCodes: ['affected_within_introduced_fixed_range'],
        },
      }),
    );
    const conflicted = await runEvaluation(prisma, seeded, advisory.revisionId);
    expect(conflicted.result).toEqual(closedFailure('immutable_conflict'));
    expect(await evidenceCount(prisma, seeded.organizationId)).toBe(1);
    expect(await matchAuditCount(prisma, seeded.organizationId)).toBe(0);
  });

  it('commits sixteen occurrences and writes nothing for seventeen', async () => {
    const sixteen = await seedAsset(prisma, advisory, 'cap16', {
      occurrences: versions(16),
    });
    const committed = await runEvaluation(prisma, sixteen, advisory.revisionId);
    expect(committed.result).toMatchObject({
      status: 'evaluated',
      selectedCount: 16,
      insertedCount: 16,
      outcomeCounts: { affected: 16, unaffected: 0, unknown: 0 },
    });
    expect(await evidenceCount(prisma, sixteen.organizationId)).toBe(16);
    const seventeen = await seedAsset(prisma, advisory, 'cap17', {
      occurrences: versions(17),
    });
    const exceeded = await runEvaluation(prisma, seventeen, advisory.revisionId);
    expect(exceeded.result).toEqual(closedFailure('capacity_exceeded'));
    expect(await evidenceCount(prisma, seventeen.organizationId)).toBe(0);
    expect(await matchAuditCount(prisma, seventeen.organizationId)).toBe(0);
  });

  it('rolls back evidence and audit when a fault is injected', async () => {
    const seeded = await seedAsset(prisma, advisory, 'fault');
    for (const fault of [
      'before_evidence_insert',
      'before_audit_insert',
      'after_audit_insert',
    ] as const) {
      const failed = await runEvaluation(prisma, seeded, advisory.revisionId, undefined, fault);
      expect(failed.result).toEqual(closedFailure('transaction_aborted'));
      expect(await evidenceCount(prisma, seeded.organizationId)).toBe(0);
      expect(await matchAuditCount(prisma, seeded.organizationId)).toBe(0);
    }
    const committed = await runEvaluation(prisma, seeded, advisory.revisionId);
    expect(committed.result.status).toBe('evaluated');
    expect(await evidenceCount(prisma, seeded.organizationId)).toBe(1);
    expect(await matchAuditCount(prisma, seeded.organizationId)).toBe(1);
  });

  it('denies every non-owner role and still allows the reloaded owner', async () => {
    const seeded = await seedAsset(prisma, advisory, 'roles', { role: 'admin' });
    for (const role of ['admin', 'member', 'viewer'] as const) {
      await prisma.membership.update({
        where: { id: seeded.membershipId },
        data: { role },
      });
      const denied = await runEvaluation(prisma, seeded, advisory.revisionId);
      expect(denied.result).toEqual(closedFailure('authority_rejected'));
      expect(await evidenceCount(prisma, seeded.organizationId)).toBe(0);
      expect(await matchAuditCount(prisma, seeded.organizationId)).toBe(0);
    }
    await prisma.membership.update({
      where: { id: seeded.membershipId },
      data: { role: 'owner' },
    });
    const allowed = await runEvaluation(prisma, seeded, advisory.revisionId);
    expect(allowed.result.status).toBe('evaluated');
    await prisma.membership.update({
      where: { id: seeded.membershipId },
      data: { role: 'viewer' },
    });
    const later = await runEvaluation(prisma, seeded, advisory.revisionId);
    expect(later.result).toEqual(closedFailure('authority_rejected'));
    expect(await evidenceCount(prisma, seeded.organizationId)).toBe(1);
    expect(await matchAuditCount(prisma, seeded.organizationId)).toBe(1);
  });

  it('rejects a disabled actor and ignores a disabled user who is not the actor', async () => {
    const seeded = await seedAsset(prisma, advisory, 'disabled-actor');
    await disableUser(prisma, seeded.userId);
    const denied = await runEvaluation(prisma, seeded, advisory.revisionId);
    expect(denied.result).toEqual(closedFailure('authority_rejected'));
    expect(await evidenceCount(prisma, seeded.organizationId)).toBe(0);
    const other = await seedAsset(prisma, advisory, 'disabled-other');
    const bystander = await prisma.user.create({
      data: {
        email: `bystander-${randomUUID().slice(0, 8)}@synthetic.patchpilot.test`,
        displayName: 'bystander',
      },
    });
    await disableUser(prisma, bystander.id);
    const allowed = await runEvaluation(prisma, other, advisory.revisionId);
    expect(allowed.result.status).toBe('evaluated');
  });

  it('reports foreign and absent assets as the same not_found result', async () => {
    const owner = await seedAsset(prisma, advisory, 'foreign-owner');
    const other = await seedAsset(prisma, advisory, 'foreign-asset');
    const foreign = await runEvaluation(
      prisma,
      { ...owner, assetId: other.assetId },
      advisory.revisionId,
    );
    const absent = await runEvaluation(
      prisma,
      { ...owner, assetId: randomUUID() },
      advisory.revisionId,
    );
    expect(foreign.result).toEqual(closedFailure('not_found'));
    expect(absent.result).toEqual(foreign.result);
    expect(await evidenceCount(prisma, owner.organizationId)).toBe(0);
    expect(await evidenceCount(prisma, other.organizationId)).toBe(0);
  });

  it('does not select mismatched packages and skips a versionless graph', async () => {
    const mismatched = await seedAsset(prisma, advisory, 'mismatch', {
      occurrences: [{ version: '1.1.0', bomRef: 'display', name: 'reviewed-npm-widget-display' }],
    });
    const none = await runEvaluation(prisma, mismatched, advisory.revisionId);
    expect(none.result).toMatchObject({ status: 'no_relevant_occurrence', selectedCount: 0 });
    expect(await evidenceCount(prisma, mismatched.organizationId)).toBe(0);
    const versionless = await seedAsset(prisma, advisory, 'versionless', {
      occurrences: [{ version: '', bomRef: 'empty', versionKnown: false }],
    });
    const skipped = await runEvaluation(prisma, versionless, advisory.revisionId);
    expect(skipped.result).toMatchObject({
      status: 'no_evaluable_occurrence',
      selectedCount: 1,
      skippedCount: 1,
      evaluatedCount: 0,
    });
    expect(await evidenceCount(prisma, versionless.organizationId)).toBe(0);
    expect(await matchAuditCount(prisma, versionless.organizationId)).toBe(0);
  });

  it('rejects ineligible revisions with one status and zero writes', async () => {
    const seeded = await seedAsset(prisma, advisory, 'ineligible');
    const missing = await runEvaluation(prisma, seeded, randomUUID());
    expect(missing.result).toEqual(closedFailure('advisory_not_eligible'));
    const unapproved = await insertRevision(prisma, 'unapproved', { approve: false });
    const withdrawn = await insertRevision(prisma, 'withdrawn', {
      approve: false,
      revisionDisposition: 'withdrawn',
      withdrawalClassification: 'withdrawn',
    });
    const quarantined = await insertRevision(prisma, 'quarantined', {
      approve: false,
      revisionDisposition: 'quarantined',
      quarantineClassification: 'quarantined',
    });
    const emptyRange = await insertRevision(prisma, 'empty-range', {
      approve: true,
      includeRanges: false,
    });
    const synthetic = await insertSyntheticRevision(prisma, 'synthetic');
    for (const revisionId of [
      unapproved.revisionId,
      withdrawn.revisionId,
      quarantined.revisionId,
      emptyRange.revisionId,
      synthetic.revisionId,
    ]) {
      const rejected = await runEvaluation(prisma, seeded, revisionId);
      expect(rejected.result).toEqual(closedFailure('advisory_not_eligible'));
    }
    const prior = await insertApprovedRevision(prisma, 'superseded-prior');
    const successor = await insertRevision(prisma, 'superseding-tip', {
      approve: true,
      familyId: prior.familyId,
      familyDigest: prior.familyDigest,
      advisoryId: prior.advisoryId,
      supersedesRevisionId: prior.revisionId,
      supersedesRevisionDigest: prior.revisionDigest,
      revisionDisposition: 'superseding',
    });
    const superseded = await runEvaluation(prisma, seeded, prior.revisionId);
    const superseding = await runEvaluation(prisma, seeded, successor.revisionId);
    expect(superseded.result).toEqual(closedFailure('advisory_not_eligible'));
    expect(superseding.result).toEqual(closedFailure('advisory_not_eligible'));
    expect(await evidenceCount(prisma, seeded.organizationId)).toBe(0);
    expect(await matchAuditCount(prisma, seeded.organizationId)).toBe(0);
  });

  it('rejects an ingestion that is missing, unfinished, or not normalization 2', async () => {
    const missing = await seedAsset(prisma, advisory, 'no-pointer', { setPointer: false });
    expect((await runEvaluation(prisma, missing, advisory.revisionId)).result).toEqual(
      closedFailure('no_successful_ingestion'),
    );
    const processing = await seedAsset(prisma, advisory, 'processing', {
      ingestionState: 'processing',
    });
    expect((await runEvaluation(prisma, processing, advisory.revisionId)).result).toEqual(
      closedFailure('ingestion_not_evaluable'),
    );
    const versionOne = await seedAsset(prisma, advisory, 'version-1', {
      normalizationVersion: '1',
    });
    expect((await runEvaluation(prisma, versionOne, advisory.revisionId)).result).toEqual(
      closedFailure('ingestion_not_evaluable'),
    );
    expect(await evidenceCount(prisma, missing.organizationId)).toBe(0);
    expect(await evidenceCount(prisma, processing.organizationId)).toBe(0);
    expect(await evidenceCount(prisma, versionOne.organizationId)).toBe(0);
  });

  it('evaluates only the locked ingestion pointer', async () => {
    const seeded = await seedAsset(prisma, advisory, 'stale');
    const laterSha = digest(`later:${seeded.assetId}`);
    const laterSbom = await createSbom(prisma, {
      organizationId: seeded.organizationId,
      assetId: seeded.assetId,
      sha256: laterSha,
      receivedAt: new Date('2026-10-03T12:00:00.000Z'),
    });
    const later = await createProcessingIngestion(prisma, {
      organizationId: seeded.organizationId,
      sbomId: laterSbom.id,
      assetId: seeded.assetId,
    });
    const componentId = seeded.occurrences[0]?.componentId;
    if (componentId === undefined) {
      throw new Error('stale seed has no component');
    }
    await prisma.componentOccurrence.create({
      data: {
        organizationId: seeded.organizationId,
        assetId: seeded.assetId,
        sbomId: laterSbom.id,
        sbomIngestionId: later.id,
        componentId,
        bomRef: 'later-version',
        version: '9.9.9',
        versionKnown: true,
        isDirect: true,
      },
    });
    await completeIngestion(prisma, later.id, 1);
    const evaluated = await runEvaluation(prisma, seeded, advisory.revisionId);
    expect(evaluated.result).toMatchObject({ status: 'evaluated', selectedCount: 1 });
    const versions = await prisma.productMatchEvaluationEvidence.findMany({
      where: { organizationId: seeded.organizationId },
      select: { rawObservedVersion: true, sbomIngestionId: true },
    });
    expect(versions).toEqual([
      { rawObservedVersion: '1.1.0', sbomIngestionId: seeded.ingestionId },
    ]);
  });

  it('aborts a resolved-name row whose identity state is not resolved', async () => {
    const seeded = await seedAsset(prisma, advisory, 'ambiguous', {
      occurrences: [
        {
          version: '1.1.0',
          bomRef: 'ambiguous',
          identityState: 'ambiguous',
        },
      ],
    });
    const aborted = await runEvaluation(prisma, seeded, advisory.revisionId);
    expect(aborted.result).toEqual(closedFailure('malformed_persisted_state'));
    expect(await evidenceCount(prisma, seeded.organizationId)).toBe(0);
    expect(await matchAuditCount(prisma, seeded.organizationId)).toBe(0);
  });

  it('aborts a second committing request that reuses the audit correlation', async () => {
    const seeded = await seedAsset(prisma, advisory, 'correlation');
    const correlationId = randomUUID();
    const first = await runEvaluation(prisma, seeded, advisory.revisionId, correlationId);
    expect(first.result.status).toBe('evaluated');
    const componentId = seeded.occurrences[0]?.componentId;
    if (componentId === undefined) {
      throw new Error('correlation seed has no component');
    }
    await prisma.componentOccurrence.create({
      data: {
        organizationId: seeded.organizationId,
        assetId: seeded.assetId,
        sbomId: seeded.sbomId,
        sbomIngestionId: seeded.ingestionId,
        componentId,
        bomRef: 'second-affected',
        version: '1.2.0',
        versionKnown: true,
        isDirect: true,
      },
    });
    const aborted = await runEvaluation(prisma, seeded, advisory.revisionId, correlationId);
    expect(aborted.result).toEqual(closedFailure('transaction_aborted'));
    expect(await evidenceCount(prisma, seeded.organizationId)).toBe(1);
    expect(await matchAuditCount(prisma, seeded.organizationId)).toBe(1);
    const retried = await runEvaluation(prisma, seeded, advisory.revisionId);
    expect(retried.result).toMatchObject({
      status: 'evaluated',
      insertedCount: 1,
      replayedCount: 1,
    });
    expect(await evidenceCount(prisma, seeded.organizationId)).toBe(2);
    expect(await matchAuditCount(prisma, seeded.organizationId)).toBe(2);
  });

  it('converges concurrent identical requests on one evidence set', async () => {
    const seeded = await seedAsset(prisma, advisory, 'concurrent');
    const left = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
    const right = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
    try {
      const [first, second] = await Promise.all([
        runEvaluation(left, seeded, advisory.revisionId),
        runEvaluation(right, seeded, advisory.revisionId),
      ]);
      const statuses = [first.result.status, second.result.status].sort();
      expect(statuses).toEqual(['already_applied', 'evaluated']);
      expect(await evidenceCount(prisma, seeded.organizationId)).toBe(1);
      expect(await matchAuditCount(prisma, seeded.organizationId)).toBe(1);
    } finally {
      await left.$disconnect();
      await right.$disconnect();
    }
  });

  it('times out while a pointer lock is held and then commits', async () => {
    const seeded = await seedAsset(prisma, advisory, 'pointer-lock');
    const holder = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
    let release!: () => void;
    const releasePromise = new Promise<void>((resolve) => {
      release = resolve;
    });
    let held!: () => void;
    const heldPromise = new Promise<void>((resolve) => {
      held = resolve;
    });
    const holding = holder.$transaction(
      async (tx) => {
        await tx.$queryRaw`
          SELECT 1::int AS locked
          FROM (
            SELECT pg_advisory_xact_lock(
              hashtextextended(${`${seeded.organizationId}:${seeded.assetId}`}, 0)
            )
          ) AS taken
        `;
        await tx.$queryRaw`
          SELECT "id"
          FROM "asset"
          WHERE "organization_id" = ${seeded.organizationId}::uuid
            AND "id" = ${seeded.assetId}::uuid
          FOR UPDATE
        `;
        held();
        await releasePromise;
      },
      { maxWait: 5_000, timeout: 15_000 },
    );
    try {
      await heldPromise;
      const waiting = await runEvaluation(prisma, seeded, advisory.revisionId);
      expect(waiting.result).toEqual(closedFailure('timeout'));
      expect(await evidenceCount(prisma, seeded.organizationId)).toBe(0);
      release();
      await holding;
      const committed = await runEvaluation(prisma, seeded, advisory.revisionId);
      expect(committed.result.status).toBe('evaluated');
    } finally {
      release();
      await holding.catch(() => undefined);
      await holder.$disconnect();
    }
  });

  it('leaves an open Finding unchanged and does not deadlock with creation', async () => {
    const seeded = await seedAsset(prisma, advisory, 'finding');
    const createdEvidence = await runEvaluation(prisma, seeded, advisory.revisionId);
    expect(createdEvidence.result.status).toBe('evaluated');
    const evidence = await prisma.productMatchEvaluationEvidence.findMany({
      where: { organizationId: seeded.organizationId, outcome: 'affected' },
      select: { id: true },
    });
    const evidenceIds = evidence.map((row) => row.id).sort(compareUuid);
    const occurrence = seeded.occurrences[0];
    if (occurrence === undefined || advisory.approvalId === null) {
      throw new Error('finding seed is incomplete');
    }
    const writer = createControlledFindingCreationPersistence(prisma);
    const holder = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
    let release!: () => void;
    const releasePromise = new Promise<void>((resolve) => {
      release = resolve;
    });
    let held!: () => void;
    const heldPromise = new Promise<void>((resolve) => {
      held = resolve;
    });
    const holding = holder.$transaction(
      async (tx) => {
        await tx.$queryRaw`
          SELECT 1::int AS locked
          FROM (
            SELECT pg_advisory_xact_lock(
              hashtextextended(${`${seeded.organizationId}:${seeded.assetId}`}, 0)
            )
          ) AS taken
        `;
        held();
        await releasePromise;
      },
      { maxWait: 5_000, timeout: 15_000 },
    );
    await heldPromise;
    const creatingWhileHeld = writer.apply(
      sealFinding(seeded, advisory.vulnerabilityId, evidenceIds),
    );
    await new Promise((resolve) => {
      setTimeout(resolve, 200);
    });
    release();
    const created = await creatingWhileHeld;
    await holding;
    await holder.$disconnect();
    expect(created.status).toBe('created');
    const finding = await prisma.finding.findFirstOrThrow({
      where: { organizationId: seeded.organizationId },
    });
    expect(finding.state).toBe('open');
    expect(finding.version).toBe(1);
    const replay = await runEvaluation(prisma, seeded, advisory.revisionId);
    expect(replay.result.status).toBe('already_applied');
    const afterReplay = await prisma.finding.findFirstOrThrow({
      where: { id: finding.id },
    });
    expect(afterReplay.state).toBe('open');
    expect(afterReplay.version).toBe(1);
    expect(afterReplay.updatedAt.toISOString()).toBe(finding.updatedAt.toISOString());
    expect(await prisma.finding.count({ where: { organizationId: seeded.organizationId } })).toBe(
      1,
    );
    expect(
      await prisma.riskCalculation.count({ where: { organizationId: seeded.organizationId } }),
    ).toBe(0);
  });
});

function versions(count: number): OccurrenceSpec[] {
  return Array.from({ length: count }, (_unused, index) => ({
    version: `1.0.${index + 1}`,
    bomRef: `cap-${index + 1}`,
  }));
}

type PortResult = {
  readonly status: string;
  readonly auditWritten?: boolean;
  readonly findingWrites?: number;
  readonly providerCalls?: number;
  readonly insertedCount?: number;
  readonly selectedCount?: number;
  readonly evaluatedCount?: number;
  readonly replayedCount?: number;
  readonly skippedCount?: number;
  readonly findingCreation?: string;
  readonly skippedByReason?: {
    readonly version_not_known: number;
    readonly version_unrepresentable: number;
  };
  readonly outcomeCounts?: {
    readonly affected: number;
    readonly unaffected: number;
    readonly unknown: number;
  };
};

function closedFailure(status: string): PortResult {
  return {
    status,
    auditWritten: false,
    findingWrites: 0,
    insertedCount: 0,
    providerCalls: 0,
  };
}

async function runEvaluation(
  client: PrismaClient,
  seeded: Pick<SeededAsset, 'organizationId' | 'assetId' | 'userId' | 'membershipId'>,
  advisoryRevisionId: string,
  correlationId = randomUUID(),
  fault?: DeliberateProductMatchEvaluationFault,
): Promise<{
  readonly command: DeliberateProductMatchEvaluationCommand;
  readonly result: PortResult;
}> {
  const command = commandFor(seeded, advisoryRevisionId, correlationId);
  const persistence = createDeliberateProductMatchEvaluationPersistence(
    client,
    fault === undefined ? undefined : { fault },
  );
  const result = await persistence.evaluate(command, DECISIONS);
  if (typeof result !== 'object' || result === null || !('status' in result)) {
    throw new Error('evaluation result was not an object');
  }
  return { command, result: result as PortResult };
}

function commandFor(
  seeded: Pick<SeededAsset, 'organizationId' | 'assetId' | 'userId' | 'membershipId'>,
  advisoryRevisionId: string,
  correlationId: string,
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
    correlationId,
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

function sealFinding(seeded: SeededAsset, vulnerabilityId: string, evidenceIds: readonly string[]) {
  const componentId = seeded.occurrences[0]?.componentId;
  if (componentId === undefined) {
    throw new Error('finding seal has no component');
  }
  const correlationId = randomUUID();
  const trustedContext = {
    schemaVersion: FINDING_CREATION_TRUSTED_CONTEXT_SCHEMA_VERSION,
    organizationId: seeded.organizationId,
    actorId: seeded.userId,
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
    componentId,
    vulnerabilityId,
    sbomIngestionId: seeded.ingestionId,
    productMatchEvidenceIds: [...evidenceIds],
    correlationId,
  });
  if (issued.status !== 'authorized') {
    throw new Error(`finding authorization was ${issued.status}`);
  }
  const opened = openFindingCreationCommand({
    schemaVersion: FINDING_CREATION_COMMAND_SCHEMA_VERSION,
    purpose: FINDING_CREATION_PURPOSE,
    policyId: FINDING_CREATION_POLICY_ID,
    policyVersion: FINDING_CREATION_POLICY_VERSION,
    expectedAssetId: seeded.assetId,
    expectedComponentId: componentId,
    expectedVulnerabilityId: vulnerabilityId,
    expectedSbomIngestionId: seeded.ingestionId,
    expectedProductMatchEvidenceIds: [...evidenceIds],
    correlationId,
    authorization: issued.authorization,
  });
  if (opened.status !== 'authorized') {
    throw new Error(`finding command was ${opened.status}`);
  }
  return { trustedContext, command: opened.command };
}

async function evidenceCount(client: PrismaClient, organizationId: string): Promise<number> {
  return client.productMatchEvaluationEvidence.count({ where: { organizationId } });
}

async function matchAuditCount(client: PrismaClient, organizationId: string): Promise<number> {
  return client.auditEvent.count({
    where: { organizationId, action: DELIBERATE_PRODUCT_MATCH_EVALUATION_AUDIT_ACTION },
  });
}

async function disableUser(client: PrismaClient, userId: string): Promise<void> {
  const correlationId = randomUUID();
  await client.$transaction(async (tx) => {
    await tx.$queryRaw`SELECT set_config('patchpilot.instance_advisory_user_status', 'on', true)`;
    await tx.$executeRaw`
      UPDATE "user"
      SET "status" = 'disabled'::"user_status",
          "disabled_at" = CURRENT_TIMESTAMP,
          "updated_at" = CURRENT_TIMESTAMP,
          "version" = "version" + 1
      WHERE "id" = ${userId}::uuid
        AND "status" = 'active'::"user_status"
    `;
    await tx.$executeRaw`
      INSERT INTO "audit_event" (
        "organization_id",
        "actor_user_id",
        "actor_membership_id",
        "actor_type",
        "action",
        "subject_type",
        "subject_id",
        "occurred_at",
        "correlation_id",
        "payload",
        "schema_version",
        "retention_category"
      ) VALUES (
        NULL,
        NULL,
        NULL,
        'system'::"audit_actor_type",
        'auth.user_disabled',
        'user',
        ${userId}::uuid,
        CURRENT_TIMESTAMP,
        ${correlationId},
        jsonb_build_object(
          'schemaVersion', 1,
          'metadata', jsonb_build_object(
            'correlationId', ${correlationId},
            'targetUserId', ${userId}
          )
        ),
        1,
        'security'::"audit_retention_category"
      )
    `;
  });
}

async function seedAsset(
  client: PrismaClient,
  advisoryRecord: AdvisoryRecord,
  label: string,
  options: SeedOptions = {},
): Promise<SeededAsset> {
  const slug = `dme-${randomUUID().slice(0, 8)}`;
  const org = await createOrg(client, slug);
  const user = await client.user.create({
    data: {
      email: `${label}-${randomUUID().slice(0, 8)}@synthetic.patchpilot.test`.toLowerCase(),
      displayName: label.slice(0, 80),
    },
  });
  const membership = await client.membership.create({
    data: {
      organizationId: org.id,
      userId: user.id,
      role: options.role ?? 'owner',
    },
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
  const occurrences: SeededOccurrence[] = [];
  const components = new Map<string, { id: string; identityKey: string; purl: string | null }>();
  for (const spec of specs) {
    const name = spec.name ?? PACKAGE_NAME;
    const ecosystem = spec.ecosystem === undefined ? 'npm' : spec.ecosystem;
    const identityState = spec.identityState ?? 'resolved';
    const componentKey = `${ecosystem ?? ''}|${name}|${identityState}`;
    let component = components.get(componentKey);
    if (component === undefined) {
      const built = componentIdentity(name, ecosystem, identityState, spec.bomRef);
      const created = await client.component.create({
        data: {
          organizationId: org.id,
          identityKey: built.identityKey,
          purl: built.purl,
          ecosystem,
          namespace: null,
          name,
          identityState,
        },
      });
      component = { id: created.id, identityKey: built.identityKey, purl: built.purl };
      components.set(componentKey, component);
    }
    const versionKnown = spec.versionKnown ?? spec.version.length > 0;
    const createdOccurrence = await client.componentOccurrence.create({
      data: {
        organizationId: org.id,
        assetId: asset.id,
        sbomId: sbom.id,
        sbomIngestionId: ingestion.id,
        componentId: component.id,
        bomRef: spec.bomRef,
        version: spec.version,
        versionKnown,
        isDirect: spec.isDirect === undefined ? true : spec.isDirect,
      },
    });
    occurrences.push({
      occurrenceId: createdOccurrence.id,
      componentId: component.id,
      identityKey: component.identityKey,
      version: spec.version,
      versionKnown,
      isDirect: spec.isDirect === undefined ? true : spec.isDirect,
      name,
      ecosystem,
      purl: component.purl,
    });
  }
  const completed = options.ingestionState !== 'processing';
  if (completed) {
    await completeIngestion(
      client,
      ingestion.id,
      components.size,
      options.normalizationVersion ?? '2',
    );
  }
  if (options.setPointer !== false) {
    await client.asset.update({
      where: { id: asset.id },
      data: { lastSuccessfulSbomIngestionId: ingestion.id },
    });
  }
  return {
    organizationId: org.id,
    assetId: asset.id,
    userId: user.id,
    membershipId: membership.id,
    ingestionId: ingestion.id,
    sbomId: sbom.id,
    sbomSha256,
    occurrences,
  };
}

function componentIdentity(
  name: string,
  ecosystem: string | null,
  identityState: 'resolved' | 'ambiguous' | 'unsupported',
  bomRef: string,
): { readonly identityKey: string; readonly purl: string | null } {
  if (identityState === 'resolved' && ecosystem === 'npm') {
    const resolved = resolvedComponent({ name, bomRef, version: '0.0.0' });
    return { identityKey: resolved.identityKey, purl: resolved.versionlessPurl };
  }
  const built = buildComponentIdentityKey({
    identityState,
    versionlessPurl: null,
    ecosystem,
    namespace: null,
    name,
    bomRef,
  });
  if (!built.ok) {
    throw new Error('component identity was rejected');
  }
  return { identityKey: built.value, purl: null };
}

async function completeIngestion(
  client: PrismaClient,
  ingestionId: string,
  componentCount: number,
  normalizationVersion = '2',
): Promise<void> {
  await client.sbomIngestion.update({
    where: { id: ingestionId },
    data: {
      state: 'completed',
      normalizationVersion,
      completedAt: new Date('2026-10-02T12:00:00.000Z'),
      graphCompleteness: 'no_dependencies',
      componentCount,
      dependencyEdgeCount: 0,
      warningCount: 0,
      stage: null,
    },
  });
}

async function insertApprovedRevision(
  client: PrismaClient,
  label: string,
): Promise<AdvisoryRecord> {
  return insertRevision(client, label, { approve: true });
}

async function insertRevision(
  client: PrismaClient,
  label: string,
  options: {
    readonly approve: boolean;
    readonly includeRanges?: boolean;
    readonly familyId?: string;
    readonly familyDigest?: string;
    readonly advisoryId?: string;
    readonly supersedesRevisionId?: string;
    readonly supersedesRevisionDigest?: string;
    readonly revisionDisposition?: 'recorded' | 'withdrawn' | 'quarantined' | 'superseding';
    readonly withdrawalClassification?: 'not_withdrawn' | 'withdrawn';
    readonly quarantineClassification?: 'not_quarantined' | 'quarantined';
  },
): Promise<AdvisoryRecord> {
  const includeRanges = options.includeRanges !== false;
  const rangeFingerprint = session14RangeFingerprint(includeRanges ? RANGES : [], []);
  const contentFingerprint = digest(`content:${label}:${randomUUID()}`);
  const advisoryId = options.advisoryId ?? `REVIEWNPM${digest(label).slice(0, 8).toUpperCase()}`;
  const familyDigest = options.familyDigest ?? digest(`family:${advisoryId}:${randomUUID()}`);
  const revisionDigest = digest(`revision:${advisoryId}:${randomUUID()}`);
  const authorIdentity = 'author.one';
  const disposition = options.revisionDisposition ?? 'recorded';
  const vulnerability = await client.vulnerability.create({
    data: {
      osvId: `REVIEWED-${digest(label).slice(0, 16).toUpperCase()}-${randomUUID().slice(0, 8)}`,
    },
    select: { id: true },
  });
  const family =
    options.familyId === undefined
      ? await client.advisoryFamily.create({
          data: {
            familySchemaVersion: MAINTAINER_REVIEWED_FAMILY_SCHEMA_VERSION,
            source: 'maintainer_reviewed_advisory',
            advisoryId,
            familyDigest,
            sourceRegistryVersion: MAINTAINER_REVIEWED_APPROVAL_PINS.licensePolicyId,
          },
          select: { id: true },
        })
      : { id: options.familyId };
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
      revisionDisposition: disposition,
      withdrawalClassification: options.withdrawalClassification ?? 'not_withdrawn',
      quarantineClassification: options.quarantineClassification ?? 'not_quarantined',
      supersedesRevisionDigest: options.supersedesRevisionDigest ?? 'none',
      ...(options.supersedesRevisionId === undefined
        ? {}
        : { supersedesAdvisoryRevisionId: options.supersedesRevisionId }),
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
      aliasSetDigest: digest(`aliases:${revisionDigest}`),
      replayFingerprint: digest(`replay:${revisionDigest}`),
      authorIdentity,
    },
    select: { id: true },
  });
  if (includeRanges) {
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
  }
  const bindable =
    (options.withdrawalClassification ?? 'not_withdrawn') === 'not_withdrawn' &&
    (options.quarantineClassification ?? 'not_quarantined') === 'not_quarantined';
  if (bindable) {
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
  }
  let approvalId: string | null = null;
  if (options.approve) {
    const approval = await createApprovalCapabilityHarness(client).approve(
      approvalCommand({
        revisionId: revision.id,
        familyDigest,
        contentFingerprint,
        rangeFingerprint,
        vulnerabilityId: vulnerability.id,
        authorIdentity,
      }),
    );
    if (approval.kind !== 'recorded') {
      throw new Error(`approval for ${label} was ${approval.kind}`);
    }
    approvalId = approval.projection.approvalId;
  }
  return {
    revisionId: revision.id,
    approvalId,
    vulnerabilityId: vulnerability.id,
    familyId: family.id,
    familyDigest,
    advisoryId,
    contentFingerprint,
    rangeFingerprint,
    packageIdentityKey: packageIdentity(),
    revisionDigest,
    authorIdentity,
  };
}

async function insertSyntheticRevision(
  client: PrismaClient,
  label: string,
): Promise<AdvisoryRecord> {
  const familyDigest = digest(`synthetic-family:${label}:${randomUUID()}`);
  const revisionDigest = digest(`synthetic-revision:${label}:${randomUUID()}`);
  const contentFingerprint = digest(`synthetic-content:${label}`);
  const rangeFingerprint = digest(`synthetic-range:${label}`);
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
  const vulnerability = await client.vulnerability.create({
    data: { osvId: `SYNTHETIC-${digest(label).slice(0, 12).toUpperCase()}` },
    select: { id: true },
  });
  const revision = await client.advisoryRevision.create({
    data: {
      revisionSchemaVersion: 'osv_advisory_revision_identity_v1',
      advisoryFamilyId: family.id,
      source: 'synthetic_fixture',
      advisoryId,
      familyDigest,
      revisionDigest,
      providerGeneration: 'synthetic_not_a_provider_generation',
      contentFingerprint,
      session14RangeFingerprint: rangeFingerprint,
      productRangeFingerprint: rangeFingerprint,
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
    select: { id: true },
  });
  return {
    revisionId: revision.id,
    approvalId: null,
    vulnerabilityId: vulnerability.id,
    familyId: family.id,
    familyDigest,
    advisoryId,
    contentFingerprint,
    rangeFingerprint,
    packageIdentityKey: packageIdentity(),
    revisionDigest,
    authorIdentity: 'author.one',
  };
}

function approvalCommand(input: {
  readonly revisionId: string;
  readonly familyDigest: string;
  readonly contentFingerprint: string;
  readonly rangeFingerprint: string;
  readonly vulnerabilityId: string;
  readonly authorIdentity: string;
}) {
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
    packageIdentityKey: packageIdentity(),
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
    expectedNpmPackageIdentity: packageIdentity(),
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
