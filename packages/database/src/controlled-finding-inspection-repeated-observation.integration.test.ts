/**
 * Disposable PostgreSQL proof that inspection tolerates legal repeated observations.
 * The public projection stays on the creation observation. The read writes nothing.
 */

import { randomUUID } from 'node:crypto';

import { PrismaClient } from '@prisma/client';
import {
  FINDING_CREATION_AUTHORIZATION_SCHEMA_VERSION,
  FINDING_CREATION_COMMAND_SCHEMA_VERSION,
  FINDING_CREATION_POLICY_ID,
  FINDING_CREATION_POLICY_VERSION,
  FINDING_CREATION_PURPOSE,
  FINDING_CREATION_TRUSTED_CONTEXT_SCHEMA_VERSION,
  FINDING_INSPECTION_COMMAND_SCHEMA_VERSION,
  FINDING_INSPECTION_RESULT_SCHEMA_VERSION,
  FINDING_INSPECTION_TRUSTED_CONTEXT_SCHEMA_VERSION,
  FINDING_REPEATED_OBSERVATION_ABSENCE_SUPPORT_SCHEMA_VERSION,
  FINDING_REPEATED_OBSERVATION_AUTHORIZATION_SCHEMA_VERSION,
  FINDING_REPEATED_OBSERVATION_COMMAND_SCHEMA_VERSION,
  FINDING_REPEATED_OBSERVATION_EVIDENCE_SUPPORT_SCHEMA_VERSION,
  FINDING_REPEATED_OBSERVATION_POLICY_ID,
  FINDING_REPEATED_OBSERVATION_POLICY_VERSION,
  FINDING_REPEATED_OBSERVATION_PURPOSE,
  FINDING_REPEATED_OBSERVATION_TRUSTED_CONTEXT_SCHEMA_VERSION,
  openFindingInspection,
  type FindingInspectionProjection,
} from '@patchpilot/domain';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';

import {
  issueFindingCreationAuthorization,
  openFindingCreationCommand,
} from '../../domain/dist/findings/controlled-creation/authorization.js';
import {
  issueFindingRepeatedObservationAuthorization,
  openFindingRepeatedObservationCommand,
} from '../../domain/dist/findings/controlled-observation/authorization.js';
import { createControlledFindingCreationPersistence } from './controlled-finding-creation-persistence.js';
import { createControlledFindingInspectionPersistence } from './controlled-finding-inspection-persistence.js';
import {
  seedControlledFindingEvidence,
  seedLaterControlledFindingIngestion,
  type ControlledFindingSeedTarget,
  type LaterControlledFindingIngestion,
} from './controlled-finding-operator-seed-fixture.js';
import { createControlledFindingRepeatedObservationPersistence } from './controlled-finding-repeated-observation-persistence.js';
import {
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
} from './integration-database.js';
import { createOrg } from './sbom-test-fixture.js';

let prisma: PrismaClient;
let database: Awaited<ReturnType<typeof createEphemeralDatabase>>;

type Actor = {
  readonly organizationId: string;
  readonly actorId: string;
  readonly membershipId: string;
};

type Prepared = Actor & {
  readonly seed: ControlledFindingSeedTarget;
  readonly findingId: string;
};

const HIDDEN = [
  'record_finding_repeated_observation',
  'controlled_finding_repeated_observation',
  'component_absent',
  'evidence_observation',
  'finding_repeated_observation',
] as const;

function compareUuid(left: string, right: string): number {
  if (left < right) {
    return -1;
  }
  if (left > right) {
    return 1;
  }
  return 0;
}

function sorted(ids: readonly string[]): string[] {
  return [...ids].sort(compareUuid);
}

function writer() {
  return createControlledFindingRepeatedObservationPersistence(prisma);
}

async function actor(label: string): Promise<Actor> {
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
  return { organizationId: org.id, actorId: user.id, membershipId: membership.id };
}

async function prepare(
  label: string,
  versions: readonly { readonly version: string; readonly bomRef: string }[] = [
    { version: '1.1.0', bomRef: 'component-1' },
  ],
): Promise<Prepared> {
  const context = await actor(label);
  const seed = await seedControlledFindingEvidence(prisma, {
    label,
    organizationId: context.organizationId,
    versions,
  });
  const evidenceIds = sorted(
    seed.evidence.filter((row) => row.outcome === 'affected').map((row) => row.evidenceId),
  );
  const correlationId = randomUUID();
  const trustedContext = {
    schemaVersion: FINDING_CREATION_TRUSTED_CONTEXT_SCHEMA_VERSION,
    organizationId: context.organizationId,
    actorId: context.actorId,
    membershipId: context.membershipId,
    membershipStatus: 'active' as const,
  };
  const issued = issueFindingCreationAuthorization({
    schemaVersion: FINDING_CREATION_AUTHORIZATION_SCHEMA_VERSION,
    trustedContext,
    purpose: FINDING_CREATION_PURPOSE,
    policyId: FINDING_CREATION_POLICY_ID,
    policyVersion: FINDING_CREATION_POLICY_VERSION,
    assetId: seed.assetId,
    componentId: seed.componentId,
    vulnerabilityId: seed.vulnerabilityId,
    sbomIngestionId: seed.ingestionId,
    productMatchEvidenceIds: evidenceIds,
    correlationId,
  });
  if (issued.status !== 'authorized') {
    throw new Error(`creation authorization was ${issued.status}`);
  }
  const opened = openFindingCreationCommand({
    schemaVersion: FINDING_CREATION_COMMAND_SCHEMA_VERSION,
    purpose: FINDING_CREATION_PURPOSE,
    policyId: FINDING_CREATION_POLICY_ID,
    policyVersion: FINDING_CREATION_POLICY_VERSION,
    expectedAssetId: seed.assetId,
    expectedComponentId: seed.componentId,
    expectedVulnerabilityId: seed.vulnerabilityId,
    expectedSbomIngestionId: seed.ingestionId,
    expectedProductMatchEvidenceIds: evidenceIds,
    correlationId,
    authorization: issued.authorization,
  });
  if (opened.status !== 'authorized') {
    throw new Error(`creation command was ${opened.status}`);
  }
  const created = await createControlledFindingCreationPersistence(prisma).apply({
    trustedContext,
    command: opened.command,
  });
  if (created.status !== 'created') {
    throw new Error(`creation was ${created.status}`);
  }
  return { ...context, seed, findingId: created.findingId };
}

function evidenceSupport(
  evidenceIds: readonly string[],
  unknownVersionOccurrenceIds: readonly string[] = [],
) {
  return {
    schemaVersion: FINDING_REPEATED_OBSERVATION_EVIDENCE_SUPPORT_SCHEMA_VERSION,
    kind: 'evidence_set' as const,
    productMatchEvidenceIds: sorted(evidenceIds),
    unknownVersionOccurrenceIds: sorted(unknownVersionOccurrenceIds),
  };
}

function absenceSupport(ingestionId: string, later: LaterControlledFindingIngestion) {
  return {
    schemaVersion: FINDING_REPEATED_OBSERVATION_ABSENCE_SUPPORT_SCHEMA_VERSION,
    kind: 'component_absence' as const,
    sbomIngestionId: ingestionId,
    graphCompleteness: later.graphCompleteness === 'complete' ? 'complete' : 'no_dependencies',
    componentCount: later.componentCount,
    occurrenceCardinality: later.occurrenceCardinality,
    dependencyEdgeCount: later.dependencyEdgeCount,
    expectedFindingComponentOccurrenceCount: 0 as const,
    normalizationVersion: 2 as const,
  };
}

function seal(preparedFinding: Prepared, ingestionId: string, support: Record<string, unknown>) {
  const correlationId = randomUUID();
  const trustedContext = {
    schemaVersion: FINDING_REPEATED_OBSERVATION_TRUSTED_CONTEXT_SCHEMA_VERSION,
    organizationId: preparedFinding.organizationId,
    actorId: preparedFinding.actorId,
    membershipId: preparedFinding.membershipId,
    membershipStatus: 'active' as const,
  };
  const issued = issueFindingRepeatedObservationAuthorization({
    schemaVersion: FINDING_REPEATED_OBSERVATION_AUTHORIZATION_SCHEMA_VERSION,
    trustedContext,
    purpose: FINDING_REPEATED_OBSERVATION_PURPOSE,
    policyId: FINDING_REPEATED_OBSERVATION_POLICY_ID,
    policyVersion: FINDING_REPEATED_OBSERVATION_POLICY_VERSION,
    findingId: preparedFinding.findingId,
    assetId: preparedFinding.seed.assetId,
    componentId: preparedFinding.seed.componentId,
    vulnerabilityId: preparedFinding.seed.vulnerabilityId,
    sbomIngestionId: ingestionId,
    support,
    correlationId,
  });
  if (issued.status !== 'authorized') {
    throw new Error(`observation authorization was ${issued.status}`);
  }
  const opened = openFindingRepeatedObservationCommand({
    schemaVersion: FINDING_REPEATED_OBSERVATION_COMMAND_SCHEMA_VERSION,
    purpose: FINDING_REPEATED_OBSERVATION_PURPOSE,
    policyId: FINDING_REPEATED_OBSERVATION_POLICY_ID,
    policyVersion: FINDING_REPEATED_OBSERVATION_POLICY_VERSION,
    expectedFindingId: preparedFinding.findingId,
    expectedAssetId: preparedFinding.seed.assetId,
    expectedComponentId: preparedFinding.seed.componentId,
    expectedVulnerabilityId: preparedFinding.seed.vulnerabilityId,
    expectedSbomIngestionId: ingestionId,
    support,
    correlationId,
    authorization: issued.authorization,
  });
  if (opened.status !== 'authorized') {
    throw new Error(`observation command was ${opened.status}`);
  }
  return { trustedContext, command: opened.command };
}

async function later(
  preparedFinding: Prepared,
  label: string,
  input: Omit<
    Parameters<typeof seedLaterControlledFindingIngestion>[1],
    'label' | 'organizationId' | 'target'
  >,
) {
  return seedLaterControlledFindingIngestion(prisma, {
    label,
    organizationId: preparedFinding.organizationId,
    target: preparedFinding.seed,
    ...input,
  });
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

async function projectionOf(preparedFinding: Prepared): Promise<FindingInspectionProjection> {
  const result = await inspect(preparedFinding.organizationId, preparedFinding.findingId);
  expect(result.status).toBe('found');
  if (result.status !== 'found') {
    throw new Error('inspection did not return the creation projection');
  }
  return result.projection;
}

async function observe(
  preparedFinding: Prepared,
  ingestion: LaterControlledFindingIngestion,
  support: Record<string, unknown>,
) {
  const observed = await writer().apply(seal(preparedFinding, ingestion.ingestionId, support));
  expect(observed.status).toBe('observed');
}

async function snapshot(organizationId: string, findingId: string) {
  const [
    finding,
    observations,
    observationRows,
    creationLinks,
    repeatedLinks,
    repeatedLinkRows,
    audits,
    evidence,
    occurrences,
    ingestions,
    asset,
  ] = await Promise.all([
    prisma.finding.findFirstOrThrow({ where: { organizationId, id: findingId } }),
    prisma.findingObservation.count({ where: { organizationId, findingId } }),
    prisma.findingObservation.findMany({
      where: { organizationId, findingId },
      orderBy: { id: 'asc' },
      select: {
        id: true,
        method: true,
        result: true,
        sbomIngestionId: true,
        observedAt: true,
        createdAt: true,
        replayFingerprint: true,
        evidenceLinkCount: true,
      },
    }),
    prisma.findingCreationEvidenceLink.findMany({
      where: { organizationId, findingId },
      orderBy: { id: 'asc' },
      select: {
        id: true,
        findingObservationId: true,
        productMatchEvaluationEvidenceId: true,
        componentOccurrenceId: true,
        outcome: true,
      },
    }),
    prisma.findingRepeatedObservationEvidenceLink.count({ where: { organizationId, findingId } }),
    prisma.findingRepeatedObservationEvidenceLink.findMany({
      where: { organizationId, findingId },
      orderBy: { id: 'asc' },
      select: {
        id: true,
        findingObservationId: true,
        productMatchEvaluationEvidenceId: true,
        componentOccurrenceId: true,
        supportKind: true,
        outcome: true,
      },
    }),
    prisma.auditEvent.count({ where: { organizationId } }),
    prisma.productMatchEvaluationEvidence.count({ where: { organizationId } }),
    prisma.componentOccurrence.findMany({
      where: { organizationId },
      orderBy: { id: 'asc' },
      select: { id: true, sbomIngestionId: true, version: true, versionKnown: true },
    }),
    prisma.sbomIngestion.findMany({
      where: { organizationId },
      orderBy: { id: 'asc' },
      select: { id: true, state: true, assetId: true, normalizationVersion: true },
    }),
    prisma.asset.findMany({
      where: { organizationId },
      orderBy: { id: 'asc' },
      select: { id: true, lastSuccessfulSbomIngestionId: true },
    }),
  ]);
  return {
    finding,
    observations,
    observationRows,
    creationLinks,
    repeatedLinks,
    repeatedLinkRows,
    audits,
    evidence,
    occurrences,
    ingestions,
    asset,
  };
}

async function setUserTriggers(
  table:
    | 'finding'
    | 'finding_observation'
    | 'finding_creation_evidence_link'
    | 'finding_repeated_observation_evidence_link'
    | 'product_match_evaluation_evidence',
  enabled: boolean,
): Promise<void> {
  const statement = enabled ? 'ENABLE TRIGGER USER' : 'DISABLE TRIGGER USER';
  await prisma.$executeRawUnsafe(`ALTER TABLE "${table}" ${statement}`);
}

async function restoreTriggers(): Promise<void> {
  await setUserTriggers('finding', true);
  await setUserTriggers('finding_observation', true);
  await setUserTriggers('finding_creation_evidence_link', true);
  await setUserTriggers('finding_repeated_observation_evidence_link', true);
  await setUserTriggers('product_match_evaluation_evidence', true);
}

function hidesRepeatedFacts(projection: FindingInspectionProjection, ingestionId: string): void {
  const encoded = JSON.stringify(projection);
  for (const token of HIDDEN) {
    expect(encoded).not.toContain(token);
  }
  expect(encoded).not.toContain(ingestionId);
  expect(projection.state).toBe('open');
  expect(projection.creationObservationPolicy).toEqual({
    policyId: 'finding_creation_policy_v1',
    policyVersion: 1,
  });
}

function expectCreationFactsPreserved(
  baseline: FindingInspectionProjection,
  projection: FindingInspectionProjection,
): void {
  expect(projection.findingId).toBe(baseline.findingId);
  expect(projection.state).toBe(baseline.state);
  expect(projection.asset).toEqual(baseline.asset);
  expect(projection.component).toEqual(baseline.component);
  expect(projection.vulnerability).toEqual(baseline.vulnerability);
  expect(projection.affectedVersions).toEqual(baseline.affectedVersions);
  expect(projection.affectedOccurrenceCount).toBe(baseline.affectedOccurrenceCount);
  expect(projection.otherOccurrenceCount).toBe(baseline.otherOccurrenceCount);
  expect(projection.otherOccurrenceClassification).toBe(baseline.otherOccurrenceClassification);
  expect(projection.createdAt).toBe(baseline.createdAt);
  expect(projection.creationObservationPolicy).toEqual(baseline.creationObservationPolicy);
  expect(projection.creationEvidenceApplicability).toBe('historical');
  expect(projection.explanationCodes).toContain('creation_evidence_historical');
}

beforeAll(async () => {
  database = await createEphemeralDatabase('it');
  await deployMigrations(database.databaseUrl);
  prisma = new PrismaClient({ datasources: { db: { url: database.databaseUrl } } });
});

afterEach(async () => {
  if (prisma !== undefined) {
    await restoreTriggers();
  }
});

afterAll(async () => {
  if (prisma !== undefined) {
    await prisma.$disconnect();
  }
  if (database !== undefined) {
    await dropEphemeralDatabase(database.admin, database.databaseName);
  }
});

describe('controlled finding repeated-observation inspection', () => {
  it('projects a creation-only Finding and writes nothing', async () => {
    const preparedFinding = await prepare('creation-only');
    const before = await snapshot(preparedFinding.organizationId, preparedFinding.findingId);
    const projection = await projectionOf(preparedFinding);
    expect(projection.affectedVersions.values).toEqual(['1.1.0']);
    expect(projection.affectedOccurrenceCount).toBe(1);
    expect(projection.state).toBe('open');
    expect(await snapshot(preparedFinding.organizationId, preparedFinding.findingId)).toEqual(
      before,
    );
    expect(before.finding.state).toBe('open');
    expect(before.finding.version).toBe(1);
    expect(before.finding.resolvedAt).toBeNull();
    expect(before.finding.reopenedAt).toBeNull();
    expect(before.finding.assignedMembershipId).toBeNull();
    expect(before.finding.dueAt).toBeNull();
    expect(before.finding.currentRiskCalculationId).toBeNull();
    expect(before.finding.lastObservedAt.toISOString()).toBe(
      before.finding.firstObservedAt.toISOString(),
    );
  });

  it('keeps the creation projection after one affected repeated observation', async () => {
    const preparedFinding = await prepare('affected');
    const baseline = await projectionOf(preparedFinding);
    const next = await later(preparedFinding, 'affected-later', {
      receivedAt: new Date('2026-10-08T12:00:00.000Z'),
      versions: [{ version: '1.2.0', bomRef: 'component-1' }],
    });
    await observe(
      preparedFinding,
      next,
      evidenceSupport(next.evidence.map((row) => row.evidenceId)),
    );
    const before = await snapshot(preparedFinding.organizationId, preparedFinding.findingId);
    const projection = await projectionOf(preparedFinding);
    expectCreationFactsPreserved(baseline, projection);
    expect(projection.affectedVersions.values).toEqual(['1.1.0']);
    hidesRepeatedFacts(projection, next.ingestionId);
    expect(await snapshot(preparedFinding.organizationId, preparedFinding.findingId)).toEqual(
      before,
    );
    expect(before.finding.lastObservedAt.getTime()).toBeGreaterThan(
      before.finding.firstObservedAt.getTime(),
    );
    expect(before.finding.updatedAt.toISOString()).toBe(
      before.finding.lastObservedAt.toISOString(),
    );
    expect(before.finding.state).toBe('open');
    expect(before.finding.version).toBe(1);
    expect(before.audits).toBeGreaterThan(0);
  });

  it('keeps the creation projection for unaffected, unknown, and component-absent observations', async () => {
    const preparedFinding = await prepare('aggregates');
    const baseline = await projectionOf(preparedFinding);
    const unaffected = await later(preparedFinding, 'unaffected', {
      receivedAt: new Date('2026-10-08T12:00:00.000Z'),
      versions: [{ version: '3.0.0', bomRef: 'component-1' }],
    });
    await observe(
      preparedFinding,
      unaffected,
      evidenceSupport(unaffected.evidence.map((row) => row.evidenceId)),
    );
    const unknown = await later(preparedFinding, 'unknown', {
      receivedAt: new Date('2026-10-09T12:00:00.000Z'),
      versions: [{ version: 'not-a-version', bomRef: 'component-1' }],
    });
    await observe(
      preparedFinding,
      unknown,
      evidenceSupport(unknown.evidence.map((row) => row.evidenceId)),
    );
    const absent = await later(preparedFinding, 'absent', {
      receivedAt: new Date('2026-10-10T12:00:00.000Z'),
      otherComponent: { name: 'other-widget', version: '1.0.0', bomRef: 'other-1' },
    });
    await observe(preparedFinding, absent, absenceSupport(absent.ingestionId, absent));
    const before = await snapshot(preparedFinding.organizationId, preparedFinding.findingId);
    const projection = await projectionOf(preparedFinding);
    expectCreationFactsPreserved(baseline, projection);
    hidesRepeatedFacts(projection, absent.ingestionId);
    expect(await snapshot(preparedFinding.organizationId, preparedFinding.findingId)).toEqual(
      before,
    );
    expect(before.finding.state).toBe('open');
    expect(before.finding.version).toBe(1);
  });

  it('keeps the creation projection across recurrence-shaped history', async () => {
    const preparedFinding = await prepare('recurrence');
    const baseline = await projectionOf(preparedFinding);
    const absent = await later(preparedFinding, 'recur-absent', {
      receivedAt: new Date('2026-10-08T12:00:00.000Z'),
      otherComponent: { name: 'other-widget', version: '1.0.0', bomRef: 'other-1' },
    });
    await observe(preparedFinding, absent, absenceSupport(absent.ingestionId, absent));
    const affected = await later(preparedFinding, 'recur-affected', {
      receivedAt: new Date('2026-10-09T12:00:00.000Z'),
      versions: [{ version: '1.1.0', bomRef: 'component-1' }],
    });
    await observe(
      preparedFinding,
      affected,
      evidenceSupport(affected.evidence.map((row) => row.evidenceId)),
    );
    const projection = await projectionOf(preparedFinding);
    expectCreationFactsPreserved(baseline, projection);
    hidesRepeatedFacts(projection, affected.ingestionId);
    expect(projection.affectedOccurrenceCount).toBe(baseline.affectedOccurrenceCount);
    expect(projection.otherOccurrenceClassification).toBe(baseline.otherOccurrenceClassification);
  });

  it('fails closed for a missing or duplicate creation observation', async () => {
    const missing = await prepare('missing-creation');
    await setUserTriggers('finding_creation_evidence_link', false);
    await prisma.findingCreationEvidenceLink.deleteMany({
      where: { findingId: missing.findingId },
    });
    await setUserTriggers('finding_observation', false);
    await prisma.findingObservation.deleteMany({ where: { findingId: missing.findingId } });
    expect((await inspect(missing.organizationId, missing.findingId)).status).toBe(
      'malformed_persisted_state',
    );
    await restoreTriggers();

    const duplicate = await prepare('duplicate-creation');
    const next = await later(duplicate, 'duplicate-ingestion', {
      receivedAt: new Date('2026-10-08T12:00:00.000Z'),
      versions: [{ version: '1.1.0', bomRef: 'component-1' }],
    });
    const creation = await prisma.findingObservation.findFirstOrThrow({
      where: { findingId: duplicate.findingId, method: 'controlled_finding_creation' },
    });
    await setUserTriggers('finding_observation', false);
    await prisma.$executeRaw`
      INSERT INTO "finding_observation" (
        "organization_id",
        "finding_id",
        "sbom_id",
        "sbom_ingestion_id",
        "occurrence_id",
        "result",
        "method",
        "observed_at",
        "evidence",
        "created_at",
        "transition_classification",
        "creation_purpose",
        "creation_policy_id",
        "creation_policy_version",
        "actor_membership_id",
        "correlation_id",
        "replay_fingerprint",
        "affected_evidence_count"
      )
      SELECT "organization_id",
             "finding_id",
             "sbom_id",
             ${next.ingestionId}::uuid,
             NULL,
             "result",
             "method",
             "observed_at",
             "evidence",
             "created_at",
             "transition_classification",
             "creation_purpose",
             "creation_policy_id",
             "creation_policy_version",
             "actor_membership_id",
             "correlation_id",
             "replay_fingerprint",
             "affected_evidence_count"
      FROM "finding_observation"
      WHERE "id" = ${creation.id}::uuid
    `;
    expect((await inspect(duplicate.organizationId, duplicate.findingId)).status).toBe(
      'malformed_persisted_state',
    );
  });

  it('fails closed for a malformed creation observation or creation link', async () => {
    const fingerprint = await prepare('bad-fingerprint');
    const creation = await prisma.findingObservation.findFirstOrThrow({
      where: { findingId: fingerprint.findingId, method: 'controlled_finding_creation' },
    });
    const replacement = 'ab'.repeat(32);
    await setUserTriggers('finding_observation', false);
    await prisma.$executeRaw`
      UPDATE "finding_observation"
      SET "replay_fingerprint" = ${replacement},
          "evidence" = jsonb_set("evidence", '{evidenceSetFingerprint}', to_jsonb(${replacement}::text))
      WHERE "id" = ${creation.id}::uuid
    `;
    expect((await inspect(fingerprint.organizationId, fingerprint.findingId)).status).toBe(
      'malformed_persisted_state',
    );
    await restoreTriggers();

    const links = await prepare('bad-link', [
      { version: '1.1.0', bomRef: 'component-a' },
      { version: '1.2.0', bomRef: 'component-b' },
    ]);
    const link = await prisma.findingCreationEvidenceLink.findFirstOrThrow({
      where: { findingId: links.findingId },
    });
    await setUserTriggers('finding_creation_evidence_link', false);
    await prisma.findingCreationEvidenceLink.delete({ where: { id: link.id } });
    expect((await inspect(links.organizationId, links.findingId)).status).toBe(
      'malformed_persisted_state',
    );
  });

  it('fails closed for malformed repeated support', async () => {
    const preparedFinding = await prepare('bad-support');
    const next = await later(preparedFinding, 'bad-support-later', {
      receivedAt: new Date('2026-10-08T12:00:00.000Z'),
      versions: [{ version: '1.1.0', bomRef: 'component-1' }],
    });
    await observe(
      preparedFinding,
      next,
      evidenceSupport(next.evidence.map((row) => row.evidenceId)),
    );
    const link = await prisma.findingRepeatedObservationEvidenceLink.findFirstOrThrow({
      where: { organizationId: preparedFinding.organizationId, sbomIngestionId: next.ingestionId },
    });
    await setUserTriggers('finding_repeated_observation_evidence_link', false);
    await prisma.findingRepeatedObservationEvidenceLink.delete({ where: { id: link.id } });
    expect((await inspect(preparedFinding.organizationId, preparedFinding.findingId)).status).toBe(
      'malformed_persisted_state',
    );
    await restoreTriggers();

    const mismatched = await prepare('bad-outcome');
    const mismatchedLater = await later(mismatched, 'bad-outcome-later', {
      receivedAt: new Date('2026-10-08T12:00:00.000Z'),
      versions: [{ version: '1.1.0', bomRef: 'component-1' }],
    });
    await observe(
      mismatched,
      mismatchedLater,
      evidenceSupport(mismatchedLater.evidence.map((row) => row.evidenceId)),
    );
    const mismatchedLink = await prisma.findingRepeatedObservationEvidenceLink.findFirstOrThrow({
      where: {
        organizationId: mismatched.organizationId,
        sbomIngestionId: mismatchedLater.ingestionId,
      },
    });
    await setUserTriggers('finding_repeated_observation_evidence_link', false);
    await prisma.findingRepeatedObservationEvidenceLink.update({
      where: { id: mismatchedLink.id },
      data: { outcome: 'unaffected' },
    });
    expect((await inspect(mismatched.organizationId, mismatched.findingId)).status).toBe(
      'malformed_persisted_state',
    );
    await restoreTriggers();

    const known = await prepare('known-as-unknown');
    const knownLater = await later(known, 'known-later', {
      receivedAt: new Date('2026-10-08T12:00:00.000Z'),
      versions: [{ version: '1.1.0', bomRef: 'component-1' }],
    });
    await observe(
      known,
      knownLater,
      evidenceSupport(knownLater.evidence.map((row) => row.evidenceId)),
    );
    const knownLink = await prisma.findingRepeatedObservationEvidenceLink.findFirstOrThrow({
      where: { organizationId: known.organizationId, sbomIngestionId: knownLater.ingestionId },
    });
    await setUserTriggers('finding_repeated_observation_evidence_link', false);
    await prisma.findingRepeatedObservationEvidenceLink.update({
      where: { id: knownLink.id },
      data: {
        supportKind: 'unknown_version_occurrence',
        productMatchEvaluationEvidenceId: null,
        outcome: null,
      },
    });
    expect((await inspect(known.organizationId, known.findingId)).status).toBe(
      'malformed_persisted_state',
    );
  });

  it('fails closed when component absence still has a support link', async () => {
    const preparedFinding = await prepare('absence-link');
    const absent = await later(preparedFinding, 'absence-link-later', {
      receivedAt: new Date('2026-10-08T12:00:00.000Z'),
      otherComponent: { name: 'other-widget', version: '1.0.0', bomRef: 'other-1' },
    });
    await observe(preparedFinding, absent, absenceSupport(absent.ingestionId, absent));
    const observation = await prisma.findingObservation.findFirstOrThrow({
      where: { findingId: preparedFinding.findingId, sbomIngestionId: absent.ingestionId },
    });
    const occurrence = await prisma.componentOccurrence.create({
      data: {
        organizationId: preparedFinding.organizationId,
        assetId: preparedFinding.seed.assetId,
        sbomId: absent.sbomId,
        sbomIngestionId: absent.ingestionId,
        componentId: preparedFinding.seed.componentId,
        bomRef: 'returned-component',
        version: '',
        versionKnown: false,
        isDirect: false,
      },
    });
    await setUserTriggers('finding_repeated_observation_evidence_link', false);
    await prisma.findingRepeatedObservationEvidenceLink.create({
      data: {
        organizationId: preparedFinding.organizationId,
        findingId: preparedFinding.findingId,
        findingObservationId: observation.id,
        sbomId: observation.sbomId,
        assetId: preparedFinding.seed.assetId,
        componentId: preparedFinding.seed.componentId,
        vulnerabilityId: preparedFinding.seed.vulnerabilityId,
        sbomIngestionId: absent.ingestionId,
        componentOccurrenceId: occurrence.id,
        supportKind: 'unknown_version_occurrence',
      },
    });
    expect((await inspect(preparedFinding.organizationId, preparedFinding.findingId)).status).toBe(
      'malformed_persisted_state',
    );
  });

  it('keeps the creation projection after an unknown-version observation', async () => {
    const preparedFinding = await prepare('unknown-version');
    const baseline = await projectionOf(preparedFinding);
    const unknown = await later(preparedFinding, 'unknown-version-later', {
      receivedAt: new Date('2026-10-11T12:00:00.000Z'),
      unknownVersions: [{ version: '', bomRef: 'component-unknown' }],
    });
    const occurrenceId = unknown.unknownVersionOccurrenceIds[0];
    if (occurrenceId === undefined) {
      throw new Error('unknown-version occurrence was not prepared');
    }
    await observe(preparedFinding, unknown, evidenceSupport([], [occurrenceId]));
    const before = await snapshot(preparedFinding.organizationId, preparedFinding.findingId);
    const projection = await projectionOf(preparedFinding);
    expectCreationFactsPreserved(baseline, projection);
    hidesRepeatedFacts(projection, unknown.ingestionId);
    expect(JSON.stringify(projection)).not.toContain(occurrenceId);
    expect(await snapshot(preparedFinding.organizationId, preparedFinding.findingId)).toEqual(
      before,
    );
  });

  it('fails closed when repeated support is attached to the creation observation', async () => {
    const preparedFinding = await prepare('cross-observation');
    const creation = await prisma.findingObservation.findFirstOrThrow({
      where: { findingId: preparedFinding.findingId, method: 'controlled_finding_creation' },
    });
    const occurrence = await prisma.componentOccurrence.findFirstOrThrow({
      where: {
        organizationId: preparedFinding.organizationId,
        sbomIngestionId: creation.sbomIngestionId,
        componentId: preparedFinding.seed.componentId,
      },
    });
    await setUserTriggers('finding_repeated_observation_evidence_link', false);
    await prisma.findingRepeatedObservationEvidenceLink.create({
      data: {
        organizationId: preparedFinding.organizationId,
        findingId: preparedFinding.findingId,
        findingObservationId: creation.id,
        sbomId: creation.sbomId,
        assetId: preparedFinding.seed.assetId,
        componentId: preparedFinding.seed.componentId,
        vulnerabilityId: preparedFinding.seed.vulnerabilityId,
        sbomIngestionId: creation.sbomIngestionId,
        componentOccurrenceId: occurrence.id,
        supportKind: 'unknown_version_occurrence',
      },
    });
    const before = await snapshot(preparedFinding.organizationId, preparedFinding.findingId);
    const result = await inspect(preparedFinding.organizationId, preparedFinding.findingId);
    expect(result.status).toBe('malformed_persisted_state');
    expect(JSON.stringify(result)).not.toContain(occurrence.id);
    expect(JSON.stringify(result)).not.toContain(creation.sbomIngestionId);
    expect(await snapshot(preparedFinding.organizationId, preparedFinding.findingId)).toEqual(
      before,
    );
  });

  it('fails closed when repeated support evidence uses an unsupported evaluator', async () => {
    const preparedFinding = await prepare('repeated-evaluator');
    const next = await later(preparedFinding, 'repeated-evaluator-later', {
      receivedAt: new Date('2026-10-08T12:00:00.000Z'),
      versions: [{ version: '1.2.0', bomRef: 'component-1' }],
    });
    await observe(
      preparedFinding,
      next,
      evidenceSupport(next.evidence.map((row) => row.evidenceId)),
    );
    const evidenceId = next.evidence[0]?.evidenceId;
    if (evidenceId === undefined) {
      throw new Error('repeated support evidence was not prepared');
    }
    const hostile = 'untrusted_evaluator';
    const defined = await prisma.$queryRaw<Array<{ definition: string }>>`
      SELECT pg_get_constraintdef(oid) AS definition
      FROM pg_constraint
      WHERE conname = 'product_match_evaluation_evidence_closed_chk'
    `;
    const definition = defined[0]?.definition;
    if (definition === undefined) {
      throw new Error('evidence lineage constraint was absent');
    }
    await setUserTriggers('product_match_evaluation_evidence', false);
    await prisma.$executeRaw`ALTER TABLE "product_match_evaluation_evidence" DROP CONSTRAINT "product_match_evaluation_evidence_closed_chk"`;
    try {
      await prisma.productMatchEvaluationEvidence.update({
        where: { id: evidenceId },
        data: { evaluatorId: hostile },
      });
      const before = await snapshot(preparedFinding.organizationId, preparedFinding.findingId);
      const result = await inspect(preparedFinding.organizationId, preparedFinding.findingId);
      expect(result.status).toBe('malformed_persisted_state');
      expect(JSON.stringify(result)).not.toContain(hostile);
      expect(JSON.stringify(result)).not.toContain(evidenceId);
      expect(await snapshot(preparedFinding.organizationId, preparedFinding.findingId)).toEqual(
        before,
      );
    } finally {
      await prisma.productMatchEvaluationEvidence.update({
        where: { id: evidenceId },
        data: { evaluatorId: 'osv_first_ecosystem_affected_version_evaluator_v1' },
      });
      await prisma.$executeRawUnsafe(
        `ALTER TABLE "product_match_evaluation_evidence" ADD CONSTRAINT "product_match_evaluation_evidence_closed_chk" ${definition}`,
      );
      await setUserTriggers('product_match_evaluation_evidence', true);
    }
  });

  it('fails closed when a later Finding timestamp has no repeated lineage', async () => {
    const preparedFinding = await prepare('timestamp');
    const moved = new Date('2030-01-01T00:00:00.000Z');
    await setUserTriggers('finding', false);
    await prisma.finding.update({
      where: { id: preparedFinding.findingId },
      data: { lastObservedAt: moved, updatedAt: moved },
    });
    expect((await inspect(preparedFinding.organizationId, preparedFinding.findingId)).status).toBe(
      'malformed_persisted_state',
    );
    await restoreTriggers();
    const reversed = await prepare('timestamp-reversed');
    await setUserTriggers('finding', false);
    await prisma.finding.update({
      where: { id: reversed.findingId },
      data: {
        lastObservedAt: new Date('2020-01-01T00:00:00.000Z'),
        updatedAt: new Date('2020-01-01T00:00:00.000Z'),
      },
    });
    expect((await inspect(reversed.organizationId, reversed.findingId)).status).toBe(
      'malformed_persisted_state',
    );
  });

  it('treats a foreign Finding and an absent Finding as the same public result', async () => {
    const left = await prepare('tenant-left');
    const right = await prepare('tenant-right');
    const foreign = await inspect(left.organizationId, right.findingId);
    const absent = await inspect(left.organizationId, 'abababab-abab-4bab-8bab-abababababab');
    expect(foreign).toEqual(absent);
    expect(foreign).toEqual({
      schemaVersion: FINDING_INSPECTION_RESULT_SCHEMA_VERSION,
      status: 'not_found',
    });
    expect(JSON.stringify(foreign)).toBe(JSON.stringify(absent));
    expect(JSON.stringify(foreign)).not.toContain(right.findingId);
    expect((await inspect(left.organizationId, left.findingId)).status).toBe('found');
  });
});
