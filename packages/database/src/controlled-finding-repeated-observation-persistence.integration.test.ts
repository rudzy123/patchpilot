/**
 * Disposable PostgreSQL proof for repeated Finding observation.
 * The evaluator runs only while seeding Product Match Evidence.
 * The observation transaction does not call a provider or an evaluator.
 */

import { randomUUID } from 'node:crypto';
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
  FINDING_INSPECTION_COMMAND_SCHEMA_VERSION,
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
} from '@patchpilot/domain';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

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
  applyThroughControlledFindingCreation,
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

function writer(client: PrismaClient = prisma) {
  return createControlledFindingRepeatedObservationPersistence(client);
}

async function actor(label: string, client: PrismaClient = prisma): Promise<Actor> {
  const org = await createOrg(client, `${label}-${randomUUID().slice(0, 8)}`);
  const user = await client.user.create({
    data: {
      email: `${label}-${randomUUID().slice(0, 8)}@synthetic.patchpilot.test`,
      displayName: label,
    },
  });
  const membership = await client.membership.create({
    data: { organizationId: org.id, userId: user.id, role: 'member' },
  });
  return { organizationId: org.id, actorId: user.id, membershipId: membership.id };
}

async function createFinding(
  context: Actor,
  seed: ControlledFindingSeedTarget,
  client: PrismaClient = prisma,
): Promise<string> {
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
  const created = await createControlledFindingCreationPersistence(client).apply({
    trustedContext,
    command: opened.command,
  });
  if (created.status !== 'created') {
    throw new Error(`creation was ${created.status}`);
  }
  return created.findingId;
}

async function prepare(
  label: string,
  versions: readonly { readonly version: string; readonly bomRef: string }[],
  client: PrismaClient = prisma,
): Promise<Prepared> {
  const context = await actor(label, client);
  const seed = await seedControlledFindingEvidence(client, {
    label,
    organizationId: context.organizationId,
    versions,
  });
  const findingId = await createFinding(context, seed, client);
  return { ...context, seed, findingId };
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

function seal(
  preparedFinding: Prepared,
  ingestionId: string,
  support: Record<string, unknown>,
  correlationId = randomUUID(),
) {
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
  input: Parameters<typeof seedLaterControlledFindingIngestion>[1] extends infer T
    ? Omit<T, 'label' | 'organizationId' | 'target'>
    : never,
  client: PrismaClient = prisma,
) {
  return seedLaterControlledFindingIngestion(client, {
    label,
    organizationId: preparedFinding.organizationId,
    target: preparedFinding.seed,
    ...input,
  });
}

async function counts(organizationId: string, client: PrismaClient = prisma) {
  const [observations, repeatedLinks, observedAudits, evidence] = await Promise.all([
    client.findingObservation.count({ where: { organizationId } }),
    client.findingRepeatedObservationEvidenceLink.count({ where: { organizationId } }),
    client.auditEvent.count({ where: { organizationId, action: 'finding.observed' } }),
    client.productMatchEvaluationEvidence.count({ where: { organizationId } }),
  ]);
  return { observations, repeatedLinks, observedAudits, evidence };
}

async function creationLineage(client: PrismaClient, findingId: string) {
  const finding = await client.$queryRaw<
    Array<{
      state: string;
      version: string;
      first_observed_at: string;
      last_observed_at: string;
      component_occurrence_id: string | null;
      resolved_at: string | null;
    }>
  >`
    SELECT "state"::text AS state,
           "version"::text AS version,
           "first_observed_at"::text AS first_observed_at,
           "last_observed_at"::text AS last_observed_at,
           "component_occurrence_id"::text AS component_occurrence_id,
           "resolved_at"::text AS resolved_at
    FROM "finding"
    WHERE "id" = ${findingId}::uuid
  `;
  const observations = await client.$queryRaw<
    Array<{
      method: string;
      result: string;
      sbom_ingestion_id: string;
      transition_classification: string | null;
      creation_purpose: string | null;
      affected_evidence_count: string | null;
      replay_fingerprint: string | null;
      evidence: string;
    }>
  >`
    SELECT "method",
           "result"::text AS result,
           "sbom_ingestion_id"::text AS sbom_ingestion_id,
           "transition_classification",
           "creation_purpose",
           "affected_evidence_count"::text AS affected_evidence_count,
           btrim("replay_fingerprint") AS replay_fingerprint,
           "evidence"::text AS evidence
    FROM "finding_observation"
    WHERE "finding_id" = ${findingId}::uuid
    ORDER BY "method"
  `;
  const links = await client.$queryRaw<Array<{ id: string }>>`
    SELECT "product_match_evaluation_evidence_id"::text AS id
    FROM "finding_creation_evidence_link"
    WHERE "finding_id" = ${findingId}::uuid
    ORDER BY "product_match_evaluation_evidence_id"::text COLLATE "C"
  `;
  const audits = await client.$queryRaw<Array<{ action: string; payload: string }>>`
    SELECT "action", "payload"::text AS payload
    FROM "audit_event"
    WHERE "subject_id" = ${findingId}::uuid
    ORDER BY "action", "correlation_id"
  `;
  const evidence = await client.$queryRaw<Array<{ count: string }>>`
    SELECT COUNT(*)::text AS count
    FROM "product_match_evaluation_evidence" AS evidence
    INNER JOIN "finding" AS finding
      ON finding."organization_id" = evidence."organization_id"
    WHERE finding."id" = ${findingId}::uuid
  `;
  return { finding, observations, links, audits, evidence };
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

describe('controlled finding repeated observation persistence', () => {
  it('records one later affected observation and leaves the Finding open', async () => {
    const preparedFinding = await prepare('affected', [
      { version: '1.1.0', bomRef: 'component-1' },
    ]);
    const next = await later(preparedFinding, 'affected-later', {
      receivedAt: new Date('2026-10-08T12:00:00.000Z'),
      versions: [{ version: '1.1.0', bomRef: 'component-1' }],
    });
    const before = await counts(preparedFinding.organizationId);
    const observed = await writer().apply(
      seal(
        preparedFinding,
        next.ingestionId,
        evidenceSupport(next.evidence.map((row) => row.evidenceId)),
      ),
    );
    expect(observed).toMatchObject({
      status: 'observed',
      aggregate: 'affected',
      mappedResult: 'present',
      findingState: 'open',
      observationInserted: true,
      evidenceLinkedOrAbsenceRecorded: true,
      findingTimestampUpdated: true,
      auditEventAdded: true,
      foreignResourceRevealed: false,
    });
    const finding = await prisma.finding.findFirstOrThrow({
      where: { organizationId: preparedFinding.organizationId, id: preparedFinding.findingId },
    });
    expect(finding.state).toBe('open');
    expect(finding.version).toBe(1);
    expect(finding.lastObservedAt.toISOString()).toBe(finding.updatedAt.toISOString());
    expect(finding.lastObservedAt.getTime()).toBeGreaterThan(finding.firstObservedAt.getTime());
    expect(finding.componentOccurrenceId).toBeNull();
    const after = await counts(preparedFinding.organizationId);
    expect(after.observations).toBe(before.observations + 1);
    expect(after.repeatedLinks).toBe(1);
    expect(after.observedAudits).toBe(1);
    expect(after.evidence).toBe(before.evidence);
  });

  it('aggregates unaffected, unknown, and mixed outcomes from derived evidence', async () => {
    const preparedFinding = await prepare('mixed', [{ version: '1.1.0', bomRef: 'component-1' }]);
    const unaffected = await later(preparedFinding, 'unaffected', {
      receivedAt: new Date('2026-10-08T12:00:00.000Z'),
      versions: [{ version: '3.0.0', bomRef: 'component-1' }],
    });
    expect(unaffected.evidence.map((row) => row.outcome)).toEqual(['unaffected']);
    const unaffectedResult = await writer().apply(
      seal(
        preparedFinding,
        unaffected.ingestionId,
        evidenceSupport(unaffected.evidence.map((row) => row.evidenceId)),
      ),
    );
    expect(unaffectedResult).toMatchObject({
      status: 'observed',
      aggregate: 'unaffected',
      mappedResult: 'absent',
      findingState: 'open',
    });

    const unknown = await later(preparedFinding, 'unknown', {
      receivedAt: new Date('2026-10-09T12:00:00.000Z'),
      versions: [{ version: 'not-a-version', bomRef: 'component-1' }],
    });
    expect(unknown.evidence.map((row) => row.outcome)).toEqual(['unknown']);
    const unknownResult = await writer().apply(
      seal(
        preparedFinding,
        unknown.ingestionId,
        evidenceSupport(unknown.evidence.map((row) => row.evidenceId)),
      ),
    );
    expect(unknownResult).toMatchObject({
      status: 'observed',
      aggregate: 'unknown',
      mappedResult: 'inconclusive',
    });

    const dominated = await later(preparedFinding, 'dominated', {
      receivedAt: new Date('2026-10-10T12:00:00.000Z'),
      versions: [
        { version: '1.1.0', bomRef: 'component-1' },
        { version: '3.0.0', bomRef: 'component-2' },
        { version: 'not-a-version', bomRef: 'component-3' },
      ],
    });
    const dominatedResult = await writer().apply(
      seal(
        preparedFinding,
        dominated.ingestionId,
        evidenceSupport(dominated.evidence.map((row) => row.evidenceId)),
      ),
    );
    expect(dominatedResult).toMatchObject({ status: 'observed', aggregate: 'affected' });
    const finding = await prisma.finding.findFirstOrThrow({
      where: { id: preparedFinding.findingId },
    });
    expect(finding.state).toBe('open');
    expect(finding.version).toBe(1);
  });

  it('records unknown-version support and component absence without Product Match Evidence writes', async () => {
    const preparedFinding = await prepare('support', [{ version: '1.1.0', bomRef: 'component-1' }]);
    const unknownVersion = await later(preparedFinding, 'unknown-version', {
      receivedAt: new Date('2026-10-08T12:00:00.000Z'),
      versions: [{ version: '3.0.0', bomRef: 'component-1' }],
      unknownVersions: [{ version: 'unspecified', bomRef: 'component-2' }],
    });
    const before = await counts(preparedFinding.organizationId);
    const observed = await writer().apply(
      seal(
        preparedFinding,
        unknownVersion.ingestionId,
        evidenceSupport(
          unknownVersion.evidence.map((row) => row.evidenceId),
          unknownVersion.unknownVersionOccurrenceIds,
        ),
      ),
    );
    expect(observed).toMatchObject({ status: 'observed', aggregate: 'unknown' });
    const absent = await later(preparedFinding, 'absent', {
      receivedAt: new Date('2026-10-09T12:00:00.000Z'),
      otherComponent: { name: 'other-widget', version: '1.0.0', bomRef: 'other-1' },
    });
    const absence = await writer().apply(
      seal(preparedFinding, absent.ingestionId, absenceSupport(absent.ingestionId, absent)),
    );
    expect(absence).toMatchObject({
      status: 'observed',
      aggregate: 'component_absent',
      mappedResult: 'absent',
      findingState: 'open',
    });
    const links = await prisma.findingRepeatedObservationEvidenceLink.count({
      where: {
        organizationId: preparedFinding.organizationId,
        sbomIngestionId: absent.ingestionId,
      },
    });
    expect(links).toBe(0);
    const after = await counts(preparedFinding.organizationId);
    expect(after.evidence).toBe(before.evidence);
  });

  it('rejects incomplete, stale, creation, and foreign targets without writes', async () => {
    const preparedFinding = await prepare('reject', [{ version: '1.1.0', bomRef: 'component-1' }]);
    const processing = await later(preparedFinding, 'processing', {
      receivedAt: new Date('2026-10-08T12:00:00.000Z'),
      versions: [{ version: '1.1.0', bomRef: 'component-1' }],
      state: 'processing',
      moveLatestPointer: false,
    });
    const completed = await later(preparedFinding, 'completed', {
      receivedAt: new Date('2026-10-09T12:00:00.000Z'),
      versions: [{ version: '1.1.0', bomRef: 'component-1' }],
    });
    const before = await counts(preparedFinding.organizationId);
    const incomplete = await writer().apply(
      seal(
        preparedFinding,
        processing.ingestionId,
        evidenceSupport(processing.evidence.map((row) => row.evidenceId)),
      ),
    );
    expect(incomplete.status).toBe('ingestion_not_completed');
    const versionOne = await later(preparedFinding, 'version-one', {
      receivedAt: new Date('2026-10-10T12:00:00.000Z'),
      versions: [{ version: '1.1.0', bomRef: 'component-1' }],
      normalizationVersion: '1',
    });
    expect(
      (
        await writer().apply(
          seal(
            preparedFinding,
            versionOne.ingestionId,
            evidenceSupport(versionOne.evidence.map((row) => row.evidenceId)),
          ),
        )
      ).status,
    ).toBe('unsupported_normalization_version');
    const stale = await writer().apply(
      seal(
        preparedFinding,
        completed.ingestionId,
        evidenceSupport(completed.evidence.map((row) => row.evidenceId)),
      ),
    );
    expect(stale.status).toBe('ingestion_not_latest');
    const creationIngestion = await writer().apply(
      seal(
        preparedFinding,
        preparedFinding.seed.ingestionId,
        evidenceSupport(preparedFinding.seed.evidence.map((row) => row.evidenceId)),
      ),
    );
    expect(creationIngestion.status).toBe('ingestion_not_latest');
    const stillCreation = await prepare('creation-ingestion', [
      { version: '1.1.0', bomRef: 'component-1' },
    ]);
    const creationOnly = await writer().apply(
      seal(
        stillCreation,
        stillCreation.seed.ingestionId,
        evidenceSupport(stillCreation.seed.evidence.map((row) => row.evidenceId)),
      ),
    );
    expect(creationOnly.status).toBe('ingestion_not_later');
    const missing = await writer().apply(
      seal(preparedFinding, randomUUID(), evidenceSupport([randomUUID()])),
    );
    const foreignOrg = await actor('foreign-org');
    const foreignSeed = await seedControlledFindingEvidence(prisma, {
      label: 'foreign-seed',
      organizationId: foreignOrg.organizationId,
      versions: [{ version: '1.1.0', bomRef: 'component-1' }],
    });
    const foreignMissing = await writer().apply(
      seal(preparedFinding, foreignSeed.ingestionId, evidenceSupport([randomUUID()])),
    );
    expect(missing.status).toBe('not_found');
    expect(foreignMissing.status).toBe(missing.status);
    const afterRejects = await counts(preparedFinding.organizationId);
    expect(afterRejects.observations).toBe(before.observations);
    expect(afterRejects.observedAudits).toBe(0);
    expect(afterRejects.repeatedLinks).toBe(0);
  });

  it('rejects incomplete and oversized support sets with zero writes', async () => {
    const preparedFinding = await prepare('sets', [{ version: '1.1.0', bomRef: 'component-1' }]);
    const next = await later(preparedFinding, 'sets-later', {
      receivedAt: new Date('2026-10-08T12:00:00.000Z'),
      versions: [
        { version: '1.1.0', bomRef: 'component-1' },
        { version: '1.2.0', bomRef: 'component-2' },
      ],
    });
    const ids = next.evidence.map((row) => row.evidenceId);
    const before = await counts(preparedFinding.organizationId);
    expect(
      (
        await writer().apply(
          seal(preparedFinding, next.ingestionId, evidenceSupport(ids.slice(0, 1))),
        )
      ).status,
    ).toBe('evidence_set_mismatch');
    expect(
      (
        await writer().apply(
          seal(preparedFinding, next.ingestionId, evidenceSupport([...ids, randomUUID()])),
        )
      ).status,
    ).toBe('evidence_set_mismatch');
    const oversizedVersions = Array.from({ length: 17 }, (_, index) => ({
      version: `1.1.${index}`,
      bomRef: `component-${index + 1}`,
    }));
    const oversized = await later(preparedFinding, 'oversized', {
      receivedAt: new Date('2026-10-09T12:00:00.000Z'),
      versions: oversizedVersions,
    });
    const oversizedIssued = issueFindingRepeatedObservationAuthorization({
      schemaVersion: FINDING_REPEATED_OBSERVATION_AUTHORIZATION_SCHEMA_VERSION,
      trustedContext: {
        schemaVersion: FINDING_REPEATED_OBSERVATION_TRUSTED_CONTEXT_SCHEMA_VERSION,
        organizationId: preparedFinding.organizationId,
        actorId: preparedFinding.actorId,
        membershipId: preparedFinding.membershipId,
        membershipStatus: 'active',
      },
      purpose: FINDING_REPEATED_OBSERVATION_PURPOSE,
      policyId: FINDING_REPEATED_OBSERVATION_POLICY_ID,
      policyVersion: FINDING_REPEATED_OBSERVATION_POLICY_VERSION,
      findingId: preparedFinding.findingId,
      assetId: preparedFinding.seed.assetId,
      componentId: preparedFinding.seed.componentId,
      vulnerabilityId: preparedFinding.seed.vulnerabilityId,
      sbomIngestionId: oversized.ingestionId,
      support: evidenceSupport(oversized.evidence.map((row) => row.evidenceId)),
      correlationId: randomUUID(),
    });
    expect(oversizedIssued.status).toBe('evidence_set_oversized');
    const afterOversized = await counts(preparedFinding.organizationId);
    expect(afterOversized.observations).toBe(before.observations);
    expect(afterOversized.observedAudits).toBe(0);
    expect(afterOversized.repeatedLinks).toBe(0);
  });

  it('replays an exact observation with zero writes and converges concurrent calls', async () => {
    const preparedFinding = await prepare('replay', [{ version: '1.1.0', bomRef: 'component-1' }]);
    const next = await later(preparedFinding, 'replay-later', {
      receivedAt: new Date('2026-10-08T12:00:00.000Z'),
      versions: [{ version: '1.1.0', bomRef: 'component-1' }],
    });
    const support = evidenceSupport(next.evidence.map((row) => row.evidenceId));
    const sealed = seal(preparedFinding, next.ingestionId, support);
    expect((await writer().apply(sealed)).status).toBe('observed');
    const finding = await prisma.finding.findFirstOrThrow({
      where: { id: preparedFinding.findingId },
    });
    const before = await counts(preparedFinding.organizationId);
    const replay = await writer().apply(sealed);
    expect(replay).toMatchObject({
      status: 'already_applied',
      observationInserted: false,
      findingTimestampUpdated: false,
      auditEventAdded: false,
    });
    const stored = await prisma.finding.findFirstOrThrow({
      where: { id: preparedFinding.findingId },
    });
    expect(stored.updatedAt.toISOString()).toBe(finding.updatedAt.toISOString());
    expect(await counts(preparedFinding.organizationId)).toEqual(before);
    const uncertain = await writer().apply({ ...sealed, fault: 'skip_existing_lookup' });
    expect(uncertain).toMatchObject({
      status: 'already_applied',
      observationInserted: false,
      findingTimestampUpdated: false,
      auditEventAdded: false,
    });
    expect(await counts(preparedFinding.organizationId)).toEqual(before);

    const concurrentFinding = await prepare('concurrent', [
      { version: '1.1.0', bomRef: 'component-1' },
    ]);
    const concurrentLater = await later(concurrentFinding, 'concurrent-later', {
      receivedAt: new Date('2026-10-08T12:00:00.000Z'),
      versions: [{ version: '1.1.0', bomRef: 'component-1' }],
    });
    const concurrentSupport = evidenceSupport(
      concurrentLater.evidence.map((row) => row.evidenceId),
    );
    const [first, second] = await Promise.all([
      writer().apply(seal(concurrentFinding, concurrentLater.ingestionId, concurrentSupport)),
      writer().apply(
        seal(concurrentFinding, concurrentLater.ingestionId, concurrentSupport, randomUUID()),
      ),
    ]);
    expect([first.status, second.status].sort()).toEqual(['already_applied', 'observed']);
    const concurrentCounts = await counts(concurrentFinding.organizationId);
    expect(concurrentCounts.observedAudits).toBe(1);
    expect(concurrentCounts.repeatedLinks).toBe(1);
  });

  it('returns immutable conflict when a stored replay fingerprint disagrees', async () => {
    const preparedFinding = await prepare('conflict', [
      { version: '1.1.0', bomRef: 'component-1' },
    ]);
    const next = await later(preparedFinding, 'conflict-later', {
      receivedAt: new Date('2026-10-08T12:00:00.000Z'),
      versions: [{ version: '1.1.0', bomRef: 'component-1' }],
    });
    const support = evidenceSupport(next.evidence.map((row) => row.evidenceId));
    const planted = await writer().apply({
      ...seal(preparedFinding, next.ingestionId, support),
      fault: 'store_disagreeing_replay_fingerprint',
    });
    expect(planted.status).toBe('observed');
    const before = await counts(preparedFinding.organizationId);
    const finding = await prisma.finding.findFirstOrThrow({
      where: { id: preparedFinding.findingId },
    });
    const conflict = await writer().apply(seal(preparedFinding, next.ingestionId, support));
    expect(conflict).toMatchObject({
      status: 'immutable_conflict',
      observationInserted: false,
      evidenceLinkedOrAbsenceRecorded: false,
      findingTimestampUpdated: false,
      auditEventAdded: false,
    });
    expect(await counts(preparedFinding.organizationId)).toEqual(before);
    const stored = await prisma.finding.findFirstOrThrow({
      where: { id: preparedFinding.findingId },
    });
    expect(stored.updatedAt.toISOString()).toBe(finding.updatedAt.toISOString());
    expect(stored.state).toBe('open');
    expect(stored.version).toBe(1);
  });

  it('rolls back observation, link, timestamp, and audit faults', async () => {
    const preparedFinding = await prepare('rollback', [
      { version: '1.1.0', bomRef: 'component-1' },
    ]);
    const next = await later(preparedFinding, 'rollback-later', {
      receivedAt: new Date('2026-10-08T12:00:00.000Z'),
      versions: [{ version: '1.1.0', bomRef: 'component-1' }],
    });
    const support = evidenceSupport(next.evidence.map((row) => row.evidenceId));
    const before = await counts(preparedFinding.organizationId);
    for (const fault of [
      'before_observation_insert',
      'before_support_link_insert',
      'before_finding_timestamp_update',
      'before_audit_insert',
      'omit_support_links',
      'store_contradictory_aggregate',
    ] as const) {
      const result = await writer().apply({
        ...seal(preparedFinding, next.ingestionId, support),
        fault,
      });
      expect(result.status, fault).toBe('transaction_aborted');
    }
    expect(await counts(preparedFinding.organizationId)).toEqual(before);
    const recovered = await writer().apply(seal(preparedFinding, next.ingestionId, support));
    expect(recovered.status).toBe('observed');
  });

  it('rejects Finding, observation, and support-link mutation outside the transaction', async () => {
    const preparedFinding = await prepare('guards', [{ version: '1.1.0', bomRef: 'component-1' }]);
    const next = await later(preparedFinding, 'guards-later', {
      receivedAt: new Date('2026-10-08T12:00:00.000Z'),
      versions: [{ version: '1.1.0', bomRef: 'component-1' }],
    });
    expect(
      (
        await writer().apply(
          seal(
            preparedFinding,
            next.ingestionId,
            evidenceSupport(next.evidence.map((row) => row.evidenceId)),
          ),
        )
      ).status,
    ).toBe('observed');
    await expect(
      prisma.$executeRaw`
        UPDATE "finding"
        SET "last_observed_at" = CURRENT_TIMESTAMP
        WHERE "id" = ${preparedFinding.findingId}::uuid
      `,
    ).rejects.toThrow();
    await expect(
      prisma.$executeRaw`
        UPDATE "finding"
        SET "state" = 'resolved'
        WHERE "id" = ${preparedFinding.findingId}::uuid
      `,
    ).rejects.toThrow();
    await expect(
      prisma.$executeRaw`DELETE FROM "finding" WHERE "id" = ${preparedFinding.findingId}::uuid`,
    ).rejects.toThrow();
    await expect(
      prisma.$executeRaw`
        UPDATE "finding_observation"
        SET "method" = 'controlled_finding_repeated_observation'
        WHERE "finding_id" = ${preparedFinding.findingId}::uuid
          AND "method" = 'controlled_finding_creation'
      `,
    ).rejects.toThrow();
    await expect(
      prisma.$executeRaw`
        DELETE FROM "finding_repeated_observation_evidence_link"
        WHERE "organization_id" = ${preparedFinding.organizationId}::uuid
      `,
    ).rejects.toThrow();
    await expect(
      prisma.$transaction(async (tx) => {
        await tx.$queryRaw`
          SELECT set_config('patchpilot.controlled_finding_repeated_observation', 'on', true)
        `;
        await tx.$executeRaw`
          UPDATE "finding"
          SET "state" = 'resolved'
          WHERE "organization_id" = ${preparedFinding.organizationId}::uuid
            AND "id" = ${preparedFinding.findingId}::uuid
        `;
      }),
    ).rejects.toThrow();
    await expect(
      prisma.$transaction(async (tx) => {
        await tx.$queryRaw`
          SELECT set_config('patchpilot.controlled_finding_repeated_observation', 'on', true)
        `;
        await tx.$executeRaw`
          UPDATE "finding"
          SET "last_observed_at" = CURRENT_TIMESTAMP,
              "updated_at" = CURRENT_TIMESTAMP
          WHERE "organization_id" = ${preparedFinding.organizationId}::uuid
            AND "id" = ${preparedFinding.findingId}::uuid
        `;
      }),
    ).rejects.toThrow();
    const mappingTarget = await later(preparedFinding, 'mapping-later', {
      receivedAt: new Date('2026-10-09T12:00:00.000Z'),
      versions: [{ version: '1.1.0', bomRef: 'component-1' }],
    });
    await expect(
      prisma.$transaction(async (tx) => {
        await tx.$queryRaw`
          SELECT set_config('patchpilot.controlled_finding_repeated_observation', 'on', true)
        `;
        await tx.$executeRaw`
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
            "actor_membership_id",
            "correlation_id",
            "replay_fingerprint",
            "observation_purpose",
            "observation_policy_id",
            "observation_policy_version",
            "aggregate_classification",
            "evidence_link_count"
          )
          SELECT
            ${preparedFinding.organizationId}::uuid,
            ${preparedFinding.findingId}::uuid,
            ${mappingTarget.sbomId}::uuid,
            ${mappingTarget.ingestionId}::uuid,
            NULL,
            'absent'::"finding_observation_result",
            'controlled_finding_repeated_observation',
            CURRENT_TIMESTAMP,
            jsonb_build_object(
              'schemaVersion', 'finding_repeated_observation_v1',
              'purpose', 'record_finding_repeated_observation',
              'policyId', 'finding_observation_policy_v1',
              'policyVersion', 1,
              'aggregate', 'affected'::"finding_repeated_observation_aggregate",
              'mappedResult', 'absent'::"finding_observation_result",
              'evidenceLinkCount', 1,
              'replayFingerprint', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
            ),
            CURRENT_TIMESTAMP,
            'evidence_observation',
            ${preparedFinding.membershipId}::uuid,
            ${randomUUID()}::uuid,
            'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'record_finding_repeated_observation',
            'finding_observation_policy_v1',
            1,
            'affected'::"finding_repeated_observation_aggregate",
            1
        `;
      }),
    ).rejects.toThrow();
    const observedLink = await prisma.findingRepeatedObservationEvidenceLink.findFirstOrThrow({
      where: { organizationId: preparedFinding.organizationId },
    });
    await expect(
      prisma.$transaction(async (tx) => {
        await tx.$queryRaw`
          SELECT set_config('patchpilot.controlled_finding_repeated_observation', 'on', true)
        `;
        await tx.$executeRaw`
          INSERT INTO "finding_repeated_observation_evidence_link" (
            "organization_id",
            "finding_id",
            "finding_observation_id",
            "sbom_id",
            "product_match_evaluation_evidence_id",
            "asset_id",
            "component_id",
            "vulnerability_id",
            "sbom_ingestion_id",
            "component_occurrence_id",
            "support_kind",
            "outcome",
            "created_at"
          )
          VALUES (
            ${observedLink.organizationId}::uuid,
            ${observedLink.findingId}::uuid,
            ${observedLink.findingObservationId}::uuid,
            ${observedLink.sbomId}::uuid,
            ${observedLink.productMatchEvaluationEvidenceId}::uuid,
            ${observedLink.assetId}::uuid,
            ${observedLink.componentId}::uuid,
            ${observedLink.vulnerabilityId}::uuid,
            ${observedLink.sbomIngestionId}::uuid,
            ${observedLink.componentOccurrenceId}::uuid,
            ${observedLink.supportKind},
            ${observedLink.outcome}::"match_evaluation_outcome",
            CURRENT_TIMESTAMP
          )
        `;
      }),
    ).rejects.toThrow();
    const finding = await prisma.finding.findFirstOrThrow({
      where: { id: preparedFinding.findingId },
    });
    expect(finding.state).toBe('open');
    expect(finding.version).toBe(1);
  });

  it('keeps composed inspection on the creation observation', async () => {
    const preparedFinding = await prepare('inspect', [{ version: '1.1.0', bomRef: 'component-1' }]);
    const next = await later(preparedFinding, 'inspect-later', {
      receivedAt: new Date('2026-10-08T12:00:00.000Z'),
      versions: [{ version: '1.1.0', bomRef: 'component-1' }],
    });
    expect(
      (
        await writer().apply(
          seal(
            preparedFinding,
            next.ingestionId,
            evidenceSupport(next.evidence.map((row) => row.evidenceId)),
          ),
        )
      ).status,
    ).toBe('observed');
    const inspected = await openFindingInspection(
      createControlledFindingInspectionPersistence(prisma),
    ).inspect({
      schemaVersion: FINDING_INSPECTION_COMMAND_SCHEMA_VERSION,
      trustedContext: {
        schemaVersion: FINDING_INSPECTION_TRUSTED_CONTEXT_SCHEMA_VERSION,
        organizationId: preparedFinding.organizationId,
      },
      findingId: preparedFinding.findingId,
    });
    expect(inspected.status).toBe('found');
    if (inspected.status === 'found') {
      expect(inspected.projection.state).toBe('open');
      expect(JSON.stringify(inspected.projection)).not.toContain(
        'record_finding_repeated_observation',
      );
    }
    const second = await later(preparedFinding, 'inspect-second', {
      receivedAt: new Date('2026-10-09T12:00:00.000Z'),
      versions: [{ version: '1.1.0', bomRef: 'component-1' }],
    });
    expect(
      (
        await writer().apply(
          seal(
            preparedFinding,
            second.ingestionId,
            evidenceSupport(second.evidence.map((row) => row.evidenceId)),
          ),
        )
      ).status,
    ).toBe('observed');
    const inspectedAgain = await openFindingInspection(
      createControlledFindingInspectionPersistence(prisma),
    ).inspect({
      schemaVersion: FINDING_INSPECTION_COMMAND_SCHEMA_VERSION,
      trustedContext: {
        schemaVersion: FINDING_INSPECTION_TRUSTED_CONTEXT_SCHEMA_VERSION,
        organizationId: preparedFinding.organizationId,
      },
      findingId: preparedFinding.findingId,
    });
    expect(inspectedAgain.status).toBe('found');
    if (inspectedAgain.status === 'found') {
      expect(JSON.stringify(inspectedAgain.projection)).not.toContain(
        'record_finding_repeated_observation',
      );
      expect(JSON.stringify(inspectedAgain.projection)).not.toContain(second.ingestionId);
    }
  });

  it('migrates an existing controlled Finding without rewriting creation lineage', async () => {
    const ephemeral = await createEphemeralDatabase('migrate');
    const client = new PrismaClient({ datasources: { db: { url: ephemeral.databaseUrl } } });
    try {
      await applyThroughControlledFindingCreation(ephemeral.databaseUrl);
      const preparedFinding = await prepare(
        'pre-migration',
        [{ version: '1.1.0', bomRef: 'component-1' }],
        client,
      );
      const before = await creationLineage(client, preparedFinding.findingId);
      expect(before.observations).toHaveLength(1);
      expect(before.observations[0]?.method).toBe('controlled_finding_creation');
      expect(before.links.length).toBeGreaterThan(0);
      expect(before.audits.map((row) => row.action)).toEqual(['finding.created']);

      await deployMigrations(ephemeral.databaseUrl);
      const after = await creationLineage(client, preparedFinding.findingId);
      expect(after).toEqual(before);
      const added = await client.$queryRaw<
        Array<{
          observation_purpose: string | null;
          observation_policy_id: string | null;
          aggregate_classification: string | null;
          evidence_link_count: number | null;
          repeated_observations: number;
          repeated_links: number;
          observed_audits: number;
        }>
      >`
        SELECT observation."observation_purpose",
               observation."observation_policy_id",
               observation."aggregate_classification"::text AS aggregate_classification,
               observation."evidence_link_count",
               (
                 SELECT COUNT(*)::int
                 FROM "finding_observation" AS repeated
                 WHERE repeated."finding_id" = observation."finding_id"
                   AND repeated."method" = 'controlled_finding_repeated_observation'
               ) AS repeated_observations,
               (
                 SELECT COUNT(*)::int
                 FROM "finding_repeated_observation_evidence_link" AS link
                 WHERE link."finding_id" = observation."finding_id"
               ) AS repeated_links,
               (
                 SELECT COUNT(*)::int
                 FROM "audit_event" AS audit
                 WHERE audit."subject_id" = observation."finding_id"
                   AND audit."action" = 'finding.observed'
               ) AS observed_audits
        FROM "finding_observation" AS observation
        WHERE observation."finding_id" = ${preparedFinding.findingId}::uuid
          AND observation."method" = 'controlled_finding_creation'
      `;
      expect(added[0]).toMatchObject({
        observation_purpose: null,
        observation_policy_id: null,
        aggregate_classification: null,
        evidence_link_count: null,
        repeated_observations: 0,
        repeated_links: 0,
        observed_audits: 0,
      });
      const inspected = await openFindingInspection(
        createControlledFindingInspectionPersistence(client),
      ).inspect({
        schemaVersion: FINDING_INSPECTION_COMMAND_SCHEMA_VERSION,
        trustedContext: {
          schemaVersion: FINDING_INSPECTION_TRUSTED_CONTEXT_SCHEMA_VERSION,
          organizationId: preparedFinding.organizationId,
        },
        findingId: preparedFinding.findingId,
      });
      expect(inspected.status).toBe('found');
      const evidenceIds = sorted(
        preparedFinding.seed.evidence
          .filter((row) => row.outcome === 'affected')
          .map((row) => row.evidenceId),
      );
      const correlationId = randomUUID();
      const trustedContext = {
        schemaVersion: FINDING_CREATION_TRUSTED_CONTEXT_SCHEMA_VERSION,
        organizationId: preparedFinding.organizationId,
        actorId: preparedFinding.actorId,
        membershipId: preparedFinding.membershipId,
        membershipStatus: 'active' as const,
      };
      const issued = issueFindingCreationAuthorization({
        schemaVersion: FINDING_CREATION_AUTHORIZATION_SCHEMA_VERSION,
        trustedContext,
        purpose: FINDING_CREATION_PURPOSE,
        policyId: FINDING_CREATION_POLICY_ID,
        policyVersion: FINDING_CREATION_POLICY_VERSION,
        assetId: preparedFinding.seed.assetId,
        componentId: preparedFinding.seed.componentId,
        vulnerabilityId: preparedFinding.seed.vulnerabilityId,
        sbomIngestionId: preparedFinding.seed.ingestionId,
        productMatchEvidenceIds: evidenceIds,
        correlationId,
      });
      expect(issued.status).toBe('authorized');
      if (issued.status !== 'authorized') {
        return;
      }
      const opened = openFindingCreationCommand({
        schemaVersion: FINDING_CREATION_COMMAND_SCHEMA_VERSION,
        purpose: FINDING_CREATION_PURPOSE,
        policyId: FINDING_CREATION_POLICY_ID,
        policyVersion: FINDING_CREATION_POLICY_VERSION,
        expectedAssetId: preparedFinding.seed.assetId,
        expectedComponentId: preparedFinding.seed.componentId,
        expectedVulnerabilityId: preparedFinding.seed.vulnerabilityId,
        expectedSbomIngestionId: preparedFinding.seed.ingestionId,
        expectedProductMatchEvidenceIds: evidenceIds,
        correlationId,
        authorization: issued.authorization,
      });
      expect(opened.status).toBe('authorized');
      if (opened.status !== 'authorized') {
        return;
      }
      const replay = await createControlledFindingCreationPersistence(client).apply({
        trustedContext,
        command: opened.command,
      });
      expect(replay.status).toBe('already_applied');

      await deployMigrations(ephemeral.databaseUrl);
      expect(await creationLineage(client, preparedFinding.findingId)).toEqual(before);
    } finally {
      await client.$disconnect();
      await dropEphemeralDatabase(ephemeral.admin, ephemeral.databaseName);
    }
  }, 120_000);

  it('does not import a provider or evaluator into the observation transaction', () => {
    const source = readFileSync(
      path.join(
        path.dirname(fileURLToPath(import.meta.url)),
        'controlled-finding-repeated-observation-persistence.ts',
      ),
      'utf8',
    );
    expect(source).not.toContain('@patchpilot/vulnerability-intelligence');
    expect(source).not.toContain('createProductMatchEvaluationComposition');
    expect(source).not.toContain('fetch(');
  });
});
