/**
 * Disposable PostgreSQL proof for the internal latest-observation read.
 * The read invokes the committed selector. It does not write or compose inspection.
 */

import { randomBytes, randomUUID } from 'node:crypto';

import { Prisma, PrismaClient } from '@prisma/client';
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
import {
  canonicalRepeatedObservationEvidenceFingerprint,
  canonicalRepeatedObservationReplayFingerprint,
} from '../../domain/dist/findings/controlled-observation/support.js';
import { createControlledFindingCreationPersistence } from './controlled-finding-creation-persistence.js';
import { createControlledFindingInspectionPersistence } from './controlled-finding-inspection-persistence.js';
import {
  createControlledFindingLatestObservationRead,
  loadControlledFindingLatestObservationSnapshot,
  type ControlledFindingLatestObservationReadOutcome,
} from './controlled-finding-latest-observation-read.js';
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
let migrationCount = 0;

const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/;
const TRIGGER_TABLES = [
  'advisory_revision',
  'advisory_vulnerability_binding',
  'component_occurrence',
  'finding',
  'finding_observation',
  'finding_creation_evidence_link',
  'finding_repeated_observation_evidence_link',
  'maintainer_reviewed_advisory_approval',
  'product_match_evaluation_evidence',
  'sbom',
  'sbom_ingestion',
] as const;

type Actor = {
  readonly organizationId: string;
  readonly actorId: string;
  readonly membershipId: string;
};

type Prepared = Actor & {
  readonly seed: ControlledFindingSeedTarget;
  readonly findingId: string;
};

type StoredObservation = {
  readonly id: string;
  readonly method: string;
  readonly ingestion_id: string;
  readonly sbom_id: string;
  readonly observed_at: string;
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

const UUID_ALPHABET = '0123456789abcdef';

function adjacentUuid(id: string, direction: 'lower' | 'higher'): string {
  const chars = [...id];
  const step = direction === 'lower' ? -1 : 1;
  const start = direction === 'lower' ? 0 : chars.length - 1;
  const end = direction === 'lower' ? chars.length : -1;
  for (let index = start; index !== end; index += direction === 'lower' ? 1 : -1) {
    const char = chars[index];
    if (char === undefined || char === '-' || index === 14 || index === 19) {
      continue;
    }
    const alphabetIndex = UUID_ALPHABET.indexOf(char);
    const next = UUID_ALPHABET[alphabetIndex + step];
    if (next !== undefined) {
      chars[index] = next;
      return chars.join('');
    }
  }
  throw new Error(`uuid has no ${direction} neighbor`);
}

async function retargetIngestion(
  organizationId: string,
  ingestion: LaterControlledFindingIngestion,
  ingestionId: string,
): Promise<LaterControlledFindingIngestion> {
  await withTriggers(
    ['component_occurrence', 'product_match_evaluation_evidence', 'sbom_ingestion'],
    async () => {
      await prisma.$executeRaw`
        UPDATE "sbom_ingestion"
        SET "id" = ${ingestionId}::uuid
        WHERE "organization_id" = ${organizationId}::uuid
          AND "id" = ${ingestion.ingestionId}::uuid
      `;
    },
  );
  return { ...ingestion, ingestionId };
}

function sorted(ids: readonly string[]): string[] {
  return [...ids].sort(compareUuid);
}

function reader(client: PrismaClient = prisma) {
  return createControlledFindingLatestObservationRead(client);
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

async function createFinding(context: Actor, seed: ControlledFindingSeedTarget): Promise<string> {
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
  return created.findingId;
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
  const findingId = await createFinding(context, seed);
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

function absenceSupport(ingestionId: string, laterIngestion: LaterControlledFindingIngestion) {
  return {
    schemaVersion: FINDING_REPEATED_OBSERVATION_ABSENCE_SUPPORT_SCHEMA_VERSION,
    kind: 'component_absence' as const,
    sbomIngestionId: ingestionId,
    graphCompleteness:
      laterIngestion.graphCompleteness === 'complete' ? 'complete' : 'no_dependencies',
    componentCount: laterIngestion.componentCount,
    occurrenceCardinality: laterIngestion.occurrenceCardinality,
    dependencyEdgeCount: laterIngestion.dependencyEdgeCount,
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

async function observe(
  preparedFinding: Prepared,
  ingestion: LaterControlledFindingIngestion,
  unknownVersionOccurrenceIds: readonly string[] = ingestion.unknownVersionOccurrenceIds,
) {
  const applied = await createControlledFindingRepeatedObservationPersistence(prisma).apply(
    seal(
      preparedFinding,
      ingestion.ingestionId,
      ingestion.evidence.length === 0 && unknownVersionOccurrenceIds.length === 0
        ? absenceSupport(ingestion.ingestionId, ingestion)
        : evidenceSupport(
            ingestion.evidence.map((row) => row.evidenceId),
            unknownVersionOccurrenceIds,
          ),
    ),
  );
  if (applied.status !== 'observed') {
    throw new Error(`observation was ${applied.status}`);
  }
  return applied;
}

async function storedObservations(findingId: string): Promise<StoredObservation[]> {
  return prisma.$queryRaw<StoredObservation[]>`
    SELECT lower("id"::text) AS id,
           "method" AS method,
           lower("sbom_ingestion_id"::text) AS ingestion_id,
           lower("sbom_id"::text) AS sbom_id,
           to_char("observed_at" AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS observed_at
    FROM "finding_observation"
    WHERE "finding_id" = ${findingId}::uuid
  `;
}

async function withTriggers(
  tables: readonly (typeof TRIGGER_TABLES)[number][],
  body: () => Promise<void>,
): Promise<void> {
  const unique = [...new Set(tables)];
  const allowed = TRIGGER_TABLES as readonly string[];
  try {
    for (const table of unique) {
      if (!allowed.includes(table)) {
        throw new Error('trigger table rejected');
      }
      await prisma.$executeRawUnsafe(`ALTER TABLE "${table}" DISABLE TRIGGER USER`);
    }
    await body();
  } finally {
    for (const table of [...unique].reverse()) {
      await prisma.$executeRawUnsafe(`ALTER TABLE "${table}" ENABLE TRIGGER USER`);
    }
  }
}

async function pointAsset(preparedFinding: Prepared, ingestionId: string): Promise<void> {
  await prisma.asset.update({
    where: { id: preparedFinding.seed.assetId },
    data: { lastSuccessfulSbomIngestionId: ingestionId },
  });
}

async function placeObservationInstants(
  preparedFinding: Prepared,
  instants: readonly { readonly observationId: string; readonly instant: string }[],
  lastObservedAt: string,
): Promise<void> {
  await withTriggers(['finding', 'finding_observation'], async () => {
    for (const instant of instants) {
      await prisma.$executeRaw`
        UPDATE "finding_observation"
        SET "observed_at" = ${instant.instant}::timestamptz,
            "created_at" = ${instant.instant}::timestamptz
        WHERE "organization_id" = ${preparedFinding.organizationId}::uuid
          AND "id" = ${instant.observationId}::uuid
      `;
    }
    await prisma.$executeRaw`
      UPDATE "finding"
      SET "last_observed_at" = ${lastObservedAt}::timestamptz,
          "updated_at" = ${lastObservedAt}::timestamptz
      WHERE "organization_id" = ${preparedFinding.organizationId}::uuid
        AND "id" = ${preparedFinding.findingId}::uuid
    `;
  });
}

async function alignIngestionTuple(
  repeatedIngestionId: string,
  creationIngestionId: string,
  receivedDelta: string,
  createdDelta: string,
): Promise<void> {
  await prisma.$executeRaw`
    UPDATE "sbom" AS target
    SET "received_at" = source_sbom."received_at" + ${receivedDelta}::interval
    FROM "sbom_ingestion" AS repeated
    INNER JOIN "sbom_ingestion" AS creation
      ON creation."id" = ${creationIngestionId}::uuid
    INNER JOIN "sbom" AS source_sbom
      ON source_sbom."organization_id" = creation."organization_id"
     AND source_sbom."id" = creation."sbom_id"
    WHERE repeated."id" = ${repeatedIngestionId}::uuid
      AND target."organization_id" = repeated."organization_id"
      AND target."id" = repeated."sbom_id"
  `;
  await prisma.$executeRaw`
    UPDATE "sbom_ingestion" AS target
    SET "created_at" = creation."created_at" + ${createdDelta}::interval
    FROM "sbom_ingestion" AS creation
    WHERE creation."id" = ${creationIngestionId}::uuid
      AND target."id" = ${repeatedIngestionId}::uuid
  `;
}

async function fingerprint(organizationId: string): Promise<string> {
  const rows = await prisma.$queryRaw<Array<{ line: string }>>`
    SELECT line
    FROM (
      SELECT 'finding|' || "id"::text || '|' || "xmin"::text || '|' || "state"::text || '|' ||
             "version"::text || '|' || "last_observed_at"::text || '|' || "updated_at"::text AS line
      FROM "finding"
      WHERE "organization_id" = ${organizationId}::uuid
      UNION ALL
      SELECT 'observation|' || "id"::text || '|' || "xmin"::text || '|' || "method" || '|' ||
             "observed_at"::text
      FROM "finding_observation"
      WHERE "organization_id" = ${organizationId}::uuid
      UNION ALL
      SELECT 'creation-link|' || "id"::text || '|' || "xmin"::text
      FROM "finding_creation_evidence_link"
      WHERE "organization_id" = ${organizationId}::uuid
      UNION ALL
      SELECT 'repeated-link|' || "id"::text || '|' || "xmin"::text
      FROM "finding_repeated_observation_evidence_link"
      WHERE "organization_id" = ${organizationId}::uuid
      UNION ALL
      SELECT 'evidence|' || "id"::text || '|' || "xmin"::text || '|' || "outcome"::text
      FROM "product_match_evaluation_evidence"
      WHERE "organization_id" = ${organizationId}::uuid
      UNION ALL
      SELECT 'approval|' || approval."id"::text || '|' || approval."xmin"::text || '|' ||
             approval."approval_purpose"
      FROM "maintainer_reviewed_advisory_approval" AS approval
      INNER JOIN "product_match_evaluation_evidence" AS evidence
        ON evidence."approval_id" = approval."id"
      WHERE evidence."organization_id" = ${organizationId}::uuid
      UNION ALL
      SELECT 'binding|' || binding."id"::text || '|' || binding."xmin"::text || '|' ||
             binding."mapping_review_state"
      FROM "advisory_vulnerability_binding" AS binding
      INNER JOIN "product_match_evaluation_evidence" AS evidence
        ON evidence."advisory_revision_id" = binding."advisory_revision_id"
      WHERE evidence."organization_id" = ${organizationId}::uuid
      UNION ALL
      SELECT 'audit|' || "id"::text || '|' || "xmin"::text || '|' || "action"
      FROM "audit_event"
      WHERE "organization_id" = ${organizationId}::uuid
      UNION ALL
      SELECT 'migrations|' || COUNT(*)::text
      FROM "_prisma_migrations"
    ) AS lines
    ORDER BY line
  `;
  return rows.map((row) => row.line).join('\n');
}

const CANDIDATE_CEILING = 1024;
const CLONE_INSTANT = '2099-01-01T00:00:00.000001Z';
const WINNER_INSTANT = '2099-01-01T00:00:00.000002Z';
const CLONE_CHUNK = 200;

type RepeatedTemplate = {
  readonly observationId: string;
  readonly ingestionId: string;
  readonly sbomId: string;
  readonly evidenceId: string;
  readonly occurrenceId: string;
  readonly observedAt: string;
  readonly aggregate: string;
};

type CandidateClone = {
  readonly sbomId: string;
  readonly ingestionId: string;
  readonly occurrenceId: string;
  readonly evidenceId: string;
  readonly observationId: string;
  readonly linkId: string;
  readonly correlationId: string;
  readonly objectKey: string;
  readonly sha256: string;
  readonly evidenceReplay: string;
  readonly observationReplay: string;
  readonly observedAt: string;
};

function uuidArray(values: readonly string[]): Prisma.Sql {
  return Prisma.sql`ARRAY[${Prisma.join(values.map((value) => Prisma.sql`${value}::uuid`))}]::uuid[]`;
}

function textArray(values: readonly string[]): Prisma.Sql {
  return Prisma.sql`ARRAY[${Prisma.join(values.map((value) => Prisma.sql`${value}`))}]::text[]`;
}

function hex64(): string {
  return randomBytes(32).toString('hex');
}

async function repeatedTemplate(findingId: string): Promise<RepeatedTemplate> {
  const rows = await prisma.$queryRaw<
    Array<{
      observation_id: string;
      ingestion_id: string;
      sbom_id: string;
      evidence_id: string;
      occurrence_id: string;
      observed_at: string;
      aggregate: string;
    }>
  >`
    SELECT lower(observation."id"::text) AS observation_id,
           lower(observation."sbom_ingestion_id"::text) AS ingestion_id,
           lower(observation."sbom_id"::text) AS sbom_id,
           lower(link."product_match_evaluation_evidence_id"::text) AS evidence_id,
           lower(link."component_occurrence_id"::text) AS occurrence_id,
           to_char(observation."observed_at" AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') AS observed_at,
           observation."aggregate_classification"::text AS aggregate
    FROM "finding_observation" AS observation
    INNER JOIN "finding_repeated_observation_evidence_link" AS link
      ON link."organization_id" = observation."organization_id"
     AND link."finding_observation_id" = observation."id"
    WHERE observation."finding_id" = ${findingId}::uuid
      AND observation."method" = 'controlled_finding_repeated_observation'
  `;
  if (rows.length !== 1 || rows[0] === undefined) {
    throw new Error(`expected one repeated template, found ${String(rows.length)}`);
  }
  const row = rows[0];
  return {
    observationId: row.observation_id,
    ingestionId: row.ingestion_id,
    sbomId: row.sbom_id,
    evidenceId: row.evidence_id,
    occurrenceId: row.occurrence_id,
    observedAt: row.observed_at,
    aggregate: row.aggregate,
  };
}

function buildCandidateClones(
  preparedFinding: Prepared,
  template: RepeatedTemplate,
  extraCount: number,
): CandidateClone[] {
  if (template.aggregate !== 'affected') {
    throw new Error(`template aggregate was ${template.aggregate}`);
  }
  const clones: CandidateClone[] = [];
  for (let index = 0; index < extraCount; index += 1) {
    const evidenceId = randomUUID();
    const ingestionId = randomUUID();
    const sha256 = hex64();
    const observedAt = index === extraCount - 1 ? WINNER_INSTANT : CLONE_INSTANT;
    const supportFingerprint = canonicalRepeatedObservationEvidenceFingerprint([evidenceId], [], 1);
    clones.push({
      sbomId: randomUUID(),
      ingestionId,
      occurrenceId: randomUUID(),
      evidenceId,
      observationId: randomUUID(),
      linkId: randomUUID(),
      correlationId: randomUUID(),
      objectKey: `org/${preparedFinding.organizationId}/assets/${preparedFinding.seed.assetId}/sboms/sha256/${sha256}`,
      sha256,
      evidenceReplay: hex64(),
      observationReplay: canonicalRepeatedObservationReplayFingerprint({
        organizationId: preparedFinding.organizationId,
        findingId: preparedFinding.findingId,
        assetId: preparedFinding.seed.assetId,
        componentId: preparedFinding.seed.componentId,
        vulnerabilityId: preparedFinding.seed.vulnerabilityId,
        sbomIngestionId: ingestionId,
        aggregate: 'affected',
        mappedResult: 'present',
        supportFingerprint,
        supportCount: 1,
      }),
      observedAt,
    });
  }
  return clones;
}

async function insertCandidateChunk(
  preparedFinding: Prepared,
  template: RepeatedTemplate,
  chunk: readonly CandidateClone[],
): Promise<void> {
  const sbomIds = chunk.map((clone) => clone.sbomId);
  const ingestionIds = chunk.map((clone) => clone.ingestionId);
  const occurrenceIds = chunk.map((clone) => clone.occurrenceId);
  const evidenceIds = chunk.map((clone) => clone.evidenceId);
  const observationIds = chunk.map((clone) => clone.observationId);
  const linkIds = chunk.map((clone) => clone.linkId);
  const correlationIds = chunk.map((clone) => clone.correlationId);
  const objectKeys = chunk.map((clone) => clone.objectKey);
  const sha256s = chunk.map((clone) => clone.sha256);
  const evidenceReplays = chunk.map((clone) => clone.evidenceReplay);
  const observationReplays = chunk.map((clone) => clone.observationReplay);
  const observedAts = chunk.map((clone) => clone.observedAt);
  await prisma.$executeRaw`
    INSERT INTO "sbom" (
      "id", "organization_id", "asset_id", "object_key", "sha256", "byte_length",
      "declared_content_type", "specification_type", "specification_version", "source",
      "original_filename", "uploaded_by_membership_id", "captured_at", "received_at",
      "parser_version_last_succeeded", "created_at"
    )
    SELECT clone.sbom_id,
           template."organization_id",
           template."asset_id",
           clone.object_key,
           clone.sha256,
           template."byte_length",
           template."declared_content_type",
           template."specification_type",
           template."specification_version",
           template."source",
           template."original_filename",
           template."uploaded_by_membership_id",
           template."captured_at",
           template."received_at",
           template."parser_version_last_succeeded",
           template."created_at"
    FROM "sbom" AS template
    CROSS JOIN unnest(
      ${uuidArray(sbomIds)},
      ${textArray(objectKeys)},
      ${textArray(sha256s)}
    ) AS clone(sbom_id, object_key, sha256)
    WHERE template."id" = ${template.sbomId}::uuid
  `;
  await prisma.$executeRaw`
    INSERT INTO "sbom_ingestion" (
      "id", "organization_id", "sbom_id", "asset_id", "state", "stage", "attempt_number",
      "parser_version", "idempotency_key", "started_at", "completed_at", "graph_completeness",
      "normalization_version", "component_count", "dependency_edge_count", "warning_count",
      "failure_category", "failure_code", "quarantine_reason", "lease_expires_at", "version",
      "created_at", "updated_at"
    )
    SELECT clone.ingestion_id,
           template."organization_id",
           clone.sbom_id,
           template."asset_id",
           template."state",
           template."stage",
           template."attempt_number",
           template."parser_version",
           NULL,
           template."started_at",
           template."completed_at",
           template."graph_completeness",
           template."normalization_version",
           template."component_count",
           template."dependency_edge_count",
           template."warning_count",
           template."failure_category",
           template."failure_code",
           template."quarantine_reason",
           template."lease_expires_at",
           template."version",
           template."created_at",
           template."updated_at"
    FROM "sbom_ingestion" AS template
    CROSS JOIN unnest(
      ${uuidArray(ingestionIds)},
      ${uuidArray(sbomIds)}
    ) AS clone(ingestion_id, sbom_id)
    WHERE template."id" = ${template.ingestionId}::uuid
  `;
  await prisma.$executeRaw`
    INSERT INTO "component_occurrence" (
      "id", "organization_id", "asset_id", "sbom_id", "sbom_ingestion_id", "component_id",
      "bom_ref", "version", "version_known", "versioned_purl", "is_direct", "created_at"
    )
    SELECT clone.occurrence_id,
           template."organization_id",
           template."asset_id",
           clone.sbom_id,
           clone.ingestion_id,
           template."component_id",
           template."bom_ref",
           template."version",
           template."version_known",
           template."versioned_purl",
           template."is_direct",
           template."created_at"
    FROM "component_occurrence" AS template
    CROSS JOIN unnest(
      ${uuidArray(occurrenceIds)},
      ${uuidArray(sbomIds)},
      ${uuidArray(ingestionIds)}
    ) AS clone(occurrence_id, sbom_id, ingestion_id)
    WHERE template."id" = ${template.occurrenceId}::uuid
  `;
  await prisma.$executeRaw`
    INSERT INTO "product_match_evaluation_evidence" (
      "id", "organization_id", "component_occurrence_id", "asset_id", "sbom_id",
      "sbom_ingestion_id", "component_id", "sbom_sha256", "component_identity_key",
      "component_evidence_fingerprint", "evidence_schema_version", "package_identity_key",
      "raw_observed_version", "raw_observed_version_sha256", "advisory_family_id",
      "advisory_revision_id", "approval_id", "content_fingerprint", "range_fingerprint",
      "vulnerability_id", "evaluator_id", "evaluator_version", "matching_policy_id",
      "matching_policy_version", "product_evidence_policy_id", "product_evidence_policy_version",
      "outcome", "product_origin", "replay_fingerprint", "finding_creation",
      "suppression_authority", "created_at"
    )
    SELECT clone.evidence_id,
           template."organization_id",
           clone.occurrence_id,
           template."asset_id",
           clone.sbom_id,
           clone.ingestion_id,
           template."component_id",
           clone.sha256,
           template."component_identity_key",
           template."component_evidence_fingerprint",
           template."evidence_schema_version",
           template."package_identity_key",
           template."raw_observed_version",
           template."raw_observed_version_sha256",
           template."advisory_family_id",
           template."advisory_revision_id",
           template."approval_id",
           template."content_fingerprint",
           template."range_fingerprint",
           template."vulnerability_id",
           template."evaluator_id",
           template."evaluator_version",
           template."matching_policy_id",
           template."matching_policy_version",
           template."product_evidence_policy_id",
           template."product_evidence_policy_version",
           template."outcome",
           template."product_origin",
           clone.evidence_replay,
           template."finding_creation",
           template."suppression_authority",
           template."created_at"
    FROM "product_match_evaluation_evidence" AS template
    CROSS JOIN unnest(
      ${uuidArray(evidenceIds)},
      ${uuidArray(occurrenceIds)},
      ${uuidArray(sbomIds)},
      ${uuidArray(ingestionIds)},
      ${textArray(sha256s)},
      ${textArray(evidenceReplays)}
    ) AS clone(evidence_id, occurrence_id, sbom_id, ingestion_id, sha256, evidence_replay)
    WHERE template."id" = ${template.evidenceId}::uuid
  `;
  await prisma.$executeRaw`
    INSERT INTO "finding_observation" (
      "id", "organization_id", "finding_id", "sbom_id", "sbom_ingestion_id", "occurrence_id",
      "result", "method", "observed_at", "evidence", "created_at", "transition_classification",
      "creation_purpose", "creation_policy_id", "creation_policy_version", "actor_membership_id",
      "correlation_id", "replay_fingerprint", "affected_evidence_count", "observation_purpose",
      "observation_policy_id", "observation_policy_version", "aggregate_classification",
      "evidence_link_count", "absence_graph_completeness", "absence_component_count",
      "absence_dependency_edge_count"
    )
    SELECT clone.observation_id,
           template."organization_id",
           template."finding_id",
           clone.sbom_id,
           clone.ingestion_id,
           NULL,
           template."result",
           template."method",
           clone.observed_at::timestamptz,
           jsonb_build_object(
             'schemaVersion', 'finding_repeated_observation_v1',
             'purpose', template."observation_purpose",
             'policyId', template."observation_policy_id",
             'policyVersion', template."observation_policy_version",
             'aggregate', template."aggregate_classification",
             'mappedResult', template."result",
             'evidenceLinkCount', template."evidence_link_count",
             'replayFingerprint', clone.observation_replay
           ),
           clone.observed_at::timestamptz,
           template."transition_classification",
           template."creation_purpose",
           template."creation_policy_id",
           template."creation_policy_version",
           template."actor_membership_id",
           clone.correlation_id,
           clone.observation_replay,
           template."affected_evidence_count",
           template."observation_purpose",
           template."observation_policy_id",
           template."observation_policy_version",
           template."aggregate_classification",
           template."evidence_link_count",
           template."absence_graph_completeness",
           template."absence_component_count",
           template."absence_dependency_edge_count"
    FROM "finding_observation" AS template
    CROSS JOIN unnest(
      ${uuidArray(observationIds)},
      ${uuidArray(sbomIds)},
      ${uuidArray(ingestionIds)},
      ${uuidArray(correlationIds)},
      ${textArray(observationReplays)},
      ${textArray(observedAts)}
    ) AS clone(
      observation_id,
      sbom_id,
      ingestion_id,
      correlation_id,
      observation_replay,
      observed_at
    )
    WHERE template."id" = ${template.observationId}::uuid
  `;
  await prisma.$executeRaw`
    INSERT INTO "finding_repeated_observation_evidence_link" (
      "id", "organization_id", "finding_id", "finding_observation_id", "sbom_id",
      "product_match_evaluation_evidence_id", "asset_id", "component_id", "vulnerability_id",
      "sbom_ingestion_id", "component_occurrence_id", "support_kind", "outcome"
    )
    SELECT clone.link_id,
           template."organization_id",
           template."finding_id",
           clone.observation_id,
           clone.sbom_id,
           clone.evidence_id,
           template."asset_id",
           template."component_id",
           template."vulnerability_id",
           clone.ingestion_id,
           clone.occurrence_id,
           template."support_kind",
           template."outcome"
    FROM "finding_repeated_observation_evidence_link" AS template
    CROSS JOIN unnest(
      ${uuidArray(linkIds)},
      ${uuidArray(observationIds)},
      ${uuidArray(sbomIds)},
      ${uuidArray(evidenceIds)},
      ${uuidArray(ingestionIds)},
      ${uuidArray(occurrenceIds)}
    ) AS clone(link_id, observation_id, sbom_id, evidence_id, ingestion_id, occurrence_id)
    WHERE template."product_match_evaluation_evidence_id" = ${template.evidenceId}::uuid
      AND template."organization_id" = ${preparedFinding.organizationId}::uuid
  `;
}

async function expandLegalRepeatedCandidates(
  preparedFinding: Prepared,
  template: RepeatedTemplate,
  clones: readonly CandidateClone[],
): Promise<void> {
  const winner = clones[clones.length - 1];
  if (winner === undefined) {
    throw new Error('candidate expansion was empty');
  }
  await withTriggers(
    [
      'sbom',
      'sbom_ingestion',
      'component_occurrence',
      'product_match_evaluation_evidence',
      'finding',
      'finding_observation',
      'finding_repeated_observation_evidence_link',
    ],
    async () => {
      for (let index = 0; index < clones.length; index += CLONE_CHUNK) {
        await insertCandidateChunk(
          preparedFinding,
          template,
          clones.slice(index, index + CLONE_CHUNK),
        );
      }
      await prisma.$executeRaw`
        UPDATE "finding"
        SET "last_observed_at" = ${WINNER_INSTANT}::timestamptz,
            "updated_at" = ${WINNER_INSTANT}::timestamptz
        WHERE "organization_id" = ${preparedFinding.organizationId}::uuid
          AND "id" = ${preparedFinding.findingId}::uuid
      `;
    },
  );
  await pointAsset(preparedFinding, winner.ingestionId);
}

function projectionOf(outcome: ControlledFindingLatestObservationReadOutcome) {
  expect(outcome.diagnostic).toBe('found');
  expect(outcome.safe.status).toBe('found');
  if (outcome.safe.status !== 'found') {
    throw new Error('latest observation was not found');
  }
  return outcome.safe.projection;
}

async function read(preparedFinding: Prepared) {
  return reader().read({
    organizationId: preparedFinding.organizationId,
    findingId: preparedFinding.findingId,
  });
}

beforeAll(async () => {
  database = await createEphemeralDatabase('migrate');
  await deployMigrations(database.databaseUrl);
  prisma = new PrismaClient({ datasources: { db: { url: database.databaseUrl } } });
  const migrations = await prisma.$queryRaw<Array<{ count: number }>>`
    SELECT COUNT(*)::int AS count FROM "_prisma_migrations"
  `;
  migrationCount = migrations[0]?.count ?? 0;
});

afterAll(async () => {
  await prisma.$disconnect();
  await dropEphemeralDatabase(database.admin, database.databaseName);
});

describe('controlled finding latest-observation PostgreSQL read', () => {
  it('returns the same safe not-found result for a missing and a foreign Finding', async () => {
    const preparedFinding = await prepare('tenant');
    const before = await fingerprint(preparedFinding.organizationId);
    const foreign = await actor('foreign');
    const missingId = 'abababab-abab-4bab-8bab-abababababab';
    const absent = await reader().read({
      organizationId: preparedFinding.organizationId,
      findingId: missingId,
    });
    const foreignFinding = await reader().read({
      organizationId: foreign.organizationId,
      findingId: preparedFinding.findingId,
    });
    expect(absent.diagnostic).toBe('not_found');
    expect(foreignFinding.diagnostic).toBe('not_found');
    expect(JSON.stringify(absent.safe)).toBe(JSON.stringify(foreignFinding.safe));
    expect(JSON.stringify(absent.safe)).not.toContain(preparedFinding.findingId);
    expect(JSON.stringify(foreignFinding.safe)).not.toContain(preparedFinding.findingId);
    expect(JSON.stringify(foreignFinding.safe)).not.toContain(foreign.organizationId);
    expect(await fingerprint(preparedFinding.organizationId)).toBe(before);
  });

  it('projects the creation observation and preserves six-digit timestamps', async () => {
    const preparedFinding = await prepare('creation');
    const before = await fingerprint(preparedFinding.organizationId);
    const outcome = await read(preparedFinding);
    const projection = projectionOf(outcome);
    const rows = await storedObservations(preparedFinding.findingId);
    const creation = rows.find((row) => row.method === 'controlled_finding_creation');
    expect(creation).toBeDefined();
    expect(projection.observationSource).toBe('creation');
    expect(projection.aggregate).toBe('affected');
    expect(projection.mappedResult).toBe('present');
    expect(projection.observedAt).toBe(creation?.observed_at);
    expect(projection.observedAt).toMatch(TIMESTAMP);
    expect(projection.findingId).toBe(preparedFinding.findingId);
    expect(projection).not.toHaveProperty('observationId');
    expect(projection).not.toHaveProperty('sbomIngestionId');
    expect(JSON.stringify(outcome.safe)).not.toContain('replayFingerprint');
    expect(await fingerprint(preparedFinding.organizationId)).toBe(before);
    const migrations = await prisma.$queryRaw<Array<{ count: number }>>`
      SELECT COUNT(*)::int AS count FROM "_prisma_migrations"
    `;
    expect(migrations[0]?.count).toBe(migrationCount);
  });

  it('selects the latest legal repeated observation independent of row order', async () => {
    const preparedFinding = await prepare('latest');
    const first = await later(preparedFinding, 'latest-a', {
      receivedAt: new Date('2026-10-08T12:00:00.000Z'),
      versions: [{ version: '1.1.0', bomRef: 'component-1' }],
    });
    await observe(preparedFinding, first);
    const second = await later(preparedFinding, 'latest-b', {
      receivedAt: new Date('2026-10-09T12:00:00.000Z'),
      versions: [{ version: '1.2.0', bomRef: 'component-1' }],
    });
    await observe(preparedFinding, second);
    const before = await fingerprint(preparedFinding.organizationId);
    const selected = projectionOf(await read(preparedFinding));
    const rows = await storedObservations(preparedFinding.findingId);
    const repeated = rows.filter((row) => row.method === 'controlled_finding_repeated_observation');
    const newest = [...repeated].sort((left, right) =>
      left.observed_at < right.observed_at ? 1 : left.observed_at > right.observed_at ? -1 : 0,
    )[0];
    expect(repeated).toHaveLength(2);
    expect(selected.observationSource).toBe('latest_repeated');
    expect(selected.observedAt).toBe(newest?.observed_at);
    expect(selected.observedAt).not.toBe(
      rows.find((row) => row.method === 'controlled_finding_creation')?.observed_at,
    );
    expect(await fingerprint(preparedFinding.organizationId)).toBe(before);

    const lower = [...repeated].sort((left, right) =>
      compareUuid(left.ingestion_id, right.ingestion_id),
    )[0];
    const higher = [...repeated].sort((left, right) =>
      compareUuid(right.ingestion_id, left.ingestion_id),
    )[0];
    if (lower === undefined || higher === undefined) {
      throw new Error('missing repeated observations');
    }
    await placeObservationInstants(
      preparedFinding,
      [
        { observationId: lower.id, instant: '2099-01-01T12:00:00.000002Z' },
        { observationId: higher.id, instant: '2099-01-01T12:00:00.000001Z' },
      ],
      '2099-01-01T12:00:00.000002Z',
    );
    await pointAsset(preparedFinding, lower.ingestion_id);
    const reversed = projectionOf(await read(preparedFinding));
    expect(reversed.observedAt).toBe('2099-01-01T12:00:00.000002Z');
    expect(reversed.observationSource).toBe('latest_repeated');
  });

  it('keeps instants inside one millisecond distinct and breaks exact ties by ingestion id', async () => {
    const preparedFinding = await prepare('microsecond');
    const first = await later(preparedFinding, 'micro-a', {
      receivedAt: new Date('2026-10-08T12:00:00.000Z'),
      versions: [{ version: '1.1.0', bomRef: 'component-1' }],
    });
    await observe(preparedFinding, first);
    const second = await later(preparedFinding, 'micro-b', {
      receivedAt: new Date('2026-10-09T12:00:00.000Z'),
      versions: [{ version: '1.2.0', bomRef: 'component-1' }],
    });
    await observe(preparedFinding, second);
    const rows = await storedObservations(preparedFinding.findingId);
    const repeated = rows.filter((row) => row.method === 'controlled_finding_repeated_observation');
    const lower = [...repeated].sort((left, right) =>
      compareUuid(left.ingestion_id, right.ingestion_id),
    )[0];
    const higher = [...repeated].sort((left, right) =>
      compareUuid(right.ingestion_id, left.ingestion_id),
    )[0];
    if (lower === undefined || higher === undefined || lower.id === higher.id) {
      throw new Error('ingestion tie fixture was incomplete');
    }
    await placeObservationInstants(
      preparedFinding,
      [
        { observationId: lower.id, instant: '2099-01-01T15:00:00.000002Z' },
        { observationId: higher.id, instant: '2099-01-01T15:00:00.000001Z' },
      ],
      '2099-01-01T15:00:00.000002Z',
    );
    await pointAsset(preparedFinding, lower.ingestion_id);
    const laterInstant = projectionOf(await read(preparedFinding));
    expect(laterInstant.observedAt).toBe('2099-01-01T15:00:00.000002Z');
    expect(laterInstant.observedAt.slice(-7)).toBe('000002Z');

    await placeObservationInstants(
      preparedFinding,
      [
        { observationId: lower.id, instant: '2099-01-01T15:00:00.123456Z' },
        { observationId: higher.id, instant: '2099-01-01T15:00:00.123456Z' },
      ],
      '2099-01-01T15:00:00.123456Z',
    );
    await pointAsset(preparedFinding, higher.ingestion_id);
    const tied = projectionOf(await read(preparedFinding));
    expect(tied.observedAt).toBe('2099-01-01T15:00:00.123456Z');
    const reloaded = await storedObservations(preparedFinding.findingId);
    const winner = reloaded.find((row) => row.ingestion_id === higher.ingestion_id);
    expect(winner?.observed_at).toBe(tied.observedAt);
  });

  it('uses the ingestion tuple at microsecond precision', async () => {
    const preparedFinding = await prepare('tuple');
    const creation = (await storedObservations(preparedFinding.findingId))[0];
    if (creation === undefined) {
      throw new Error('missing creation observation');
    }
    const lowerSeed = await later(preparedFinding, 'tuple-low', {
      receivedAt: new Date('2026-10-08T12:00:00.000Z'),
      versions: [{ version: '1.1.0', bomRef: 'component-1' }],
      moveLatestPointer: false,
    });
    const lower = await retargetIngestion(
      preparedFinding.organizationId,
      lowerSeed,
      adjacentUuid(creation.ingestion_id, 'lower'),
    );
    expect(compareUuid(lower.ingestionId, creation.ingestion_id)).toBe(-1);
    await pointAsset(preparedFinding, lower.ingestionId);
    await observe(preparedFinding, lower);
    await alignIngestionTuple(lower.ingestionId, creation.ingestion_id, '1 microsecond', '0');
    await pointAsset(preparedFinding, lower.ingestionId);
    const preserved = projectionOf(await read(preparedFinding));
    expect(preserved.observationSource).toBe('latest_repeated');

    await alignIngestionTuple(lower.ingestionId, creation.ingestion_id, '0', '1 microsecond');
    const createdPrecision = projectionOf(await read(preparedFinding));
    expect(createdPrecision.observationSource).toBe('latest_repeated');

    await alignIngestionTuple(lower.ingestionId, creation.ingestion_id, '0', '0');
    const equalTimestamps = await read(preparedFinding);
    expect(equalTimestamps.safe.status).toBe('unavailable');
    expect(equalTimestamps.diagnostic).not.toBe('not_found');

    const higherSeed = await later(preparedFinding, 'tuple-high', {
      receivedAt: new Date('2026-10-10T12:00:00.000Z'),
      versions: [{ version: '1.4.0', bomRef: 'component-1' }],
      moveLatestPointer: false,
    });
    const higher = await retargetIngestion(
      preparedFinding.organizationId,
      higherSeed,
      adjacentUuid(creation.ingestion_id, 'higher'),
    );
    expect(compareUuid(higher.ingestionId, creation.ingestion_id)).toBe(1);
    await pointAsset(preparedFinding, higher.ingestionId);
    await observe(preparedFinding, higher);
    await alignIngestionTuple(
      higher.ingestionId,
      creation.ingestion_id,
      '-1 microsecond',
      '1 microsecond',
    );
    await pointAsset(preparedFinding, higher.ingestionId);
    const rescued = await read(preparedFinding);
    expect(rescued.safe.status).toBe('unavailable');
    expect(rescued.diagnostic).toBe('malformed_persisted_state');
  });

  it('fails closed when an older or newer candidate is malformed', async () => {
    const preparedFinding = await prepare('complete');
    const older = await later(preparedFinding, 'complete-old', {
      receivedAt: new Date('2026-10-08T12:00:00.000Z'),
      versions: [{ version: '1.1.0', bomRef: 'component-1' }],
    });
    await observe(preparedFinding, older);
    const newer = await later(preparedFinding, 'complete-new', {
      receivedAt: new Date('2026-10-09T12:00:00.000Z'),
      versions: [{ version: '1.2.0', bomRef: 'component-1' }],
    });
    await observe(preparedFinding, newer);
    const third = await later(preparedFinding, 'complete-third', {
      receivedAt: new Date('2026-10-10T12:00:00.000Z'),
      versions: [{ version: '1.3.0', bomRef: 'component-1' }],
    });
    await observe(preparedFinding, third);
    expect(projectionOf(await read(preparedFinding)).observationSource).toBe('latest_repeated');
    const rows = await storedObservations(preparedFinding.findingId);
    const oldest = [...rows]
      .filter((row) => row.method === 'controlled_finding_repeated_observation')
      .sort((left, right) => (left.observed_at < right.observed_at ? -1 : 1))[0];
    if (oldest === undefined) {
      throw new Error('missing oldest observation');
    }
    await withTriggers(['finding_repeated_observation_evidence_link'], async () => {
      await prisma.$executeRaw`
        DELETE FROM "finding_repeated_observation_evidence_link"
        WHERE "organization_id" = ${preparedFinding.organizationId}::uuid
          AND "finding_observation_id" = ${oldest.id}::uuid
      `;
    });
    const hiddenOldest = await read(preparedFinding);
    expect(hiddenOldest.safe.status).toBe('unavailable');
    expect(hiddenOldest.diagnostic).not.toBe('not_found');
    expect(hiddenOldest.safe).not.toHaveProperty('projection');
  });

  it('does not skip a malformed newest observation in favor of an older legal one', async () => {
    const preparedFinding = await prepare('newest');
    const older = await later(preparedFinding, 'newest-old', {
      receivedAt: new Date('2026-10-08T12:00:00.000Z'),
      versions: [{ version: '1.1.0', bomRef: 'component-1' }],
    });
    await observe(preparedFinding, older);
    const newer = await later(preparedFinding, 'newest-new', {
      receivedAt: new Date('2026-10-09T12:00:00.000Z'),
      versions: [{ version: '1.2.0', bomRef: 'component-1' }],
    });
    await observe(preparedFinding, newer);
    const rows = await storedObservations(preparedFinding.findingId);
    const newest = [...rows]
      .filter((row) => row.method === 'controlled_finding_repeated_observation')
      .sort((left, right) => (left.observed_at > right.observed_at ? -1 : 1))[0];
    if (newest === undefined) {
      throw new Error('missing newest observation');
    }
    await withTriggers(['finding_repeated_observation_evidence_link'], async () => {
      await prisma.$executeRaw`
        DELETE FROM "finding_repeated_observation_evidence_link"
        WHERE "finding_observation_id" = ${newest.id}::uuid
      `;
    });
    const outcome = await read(preparedFinding);
    expect(outcome.safe.status).toBe('unavailable');
    expect(outcome.diagnostic).toBe('malformed_persisted_state');
  });

  it('rejects withdrawn, quarantined, superseded, unreviewed, and wrong-purpose evidence', async () => {
    const withdrawn = await prepare('withdrawn');
    const withdrawnLater = await later(withdrawn, 'withdrawn-later', {
      receivedAt: new Date('2026-10-08T12:00:00.000Z'),
      versions: [{ version: '1.1.0', bomRef: 'component-1' }],
    });
    await observe(withdrawn, withdrawnLater);
    await withTriggers(['advisory_revision'], async () => {
      await prisma.$executeRaw`
        UPDATE "advisory_revision" AS revision
        SET "withdrawal_classification" = 'withdrawn',
            "revision_disposition" = 'withdrawn'
        FROM "product_match_evaluation_evidence" AS evidence
        WHERE evidence."organization_id" = ${withdrawn.organizationId}::uuid
          AND evidence."id" = ${withdrawnLater.evidence[0]?.evidenceId ?? ''}::uuid
          AND revision."id" = evidence."advisory_revision_id"
      `;
    });
    const before = await fingerprint(withdrawn.organizationId);
    const withdrawnRead = await read(withdrawn);
    expect(withdrawnRead.safe.status).toBe('unavailable');
    expect(withdrawnRead.diagnostic).toBe('integrity_failure');
    expect(await fingerprint(withdrawn.organizationId)).toBe(before);

    const quarantined = await prepare('quarantine');
    await withTriggers(['advisory_revision'], async () => {
      await prisma.$executeRaw`
        UPDATE "advisory_revision" AS revision
        SET "quarantine_classification" = 'quarantined',
            "revision_disposition" = 'quarantined'
        FROM "product_match_evaluation_evidence" AS evidence
        WHERE evidence."organization_id" = ${quarantined.organizationId}::uuid
          AND revision."id" = evidence."advisory_revision_id"
      `;
    });
    expect((await read(quarantined)).diagnostic).toBe('integrity_failure');

    const purpose = await prepare('purpose');
    const beforePurpose = await fingerprint(purpose.organizationId);
    await expect(
      prisma.$executeRaw`
        UPDATE "maintainer_reviewed_advisory_approval" AS approval
        SET "approval_purpose" = 'not_the_accepted_purpose'
        FROM "product_match_evaluation_evidence" AS evidence
        WHERE evidence."organization_id" = ${purpose.organizationId}::uuid
          AND approval."id" = evidence."approval_id"
      `,
    ).rejects.toThrow();
    expect(projectionOf(await read(purpose)).observationSource).toBe('creation');
    expect(await fingerprint(purpose.organizationId)).toBe(beforePurpose);

    const binding = await prepare('binding');
    const beforeBinding = await fingerprint(binding.organizationId);
    await expect(
      prisma.$executeRaw`
        UPDATE "advisory_vulnerability_binding" AS binding
        SET "mapping_review_state" = 'unreviewed'
        FROM "product_match_evaluation_evidence" AS evidence
        WHERE evidence."organization_id" = ${binding.organizationId}::uuid
          AND binding."advisory_revision_id" = evidence."advisory_revision_id"
      `,
    ).rejects.toThrow();
    expect(projectionOf(await read(binding)).observationSource).toBe('creation');
    expect(await fingerprint(binding.organizationId)).toBe(beforeBinding);

    const superseded = await prepare('successor');
    const supersededLater = await later(superseded, 'successor-later', {
      receivedAt: new Date('2026-10-08T12:00:00.000Z'),
      versions: [{ version: '1.1.0', bomRef: 'component-1' }],
    });
    await observe(superseded, supersededLater);
    await withTriggers(['advisory_revision'], async () => {
      await prisma.$executeRaw`
        CREATE TEMP TABLE "successor_clone" AS
        SELECT *
        FROM "advisory_revision" AS revision
        WHERE revision."id" = (
          SELECT evidence."advisory_revision_id"
          FROM "product_match_evaluation_evidence" AS evidence
          WHERE evidence."id" = ${supersededLater.evidence[0]?.evidenceId ?? ''}::uuid
        )
      `;
      await prisma.$executeRaw`
        UPDATE "successor_clone"
        SET "id" = gen_random_uuid(),
            "revision_digest" = md5(gen_random_uuid()::text) || md5(gen_random_uuid()::text),
            "replay_fingerprint" = md5(gen_random_uuid()::text) || md5(gen_random_uuid()::text),
            "revision_disposition" = 'superseding',
            "supersedes_revision_digest" = md5(gen_random_uuid()::text) || md5(gen_random_uuid()::text),
            "supersedes_advisory_revision_id" = (
              SELECT evidence."advisory_revision_id"
              FROM "product_match_evaluation_evidence" AS evidence
              WHERE evidence."id" = ${supersededLater.evidence[0]?.evidenceId ?? ''}::uuid
            )
      `;
      await prisma.$executeRaw`INSERT INTO "advisory_revision" SELECT * FROM "successor_clone"`;
      await prisma.$executeRaw`DROP TABLE "successor_clone"`;
    });
    const successorRead = await read(superseded);
    expect(successorRead.safe.status).toBe('unavailable');
    expect(successorRead.diagnostic).toBe('integrity_failure');
  });

  it('fails closed on missing support, count mismatch, and normalization mismatch', async () => {
    const missing = await prepare('missing-support');
    const next = await later(missing, 'missing-support-later', {
      receivedAt: new Date('2026-10-08T12:00:00.000Z'),
      versions: [{ version: '1.1.0', bomRef: 'component-1' }],
    });
    await observe(missing, next);
    await withTriggers(['finding_repeated_observation_evidence_link'], async () => {
      await prisma.$executeRaw`
        DELETE FROM "finding_repeated_observation_evidence_link"
        WHERE "organization_id" = ${missing.organizationId}::uuid
          AND "sbom_ingestion_id" = ${next.ingestionId}::uuid
      `;
    });
    const before = await fingerprint(missing.organizationId);
    const missingSupport = await read(missing);
    expect(missingSupport.safe.status).toBe('unavailable');
    expect(missingSupport.diagnostic).toBe('malformed_persisted_state');
    expect(JSON.stringify(missingSupport.safe)).not.toContain('finding_repeated_observation');
    expect(await fingerprint(missing.organizationId)).toBe(before);

    const counted = await prepare('count');
    const countedLater = await later(counted, 'count-later', {
      receivedAt: new Date('2026-10-08T12:00:00.000Z'),
      versions: [{ version: '1.1.0', bomRef: 'component-1' }],
    });
    await observe(counted, countedLater);
    await withTriggers(['finding_observation'], async () => {
      await prisma.$executeRaw`
        UPDATE "finding_observation"
        SET "evidence_link_count" = 2,
            "evidence" = jsonb_set("evidence", '{evidenceLinkCount}', '2'::jsonb)
        WHERE "organization_id" = ${counted.organizationId}::uuid
          AND "sbom_ingestion_id" = ${countedLater.ingestionId}::uuid
      `;
    });
    expect((await read(counted)).diagnostic).toBe('malformed_persisted_state');

    const normalized = await prepare('normalization');
    const normalizedLater = await later(normalized, 'normalization-later', {
      receivedAt: new Date('2026-10-08T12:00:00.000Z'),
      versions: [{ version: '1.1.0', bomRef: 'component-1' }],
    });
    await observe(normalized, normalizedLater);
    await prisma.$executeRaw`
      UPDATE "sbom_ingestion"
      SET "normalization_version" = '1'
      WHERE "id" = ${normalizedLater.ingestionId}::uuid
    `;
    expect((await read(normalized)).safe.status).toBe('unavailable');
  });

  it('projects legal absence and fails closed when absence contradicts an occurrence', async () => {
    const preparedFinding = await prepare('absence');
    const absent = await later(preparedFinding, 'absence-later', {
      receivedAt: new Date('2026-10-08T12:00:00.000Z'),
      otherComponent: { name: 'other-widget', version: '1.0.0', bomRef: 'other-1' },
    });
    await observe(preparedFinding, absent);
    const projection = projectionOf(await read(preparedFinding));
    expect(projection.observationSource).toBe('latest_repeated');
    expect(projection.aggregate).toBe('component_absent');
    expect(projection.evidence).toMatchObject({
      kind: 'component_absence',
      graphCompleteness: 'no_dependencies',
      dependencyEdgeCount: 0,
    });
    expect(JSON.stringify(projection)).not.toContain(absent.ingestionId);

    await prisma.componentOccurrence.create({
      data: {
        organizationId: preparedFinding.organizationId,
        assetId: preparedFinding.seed.assetId,
        sbomId: absent.sbomId,
        sbomIngestionId: absent.ingestionId,
        componentId: preparedFinding.seed.componentId,
        bomRef: 'returned-component',
        version: '9.9.9',
        versionKnown: true,
        isDirect: true,
      },
    });
    const contradicted = await read(preparedFinding);
    expect(contradicted.safe.status).toBe('unavailable');
    expect(contradicted.diagnostic).toBe('malformed_persisted_state');
  });

  it('rejects absence proofs the check constraint cannot store', async () => {
    const preparedFinding = await prepare('absence-check');
    const absent = await later(preparedFinding, 'absence-check-later', {
      receivedAt: new Date('2026-10-08T12:00:00.000Z'),
      otherComponent: { name: 'other-widget', version: '1.0.0', bomRef: 'other-1' },
    });
    await observe(preparedFinding, absent);
    await expect(
      prisma.$executeRaw`
        UPDATE "finding_observation"
        SET "absence_component_count" = -1
        WHERE "sbom_ingestion_id" = ${absent.ingestionId}::uuid
      `,
    ).rejects.toThrow();
    await expect(
      prisma.$executeRaw`
        UPDATE "finding_observation"
        SET "absence_graph_completeness" = 'partial'
        WHERE "sbom_ingestion_id" = ${absent.ingestionId}::uuid
      `,
    ).rejects.toThrow();
    expect(projectionOf(await read(preparedFinding)).aggregate).toBe('component_absent');
  });

  it('keeps duplicate identities and cross-tenant links behind database constraints', async () => {
    const preparedFinding = await prepare('constraints');
    const next = await later(preparedFinding, 'constraints-later', {
      receivedAt: new Date('2026-10-08T12:00:00.000Z'),
      versions: [{ version: '1.1.0', bomRef: 'component-1' }],
    });
    await observe(preparedFinding, next);
    const before = await fingerprint(preparedFinding.organizationId);
    await expect(
      prisma.$transaction(async (tx) => {
        await tx.$executeRaw`
          SELECT set_config('patchpilot.controlled_finding_repeated_observation', 'on', true)
        `;
        await tx.$executeRaw`
        INSERT INTO "finding_observation" (
          "id", "organization_id", "finding_id", "sbom_id", "sbom_ingestion_id",
          "result", "method", "observed_at", "evidence", "created_at",
          "transition_classification", "actor_membership_id", "correlation_id",
          "replay_fingerprint", "observation_purpose", "observation_policy_id",
          "observation_policy_version", "aggregate_classification", "evidence_link_count"
        )
        SELECT gen_random_uuid(),
               "organization_id",
               "finding_id",
               "sbom_id",
               "sbom_ingestion_id",
               "result",
               "method",
               CURRENT_TIMESTAMP,
               "evidence",
               CURRENT_TIMESTAMP,
               "transition_classification",
               "actor_membership_id",
               "correlation_id",
               "replay_fingerprint",
               "observation_purpose",
               "observation_policy_id",
               "observation_policy_version",
               "aggregate_classification",
               "evidence_link_count"
        FROM "finding_observation"
        WHERE "finding_id" = ${preparedFinding.findingId}::uuid
          AND "method" = 'controlled_finding_repeated_observation'
      `;
      }),
    ).rejects.toThrow();
    const foreign = await actor('constraint-foreign');
    await expect(
      prisma.$executeRaw`
        INSERT INTO "finding_repeated_observation_evidence_link" (
          "organization_id", "finding_id", "finding_observation_id", "sbom_id",
          "asset_id", "component_id", "vulnerability_id", "sbom_ingestion_id",
          "component_occurrence_id", "support_kind"
        )
        SELECT ${foreign.organizationId}::uuid,
               link."finding_id",
               link."finding_observation_id",
               link."sbom_id",
               link."asset_id",
               link."component_id",
               link."vulnerability_id",
               link."sbom_ingestion_id",
               link."component_occurrence_id",
               link."support_kind"
        FROM "finding_repeated_observation_evidence_link" AS link
        WHERE link."organization_id" = ${preparedFinding.organizationId}::uuid
        LIMIT 1
      `,
    ).rejects.toThrow();
    expect(await fingerprint(preparedFinding.organizationId)).toBe(before);
  });

  it('observes a coherent snapshot across a concurrent repeated-observation commit', async () => {
    const preparedFinding = await prepare('snapshot');
    const next = await later(preparedFinding, 'snapshot-later', {
      receivedAt: new Date('2026-10-08T12:00:00.000Z'),
      versions: [{ version: '1.1.0', bomRef: 'component-1' }],
    });
    const readerClient = new PrismaClient({
      datasources: { db: { url: database.databaseUrl } },
    });
    let releaseReader: () => void = () => undefined;
    const writerFinished = new Promise<void>((resolve) => {
      releaseReader = resolve;
    });
    let markReady: () => void = () => undefined;
    const readerReady = new Promise<void>((resolve) => {
      markReady = resolve;
    });
    const during = readerClient.$transaction(
      async (tx) => {
        await tx.$queryRaw`SELECT 1`;
        markReady();
        await writerFinished;
        return loadControlledFindingLatestObservationSnapshot(tx, {
          organizationId: preparedFinding.organizationId,
          findingId: preparedFinding.findingId,
        });
      },
      { isolationLevel: 'RepeatableRead', timeout: 20_000 },
    );
    try {
      await readerReady;
      await observe(preparedFinding, next);
    } finally {
      releaseReader();
    }
    const snapshot = await during;
    const after = await read(preparedFinding);
    expect(snapshot.safe.status).not.toBe('found');
    expect(snapshot.diagnostic).not.toBe('found');
    expect(projectionOf(after).observationSource).toBe('latest_repeated');
    await readerClient.$disconnect();
  });

  it('projects legal unknown-version support and fails closed on an illegal unknown version', async () => {
    const legal = await prepare('unknown-legal');
    const unknownOnly = await later(legal, 'unknown-legal-later', {
      receivedAt: new Date('2026-10-08T12:00:00.000Z'),
      unknownVersions: [{ version: 'unspecified', bomRef: 'component-unknown' }],
    });
    await observe(legal, unknownOnly);
    const beforeLegal = await fingerprint(legal.organizationId);
    const projection = projectionOf(await read(legal));
    expect(projection.observationSource).toBe('latest_repeated');
    expect(projection.aggregate).toBe('unknown');
    expect(projection.mappedResult).toBe('inconclusive');
    expect(projection.evidence).toMatchObject({
      kind: 'occurrence_support',
      unknownVersionSupportCount: 1,
      affectedSupportCount: 0,
      knownVersions: [],
    });
    expect(await fingerprint(legal.organizationId)).toBe(beforeLegal);

    const illegal = await prepare('unknown-illegal');
    const illegalLater = await later(illegal, 'unknown-illegal-later', {
      receivedAt: new Date('2026-10-08T12:00:00.000Z'),
      unknownVersions: [{ version: 'unspecified', bomRef: 'component-unknown' }],
    });
    await observe(illegal, illegalLater);
    const unknownOccurrenceId = illegalLater.unknownVersionOccurrenceIds[0];
    if (unknownOccurrenceId === undefined) {
      throw new Error('missing unknown-version occurrence');
    }
    await expect(
      prisma.$executeRaw`
        UPDATE "finding_repeated_observation_evidence_link"
        SET "product_match_evaluation_evidence_id" = ${illegal.seed.evidence[0]?.evidenceId ?? ''}::uuid,
            "outcome" = 'affected'
        WHERE "organization_id" = ${illegal.organizationId}::uuid
          AND "support_kind" = 'unknown_version_occurrence'
      `,
    ).rejects.toThrow();
    await withTriggers(['component_occurrence'], async () => {
      await prisma.$executeRaw`
        UPDATE "component_occurrence"
        SET "version_known" = TRUE,
            "version" = 'smuggled'
        WHERE "organization_id" = ${illegal.organizationId}::uuid
          AND "id" = ${unknownOccurrenceId}::uuid
      `;
    });
    const beforeIllegal = await fingerprint(illegal.organizationId);
    const rejected = await read(illegal);
    expect(rejected.safe.status).toBe('unavailable');
    expect(rejected.diagnostic).toBe('malformed_persisted_state');
    expect(rejected.safe).not.toHaveProperty('projection');
    expect(JSON.stringify(rejected.safe)).not.toContain('smuggled');
    expect(await fingerprint(illegal.organizationId)).toBe(beforeIllegal);
  });

  it('fails closed when legal product-match support is mixed with illegal unknown-version support', async () => {
    const preparedFinding = await prepare('mixed-support');
    const mixed = await later(preparedFinding, 'mixed-support-later', {
      receivedAt: new Date('2026-10-08T12:00:00.000Z'),
      versions: [{ version: '1.1.0', bomRef: 'component-known' }],
      unknownVersions: [{ version: 'unspecified', bomRef: 'component-unknown' }],
    });
    await observe(preparedFinding, mixed);
    const legal = projectionOf(await read(preparedFinding));
    expect(legal.aggregate).toBe('affected');
    expect(legal.evidence).toMatchObject({
      kind: 'occurrence_support',
      affectedSupportCount: 1,
      unknownVersionSupportCount: 1,
    });
    const unknownOccurrenceId = mixed.unknownVersionOccurrenceIds[0];
    if (unknownOccurrenceId === undefined) {
      throw new Error('missing mixed unknown-version occurrence');
    }
    await withTriggers(['component_occurrence'], async () => {
      await prisma.$executeRaw`
        UPDATE "component_occurrence"
        SET "version_known" = TRUE,
            "version" = 'smuggled'
        WHERE "organization_id" = ${preparedFinding.organizationId}::uuid
          AND "id" = ${unknownOccurrenceId}::uuid
      `;
    });
    const before = await fingerprint(preparedFinding.organizationId);
    const rejected = await read(preparedFinding);
    expect(rejected.safe.status).toBe('unavailable');
    expect(rejected.diagnostic).toBe('malformed_persisted_state');
    expect(rejected.safe).not.toHaveProperty('projection');
    expect(JSON.stringify(rejected.safe)).not.toContain('1.1.0');
    expect(await fingerprint(preparedFinding.organizationId)).toBe(before);
  });

  it('fails closed when a component-absent observation gains a support link', async () => {
    const preparedFinding = await prepare('absence-link');
    const absent = await later(preparedFinding, 'absence-link-later', {
      receivedAt: new Date('2026-10-08T12:00:00.000Z'),
      otherComponent: { name: 'other-widget', version: '1.0.0', bomRef: 'other-1' },
    });
    await observe(preparedFinding, absent);
    expect(projectionOf(await read(preparedFinding)).aggregate).toBe('component_absent');
    const rows = await storedObservations(preparedFinding.findingId);
    const absence = rows.find((row) => row.method === 'controlled_finding_repeated_observation');
    if (absence === undefined) {
      throw new Error('missing absence observation');
    }
    const hostileOccurrenceId = randomUUID();
    await withTriggers(
      ['component_occurrence', 'finding_repeated_observation_evidence_link'],
      async () => {
        await prisma.$executeRaw`
          INSERT INTO "component_occurrence" (
            "id", "organization_id", "asset_id", "sbom_id", "sbom_ingestion_id", "component_id",
            "bom_ref", "version", "version_known", "is_direct"
          )
          VALUES (
            ${hostileOccurrenceId}::uuid,
            ${preparedFinding.organizationId}::uuid,
            ${preparedFinding.seed.assetId}::uuid,
            ${absent.sbomId}::uuid,
            ${absent.ingestionId}::uuid,
            ${preparedFinding.seed.componentId}::uuid,
            'hostile-absence-link',
            '',
            FALSE,
            FALSE
          )
        `;
        await prisma.$executeRaw`
          INSERT INTO "finding_repeated_observation_evidence_link" (
            "organization_id", "finding_id", "finding_observation_id", "sbom_id",
            "asset_id", "component_id", "vulnerability_id", "sbom_ingestion_id",
            "component_occurrence_id", "support_kind"
          )
          VALUES (
            ${preparedFinding.organizationId}::uuid,
            ${preparedFinding.findingId}::uuid,
            ${absence.id}::uuid,
            ${absent.sbomId}::uuid,
            ${preparedFinding.seed.assetId}::uuid,
            ${preparedFinding.seed.componentId}::uuid,
            ${preparedFinding.seed.vulnerabilityId}::uuid,
            ${absent.ingestionId}::uuid,
            ${hostileOccurrenceId}::uuid,
            'unknown_version_occurrence'
          )
        `;
      },
    );
    const before = await fingerprint(preparedFinding.organizationId);
    const rejected = await read(preparedFinding);
    expect(rejected.safe.status).toBe('unavailable');
    expect(rejected.diagnostic).toBe('malformed_persisted_state');
    expect(rejected.safe).not.toHaveProperty('projection');
    expect(await fingerprint(preparedFinding.organizationId)).toBe(before);
  });

  it('fails closed when the creation observation loses its evidence link', async () => {
    const preparedFinding = await prepare('creation-integrity');
    const beforeMutation = projectionOf(await read(preparedFinding));
    expect(beforeMutation.observationSource).toBe('creation');
    await withTriggers(['finding_creation_evidence_link'], async () => {
      await prisma.$executeRaw`
        DELETE FROM "finding_creation_evidence_link"
        WHERE "organization_id" = ${preparedFinding.organizationId}::uuid
          AND "finding_id" = ${preparedFinding.findingId}::uuid
      `;
    });
    const before = await fingerprint(preparedFinding.organizationId);
    const rejected = await read(preparedFinding);
    expect(rejected.safe.status).toBe('unavailable');
    expect(rejected.diagnostic).toBe('malformed_persisted_state');
    expect(rejected.diagnostic).not.toBe('not_found');
    expect(rejected.safe).not.toHaveProperty('projection');
    expect(await fingerprint(preparedFinding.organizationId)).toBe(before);
  });

  it('selects all legal candidates past 1024 and still sees an older illegal candidate', async () => {
    const preparedFinding = await prepare('candidate-ceiling');
    const templateIngestion = await later(preparedFinding, 'candidate-ceiling-template', {
      receivedAt: new Date('2026-10-08T12:00:00.000Z'),
      versions: [{ version: '1.1.0', bomRef: 'component-1' }],
    });
    await observe(preparedFinding, templateIngestion);
    const template = await repeatedTemplate(preparedFinding.findingId);
    const clones = buildCandidateClones(preparedFinding, template, CANDIDATE_CEILING);
    await expandLegalRepeatedCandidates(preparedFinding, template, clones);
    const repeatedCount = await prisma.$queryRaw<Array<{ count: number }>>`
        SELECT COUNT(*)::int AS count
        FROM "finding_observation"
        WHERE "organization_id" = ${preparedFinding.organizationId}::uuid
          AND "finding_id" = ${preparedFinding.findingId}::uuid
          AND "method" = 'controlled_finding_repeated_observation'
      `;
    expect(repeatedCount[0]?.count).toBe(CANDIDATE_CEILING + 1);
    const before = await fingerprint(preparedFinding.organizationId);
    const selected = projectionOf(await read(preparedFinding));
    expect(selected.observationSource).toBe('latest_repeated');
    expect(selected.observedAt).toBe(WINNER_INSTANT);
    expect(selected.aggregate).toBe('affected');
    expect(await fingerprint(preparedFinding.organizationId)).toBe(before);

    const wrongReplay = 'ab'.repeat(32);
    await withTriggers(['finding_observation'], async () => {
      await prisma.$executeRaw`
          UPDATE "finding_observation"
          SET "replay_fingerprint" = ${wrongReplay},
              "evidence" = jsonb_set(
                "evidence",
                '{replayFingerprint}',
                to_jsonb(${wrongReplay}::text)
              )
          WHERE "organization_id" = ${preparedFinding.organizationId}::uuid
            AND "id" = ${template.observationId}::uuid
        `;
    });
    const beforeIllegal = await fingerprint(preparedFinding.organizationId);
    const rejected = await read(preparedFinding);
    expect(rejected.safe.status).toBe('unavailable');
    expect(rejected.diagnostic).toBe('malformed_persisted_state');
    expect(rejected.safe).not.toHaveProperty('projection');
    expect(await fingerprint(preparedFinding.organizationId)).toBe(beforeIllegal);
  }, 90_000);

  it('leaves current production inspection creation based', async () => {
    const preparedFinding = await prepare('compatibility');
    const next = await later(preparedFinding, 'compatibility-later', {
      receivedAt: new Date('2026-10-08T12:00:00.000Z'),
      versions: [{ version: '1.1.0', bomRef: 'component-1' }],
    });
    await observe(preparedFinding, next);
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
      expect(inspected.projection).not.toHaveProperty('observationSource');
      expect(JSON.stringify(inspected.projection)).not.toContain('latest_repeated');
    }
    const latest = projectionOf(await read(preparedFinding));
    expect(latest.observationSource).toBe('latest_repeated');
  });

  it('parameterizes the tenant lookup and does not emit a write statement', async () => {
    const preparedFinding = await prepare('query-shape');
    const queries: string[] = [];
    const logging = new PrismaClient({
      datasources: { db: { url: database.databaseUrl } },
      log: [{ emit: 'event', level: 'query' }],
    });
    logging.$on('query', (event) => {
      queries.push(event.query);
    });
    const outcome = await reader(logging).read({
      organizationId: preparedFinding.organizationId,
      findingId: preparedFinding.findingId,
    });
    expect(outcome.safe.status).toBe('found');
    const findingQuery = queries.find(
      (query) => query.includes('"finding"') && query.toLowerCase().includes('where'),
    );
    expect(findingQuery).toBeDefined();
    expect(findingQuery).toContain('organization_id');
    expect(findingQuery).not.toContain(preparedFinding.organizationId);
    expect(findingQuery).not.toContain(preparedFinding.findingId);
    expect(findingQuery?.includes('SELECT *')).toBe(false);
    const joined = queries.join('\n').toLowerCase();
    expect(joined).not.toMatch(/\blimit\s+1\b/);
    expect(joined).not.toMatch(/\binsert\s+into\b/);
    expect(joined).not.toMatch(/\bdelete\s+from\b/);
    expect(joined).not.toMatch(/\bupdate\s+"/);
    await logging.$disconnect();
  });

  it('maps an unreachable database to unavailable rather than not_found', async () => {
    const preparedFinding = await prepare('down');
    const before = await fingerprint(preparedFinding.organizationId);
    const brokenUrl = new URL(database.databaseUrl);
    brokenUrl.port = '1';
    const unreachable = new PrismaClient({ datasources: { db: { url: brokenUrl.toString() } } });
    try {
      const outcome = await reader(unreachable).read({
        organizationId: preparedFinding.organizationId,
        findingId: preparedFinding.findingId,
      });
      expect(outcome.diagnostic).toBe('database_unavailable');
      expect(outcome.safe.status).toBe('unavailable');
      expect(JSON.stringify(outcome.safe)).not.toContain(preparedFinding.findingId);
    } finally {
      await unreachable.$disconnect();
    }
    expect(await fingerprint(preparedFinding.organizationId)).toBe(before);
  });
});
