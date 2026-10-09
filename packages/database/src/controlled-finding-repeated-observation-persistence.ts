/**
 * Controlled Finding repeated-observation transaction.
 * One transaction records one later observation, its support links or absence
 * metadata, two Finding timestamps, and one finding.observed audit event.
 * Production startup does not construct this adapter.
 * No provider, evaluator, parser, object storage, network, or queue call runs here.
 * Same-asset work serializes on the organization-and-asset advisory lock.
 */

import { Prisma, type PrismaClient } from '@prisma/client';
import { canonicalRepeatedObservationReplayFingerprint } from '../../domain/dist/findings/controlled-observation/support.js';
import {
  FINDING_REPEATED_OBSERVATION_MAX_SUPPORT_FACTS,
  FINDING_REPEATED_OBSERVATION_POLICY_ID,
  FINDING_REPEATED_OBSERVATION_POLICY_VERSION,
  FINDING_REPEATED_OBSERVATION_PURPOSE,
  FINDING_REPEATED_OBSERVATION_TRANSACTION_SCHEMA_VERSION,
  canonicalRepeatedObservationAbsenceFingerprint,
  canonicalRepeatedObservationEvidenceFingerprint,
  classifyFindingRepeatedObservationReplay,
  classifyInspectionObservationShape,
  mapRepeatedObservationAggregate,
  parseTrustedFindingRepeatedObservationContext,
  presentFindingRepeatedObservationAuthorization,
  repeatedObservationTenantDisclosure,
  type FindingRepeatedObservationAggregate,
  type FindingRepeatedObservationTransactionResult,
} from '@patchpilot/domain';

const REPEATED_METHOD = 'controlled_finding_repeated_observation';
const REPEATED_TRANSITION = 'evidence_observation';
const CREATION_METHOD = 'controlled_finding_creation';
const NORMALIZATION_VERSION = '2';
const MAX_SUPPORT = FINDING_REPEATED_OBSERVATION_MAX_SUPPORT_FACTS;

export const CONTROLLED_FINDING_REPEATED_OBSERVATION_FAULTS = [
  'before_observation_insert',
  'before_support_link_insert',
  'before_finding_timestamp_update',
  'before_audit_insert',
  'before_return',
  'omit_support_links',
  'skip_existing_lookup',
  'store_disagreeing_replay_fingerprint',
  'store_contradictory_aggregate',
] as const;

export type ControlledFindingRepeatedObservationFault =
  (typeof CONTROLLED_FINDING_REPEATED_OBSERVATION_FAULTS)[number];

export type ControlledFindingRepeatedObservationApplyInput = {
  readonly trustedContext: unknown;
  readonly command: unknown;
  readonly fault?: ControlledFindingRepeatedObservationFault;
};

type EvidenceCommand = {
  readonly kind: 'evidence_set';
  readonly findingId: string;
  readonly assetId: string;
  readonly componentId: string;
  readonly vulnerabilityId: string;
  readonly sbomIngestionId: string;
  readonly correlationId: string;
  readonly evidenceIds: readonly string[];
  readonly unknownVersionOccurrenceIds: readonly string[];
  readonly supportCount: number;
};

type AbsenceCommand = {
  readonly kind: 'component_absence';
  readonly findingId: string;
  readonly assetId: string;
  readonly componentId: string;
  readonly vulnerabilityId: string;
  readonly sbomIngestionId: string;
  readonly correlationId: string;
  readonly graphCompleteness: 'complete' | 'no_dependencies';
  readonly componentCount: number;
  readonly occurrenceCardinality: number;
  readonly dependencyEdgeCount: number;
};

type CommandBinding = EvidenceCommand | AbsenceCommand;

type OccurrenceRow = {
  id: string;
  version_known: boolean | null;
};

type CurrentEvidenceRow = {
  id: string;
  component_occurrence_id: string;
  outcome: 'affected' | 'unaffected' | 'unknown';
};

type SupportLink = {
  readonly occurrenceId: string;
  readonly evidenceId: string | null;
  readonly outcome: 'affected' | 'unaffected' | 'unknown' | null;
  readonly supportKind: 'product_match_evidence' | 'unknown_version_occurrence';
};

type DerivedObservation = {
  readonly aggregate: FindingRepeatedObservationAggregate;
  readonly mappedResult: 'present' | 'absent' | 'inconclusive';
  readonly links: readonly SupportLink[];
  readonly evidenceIds: readonly string[];
  readonly unknownVersionOccurrenceIds: readonly string[];
  readonly supportFingerprint: string;
  readonly replayFingerprint: string;
  readonly supportCount: number;
  readonly absence: {
    readonly graphCompleteness: 'complete' | 'no_dependencies';
    readonly componentCount: number;
    readonly dependencyEdgeCount: number;
  } | null;
};

type StoredObservation = {
  id: string;
  sbom_id: string;
  result: string;
  method: string;
  occurrence_id: string | null;
  transition_classification: string | null;
  creation_purpose: string | null;
  creation_policy_id: string | null;
  creation_policy_version: number | null;
  observation_purpose: string | null;
  observation_policy_id: string | null;
  observation_policy_version: number | null;
  aggregate_classification: string | null;
  evidence_link_count: number | null;
  replay_fingerprint: string | null;
  absence_graph_completeness: string | null;
  absence_component_count: number | null;
  absence_dependency_edge_count: number | null;
};

type StoredLink = {
  component_occurrence_id: string;
  product_match_evaluation_evidence_id: string | null;
  support_kind: string;
  outcome: string | null;
};

class ObservationFault extends Error {
  constructor(readonly stage: ControlledFindingRepeatedObservationFault) {
    super('controlled finding repeated observation fault');
  }
}

export function createControlledFindingRepeatedObservationPersistence(client: PrismaClient) {
  return {
    async apply(
      input: ControlledFindingRepeatedObservationApplyInput,
    ): Promise<FindingRepeatedObservationTransactionResult> {
      const trusted = parseTrustedFindingRepeatedObservationContext(input.trustedContext);
      if (!trusted.ok) {
        return stopped('invalid_command');
      }
      const presented = presentFindingRepeatedObservationAuthorization({
        trustedContext: input.trustedContext,
        command: input.command,
      });
      if (presented.status !== 'authorized') {
        return stopped(presented.status);
      }
      const command = readCommand(input.command);
      if (command === null) {
        return stopped('invalid_command');
      }
      const request = {
        organizationId: trusted.context.organizationId,
        actorId: trusted.context.actorId,
        membershipId: trusted.context.membershipId,
        command,
        fault: input.fault,
      };
      try {
        return await client.$transaction((tx) => applyInTransaction(tx, request));
      } catch (error) {
        if (error instanceof ObservationFault) {
          return stopped('transaction_aborted');
        }
        if (isUniqueViolation(error)) {
          return reloadAfterConflict(client, request);
        }
        if (isDatabaseUnavailable(error)) {
          return stopped('database_unavailable');
        }
        if (isConstraintFailure(error)) {
          return stopped('transaction_aborted');
        }
        return stopped('internal_failure');
      }
    },
  };
}

async function applyInTransaction(
  tx: Prisma.TransactionClient,
  input: {
    readonly organizationId: string;
    readonly actorId: string;
    readonly membershipId: string;
    readonly command: CommandBinding;
    readonly fault: ControlledFindingRepeatedObservationFault | undefined;
  },
): Promise<FindingRepeatedObservationTransactionResult> {
  await tx.$queryRaw`
    SELECT set_config('patchpilot.controlled_finding_repeated_observation', 'on', true) AS configured
  `;
  const locked = await tx.$queryRaw<Array<{ locked: number }>>`
    SELECT 1::int AS locked
    FROM (
      SELECT pg_advisory_xact_lock(
        hashtextextended(${`${input.organizationId}:${input.command.assetId}`}, 0)
      )
    ) AS taken
  `;
  if (locked.length !== 1) {
    return stopped('internal_failure');
  }
  const asset = await tx.$queryRaw<Array<{ current_id: string | null }>>`
    SELECT "last_successful_sbom_ingestion_id"::text AS current_id
    FROM "asset"
    WHERE "organization_id" = ${input.organizationId}::uuid
      AND "id" = ${input.command.assetId}::uuid
    FOR UPDATE
  `;
  if (asset.length !== 1) {
    return stopped('not_found');
  }
  const organization = await tx.$queryRaw<Array<{ id: string }>>`
    SELECT "id"::text AS id
    FROM "organization"
    WHERE "id" = ${input.organizationId}::uuid
  `;
  if (organization.length !== 1) {
    return stopped('not_found');
  }
  const membership = await tx.$queryRaw<Array<{ id: string; user_id: string; status: string }>>`
    SELECT "id"::text AS id, "user_id"::text AS user_id, "status"::text AS status
    FROM "membership"
    WHERE "organization_id" = ${input.organizationId}::uuid
      AND "id" = ${input.membershipId}::uuid
    FOR UPDATE
  `;
  const member = membership[0];
  if (member === undefined || member.status !== 'active' || member.user_id !== input.actorId) {
    return stopped('authority_rejected');
  }
  const findings = await tx.$queryRaw<Array<{ id: string; state: string; version: number }>>`
    SELECT "id"::text AS id, "state"::text AS state, "version"
    FROM "finding"
    WHERE "organization_id" = ${input.organizationId}::uuid
      AND "id" = ${input.command.findingId}::uuid
      AND "asset_id" = ${input.command.assetId}::uuid
      AND "component_id" = ${input.command.componentId}::uuid
      AND "vulnerability_id" = ${input.command.vulnerabilityId}::uuid
    FOR UPDATE
  `;
  const finding = findings[0];
  if (finding === undefined) {
    return stopped('not_found');
  }
  if (finding.state !== 'open' || finding.version !== 1) {
    return stopped('malformed_persisted_state');
  }
  const lineage = await validateCreationLineage(
    tx,
    input.organizationId,
    finding.id,
    input.command,
  );
  if (lineage.status !== 'ready') {
    return stopped(lineage.status);
  }
  const ingestion = await loadTargetIngestion(
    tx,
    input.organizationId,
    input.command,
    lineage.creationIngestionId,
    asset[0]?.current_id ?? null,
  );
  if (ingestion.status !== 'ready') {
    return stopped(ingestion.status);
  }
  await tx.$executeRaw`
    LOCK TABLE "product_match_evaluation_evidence" IN SHARE ROW EXCLUSIVE MODE
  `;
  const derived = await deriveObservation(tx, input.organizationId, input.command, ingestion.row);
  if (derived.status !== 'ready') {
    return stopped(derived.status);
  }
  if (input.fault !== 'skip_existing_lookup') {
    const existing = await classifyExisting(
      tx,
      input.organizationId,
      input.command,
      derived.observation,
    );
    if (existing !== null) {
      return existing;
    }
  }
  return insertObservation(tx, input, ingestion.row.sbom_id, derived.observation);
}

async function insertObservation(
  tx: Prisma.TransactionClient,
  input: {
    readonly organizationId: string;
    readonly actorId: string;
    readonly membershipId: string;
    readonly command: CommandBinding;
    readonly fault: ControlledFindingRepeatedObservationFault | undefined;
  },
  sbomId: string,
  derived: DerivedObservation,
): Promise<FindingRepeatedObservationTransactionResult> {
  throwFault(input.fault, 'before_observation_insert');
  const replayFingerprint =
    input.fault === 'store_disagreeing_replay_fingerprint'
      ? disagreeingFingerprint(derived.replayFingerprint)
      : derived.replayFingerprint;
  const contradictAggregate =
    input.fault === 'store_contradictory_aggregate' && derived.aggregate === 'affected';
  const persistedAggregate = contradictAggregate ? 'unaffected' : derived.aggregate;
  const persistedResult = contradictAggregate ? 'absent' : derived.mappedResult;
  const absenceGraph = derived.absence?.graphCompleteness ?? null;
  const absenceComponents = derived.absence?.componentCount ?? null;
  const absenceEdges = derived.absence?.dependencyEdgeCount ?? null;
  const inserted = await tx.$queryRaw<Array<{ id: string }>>`
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
      "evidence_link_count",
      "absence_graph_completeness",
      "absence_component_count",
      "absence_dependency_edge_count"
    )
    VALUES (
      ${input.organizationId}::uuid,
      ${input.command.findingId}::uuid,
      ${sbomId}::uuid,
      ${input.command.sbomIngestionId}::uuid,
      NULL,
      ${persistedResult}::"finding_observation_result",
      ${REPEATED_METHOD},
      CURRENT_TIMESTAMP,
      jsonb_build_object(
        'schemaVersion', 'finding_repeated_observation_v1',
        'purpose', ${FINDING_REPEATED_OBSERVATION_PURPOSE},
        'policyId', ${FINDING_REPEATED_OBSERVATION_POLICY_ID},
        'policyVersion', ${FINDING_REPEATED_OBSERVATION_POLICY_VERSION}::int,
        'aggregate', ${persistedAggregate}::"finding_repeated_observation_aggregate",
        'mappedResult', ${persistedResult}::"finding_observation_result",
        'evidenceLinkCount', ${derived.supportCount}::int,
        'replayFingerprint', ${replayFingerprint}
      ),
      CURRENT_TIMESTAMP,
      ${REPEATED_TRANSITION},
      ${input.membershipId}::uuid,
      ${input.command.correlationId}::uuid,
      ${replayFingerprint},
      ${FINDING_REPEATED_OBSERVATION_PURPOSE},
      ${FINDING_REPEATED_OBSERVATION_POLICY_ID},
      ${FINDING_REPEATED_OBSERVATION_POLICY_VERSION}::int,
      ${persistedAggregate}::"finding_repeated_observation_aggregate",
      ${derived.supportCount}::int,
      ${absenceGraph}::"sbom_graph_completeness",
      ${absenceComponents}::int,
      ${absenceEdges}::int
    )
    RETURNING "id"::text AS id
  `;
  const observationId = inserted[0]?.id;
  if (observationId === undefined) {
    throw new ObservationFault('before_support_link_insert');
  }
  if (input.fault !== 'omit_support_links') {
    throwFault(input.fault, 'before_support_link_insert');
    for (const link of derived.links) {
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
          ${input.organizationId}::uuid,
          ${input.command.findingId}::uuid,
          ${observationId}::uuid,
          ${sbomId}::uuid,
          ${link.evidenceId}::uuid,
          ${input.command.assetId}::uuid,
          ${input.command.componentId}::uuid,
          ${input.command.vulnerabilityId}::uuid,
          ${input.command.sbomIngestionId}::uuid,
          ${link.occurrenceId}::uuid,
          ${link.supportKind},
          ${link.outcome}::"match_evaluation_outcome",
          CURRENT_TIMESTAMP
        )
      `;
    }
  }
  throwFault(input.fault, 'before_finding_timestamp_update');
  const updated = await tx.$executeRaw`
    UPDATE "finding"
    SET "last_observed_at" = (
          SELECT "observed_at"
          FROM "finding_observation"
          WHERE "organization_id" = ${input.organizationId}::uuid
            AND "id" = ${observationId}::uuid
        ),
        "updated_at" = (
          SELECT "observed_at"
          FROM "finding_observation"
          WHERE "organization_id" = ${input.organizationId}::uuid
            AND "id" = ${observationId}::uuid
        )
    WHERE "organization_id" = ${input.organizationId}::uuid
      AND "id" = ${input.command.findingId}::uuid
  `;
  if (updated !== 1) {
    throw new ObservationFault('before_audit_insert');
  }
  throwFault(input.fault, 'before_audit_insert');
  const supportClassification =
    persistedAggregate === 'component_absent' ? 'component_absence' : 'evidence_set';
  await tx.$executeRaw`
    INSERT INTO "audit_event" (
      "organization_id",
      "actor_user_id",
      "actor_membership_id",
      "actor_type",
      "action",
      "subject_type",
      "subject_id",
      "correlation_id",
      "payload",
      "schema_version"
    )
    VALUES (
      ${input.organizationId}::uuid,
      ${input.actorId}::uuid,
      ${input.membershipId}::uuid,
      'user',
      'finding.observed',
      'finding',
      ${input.command.findingId}::uuid,
      ${input.command.correlationId},
      jsonb_build_object(
        'schemaVersion', 1,
        'metadata', jsonb_build_object(
          'purpose', ${FINDING_REPEATED_OBSERVATION_PURPOSE},
          'policyId', ${FINDING_REPEATED_OBSERVATION_POLICY_ID},
          'policyVersion', ${FINDING_REPEATED_OBSERVATION_POLICY_VERSION}::int,
          'aggregate', ${persistedAggregate}::"finding_repeated_observation_aggregate",
          'sbomIngestionId', ${input.command.sbomIngestionId}::uuid,
          'evidenceLinkCount', ${derived.supportCount}::int,
          'supportClassification', ${supportClassification}
        )
      ),
      1
    )
  `;
  throwFault(input.fault, 'before_return');
  return {
    ...repeatedObservationTenantDisclosure(),
    schemaVersion: FINDING_REPEATED_OBSERVATION_TRANSACTION_SCHEMA_VERSION,
    status: 'observed',
    findingId: input.command.findingId,
    sbomIngestionId: input.command.sbomIngestionId,
    aggregate: derived.aggregate,
    mappedResult: derived.mappedResult,
    findingState: 'open',
    observationInserted: true,
    evidenceLinkedOrAbsenceRecorded: true,
    findingTimestampUpdated: true,
    auditEventAdded: true,
  };
}

async function validateCreationLineage(
  tx: Prisma.TransactionClient,
  organizationId: string,
  findingId: string,
  command: CommandBinding,
): Promise<
  | { readonly status: 'ready'; readonly creationIngestionId: string }
  | { readonly status: 'malformed_persisted_state' }
> {
  const observations = await tx.$queryRaw<
    Array<{
      id: string;
      sbom_ingestion_id: string;
      method: string;
      result: string;
      occurrence_id: string | null;
      transition_classification: string | null;
      affected_evidence_count: number | null;
    }>
  >`
    SELECT "id"::text AS id,
           "sbom_ingestion_id"::text AS sbom_ingestion_id,
           "method",
           "result"::text AS result,
           "occurrence_id"::text AS occurrence_id,
           "transition_classification",
           "affected_evidence_count"
    FROM "finding_observation"
    WHERE "organization_id" = ${organizationId}::uuid
      AND "finding_id" = ${findingId}::uuid
      AND "method" = ${CREATION_METHOD}
  `;
  const creation = observations.length === 1 ? observations[0] : undefined;
  if (
    creation === undefined ||
    creation.result !== 'present' ||
    creation.occurrence_id !== null ||
    creation.transition_classification !== 'initial_creation' ||
    creation.affected_evidence_count === null ||
    creation.affected_evidence_count < 1
  ) {
    return { status: 'malformed_persisted_state' };
  }
  const links = await tx.$queryRaw<Array<{ count: number }>>`
    SELECT COUNT(*)::int AS count
    FROM "finding_creation_evidence_link"
    WHERE "organization_id" = ${organizationId}::uuid
      AND "finding_observation_id" = ${creation.id}::uuid
  `;
  if (links[0]?.count !== creation.affected_evidence_count) {
    return { status: 'malformed_persisted_state' };
  }
  const ingestion = await tx.$queryRaw<Array<{ id: string }>>`
    SELECT "id"::text AS id
    FROM "sbom_ingestion"
    WHERE "organization_id" = ${organizationId}::uuid
      AND "id" = ${creation.sbom_ingestion_id}::uuid
      AND "asset_id" = ${command.assetId}::uuid
      AND "state" = 'completed'
      AND "normalization_version" = ${NORMALIZATION_VERSION}
  `;
  if (ingestion.length !== 1) {
    return { status: 'malformed_persisted_state' };
  }
  return { status: 'ready', creationIngestionId: creation.sbom_ingestion_id };
}

type IngestionRow = {
  sbom_id: string;
  state: string;
  normalization_version: string;
  graph_completeness: string | null;
  component_count: number | null;
  dependency_edge_count: number | null;
  strictly_later: boolean;
  live_components: number;
  live_edges: number;
  target_component_occurrences: number;
};

async function loadTargetIngestion(
  tx: Prisma.TransactionClient,
  organizationId: string,
  command: CommandBinding,
  creationIngestionId: string,
  latestIngestionId: string | null,
): Promise<
  | { readonly status: 'ready'; readonly row: IngestionRow }
  | {
      readonly status:
        | 'not_found'
        | 'ingestion_not_completed'
        | 'unsupported_normalization_version'
        | 'ingestion_not_latest'
        | 'ingestion_not_later'
        | 'malformed_persisted_state';
    }
> {
  const rows = await tx.$queryRaw<IngestionRow[]>`
    SELECT target."sbom_id"::text AS sbom_id,
           target."state"::text AS state,
           target."normalization_version",
           target."graph_completeness"::text AS graph_completeness,
           target."component_count",
           target."dependency_edge_count",
           (
             (target_sbom."received_at", target."created_at", target."id")
             > (creation_sbom."received_at", creation."created_at", creation."id")
           ) AS strictly_later,
           (
             SELECT COUNT(*)::int
             FROM "component_occurrence" AS occurrence
             WHERE occurrence."organization_id" = target."organization_id"
               AND occurrence."sbom_ingestion_id" = target."id"
           ) AS live_components,
           (
             SELECT COUNT(*)::int
             FROM "dependency_relationship" AS edge
             WHERE edge."organization_id" = target."organization_id"
               AND edge."sbom_ingestion_id" = target."id"
           ) AS live_edges,
           (
             SELECT COUNT(*)::int
             FROM "component_occurrence" AS occurrence
             WHERE occurrence."organization_id" = target."organization_id"
               AND occurrence."asset_id" = target."asset_id"
               AND occurrence."component_id" = ${command.componentId}::uuid
               AND occurrence."sbom_ingestion_id" = target."id"
           ) AS target_component_occurrences
    FROM "sbom_ingestion" AS target
    INNER JOIN "sbom" AS target_sbom
      ON target_sbom."organization_id" = target."organization_id"
     AND target_sbom."id" = target."sbom_id"
    INNER JOIN "sbom_ingestion" AS creation
      ON creation."organization_id" = target."organization_id"
     AND creation."id" = ${creationIngestionId}::uuid
    INNER JOIN "sbom" AS creation_sbom
      ON creation_sbom."organization_id" = creation."organization_id"
     AND creation_sbom."id" = creation."sbom_id"
    WHERE target."organization_id" = ${organizationId}::uuid
      AND target."id" = ${command.sbomIngestionId}::uuid
      AND target."asset_id" = ${command.assetId}::uuid
  `;
  const row = rows[0];
  if (row === undefined) {
    return { status: 'not_found' };
  }
  if (row.state !== 'completed') {
    return { status: 'ingestion_not_completed' };
  }
  if (row.normalization_version !== NORMALIZATION_VERSION) {
    return { status: 'unsupported_normalization_version' };
  }
  if (latestIngestionId !== command.sbomIngestionId) {
    return { status: 'ingestion_not_latest' };
  }
  if (row.strictly_later !== true || command.sbomIngestionId === creationIngestionId) {
    return { status: 'ingestion_not_later' };
  }
  if (
    row.component_count === null ||
    row.dependency_edge_count === null ||
    row.graph_completeness === null
  ) {
    return { status: 'malformed_persisted_state' };
  }
  return { status: 'ready', row };
}

async function deriveObservation(
  tx: Prisma.TransactionClient,
  organizationId: string,
  command: CommandBinding,
  ingestion: IngestionRow,
): Promise<
  | { readonly status: 'ready'; readonly observation: DerivedObservation }
  | {
      readonly status:
        | 'evidence_unavailable'
        | 'evidence_set_oversized'
        | 'evidence_set_mismatch'
        | 'malformed_persisted_state';
    }
> {
  const occurrences = await tx.$queryRaw<OccurrenceRow[]>`
    SELECT "id"::text AS id, "version_known"
    FROM "component_occurrence"
    WHERE "organization_id" = ${organizationId}::uuid
      AND "asset_id" = ${command.assetId}::uuid
      AND "component_id" = ${command.componentId}::uuid
      AND "sbom_ingestion_id" = ${command.sbomIngestionId}::uuid
    ORDER BY "id"::text COLLATE "C"
  `;
  if (occurrences.some((row) => row.version_known === null)) {
    return { status: 'malformed_persisted_state' };
  }
  if (occurrences.length === 0) {
    return deriveAbsence(organizationId, command, ingestion);
  }
  if (command.kind === 'component_absence') {
    return { status: 'evidence_unavailable' };
  }
  if (occurrences.length > MAX_SUPPORT) {
    return { status: 'evidence_set_oversized' };
  }
  const current = await tx.$queryRaw<CurrentEvidenceRow[]>`
    SELECT id::text AS id,
           component_occurrence_id::text AS component_occurrence_id,
           outcome::text AS outcome
    FROM patchpilot_finding_repeated_observation_current_evidence(
      ${organizationId}::uuid,
      ${command.assetId}::uuid,
      ${command.componentId}::uuid,
      ${command.vulnerabilityId}::uuid,
      ${command.sbomIngestionId}::uuid
    )
  `;
  const byOccurrence = new Map<string, CurrentEvidenceRow[]>();
  for (const row of current) {
    const list = byOccurrence.get(row.component_occurrence_id) ?? [];
    list.push(row);
    byOccurrence.set(row.component_occurrence_id, list);
  }
  const unknownIds = occurrences
    .filter((row) => row.version_known === false)
    .map((row) => row.id)
    .sort(compareUuid);
  if (unknownIds.length > 0) {
    const unexpected = await tx.$queryRaw<Array<{ count: number }>>`
      SELECT COUNT(*)::int AS count
      FROM "product_match_evaluation_evidence"
      WHERE "organization_id" = ${organizationId}::uuid
        AND "component_occurrence_id" IN (${Prisma.join(unknownIds.map((id) => Prisma.sql`${id}::uuid`))})
    `;
    if ((unexpected[0]?.count ?? 0) > 0) {
      return { status: 'malformed_persisted_state' };
    }
  }
  const links: SupportLink[] = [];
  let affected = false;
  let unknown = false;
  for (const occurrence of occurrences) {
    if (occurrence.version_known === false) {
      unknown = true;
      links.push({
        occurrenceId: occurrence.id,
        evidenceId: null,
        outcome: null,
        supportKind: 'unknown_version_occurrence',
      });
      continue;
    }
    const rows = byOccurrence.get(occurrence.id) ?? [];
    if (rows.length !== 1) {
      return { status: 'evidence_unavailable' };
    }
    const row = rows[0];
    if (row === undefined) {
      return { status: 'evidence_unavailable' };
    }
    if (row.outcome === 'affected') {
      affected = true;
    } else if (row.outcome === 'unknown') {
      unknown = true;
    } else if (row.outcome !== 'unaffected') {
      return { status: 'malformed_persisted_state' };
    }
    links.push({
      occurrenceId: occurrence.id,
      evidenceId: row.id,
      outcome: row.outcome,
      supportKind: 'product_match_evidence',
    });
  }
  const aggregate: FindingRepeatedObservationAggregate = affected
    ? 'affected'
    : unknown
      ? 'unknown'
      : 'unaffected';
  const evidenceIds = links
    .map((link) => link.evidenceId)
    .filter((id): id is string => id !== null)
    .sort(compareUuid);
  const unknownVersionOccurrenceIds = unknownIds;
  if (
    !sameIds(evidenceIds, command.evidenceIds) ||
    !sameIds(unknownVersionOccurrenceIds, command.unknownVersionOccurrenceIds) ||
    evidenceIds.length + unknownVersionOccurrenceIds.length !== command.supportCount
  ) {
    return { status: 'evidence_set_mismatch' };
  }
  const supportFingerprint = canonicalRepeatedObservationEvidenceFingerprint(
    evidenceIds,
    unknownVersionOccurrenceIds,
    command.supportCount,
  );
  const mappedResult = mapRepeatedObservationAggregate(aggregate);
  const replayFingerprint = canonicalRepeatedObservationReplayFingerprint({
    organizationId,
    findingId: command.findingId,
    assetId: command.assetId,
    componentId: command.componentId,
    vulnerabilityId: command.vulnerabilityId,
    sbomIngestionId: command.sbomIngestionId,
    aggregate,
    mappedResult,
    supportFingerprint,
    supportCount: command.supportCount,
  });
  return {
    status: 'ready',
    observation: {
      aggregate,
      mappedResult,
      links,
      evidenceIds,
      unknownVersionOccurrenceIds,
      supportFingerprint,
      replayFingerprint,
      supportCount: command.supportCount,
      absence: null,
    },
  };
}

function deriveAbsence(
  organizationId: string,
  command: CommandBinding,
  ingestion: IngestionRow,
):
  | { readonly status: 'ready'; readonly observation: DerivedObservation }
  | { readonly status: 'evidence_unavailable' | 'evidence_set_mismatch' } {
  const graph = ingestion.graph_completeness;
  const componentCount = ingestion.component_count;
  const edgeCount = ingestion.dependency_edge_count;
  if (graph !== 'complete' && graph !== 'no_dependencies') {
    return { status: 'evidence_unavailable' };
  }
  if (
    componentCount === null ||
    edgeCount === null ||
    componentCount < 1 ||
    componentCount !== ingestion.live_components ||
    edgeCount !== ingestion.live_edges ||
    ingestion.target_component_occurrences !== 0 ||
    (graph === 'complete' && edgeCount < 1) ||
    (graph === 'no_dependencies' && edgeCount !== 0)
  ) {
    return { status: 'evidence_unavailable' };
  }
  if (command.kind !== 'component_absence') {
    return { status: 'evidence_set_mismatch' };
  }
  if (
    command.graphCompleteness !== graph ||
    command.componentCount !== componentCount ||
    command.occurrenceCardinality !== ingestion.live_components ||
    command.dependencyEdgeCount !== edgeCount
  ) {
    return { status: 'evidence_set_mismatch' };
  }
  const supportFingerprint = canonicalRepeatedObservationAbsenceFingerprint({
    sbomIngestionId: command.sbomIngestionId,
    graphCompleteness: graph,
    componentCount,
    occurrenceCardinality: ingestion.live_components,
    dependencyEdgeCount: edgeCount,
  });
  const replayFingerprint = canonicalRepeatedObservationReplayFingerprint({
    organizationId,
    findingId: command.findingId,
    assetId: command.assetId,
    componentId: command.componentId,
    vulnerabilityId: command.vulnerabilityId,
    sbomIngestionId: command.sbomIngestionId,
    aggregate: 'component_absent',
    mappedResult: 'absent',
    supportFingerprint,
    supportCount: 0,
  });
  return {
    status: 'ready',
    observation: {
      aggregate: 'component_absent',
      mappedResult: 'absent',
      links: [],
      evidenceIds: [],
      unknownVersionOccurrenceIds: [],
      supportFingerprint,
      replayFingerprint,
      supportCount: 0,
      absence: {
        graphCompleteness: graph,
        componentCount,
        dependencyEdgeCount: edgeCount,
      },
    },
  };
}

async function classifyExisting(
  tx: Prisma.TransactionClient,
  organizationId: string,
  command: CommandBinding,
  derived: DerivedObservation,
): Promise<FindingRepeatedObservationTransactionResult | null> {
  const rows = await tx.$queryRaw<StoredObservation[]>`
    SELECT "id"::text AS id,
           "sbom_id"::text AS sbom_id,
           "result"::text AS result,
           "method",
           "occurrence_id"::text AS occurrence_id,
           "transition_classification",
           "creation_purpose",
           "creation_policy_id",
           "creation_policy_version",
           "observation_purpose",
           "observation_policy_id",
           "observation_policy_version",
           "aggregate_classification"::text AS aggregate_classification,
           "evidence_link_count",
           "replay_fingerprint",
           "absence_graph_completeness"::text AS absence_graph_completeness,
           "absence_component_count",
           "absence_dependency_edge_count"
    FROM "finding_observation"
    WHERE "organization_id" = ${organizationId}::uuid
      AND "finding_id" = ${command.findingId}::uuid
      AND "sbom_ingestion_id" = ${command.sbomIngestionId}::uuid
  `;
  const stored = rows[0];
  if (stored === undefined) {
    return null;
  }
  if (rows.length !== 1) {
    return stopped('malformed_persisted_state');
  }
  const links = await tx.$queryRaw<StoredLink[]>`
    SELECT "component_occurrence_id"::text AS component_occurrence_id,
           "product_match_evaluation_evidence_id"::text AS product_match_evaluation_evidence_id,
           "support_kind",
           "outcome"::text AS outcome
    FROM "finding_repeated_observation_evidence_link"
    WHERE "organization_id" = ${organizationId}::uuid
      AND "finding_observation_id" = ${stored.id}::uuid
    ORDER BY "component_occurrence_id"::text COLLATE "C"
  `;
  const shape = classifyInspectionObservationShape({
    method: stored.method,
    result: stored.result,
    occurrenceId: stored.occurrence_id,
    transitionClassification: stored.transition_classification,
    creationPurpose: stored.creation_purpose,
    creationPolicyId: stored.creation_policy_id,
    creationPolicyVersion: stored.creation_policy_version,
    observationPurpose: stored.observation_purpose,
    observationPolicyId: stored.observation_policy_id,
    observationPolicyVersion: stored.observation_policy_version,
    aggregate: stored.aggregate_classification,
  });
  const storedEvidenceIds = links
    .map((link) => link.product_match_evaluation_evidence_id)
    .filter((id): id is string => id !== null)
    .sort(compareUuid);
  const storedUnknownIds = links
    .filter((link) => link.support_kind === 'unknown_version_occurrence')
    .map((link) => link.component_occurrence_id)
    .sort(compareUuid);
  const storedFingerprint = (stored.replay_fingerprint ?? '').trim();
  const recomputedSupportFingerprint = supportFingerprintForStored(
    command.sbomIngestionId,
    stored,
    storedEvidenceIds,
    storedUnknownIds,
  );
  const linksAgree =
    derived.aggregate === 'component_absent'
      ? links.length === 0 &&
        stored.absence_graph_completeness === derived.absence?.graphCompleteness &&
        stored.absence_component_count === derived.absence?.componentCount &&
        stored.absence_dependency_edge_count === derived.absence?.dependencyEdgeCount
      : sameIds(storedEvidenceIds, derived.evidenceIds) &&
        sameIds(storedUnknownIds, derived.unknownVersionOccurrenceIds) &&
        stored.absence_graph_completeness === null;
  const comparison = classifyFindingRepeatedObservationReplay({
    schemaVersion: 'finding_repeated_observation_replay_comparison_v1',
    observationPresent: true,
    naturalIdentityAgrees: true,
    purposeAgrees: stored.observation_purpose === FINDING_REPEATED_OBSERVATION_PURPOSE,
    policyAgrees:
      stored.observation_policy_id === FINDING_REPEATED_OBSERVATION_POLICY_ID &&
      stored.observation_policy_version === FINDING_REPEATED_OBSERVATION_POLICY_VERSION,
    aggregateAgrees: stored.aggregate_classification === derived.aggregate,
    mappedResultAgrees: stored.result === derived.mappedResult,
    supportFingerprintAgrees:
      recomputedSupportFingerprint !== null &&
      recomputedSupportFingerprint === derived.supportFingerprint,
    evidenceLinkSetAgrees: linksAgree && stored.evidence_link_count === derived.supportCount,
    unknownVersionProofSetAgrees: sameIds(storedUnknownIds, derived.unknownVersionOccurrenceIds),
    absenceProofAgrees:
      derived.absence === null
        ? stored.absence_graph_completeness === null
        : stored.absence_graph_completeness === derived.absence.graphCompleteness &&
          stored.absence_component_count === derived.absence.componentCount &&
          stored.absence_dependency_edge_count === derived.absence.dependencyEdgeCount,
    ingestionAgrees: true,
    findingTargetAgrees: true,
    replayFingerprintAgrees: storedFingerprint === derived.replayFingerprint,
    persistedStateWellFormed: shape.role === 'later_observation' && storedFingerprint.length === 64,
    uniquenessViolation: false,
    semanticComparisonComplete: true,
  });
  if (comparison.classification === 'already_applied') {
    return {
      ...repeatedObservationTenantDisclosure(),
      schemaVersion: FINDING_REPEATED_OBSERVATION_TRANSACTION_SCHEMA_VERSION,
      status: 'already_applied',
      findingId: command.findingId,
      sbomIngestionId: command.sbomIngestionId,
      aggregate: derived.aggregate,
      mappedResult: derived.mappedResult,
      findingState: 'open',
      observationInserted: false,
      evidenceLinkedOrAbsenceRecorded: false,
      findingTimestampUpdated: false,
      auditEventAdded: false,
    };
  }
  if (
    comparison.outcome === 'immutable_conflict' ||
    comparison.outcome === 'malformed_persisted_state'
  ) {
    return stopped(comparison.outcome);
  }
  return stopped('malformed_persisted_state');
}

async function reloadAfterConflict(
  client: PrismaClient,
  input: {
    readonly organizationId: string;
    readonly actorId: string;
    readonly membershipId: string;
    readonly command: CommandBinding;
    readonly fault: ControlledFindingRepeatedObservationFault | undefined;
  },
): Promise<FindingRepeatedObservationTransactionResult> {
  try {
    return await client.$transaction((tx) =>
      applyInTransaction(tx, {
        organizationId: input.organizationId,
        actorId: input.actorId,
        membershipId: input.membershipId,
        command: input.command,
        fault: undefined,
      }),
    );
  } catch {
    return stopped('concurrency_conflict');
  }
}

function readCommand(value: unknown): CommandBinding | null {
  if (typeof value !== 'object' || value === null) {
    return null;
  }
  const record = value as Record<string, unknown>;
  const findingId = record['expectedFindingId'];
  const assetId = record['expectedAssetId'];
  const componentId = record['expectedComponentId'];
  const vulnerabilityId = record['expectedVulnerabilityId'];
  const sbomIngestionId = record['expectedSbomIngestionId'];
  const correlationId = record['correlationId'];
  if (
    typeof findingId !== 'string' ||
    typeof assetId !== 'string' ||
    typeof componentId !== 'string' ||
    typeof vulnerabilityId !== 'string' ||
    typeof sbomIngestionId !== 'string' ||
    typeof correlationId !== 'string'
  ) {
    return null;
  }
  if (record['supportKind'] === 'evidence_set') {
    const evidenceIds = record['expectedProductMatchEvidenceIds'];
    const unknownVersionOccurrenceIds = record['expectedUnknownVersionOccurrenceIds'];
    const supportCount = record['expectedSupportCount'];
    if (
      !isStringList(evidenceIds) ||
      !isStringList(unknownVersionOccurrenceIds) ||
      typeof supportCount !== 'number'
    ) {
      return null;
    }
    return {
      kind: 'evidence_set',
      findingId,
      assetId,
      componentId,
      vulnerabilityId,
      sbomIngestionId,
      correlationId,
      evidenceIds,
      unknownVersionOccurrenceIds,
      supportCount,
    };
  }
  if (record['supportKind'] === 'component_absence') {
    const graphCompleteness = record['expectedGraphCompleteness'];
    if (graphCompleteness !== 'complete' && graphCompleteness !== 'no_dependencies') {
      return null;
    }
    const componentCount = record['expectedComponentCount'];
    const occurrenceCardinality = record['expectedOccurrenceCardinality'];
    const dependencyEdgeCount = record['expectedDependencyEdgeCount'];
    if (
      typeof componentCount !== 'number' ||
      typeof occurrenceCardinality !== 'number' ||
      typeof dependencyEdgeCount !== 'number' ||
      record['expectedFindingComponentOccurrenceCount'] !== 0 ||
      record['expectedNormalizationVersion'] !== 2
    ) {
      return null;
    }
    return {
      kind: 'component_absence',
      findingId,
      assetId,
      componentId,
      vulnerabilityId,
      sbomIngestionId,
      correlationId,
      graphCompleteness,
      componentCount,
      occurrenceCardinality,
      dependencyEdgeCount,
    };
  }
  return null;
}

function isStringList(value: unknown): value is readonly string[] {
  return Array.isArray(value) && value.every((item) => typeof item === 'string');
}

function supportFingerprintForStored(
  sbomIngestionId: string,
  stored: StoredObservation,
  evidenceIds: readonly string[],
  unknownIds: readonly string[],
): string | null {
  if (stored.aggregate_classification === 'component_absent') {
    if (
      (stored.absence_graph_completeness !== 'complete' &&
        stored.absence_graph_completeness !== 'no_dependencies') ||
      stored.absence_component_count === null ||
      stored.absence_dependency_edge_count === null
    ) {
      return null;
    }
    return canonicalRepeatedObservationAbsenceFingerprint({
      sbomIngestionId,
      graphCompleteness: stored.absence_graph_completeness,
      componentCount: stored.absence_component_count,
      occurrenceCardinality: stored.absence_component_count,
      dependencyEdgeCount: stored.absence_dependency_edge_count,
    });
  }
  return canonicalRepeatedObservationEvidenceFingerprint(
    evidenceIds,
    unknownIds,
    evidenceIds.length + unknownIds.length,
  );
}

function sameIds(left: readonly string[], right: readonly string[]): boolean {
  if (left.length !== right.length) {
    return false;
  }
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) {
      return false;
    }
  }
  return true;
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

function disagreeingFingerprint(fingerprint: string): string {
  const first = fingerprint.startsWith('0') ? '1' : '0';
  return `${first}${fingerprint.slice(1)}`;
}

function throwFault(
  fault: ControlledFindingRepeatedObservationFault | undefined,
  stage: ControlledFindingRepeatedObservationFault,
): void {
  if (fault === stage) {
    throw new ObservationFault(stage);
  }
}

function stopped(
  status: Exclude<
    FindingRepeatedObservationTransactionResult['status'],
    'observed' | 'already_applied'
  >,
): FindingRepeatedObservationTransactionResult {
  return {
    ...repeatedObservationTenantDisclosure(),
    schemaVersion: FINDING_REPEATED_OBSERVATION_TRANSACTION_SCHEMA_VERSION,
    status,
    observationInserted: false,
    evidenceLinkedOrAbsenceRecorded: false,
    findingTimestampUpdated: false,
    auditEventAdded: false,
  };
}

function isUniqueViolation(error: unknown): boolean {
  if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') {
    return true;
  }
  return sqlState(error) === '23505';
}

function isConstraintFailure(error: unknown): boolean {
  const state = sqlState(error);
  if (state === '23514' || state === '23503' || state === '42501' || state === '23001') {
    return true;
  }
  const message = error instanceof Error ? error.message : '';
  return (
    message.includes('finding repeated observation is incomplete') ||
    message.includes('finding repeated observation audit is incomplete')
  );
}

function isDatabaseUnavailable(error: unknown): boolean {
  return (
    error instanceof Prisma.PrismaClientInitializationError ||
    error instanceof Prisma.PrismaClientRustPanicError
  );
}

function sqlState(error: unknown): string | null {
  if (error instanceof Prisma.PrismaClientKnownRequestError) {
    const metaCode = error.meta?.['code'];
    return typeof metaCode === 'string' ? metaCode : null;
  }
  if (error instanceof Prisma.PrismaClientUnknownRequestError) {
    const match = /code: "([0-9A-Z]{5})"/.exec(error.message);
    return match?.[1] ?? null;
  }
  if (typeof error !== 'object' || error === null) {
    return null;
  }
  const code = (error as { code?: unknown }).code;
  if (typeof code === 'string' && code.length === 5) {
    return code;
  }
  return null;
}
