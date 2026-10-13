/**
 * Internal read of one Controlled Finding aggregate for latest-observation selection.
 * One Repeatable Read, read-only transaction loads the creation observation and every
 * repeated candidate, then calls the committed selector. The bounded projection is
 * the only application-facing result. This module is not a package barrel export,
 * not an API route, and not production inspection.
 * PostgreSQL default Read Committed can combine rows from different commits.
 * Repeatable Read takes one snapshot at the first statement, so a repeated-observation
 * commit is either wholly absent or wholly visible. The transaction sets
 * transaction_read_only and does not insert, update, or delete.
 */

import { Prisma, type PrismaClient } from '@prisma/client';
import { classifyInspectionObservationShape } from '@patchpilot/domain';
import {
  FINDING_LATEST_OBSERVATION_EXTERNAL_SCHEMA_VERSION,
  FINDING_LATEST_OBSERVATION_EXTERNAL_UNAVAILABLE,
  FINDING_LATEST_OBSERVATION_SELECTION_SCHEMA_VERSION,
  mapFindingLatestObservationInspectionResult,
  selectFindingLatestObservation,
  type FindingLatestObservationExternalResult,
  type FindingLatestObservationSelectionResult,
} from '../../domain/dist/findings/controlled-inspection/latest-observation-selection.js';

import { isRootPrismaClient } from './guards.js';

const UUID_LOWER_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

const DIAGNOSTICS = [
  'found',
  'not_found',
  'malformed_persisted_state',
  'evidence_unavailable',
  'unsupported_envelope',
  'integrity_failure',
  'database_unavailable',
  'internal_failure',
] as const;

export type ControlledFindingLatestObservationReadDiagnostic = (typeof DIAGNOSTICS)[number];

export type ControlledFindingLatestObservationReadQuery = {
  readonly organizationId: string;
  readonly findingId: string;
};

/**
 * `safe` is the confidential result. `diagnostic` stays inside this adapter for
 * tests and must not be copied onto an HTTP response.
 */
export type ControlledFindingLatestObservationReadOutcome = {
  readonly safe: FindingLatestObservationExternalResult;
  readonly diagnostic: ControlledFindingLatestObservationReadDiagnostic;
};

type FindingRow = {
  finding_id: string;
  organization_id: string;
  asset_id: string;
  component_id: string;
  vulnerability_id: string;
  state: string;
  version: number | bigint;
  component_occurrence_id: string | null;
  resolved_at: string | null;
  reopened_at: string | null;
  assigned_membership_id: string | null;
  assigned_team_id: string | null;
  due_at: string | null;
  current_risk_calculation_id: string | null;
  first_observed_at: string | null;
  last_observed_at: string | null;
  created_at: string | null;
  updated_at: string | null;
  asset_current_ingestion_id: string | null;
  remediation_task_count: number | bigint;
  risk_acceptance_count: number | bigint;
  risk_calculation_count: number | bigint;
  generic_evidence_count: number | bigint;
};

type ObservationRow = {
  observation_id: string;
  organization_id: string;
  finding_id: string;
  sbom_id: string;
  sbom_ingestion_id: string;
  occurrence_id: string | null;
  result: string;
  method: string;
  observed_at: string | null;
  created_at: string | null;
  transition_classification: string | null;
  creation_purpose: string | null;
  creation_policy_id: string | null;
  creation_policy_version: number | bigint | null;
  actor_membership_id: string | null;
  correlation_id: string | null;
  replay_fingerprint: string | null;
  affected_evidence_count: number | bigint | null;
  observation_purpose: string | null;
  observation_policy_id: string | null;
  observation_policy_version: number | bigint | null;
  aggregate_classification: string | null;
  evidence_link_count: number | bigint | null;
  absence_graph_completeness: string | null;
  absence_component_count: number | bigint | null;
  absence_dependency_edge_count: number | bigint | null;
  evidence: unknown;
};

type CreationLinkRow = {
  organization_id: string;
  finding_id: string;
  finding_observation_id: string;
  evidence_id: string;
  asset_id: string;
  component_id: string;
  vulnerability_id: string;
  sbom_ingestion_id: string;
  occurrence_id: string;
  outcome: string;
};

type RepeatedLinkRow = {
  organization_id: string;
  finding_id: string;
  finding_observation_id: string;
  sbom_id: string;
  evidence_id: string | null;
  asset_id: string;
  component_id: string;
  vulnerability_id: string;
  sbom_ingestion_id: string;
  occurrence_id: string;
  support_kind: string;
  outcome: string | null;
};

type EvidenceFactRow = {
  evidence_id: string;
  organization_id: string;
  outcome: string;
  asset_id: string;
  component_id: string;
  vulnerability_id: string;
  sbom_ingestion_id: string;
  component_occurrence_id: string;
  product_origin: string;
  evaluator_id: string;
  evaluator_version: string;
  matching_policy_id: string;
  matching_policy_version: string;
  product_evidence_policy_id: string;
  product_evidence_policy_version: number | bigint;
  evidence_schema_version: string;
  finding_creation: string;
  suppression_authority: boolean;
  raw_observed_version: string;
  revision_id: string | null;
  revision_origin: string | null;
  withdrawal: string | null;
  quarantine: string | null;
  has_successor: boolean | null;
  approval_row_id: string | null;
  approval_purpose: string | null;
  approval_revision_id: string | null;
  approval_vulnerability_id: string | null;
  binding_row_id: string | null;
  binding_vulnerability_id: string | null;
  binding_review_state: string | null;
  binding_conflict: string | null;
};

type IngestionRow = {
  ingestion_id: string;
  sbom_id: string | null;
  organization_id: string;
  asset_id: string;
  state: string;
  normalization_version: string;
  received_at: string | null;
  created_at: string | null;
  graph_completeness: string | null;
  component_count: number | bigint | null;
  dependency_edge_count: number | bigint | null;
};

type OccurrenceRow = {
  occurrence_id: string;
  organization_id: string;
  asset_id: string;
  component_id: string;
  sbom_ingestion_id: string;
  version: string;
  version_known: boolean;
};

type CountRow = {
  ingestion_id: string;
  live_count: number | bigint;
};

type IdRow = {
  id: string;
};

export function createControlledFindingLatestObservationRead(client: PrismaClient): {
  read(
    query: ControlledFindingLatestObservationReadQuery,
  ): Promise<ControlledFindingLatestObservationReadOutcome>;
} {
  if (!isRootPrismaClient(client)) {
    throw new Error('Latest-observation inspection read requires the root database client.');
  }
  return {
    async read(query) {
      return readControlledFindingLatestObservation(client, query);
    },
  };
}

export async function readControlledFindingLatestObservation(
  client: PrismaClient,
  query: ControlledFindingLatestObservationReadQuery,
): Promise<ControlledFindingLatestObservationReadOutcome> {
  if (!isUuid(query.organizationId) || !isUuid(query.findingId)) {
    return unavailable('internal_failure');
  }
  try {
    return await client.$transaction(
      async (tx) => loadControlledFindingLatestObservationSnapshot(tx, query),
      { isolationLevel: Prisma.TransactionIsolationLevel.RepeatableRead },
    );
  } catch (error) {
    return unavailable(translateFailure(error));
  }
}

export async function loadControlledFindingLatestObservationSnapshot(
  tx: Prisma.TransactionClient,
  query: ControlledFindingLatestObservationReadQuery,
): Promise<ControlledFindingLatestObservationReadOutcome> {
  if (!isUuid(query.organizationId) || !isUuid(query.findingId)) {
    return unavailable('internal_failure');
  }
  await tx.$queryRaw`SELECT set_config('transaction_read_only', 'on', true)`;
  const findings = await tx.$queryRaw<FindingRow[]>`
    SELECT lower(finding."id"::text) AS finding_id,
           lower(finding."organization_id"::text) AS organization_id,
           lower(finding."asset_id"::text) AS asset_id,
           lower(finding."component_id"::text) AS component_id,
           lower(finding."vulnerability_id"::text) AS vulnerability_id,
           finding."state"::text AS state,
           finding."version" AS version,
           lower(finding."component_occurrence_id"::text) AS component_occurrence_id,
           ${canonicalTimestamp(Prisma.sql`finding."resolved_at"`)} AS resolved_at,
           ${canonicalTimestamp(Prisma.sql`finding."reopened_at"`)} AS reopened_at,
           lower(finding."assigned_membership_id"::text) AS assigned_membership_id,
           lower(finding."assigned_team_id"::text) AS assigned_team_id,
           ${canonicalTimestamp(Prisma.sql`finding."due_at"`)} AS due_at,
           lower(finding."current_risk_calculation_id"::text) AS current_risk_calculation_id,
           ${canonicalTimestamp(Prisma.sql`finding."first_observed_at"`)} AS first_observed_at,
           ${canonicalTimestamp(Prisma.sql`finding."last_observed_at"`)} AS last_observed_at,
           ${canonicalTimestamp(Prisma.sql`finding."created_at"`)} AS created_at,
           ${canonicalTimestamp(Prisma.sql`finding."updated_at"`)} AS updated_at,
           lower(asset."last_successful_sbom_ingestion_id"::text) AS asset_current_ingestion_id,
           (
             SELECT COUNT(*)::int
             FROM "remediation_task" AS remediation
             WHERE remediation."organization_id" = finding."organization_id"
               AND remediation."finding_id" = finding."id"
           ) AS remediation_task_count,
           (
             SELECT COUNT(*)::int
             FROM "risk_acceptance" AS acceptance
             WHERE acceptance."organization_id" = finding."organization_id"
               AND acceptance."finding_id" = finding."id"
           ) AS risk_acceptance_count,
           (
             SELECT COUNT(*)::int
             FROM "risk_calculation" AS calculation
             WHERE calculation."organization_id" = finding."organization_id"
               AND calculation."finding_id" = finding."id"
           ) AS risk_calculation_count,
           (
             SELECT COUNT(*)::int
             FROM "evidence" AS generic_evidence
             WHERE generic_evidence."organization_id" = finding."organization_id"
               AND generic_evidence."finding_id" = finding."id"
           ) AS generic_evidence_count
    FROM "finding" AS finding
    LEFT JOIN "asset" AS asset
      ON asset."organization_id" = finding."organization_id"
     AND asset."id" = finding."asset_id"
    WHERE finding."organization_id" = ${query.organizationId}::uuid
      AND finding."id" = ${query.findingId}::uuid
  `;
  if (findings.length === 0) {
    return notFound();
  }
  const finding = findings[0];
  if (finding === undefined || findings.length !== 1) {
    return unavailable('malformed_persisted_state');
  }
  const observations = await tx.$queryRaw<ObservationRow[]>`
    SELECT lower(observation."id"::text) AS observation_id,
           lower(observation."organization_id"::text) AS organization_id,
           lower(observation."finding_id"::text) AS finding_id,
           lower(observation."sbom_id"::text) AS sbom_id,
           lower(observation."sbom_ingestion_id"::text) AS sbom_ingestion_id,
           lower(observation."occurrence_id"::text) AS occurrence_id,
           observation."result"::text AS result,
           observation."method" AS method,
           ${canonicalTimestamp(Prisma.sql`observation."observed_at"`)} AS observed_at,
           ${canonicalTimestamp(Prisma.sql`observation."created_at"`)} AS created_at,
           observation."transition_classification" AS transition_classification,
           observation."creation_purpose" AS creation_purpose,
           observation."creation_policy_id" AS creation_policy_id,
           observation."creation_policy_version" AS creation_policy_version,
           lower(observation."actor_membership_id"::text) AS actor_membership_id,
           lower(observation."correlation_id"::text) AS correlation_id,
           btrim(observation."replay_fingerprint") AS replay_fingerprint,
           observation."affected_evidence_count" AS affected_evidence_count,
           observation."observation_purpose" AS observation_purpose,
           observation."observation_policy_id" AS observation_policy_id,
           observation."observation_policy_version" AS observation_policy_version,
           observation."aggregate_classification"::text AS aggregate_classification,
           observation."evidence_link_count" AS evidence_link_count,
           observation."absence_graph_completeness"::text AS absence_graph_completeness,
           observation."absence_component_count" AS absence_component_count,
           observation."absence_dependency_edge_count" AS absence_dependency_edge_count,
           observation."evidence" AS evidence
    FROM "finding_observation" AS observation
    WHERE observation."organization_id" = ${query.organizationId}::uuid
      AND observation."finding_id" = ${query.findingId}::uuid
  `;
  const creationRows = [];
  const repeatedRows = [];
  for (const row of observations) {
    const role = classifyInspectionObservationShape({
      method: row.method,
      result: row.result,
      occurrenceId: row.occurrence_id,
      transitionClassification: row.transition_classification,
      creationPurpose: row.creation_purpose,
      creationPolicyId: row.creation_policy_id,
      creationPolicyVersion: sqlNumber(row.creation_policy_version),
      observationPurpose: row.observation_purpose,
      observationPolicyId: row.observation_policy_id,
      observationPolicyVersion: sqlNumber(row.observation_policy_version),
      aggregate: row.aggregate_classification,
    }).role;
    if (role === 'creation_observation') {
      creationRows.push(row);
    } else {
      repeatedRows.push(row);
    }
  }
  if (creationRows.length !== 1) {
    return unavailable('malformed_persisted_state');
  }
  const creation = creationRows[0];
  if (creation === undefined) {
    return unavailable('malformed_persisted_state');
  }
  const [creationLinks, repeatedLinks] = await Promise.all([
    tx.$queryRaw<CreationLinkRow[]>`
      SELECT lower(link."organization_id"::text) AS organization_id,
             lower(link."finding_id"::text) AS finding_id,
             lower(link."finding_observation_id"::text) AS finding_observation_id,
             lower(link."product_match_evaluation_evidence_id"::text) AS evidence_id,
             lower(link."asset_id"::text) AS asset_id,
             lower(link."component_id"::text) AS component_id,
             lower(link."vulnerability_id"::text) AS vulnerability_id,
             lower(link."sbom_ingestion_id"::text) AS sbom_ingestion_id,
             lower(link."component_occurrence_id"::text) AS occurrence_id,
             link."outcome"::text AS outcome
      FROM "finding_creation_evidence_link" AS link
      WHERE link."organization_id" = ${query.organizationId}::uuid
        AND link."finding_id" = ${query.findingId}::uuid
    `,
    tx.$queryRaw<RepeatedLinkRow[]>`
      SELECT lower(link."organization_id"::text) AS organization_id,
             lower(link."finding_id"::text) AS finding_id,
             lower(link."finding_observation_id"::text) AS finding_observation_id,
             lower(link."sbom_id"::text) AS sbom_id,
             lower(link."product_match_evaluation_evidence_id"::text) AS evidence_id,
             lower(link."asset_id"::text) AS asset_id,
             lower(link."component_id"::text) AS component_id,
             lower(link."vulnerability_id"::text) AS vulnerability_id,
             lower(link."sbom_ingestion_id"::text) AS sbom_ingestion_id,
             lower(link."component_occurrence_id"::text) AS occurrence_id,
             link."support_kind" AS support_kind,
             link."outcome"::text AS outcome
      FROM "finding_repeated_observation_evidence_link" AS link
      WHERE link."organization_id" = ${query.organizationId}::uuid
        AND link."finding_id" = ${query.findingId}::uuid
    `,
  ]);
  const repeatedIds = new Set(repeatedRows.map((row) => row.observation_id));
  for (const link of repeatedLinks) {
    if (!repeatedIds.has(link.finding_observation_id)) {
      return unavailable('malformed_persisted_state');
    }
  }
  const evidenceIds = uniqueIds([
    ...creationLinks.map((link) => link.evidence_id),
    ...repeatedLinks.flatMap((link) => (link.evidence_id === null ? [] : [link.evidence_id])),
  ]);
  const ingestionIds = uniqueIds([
    creation.sbom_ingestion_id,
    ...repeatedRows.map((row) => row.sbom_ingestion_id),
    ...creationLinks.map((link) => link.sbom_ingestion_id),
    ...repeatedLinks.map((link) => link.sbom_ingestion_id),
  ]);
  const occurrenceIds = uniqueIds([
    ...creationLinks.map((link) => link.occurrence_id),
    ...repeatedLinks.map((link) => link.occurrence_id),
  ]);
  const unknownOccurrenceIds = uniqueIds(
    repeatedLinks
      .filter((link) => link.support_kind === 'unknown_version_occurrence')
      .map((link) => link.occurrence_id),
  );
  const membershipIds = uniqueIds(
    repeatedRows.flatMap((row) =>
      row.actor_membership_id === null ? [] : [row.actor_membership_id],
    ),
  );
  const [evidenceRows, ingestions, occurrences, componentCounts, edgeCounts, memberships, stray] =
    await Promise.all([
      evidenceIds.length === 0
        ? Promise.resolve([] as EvidenceFactRow[])
        : tx.$queryRaw<EvidenceFactRow[]>`
            SELECT lower(evidence."id"::text) AS evidence_id,
                   lower(evidence."organization_id"::text) AS organization_id,
                   evidence."outcome"::text AS outcome,
                   lower(evidence."asset_id"::text) AS asset_id,
                   lower(evidence."component_id"::text) AS component_id,
                   lower(evidence."vulnerability_id"::text) AS vulnerability_id,
                   lower(evidence."sbom_ingestion_id"::text) AS sbom_ingestion_id,
                   lower(evidence."component_occurrence_id"::text) AS component_occurrence_id,
                   evidence."product_origin" AS product_origin,
                   evidence."evaluator_id" AS evaluator_id,
                   evidence."evaluator_version" AS evaluator_version,
                   evidence."matching_policy_id" AS matching_policy_id,
                   evidence."matching_policy_version" AS matching_policy_version,
                   evidence."product_evidence_policy_id" AS product_evidence_policy_id,
                   evidence."product_evidence_policy_version" AS product_evidence_policy_version,
                   evidence."evidence_schema_version" AS evidence_schema_version,
                   evidence."finding_creation" AS finding_creation,
                   evidence."suppression_authority" AS suppression_authority,
                   evidence."raw_observed_version" AS raw_observed_version,
                   lower(revision."id"::text) AS revision_id,
                   revision."origin"::text AS revision_origin,
                   revision."withdrawal_classification"::text AS withdrawal,
                   revision."quarantine_classification"::text AS quarantine,
                   EXISTS (
                     SELECT 1
                     FROM "advisory_revision" AS successor
                     WHERE successor."supersedes_advisory_revision_id" = revision."id"
                   ) AS has_successor,
                   lower(approval."id"::text) AS approval_row_id,
                   approval."approval_purpose" AS approval_purpose,
                   lower(approval."advisory_revision_id"::text) AS approval_revision_id,
                   lower(approval."vulnerability_id"::text) AS approval_vulnerability_id,
                   lower(binding."id"::text) AS binding_row_id,
                   lower(binding."vulnerability_id"::text) AS binding_vulnerability_id,
                   binding."mapping_review_state" AS binding_review_state,
                   binding."conflict_classification" AS binding_conflict
            FROM "product_match_evaluation_evidence" AS evidence
            LEFT JOIN "advisory_revision" AS revision
              ON revision."id" = evidence."advisory_revision_id"
            LEFT JOIN "maintainer_reviewed_advisory_approval" AS approval
              ON approval."id" = evidence."approval_id"
            LEFT JOIN "advisory_vulnerability_binding" AS binding
              ON binding."advisory_revision_id" = revision."id"
            WHERE evidence."organization_id" = ${query.organizationId}::uuid
              AND evidence."id" IN (${uuidList(evidenceIds)})
          `,
      ingestionIds.length === 0
        ? Promise.resolve([] as IngestionRow[])
        : tx.$queryRaw<IngestionRow[]>`
            SELECT lower(ingestion."id"::text) AS ingestion_id,
                   lower(ingestion."sbom_id"::text) AS sbom_id,
                   lower(ingestion."organization_id"::text) AS organization_id,
                   lower(ingestion."asset_id"::text) AS asset_id,
                   ingestion."state"::text AS state,
                   ingestion."normalization_version" AS normalization_version,
                   ${canonicalTimestamp(Prisma.sql`sbom."received_at"`)} AS received_at,
                   ${canonicalTimestamp(Prisma.sql`ingestion."created_at"`)} AS created_at,
                   ingestion."graph_completeness"::text AS graph_completeness,
                   ingestion."component_count" AS component_count,
                   ingestion."dependency_edge_count" AS dependency_edge_count
            FROM "sbom_ingestion" AS ingestion
            LEFT JOIN "sbom" AS sbom
              ON sbom."organization_id" = ingestion."organization_id"
             AND sbom."id" = ingestion."sbom_id"
            WHERE ingestion."organization_id" = ${query.organizationId}::uuid
              AND ingestion."id" IN (${uuidList(ingestionIds)})
          `,
      occurrenceIds.length === 0 && ingestionIds.length === 0
        ? Promise.resolve([] as OccurrenceRow[])
        : tx.$queryRaw<OccurrenceRow[]>`
            SELECT lower(occurrence."id"::text) AS occurrence_id,
                   lower(occurrence."organization_id"::text) AS organization_id,
                   lower(occurrence."asset_id"::text) AS asset_id,
                   lower(occurrence."component_id"::text) AS component_id,
                   lower(occurrence."sbom_ingestion_id"::text) AS sbom_ingestion_id,
                   occurrence."version" AS version,
                   occurrence."version_known" AS version_known
            FROM "component_occurrence" AS occurrence
            WHERE occurrence."organization_id" = ${query.organizationId}::uuid
              AND (
                (
                  occurrence."asset_id" = ${finding.asset_id}::uuid
                  AND occurrence."component_id" = ${finding.component_id}::uuid
                  AND occurrence."sbom_ingestion_id" IN (${uuidList(ingestionIds)})
                )
                ${
                  occurrenceIds.length === 0
                    ? Prisma.empty
                    : Prisma.sql`OR occurrence."id" IN (${uuidList(occurrenceIds)})`
                }
              )
          `,
      ingestionIds.length === 0
        ? Promise.resolve([] as CountRow[])
        : tx.$queryRaw<CountRow[]>`
            SELECT lower(occurrence."sbom_ingestion_id"::text) AS ingestion_id,
                   COUNT(*)::int AS live_count
            FROM "component_occurrence" AS occurrence
            WHERE occurrence."organization_id" = ${query.organizationId}::uuid
              AND occurrence."sbom_ingestion_id" IN (${uuidList(ingestionIds)})
            GROUP BY occurrence."sbom_ingestion_id"
          `,
      ingestionIds.length === 0
        ? Promise.resolve([] as CountRow[])
        : tx.$queryRaw<CountRow[]>`
            SELECT lower(edge."sbom_ingestion_id"::text) AS ingestion_id,
                   COUNT(*)::int AS live_count
            FROM "dependency_relationship" AS edge
            WHERE edge."organization_id" = ${query.organizationId}::uuid
              AND edge."sbom_ingestion_id" IN (${uuidList(ingestionIds)})
            GROUP BY edge."sbom_ingestion_id"
          `,
      membershipIds.length === 0
        ? Promise.resolve([] as IdRow[])
        : tx.$queryRaw<IdRow[]>`
            SELECT lower(membership."id"::text) AS id
            FROM "membership" AS membership
            WHERE membership."organization_id" = ${query.organizationId}::uuid
              AND membership."id" IN (${uuidList(membershipIds)})
          `,
      unknownOccurrenceIds.length === 0
        ? Promise.resolve([] as IdRow[])
        : tx.$queryRaw<IdRow[]>`
            SELECT lower(evidence."component_occurrence_id"::text) AS id
            FROM "product_match_evaluation_evidence" AS evidence
            WHERE evidence."organization_id" = ${query.organizationId}::uuid
              AND evidence."component_occurrence_id" IN (${uuidList(unknownOccurrenceIds)})
          `,
    ]);
  if (new Set(evidenceRows.map((row) => row.evidence_id)).size !== evidenceRows.length) {
    return unavailable('malformed_persisted_state');
  }
  const evidenceById = new Map(evidenceRows.map((row) => [row.evidence_id, row]));
  const ingestionById = new Map(ingestions.map((row) => [row.ingestion_id, row]));
  const occurrenceById = new Map(occurrences.map((row) => [row.occurrence_id, row]));
  const componentCountByIngestion = countMap(componentCounts);
  const edgeCountByIngestion = countMap(edgeCounts);
  const membershipPresent = new Set(memberships.map((row) => row.id));
  const strayOccurrences = new Set(stray.map((row) => row.id));
  const creationOccurrences = occurrences.filter(
    (row) =>
      row.asset_id === finding.asset_id &&
      row.component_id === finding.component_id &&
      row.sbom_ingestion_id === creation.sbom_ingestion_id,
  );
  const linkedCreationIds = new Set(creationLinks.map((link) => link.occurrence_id));
  const linkedInCreationIngestion = creationOccurrences.filter((row) =>
    linkedCreationIds.has(row.occurrence_id),
  ).length;
  const input = {
    schemaVersion: FINDING_LATEST_OBSERVATION_SELECTION_SCHEMA_VERSION,
    authorizedOrganizationId: query.organizationId,
    requestedFindingId: query.findingId,
    finding: {
      organizationId: finding.organization_id,
      findingId: finding.finding_id,
      assetId: finding.asset_id,
      componentId: finding.component_id,
      vulnerabilityId: finding.vulnerability_id,
      state: finding.state,
      version: sqlNumber(finding.version),
      componentOccurrenceId: finding.component_occurrence_id,
      resolvedAt: finding.resolved_at,
      reopenedAt: finding.reopened_at,
      assignedMembershipId: finding.assigned_membership_id,
      assignedTeamId: finding.assigned_team_id,
      dueAt: finding.due_at,
      currentRiskCalculationId: finding.current_risk_calculation_id,
      firstObservedAt: finding.first_observed_at,
      lastObservedAt: finding.last_observed_at,
      createdAt: finding.created_at,
      updatedAt: finding.updated_at,
      assetCurrentIngestionId: finding.asset_current_ingestion_id,
      remediationTaskCount: sqlNumber(finding.remediation_task_count),
      riskAcceptanceCount: sqlNumber(finding.risk_acceptance_count),
      riskCalculationCount: sqlNumber(finding.risk_calculation_count),
      genericEvidenceCount: sqlNumber(finding.generic_evidence_count),
    },
    creation: {
      observationId: creation.observation_id,
      organizationId: creation.organization_id,
      findingId: creation.finding_id,
      sbomId: creation.sbom_id,
      sbomIngestionId: creation.sbom_ingestion_id,
      observedAt: creation.observed_at,
      createdAt: creation.created_at,
      method: creation.method,
      result: creation.result,
      occurrenceId: creation.occurrence_id,
      transitionClassification: creation.transition_classification,
      creationPurpose: creation.creation_purpose,
      creationPolicyId: creation.creation_policy_id,
      creationPolicyVersion: sqlNumber(creation.creation_policy_version),
      observationPurpose: creation.observation_purpose,
      observationPolicyId: creation.observation_policy_id,
      observationPolicyVersion: sqlNumber(creation.observation_policy_version),
      aggregate: creation.aggregate_classification,
      affectedEvidenceCount: sqlNumber(creation.affected_evidence_count),
      evidence: cloneJson(creation.evidence),
      replayFingerprint: creation.replay_fingerprint,
      otherOccurrenceCount: creationOccurrences.length - linkedInCreationIngestion,
      creationIngestionOccurrenceCount: creationOccurrences.length,
      ingestion: creationIngestion(ingestionById.get(creation.sbom_ingestion_id) ?? null),
      links: creationLinks.map((link) =>
        creationLink(
          link,
          evidenceById.get(link.evidence_id),
          occurrenceById.get(link.occurrence_id),
        ),
      ),
    },
    repeated: repeatedRows.map((row) =>
      repeatedCandidate(
        row,
        finding,
        repeatedLinks.filter((link) => link.finding_observation_id === row.observation_id),
        evidenceById,
        occurrenceById,
        occurrences,
        ingestionById.get(row.sbom_ingestion_id) ?? null,
        componentCountByIngestion.get(row.sbom_ingestion_id) ?? 0,
        edgeCountByIngestion.get(row.sbom_ingestion_id) ?? 0,
        membershipPresent.has(row.actor_membership_id ?? ''),
        strayOccurrences,
      ),
    ),
  };
  const selected = selectFindingLatestObservation(input);
  return {
    safe: mapFindingLatestObservationInspectionResult(selected),
    diagnostic: diagnosticFromSelector(selected),
  };
}

function creationIngestion(row: IngestionRow | null): Record<string, unknown> {
  if (row === null) {
    return {
      id: null,
      sbomId: null,
      organizationId: null,
      assetId: null,
      state: null,
      normalizationVersion: null,
      receivedAt: null,
      createdAt: null,
    };
  }
  return {
    id: row.ingestion_id,
    sbomId: row.sbom_id,
    organizationId: row.organization_id,
    assetId: row.asset_id,
    state: row.state,
    normalizationVersion: row.normalization_version,
    receivedAt: row.received_at,
    createdAt: row.created_at,
  };
}

function creationLink(
  link: CreationLinkRow,
  evidence: EvidenceFactRow | undefined,
  occurrence: OccurrenceRow | undefined,
): Record<string, unknown> {
  const facts = evidenceFacts(evidence);
  return {
    organizationId: link.organization_id,
    findingId: link.finding_id,
    findingObservationId: link.finding_observation_id,
    evidenceId: link.evidence_id,
    evidenceOrganizationId: evidence?.organization_id ?? null,
    assetId: link.asset_id,
    componentId: link.component_id,
    vulnerabilityId: link.vulnerability_id,
    sbomIngestionId: link.sbom_ingestion_id,
    occurrenceId: link.occurrence_id,
    outcome: link.outcome,
    evidencePresent: evidence !== undefined && evidence.organization_id === link.organization_id,
    occurrencePresent:
      occurrence !== undefined && occurrence.organization_id === link.organization_id,
    occurrenceVersion: occurrenceVersion(occurrence),
    occurrenceVersionKnown: occurrence?.version_known ?? null,
    evidenceAligned: evidenceAligned(link, evidence),
    evidenceOutcome: evidence?.outcome ?? null,
    productOrigin: evidence?.product_origin ?? null,
    evaluatorId: evidence?.evaluator_id ?? null,
    evaluatorVersion: evidence?.evaluator_version ?? null,
    matchingPolicyId: evidence?.matching_policy_id ?? null,
    matchingPolicyVersion: evidence?.matching_policy_version ?? null,
    productEvidencePolicyId: evidence?.product_evidence_policy_id ?? null,
    productEvidencePolicyVersion: sqlNumber(evidence?.product_evidence_policy_version ?? null),
    evidenceSchemaVersion: evidence?.evidence_schema_version ?? null,
    findingCreation: evidence?.finding_creation ?? null,
    suppressionAuthority: evidence?.suppression_authority ?? null,
    evidenceRawObservedVersion: evidence?.raw_observed_version ?? null,
    occurrenceAssetId: occurrence?.asset_id ?? null,
    occurrenceComponentId: occurrence?.component_id ?? null,
    occurrenceIngestionId: occurrence?.sbom_ingestion_id ?? null,
    withdrawal: facts.withdrawal,
    quarantine: facts.quarantine,
    hasSuccessor: facts.hasSuccessor,
    revisionOrigin: facts.revisionOrigin,
    approvalPresent: facts.approvalPresent,
    approvalPurpose: facts.approvalPurpose,
    approvalRevisionMatches: facts.approvalRevisionMatches,
    approvalVulnerabilityMatches: facts.approvalVulnerabilityMatches,
    bindingPresent: facts.bindingPresent,
    bindingReviewed: facts.bindingReviewed,
  };
}

function repeatedCandidate(
  row: ObservationRow,
  finding: FindingRow,
  links: readonly RepeatedLinkRow[],
  evidenceById: ReadonlyMap<string, EvidenceFactRow>,
  occurrenceById: ReadonlyMap<string, OccurrenceRow>,
  occurrences: readonly OccurrenceRow[],
  ingestion: IngestionRow | null,
  liveComponentCount: number,
  liveEdgeCount: number,
  memberPresent: boolean,
  strayOccurrences: ReadonlySet<string>,
): Record<string, unknown> {
  const unknownVersionOccurrenceHasEvidence = links.some(
    (link) =>
      link.support_kind === 'unknown_version_occurrence' &&
      strayOccurrences.has(link.occurrence_id),
  );
  return {
    observationId: row.observation_id,
    organizationId: row.organization_id,
    findingId: row.finding_id,
    sbomId: row.sbom_id,
    sbomIngestionId: row.sbom_ingestion_id,
    method: row.method,
    result: row.result,
    occurrenceId: row.occurrence_id,
    transitionClassification: row.transition_classification,
    creationPurpose: row.creation_purpose,
    creationPolicyId: row.creation_policy_id,
    creationPolicyVersion: sqlNumber(row.creation_policy_version),
    observationPurpose: row.observation_purpose,
    observationPolicyId: row.observation_policy_id,
    observationPolicyVersion: sqlNumber(row.observation_policy_version),
    aggregate: row.aggregate_classification,
    evidenceLinkCount: sqlNumber(row.evidence_link_count),
    replayFingerprint: row.replay_fingerprint,
    actorMembershipId: row.actor_membership_id,
    correlationId: row.correlation_id,
    observedAt: row.observed_at,
    createdAt: row.created_at,
    membershipPresent: memberPresent,
    absenceGraphCompleteness: row.absence_graph_completeness,
    absenceComponentCount: sqlNumber(row.absence_component_count),
    absenceDependencyEdgeCount: sqlNumber(row.absence_dependency_edge_count),
    evidence: cloneJson(row.evidence),
    unknownVersionOccurrenceHasEvidence,
    ingestion: repeatedIngestion(
      ingestion,
      finding,
      row.sbom_ingestion_id,
      occurrences,
      liveComponentCount,
      liveEdgeCount,
    ),
    supports: links.map((link) =>
      supportFact(
        link,
        evidenceById.get(link.evidence_id ?? ''),
        occurrenceById.get(link.occurrence_id),
      ),
    ),
  };
}

function repeatedIngestion(
  row: IngestionRow | null,
  finding: FindingRow,
  ingestionId: string,
  occurrences: readonly OccurrenceRow[],
  liveComponentCount: number,
  liveEdgeCount: number,
): Record<string, unknown> {
  const targetOccurrenceIds = occurrences
    .filter(
      (occurrence) =>
        occurrence.asset_id === finding.asset_id &&
        occurrence.component_id === finding.component_id &&
        occurrence.sbom_ingestion_id === ingestionId,
    )
    .map((occurrence) => occurrence.occurrence_id);
  if (row === null) {
    return {
      id: null,
      sbomId: null,
      organizationId: null,
      assetId: null,
      state: null,
      normalizationVersion: null,
      receivedAt: null,
      createdAt: null,
      graphCompleteness: null,
      componentCount: null,
      dependencyEdgeCount: null,
      liveComponentCount,
      liveEdgeCount,
      targetOccurrenceIds,
    };
  }
  return {
    id: row.ingestion_id,
    sbomId: row.sbom_id,
    organizationId: row.organization_id,
    assetId: row.asset_id,
    state: row.state,
    normalizationVersion: row.normalization_version,
    receivedAt: row.received_at,
    createdAt: row.created_at,
    graphCompleteness: row.graph_completeness,
    componentCount: sqlNumber(row.component_count),
    dependencyEdgeCount: sqlNumber(row.dependency_edge_count),
    liveComponentCount,
    liveEdgeCount,
    targetOccurrenceIds,
  };
}

function supportFact(
  link: RepeatedLinkRow,
  evidence: EvidenceFactRow | undefined,
  occurrence: OccurrenceRow | undefined,
): Record<string, unknown> {
  const unknown = link.support_kind === 'unknown_version_occurrence';
  const facts = unknown ? nullEvidenceFacts() : evidenceFacts(evidence);
  const storedEvidence = unknown ? undefined : evidence;
  return {
    organizationId: link.organization_id,
    findingId: link.finding_id,
    findingObservationId: link.finding_observation_id,
    assetId: link.asset_id,
    componentId: link.component_id,
    vulnerabilityId: link.vulnerability_id,
    sbomId: link.sbom_id,
    sbomIngestionId: link.sbom_ingestion_id,
    occurrenceId: link.occurrence_id,
    supportKind: link.support_kind,
    evidenceId: link.evidence_id,
    evidenceOrganizationId: unknown ? null : (storedEvidence?.organization_id ?? null),
    outcome: link.outcome,
    occurrenceVersionKnown: occurrence?.version_known ?? null,
    occurrenceAligned: occurrenceAligned(link, occurrence),
    evidencePresent: unknown
      ? false
      : storedEvidence !== undefined && storedEvidence.organization_id === link.organization_id,
    occurrencePresent:
      occurrence !== undefined && occurrence.organization_id === link.organization_id,
    occurrenceVersion: occurrenceVersion(occurrence),
    evidenceAligned: unknown ? false : evidenceAligned(link, storedEvidence),
    evidenceOutcome: unknown ? null : (storedEvidence?.outcome ?? null),
    productOrigin: unknown ? null : (storedEvidence?.product_origin ?? null),
    evaluatorId: unknown ? null : (storedEvidence?.evaluator_id ?? null),
    evaluatorVersion: unknown ? null : (storedEvidence?.evaluator_version ?? null),
    matchingPolicyId: unknown ? null : (storedEvidence?.matching_policy_id ?? null),
    matchingPolicyVersion: unknown ? null : (storedEvidence?.matching_policy_version ?? null),
    productEvidencePolicyId: unknown ? null : (storedEvidence?.product_evidence_policy_id ?? null),
    productEvidencePolicyVersion: unknown
      ? null
      : sqlNumber(storedEvidence?.product_evidence_policy_version ?? null),
    evidenceSchemaVersion: unknown ? null : (storedEvidence?.evidence_schema_version ?? null),
    findingCreation: unknown ? null : (storedEvidence?.finding_creation ?? null),
    suppressionAuthority: unknown ? null : (storedEvidence?.suppression_authority ?? null),
    evidenceRawObservedVersion: unknown ? null : (storedEvidence?.raw_observed_version ?? null),
    withdrawal: facts.withdrawal,
    quarantine: facts.quarantine,
    hasSuccessor: facts.hasSuccessor,
    revisionOrigin: facts.revisionOrigin,
    approvalPresent: facts.approvalPresent,
    approvalPurpose: facts.approvalPurpose,
    approvalRevisionMatches: facts.approvalRevisionMatches,
    approvalVulnerabilityMatches: facts.approvalVulnerabilityMatches,
    bindingPresent: facts.bindingPresent,
    bindingReviewed: facts.bindingReviewed,
  };
}

type EvidenceFacts = {
  readonly withdrawal: string | null;
  readonly quarantine: string | null;
  readonly hasSuccessor: boolean | null;
  readonly revisionOrigin: string | null;
  readonly approvalPresent: boolean | null;
  readonly approvalPurpose: string | null;
  readonly approvalRevisionMatches: boolean | null;
  readonly approvalVulnerabilityMatches: boolean | null;
  readonly bindingPresent: boolean | null;
  readonly bindingReviewed: boolean | null;
};

function nullEvidenceFacts(): EvidenceFacts {
  return {
    withdrawal: null,
    quarantine: null,
    hasSuccessor: null,
    revisionOrigin: null,
    approvalPresent: null,
    approvalPurpose: null,
    approvalRevisionMatches: null,
    approvalVulnerabilityMatches: null,
    bindingPresent: null,
    bindingReviewed: null,
  };
}

function evidenceFacts(evidence: EvidenceFactRow | undefined): EvidenceFacts {
  if (evidence === undefined || evidence.revision_id === null) {
    return nullEvidenceFacts();
  }
  const approvalPresent = evidence.approval_row_id !== null;
  const bindingPresent = evidence.binding_row_id !== null;
  return {
    withdrawal: evidence.withdrawal,
    quarantine: evidence.quarantine,
    hasSuccessor: evidence.has_successor,
    revisionOrigin: evidence.revision_origin,
    approvalPresent,
    approvalPurpose: approvalPresent ? evidence.approval_purpose : null,
    approvalRevisionMatches: approvalPresent
      ? evidence.approval_revision_id === evidence.revision_id
      : null,
    approvalVulnerabilityMatches: approvalPresent
      ? evidence.approval_vulnerability_id === evidence.vulnerability_id
      : null,
    bindingPresent,
    bindingReviewed: bindingPresent
      ? evidence.binding_review_state === 'reviewed' &&
        evidence.binding_conflict === 'none' &&
        evidence.binding_vulnerability_id === evidence.vulnerability_id
      : null,
  };
}

function evidenceAligned(
  link: {
    asset_id: string;
    component_id: string;
    vulnerability_id: string;
    sbom_ingestion_id: string;
    occurrence_id: string;
  },
  evidence: EvidenceFactRow | undefined,
): boolean {
  return (
    evidence !== undefined &&
    evidence.asset_id === link.asset_id &&
    evidence.component_id === link.component_id &&
    evidence.vulnerability_id === link.vulnerability_id &&
    evidence.sbom_ingestion_id === link.sbom_ingestion_id &&
    evidence.component_occurrence_id === link.occurrence_id
  );
}

function occurrenceAligned(
  link: {
    organization_id: string;
    asset_id: string;
    component_id: string;
    sbom_ingestion_id: string;
  },
  occurrence: OccurrenceRow | undefined,
): boolean {
  return (
    occurrence !== undefined &&
    occurrence.organization_id === link.organization_id &&
    occurrence.asset_id === link.asset_id &&
    occurrence.component_id === link.component_id &&
    occurrence.sbom_ingestion_id === link.sbom_ingestion_id
  );
}

function occurrenceVersion(occurrence: OccurrenceRow | undefined): string | null {
  if (occurrence === undefined) {
    return null;
  }
  if (occurrence.version_known === false && occurrence.version === '') {
    return null;
  }
  return occurrence.version;
}

function countMap(rows: readonly CountRow[]): Map<string, number> {
  const counts = new Map<string, number>();
  for (const row of rows) {
    const count = sqlNumber(row.live_count);
    counts.set(row.ingestion_id, typeof count === 'number' ? count : Number.NaN);
  }
  return counts;
}

function uniqueIds(ids: readonly string[]): string[] {
  return [...new Set(ids)];
}

function uuidList(ids: readonly string[]): Prisma.Sql {
  return Prisma.join(ids.map((id) => Prisma.sql`${id}::uuid`));
}

function canonicalTimestamp(column: Prisma.Sql): Prisma.Sql {
  return Prisma.sql`to_char(${column} AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')`;
}

function sqlNumber(value: number | bigint | null | undefined): number | string | null {
  if (value === null || value === undefined) {
    return null;
  }
  if (typeof value === 'bigint') {
    const converted = Number(value);
    return Number.isSafeInteger(converted) ? converted : value.toString();
  }
  return value;
}

function cloneJson(value: unknown): unknown {
  if (typeof value === 'string') {
    try {
      return JSON.parse(value) as unknown;
    } catch {
      return value;
    }
  }
  if (typeof value === 'object' && value !== null) {
    return JSON.parse(JSON.stringify(value)) as unknown;
  }
  return value;
}

function isReadDiagnostic(
  value: string,
): value is ControlledFindingLatestObservationReadDiagnostic {
  return (DIAGNOSTICS as readonly string[]).includes(value);
}

function diagnosticFromSelector(
  selected: FindingLatestObservationSelectionResult,
): ControlledFindingLatestObservationReadDiagnostic {
  return isReadDiagnostic(selected.status) ? selected.status : 'internal_failure';
}

function notFound(): ControlledFindingLatestObservationReadOutcome {
  return {
    safe: Object.freeze({
      schemaVersion: FINDING_LATEST_OBSERVATION_EXTERNAL_SCHEMA_VERSION,
      status: 'not_found',
    }),
    diagnostic: 'not_found',
  };
}

function unavailable(
  diagnostic: Exclude<ControlledFindingLatestObservationReadDiagnostic, 'found' | 'not_found'>,
): ControlledFindingLatestObservationReadOutcome {
  return {
    safe: Object.freeze({
      schemaVersion: FINDING_LATEST_OBSERVATION_EXTERNAL_SCHEMA_VERSION,
      status: FINDING_LATEST_OBSERVATION_EXTERNAL_UNAVAILABLE,
    }),
    diagnostic,
  };
}

function isUuid(value: string): boolean {
  return UUID_LOWER_PATTERN.test(value);
}

function translateFailure(error: unknown): 'database_unavailable' | 'internal_failure' {
  if (
    error instanceof Prisma.PrismaClientInitializationError ||
    error instanceof Prisma.PrismaClientRustPanicError
  ) {
    return 'database_unavailable';
  }
  if (error instanceof Prisma.PrismaClientKnownRequestError) {
    if (
      error.code === 'P1001' ||
      error.code === 'P1002' ||
      error.code === 'P1008' ||
      error.code === 'P1017' ||
      error.code === 'P2024'
    ) {
      return 'database_unavailable';
    }
  }
  return 'internal_failure';
}
