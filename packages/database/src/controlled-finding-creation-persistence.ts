/**
 * Production-uncomposed controlled Finding creation.
 * One transaction inserts one Finding, one creation observation, one evidence
 * link per qualifying row, and one audit event, or inserts none of them.
 * API, web, worker, seed, and the package barrel do not construct this adapter.
 */

import { createHash } from 'node:crypto';

import { Prisma, type PrismaClient } from '@prisma/client';
import {
  FINDING_CREATION_EVIDENCE_SET_SCHEMA_VERSION,
  FINDING_CREATION_POLICY_ID,
  FINDING_CREATION_POLICY_VERSION,
  FINDING_CREATION_PURPOSE,
  FINDING_CREATION_REPLAY_COMPARISON_SCHEMA_VERSION,
  FINDING_CREATION_TRANSACTION_SCHEMA_VERSION,
  classifyFindingCreationReplay,
  findingCreationOutcomeForReason,
  parseTrustedFindingCreationContext,
  presentFindingCreationAuthorization,
  type FindingCreationTransactionOutcome,
  type FindingCreationTransactionResult,
} from '@patchpilot/domain';

const CREATION_METHOD = 'controlled_finding_creation';
const CREATION_TRANSITION = 'initial_creation';
const ACCEPTED_EVALUATOR_ID = 'osv_first_ecosystem_affected_version_evaluator_v1';
const ACCEPTED_EVALUATOR_VERSION = 'session_14_batch_2_in_memory';
const ACCEPTED_MATCHING_POLICY_ID = 'osv_first_ecosystem_matching_architecture_v1';
const ACCEPTED_ORIGIN = 'maintainer_reviewed_advisory';
const ACCEPTED_APPROVAL_PURPOSE = 'approve_maintainer_reviewed_advisory_for_product_evaluation';
const ACCEPTED_EVIDENCE_SCHEMA = 'product_match_evaluation_evidence_v1';
const ACCEPTED_PRODUCT_POLICY_ID = 'product_match_evaluation_policy_v1';
const NORMALIZATION_VERSION = '2';

export const CONTROLLED_FINDING_CREATION_FAULTS = [
  'before_finding_insert',
  'before_observation_insert',
  'before_evidence_link_insert',
  'before_audit_insert',
  'skip_existing_lookup',
] as const;

export type ControlledFindingCreationFault = (typeof CONTROLLED_FINDING_CREATION_FAULTS)[number];

export type ControlledFindingCreationApplyInput = {
  readonly trustedContext: unknown;
  readonly command: unknown;
  readonly fault?: ControlledFindingCreationFault;
};

type EvidenceFailure = Exclude<
  FindingCreationTransactionOutcome,
  'created' | 'already_applied' | 'authority_rejected' | 'authority_required' | 'invalid_command'
>;

type EvidenceDetail = {
  id: string;
  asset_id: string;
  component_id: string;
  vulnerability_id: string;
  sbom_id: string;
  sbom_ingestion_id: string;
  component_occurrence_id: string;
  outcome: string;
  product_origin: string;
  finding_creation: string;
  suppression_authority: boolean;
  evaluator_id: string;
  evaluator_version: string;
  matching_policy_id: string;
  matching_policy_version: string;
  product_evidence_policy_id: string;
  product_evidence_policy_version: number;
  evidence_schema_version: string;
  normalization_version: string | null;
  ingestion_state: string | null;
  latest_ingestion_id: string | null;
  withdrawal: string | null;
  quarantine: string | null;
  has_successor: boolean;
  approval_purpose: string | null;
  approval_revision_matches: boolean;
  occurrence_aligned: boolean;
  version_known: boolean | null;
  binding_reviewed: boolean;
};

type StoredFinding = {
  id: string;
  state: string;
  component_occurrence_id: string | null;
  resolved_at: Date | null;
  reopened_at: Date | null;
  assigned_membership_id: string | null;
  assigned_team_id: string | null;
  due_at: Date | null;
  current_risk_calculation_id: string | null;
  version: number;
};

type StoredObservation = {
  id: string;
  sbom_id: string;
  sbom_ingestion_id: string;
  occurrence_id: string | null;
  result: string;
  method: string;
  transition_classification: string | null;
  creation_purpose: string | null;
  creation_policy_id: string | null;
  creation_policy_version: number | null;
  replay_fingerprint: string | null;
  affected_evidence_count: number | null;
};

type CommandBinding = {
  readonly assetId: string;
  readonly componentId: string;
  readonly vulnerabilityId: string;
  readonly sbomIngestionId: string;
  readonly evidenceIds: readonly string[];
  readonly fingerprint: string;
  readonly correlationId: string;
};

class CreationFault extends Error {
  constructor(readonly stage: ControlledFindingCreationFault) {
    super('controlled finding creation fault');
  }
}

export function createControlledFindingCreationPersistence(client: PrismaClient) {
  return {
    async apply(
      input: ControlledFindingCreationApplyInput,
    ): Promise<FindingCreationTransactionResult> {
      const trusted = parseTrustedFindingCreationContext(input.trustedContext);
      if (!trusted.ok) {
        const outcome = findingCreationOutcomeForReason(trusted.reason);
        return stopped(outcome === 'authorized' ? 'internal_failure' : outcome);
      }
      const presented = presentFindingCreationAuthorization({
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
      try {
        return await client.$transaction((tx) =>
          applyInTransaction(tx, {
            organizationId: trusted.context.organizationId,
            actorId: trusted.context.actorId,
            membershipId: trusted.context.membershipId,
            command,
            fault: input.fault,
          }),
        );
      } catch (error) {
        if (error instanceof CreationFault) {
          return stopped('transaction_aborted');
        }
        if (isUniqueViolation(error)) {
          return reloadAfterConflict(client, trusted.context.organizationId, command);
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
    readonly fault: ControlledFindingCreationFault | undefined;
  },
): Promise<FindingCreationTransactionResult> {
  await tx.$queryRaw`
    SELECT set_config('patchpilot.controlled_finding_creation', 'on', true) AS configured
  `;
  const locked = await tx.$queryRaw<Array<{ current_id: string | null }>>`
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
  const assetRow = asset[0];
  if (assetRow === undefined) {
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

  const existing = await tx.$queryRaw<StoredFinding[]>`
    SELECT
      "id"::text AS id,
      "state"::text AS state,
      "component_occurrence_id"::text AS component_occurrence_id,
      "resolved_at",
      "reopened_at",
      "assigned_membership_id"::text AS assigned_membership_id,
      "assigned_team_id"::text AS assigned_team_id,
      "due_at",
      "current_risk_calculation_id"::text AS current_risk_calculation_id,
      "version"
    FROM "finding"
    WHERE "organization_id" = ${input.organizationId}::uuid
      AND "asset_id" = ${input.command.assetId}::uuid
      AND "component_id" = ${input.command.componentId}::uuid
      AND "vulnerability_id" = ${input.command.vulnerabilityId}::uuid
    FOR UPDATE
  `;
  const storedFinding = existing[0];
  if (storedFinding !== undefined && input.fault !== 'skip_existing_lookup') {
    return classifyStored(tx, input.organizationId, input.command, storedFinding);
  }

  await tx.$executeRaw`
    LOCK TABLE "product_match_evaluation_evidence" IN SHARE ROW EXCLUSIVE MODE
  `;
  const evidence = await loadEvidence(tx, input.organizationId, input.command.evidenceIds);
  if (evidence === null) {
    return stopped('not_found');
  }
  const qualifying = await tx.$queryRaw<Array<{ id: string }>>`
    SELECT id::text AS id
    FROM patchpilot_finding_creation_qualifying_evidence(
      ${input.organizationId}::uuid,
      ${input.command.assetId}::uuid,
      ${input.command.componentId}::uuid,
      ${input.command.vulnerabilityId}::uuid,
      ${input.command.sbomIngestionId}::uuid
    )
  `;
  const qualifyingIds = qualifying.map((row) => row.id).sort(compareUuid);
  const failure = classifyRequestedEvidence(
    evidence,
    input.command,
    assetRow.current_id,
    qualifyingIds,
  );
  if (failure !== null) {
    return stopped(failure);
  }
  const sbomId = evidence[0]?.sbom_id;
  if (sbomId === undefined || evidence.some((row) => row.sbom_id !== sbomId)) {
    return stopped('malformed_persisted_state');
  }

  throwFault(input.fault, 'before_finding_insert');
  const inserted = await tx.$queryRaw<Array<{ id: string }>>`
    INSERT INTO "finding" (
      "organization_id",
      "asset_id",
      "vulnerability_id",
      "component_id",
      "state",
      "first_observed_at",
      "last_observed_at",
      "version",
      "created_at",
      "updated_at"
    )
    VALUES (
      ${input.organizationId}::uuid,
      ${input.command.assetId}::uuid,
      ${input.command.vulnerabilityId}::uuid,
      ${input.command.componentId}::uuid,
      'open',
      CURRENT_TIMESTAMP,
      CURRENT_TIMESTAMP,
      1,
      CURRENT_TIMESTAMP,
      CURRENT_TIMESTAMP
    )
    RETURNING "id"::text AS id
  `;
  const findingId = inserted[0]?.id;
  if (findingId === undefined) {
    throw new CreationFault('before_observation_insert');
  }

  throwFault(input.fault, 'before_observation_insert');
  const observation = await tx.$queryRaw<Array<{ id: string }>>`
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
    VALUES (
      ${input.organizationId}::uuid,
      ${findingId}::uuid,
      ${sbomId}::uuid,
      ${input.command.sbomIngestionId}::uuid,
      NULL,
      'present',
      ${CREATION_METHOD},
      CURRENT_TIMESTAMP,
      jsonb_build_object(
        'schemaVersion', 'finding_creation_observation_v1',
        'transition', ${CREATION_TRANSITION},
        'purpose', ${FINDING_CREATION_PURPOSE},
        'policyId', ${FINDING_CREATION_POLICY_ID},
        'policyVersion', ${FINDING_CREATION_POLICY_VERSION}::int,
        'affectedEvidenceCount', ${input.command.evidenceIds.length}::int,
        'evidenceSetFingerprint', ${input.command.fingerprint}
      ),
      CURRENT_TIMESTAMP,
      ${CREATION_TRANSITION},
      ${FINDING_CREATION_PURPOSE},
      ${FINDING_CREATION_POLICY_ID},
      ${FINDING_CREATION_POLICY_VERSION}::int,
      ${input.membershipId}::uuid,
      ${input.command.correlationId}::uuid,
      ${input.command.fingerprint},
      ${input.command.evidenceIds.length}::int
    )
    RETURNING "id"::text AS id
  `;
  const observationId = observation[0]?.id;
  if (observationId === undefined) {
    throw new CreationFault('before_evidence_link_insert');
  }

  throwFault(input.fault, 'before_evidence_link_insert');
  for (const row of evidence) {
    await tx.$executeRaw`
      INSERT INTO "finding_creation_evidence_link" (
        "organization_id",
        "finding_id",
        "finding_observation_id",
        "product_match_evaluation_evidence_id",
        "asset_id",
        "component_id",
        "vulnerability_id",
        "sbom_ingestion_id",
        "component_occurrence_id",
        "outcome",
        "created_at"
      )
      VALUES (
        ${input.organizationId}::uuid,
        ${findingId}::uuid,
        ${observationId}::uuid,
        ${row.id}::uuid,
        ${row.asset_id}::uuid,
        ${row.component_id}::uuid,
        ${row.vulnerability_id}::uuid,
        ${row.sbom_ingestion_id}::uuid,
        ${row.component_occurrence_id}::uuid,
        'affected',
        CURRENT_TIMESTAMP
      )
    `;
  }

  throwFault(input.fault, 'before_audit_insert');
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
      'finding.created',
      'finding',
      ${findingId}::uuid,
      ${input.command.correlationId},
      jsonb_build_object(
        'schemaVersion', 1,
        'metadata', jsonb_build_object(
          'purpose', ${FINDING_CREATION_PURPOSE},
          'policyId', ${FINDING_CREATION_POLICY_ID},
          'policyVersion', ${FINDING_CREATION_POLICY_VERSION}::int,
          'affectedEvidenceCount', ${input.command.evidenceIds.length}::int,
          'sbomIngestionId', ${input.command.sbomIngestionId}
        )
      ),
      1
    )
  `;

  const confirmed = await tx.$queryRaw<Array<{ links: number }>>`
    SELECT COUNT(*)::int AS links
    FROM "finding_creation_evidence_link"
    WHERE "organization_id" = ${input.organizationId}::uuid
      AND "finding_id" = ${findingId}::uuid
      AND "finding_observation_id" = ${observationId}::uuid
  `;
  if (confirmed[0]?.links !== input.command.evidenceIds.length) {
    throw new CreationFault('before_audit_insert');
  }
  return {
    schemaVersion: FINDING_CREATION_TRANSACTION_SCHEMA_VERSION,
    status: 'created',
    findingId,
    foreignResourceRevealed: false,
    tenantDisclosure: 'indistinguishable',
    authorityCreated: false,
    writesPerformed: true,
    observationAdded: true,
    auditEventAdded: true,
    timestampChanged: false,
  };
}

async function classifyStored(
  tx: Prisma.TransactionClient,
  organizationId: string,
  command: CommandBinding,
  finding: StoredFinding,
): Promise<FindingCreationTransactionResult> {
  const observations = await tx.$queryRaw<StoredObservation[]>`
    SELECT
      "id"::text AS id,
      "sbom_id"::text AS sbom_id,
      "sbom_ingestion_id"::text AS sbom_ingestion_id,
      "occurrence_id"::text AS occurrence_id,
      "result"::text AS result,
      "method",
      "transition_classification",
      "creation_purpose",
      "creation_policy_id",
      "creation_policy_version",
      "replay_fingerprint",
      "affected_evidence_count"
    FROM "finding_observation"
    WHERE "organization_id" = ${organizationId}::uuid
      AND "finding_id" = ${finding.id}::uuid
  `;
  const observation = observations.length === 1 ? observations[0] : undefined;
  const links =
    observation === undefined
      ? []
      : await tx.$queryRaw<Array<{ id: string }>>`
          SELECT "product_match_evaluation_evidence_id"::text AS id
          FROM "finding_creation_evidence_link"
          WHERE "organization_id" = ${organizationId}::uuid
            AND "finding_observation_id" = ${observation.id}::uuid
          ORDER BY "product_match_evaluation_evidence_id"::text COLLATE "C"
        `;
  const linkIds = links.map((row) => row.id).sort(compareUuid);
  const recomputed = creationEvidenceFingerprint(linkIds);
  const findingWellFormed =
    finding.state === 'open' &&
    finding.component_occurrence_id === null &&
    finding.resolved_at === null &&
    finding.reopened_at === null &&
    finding.assigned_membership_id === null &&
    finding.assigned_team_id === null &&
    finding.due_at === null &&
    finding.current_risk_calculation_id === null &&
    finding.version === 1;
  const observationPresent =
    observation !== undefined &&
    observation.method === CREATION_METHOD &&
    observation.result === 'present' &&
    observation.occurrence_id === null &&
    observation.transition_classification === CREATION_TRANSITION;
  const storedFingerprint = (observation?.replay_fingerprint ?? '').trim();
  const linksMatchStoredFingerprint =
    observationPresent &&
    storedFingerprint === recomputed &&
    observation?.affected_evidence_count === linkIds.length;
  const comparison = classifyFindingCreationReplay({
    schemaVersion: FINDING_CREATION_REPLAY_COMPARISON_SCHEMA_VERSION,
    findingPresent: true,
    creationObservationPresent: observationPresent,
    evidenceLinksComplete: linksMatchStoredFingerprint && sameIds(linkIds, command.evidenceIds),
    naturalIdentityAgrees: true,
    purposeAgrees: observation?.creation_purpose === FINDING_CREATION_PURPOSE,
    policyAgrees:
      observation?.creation_policy_id === FINDING_CREATION_POLICY_ID &&
      observation?.creation_policy_version === FINDING_CREATION_POLICY_VERSION,
    evidenceFingerprintAgrees: storedFingerprint === command.fingerprint,
    ingestionAgrees: observation?.sbom_ingestion_id === command.sbomIngestionId,
    linkSetAgrees: sameIds(linkIds, command.evidenceIds),
    persistedStateWellFormed:
      findingWellFormed &&
      observations.length <= 1 &&
      (observation === undefined || linksMatchStoredFingerprint || !observationPresent),
  });
  if (comparison.classification === 'already_applied') {
    return {
      schemaVersion: FINDING_CREATION_TRANSACTION_SCHEMA_VERSION,
      status: 'already_applied',
      findingId: finding.id,
      foreignResourceRevealed: false,
      tenantDisclosure: 'indistinguishable',
      authorityCreated: false,
      writesPerformed: false,
      observationAdded: false,
      auditEventAdded: false,
      timestampChanged: false,
    };
  }
  if (
    comparison.outcome === 'immutable_conflict' ||
    comparison.outcome === 'finding_already_exists' ||
    comparison.outcome === 'malformed_persisted_state'
  ) {
    return stopped(comparison.outcome);
  }
  return stopped('internal_failure');
}

async function reloadAfterConflict(
  client: PrismaClient,
  organizationId: string,
  command: CommandBinding,
): Promise<FindingCreationTransactionResult> {
  try {
    return await client.$transaction(async (tx) => {
      const existing = await tx.$queryRaw<StoredFinding[]>`
        SELECT
          "id"::text AS id,
          "state"::text AS state,
          "component_occurrence_id"::text AS component_occurrence_id,
          "resolved_at",
          "reopened_at",
          "assigned_membership_id"::text AS assigned_membership_id,
          "assigned_team_id"::text AS assigned_team_id,
          "due_at",
          "current_risk_calculation_id"::text AS current_risk_calculation_id,
          "version"
        FROM "finding"
        WHERE "organization_id" = ${organizationId}::uuid
          AND "asset_id" = ${command.assetId}::uuid
          AND "component_id" = ${command.componentId}::uuid
          AND "vulnerability_id" = ${command.vulnerabilityId}::uuid
      `;
      const finding = existing[0];
      if (finding === undefined) {
        return stopped('transaction_aborted');
      }
      return classifyStored(tx, organizationId, command, finding);
    });
  } catch {
    return stopped('transaction_aborted');
  }
}

async function loadEvidence(
  tx: Prisma.TransactionClient,
  organizationId: string,
  evidenceIds: readonly string[],
): Promise<EvidenceDetail[] | null> {
  const rows = await tx.$queryRaw<EvidenceDetail[]>`
    SELECT
      evidence."id"::text AS id,
      evidence."asset_id"::text AS asset_id,
      evidence."component_id"::text AS component_id,
      evidence."vulnerability_id"::text AS vulnerability_id,
      evidence."sbom_id"::text AS sbom_id,
      evidence."sbom_ingestion_id"::text AS sbom_ingestion_id,
      evidence."component_occurrence_id"::text AS component_occurrence_id,
      evidence."outcome"::text AS outcome,
      evidence."product_origin",
      evidence."finding_creation",
      evidence."suppression_authority",
      evidence."evaluator_id",
      evidence."evaluator_version",
      evidence."matching_policy_id",
      evidence."matching_policy_version",
      evidence."product_evidence_policy_id",
      evidence."product_evidence_policy_version",
      evidence."evidence_schema_version",
      ingestion."normalization_version",
      ingestion."state"::text AS ingestion_state,
      asset."last_successful_sbom_ingestion_id"::text AS latest_ingestion_id,
      revision."withdrawal_classification"::text AS withdrawal,
      revision."quarantine_classification"::text AS quarantine,
      EXISTS (
        SELECT 1
        FROM "advisory_revision" AS successor
        WHERE successor."supersedes_advisory_revision_id" = revision."id"
      ) AS has_successor,
      approval."approval_purpose",
      (approval."advisory_revision_id" = evidence."advisory_revision_id"
        AND approval."vulnerability_id" = evidence."vulnerability_id") AS approval_revision_matches,
      (
        occurrence."id" IS NOT NULL
        AND occurrence."asset_id" = evidence."asset_id"
        AND occurrence."component_id" = evidence."component_id"
        AND occurrence."sbom_ingestion_id" = evidence."sbom_ingestion_id"
      ) AS occurrence_aligned,
      occurrence."version_known",
      (
        binding."mapping_review_state" = 'reviewed'
        AND binding."conflict_classification" = 'none'
        AND binding."vulnerability_id" = evidence."vulnerability_id"
      ) AS binding_reviewed
    FROM "product_match_evaluation_evidence" AS evidence
    LEFT JOIN "sbom_ingestion" AS ingestion
      ON ingestion."organization_id" = evidence."organization_id"
     AND ingestion."id" = evidence."sbom_ingestion_id"
    LEFT JOIN "asset" AS asset
      ON asset."organization_id" = evidence."organization_id"
     AND asset."id" = evidence."asset_id"
    LEFT JOIN "advisory_revision" AS revision
      ON revision."id" = evidence."advisory_revision_id"
    LEFT JOIN "maintainer_reviewed_advisory_approval" AS approval
      ON approval."id" = evidence."approval_id"
    LEFT JOIN "component_occurrence" AS occurrence
      ON occurrence."organization_id" = evidence."organization_id"
     AND occurrence."id" = evidence."component_occurrence_id"
    LEFT JOIN "advisory_vulnerability_binding" AS binding
      ON binding."advisory_revision_id" = evidence."advisory_revision_id"
    WHERE evidence."organization_id" = ${organizationId}::uuid
      AND evidence."id" IN (${Prisma.join(evidenceIds.map((id) => Prisma.sql`${id}::uuid`))})
    ORDER BY evidence."id"::text
  `;
  if (rows.length !== evidenceIds.length) {
    return null;
  }
  const loaded = new Set(rows.map((row) => row.id));
  for (const id of evidenceIds) {
    if (!loaded.has(id)) {
      return null;
    }
  }
  return rows;
}

function classifyRequestedEvidence(
  rows: readonly EvidenceDetail[],
  command: CommandBinding,
  latestIngestionId: string | null,
  qualifyingIds: readonly string[],
): EvidenceFailure | null {
  const qualifying = new Set(qualifyingIds);
  for (const row of rows) {
    if (qualifying.has(row.id)) {
      continue;
    }
    return classifyUnqualified(row, command, latestIngestionId);
  }
  if (!sameIds(qualifyingIds, command.evidenceIds)) {
    return 'evidence_set_mismatch';
  }
  if (latestIngestionId !== command.sbomIngestionId) {
    return 'evidence_not_current';
  }
  return null;
}

function classifyUnqualified(
  row: EvidenceDetail,
  command: CommandBinding,
  latestIngestionId: string | null,
): EvidenceFailure {
  if (
    !row.occurrence_aligned ||
    row.version_known !== true ||
    row.approval_purpose === null ||
    row.approval_revision_matches !== true ||
    row.binding_reviewed !== true ||
    row.normalization_version === null ||
    row.ingestion_state === null
  ) {
    return 'malformed_persisted_state';
  }
  if (row.outcome !== 'affected') {
    return 'evidence_not_affected';
  }
  if (
    row.asset_id !== command.assetId ||
    row.component_id !== command.componentId ||
    row.vulnerability_id !== command.vulnerabilityId
  ) {
    return 'target_mismatch';
  }
  if (
    row.product_origin !== ACCEPTED_ORIGIN ||
    row.finding_creation !== 'unavailable' ||
    row.suppression_authority !== false ||
    row.evaluator_id !== ACCEPTED_EVALUATOR_ID ||
    row.evaluator_version !== ACCEPTED_EVALUATOR_VERSION ||
    row.matching_policy_id !== ACCEPTED_MATCHING_POLICY_ID ||
    row.matching_policy_version !== ACCEPTED_MATCHING_POLICY_ID ||
    row.product_evidence_policy_id !== ACCEPTED_PRODUCT_POLICY_ID ||
    row.product_evidence_policy_version !== 1 ||
    row.evidence_schema_version !== ACCEPTED_EVIDENCE_SCHEMA ||
    row.approval_purpose !== ACCEPTED_APPROVAL_PURPOSE ||
    row.normalization_version !== NORMALIZATION_VERSION ||
    row.ingestion_state !== 'completed'
  ) {
    return 'evidence_not_eligible';
  }
  if (
    row.sbom_ingestion_id !== command.sbomIngestionId ||
    latestIngestionId !== command.sbomIngestionId ||
    row.latest_ingestion_id !== command.sbomIngestionId ||
    row.withdrawal !== 'not_withdrawn' ||
    row.quarantine !== 'not_quarantined' ||
    row.has_successor
  ) {
    return 'evidence_not_current';
  }
  return 'evidence_not_eligible';
}

function readCommand(command: unknown): CommandBinding | null {
  if (typeof command !== 'object' || command === null) {
    return null;
  }
  const record = command as {
    expectedAssetId?: unknown;
    expectedComponentId?: unknown;
    expectedVulnerabilityId?: unknown;
    expectedSbomIngestionId?: unknown;
    expectedProductMatchEvidenceIds?: unknown;
    correlationId?: unknown;
  };
  if (
    typeof record.expectedAssetId !== 'string' ||
    typeof record.expectedComponentId !== 'string' ||
    typeof record.expectedVulnerabilityId !== 'string' ||
    typeof record.expectedSbomIngestionId !== 'string' ||
    typeof record.correlationId !== 'string' ||
    !Array.isArray(record.expectedProductMatchEvidenceIds)
  ) {
    return null;
  }
  const evidenceIds: string[] = [];
  for (const id of record.expectedProductMatchEvidenceIds) {
    if (typeof id !== 'string') {
      return null;
    }
    evidenceIds.push(id);
  }
  return {
    assetId: record.expectedAssetId,
    componentId: record.expectedComponentId,
    vulnerabilityId: record.expectedVulnerabilityId,
    sbomIngestionId: record.expectedSbomIngestionId,
    evidenceIds,
    fingerprint: creationEvidenceFingerprint(evidenceIds),
    correlationId: record.correlationId,
  };
}

function creationEvidenceFingerprint(ids: readonly string[]): string {
  const fields = [
    lengthPrefixed('schema', FINDING_CREATION_EVIDENCE_SET_SCHEMA_VERSION),
    lengthPrefixed('count', String(ids.length)),
  ];
  for (let index = 0; index < ids.length; index += 1) {
    const id = ids[index];
    if (id === undefined) {
      return '';
    }
    fields.push(lengthPrefixed(`id.${String(index)}`, id));
  }
  return createHash('sha256').update(fields.join('|'), 'utf8').digest('hex');
}

function lengthPrefixed(name: string, value: string): string {
  return `${String(name.length)}:${name}${String(value.length)}:${value}`;
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

function throwFault(
  fault: ControlledFindingCreationFault | undefined,
  stage: ControlledFindingCreationFault,
): void {
  if (fault === stage) {
    throw new CreationFault(stage);
  }
}

function stopped(
  status: Exclude<FindingCreationTransactionOutcome, 'created' | 'already_applied'>,
): FindingCreationTransactionResult {
  return {
    schemaVersion: FINDING_CREATION_TRANSACTION_SCHEMA_VERSION,
    status,
    foreignResourceRevealed: false,
    tenantDisclosure: 'indistinguishable',
    authorityCreated: false,
    writesPerformed: false,
    observationAdded: false,
    auditEventAdded: false,
    timestampChanged: false,
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
  return state === '23514' || state === '23503' || state === '42501' || state === '23001';
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
  if (
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    typeof error.code === 'string'
  ) {
    return /^[0-9A-Z]{5}$/.test(error.code) ? error.code : null;
  }
  return null;
}
