/**
 * Read-only controlled Finding target discovery.
 * One repeatable-read transaction reads the authoritative creation predicate.
 * It does not insert, update, lock, or set the creation transaction flag.
 * The API discovery runtime is the only production constructor.
 */

import { Prisma, type PrismaClient } from '@prisma/client';
import {
  FINDING_DISCOVERY_MAX_EVIDENCE_SET_SIZE,
  FINDING_DISCOVERY_MAX_EXAMINED_PAIRS,
  type FindingDiscoveryLineageFact,
  type FindingDiscoveryObservationFact,
  type FindingDiscoveryPairFact,
  type FindingDiscoveryPort,
  type FindingDiscoveryQualifyingRow,
  type FindingDiscoveryRead,
  type FindingDiscoveryReadQuery,
} from '@patchpilot/domain/controlled-finding-discovery';

import { isRootPrismaClient } from './guards.js';

const UUID_LOWER_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

const WINDOW_LIMIT = FINDING_DISCOVERY_MAX_EXAMINED_PAIRS + 1;

type PairKey = {
  component_id: string;
  vulnerability_id: string;
};

type QualifyingJoinRow = PairKey & {
  evidence_id: string | null;
};

type VersionRow = {
  id: string;
  component_id: string;
  vulnerability_id: string;
  occurrence_id: string;
  version: string | null;
  public_id: string | null;
};

type OccurrenceRow = {
  component_id: string;
  id: string;
};

type FindingRow = {
  id: string;
  component_id: string;
  vulnerability_id: string;
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

type ObservationRow = {
  finding_id: string;
  method: string;
  result: string;
  occurrence_id: string | null;
  transition_classification: string | null;
  creation_purpose: string | null;
  creation_policy_id: string | null;
  creation_policy_version: number | null;
  replay_fingerprint: string | null;
  affected_evidence_count: number | null;
  sbom_ingestion_id: string;
};

type LinkRow = {
  finding_id: string;
  evidence_id: string;
};

type MembershipAuthorityRow = {
  id: string;
  user_id: string;
  status: string;
  role: string;
  organization_status: string;
};

export function createControlledFindingDiscoveryPersistence(
  client: PrismaClient,
): FindingDiscoveryPort {
  if (!isRootPrismaClient(client)) {
    throw new Error('Finding discovery requires the root database client.');
  }
  return {
    async read(query): Promise<FindingDiscoveryRead> {
      if (
        !isUuid(query.organizationId) ||
        !isUuid(query.membershipId) ||
        !isUuid(query.actorId) ||
        !isUuid(query.assetId) ||
        (query.cursor !== null &&
          (!isUuid(query.cursor.ingestionId) ||
            !isUuid(query.cursor.componentId) ||
            !isUuid(query.cursor.vulnerabilityId)))
      ) {
        return { status: 'internal_failure' };
      }
      try {
        return await client.$transaction(
          async (tx) => {
            await tx.$queryRaw`SELECT set_config('transaction_read_only', 'on', true)`;
            await tx.$queryRaw`SELECT set_config('statement_timeout', '2000', true)`;
            const settings = await tx.$queryRaw<
              Array<{
                read_only: string;
                isolation: string;
                statement_timeout: string;
                creation_flag: string | null;
              }>
            >`
              SELECT current_setting('transaction_read_only') AS read_only,
                     current_setting('transaction_isolation') AS isolation,
                     current_setting('statement_timeout') AS statement_timeout,
                     current_setting('patchpilot.controlled_finding_creation', true) AS creation_flag
            `;
            const setting = settings[0];
            if (
              setting === undefined ||
              setting.read_only !== 'on' ||
              setting.isolation !== 'repeatable read' ||
              !acceptedStatementTimeout(setting.statement_timeout) ||
              setting.creation_flag === 'on'
            ) {
              return { status: 'internal_failure' };
            }
            return readInTransaction(tx, query);
          },
          {
            isolationLevel: Prisma.TransactionIsolationLevel.RepeatableRead,
            maxWait: 2_000,
            timeout: 2_000,
          },
        );
      } catch (error) {
        return { status: translateFailure(error) };
      }
    },
  };
}

async function readInTransaction(
  tx: Prisma.TransactionClient,
  query: FindingDiscoveryReadQuery,
): Promise<FindingDiscoveryRead> {
  const membership = await tx.$queryRaw<MembershipAuthorityRow[]>`
    SELECT membership."id"::text AS id,
           membership."user_id"::text AS user_id,
           membership."status"::text AS status,
           membership."role"::text AS role,
           organization."status"::text AS organization_status
    FROM "membership" AS membership
    INNER JOIN "organization" AS organization
      ON organization."id" = membership."organization_id"
    WHERE membership."organization_id" = ${query.organizationId}::uuid
      AND membership."id" = ${query.membershipId}::uuid
  `;
  const member = membership[0];
  if (
    membership.length !== 1 ||
    member === undefined ||
    member.status !== 'active' ||
    member.organization_status !== 'active' ||
    member.user_id !== query.actorId ||
    !discoveryRoleGranted(member.role)
  ) {
    return { status: 'authority_rejected' };
  }
  const asset = await tx.$queryRaw<Array<{ ingestion_id: string | null }>>`
    SELECT "last_successful_sbom_ingestion_id"::text AS ingestion_id
    FROM "asset"
    WHERE "organization_id" = ${query.organizationId}::uuid
      AND "id" = ${query.assetId}::uuid
  `;
  if (asset.length !== 1) {
    return { status: 'not_found' };
  }
  const ingestionId = asset[0]?.ingestion_id ?? null;
  if (query.cursor !== null && (ingestionId === null || query.cursor.ingestionId !== ingestionId)) {
    return { status: 'stale_cursor' };
  }
  if (ingestionId === null) {
    return { status: 'ready', ingestionId: null, pairs: [], pairSpaceContinues: false };
  }
  const cursorPredicate =
    query.cursor === null
      ? Prisma.sql`TRUE`
      : Prisma.sql`(
          evidence."component_id"::text COLLATE "C",
          evidence."vulnerability_id"::text COLLATE "C"
        ) > (
          ${query.cursor.componentId}::text COLLATE "C",
          ${query.cursor.vulnerabilityId}::text COLLATE "C"
        )`;
  const keys = await tx.$queryRaw<PairKey[]>`
    SELECT evidence."component_id"::text AS component_id,
           evidence."vulnerability_id"::text AS vulnerability_id
    FROM "product_match_evaluation_evidence" AS evidence
    WHERE evidence."organization_id" = ${query.organizationId}::uuid
      AND evidence."asset_id" = ${query.assetId}::uuid
      AND evidence."sbom_ingestion_id" = ${ingestionId}::uuid
      AND ${cursorPredicate}
    GROUP BY evidence."component_id", evidence."vulnerability_id"
    ORDER BY evidence."component_id"::text COLLATE "C",
             evidence."vulnerability_id"::text COLLATE "C"
    LIMIT ${WINDOW_LIMIT}::int
  `;
  const pairSpaceContinues = keys.length > FINDING_DISCOVERY_MAX_EXAMINED_PAIRS;
  const window = keys.slice(0, FINDING_DISCOVERY_MAX_EXAMINED_PAIRS);
  if (window.length === 0) {
    return { status: 'ready', ingestionId, pairs: [], pairSpaceContinues: false };
  }
  const pairValues = Prisma.join(
    window.map((pair) => Prisma.sql`(${pair.component_id}::uuid, ${pair.vulnerability_id}::uuid)`),
  );
  const joined = await tx.$queryRaw<QualifyingJoinRow[]>`
    SELECT pair.component_id::text AS component_id,
           pair.vulnerability_id::text AS vulnerability_id,
           qualifying.id::text AS evidence_id
    FROM (VALUES ${pairValues}) AS pair(component_id, vulnerability_id)
    LEFT JOIN LATERAL patchpilot_finding_creation_qualifying_evidence(
      ${query.organizationId}::uuid,
      ${query.assetId}::uuid,
      pair.component_id,
      pair.vulnerability_id,
      ${ingestionId}::uuid
    ) AS qualifying ON TRUE
    ORDER BY pair.component_id::text COLLATE "C",
             pair.vulnerability_id::text COLLATE "C",
             qualifying.id::text COLLATE "C"
  `;
  const grouped = groupQualifying(window, joined);
  if (grouped === null) {
    return { status: 'internal_failure' };
  }
  const detailIds = grouped
    .filter(
      (pair) =>
        pair.qualifyingCount > 0 && pair.qualifyingCount <= FINDING_DISCOVERY_MAX_EVIDENCE_SET_SIZE,
    )
    .flatMap((pair) => pair.evidenceIds);
  const versions =
    detailIds.length === 0
      ? []
      : await tx.$queryRaw<VersionRow[]>`
          SELECT evidence."id"::text AS id,
                 evidence."component_id"::text AS component_id,
                 evidence."vulnerability_id"::text AS vulnerability_id,
                 evidence."component_occurrence_id"::text AS occurrence_id,
                 occurrence."version" AS version,
                 vulnerability."osv_id" AS public_id
          FROM "product_match_evaluation_evidence" AS evidence
          INNER JOIN "component_occurrence" AS occurrence
            ON occurrence."organization_id" = evidence."organization_id"
           AND occurrence."id" = evidence."component_occurrence_id"
           AND occurrence."asset_id" = evidence."asset_id"
           AND occurrence."component_id" = evidence."component_id"
          INNER JOIN "vulnerability" AS vulnerability
            ON vulnerability."id" = evidence."vulnerability_id"
          WHERE evidence."organization_id" = ${query.organizationId}::uuid
            AND evidence."asset_id" = ${query.assetId}::uuid
            AND evidence."sbom_ingestion_id" = ${ingestionId}::uuid
            AND evidence."id" IN (${Prisma.join(detailIds.map((id) => Prisma.sql`${id}::uuid`))})
          ORDER BY evidence."id"::text COLLATE "C"
        `;
  const activeComponents = [
    ...new Set(
      grouped
        .filter(
          (pair) =>
            pair.qualifyingCount > 0 &&
            pair.qualifyingCount <= FINDING_DISCOVERY_MAX_EVIDENCE_SET_SIZE,
        )
        .map((pair) => pair.componentId),
    ),
  ];
  const occurrences =
    activeComponents.length === 0
      ? []
      : await tx.$queryRaw<OccurrenceRow[]>`
          SELECT "component_id"::text AS component_id, "id"::text AS id
          FROM "component_occurrence"
          WHERE "organization_id" = ${query.organizationId}::uuid
            AND "asset_id" = ${query.assetId}::uuid
            AND "sbom_ingestion_id" = ${ingestionId}::uuid
            AND "component_id" IN (${Prisma.join(activeComponents.map((id) => Prisma.sql`${id}::uuid`))})
        `;
  const lineagePairs = grouped.filter((pair) => pair.qualifyingCount > 0);
  const lineage = await loadLineage(tx, query.organizationId, query.assetId, lineagePairs);
  if (lineage === null) {
    return { status: 'internal_failure' };
  }
  const pairs: FindingDiscoveryPairFact[] = [];
  for (const pair of grouped) {
    const built = buildPair(pair, versions, occurrences, lineage);
    if (built === null) {
      return { status: 'internal_failure' };
    }
    pairs.push(built);
  }
  return { status: 'ready', ingestionId, pairs, pairSpaceContinues };
}

type GroupedPair = {
  componentId: string;
  vulnerabilityId: string;
  qualifyingCount: number;
  evidenceIds: string[];
};

function groupQualifying(
  window: readonly PairKey[],
  rows: readonly QualifyingJoinRow[],
): GroupedPair[] | null {
  const byKey = new Map<string, string[]>();
  for (const row of rows) {
    if (!isUuid(row.component_id) || !isUuid(row.vulnerability_id)) {
      return null;
    }
    const key = pairKey(row.component_id, row.vulnerability_id);
    const ids = byKey.get(key) ?? [];
    if (row.evidence_id !== null) {
      if (!isUuid(row.evidence_id) || ids.includes(row.evidence_id)) {
        return null;
      }
      ids.push(row.evidence_id);
    }
    byKey.set(key, ids);
  }
  const grouped: GroupedPair[] = [];
  for (const key of window) {
    const evidenceIds = byKey.get(pairKey(key.component_id, key.vulnerability_id));
    if (evidenceIds === undefined) {
      return null;
    }
    grouped.push({
      componentId: key.component_id,
      vulnerabilityId: key.vulnerability_id,
      qualifyingCount: evidenceIds.length,
      evidenceIds: evidenceIds.length > FINDING_DISCOVERY_MAX_EVIDENCE_SET_SIZE ? [] : evidenceIds,
    });
  }
  return grouped;
}

function buildPair(
  pair: GroupedPair,
  versions: readonly VersionRow[],
  occurrences: readonly OccurrenceRow[],
  lineage: ReadonlyMap<string, FindingDiscoveryLineageFact>,
): FindingDiscoveryPairFact | null {
  if (
    pair.qualifyingCount === 0 ||
    pair.qualifyingCount > FINDING_DISCOVERY_MAX_EVIDENCE_SET_SIZE
  ) {
    return {
      componentId: pair.componentId,
      vulnerabilityId: pair.vulnerabilityId,
      vulnerabilityPublicId: null,
      qualifyingCount: pair.qualifyingCount,
      qualifying: [],
      otherOccurrenceCount: 0,
      lineage: lineage.get(pairKey(pair.componentId, pair.vulnerabilityId)) ?? null,
    };
  }
  const rows = versions.filter(
    (row) => row.component_id === pair.componentId && row.vulnerability_id === pair.vulnerabilityId,
  );
  if (rows.length !== pair.evidenceIds.length) {
    return null;
  }
  const byId = new Map(rows.map((row) => [row.id, row]));
  const qualifying: FindingDiscoveryQualifyingRow[] = [];
  let publicId: string | null = null;
  for (const id of pair.evidenceIds) {
    const row = byId.get(id);
    if (row === undefined || !isUuid(row.occurrence_id)) {
      return null;
    }
    if (publicId === null) {
      publicId = row.public_id;
    } else if (row.public_id !== publicId) {
      return null;
    }
    qualifying.push({
      id,
      occurrenceId: row.occurrence_id,
      version: row.version,
    });
  }
  const qualifyingOccurrences = new Set(qualifying.map((row) => row.occurrenceId));
  let otherOccurrenceCount = 0;
  for (const occurrence of occurrences) {
    if (occurrence.component_id === pair.componentId && !qualifyingOccurrences.has(occurrence.id)) {
      otherOccurrenceCount += 1;
    }
  }
  return {
    componentId: pair.componentId,
    vulnerabilityId: pair.vulnerabilityId,
    vulnerabilityPublicId: publicId,
    qualifyingCount: pair.qualifyingCount,
    qualifying,
    otherOccurrenceCount,
    lineage: lineage.get(pairKey(pair.componentId, pair.vulnerabilityId)) ?? null,
  };
}

async function loadLineage(
  tx: Prisma.TransactionClient,
  organizationId: string,
  assetId: string,
  pairs: readonly GroupedPair[],
): Promise<ReadonlyMap<string, FindingDiscoveryLineageFact> | null> {
  const lineage = new Map<string, FindingDiscoveryLineageFact>();
  if (pairs.length === 0) {
    return lineage;
  }
  const predicates = pairs.map(
    (pair) =>
      Prisma.sql`(finding."component_id" = ${pair.componentId}::uuid AND finding."vulnerability_id" = ${pair.vulnerabilityId}::uuid)`,
  );
  const findings = await tx.$queryRaw<FindingRow[]>`
    SELECT finding."id"::text AS id,
           finding."component_id"::text AS component_id,
           finding."vulnerability_id"::text AS vulnerability_id,
           finding."state"::text AS state,
           finding."component_occurrence_id"::text AS component_occurrence_id,
           finding."resolved_at",
           finding."reopened_at",
           finding."assigned_membership_id"::text AS assigned_membership_id,
           finding."assigned_team_id"::text AS assigned_team_id,
           finding."due_at",
           finding."current_risk_calculation_id"::text AS current_risk_calculation_id,
           finding."version"
    FROM "finding" AS finding
    WHERE finding."organization_id" = ${organizationId}::uuid
      AND finding."asset_id" = ${assetId}::uuid
      AND (${Prisma.join(predicates, ' OR ')})
  `;
  if (findings.length === 0) {
    return lineage;
  }
  const findingIds = findings.map((row) => row.id);
  const observations = await tx.$queryRaw<ObservationRow[]>`
    SELECT "finding_id"::text AS finding_id,
           "method",
           "result"::text AS result,
           "occurrence_id"::text AS occurrence_id,
           "transition_classification",
           "creation_purpose",
           "creation_policy_id",
           "creation_policy_version",
           "replay_fingerprint",
           "affected_evidence_count",
           "sbom_ingestion_id"::text AS sbom_ingestion_id
    FROM "finding_observation"
    WHERE "organization_id" = ${organizationId}::uuid
      AND "finding_id" IN (${Prisma.join(findingIds.map((id) => Prisma.sql`${id}::uuid`))})
  `;
  const links = await tx.$queryRaw<LinkRow[]>`
    SELECT "finding_id"::text AS finding_id,
           "product_match_evaluation_evidence_id"::text AS evidence_id
    FROM "finding_creation_evidence_link"
    WHERE "organization_id" = ${organizationId}::uuid
      AND "finding_id" IN (${Prisma.join(findingIds.map((id) => Prisma.sql`${id}::uuid`))})
    ORDER BY "product_match_evaluation_evidence_id"::text COLLATE "C"
  `;
  const observationsByFinding = new Map<string, ObservationRow[]>();
  for (const observation of observations) {
    const list = observationsByFinding.get(observation.finding_id) ?? [];
    list.push(observation);
    observationsByFinding.set(observation.finding_id, list);
  }
  const linksByFinding = new Map<string, string[]>();
  for (const link of links) {
    const list = linksByFinding.get(link.finding_id) ?? [];
    list.push(link.evidence_id);
    linksByFinding.set(link.finding_id, list);
  }
  for (const finding of findings) {
    const storedObservations = observationsByFinding.get(finding.id) ?? [];
    const observation = storedObservations.length === 1 ? storedObservations[0] : undefined;
    const fact: FindingDiscoveryLineageFact = {
      findingId: finding.id,
      state: finding.state,
      componentOccurrenceId: finding.component_occurrence_id,
      resolvedAt: instant(finding.resolved_at),
      reopenedAt: instant(finding.reopened_at),
      assignedMembershipId: finding.assigned_membership_id,
      assignedTeamId: finding.assigned_team_id,
      dueAt: instant(finding.due_at),
      currentRiskCalculationId: finding.current_risk_calculation_id,
      version: finding.version,
      observationCount: storedObservations.length,
      observation: observation === undefined ? null : observationFact(observation),
      linkEvidenceIds: [...(linksByFinding.get(finding.id) ?? [])].sort(compareUtf16),
    };
    const key = pairKey(finding.component_id, finding.vulnerability_id);
    if (lineage.has(key)) {
      return null;
    }
    lineage.set(key, fact);
  }
  return lineage;
}

function observationFact(observation: ObservationRow): FindingDiscoveryObservationFact {
  return {
    method: observation.method,
    result: observation.result,
    occurrenceId: observation.occurrence_id,
    transitionClassification: observation.transition_classification,
    creationPurpose: observation.creation_purpose,
    creationPolicyId: observation.creation_policy_id,
    creationPolicyVersion: observation.creation_policy_version,
    replayFingerprint: observation.replay_fingerprint,
    affectedEvidenceCount: observation.affected_evidence_count,
    sbomIngestionId: observation.sbom_ingestion_id,
  };
}

function pairKey(componentId: string, vulnerabilityId: string): string {
  return `${componentId}:${vulnerabilityId}`;
}

function instant(value: Date | null): string | null {
  if (value === null) {
    return null;
  }
  return value.toISOString();
}

function discoveryRoleGranted(role: string): boolean {
  return role === 'owner' || role === 'admin';
}

function compareUtf16(left: string, right: string): number {
  if (left < right) {
    return -1;
  }
  if (left > right) {
    return 1;
  }
  return 0;
}

function acceptedStatementTimeout(value: string): boolean {
  return value === '2s' || value === '2000ms' || value === '2000';
}

const UNAVAILABLE_PRISMA_CODES = new Set(['P1001', 'P1002', 'P1008', 'P1017', 'P2024', 'P2028']);

function isUuid(value: string): boolean {
  return UUID_LOWER_PATTERN.test(value);
}

function translateFailure(error: unknown): 'database_unavailable' | 'internal_failure' {
  const state = sqlState(error);
  if (
    state === '57014' ||
    error instanceof Prisma.PrismaClientInitializationError ||
    error instanceof Prisma.PrismaClientRustPanicError ||
    (error instanceof Prisma.PrismaClientKnownRequestError &&
      UNAVAILABLE_PRISMA_CODES.has(error.code)) ||
    (error instanceof Error &&
      /statement timeout|canceling statement due to statement timeout/i.test(error.message))
  ) {
    return 'database_unavailable';
  }
  return 'internal_failure';
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
