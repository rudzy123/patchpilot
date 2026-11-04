/**
 * Read-only remediation queue pages.
 * Order is priority descending, escalation recommended first, KEV listed
 * first, source-severity percent descending, then first observation and
 * Finding id ascending. This module does not call the priority engine.
 * A missing or malformed stored row fails the page so the three sections
 * still partition the organization's Findings.
 */

import { Prisma, type PrismaClient } from '@prisma/client';
import {
  BUILTIN_PRIORITY_POLICY_KEY,
  BUILTIN_PRIORITY_POLICY_VERSION,
  projectPriorityReviewMarker,
  type RemediationQueueCalculationFields,
  type RemediationQueueRawRow,
  type RemediationQueueReadQuery,
  type RemediationQueueReadResult,
  type RemediationQueueSection,
} from '@patchpilot/domain';

const SHA256_HEX = '^[a-f0-9]{64}$';
const DECIMAL_TEXT = '^(?:0|[1-9][0-9]{0,8})(?:\\.[0-9]{1,6})?$';
const UUID_TEXT = '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$';
const UUID_TEXT_EXACT = new RegExp(UUID_TEXT);
const UTC_MILLIS = 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"';
const OBSERVED_AT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

const RANKED_ORDER = Prisma.sql`
  priority_numeric DESC NULLS LAST,
  escalation_rank ASC NULLS LAST,
  kev_rank ASC NULLS LAST,
  severity_numeric DESC NULLS LAST,
  first_observed_text COLLATE "C" ASC,
  finding_id COLLATE "C" ASC
`;

const INCOMPARABLE_ORDER = Prisma.sql`
  calculated_at_text COLLATE "C" ASC,
  finding_id COLLATE "C" ASC
`;

const NOT_CALCULATED_ORDER = Prisma.sql`
  first_observed_text COLLATE "C" ASC,
  finding_id COLLATE "C" ASC
`;

type PolicySqlRow = {
  readonly id: string;
  readonly policy_key: string;
  readonly version: number | bigint;
  readonly definition: Prisma.JsonValue;
};

type MetaSqlRow = {
  readonly as_of: string;
  readonly finding_count: number | bigint | string;
  readonly malformed_count: number | bigint | string;
  readonly ranked_count: number | bigint | string;
  readonly incomparable_count: number | bigint | string;
  readonly not_calculated_count: number | bigint | string;
  readonly kev_generation_id: string | null;
};

type QueueSqlRow = {
  readonly finding_id: string;
  readonly asset_id: string;
  readonly asset_name: string;
  readonly component_name: string;
  readonly component_version: string;
  readonly vulnerability_public_id: string;
  readonly first_observed_text: string;
  readonly last_observed_text: string | null;
  readonly asset_updated_text: string | null;
  readonly section: string;
  readonly calculation_id: string | null;
  readonly risk_policy_id: string | null;
  readonly policy_key: string | null;
  readonly policy_version: number | bigint | null;
  readonly policy_definition_sha256: string | null;
  readonly engine_version: string | null;
  readonly calculated_at_text: string | null;
  readonly priority_text: string | null;
  readonly priority_band: string | null;
  readonly escalation_recommended: boolean | null;
  readonly kev_listed: boolean | null;
  readonly severity_text: string | null;
  readonly stored_kev_generation_id: string | null;
  readonly prior_review_exists: boolean | null;
  readonly review_id: string | null;
  readonly review_decision: string | null;
  readonly review_corrected_band: string | null;
  readonly review_expires_text: string | null;
  readonly review_head_count: number | bigint | null;
};

export async function readRemediationQueuePage(
  client: PrismaClient,
  input: RemediationQueueReadQuery,
): Promise<RemediationQueueReadResult> {
  if (!isQueueQuery(input)) {
    return { kind: 'unavailable' };
  }
  try {
    return await client.$transaction((tx) => readInTransaction(tx, input), {
      isolationLevel: Prisma.TransactionIsolationLevel.RepeatableRead,
    });
  } catch {
    return { kind: 'unavailable' };
  }
}

async function readInTransaction(
  client: Prisma.TransactionClient,
  input: RemediationQueueReadQuery,
): Promise<RemediationQueueReadResult> {
  const policies = await client.$queryRaw<PolicySqlRow[]>(Prisma.sql`
    SELECT
      p."id"::text AS id,
      p."policy_key" AS policy_key,
      p."version"::int AS version,
      p."definition" AS definition
    FROM "risk_policy" p
    WHERE p."organization_id" IS NULL
      AND p."scope" = 'builtin'::"risk_policy_scope"
      AND p."policy_key" = ${BUILTIN_PRIORITY_POLICY_KEY}
      AND p."version" = ${BUILTIN_PRIORITY_POLICY_VERSION}::int
      AND p."status" = 'published'::"risk_policy_status"
  `);
  if (policies.length === 0) {
    return { kind: 'policy_absent' };
  }
  const policy = policies[0];
  if (policies.length !== 1 || policy === undefined || !isPublishedPolicy(policy)) {
    return { kind: 'unavailable' };
  }
  const metaRows = await client.$queryRaw<MetaSqlRow[]>(Prisma.sql`
    WITH classified AS (
      ${classifiedFindings(input)}
    )
    SELECT
      to_char(
        date_trunc('milliseconds', clock_timestamp()) AT TIME ZONE 'UTC',
        ${UTC_MILLIS}
      ) AS as_of,
      COUNT(*)::int AS finding_count,
      COUNT(*) FILTER (WHERE malformed)::int AS malformed_count,
      COUNT(*) FILTER (WHERE NOT malformed AND section = 'ranked')::int AS ranked_count,
      COUNT(*) FILTER (WHERE NOT malformed AND section = 'incomparable')::int AS incomparable_count,
      COUNT(*) FILTER (WHERE NOT malformed AND section = 'not_calculated')::int AS not_calculated_count,
      (
        SELECT s."active_generation_id"::text
        FROM "intelligence_source" s
        WHERE s."provider_key" = 'cisa_kev'::"integration_provider_key"
      ) AS kev_generation_id
    FROM classified
  `);
  const meta = metaRows[0];
  if (metaRows.length !== 1 || meta === undefined || !OBSERVED_AT.test(meta.as_of)) {
    return { kind: 'malformed' };
  }
  const findingCount = readCount(meta.finding_count);
  const malformedCount = readCount(meta.malformed_count);
  const ranked = readCount(meta.ranked_count);
  const incomparable = readCount(meta.incomparable_count);
  const notCalculated = readCount(meta.not_calculated_count);
  const activeKevGenerationId = readOptionalUuid(meta.kev_generation_id);
  if (
    findingCount === null ||
    malformedCount === null ||
    ranked === null ||
    incomparable === null ||
    notCalculated === null ||
    activeKevGenerationId === 'malformed' ||
    malformedCount > 0 ||
    ranked + incomparable + notCalculated !== findingCount
  ) {
    return { kind: 'malformed' };
  }
  const predicate = cursorPredicate(input);
  if (predicate === null) {
    return { kind: 'unavailable' };
  }
  const order =
    input.section === 'ranked'
      ? RANKED_ORDER
      : input.section === 'incomparable'
        ? INCOMPARABLE_ORDER
        : NOT_CALCULATED_ORDER;
  const pageRows = await client.$queryRaw<QueueSqlRow[]>(Prisma.sql`
    WITH classified AS (
      ${classifiedFindings(input)}
    )
    SELECT
      finding_id,
      asset_id,
      asset_name,
      component_name,
      component_version,
      vulnerability_public_id,
      first_observed_text,
      last_observed_text,
      asset_updated_text,
      section,
      calculation_id,
      risk_policy_id,
      policy_key,
      policy_version,
      policy_definition_sha256,
      engine_version,
      calculated_at_text,
      priority_text,
      priority_band,
      escalation_recommended,
      kev_listed,
      severity_text,
      stored_kev_generation_id,
      prior_review_exists,
      review_id,
      review_decision,
      review_corrected_band,
      review_expires_text,
      review_head_count
    FROM classified
    WHERE NOT malformed
      AND section = ${input.section}
      AND ${predicate}
    ORDER BY ${order}
    LIMIT ${input.limit + 1}::int
  `);
  const hasMore = pageRows.length > input.limit;
  const kept = hasMore ? pageRows.slice(0, input.limit) : pageRows;
  const rows: RemediationQueueRawRow[] = [];
  for (const row of kept) {
    const mapped = mapQueueRow(row, input.section, meta.as_of);
    if (mapped === null) {
      return { kind: 'malformed' };
    }
    rows.push(mapped);
  }
  return {
    kind: 'page',
    asOf: meta.as_of,
    publishedPolicyId: policy.id,
    publishedPolicyKey: BUILTIN_PRIORITY_POLICY_KEY,
    publishedPolicyVersion: BUILTIN_PRIORITY_POLICY_VERSION,
    publishedDefinition: policy.definition,
    activeKevGenerationId,
    counts: { ranked, incomparable, not_calculated: notCalculated },
    findingCount,
    rows,
    hasMore,
  };
}

function classifiedFindings(input: RemediationQueueReadQuery): Prisma.Sql {
  return Prisma.sql`
    SELECT
      base.*,
      CASE
        WHEN base.calculation_id IS NULL THEN 'not_calculated'
        WHEN base.policy_key = ${BUILTIN_PRIORITY_POLICY_KEY}
          AND base.policy_definition_sha256 = ${input.referencePolicyDefinitionSha256}
          AND base.engine_version = ${input.referenceEngineVersion}
        THEN 'ranked'
        ELSE 'incomparable'
      END AS section,
      (
        base.asset_name IS NULL
        OR base.component_name IS NULL
        OR base.component_version IS NULL
        OR base.vulnerability_public_id IS NULL
        OR base.first_observed_text IS NULL
        OR (
          base.calculation_id IS NOT NULL
          AND (
            base.priority_text IS NULL
            OR base.priority_band IS NULL
            OR base.escalation_recommended IS NULL
            OR base.kev_listed IS NULL
            OR base.severity_text IS NULL
            OR base.policy_definition_sha256 IS NULL
            OR base.engine_version IS NULL
            OR base.calculated_at_text IS NULL
            OR base.risk_policy_id IS NULL
            OR base.policy_key IS NULL
            OR base.policy_version IS NULL
            OR base.last_observed_text IS NULL
            OR base.asset_updated_text IS NULL
            OR NOT base.kev_source_ok
          )
        )
      ) AS malformed,
      CASE
        WHEN base.priority_text IS NULL THEN NULL
        ELSE base.priority_text::numeric
      END AS priority_numeric,
      CASE
        WHEN base.severity_text IS NULL THEN NULL
        ELSE base.severity_text::numeric
      END AS severity_numeric,
      CASE
        WHEN base.escalation_recommended IS NULL THEN NULL
        WHEN base.escalation_recommended THEN 0
        ELSE 1
      END AS escalation_rank,
      CASE
        WHEN base.kev_listed IS NULL THEN NULL
        WHEN base.kev_listed THEN 0
        ELSE 1
      END AS kev_rank
    FROM (
      SELECT
        f."id"::text AS finding_id,
        f."asset_id"::text AS asset_id,
        CASE
          WHEN a."name" IS NOT NULL AND char_length(a."name") BETWEEN 1 AND 200 THEN a."name"
          ELSE NULL
        END AS asset_name,
        CASE
          WHEN comp."name" IS NOT NULL AND char_length(comp."name") BETWEEN 1 AND 512 THEN comp."name"
          ELSE NULL
        END AS component_name,
        (
          SELECT min((occ."version") COLLATE "C")
          FROM "finding_creation_evidence_link" link
          INNER JOIN "component_occurrence" occ
            ON occ."organization_id" = link."organization_id"
           AND occ."id" = link."component_occurrence_id"
          WHERE link."organization_id" = f."organization_id"
            AND link."finding_id" = f."id"
            AND occ."version_known" IS TRUE
            AND char_length(occ."version") BETWEEN 1 AND 256
        ) AS component_version,
        CASE
          WHEN v."osv_id" IS NOT NULL AND char_length(v."osv_id") BETWEEN 1 AND 128 THEN v."osv_id"
          ELSE NULL
        END AS vulnerability_public_id,
        to_char(
          date_trunc('milliseconds', f."first_observed_at") AT TIME ZONE 'UTC',
          ${UTC_MILLIS}
        ) AS first_observed_text,
        to_char(
          date_trunc('milliseconds', f."last_observed_at") AT TIME ZONE 'UTC',
          ${UTC_MILLIS}
        ) AS last_observed_text,
        to_char(
          date_trunc('milliseconds', a."updated_at") AT TIME ZONE 'UTC',
          ${UTC_MILLIS}
        ) AS asset_updated_text,
        c.id AS calculation_id,
        c.risk_policy_id,
        c.policy_key,
        c.policy_version,
        CASE
          WHEN c.policy_definition_sha256 ~ ${SHA256_HEX} THEN c.policy_definition_sha256
          ELSE NULL
        END AS policy_definition_sha256,
        CASE
          WHEN c.engine_version IS NOT NULL AND char_length(c.engine_version) BETWEEN 1 AND 64
          THEN c.engine_version
          ELSE NULL
        END AS engine_version,
        to_char(
          date_trunc('milliseconds', c.calculated_at) AT TIME ZONE 'UTC',
          ${UTC_MILLIS}
        ) AS calculated_at_text,
        CASE
          WHEN c.id IS NULL THEN NULL
          WHEN jsonb_typeof(c.result -> 'priority') = 'number'
            AND (c.result ->> 'priority') ~ ${DECIMAL_TEXT}
          THEN c.result ->> 'priority'
          ELSE NULL
        END AS priority_text,
        CASE
          WHEN c.id IS NULL THEN NULL
          WHEN c.result ->> 'priorityBand' IN ('P1', 'P2', 'P3', 'P4') THEN c.result ->> 'priorityBand'
          ELSE NULL
        END AS priority_band,
        CASE
          WHEN c.id IS NULL THEN NULL
          WHEN jsonb_typeof(c.result -> 'escalationRecommendation') = 'boolean'
          THEN (c.result ->> 'escalationRecommendation') = 'true'
          ELSE NULL
        END AS escalation_recommended,
        CASE
          WHEN c.id IS NULL THEN NULL
          ELSE COALESCE(kev.listed, FALSE)
        END AS kev_listed,
        CASE
          WHEN c.id IS NULL THEN NULL
          WHEN sev.severity_text IS NULL THEN '0'
          WHEN sev.severity_text ~ ${DECIMAL_TEXT} THEN sev.severity_text
          ELSE NULL
        END AS severity_text,
        CASE
          WHEN c.id IS NULL THEN TRUE
          WHEN c.factors #>> '{sources,kev,state}' = 'unavailable' THEN TRUE
          WHEN c.factors #>> '{sources,kev,state}' = 'catalog'
            AND (
              c.factors #> '{sources,kev,generationId}' = 'null'::jsonb
              OR (c.factors #>> '{sources,kev,generationId}') ~ ${UUID_TEXT}
            )
          THEN TRUE
          ELSE FALSE
        END AS kev_source_ok,
        CASE
          WHEN c.factors #>> '{sources,kev,state}' = 'catalog'
            AND (c.factors #>> '{sources,kev,generationId}') ~ ${UUID_TEXT}
          THEN c.factors #>> '{sources,kev,generationId}'
          ELSE NULL
        END AS stored_kev_generation_id,
        EXISTS (
          SELECT 1
          FROM "risk_calculation_review" older
          WHERE older."organization_id" = f."organization_id"
            AND older."finding_id" = f."id"
            AND c.id IS NOT NULL
            AND older."risk_calculation_id" <> c.id::uuid
        ) AS prior_review_exists,
        rev.review_id,
        rev.review_decision,
        rev.review_corrected_band,
        to_char(
          date_trunc('milliseconds', rev.review_expires_at) AT TIME ZONE 'UTC',
          ${UTC_MILLIS}
        ) AS review_expires_text,
        rev.review_head_count
      FROM "finding" f
      LEFT JOIN "asset" a
        ON a."organization_id" = f."organization_id"
       AND a."id" = f."asset_id"
      LEFT JOIN "component" comp
        ON comp."organization_id" = f."organization_id"
       AND comp."id" = f."component_id"
      LEFT JOIN "vulnerability" v
        ON v."id" = f."vulnerability_id"
      LEFT JOIN LATERAL (
        SELECT
          rc."id"::text AS id,
          rc."risk_policy_id"::text AS risk_policy_id,
          rp."policy_key" AS policy_key,
          rc."policy_version"::int AS policy_version,
          btrim(rc."policy_definition_sha256") AS policy_definition_sha256,
          btrim(rc."calculation_engine_version") AS engine_version,
          rc."calculated_at" AS calculated_at,
          rc."factors" AS factors,
          rc."result" AS result
        FROM "risk_calculation" rc
        INNER JOIN "risk_policy" rp ON rp."id" = rc."risk_policy_id"
        WHERE rc."organization_id" = f."organization_id"
          AND rc."finding_id" = f."id"
        ORDER BY rc."calculated_at" DESC, rc."id" DESC
        LIMIT 1
      ) c ON TRUE
      LEFT JOIN LATERAL (
        SELECT CASE
          WHEN elem->>'normalizedPercent' ~ ${DECIMAL_TEXT} THEN elem->>'normalizedPercent'
          ELSE 'invalid'
        END AS severity_text
        FROM jsonb_array_elements(
          CASE
            WHEN c.factors IS NOT NULL AND jsonb_typeof(c.factors -> 'factors') = 'array'
            THEN c.factors -> 'factors'
            ELSE '[]'::jsonb
          END
        ) elem
        WHERE elem->>'factorId' = 'source_severity'
        LIMIT 1
      ) sev ON TRUE
      LEFT JOIN LATERAL (
        SELECT (
          elem->>'inputState' = 'observed'
          AND elem->>'observedValue' IN (
            'listed_catalog_current',
            'listed_catalog_stale',
            'listed_catalog_disabled_with_history'
          )
        ) AS listed
        FROM jsonb_array_elements(
          CASE
            WHEN c.factors IS NOT NULL AND jsonb_typeof(c.factors -> 'factors') = 'array'
            THEN c.factors -> 'factors'
            ELSE '[]'::jsonb
          END
        ) elem
        WHERE elem->>'factorId' = 'kev_listed'
        LIMIT 1
      ) kev ON TRUE
      LEFT JOIN LATERAL (
        SELECT
          head."id"::text AS review_id,
          head."decision" AS review_decision,
          head."corrected_band" AS review_corrected_band,
          head."expires_at" AS review_expires_at,
          (
            SELECT COUNT(*)::int
            FROM "risk_calculation_review" candidate
            WHERE candidate."organization_id" = f."organization_id"
              AND c.id IS NOT NULL
              AND candidate."risk_calculation_id" = c.id::uuid
              AND NOT EXISTS (
                SELECT 1
                FROM "risk_calculation_review" successor
                WHERE successor."organization_id" = candidate."organization_id"
                  AND successor."supersedes_review_id" = candidate."id"
              )
          ) AS review_head_count
        FROM "risk_calculation_review" head
        WHERE c.id IS NOT NULL
          AND head."organization_id" = f."organization_id"
          AND head."risk_calculation_id" = c.id::uuid
          AND NOT EXISTS (
            SELECT 1
            FROM "risk_calculation_review" successor
            WHERE successor."organization_id" = head."organization_id"
              AND successor."supersedes_review_id" = head."id"
          )
        ORDER BY head."id" DESC
        LIMIT 1
      ) rev ON TRUE
      WHERE f."organization_id" = ${input.organizationId}::uuid
    ) base
  `;
}

function cursorPredicate(input: RemediationQueueReadQuery): Prisma.Sql | null {
  const cursor = input.cursor;
  if (cursor === null) {
    return Prisma.sql`TRUE`;
  }
  if (cursor.section !== input.section) {
    return null;
  }
  if (cursor.section === 'ranked') {
    return Prisma.sql`
      (
        priority_numeric < ${cursor.priorityText}::numeric
        OR (
          priority_numeric = ${cursor.priorityText}::numeric
          AND (
            escalation_rank > ${cursor.escalationRecommended ? 0 : 1}::int
            OR (
              escalation_rank = ${cursor.escalationRecommended ? 0 : 1}::int
              AND (
                kev_rank > ${cursor.kevListed ? 0 : 1}::int
                OR (
                  kev_rank = ${cursor.kevListed ? 0 : 1}::int
                  AND (
                    severity_numeric < ${cursor.severityText}::numeric
                    OR (
                      severity_numeric = ${cursor.severityText}::numeric
                      AND (
                        first_observed_text COLLATE "C" > ${cursor.firstObservedAt}
                        OR (
                          first_observed_text COLLATE "C" = ${cursor.firstObservedAt}
                          AND finding_id COLLATE "C" > ${cursor.findingId}
                        )
                      )
                    )
                  )
                )
              )
            )
          )
        )
      )
    `;
  }
  if (cursor.section === 'incomparable') {
    return Prisma.sql`
      (
        calculated_at_text COLLATE "C" > ${cursor.calculatedAt}
        OR (
          calculated_at_text COLLATE "C" = ${cursor.calculatedAt}
          AND finding_id COLLATE "C" > ${cursor.findingId}
        )
      )
    `;
  }
  return Prisma.sql`
    (
      first_observed_text COLLATE "C" > ${cursor.firstObservedAt}
      OR (
        first_observed_text COLLATE "C" = ${cursor.firstObservedAt}
        AND finding_id COLLATE "C" > ${cursor.findingId}
      )
    )
  `;
}

function mapQueueRow(
  row: QueueSqlRow,
  section: RemediationQueueSection,
  asOf: string,
): RemediationQueueRawRow | null {
  if (row.section !== section || !isText(row.finding_id) || !isText(row.asset_id)) {
    return null;
  }
  if (
    !isText(row.asset_name) ||
    !isText(row.component_name) ||
    !isText(row.component_version) ||
    !isText(row.vulnerability_public_id) ||
    !isText(row.first_observed_text) ||
    !OBSERVED_AT.test(row.first_observed_text)
  ) {
    return null;
  }
  const identity = {
    findingId: row.finding_id,
    assetId: row.asset_id,
    assetName: row.asset_name,
    componentName: row.component_name,
    componentVersion: row.component_version,
    vulnerabilityPublicId: row.vulnerability_public_id,
    firstObservedAt: row.first_observed_text,
  };
  const humanReview = projectQueueReview(row, asOf);
  if (humanReview === null) {
    return null;
  }
  if (section === 'not_calculated') {
    if (row.calculation_id !== null || humanReview.status !== 'none') {
      return null;
    }
    return { ...identity, section, calculation: null, humanReview };
  }
  const calculation = mapCalculation(row);
  if (calculation === null) {
    return null;
  }
  return { ...identity, section, calculation, humanReview };
}

function projectQueueReview(row: QueueSqlRow, asOf: string) {
  if (!OBSERVED_AT.test(asOf) || typeof row.prior_review_exists !== 'boolean') {
    return null;
  }
  const asOfDate = new Date(asOf);
  const headCount = readReviewHeadCount(row.review_head_count);
  if (row.review_id === null) {
    if (headCount !== 0) {
      return null;
    }
    return projectPriorityReviewMarker({
      asOf: asOfDate,
      priorReviewExists: row.prior_review_exists,
      head: null,
    });
  }
  if (headCount !== 1 || !UUID_TEXT_EXACT.test(row.review_id)) {
    return null;
  }
  const decision = row.review_decision;
  if (decision !== 'accepted' && decision !== 'corrected' && decision !== 'withdrawn') {
    return null;
  }
  const correctedBand = readQueueBand(row.review_corrected_band);
  if (correctedBand === 'invalid') {
    return null;
  }
  const expiresAt =
    row.review_expires_text === null
      ? null
      : OBSERVED_AT.test(row.review_expires_text)
        ? new Date(row.review_expires_text)
        : 'invalid';
  if (expiresAt === 'invalid') {
    return null;
  }
  return projectPriorityReviewMarker({
    asOf: asOfDate,
    priorReviewExists: row.prior_review_exists,
    head: {
      reviewId: row.review_id,
      decision,
      correctedBand,
      expiresAt,
    },
  });
}

function readReviewHeadCount(value: number | bigint | null): number | null {
  if (value === null) {
    return 0;
  }
  const count = typeof value === 'bigint' ? Number(value) : value;
  return Number.isInteger(count) && count >= 0 ? count : null;
}

function readQueueBand(value: string | null): 'P1' | 'P2' | 'P3' | 'P4' | null | 'invalid' {
  if (value === null) {
    return null;
  }
  if (value === 'P1' || value === 'P2' || value === 'P3' || value === 'P4') {
    return value;
  }
  return 'invalid';
}

function mapCalculation(row: QueueSqlRow): RemediationQueueCalculationFields | null {
  if (
    !isText(row.risk_policy_id) ||
    !isText(row.policy_key) ||
    !isText(row.policy_definition_sha256) ||
    !isText(row.engine_version) ||
    !isText(row.calculated_at_text) ||
    !OBSERVED_AT.test(row.calculated_at_text) ||
    !isText(row.priority_text) ||
    !isText(row.severity_text) ||
    !isText(row.last_observed_text) ||
    !OBSERVED_AT.test(row.last_observed_text) ||
    !isText(row.asset_updated_text) ||
    !OBSERVED_AT.test(row.asset_updated_text) ||
    !isBand(row.priority_band) ||
    typeof row.escalation_recommended !== 'boolean' ||
    typeof row.kev_listed !== 'boolean'
  ) {
    return null;
  }
  const policyVersion = readCount(row.policy_version);
  const priority = Number(row.priority_text);
  const severityPercent = Number(row.severity_text);
  const generation = readOptionalUuid(row.stored_kev_generation_id);
  if (
    policyVersion === null ||
    policyVersion < 1 ||
    !Number.isFinite(priority) ||
    !Number.isFinite(severityPercent) ||
    generation === 'malformed'
  ) {
    return null;
  }
  return {
    riskPolicyId: row.risk_policy_id,
    policyKey: row.policy_key,
    policyVersion,
    policyDefinitionSha256: row.policy_definition_sha256,
    calculatedAt: row.calculated_at_text,
    calculationEngineVersion: row.engine_version,
    priorityText: row.priority_text,
    priority,
    priorityBand: row.priority_band,
    escalationRecommended: row.escalation_recommended,
    kevListed: row.kev_listed,
    severityText: row.severity_text,
    severityPercent,
    storedKevGenerationId: generation,
    lastObservedAt: row.last_observed_text,
    assetUpdatedAt: row.asset_updated_text,
  };
}

function isQueueQuery(input: RemediationQueueReadQuery): boolean {
  return (
    UUID_TEXT_PATTERN.test(input.organizationId) &&
    SHA256_PATTERN.test(input.referencePolicyDefinitionSha256) &&
    input.referenceEngineVersion.length > 0 &&
    input.referenceEngineVersion.length <= 64 &&
    Number.isInteger(input.limit) &&
    input.limit >= 1 &&
    input.limit <= 50 &&
    (input.section === 'ranked' ||
      input.section === 'incomparable' ||
      input.section === 'not_calculated')
  );
}

function isPublishedPolicy(row: PolicySqlRow): boolean {
  const version = readCount(row.version);
  return (
    UUID_TEXT_PATTERN.test(row.id) &&
    row.policy_key === BUILTIN_PRIORITY_POLICY_KEY &&
    version === BUILTIN_PRIORITY_POLICY_VERSION &&
    isJsonObject(row.definition)
  );
}

function isJsonObject(value: Prisma.JsonValue): value is Prisma.JsonObject {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function readCount(value: number | bigint | string | null): number | null {
  if (typeof value === 'number' && Number.isSafeInteger(value) && value >= 0) {
    return value;
  }
  if (typeof value === 'bigint' && value >= 0n && value <= BigInt(Number.MAX_SAFE_INTEGER)) {
    return Number(value);
  }
  if (typeof value === 'string' && /^\d+$/.test(value)) {
    const parsed = Number(value);
    if (Number.isSafeInteger(parsed)) {
      return parsed;
    }
  }
  return null;
}

function readOptionalUuid(value: string | null): string | null | 'malformed' {
  if (value === null) {
    return null;
  }
  if (!UUID_TEXT_PATTERN.test(value)) {
    return 'malformed';
  }
  return value;
}

function isText(value: string | null): value is string {
  return typeof value === 'string' && value.length > 0;
}

function isBand(value: string | null): value is 'P1' | 'P2' | 'P3' | 'P4' {
  return value === 'P1' || value === 'P2' || value === 'P3' || value === 'P4';
}

const UUID_TEXT_PATTERN = new RegExp(UUID_TEXT);
const SHA256_PATTERN = new RegExp(SHA256_HEX);
