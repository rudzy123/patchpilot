/**
 * PostgreSQL adapter for one append-only priority review.
 * The transaction takes the calculation writer's Finding lock, reloads the
 * actor's membership, and appends the review and its audit row together.
 * It does not update the Finding or the RiskCalculation, and it does not
 * log the review reason.
 */

import { createHash } from 'node:crypto';

import { Prisma, type PrismaClient } from '@prisma/client';
import {
  JSON_SCHEMA_VERSION_V1,
  normalizePriorityReviewReason,
  priorityReviewAuditAction,
  priorityReviewAuditPayload,
  PRIORITY_REVIEW_SUBJECT_TYPE,
  type PriorityReviewDecision,
  type RecordPriorityReviewCommand,
  type RecordPriorityReviewPersistenceResult,
} from '@patchpilot/domain';

const UUID_LOWER = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

type NormalizedReview = RecordPriorityReviewCommand & {
  readonly reasonSha256: string | null;
};

type ReviewHead = {
  readonly id: string;
  readonly supersedesReviewId: string | null;
  readonly decision: PriorityReviewDecision;
  readonly correctedBand: RecordPriorityReviewCommand['correctedBand'];
  readonly expiresAt: Date | null;
  readonly reasonSha256: string | null;
};

class PersistenceAbort extends Error {
  constructor(readonly failure: 'internal_failure') {
    super(failure);
  }
}

export function createPriorityReviewPersistence(client: PrismaClient): {
  recordPriorityReview(
    command: RecordPriorityReviewCommand,
  ): Promise<RecordPriorityReviewPersistenceResult>;
} {
  return {
    async recordPriorityReview(command) {
      const normalized = normalizeCommand(command);
      if (normalized === null) {
        return { kind: 'rejected' };
      }
      try {
        return await client.$transaction((tx) => recordInTransaction(tx, normalized), {
          isolationLevel: Prisma.TransactionIsolationLevel.ReadCommitted,
        });
      } catch (error) {
        if (error instanceof PersistenceAbort) {
          return { kind: 'unavailable' };
        }
        if (isUniqueViolation(error)) {
          return reconcileUnique(client, normalized);
        }
        if (isCheckViolation(error)) {
          return { kind: 'rejected' };
        }
        if (sqlState(error) === '23503') {
          return { kind: 'not_found' };
        }
        return { kind: 'unavailable' };
      }
    },
  };
}

async function recordInTransaction(
  tx: Prisma.TransactionClient,
  command: NormalizedReview,
): Promise<RecordPriorityReviewPersistenceResult> {
  await lockTransactionScope(tx, `${command.organizationId}:${command.findingId}`);
  const actor = await loadActor(
    tx,
    command.organizationId,
    command.membershipId,
    command.actorUserId,
  );
  if (actor === null) {
    return { kind: 'unauthorized' };
  }
  const finding = await lockFinding(tx, command.organizationId, command.findingId);
  if (!finding) {
    return { kind: 'not_found' };
  }
  const latest = await loadLatestCalculation(tx, command.organizationId, command.findingId);
  if (latest === null) {
    return { kind: 'not_found' };
  }
  if (latest.id !== command.riskCalculationId) {
    const named = await calculationBelongsToFinding(
      tx,
      command.organizationId,
      command.findingId,
      command.riskCalculationId,
    );
    return named ? { kind: 'calculation_not_current' } : { kind: 'not_found' };
  }
  if (command.decision === 'corrected' && command.correctedBand === latest.priorityBand) {
    return { kind: 'rejected' };
  }
  const clock = await readDatabaseClock(tx);
  if (
    command.decision === 'corrected' &&
    !expiryInWindow(command.expiresAt, clock.createdAt, clock.expiresLimit)
  ) {
    return { kind: 'rejected' };
  }
  const head = await loadHead(tx, command.organizationId, latest.id);
  const acknowledgement = await acknowledge(tx, command, head);
  if (acknowledgement !== 'insert') {
    return acknowledgement;
  }
  const reviewId = await insertReview(tx, command, clock.createdAt);
  const payload = priorityReviewAuditPayload({
    reviewId,
    findingId: command.findingId,
    riskCalculationId: command.riskCalculationId,
    decision: command.decision,
    correctedBand: command.correctedBand,
    expiresAt: command.expiresAt === null ? null : command.expiresAt.toISOString(),
    supersedesReviewId: command.supersedesReviewId,
    reasonLength: command.reason === null ? 0 : command.reason.length,
  });
  if (payload === null || Object.prototype.hasOwnProperty.call(payload, 'reason')) {
    throw new PersistenceAbort('internal_failure');
  }
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
      "schema_version",
      "retention_category"
    )
    VALUES (
      ${command.organizationId}::uuid,
      ${command.actorUserId}::uuid,
      ${command.membershipId}::uuid,
      'user'::"audit_actor_type",
      ${priorityReviewAuditAction(command.decision)},
      ${PRIORITY_REVIEW_SUBJECT_TYPE},
      ${reviewId}::uuid,
      ${command.correlationId},
      ${JSON.stringify(payload)}::jsonb,
      ${JSON_SCHEMA_VERSION_V1}::int,
      'security'::"audit_retention_category"
    )
  `;
  return {
    kind: 'recorded',
    reviewId,
    findingId: command.findingId,
    riskCalculationId: command.riskCalculationId,
  };
}

async function acknowledge(
  tx: Prisma.TransactionClient,
  command: NormalizedReview,
  head: ReviewHead | null,
): Promise<RecordPriorityReviewPersistenceResult | 'insert'> {
  if (
    head !== null &&
    sameContent(head, command) &&
    command.supersedesReviewId === head.supersedesReviewId
  ) {
    return applied(head.id, command);
  }
  if (head !== null && command.supersedesReviewId === head.id) {
    if (sameContent(head, command)) {
      return applied(head.id, command);
    }
    return 'insert';
  }
  if (head === null && command.supersedesReviewId === null) {
    return 'insert';
  }
  if (command.supersedesReviewId === null) {
    return { kind: 'review_not_current' };
  }
  const named = await loadReviewForFinding(
    tx,
    command.organizationId,
    command.findingId,
    command.supersedesReviewId,
  );
  if (named === null) {
    return { kind: 'not_found' };
  }
  return { kind: 'review_not_current' };
}

function applied(
  reviewId: string,
  command: NormalizedReview,
): RecordPriorityReviewPersistenceResult {
  return {
    kind: 'already_applied',
    reviewId,
    findingId: command.findingId,
    riskCalculationId: command.riskCalculationId,
  };
}

async function reconcileUnique(
  client: PrismaClient,
  command: NormalizedReview,
): Promise<RecordPriorityReviewPersistenceResult> {
  try {
    return await client.$transaction(
      async (tx) => {
        await lockTransactionScope(tx, `${command.organizationId}:${command.findingId}`);
        const head = await loadHead(tx, command.organizationId, command.riskCalculationId);
        if (head !== null && sameContent(head, command)) {
          return applied(head.id, command);
        }
        return { kind: 'review_not_current' };
      },
      { isolationLevel: Prisma.TransactionIsolationLevel.ReadCommitted },
    );
  } catch {
    return { kind: 'unavailable' };
  }
}

function normalizeCommand(command: RecordPriorityReviewCommand): NormalizedReview | null {
  if (
    !isUuid(command.organizationId) ||
    !isUuid(command.actorUserId) ||
    !isUuid(command.membershipId) ||
    !isUuid(command.findingId) ||
    !isUuid(command.riskCalculationId) ||
    !isUuid(command.correlationId)
  ) {
    return null;
  }
  if (command.supersedesReviewId !== null && !isUuid(command.supersedesReviewId)) {
    return null;
  }
  let reason: string | null = null;
  let reasonSha256: string | null = null;
  if (command.reason !== null) {
    const normalized = normalizePriorityReviewReason(command.reason);
    if (normalized === null || normalized !== command.reason) {
      return null;
    }
    reason = normalized;
    reasonSha256 = createHash('sha256').update(normalized, 'utf8').digest('hex');
  }
  if (command.decision === 'corrected') {
    if (command.correctedBand === null || command.expiresAt === null || reason === null) {
      return null;
    }
  } else if (command.correctedBand !== null || command.expiresAt !== null) {
    return null;
  }
  if (
    command.decision === 'withdrawn' &&
    (command.supersedesReviewId === null || reason === null)
  ) {
    return null;
  }
  if (
    command.decision !== 'corrected' &&
    command.decision !== 'accepted' &&
    command.decision !== 'withdrawn'
  ) {
    return null;
  }
  return { ...command, reason, reasonSha256 };
}

function sameContent(head: ReviewHead, command: NormalizedReview): boolean {
  return (
    head.decision === command.decision &&
    head.correctedBand === command.correctedBand &&
    head.reasonSha256 === command.reasonSha256 &&
    sameInstant(head.expiresAt, command.expiresAt)
  );
}

function sameInstant(left: Date | null, right: Date | null): boolean {
  if (left === null || right === null) {
    return left === null && right === null;
  }
  return left.getTime() === right.getTime();
}

function expiryInWindow(expiresAt: Date | null, createdAt: Date, expiresLimit: Date): boolean {
  if (expiresAt === null) {
    return false;
  }
  return expiresAt.getTime() > createdAt.getTime() && expiresAt.getTime() <= expiresLimit.getTime();
}

async function insertReview(
  tx: Prisma.TransactionClient,
  command: NormalizedReview,
  createdAt: Date,
): Promise<string> {
  const supersedes =
    command.supersedesReviewId === null
      ? Prisma.sql`NULL`
      : Prisma.sql`${command.supersedesReviewId}::uuid`;
  const correctedBand =
    command.correctedBand === null ? Prisma.sql`NULL` : Prisma.sql`${command.correctedBand}`;
  const expiresAt =
    command.expiresAt === null ? Prisma.sql`NULL` : Prisma.sql`${command.expiresAt}`;
  const reason = command.reason === null ? Prisma.sql`NULL` : Prisma.sql`${command.reason}`;
  const reasonSha256 =
    command.reasonSha256 === null ? Prisma.sql`NULL` : Prisma.sql`${command.reasonSha256}`;
  const inserted = await tx.$queryRaw<Array<{ id: string }>>`
    INSERT INTO "risk_calculation_review" (
      "organization_id",
      "finding_id",
      "risk_calculation_id",
      "supersedes_review_id",
      "decision",
      "corrected_band",
      "expires_at",
      "reason",
      "reason_sha256",
      "actor_user_id",
      "actor_membership_id",
      "correlation_id",
      "created_at"
    )
    VALUES (
      ${command.organizationId}::uuid,
      ${command.findingId}::uuid,
      ${command.riskCalculationId}::uuid,
      ${supersedes},
      ${command.decision},
      ${correctedBand},
      ${expiresAt},
      ${reason},
      ${reasonSha256},
      ${command.actorUserId}::uuid,
      ${command.membershipId}::uuid,
      ${command.correlationId}::uuid,
      ${createdAt}
    )
    RETURNING "id"::text AS "id"
  `;
  const id = normalizeUuid(inserted[0]?.id);
  if (inserted.length !== 1 || id === null) {
    throw new PersistenceAbort('internal_failure');
  }
  return id;
}

async function loadLatestCalculation(
  tx: Prisma.TransactionClient,
  organizationId: string,
  findingId: string,
): Promise<{ readonly id: string; readonly priorityBand: string } | null> {
  const rows = await tx.$queryRaw<Array<{ id: string; priority_band: string | null }>>`
    SELECT "id"::text AS "id", "result" ->> 'priorityBand' AS "priority_band"
    FROM "risk_calculation"
    WHERE "organization_id" = ${organizationId}::uuid
      AND "finding_id" = ${findingId}::uuid
    ORDER BY "calculated_at" DESC, "id" DESC
    LIMIT 1
  `;
  const row = rows[0];
  if (row === undefined) {
    return null;
  }
  const id = normalizeUuid(row.id);
  if (rows.length !== 1 || id === null || row.priority_band === null) {
    throw new PersistenceAbort('internal_failure');
  }
  return { id, priorityBand: row.priority_band };
}

async function calculationBelongsToFinding(
  tx: Prisma.TransactionClient,
  organizationId: string,
  findingId: string,
  riskCalculationId: string,
): Promise<boolean> {
  const rows = await tx.$queryRaw<Array<{ present: boolean }>>`
    SELECT EXISTS (
      SELECT 1
      FROM "risk_calculation"
      WHERE "organization_id" = ${organizationId}::uuid
        AND "finding_id" = ${findingId}::uuid
        AND "id" = ${riskCalculationId}::uuid
    ) AS "present"
  `;
  return rows[0]?.present === true;
}

async function loadHead(
  tx: Prisma.TransactionClient,
  organizationId: string,
  riskCalculationId: string,
): Promise<ReviewHead | null> {
  const rows = await tx.$queryRaw<
    Array<{
      id: string;
      supersedes_review_id: string | null;
      decision: string;
      corrected_band: string | null;
      expires_at: Date | string | null;
      reason_sha256: string | null;
      head_count: number | bigint;
    }>
  >`
    SELECT
      head."id"::text AS "id",
      head."supersedes_review_id"::text AS "supersedes_review_id",
      head."decision" AS "decision",
      head."corrected_band" AS "corrected_band",
      head."expires_at" AS "expires_at",
      btrim(head."reason_sha256") AS "reason_sha256",
      (
        SELECT COUNT(*)::int
        FROM "risk_calculation_review" candidate
        WHERE candidate."organization_id" = ${organizationId}::uuid
          AND candidate."risk_calculation_id" = ${riskCalculationId}::uuid
          AND NOT EXISTS (
            SELECT 1
            FROM "risk_calculation_review" successor
            WHERE successor."organization_id" = candidate."organization_id"
              AND successor."supersedes_review_id" = candidate."id"
          )
      ) AS "head_count"
    FROM "risk_calculation_review" head
    WHERE head."organization_id" = ${organizationId}::uuid
      AND head."risk_calculation_id" = ${riskCalculationId}::uuid
      AND NOT EXISTS (
        SELECT 1
        FROM "risk_calculation_review" successor
        WHERE successor."organization_id" = head."organization_id"
          AND successor."supersedes_review_id" = head."id"
      )
    ORDER BY head."id" DESC
    LIMIT 1
  `;
  const row = rows[0];
  if (row === undefined) {
    return null;
  }
  const headCount = typeof row.head_count === 'bigint' ? Number(row.head_count) : row.head_count;
  if (rows.length !== 1 || headCount !== 1) {
    throw new PersistenceAbort('internal_failure');
  }
  const id = normalizeUuid(row.id);
  const supersedes =
    row.supersedes_review_id === null ? null : normalizeUuid(row.supersedes_review_id);
  const expiresAt = row.expires_at === null ? null : readTimestamp(row.expires_at);
  if (
    id === null ||
    (row.supersedes_review_id !== null && supersedes === null) ||
    !isDecision(row.decision) ||
    !isBand(row.corrected_band) ||
    expiresAt === 'invalid' ||
    (row.reason_sha256 !== null && !/^[a-f0-9]{64}$/.test(row.reason_sha256))
  ) {
    throw new PersistenceAbort('internal_failure');
  }
  return {
    id,
    supersedesReviewId: supersedes,
    decision: row.decision,
    correctedBand: row.corrected_band,
    expiresAt,
    reasonSha256: row.reason_sha256,
  };
}

async function loadReviewForFinding(
  tx: Prisma.TransactionClient,
  organizationId: string,
  findingId: string,
  reviewId: string,
): Promise<string | null> {
  const rows = await tx.$queryRaw<Array<{ id: string }>>`
    SELECT "id"::text AS "id"
    FROM "risk_calculation_review"
    WHERE "organization_id" = ${organizationId}::uuid
      AND "finding_id" = ${findingId}::uuid
      AND "id" = ${reviewId}::uuid
  `;
  const id = normalizeUuid(rows[0]?.id);
  return rows.length === 1 && id === reviewId ? id : null;
}

async function loadActor(
  tx: Prisma.TransactionClient,
  organizationId: string,
  membershipId: string,
  actorUserId: string,
): Promise<string | null> {
  const rows = await tx.$queryRaw<Array<{ user_id: string }>>`
    SELECT "user_id"::text AS "user_id"
    FROM "membership"
    WHERE "organization_id" = ${organizationId}::uuid
      AND "id" = ${membershipId}::uuid
      AND "user_id" = ${actorUserId}::uuid
      AND "status" = 'active'::"membership_status"
  `;
  const userId = normalizeUuid(rows[0]?.user_id);
  if (rows.length !== 1 || userId !== actorUserId) {
    return null;
  }
  return userId;
}

async function lockFinding(
  tx: Prisma.TransactionClient,
  organizationId: string,
  findingId: string,
): Promise<boolean> {
  const rows = await tx.$queryRaw<Array<{ id: string }>>`
    SELECT "id"::text AS "id"
    FROM "finding"
    WHERE "organization_id" = ${organizationId}::uuid
      AND "id" = ${findingId}::uuid
    FOR UPDATE
  `;
  return rows.length === 1 && normalizeUuid(rows[0]?.id) === findingId;
}

async function lockTransactionScope(tx: Prisma.TransactionClient, lockKey: string): Promise<void> {
  const locked = await tx.$queryRaw<Array<{ locked: number }>>`
    SELECT 1::int AS "locked"
    FROM (
      SELECT pg_advisory_xact_lock(hashtextextended(${lockKey}, 0))
    ) AS taken
  `;
  if (locked.length !== 1) {
    throw new PersistenceAbort('internal_failure');
  }
}

async function readDatabaseClock(
  tx: Prisma.TransactionClient,
): Promise<{ readonly createdAt: Date; readonly expiresLimit: Date }> {
  const rows = await tx.$queryRaw<
    Array<{ created_at: Date | string; expires_limit: Date | string }>
  >`
    SELECT
      CURRENT_TIMESTAMP AS "created_at",
      CURRENT_TIMESTAMP + INTERVAL '180 days' AS "expires_limit"
  `;
  const createdAt = readTimestamp(rows[0]?.created_at);
  const expiresLimit = readTimestamp(rows[0]?.expires_limit);
  if (
    rows.length !== 1 ||
    createdAt === 'invalid' ||
    createdAt === null ||
    expiresLimit === 'invalid' ||
    expiresLimit === null
  ) {
    throw new PersistenceAbort('internal_failure');
  }
  return { createdAt, expiresLimit };
}

function readTimestamp(value: Date | string | null | undefined): Date | null | 'invalid' {
  if (value === null || value === undefined) {
    return null;
  }
  const parsed = value instanceof Date ? value : new Date(value);
  if (!Number.isFinite(parsed.getTime())) {
    return 'invalid';
  }
  return parsed;
}

function isDecision(value: string): value is PriorityReviewDecision {
  return value === 'accepted' || value === 'corrected' || value === 'withdrawn';
}

function isBand(value: string | null): value is RecordPriorityReviewCommand['correctedBand'] {
  return value === null || value === 'P1' || value === 'P2' || value === 'P3' || value === 'P4';
}

function isUuid(value: string): boolean {
  return UUID_LOWER.test(value);
}

function normalizeUuid(value: string | null | undefined): string | null {
  if (value === null || value === undefined) {
    return null;
  }
  const normalized = value.trim().toLowerCase();
  return UUID_LOWER.test(normalized) ? normalized : null;
}

function isUniqueViolation(error: unknown): boolean {
  return (
    sqlState(error) === '23505' ||
    (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002')
  );
}

function isCheckViolation(error: unknown): boolean {
  return sqlState(error) === '23514';
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
