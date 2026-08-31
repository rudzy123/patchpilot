import { Prisma } from '@prisma/client';
import {
  err,
  ok,
  type ClaimOutboxBatchInput,
  type ClaimableOutboxEvent,
  type ClaimedOutboxEvent,
  type ExpireOutboxLeaseInput,
  type MarkOutboxProcessedInput,
  type OutboxDeadLetterInput,
  type OutboxDeliveryFailureInput,
  type OutboxEventRecord,
  type OutboxRelayPersistencePort,
  type Result,
} from '@patchpilot/domain';

import { isRootPrismaClient, type PrismaClientLike } from './guards.js';
import { mapOutboxEvent } from './mappers.js';

export class PrismaOutboxRelayPersistence implements OutboxRelayPersistencePort {
  public constructor(private readonly client: PrismaClientLike) {}

  public async claimDueBatch(input: ClaimOutboxBatchInput): Promise<readonly ClaimedOutboxEvent[]> {
    const limit = boundClaimLimit(input.limit);
    if (limit < 1) {
      return [];
    }

    return this.runInTransaction(async (tx) => {
      const pending = await tx.$queryRaw<Array<{ id: string }>>`
        SELECT "id"
        FROM "outbox_event"
        WHERE "status" = 'pending'
          AND "available_at" <= ${input.now}
        ORDER BY "available_at" ASC, "id" ASC
        LIMIT ${limit}
        FOR UPDATE SKIP LOCKED
      `;
      const remaining = limit - pending.length;
      const expired =
        remaining > 0
          ? await tx.$queryRaw<Array<{ id: string }>>`
              SELECT "id"
              FROM "outbox_event"
              WHERE "status" = 'claimed'
                AND "lease_expires_at" < ${input.now}
              ORDER BY "available_at" ASC, "id" ASC
              LIMIT ${remaining}
              FOR UPDATE SKIP LOCKED
            `
          : [];
      const ids = [...pending, ...expired].map((row) => row.id);
      if (ids.length === 0) {
        return [];
      }

      const claimed = await tx.$queryRaw<ClaimedRow[]>`
        UPDATE "outbox_event"
        SET
          "status" = 'claimed',
          "claimed_at" = ${input.now},
          "lease_expires_at" = ${input.leaseExpiresAt},
          "attempt_count" = "attempt_count" + 1
        WHERE "id" IN (${Prisma.join(ids.map((id) => Prisma.sql`${id}::uuid`))})
        RETURNING
          "id",
          "organization_id" AS "organizationId",
          "aggregate_type" AS "aggregateType",
          "aggregate_id" AS "aggregateId",
          "event_type" AS "eventType",
          "dedupe_key" AS "dedupeKey",
          "available_at" AS "availableAt",
          "attempt_count" AS "attemptCount",
          "claimed_at" AS "claimedAt",
          "lease_expires_at" AS "leaseExpiresAt"
      `;
      const byId = new Map(claimed.map((row) => [row.id, row]));
      const ordered: ClaimedOutboxEvent[] = [];
      for (const id of ids) {
        const row = byId.get(id);
        if (row === undefined || row.claimedAt === null || row.leaseExpiresAt === null) {
          continue;
        }
        ordered.push({
          id: row.id,
          organizationId: row.organizationId,
          aggregateType: row.aggregateType,
          aggregateId: row.aggregateId,
          eventType: row.eventType,
          dedupeKey: row.dedupeKey,
          availableAt: row.availableAt,
          attemptCount: row.attemptCount,
          eventId: row.id,
          claimedAt: row.claimedAt,
          leaseExpiresAt: row.leaseExpiresAt,
        });
      }
      return ordered;
    });
  }

  public async expireLease(input: ExpireOutboxLeaseInput): Promise<Result<void>> {
    const updated = await this.client.outboxEvent.updateMany({
      where: {
        id: input.eventId,
        ...organizationWhere(input.organizationId),
        status: 'claimed',
        leaseExpiresAt: { lt: input.now },
      },
      data: {
        status: 'pending',
        claimedAt: null,
        leaseExpiresAt: null,
      },
    });
    if (updated.count === 0) {
      return err({ code: 'conflict', message: 'Outbox lease was not expired.' });
    }
    return ok(undefined);
  }

  public async markProcessedAfterQueueAcceptance(
    input: MarkOutboxProcessedInput,
  ): Promise<Result<OutboxEventRecord>> {
    const updated = await this.client.outboxEvent.updateMany({
      where: {
        id: input.eventId,
        ...organizationWhere(input.organizationId),
        status: 'claimed',
      },
      data: {
        status: 'processed',
        processedAt: input.acceptedAt,
      },
    });
    if (updated.count === 0) {
      return err({ code: 'conflict', message: 'Outbox event was not marked processed.' });
    }
    return this.loadEvent(input.organizationId, input.eventId);
  }

  public async markRetryableDeliveryFailure(
    input: OutboxDeliveryFailureInput,
  ): Promise<Result<OutboxEventRecord>> {
    const updated = await this.client.outboxEvent.updateMany({
      where: {
        id: input.eventId,
        ...organizationWhere(input.organizationId),
        status: 'claimed',
      },
      data: {
        status: 'pending',
        claimedAt: null,
        leaseExpiresAt: null,
        availableAt: input.availableAt,
        lastFailureCategory: input.failureCategory,
        lastFailureCode: input.failureCode,
      },
    });
    if (updated.count === 0) {
      return err({ code: 'conflict', message: 'Outbox event was not marked for retry.' });
    }
    return this.loadEvent(input.organizationId, input.eventId);
  }

  public async markDeadLetter(input: OutboxDeadLetterInput): Promise<Result<OutboxEventRecord>> {
    const updated = await this.client.outboxEvent.updateMany({
      where: {
        id: input.eventId,
        ...organizationWhere(input.organizationId),
        status: { in: ['claimed', 'pending', 'failed'] },
      },
      data: {
        status: 'dead_lettered',
        claimedAt: null,
        leaseExpiresAt: null,
        lastFailureCategory: input.failureCategory,
        lastFailureCode: input.failureCode,
      },
    });
    if (updated.count === 0) {
      return err({ code: 'conflict', message: 'Outbox event was not dead-lettered.' });
    }
    return this.loadEvent(input.organizationId, input.eventId);
  }

  public async listProcessedAwaitingBackgroundJob(input: {
    limit: number;
  }): Promise<readonly ClaimableOutboxEvent[]> {
    const limit = boundClaimLimit(input.limit);
    if (limit < 1) {
      return [];
    }

    const rows = await this.client.$queryRaw<AwaitingRow[]>`
      SELECT
        o."id",
        o."organization_id" AS "organizationId",
        o."aggregate_type" AS "aggregateType",
        o."aggregate_id" AS "aggregateId",
        o."event_type" AS "eventType",
        o."dedupe_key" AS "dedupeKey",
        o."available_at" AS "availableAt",
        o."attempt_count" AS "attemptCount"
      FROM "outbox_event" o
      WHERE o."status" = 'processed'
        AND NOT EXISTS (
          SELECT 1
          FROM "background_job" b
          WHERE b."outbox_event_id" = o."id"
        )
      ORDER BY o."processed_at" ASC, o."id" ASC
      LIMIT ${limit}
    `;
    return rows.map((row) => ({
      id: row.id,
      organizationId: row.organizationId,
      aggregateType: row.aggregateType,
      aggregateId: row.aggregateId,
      eventType: row.eventType,
      dedupeKey: row.dedupeKey,
      availableAt: row.availableAt,
      attemptCount: row.attemptCount,
    }));
  }

  private async loadEvent(
    organizationId: string | null,
    eventId: string,
  ): Promise<Result<OutboxEventRecord>> {
    const row = await this.client.outboxEvent.findFirst({
      where: { id: eventId, ...organizationWhere(organizationId) },
    });
    if (row === null) {
      return err({ code: 'not_found', message: 'Outbox event was not found.' });
    }
    return ok(mapOutboxEvent(row));
  }

  private async runInTransaction<T>(work: (client: PrismaClientLike) => Promise<T>): Promise<T> {
    if (isRootPrismaClient(this.client)) {
      return this.client.$transaction(async (tx) => work(tx));
    }
    return work(this.client);
  }
}

type ClaimedRow = {
  id: string;
  organizationId: string | null;
  aggregateType: string;
  aggregateId: string;
  eventType: string;
  dedupeKey: string;
  availableAt: Date;
  attemptCount: number;
  claimedAt: Date | null;
  leaseExpiresAt: Date | null;
};

type AwaitingRow = {
  id: string;
  organizationId: string | null;
  aggregateType: string;
  aggregateId: string;
  eventType: string;
  dedupeKey: string;
  availableAt: Date;
  attemptCount: number;
};

export function organizationWhere(
  organizationId: string | null,
): { organizationId: string | null } | { organizationId: string } {
  if (organizationId === null) {
    return { organizationId: null };
  }
  return { organizationId };
}

function boundClaimLimit(limit: number): number {
  if (!Number.isInteger(limit) || limit < 1) {
    return 0;
  }
  if (limit > 100) {
    return 100;
  }
  return limit;
}
