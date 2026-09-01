import { Prisma } from '@prisma/client';
import {
  err,
  ok,
  type BackgroundJobExecutionClaim,
  type BackgroundJobExecutionPort,
  type BackgroundJobLease,
  type BackgroundJobRecord,
  type ClaimBackgroundJobInput,
  type LookupBackgroundJobByIdInput,
  type LookupBackgroundJobByOutboxInput,
  type LookupTerminalBackgroundJobInput,
  type QueueBackgroundJobInput,
  type QueuedBackgroundJob,
  type RenewBackgroundJobLeaseInput,
  type Result,
  type RetryBackgroundJobInput,
  type SucceedBackgroundJobInput,
  type TerminalBackgroundJobFailureInput,
} from '@patchpilot/domain';

import type { PrismaClientLike } from './guards.js';
import { organizationWhere } from './outbox-relay-persistence.js';

const TERMINAL_JOB_STATUSES = ['succeeded', 'failed', 'dead_lettered', 'cancelled'] as const;

export class PrismaBackgroundJobExecution implements BackgroundJobExecutionPort {
  public constructor(private readonly client: PrismaClientLike) {}

  public async enqueueQueued(input: QueueBackgroundJobInput): Promise<QueuedBackgroundJob> {
    try {
      const row = await this.client.backgroundJob.create({
        data: {
          organizationId: input.organizationId,
          outboxEventId: input.outboxEventId,
          jobType: input.jobType,
          status: 'queued',
        },
      });
      return toQueued(row);
    } catch (error) {
      if (!isUniqueViolation(error)) {
        throw error;
      }
    }

    const existing = await this.client.backgroundJob.findUnique({
      where: { outboxEventId: input.outboxEventId },
    });
    if (existing === null) {
      throw new Error('Background job unique conflict could not be loaded.');
    }
    return toQueued(existing);
  }

  public async findByOutboxEventId(
    input: LookupBackgroundJobByOutboxInput,
  ): Promise<BackgroundJobRecord | undefined> {
    const row = await this.client.backgroundJob.findFirst({
      where: {
        outboxEventId: input.outboxEventId,
        ...organizationWhere(input.organizationId),
      },
    });
    return row === null ? undefined : mapBackgroundJob(row);
  }

  public async findById(
    input: LookupBackgroundJobByIdInput,
  ): Promise<BackgroundJobRecord | undefined> {
    const row = await this.client.backgroundJob.findFirst({
      where: { id: input.jobId, ...organizationWhere(input.organizationId) },
    });
    return row === null ? undefined : mapBackgroundJob(row);
  }

  public async claimExecution(
    input: ClaimBackgroundJobInput,
  ): Promise<Result<BackgroundJobExecutionClaim>> {
    const rows = await this.client.$queryRaw<ClaimRow[]>`
      UPDATE "background_job"
      SET
        "status" = 'running',
        "worker_identifier" = ${input.workerIdentifier},
        "lease_expires_at" = ${input.leaseExpiresAt},
        "started_at" = COALESCE("started_at", ${input.now}),
        "attempt" = "attempt" + 1
      WHERE "id" = ${input.jobId}::uuid
        AND ${orgPredicate(input.organizationId)}
        AND (
          "status" = 'queued'
          OR ("status" = 'running' AND "lease_expires_at" IS NOT NULL AND "lease_expires_at" < ${input.now})
        )
      RETURNING
        "id" AS "jobId",
        "worker_identifier" AS "workerIdentifier",
        "lease_expires_at" AS "leaseExpiresAt",
        "attempt"
    `;
    const row = rows[0];
    if (row === undefined || row.workerIdentifier === null || row.leaseExpiresAt === null) {
      return err({ code: 'conflict', message: 'Background job was not claimed.' });
    }
    return ok({
      jobId: row.jobId,
      workerIdentifier: row.workerIdentifier,
      leaseExpiresAt: row.leaseExpiresAt,
      attempt: row.attempt,
    });
  }

  public async renewLease(
    input: RenewBackgroundJobLeaseInput,
  ): Promise<Result<BackgroundJobLease>> {
    const updated = await this.client.backgroundJob.updateMany({
      where: {
        id: input.jobId,
        ...organizationWhere(input.organizationId),
        workerIdentifier: input.workerIdentifier,
        status: 'running',
      },
      data: { leaseExpiresAt: input.leaseExpiresAt },
    });
    if (updated.count === 0) {
      return err({ code: 'conflict', message: 'Background job lease was not renewed.' });
    }
    return ok({
      jobId: input.jobId,
      workerIdentifier: input.workerIdentifier,
      leaseExpiresAt: input.leaseExpiresAt,
    });
  }

  public async markRetry(input: RetryBackgroundJobInput): Promise<Result<QueuedBackgroundJob>> {
    const updated = await this.client.backgroundJob.updateMany({
      where: {
        id: input.jobId,
        ...organizationWhere(input.organizationId),
        workerIdentifier: input.workerIdentifier,
        status: 'running',
      },
      data: {
        status: 'queued',
        workerIdentifier: null,
        leaseExpiresAt: null,
        failureCategory: input.failureCategory,
        failureCode: input.failureCode,
      },
    });
    if (updated.count === 0) {
      return err({ code: 'conflict', message: 'Background job was not marked for retry.' });
    }
    const row = await this.client.backgroundJob.findFirst({
      where: { id: input.jobId, ...organizationWhere(input.organizationId) },
    });
    if (row === null) {
      return err({ code: 'not_found', message: 'Background job was not found.' });
    }
    return ok(toQueued(row));
  }

  public async markSucceeded(
    input: SucceedBackgroundJobInput,
  ): Promise<Result<BackgroundJobRecord>> {
    const updated = await this.client.backgroundJob.updateMany({
      where: {
        id: input.jobId,
        ...organizationWhere(input.organizationId),
        workerIdentifier: input.workerIdentifier,
        status: 'running',
      },
      data: {
        status: 'succeeded',
        completedAt: input.completedAt,
        leaseExpiresAt: null,
        failureCategory: null,
        failureCode: null,
      },
    });
    if (updated.count === 0) {
      const terminal = await this.findById({
        organizationId: input.organizationId,
        jobId: input.jobId,
      });
      if (terminal?.status === 'succeeded') {
        return ok(terminal);
      }
      return err({ code: 'conflict', message: 'Background job was not marked succeeded.' });
    }
    const record = await this.findById({
      organizationId: input.organizationId,
      jobId: input.jobId,
    });
    if (record === undefined) {
      return err({ code: 'not_found', message: 'Background job was not found.' });
    }
    return ok(record);
  }

  public async markTerminalFailure(
    input: TerminalBackgroundJobFailureInput,
  ): Promise<Result<BackgroundJobRecord>> {
    const updated = await this.client.backgroundJob.updateMany({
      where: {
        id: input.jobId,
        ...organizationWhere(input.organizationId),
        workerIdentifier: input.workerIdentifier,
        status: 'running',
      },
      data: {
        status: 'failed',
        completedAt: input.completedAt,
        leaseExpiresAt: null,
        failureCategory: input.failureCategory,
        failureCode: input.failureCode,
      },
    });
    if (updated.count === 0) {
      const terminal = await this.findById({
        organizationId: input.organizationId,
        jobId: input.jobId,
      });
      if (terminal?.status === 'failed') {
        return ok(terminal);
      }
      return err({ code: 'conflict', message: 'Background job was not marked failed.' });
    }
    const record = await this.findById({
      organizationId: input.organizationId,
      jobId: input.jobId,
    });
    if (record === undefined) {
      return err({ code: 'not_found', message: 'Background job was not found.' });
    }
    return ok(record);
  }

  public async findIdempotentTerminal(
    input: LookupTerminalBackgroundJobInput,
  ): Promise<BackgroundJobRecord | undefined> {
    const row = await this.client.backgroundJob.findFirst({
      where: {
        ...organizationWhere(input.organizationId),
        jobType: input.jobType,
        status: { in: [...TERMINAL_JOB_STATUSES] },
        outboxEvent: { dedupeKey: input.dedupeKey },
      },
    });
    return row === null ? undefined : mapBackgroundJob(row);
  }
}

type ClaimRow = {
  jobId: string;
  workerIdentifier: string | null;
  leaseExpiresAt: Date | null;
  attempt: number;
};

type JobRow = {
  id: string;
  organizationId: string | null;
  outboxEventId: string | null;
  jobType: string;
  status: BackgroundJobRecord['status'];
  attempt: number;
  startedAt: Date | null;
  leaseExpiresAt: Date | null;
  completedAt: Date | null;
  failureCategory: string | null;
  failureCode: string | null;
  workerIdentifier: string | null;
  createdAt: Date;
};

function toQueued(row: JobRow): QueuedBackgroundJob {
  return {
    id: row.id,
    organizationId: row.organizationId,
    jobType: row.jobType,
    status: 'queued',
    attempt: row.attempt,
  };
}

function mapBackgroundJob(row: JobRow): BackgroundJobRecord {
  return {
    id: row.id,
    organizationId: row.organizationId,
    outboxEventId: row.outboxEventId,
    jobType: row.jobType,
    status: row.status,
    attempt: row.attempt,
    startedAt: row.startedAt,
    leaseExpiresAt: row.leaseExpiresAt,
    completedAt: row.completedAt,
    failureCategory: row.failureCategory,
    failureCode: row.failureCode,
    workerIdentifier: row.workerIdentifier,
    createdAt: row.createdAt,
  };
}

function isUniqueViolation(error: unknown): boolean {
  return error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002';
}

function orgPredicate(organizationId: string | null): Prisma.Sql {
  if (organizationId === null) {
    return Prisma.sql`"organization_id" IS NULL`;
  }
  return Prisma.sql`"organization_id" = ${organizationId}::uuid`;
}
