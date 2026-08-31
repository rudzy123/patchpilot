import { Prisma } from '@prisma/client';
import {
  JSON_SCHEMA_VERSION_V1,
  SBOM_UPLOAD_IDEMPOTENCY_RESPONSE_SCHEMA_VERSION,
  err,
  ok,
  type FinalizeIdempotencyInput,
  type HashFreeIdempotencyReservationInput,
  type IdempotencyReservationRecord,
  type ReserveStartedResult,
  type ResolveCompletedReplayInput,
  type ResolveCompletedReplayResult,
  type Result,
  type SbomUploadIdempotencyPort,
  type SbomUploadIdempotencyResponseIds,
} from '@patchpilot/domain';

import type { PrismaClientLike } from './guards.js';
import { asJsonObject, isUuid, requireSha256 } from './guards.js';

export class PrismaSbomUploadIdempotency implements SbomUploadIdempotencyPort {
  public constructor(private readonly client: PrismaClientLike) {}

  public async reserveStarted(
    input: HashFreeIdempotencyReservationInput,
  ): Promise<ReserveStartedResult> {
    const organizationId = input.organizationId;
    const scope = input.scope;
    const keyHash = requireSha256(input.keyHash, 'keyHash');
    const reservationFingerprint = requireSha256(
      input.reservationFingerprint,
      'reservationFingerprint',
    );

    try {
      const row = await this.client.idempotencyRecord.create({
        data: {
          organizationId,
          scope,
          keyHash,
          requestFingerprint: reservationFingerprint,
          status: 'started',
          expiresAt: input.expiresAt,
        },
      });
      return { kind: 'acquired', record: mapReservation(row) };
    } catch (error) {
      if (!isUniqueViolation(error)) {
        throw error;
      }
    }

    const existing = await this.client.idempotencyRecord.findFirst({
      where: { organizationId, scope, keyHash },
    });
    if (existing === null) {
      throw new Error('Idempotency reservation conflict could not be loaded.');
    }

    const now = new Date();
    if (existing.status === 'completed') {
      return { kind: 'completed', record: mapReservation(existing) };
    }
    if (existing.status === 'conflict') {
      return { kind: 'conflict', record: mapReservation(existing) };
    }
    if (existing.status === 'started' && existing.expiresAt > now) {
      if (existing.requestFingerprint !== reservationFingerprint) {
        return { kind: 'conflict', record: mapReservation(existing) };
      }
      return { kind: 'unexpired_started', record: mapReservation(existing) };
    }
    if (existing.status === 'started' && existing.expiresAt <= now) {
      return { kind: 'reclaimable_expired', record: mapReservation(existing) };
    }
    return { kind: 'conflict', record: mapReservation(existing) };
  }

  public async findUnexpiredStarted(
    input: HashFreeIdempotencyReservationInput,
  ): Promise<IdempotencyReservationRecord | undefined> {
    const row = await this.client.idempotencyRecord.findFirst({
      where: {
        organizationId: input.organizationId,
        scope: input.scope,
        keyHash: requireSha256(input.keyHash, 'keyHash'),
        status: 'started',
        expiresAt: { gt: new Date() },
      },
    });
    return row === null ? undefined : mapReservation(row);
  }

  public async reclaimExpiredStarted(
    input: HashFreeIdempotencyReservationInput,
  ): Promise<Result<IdempotencyReservationRecord>> {
    const rows = await this.client.$queryRaw<IdempotencyRow[]>`
      UPDATE "idempotency_record"
      SET
        "request_fingerprint" = ${requireSha256(input.reservationFingerprint, 'reservationFingerprint')},
        "expires_at" = ${input.expiresAt},
        "status" = 'started',
        "response" = NULL,
        "response_status" = NULL,
        "completed_at" = NULL
      WHERE "organization_id" = ${input.organizationId}::uuid
        AND "scope" = ${input.scope}
        AND "key_hash" = ${requireSha256(input.keyHash, 'keyHash')}
        AND "status" = 'started'
        AND "expires_at" <= CURRENT_TIMESTAMP
      RETURNING
        "id",
        "organization_id" AS "organizationId",
        "scope",
        "key_hash" AS "keyHash",
        "request_fingerprint" AS "requestFingerprint",
        "status",
        "response_status" AS "responseStatus",
        "response",
        "created_at" AS "createdAt",
        "expires_at" AS "expiresAt",
        "completed_at" AS "completedAt"
    `;
    const row = rows[0];
    if (row === undefined) {
      return err({
        code: 'conflict',
        message: 'Expired idempotency reservation was not reclaimed.',
      });
    }
    return ok(mapReservation(row));
  }

  public async finalizeCompleted(
    input: FinalizeIdempotencyInput,
  ): Promise<Result<IdempotencyReservationRecord>> {
    const response = asJsonObject(
      {
        schemaVersion: input.response.schemaVersion,
        sbomId: input.response.sbomId,
        ingestionId: input.response.ingestionId,
      },
      'response',
    );
    const completedAt = new Date();
    const rows = await this.client.$queryRaw<IdempotencyRow[]>`
      UPDATE "idempotency_record"
      SET
        "status" = 'completed',
        "request_fingerprint" = ${requireSha256(input.finalFingerprint, 'finalFingerprint')},
        "response" = ${response}::jsonb,
        "response_status" = ${input.responseStatus},
        "completed_at" = ${completedAt}
      WHERE "organization_id" = ${input.organizationId}::uuid
        AND "scope" = ${input.scope}
        AND "key_hash" = ${requireSha256(input.keyHash, 'keyHash')}
        AND "status" = 'started'
        AND "request_fingerprint" = ${requireSha256(input.reservationFingerprint, 'reservationFingerprint')}
      RETURNING
        "id",
        "organization_id" AS "organizationId",
        "scope",
        "key_hash" AS "keyHash",
        "request_fingerprint" AS "requestFingerprint",
        "status",
        "response_status" AS "responseStatus",
        "response",
        "created_at" AS "createdAt",
        "expires_at" AS "expiresAt",
        "completed_at" AS "completedAt"
    `;
    const row = rows[0];
    if (row === undefined) {
      return err({
        code: 'conflict',
        message: 'Idempotency reservation could not be finalized.',
      });
    }
    return ok(mapReservation(row));
  }

  public async resolveCompletedReplay(
    input: ResolveCompletedReplayInput,
  ): Promise<Result<ResolveCompletedReplayResult>> {
    if (!isUuid(input.organizationId)) {
      return err({
        code: 'not_found',
        message: 'Completed idempotency reservation was not found.',
      });
    }
    const row = await this.client.idempotencyRecord.findFirst({
      where: {
        organizationId: input.organizationId,
        scope: input.scope,
        keyHash: requireSha256(input.keyHash, 'keyHash'),
        status: 'completed',
      },
    });
    if (row === null) {
      return err({
        code: 'not_found',
        message: 'Completed idempotency reservation was not found.',
      });
    }
    if (row.requestFingerprint !== requireSha256(input.finalFingerprint, 'finalFingerprint')) {
      return ok({ kind: 'fingerprint_mismatch' });
    }
    if (row.responseStatus === null || row.response === null) {
      return err({ code: 'internal', message: 'Completed idempotency response is missing.' });
    }
    return ok({
      kind: 'replay',
      response: readResponseIds(row.response),
      responseStatus: row.responseStatus,
    });
  }
}

type IdempotencyRow = {
  id: string;
  organizationId: string;
  scope: string;
  keyHash: string;
  requestFingerprint: string;
  status: 'started' | 'completed' | 'conflict';
  responseStatus: number | null;
  response: unknown;
  createdAt: Date;
  expiresAt: Date;
  completedAt: Date | null;
};

function mapReservation(row: IdempotencyRow): IdempotencyReservationRecord {
  const completed = row.status === 'completed';
  return {
    id: row.id,
    organizationId: row.organizationId,
    scope: row.scope,
    keyHash: row.keyHash,
    reservationFingerprint: row.requestFingerprint,
    status: row.status,
    expiresAt: row.expiresAt,
    completedAt: row.completedAt,
    response: completed && row.response !== null ? readResponseIds(row.response) : null,
    finalFingerprint: completed ? row.requestFingerprint : null,
  };
}

function readResponseIds(value: unknown): SbomUploadIdempotencyResponseIds {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Idempotency response must be a JSON object.');
  }
  const record = value as Record<string, unknown>;
  const schemaVersion = record['schemaVersion'];
  const sbomId = record['sbomId'];
  const ingestionId = record['ingestionId'];
  if (
    schemaVersion !== SBOM_UPLOAD_IDEMPOTENCY_RESPONSE_SCHEMA_VERSION &&
    schemaVersion !== JSON_SCHEMA_VERSION_V1
  ) {
    throw new Error('Idempotency response schemaVersion is not supported.');
  }
  if (typeof sbomId !== 'string' || typeof ingestionId !== 'string') {
    throw new Error('Idempotency response must include opaque sbom and ingestion ids.');
  }
  return {
    schemaVersion: SBOM_UPLOAD_IDEMPOTENCY_RESPONSE_SCHEMA_VERSION,
    sbomId,
    ingestionId,
  };
}

function isUniqueViolation(error: unknown): boolean {
  return error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002';
}
