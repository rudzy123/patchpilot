/**
 * Session 12 Batch 7 PostgreSQL adapters for OSV runtime coordination.
 *
 * Durable authority only: request/run ensure, lease fencing, stage attempts,
 * and retry inspection. No retry execution, scheduler, provider I/O, parser,
 * object storage, catalog activation, Findings, or production composition.
 *
 * Retry eligibility is inspection only. Session 12 Batch 8 must recheck
 * ownership, run state, and prior-attempt terminal identity in the same
 * transaction that reserves the next ordinal. Inspection is not dispatch
 * authority. Adapters perform one insert or one guarded update per command
 * and do not retry serialization internally.
 */

import { Prisma, type PrismaClient } from '@prisma/client';
import {
  absentOsvRuntimeLeaseProjection,
  compareOsvRuntimePersistedAttemptIdentity,
  compareOsvRuntimePersistedAttemptTerminal,
  compareOsvRuntimePersistedRequest,
  compareOsvRuntimePersistedRun,
  createOsvRuntimeLeaseOwnershipProofForOwner,
  digestOsvRuntimeHolderToken,
  maxTotalAttemptsForStage,
  nextOsvRuntimeAttemptOrdinal,
  nominalDelayMsForAttemptOrdinal,
  OSV_RUNTIME_LEASE_SCOPE_IDENTIFIER,
  osvRuntimeAttemptTransitionAllowed,
  paginationPolicyIdentifierForReason,
  readOsvRuntimeAcquireSecretForOwner,
  readOsvRuntimeHolderTokenForOwner,
  osvRuntimeRunTerminalStates,
  osvRuntimeRunTransitionAllowed,
  type OsvRuntimeCoordinationPersistencePort,
  type OsvRuntimeCoordinationRejectionCode,
  type OsvRuntimeCoordinationResult,
  type OsvRuntimeEnsureAttemptResult,
  type OsvRuntimeEnsureRequestResult,
  type OsvRuntimeEnsureRunResult,
  type OsvRuntimeLeaseAcquirePersistenceCommand,
  type OsvRuntimeLeaseAcquireResult,
  type OsvRuntimeLeaseHeartbeatCommand,
  type OsvRuntimeLeaseOwnershipProof,
  type OsvRuntimeLeaseOwnershipQuery,
  type OsvRuntimeLeaseProjection,
  type OsvRuntimeLeaseReleaseCommand,
  type OsvRuntimeOwnershipInspection,
  type OsvRuntimePersistedStageAttempt,
  type OsvRuntimePersistedSynchronizationRequest,
  type OsvRuntimeRetryEligibilityInspection,
  type OsvRuntimeRetryEligibilityQuery,
  type OsvRuntimeRunTransitionCommand,
  type OsvRuntimeRunTransitionResult,
  type OsvRuntimeStageAttemptReserveCommand,
  type OsvRuntimeStageAttemptStartCommand,
  type OsvRuntimeStageAttemptTerminalCommand,
  type OsvRuntimeSynchronizationRequestEnsureCommand,
  type OsvRuntimeSynchronizationRunEnsureCommand,
} from '@patchpilot/vulnerability-intelligence';

import {
  classifyUniqueConflict,
  isUniqueViolation,
  tokensInclude,
  translateRuntimeCoordinationFailure,
} from './osv-runtime-coordination-errors.js';
import {
  coerceAttemptRow,
  coerceLeaseRow,
  coerceRunRow,
  holderDigestOf,
  mapAttempt,
  mapLeaseProjection,
  mapRequest,
  mapRun,
  bigintToLeaseInteger,
  OsvRuntimeCoordinationMappingError,
  type AttemptRow,
  type LeaseRow,
  type RequestRow,
  type RunRow,
} from './osv-runtime-coordination-mappers.js';
import { isRootPrismaClient, type PrismaClientLike } from './guards.js';

const ROOT_CLIENT_REQUIRED =
  'OSV runtime coordination persistence requires the root database client.';
const LEASE_TTL_SQL = Prisma.sql`INTERVAL '900000 milliseconds'`;

export type OsvRuntimeCoordinationPersistenceAdapters = OsvRuntimeCoordinationPersistencePort;

type OsvRuntimeRequestRepository = OsvRuntimeCoordinationPersistencePort['requests'];
type OsvRuntimeRunRepository = OsvRuntimeCoordinationPersistencePort['runs'];
type OsvRuntimeLeaseRepository = OsvRuntimeCoordinationPersistencePort['leases'];
type OsvRuntimeAttemptRepository = OsvRuntimeCoordinationPersistencePort['attempts'];

export function createOsvRuntimeCoordinationPersistence(
  client: PrismaClient,
): OsvRuntimeCoordinationPersistenceAdapters {
  if (client === null || client === undefined || !isRootPrismaClient(client)) {
    throw new OsvRuntimeCoordinationPersistenceFailure(ROOT_CLIENT_REQUIRED);
  }
  return createOsvRuntimeCoordinationPersistenceForClient(client);
}

export function createOsvRuntimeCoordinationPersistenceForClient(
  client: PrismaClientLike,
): OsvRuntimeCoordinationPersistenceAdapters {
  return {
    requests: new PrismaOsvRuntimeRequestRepository(client),
    runs: new PrismaOsvRuntimeRunRepository(client),
    leases: new PrismaOsvRuntimeLeaseRepository(client),
    attempts: new PrismaOsvRuntimeAttemptRepository(client),
  };
}

class OsvRuntimeCoordinationPersistenceFailure extends Error {
  public constructor(message: string) {
    super(message);
    this.name = 'OsvRuntimeCoordinationPersistenceFailure';
  }
}

function firstLease(rows: readonly unknown[]): LeaseRow | undefined {
  const raw = rows[0];
  if (raw === undefined || raw === null || typeof raw !== 'object') {
    return undefined;
  }
  return coerceLeaseRow(raw as Record<string, unknown>);
}

function firstRun(rows: readonly unknown[]): RunRow | undefined {
  const raw = rows[0];
  if (raw === undefined || raw === null || typeof raw !== 'object') {
    return undefined;
  }
  return coerceRunRow(raw as Record<string, unknown>);
}

function firstAttempt(rows: readonly unknown[]): AttemptRow | undefined {
  const raw = rows[0];
  if (raw === undefined || raw === null || typeof raw !== 'object') {
    return undefined;
  }
  return coerceAttemptRow(raw as Record<string, unknown>);
}

async function runInTransaction<T>(
  client: PrismaClientLike,
  fn: (tx: PrismaClientLike) => Promise<T>,
): Promise<T> {
  if (isRootPrismaClient(client)) {
    return client.$transaction(async (tx) => fn(tx));
  }
  return fn(client);
}

function fail(code: OsvRuntimeCoordinationRejectionCode): OsvRuntimeCoordinationResult<never> {
  return { ok: false, code };
}

function mapCaught(error: unknown): OsvRuntimeCoordinationResult<never> {
  if (error instanceof OsvRuntimeCoordinationMappingError) {
    return fail('invalid_field');
  }
  return fail(translateRuntimeCoordinationFailure(error));
}

function isLeaseNaturalKey(tokens: readonly string[]): boolean {
  return tokensInclude(tokens, ['scope']);
}

async function loadRequestByIdempotency(
  client: PrismaClientLike,
  command: OsvRuntimeSynchronizationRequestEnsureCommand,
): Promise<RequestRow | null> {
  const identity = command.idempotency;
  if (identity.requestKind === 'operator_request' && identity.operatorRequestId !== null) {
    return client.osvRuntimeSynchronizationRequest.findUnique({
      where: { operatorRequestId: identity.operatorRequestId },
    });
  }
  if (identity.requestKind === 'scheduler_window' && identity.schedulerWindowId !== null) {
    const rows = await client.osvRuntimeSynchronizationRequest.findMany({
      where: {
        schedulerWindowId: identity.schedulerWindowId,
        workScope: identity.workScope,
        synchronizationReason: identity.reason,
        versionSetFingerprint: identity.versionSetFingerprint,
        requestKind: 'scheduler_window',
      },
      take: 2,
    });
    if (rows.length > 1) {
      throw new OsvRuntimeCoordinationMappingError('scheduler request identity is not unique.');
    }
    return rows[0] ?? null;
  }
  return null;
}

function requestCreateData(command: OsvRuntimeSynchronizationRequestEnsureCommand) {
  const payload = command.payload;
  const identity = command.idempotency;
  return {
    jobType: payload.jobType,
    jobSchemaVersion: payload.jobSchemaVersion,
    synchronizationReason: payload.synchronizationReason,
    workScope: payload.workScope,
    leaseScope: payload.leaseScope,
    catalogScope: payload.catalogScope,
    versionSetFingerprint: payload.versionSetFingerprint,
    requestedAt: new Date(payload.requestedAt),
    correlationId: payload.correlationId,
    canaryPolicyIdentifier: payload.canaryPolicyIdentifier ?? null,
    requestKind: identity.requestKind,
    schedulerWindowId: identity.schedulerWindowId,
    operatorRequestId: identity.operatorRequestId,
    requestState: command.requestState,
  };
}

class PrismaOsvRuntimeRequestRepository implements OsvRuntimeRequestRepository {
  public constructor(private readonly client: PrismaClientLike) {}

  public async ensure(
    command: OsvRuntimeSynchronizationRequestEnsureCommand,
  ): Promise<OsvRuntimeCoordinationResult<OsvRuntimeEnsureRequestResult>> {
    try {
      const created = await this.client.osvRuntimeSynchronizationRequest.create({
        data: requestCreateData(command),
      });
      return {
        ok: true,
        value: { status: 'created', request: mapRequest(created) },
      };
    } catch (error) {
      if (isUniqueViolation(error)) {
        return this.reloadRequest(command);
      }
      return mapCaught(error);
    }
  }

  private async reloadRequest(
    command: OsvRuntimeSynchronizationRequestEnsureCommand,
  ): Promise<OsvRuntimeCoordinationResult<OsvRuntimeEnsureRequestResult>> {
    try {
      const existing = await loadRequestByIdempotency(this.client, command);
      if (existing === null) {
        return fail('not_found');
      }
      const mapped = mapRequest(existing);
      const comparison = compareOsvRuntimePersistedRequest(mapped, command);
      if (comparison === 'immutable_conflict') {
        return fail('immutable_conflict');
      }
      return { ok: true, value: { status: 'already_applied', request: mapped } };
    } catch (error) {
      return mapCaught(error);
    }
  }
}

class PrismaOsvRuntimeRunRepository implements OsvRuntimeRunRepository {
  public constructor(private readonly client: PrismaClientLike) {}

  public async ensure(
    command: OsvRuntimeSynchronizationRunEnsureCommand,
  ): Promise<OsvRuntimeCoordinationResult<OsvRuntimeEnsureRunResult>> {
    try {
      const request = await this.client.osvRuntimeSynchronizationRequest.findUnique({
        where: { id: command.requestId },
      });
      if (request === null) {
        return fail('not_found');
      }
      const mappedRequest = mapRequest(request);
      const paginationPolicy = paginationPolicyIdentifierForReason(
        mappedRequest.synchronizationReason,
      );
      try {
        const inserted = await this.client.$queryRaw<unknown[]>`
          INSERT INTO "osv_runtime_synchronization_run" (
            "request_id",
            "work_scope",
            "lease_scope",
            "synchronization_reason",
            "pagination_policy_identifier",
            "version_set_fingerprint",
            "runtime_architecture_identifier",
            "synchronization_algorithm_identifier",
            "retry_policy_identifier",
            "state",
            "created_at",
            "updated_at"
          )
          VALUES (
            ${mappedRequest.id}::uuid,
            ${mappedRequest.workScope}::"osv_runtime_work_scope",
            ${mappedRequest.leaseScope},
            ${mappedRequest.synchronizationReason}::"osv_runtime_synchronization_reason",
            ${paginationPolicy},
            ${mappedRequest.versionSetFingerprint},
            'osv_runtime_enablement_architecture_v1',
            'osv_catalog_sync_algorithm_v1',
            'osv_runtime_retry_policy_v1',
            'planned',
            CURRENT_TIMESTAMP,
            CURRENT_TIMESTAMP
          )
          ON CONFLICT ("request_id") DO NOTHING
          RETURNING *
        `;
        const created = firstRun(inserted);
        if (created !== undefined) {
          return { ok: true, value: { status: 'created', run: mapRun(created) } };
        }
        return this.reloadRun(mappedRequest);
      } catch (error) {
        if (isUniqueViolation(error)) {
          return this.reloadRun(mappedRequest);
        }
        return mapCaught(error);
      }
    } catch (error) {
      return mapCaught(error);
    }
  }

  public async transition(
    command: OsvRuntimeRunTransitionCommand,
  ): Promise<OsvRuntimeCoordinationResult<OsvRuntimeRunTransitionResult>> {
    try {
      if (!osvRuntimeRunTransitionAllowed(command.expectedState, command.nextState)) {
        return fail('state_conflict');
      }
      const requiresOwnership =
        command.nextState === 'running' ||
        command.nextState === 'retry_wait' ||
        command.nextState === 'completed';
      if (requiresOwnership && command.proof === null) {
        return fail('invalid_field');
      }
      return await runInTransaction(this.client, async (tx) => {
        if (requiresOwnership && command.proof !== null) {
          const ownership = await inspectOwnership(tx, command.proof, command.runId);
          if (!ownership.ok) {
            return ownership;
          }
          if (!ownership.value.authorized) {
            return fail('ownership_conflict');
          }
        }
        const updated = await transitionRunRow(tx, command);
        if (updated === null) {
          return this.reloadTransition(tx, command);
        }
        return {
          ok: true,
          value: { status: 'transitioned', run: mapRun(updated) },
        };
      });
    } catch (error) {
      return mapCaught(error);
    }
  }

  private async reloadRun(
    request: OsvRuntimePersistedSynchronizationRequest,
  ): Promise<OsvRuntimeCoordinationResult<OsvRuntimeEnsureRunResult>> {
    const existing = await this.client.osvRuntimeSynchronizationRun.findUnique({
      where: { requestId: request.id },
    });
    if (existing === null) {
      return fail('not_found');
    }
    const mapped = mapRun(existing);
    const comparison = compareOsvRuntimePersistedRun(mapped, request);
    if (comparison === 'immutable_conflict') {
      return fail('immutable_conflict');
    }
    return { ok: true, value: { status: 'already_applied', run: mapped } };
  }

  private async reloadTransition(
    tx: PrismaClientLike,
    command: OsvRuntimeRunTransitionCommand,
  ): Promise<OsvRuntimeCoordinationResult<OsvRuntimeRunTransitionResult>> {
    const existing = await tx.osvRuntimeSynchronizationRun.findUnique({
      where: { id: command.runId },
    });
    if (existing === null) {
      return fail('not_found');
    }
    const mapped = mapRun(existing);
    if (mapped.state !== command.nextState) {
      return fail('state_conflict');
    }
    const sameTerminal =
      mapped.terminalCode === command.terminalCode &&
      mapped.retryDisposition === command.retryDisposition &&
      mapped.lastAcceptedStage === command.lastAcceptedStage &&
      mapped.cancellationBoundary === command.cancellationBoundary;
    if (!sameTerminal) {
      return fail('immutable_conflict');
    }
    return { ok: true, value: { status: 'already_applied', run: mapped } };
  }
}

async function transitionRunRow(
  tx: PrismaClientLike,
  command: OsvRuntimeRunTransitionCommand,
): Promise<RunRow | null> {
  const next = command.nextState;
  const terminal =
    next === 'halted' || next === 'cancelled' || next === 'failed' || next === 'completed';
  const rows = await tx.$queryRaw<RunRow[]>`
    UPDATE "osv_runtime_synchronization_run"
    SET
      "state" = ${next}::"osv_runtime_run_state",
      "started_at" = CASE
        WHEN ${next}::text IN ('running', 'retry_wait', 'completed', 'failed')
          AND "started_at" IS NULL THEN CURRENT_TIMESTAMP
        ELSE "started_at"
      END,
      "terminal_at" = CASE
        WHEN ${terminal} THEN CURRENT_TIMESTAMP
        ELSE NULL
      END,
      "terminal_code" = ${command.terminalCode},
      "retry_disposition" = ${command.retryDisposition}::"osv_runtime_retry_eligibility",
      "last_accepted_stage" = ${command.lastAcceptedStage}::"osv_runtime_retryable_stage",
      "cancellation_boundary" = ${command.cancellationBoundary},
      "updated_at" = CURRENT_TIMESTAMP
    WHERE "id" = ${command.runId}::uuid
      AND "state" = ${command.expectedState}::"osv_runtime_run_state"
    RETURNING *
  `;
  return firstRun(rows) ?? null;
}

function attachProof(input: {
  readonly runId: string;
  readonly holderToken: string;
  readonly projection: OsvRuntimeLeaseProjection;
}): OsvRuntimeCoordinationResult<OsvRuntimeLeaseOwnershipProof> {
  if (
    input.projection.acquiredAt === null ||
    input.projection.heartbeatAt === null ||
    input.projection.expiresAt === null
  ) {
    return fail('invalid_field');
  }
  return createOsvRuntimeLeaseOwnershipProofForOwner({
    scope: OSV_RUNTIME_LEASE_SCOPE_IDENTIFIER,
    runId: input.runId,
    holderToken: input.holderToken,
    leaseRevision: input.projection.leaseRevision,
    fencingToken: input.projection.fencingToken,
    acquiredAt: input.projection.acquiredAt,
    heartbeatAt: input.projection.heartbeatAt,
    expiresAt: input.projection.expiresAt,
  });
}

async function loadLease(client: PrismaClientLike): Promise<LeaseRow | null> {
  return client.osvRuntimeLeaseProjection.findUnique({
    where: { scope: OSV_RUNTIME_LEASE_SCOPE_IDENTIFIER },
  });
}

async function inspectOwnership(
  client: PrismaClientLike,
  proof: OsvRuntimeLeaseOwnershipProof,
  expectedRunId: string,
): Promise<OsvRuntimeCoordinationResult<OsvRuntimeOwnershipInspection>> {
  const loaded = await loadLeaseWithDatabaseTime(client);
  if (loaded === null) {
    return { ok: true, value: { status: 'absent', authorized: false } };
  }
  const { row, unexpired } = loaded;
  if (row.state === 'released') {
    return { ok: true, value: { status: 'released', authorized: false } };
  }
  const presented = readOsvRuntimeHolderTokenForOwner(proof);
  if (presented === null) {
    return { ok: true, value: { status: 'lost', authorized: false } };
  }
  const digest = digestOsvRuntimeHolderToken(presented);
  if (!digest.ok) {
    return digest;
  }
  if (proof.scope !== row.scope || proof.scope !== OSV_RUNTIME_LEASE_SCOPE_IDENTIFIER) {
    return { ok: true, value: { status: 'policy_mismatch', authorized: false } };
  }
  if (proof.runId !== expectedRunId || row.runId !== expectedRunId) {
    return { ok: true, value: { status: 'lost', authorized: false } };
  }
  if (digest.value !== holderDigestOf(row)) {
    return { ok: true, value: { status: 'lost', authorized: false } };
  }
  if (proof.fencingToken !== mapLeaseProjection(row).fencingToken) {
    return { ok: true, value: { status: 'lost', authorized: false } };
  }
  if (!unexpired) {
    return { ok: true, value: { status: 'expired', authorized: false } };
  }
  return { ok: true, value: { status: 'current', authorized: true } };
}

async function loadLeaseWithDatabaseTime(
  client: PrismaClientLike,
): Promise<{ readonly row: LeaseRow; readonly unexpired: boolean } | null> {
  const rows = await client.$queryRaw<Array<Record<string, unknown>>>`
    SELECT
      *,
      (CURRENT_TIMESTAMP < "expires_at") AS "ownership_current"
    FROM "osv_runtime_lease_projection"
    WHERE "scope" = ${OSV_RUNTIME_LEASE_SCOPE_IDENTIFIER}
  `;
  const raw = rows[0];
  if (raw === undefined) {
    return null;
  }
  return {
    row: coerceLeaseRow(raw),
    unexpired: asSqlBoolean(raw['ownership_current'] ?? raw['ownershipCurrent']),
  };
}

function asSqlBoolean(value: unknown): boolean {
  return value === true || value === 't' || value === 'true';
}

class PrismaOsvRuntimeLeaseRepository implements OsvRuntimeLeaseRepository {
  public constructor(private readonly client: PrismaClientLike) {}

  public async acquire(
    command: OsvRuntimeLeaseAcquirePersistenceCommand,
  ): Promise<OsvRuntimeCoordinationResult<OsvRuntimeLeaseAcquireResult>> {
    try {
      const holderToken = readOsvRuntimeAcquireSecretForOwner(command.secret);
      if (holderToken === null) {
        return fail('invalid_holder_token');
      }
      const digest = digestOsvRuntimeHolderToken(holderToken);
      if (!digest.ok) {
        return digest;
      }
      return await runInTransaction(this.client, async (tx) => {
        const run = await tx.osvRuntimeSynchronizationRun.findUnique({
          where: { id: command.runId },
        });
        if (run === null) {
          return fail('not_found');
        }
        if (run.leaseScope !== OSV_RUNTIME_LEASE_SCOPE_IDENTIFIER) {
          return fail('invalid_scope');
        }
        if ((osvRuntimeRunTerminalStates as readonly string[]).includes(run.state)) {
          return fail('state_conflict');
        }
        const current = await loadLease(tx);
        if (current === null) {
          const inserted = await insertHeldLease(tx, command.runId, digest.value);
          if (inserted === null) {
            const winner = await loadLease(tx);
            if (winner === null) {
              return fail('database_unavailable');
            }
            return heldByOtherOrSameOwner(winner, command.runId, holderToken, digest.value);
          }
          return acquiredOutcome('acquired', inserted, holderToken);
        }
        return mutateExistingLease(tx, current, command, holderToken, digest.value);
      });
    } catch (error) {
      if (
        isUniqueViolation(error) &&
        classifyUniqueConflict(error, isLeaseNaturalKey) !== 'unrelated'
      ) {
        return fail('ownership_conflict');
      }
      return mapCaught(error);
    }
  }

  public async heartbeat(command: OsvRuntimeLeaseHeartbeatCommand): Promise<
    OsvRuntimeCoordinationResult<{
      readonly outcome:
        'accepted' | 'ownership_lost' | 'expired' | 'invalid_request' | 'database_unavailable';
      readonly projection: OsvRuntimeLeaseProjection;
      readonly proof: OsvRuntimeLeaseOwnershipProof | null;
    }>
  > {
    try {
      const presented = readOsvRuntimeHolderTokenForOwner(command.proof);
      if (presented === null) {
        return fail('invalid_holder_token');
      }
      const digest = digestOsvRuntimeHolderToken(presented);
      if (!digest.ok) {
        return digest;
      }
      return await runInTransaction(this.client, async (tx) => {
        const updated = await tx.$queryRaw<LeaseRow[]>`
          UPDATE "osv_runtime_lease_projection"
          SET
            "heartbeat_at" = CURRENT_TIMESTAMP,
            "expires_at" = CURRENT_TIMESTAMP + ${LEASE_TTL_SQL},
            "row_revision" = "row_revision" + 1,
            "updated_at" = CURRENT_TIMESTAMP
          WHERE "scope" = ${OSV_RUNTIME_LEASE_SCOPE_IDENTIFIER}
            AND "run_id" = ${command.proof.runId}::uuid
            AND "holder_token_digest" = ${digest.value}
            AND "row_revision" = ${BigInt(command.proof.leaseRevision)}
            AND "fencing_token" = ${BigInt(command.proof.fencingToken)}
            AND "state" = 'held'
            AND CURRENT_TIMESTAMP < "expires_at"
          RETURNING *
        `;
        const row = firstLease(updated);
        if (row !== undefined) {
          const projection = mapLeaseProjection(row);
          const proof = attachProof({
            runId: command.proof.runId,
            holderToken: presented,
            projection,
          });
          if (!proof.ok) {
            return proof;
          }
          return {
            ok: true,
            value: { outcome: 'accepted' as const, projection, proof: proof.value },
          };
        }
        const current = await loadLease(tx);
        if (current === null) {
          return {
            ok: true,
            value: {
              outcome: 'ownership_lost' as const,
              projection: mapAbsentProjection(),
              proof: null,
            },
          };
        }
        const projection = mapLeaseProjection(current);
        if (current.state !== 'held') {
          return {
            ok: true,
            value: { outcome: 'ownership_lost' as const, projection, proof: null },
          };
        }
        const timed = await loadLeaseWithDatabaseTime(tx);
        const sameOwner =
          current.runId === command.proof.runId && holderDigestOf(current) === digest.value;
        if (timed === null || !timed.unexpired) {
          if (sameOwner) {
            return { ok: true, value: { outcome: 'expired' as const, projection, proof: null } };
          }
          return {
            ok: true,
            value: { outcome: 'ownership_lost' as const, projection, proof: null },
          };
        }
        return {
          ok: true,
          value: { outcome: 'ownership_lost' as const, projection, proof: null },
        };
      });
    } catch (error) {
      return mapCaught(error);
    }
  }

  public async release(command: OsvRuntimeLeaseReleaseCommand): Promise<
    OsvRuntimeCoordinationResult<{
      readonly outcome:
        | 'released'
        | 'already_released'
        | 'stale_owner'
        | 'wrong_revision'
        | 'wrong_fencing_token'
        | 'invalid_request'
        | 'database_unavailable';
      readonly projection: OsvRuntimeLeaseProjection;
    }>
  > {
    try {
      const presented = readOsvRuntimeHolderTokenForOwner(command.proof);
      if (presented === null) {
        return fail('invalid_holder_token');
      }
      const digest = digestOsvRuntimeHolderToken(presented);
      if (!digest.ok) {
        return digest;
      }
      return await runInTransaction(this.client, async (tx) => {
        const current = await loadLease(tx);
        if (current === null) {
          return {
            ok: true,
            value: { outcome: 'stale_owner' as const, projection: mapAbsentProjection() },
          };
        }
        const projection = mapLeaseProjection(current);
        if (current.state === 'released') {
          if (
            current.releaseReason === command.reason &&
            current.runId === command.proof.runId &&
            holderDigestOf(current) === digest.value
          ) {
            return { ok: true, value: { outcome: 'already_released' as const, projection } };
          }
          if (holderDigestOf(current) !== digest.value || current.runId !== command.proof.runId) {
            return { ok: true, value: { outcome: 'stale_owner' as const, projection } };
          }
          return { ok: true, value: { outcome: 'invalid_request' as const, projection } };
        }
        if (holderDigestOf(current) !== digest.value || current.runId !== command.proof.runId) {
          return { ok: true, value: { outcome: 'stale_owner' as const, projection } };
        }
        if (projection.leaseRevision !== command.proof.leaseRevision) {
          return { ok: true, value: { outcome: 'wrong_revision' as const, projection } };
        }
        if (projection.fencingToken !== command.proof.fencingToken) {
          return { ok: true, value: { outcome: 'wrong_fencing_token' as const, projection } };
        }
        const updated = await tx.$queryRaw<LeaseRow[]>`
          UPDATE "osv_runtime_lease_projection"
          SET
            "state" = 'released',
            "released_at" = CURRENT_TIMESTAMP,
            "release_reason" = ${command.reason}::"osv_runtime_lease_release_reason",
            "row_revision" = "row_revision" + 1,
            "fencing_token" = "fencing_token" + 1,
            "updated_at" = CURRENT_TIMESTAMP
          WHERE "scope" = ${OSV_RUNTIME_LEASE_SCOPE_IDENTIFIER}
            AND "run_id" = ${command.proof.runId}::uuid
            AND "holder_token_digest" = ${digest.value}
            AND "row_revision" = ${BigInt(command.proof.leaseRevision)}
            AND "fencing_token" = ${BigInt(command.proof.fencingToken)}
            AND "state" = 'held'
            AND CURRENT_TIMESTAMP < "expires_at"
          RETURNING *
        `;
        const row = firstLease(updated);
        if (row === undefined) {
          return { ok: true, value: { outcome: 'stale_owner' as const, projection } };
        }
        return {
          ok: true,
          value: { outcome: 'released' as const, projection: mapLeaseProjection(row) },
        };
      });
    } catch (error) {
      return mapCaught(error);
    }
  }

  public async validateOwnership(
    query: OsvRuntimeLeaseOwnershipQuery,
  ): Promise<OsvRuntimeCoordinationResult<OsvRuntimeOwnershipInspection>> {
    try {
      return await inspectOwnership(this.client, query.proof, query.expectedRunId);
    } catch (error) {
      const translated = translateRuntimeCoordinationFailure(error);
      if (translated === 'database_unavailable') {
        return { ok: true, value: { status: 'database_unavailable', authorized: false } };
      }
      return mapCaught(error);
    }
  }
}

function mapAbsentProjection(): OsvRuntimeLeaseProjection {
  return absentOsvRuntimeLeaseProjection();
}

async function insertHeldLease(
  tx: PrismaClientLike,
  runId: string,
  digest: string,
): Promise<LeaseRow | null> {
  const rows = await tx.$queryRaw<LeaseRow[]>`
    INSERT INTO "osv_runtime_lease_projection" (
      "scope",
      "run_id",
      "holder_token_digest",
      "row_revision",
      "fencing_token",
      "state",
      "acquired_at",
      "heartbeat_at",
      "expires_at",
      "released_at",
      "release_reason",
      "created_at",
      "updated_at"
    )
    VALUES (
      ${OSV_RUNTIME_LEASE_SCOPE_IDENTIFIER},
      ${runId}::uuid,
      ${digest},
      1,
      1,
      'held',
      CURRENT_TIMESTAMP,
      CURRENT_TIMESTAMP,
      CURRENT_TIMESTAMP + ${LEASE_TTL_SQL},
      NULL,
      NULL,
      CURRENT_TIMESTAMP,
      CURRENT_TIMESTAMP
    )
    ON CONFLICT ("scope") DO NOTHING
    RETURNING *
  `;
  const raw = rows[0];
  return raw === undefined ? null : coerceLeaseRow(raw as unknown as Record<string, unknown>);
}

async function mutateExistingLease(
  tx: PrismaClientLike,
  current: LeaseRow,
  command: OsvRuntimeLeaseAcquirePersistenceCommand,
  holderToken: string,
  digest: string,
): Promise<OsvRuntimeCoordinationResult<OsvRuntimeLeaseAcquireResult>> {
  const timed = await loadLeaseWithDatabaseTime(tx);
  const expired = current.state === 'held' && (timed === null || !timed.unexpired);
  if (current.state === 'held' && !expired) {
    return heldByOtherOrSameOwner(current, command.runId, holderToken, digest);
  }
  let expectedRevision = command.expectedLeaseRevision ?? bigintToString(current.rowRevision);
  let expectedFencing = command.expectedFencingToken ?? bigintToString(current.fencingToken);
  if (
    expectedRevision !== bigintToString(current.rowRevision) ||
    expectedFencing !== bigintToString(current.fencingToken)
  ) {
    return {
      ok: true,
      value: {
        outcome: 'held_by_other',
        projection: mapLeaseProjection(current),
        proof: null,
      },
    };
  }
  const takeover = current.state === 'held';
  // Batch 6-R trigger treats held→held with the same run and digest as a
  // heartbeat, so fencing cannot increment on that path. Expired same-owner
  // acquire is a new ownership generation: bump fencing through released then
  // held in this one transaction. Public release() still rejects expired owners.
  if (takeover && current.runId === command.runId && holderDigestOf(current) === digest) {
    const bumped = await tx.$queryRaw<LeaseRow[]>`
      UPDATE "osv_runtime_lease_projection"
      SET
        "state" = 'released',
        "released_at" = CURRENT_TIMESTAMP,
        "release_reason" = 'shutdown'::"osv_runtime_lease_release_reason",
        "row_revision" = "row_revision" + 1,
        "fencing_token" = "fencing_token" + 1,
        "updated_at" = CURRENT_TIMESTAMP
      WHERE "scope" = ${OSV_RUNTIME_LEASE_SCOPE_IDENTIFIER}
        AND "run_id" = ${command.runId}::uuid
        AND "holder_token_digest" = ${digest}
        AND "row_revision" = ${BigInt(expectedRevision)}
        AND "fencing_token" = ${BigInt(expectedFencing)}
        AND "state" = 'held'
        AND CURRENT_TIMESTAMP >= "expires_at"
      RETURNING *
    `;
    const released = firstLease(bumped);
    if (released === undefined) {
      const winner = await loadLease(tx);
      if (winner === null) {
        return fail('database_unavailable');
      }
      return {
        ok: true,
        value: {
          outcome: 'held_by_other',
          projection: mapLeaseProjection(winner),
          proof: null,
        },
      };
    }
    expectedRevision = bigintToString(released.rowRevision);
    expectedFencing = bigintToString(released.fencingToken);
  }
  const updated = await tx.$queryRaw<LeaseRow[]>`
    UPDATE "osv_runtime_lease_projection"
    SET
      "run_id" = ${command.runId}::uuid,
      "holder_token_digest" = ${digest},
      "row_revision" = "row_revision" + 1,
      "fencing_token" = "fencing_token" + 1,
      "state" = 'held',
      "acquired_at" = CURRENT_TIMESTAMP,
      "heartbeat_at" = CURRENT_TIMESTAMP,
      "expires_at" = CURRENT_TIMESTAMP + ${LEASE_TTL_SQL},
      "released_at" = NULL,
      "release_reason" = NULL,
      "updated_at" = CURRENT_TIMESTAMP
    WHERE "scope" = ${OSV_RUNTIME_LEASE_SCOPE_IDENTIFIER}
      AND "row_revision" = ${BigInt(expectedRevision)}
      AND "fencing_token" = ${BigInt(expectedFencing)}
      AND (
        ("state" = 'held' AND CURRENT_TIMESTAMP >= "expires_at")
        OR "state" = 'released'
      )
    RETURNING *
  `;
  const row = firstLease(updated);
  if (row === undefined) {
    const winner = await loadLease(tx);
    if (winner === null) {
      return fail('database_unavailable');
    }
    return {
      ok: true,
      value: {
        outcome: 'held_by_other',
        projection: mapLeaseProjection(winner),
        proof: null,
      },
    };
  }
  return acquiredOutcome(takeover ? 'stale_takeover_acquired' : 'acquired', row, holderToken);
}

function bigintToString(value: bigint | number | string): string {
  return bigintToLeaseInteger(value);
}

function expectedNextAttemptOrdinal(
  prior: readonly {
    readonly attemptOrdinal: number;
    readonly state: string;
    readonly retryDisposition: string;
  }[],
): 1 | 2 | 3 | null {
  if (prior.length === 0) {
    return 1;
  }
  for (const [index, row] of prior.entries()) {
    if (row.attemptOrdinal !== index + 1) {
      return null;
    }
  }
  const latest = prior[prior.length - 1];
  if (latest === undefined) {
    return 1;
  }
  if (latest.state !== 'retryable_failed' || latest.retryDisposition !== 'durable_retry') {
    return null;
  }
  const next = latest.attemptOrdinal + 1;
  if (next !== 2 && next !== 3) {
    return null;
  }
  return next;
}

function heldByOtherOrSameOwner(
  current: LeaseRow,
  runId: string,
  holderToken: string,
  digest: string,
): OsvRuntimeCoordinationResult<OsvRuntimeLeaseAcquireResult> {
  const projection = mapLeaseProjection(current);
  if (current.state === 'held' && current.runId === runId && holderDigestOf(current) === digest) {
    const proof = attachProof({ runId, holderToken, projection });
    if (!proof.ok) {
      return proof;
    }
    return {
      ok: true,
      value: {
        outcome: 'already_held_by_same_owner',
        projection,
        proof: proof.value,
      },
    };
  }
  return {
    ok: true,
    value: { outcome: 'held_by_other', projection, proof: null },
  };
}

function acquiredOutcome(
  outcome: 'acquired' | 'stale_takeover_acquired',
  row: LeaseRow,
  holderToken: string,
): OsvRuntimeCoordinationResult<OsvRuntimeLeaseAcquireResult> {
  const projection = mapLeaseProjection(row);
  const proof = attachProof({ runId: row.runId, holderToken, projection });
  if (!proof.ok) {
    return proof;
  }
  return { ok: true, value: { outcome, projection, proof: proof.value } };
}

class PrismaOsvRuntimeAttemptRepository implements OsvRuntimeAttemptRepository {
  public constructor(private readonly client: PrismaClientLike) {}

  public async reserve(
    command: OsvRuntimeStageAttemptReserveCommand,
  ): Promise<OsvRuntimeCoordinationResult<OsvRuntimeEnsureAttemptResult>> {
    try {
      return await runInTransaction(this.client, async (tx) => {
        const run = await tx.osvRuntimeSynchronizationRun.findUnique({
          where: { id: command.runId },
        });
        if (run === null) {
          return fail('not_found');
        }
        if (run.versionSetFingerprint !== command.versionSetFingerprint) {
          return fail('caller_fingerprint_rejected');
        }
        if ((osvRuntimeRunTerminalStates as readonly string[]).includes(run.state)) {
          return fail('state_conflict');
        }
        const maximum = maxTotalAttemptsForStage(command.stage);
        if (command.stage === 'inventory_convergence' && command.attemptOrdinal !== 1) {
          return fail('invalid_attempt_ordinal');
        }
        if (maximum !== 0 && command.attemptOrdinal > maximum) {
          return fail('invalid_attempt_ordinal');
        }
        const prior = await tx.osvRuntimeStageAttempt.findMany({
          where: {
            runId: command.runId,
            stage: command.stage,
            targetIdentityDigest: command.targetIdentityDigest,
          },
          orderBy: { attemptOrdinal: 'asc' },
          take: 4,
        });
        if (prior.length > 3) {
          return fail('state_conflict');
        }
        const existing = prior.find((row) => row.attemptOrdinal === command.attemptOrdinal);
        if (existing !== undefined) {
          const mapped = mapAttempt(existing);
          const comparison = compareOsvRuntimePersistedAttemptIdentity(mapped, command);
          if (comparison === 'immutable_conflict') {
            return fail('immutable_conflict');
          }
          return { ok: true, value: { status: 'already_applied', attempt: mapped } };
        }
        if (prior.some((row) => row.state === 'exhausted' || row.retryExhausted)) {
          return fail('retry_exhausted');
        }
        if (
          prior.some(
            (row) =>
              row.state === 'permanent_failed' ||
              row.state === 'cancelled' ||
              row.state === 'succeeded',
          )
        ) {
          return fail('state_conflict');
        }
        if (prior.some((row) => row.state === 'planned' || row.state === 'running')) {
          return fail('state_conflict');
        }
        const expectedOrdinal = expectedNextAttemptOrdinal(prior);
        if (expectedOrdinal === null || command.attemptOrdinal !== expectedOrdinal) {
          return fail('invalid_attempt_ordinal');
        }
        try {
          const created = await tx.osvRuntimeStageAttempt.create({
            data: {
              runId: command.runId,
              stage: command.stage,
              targetIdentityDigest: command.targetIdentityDigest,
              attemptOrdinal: command.attemptOrdinal,
              retryPolicyIdentifier: 'osv_runtime_retry_policy_v1',
              state: 'planned',
              retryDisposition: command.retryDisposition,
              nominalDelayMs: nominalDelayMsForAttemptOrdinal(command.attemptOrdinal),
              selectedDelayMs: command.selectedDelayMs,
              retryExhausted: false,
              versionSetFingerprint: command.versionSetFingerprint,
            },
          });
          return { ok: true, value: { status: 'created', attempt: mapAttempt(created) } };
        } catch (error) {
          if (isUniqueViolation(error)) {
            return this.reloadAttempt(tx, command);
          }
          return mapCaught(error);
        }
      });
    } catch (error) {
      return mapCaught(error);
    }
  }

  public async start(command: OsvRuntimeStageAttemptStartCommand): Promise<
    OsvRuntimeCoordinationResult<{
      status: 'already_applied' | 'transitioned';
      attempt: OsvRuntimePersistedStageAttempt;
    }>
  > {
    try {
      return await runInTransaction(this.client, async (tx) => {
        const run = await tx.osvRuntimeSynchronizationRun.findUnique({
          where: { id: command.runId },
        });
        if (run === null) {
          return fail('not_found');
        }
        if ((osvRuntimeRunTerminalStates as readonly string[]).includes(run.state)) {
          return fail('state_conflict');
        }
        const updated = await tx.$queryRaw<AttemptRow[]>`
          UPDATE "osv_runtime_stage_attempt"
          SET
            "state" = 'running',
            "started_at" = CURRENT_TIMESTAMP
          WHERE "run_id" = ${command.runId}::uuid
            AND "stage" = ${command.stage}::"osv_runtime_retryable_stage"
            AND "attempt_ordinal" = ${command.attemptOrdinal}
            AND ${targetPredicate(command.targetIdentityDigest)}
            AND "state" = 'planned'
          RETURNING *
        `;
        const row = firstAttempt(updated);
        if (row !== undefined) {
          return { ok: true, value: { status: 'transitioned', attempt: mapAttempt(row) } };
        }
        return this.reloadStart(tx, command);
      });
    } catch (error) {
      return mapCaught(error);
    }
  }

  public async recordTerminal(command: OsvRuntimeStageAttemptTerminalCommand): Promise<
    OsvRuntimeCoordinationResult<{
      status: 'already_applied' | 'transitioned';
      attempt: OsvRuntimePersistedStageAttempt;
    }>
  > {
    try {
      const remaining = nextOsvRuntimeAttemptOrdinal(command.attemptOrdinal, command.stage);
      const exhaustRetryable = command.terminalState === 'retryable_failed' && remaining === null;
      const terminalState = exhaustRetryable ? 'exhausted' : command.terminalState;
      if (!osvRuntimeAttemptTransitionAllowed(command.expectedState, terminalState)) {
        return fail('state_conflict');
      }
      const retryExhausted = terminalState === 'exhausted';
      const retryDisposition =
        terminalState === 'succeeded' || terminalState === 'cancelled'
          ? 'no_retry'
          : terminalState === 'exhausted'
            ? 'retry_exhausted'
            : terminalState === 'retryable_failed'
              ? 'durable_retry'
              : 'no_retry';
      const retryDelayMs = terminalState === 'retryable_failed' ? command.retryDelayMs : null;
      const updated = await this.client.$queryRaw<AttemptRow[]>`
        UPDATE "osv_runtime_stage_attempt"
        SET
          "state" = ${terminalState}::"osv_runtime_attempt_state",
          "started_at" = CASE
            WHEN "started_at" IS NULL AND ${terminalState}::text <> 'cancelled'
              THEN CURRENT_TIMESTAMP
            ELSE "started_at"
          END,
          "terminal_at" = CURRENT_TIMESTAMP,
          "failure_code" = ${command.failureCode},
          "failure_catalog" = ${command.failureCatalog},
          "retry_disposition" = ${retryDisposition}::"osv_runtime_retry_eligibility",
          "retry_exhausted" = ${retryExhausted},
          "retry_not_before" = CASE
            WHEN ${retryDelayMs}::integer IS NULL THEN NULL
            ELSE CURRENT_TIMESTAMP + (${retryDelayMs}::integer * INTERVAL '1 millisecond')
          END
        WHERE "run_id" = ${command.runId}::uuid
          AND "stage" = ${command.stage}::"osv_runtime_retryable_stage"
          AND "attempt_ordinal" = ${command.attemptOrdinal}
          AND ${targetPredicate(command.targetIdentityDigest)}
          AND "state" = ${command.expectedState}::"osv_runtime_attempt_state"
        RETURNING *
      `;
      const row = firstAttempt(updated);
      if (row !== undefined) {
        return { ok: true, value: { status: 'transitioned', attempt: mapAttempt(row) } };
      }
      return this.reloadTerminal(command, exhaustRetryable);
    } catch (error) {
      return mapCaught(error);
    }
  }

  public async inspectRetryEligibility(
    query: OsvRuntimeRetryEligibilityQuery,
  ): Promise<OsvRuntimeCoordinationResult<OsvRuntimeRetryEligibilityInspection>> {
    try {
      const attempts = await this.client.osvRuntimeStageAttempt.findMany({
        where: {
          runId: query.runId,
          stage: query.stage,
          targetIdentityDigest: query.targetIdentityDigest,
        },
        orderBy: { attemptOrdinal: 'desc' },
        take: 2,
      });
      if (attempts.length > 1) {
        const latestOrdinal = attempts[0]?.attemptOrdinal;
        const duplicateOrdinal = attempts.filter((row) => row.attemptOrdinal === latestOrdinal);
        if (duplicateOrdinal.length > 1) {
          return fail('state_conflict');
        }
      }
      const latest = attempts[0];
      if (latest === undefined) {
        return { ok: true, value: { status: 'absent', attempt: null } };
      }
      const mapped = mapAttempt(latest);
      if (mapped.state === 'cancelled') {
        return { ok: true, value: { status: 'cancelled', attempt: mapped } };
      }
      if (mapped.state === 'permanent_failed') {
        return { ok: true, value: { status: 'permanent', attempt: mapped } };
      }
      if (mapped.state === 'exhausted' || mapped.retryExhausted) {
        return { ok: true, value: { status: 'exhausted', attempt: mapped } };
      }
      const run = await this.client.osvRuntimeSynchronizationRun.findUnique({
        where: { id: query.runId },
      });
      if (run === null) {
        return { ok: true, value: { status: 'absent', attempt: mapped } };
      }
      if (run.state === 'halted') {
        return { ok: true, value: { status: 'halted', attempt: mapped } };
      }
      if (run.state === 'cancelled') {
        return { ok: true, value: { status: 'cancelled', attempt: mapped } };
      }
      if (run.state === 'failed' || run.state === 'completed') {
        return { ok: true, value: { status: 'permanent', attempt: mapped } };
      }
      if (mapped.state !== 'retryable_failed' || mapped.retryNotBefore === null) {
        return { ok: true, value: { status: 'policy_mismatch', attempt: mapped } };
      }
      const due = await this.client.$queryRaw<Array<Record<string, unknown>>>`
        SELECT (CURRENT_TIMESTAMP >= "retry_not_before") AS "retry_due"
        FROM "osv_runtime_stage_attempt"
        WHERE "id" = ${mapped.id}::uuid
      `;
      const dueFlag = due[0]?.['retry_due'] ?? due[0]?.['retryDue'];
      if (!asSqlBoolean(dueFlag)) {
        return { ok: true, value: { status: 'too_early', attempt: mapped } };
      }
      if (query.proof === null) {
        return { ok: true, value: { status: 'ownership_lost', attempt: mapped } };
      }
      const ownership = await inspectOwnership(this.client, query.proof, query.runId);
      if (!ownership.ok) {
        return ownership;
      }
      if (!ownership.value.authorized) {
        return { ok: true, value: { status: 'ownership_lost', attempt: mapped } };
      }
      return { ok: true, value: { status: 'eligible', attempt: mapped } };
    } catch (error) {
      return mapCaught(error);
    }
  }

  private async reloadAttempt(
    client: PrismaClientLike,
    command: OsvRuntimeStageAttemptReserveCommand,
  ): Promise<OsvRuntimeCoordinationResult<OsvRuntimeEnsureAttemptResult>> {
    const existing = await client.osvRuntimeStageAttempt.findMany({
      where: {
        runId: command.runId,
        stage: command.stage,
        attemptOrdinal: command.attemptOrdinal,
        targetIdentityDigest: command.targetIdentityDigest,
      },
      take: 2,
    });
    if (existing.length > 1) {
      return fail('state_conflict');
    }
    const row = existing[0];
    if (row === undefined) {
      return fail('not_found');
    }
    const mapped = mapAttempt(row);
    const comparison = compareOsvRuntimePersistedAttemptIdentity(mapped, command);
    if (comparison === 'immutable_conflict') {
      return fail('immutable_conflict');
    }
    return { ok: true, value: { status: 'already_applied', attempt: mapped } };
  }

  private async reloadStart(
    client: PrismaClientLike,
    command: OsvRuntimeStageAttemptStartCommand,
  ): Promise<
    OsvRuntimeCoordinationResult<{
      status: 'already_applied' | 'transitioned';
      attempt: OsvRuntimePersistedStageAttempt;
    }>
  > {
    const existing = await client.osvRuntimeStageAttempt.findMany({
      where: {
        runId: command.runId,
        stage: command.stage,
        attemptOrdinal: command.attemptOrdinal,
        targetIdentityDigest: command.targetIdentityDigest,
      },
      take: 2,
    });
    if (existing.length > 1) {
      return fail('state_conflict');
    }
    const row = existing[0];
    if (row === undefined) {
      return fail('not_found');
    }
    const mapped = mapAttempt(row);
    if (mapped.state === 'running') {
      return { ok: true, value: { status: 'already_applied', attempt: mapped } };
    }
    return fail('state_conflict');
  }

  private async reloadTerminal(
    command: OsvRuntimeStageAttemptTerminalCommand,
    expectedExhausted: boolean,
  ): Promise<
    OsvRuntimeCoordinationResult<{
      status: 'already_applied' | 'transitioned';
      attempt: OsvRuntimePersistedStageAttempt;
    }>
  > {
    const existing = await this.client.osvRuntimeStageAttempt.findMany({
      where: {
        runId: command.runId,
        stage: command.stage,
        attemptOrdinal: command.attemptOrdinal,
        targetIdentityDigest: command.targetIdentityDigest,
      },
      take: 2,
    });
    if (existing.length > 1) {
      return fail('state_conflict');
    }
    const row = existing[0];
    if (row === undefined) {
      return fail('not_found');
    }
    const mapped = mapAttempt(row);
    const comparison = compareOsvRuntimePersistedAttemptTerminal(
      mapped,
      command,
      expectedExhausted,
    );
    if (comparison === 'already_applied') {
      return { ok: true, value: { status: 'already_applied', attempt: mapped } };
    }
    return fail('immutable_conflict');
  }
}

function targetPredicate(digest: string | null): Prisma.Sql {
  if (digest === null) {
    return Prisma.sql`"target_identity_digest" IS NULL`;
  }
  return Prisma.sql`"target_identity_digest" = ${digest}`;
}
