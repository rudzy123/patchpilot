/**
 * Session 12 Batch 7 mapping from Prisma OSV runtime-coordination rows to
 * Batch 5/7 contracts. Mappers reconstruct records through committed
 * constructors. They never include holder tokens, holder digests, page tokens,
 * provider bodies, tenant fields, or Findings.
 */

import type {
  OsvRuntimeAttemptState,
  OsvRuntimeJobRequestKind,
  OsvRuntimeJobRequestState,
  OsvRuntimeLeaseProjectionState,
  OsvRuntimeLeaseReleaseReason,
  OsvRuntimeRetryableStage,
  OsvRuntimeRetryEligibility,
  OsvRuntimeRunState,
  OsvRuntimeSynchronizationReason,
  OsvRuntimeWorkScope,
} from '@prisma/client';
import {
  createOsvRuntimeLeaseProjection,
  createOsvRuntimePersistedStageAttempt,
  createOsvRuntimePersistedSynchronizationRequest,
  createOsvRuntimePersistedSynchronizationRun,
  type OsvRuntimeCoordinationResult,
  type OsvRuntimeLeaseProjection,
  type OsvRuntimePersistedStageAttempt,
  type OsvRuntimePersistedSynchronizationRequest,
  type OsvRuntimePersistedSynchronizationRun,
} from '@patchpilot/vulnerability-intelligence';

export class OsvRuntimeCoordinationMappingError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = 'OsvRuntimeCoordinationMappingError';
  }
}

export function toIsoUtc(value: Date): string {
  return value.toISOString();
}

export function fromIsoUtc(value: string): Date {
  return new Date(value);
}

export function bigintToLeaseInteger(value: bigint | number | string): string {
  if (typeof value === 'bigint') {
    if (value < 1n) {
      throw new OsvRuntimeCoordinationMappingError('lease integer mapping failed.');
    }
    return value.toString();
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 1) {
      throw new OsvRuntimeCoordinationMappingError('lease integer mapping failed.');
    }
    return BigInt(value).toString();
  }
  if (typeof value === 'string' && /^-?[0-9]+$/.test(value)) {
    const parsed = BigInt(value);
    if (parsed < 1n) {
      throw new OsvRuntimeCoordinationMappingError('lease integer mapping failed.');
    }
    return parsed.toString();
  }
  throw new OsvRuntimeCoordinationMappingError('lease integer mapping failed.');
}

export type RequestRow = {
  readonly id: string;
  readonly jobType: string;
  readonly jobSchemaVersion: string;
  readonly synchronizationReason: OsvRuntimeSynchronizationReason;
  readonly workScope: OsvRuntimeWorkScope;
  readonly leaseScope: string;
  readonly catalogScope: string;
  readonly versionSetFingerprint: string;
  readonly requestedAt: Date;
  readonly correlationId: string;
  readonly canaryPolicyIdentifier: string | null;
  readonly requestKind: OsvRuntimeJobRequestKind;
  readonly schedulerWindowId: string | null;
  readonly operatorRequestId: string | null;
  readonly requestState: OsvRuntimeJobRequestState;
  readonly createdAt: Date;
};

export type RunRow = {
  readonly id: string;
  readonly requestId: string;
  readonly workScope: OsvRuntimeWorkScope;
  readonly leaseScope: string;
  readonly synchronizationReason: OsvRuntimeSynchronizationReason;
  readonly paginationPolicyIdentifier: string;
  readonly versionSetFingerprint: string;
  readonly runtimeArchitectureIdentifier: string;
  readonly synchronizationAlgorithmIdentifier: string;
  readonly retryPolicyIdentifier: string;
  readonly state: OsvRuntimeRunState;
  readonly startedAt: Date | null;
  readonly terminalAt: Date | null;
  readonly terminalCode: string | null;
  readonly retryDisposition: OsvRuntimeRetryEligibility | null;
  readonly lastAcceptedStage: OsvRuntimeRetryableStage | null;
  readonly cancellationBoundary: string | null;
  readonly createdAt: Date;
  readonly updatedAt: Date;
};

export type LeaseRow = {
  readonly scope: string;
  readonly runId: string;
  readonly holderTokenDigest: string;
  readonly rowRevision: bigint | number | string;
  readonly fencingToken: bigint | number | string;
  readonly state: OsvRuntimeLeaseProjectionState;
  readonly acquiredAt: Date;
  readonly heartbeatAt: Date;
  readonly expiresAt: Date;
  readonly releasedAt: Date | null;
  readonly releaseReason: OsvRuntimeLeaseReleaseReason | null;
};

export type AttemptRow = {
  readonly id: string;
  readonly runId: string;
  readonly stage: OsvRuntimeRetryableStage;
  readonly targetIdentityDigest: string | null;
  readonly attemptOrdinal: number;
  readonly retryPolicyIdentifier: string;
  readonly state: OsvRuntimeAttemptState;
  readonly startedAt: Date | null;
  readonly terminalAt: Date | null;
  readonly failureCode: string | null;
  readonly failureCatalog: string | null;
  readonly retryDisposition: OsvRuntimeRetryEligibility;
  readonly nominalDelayMs: number;
  readonly selectedDelayMs: number;
  readonly retryNotBefore: Date | null;
  readonly retryExhausted: boolean;
  readonly versionSetFingerprint: string;
  readonly createdAt: Date;
};

function requireOk<T>(result: OsvRuntimeCoordinationResult<T>, label: string): T {
  if (!result.ok) {
    throw new OsvRuntimeCoordinationMappingError(`${label} mapping failed.`);
  }
  return result.value;
}

export function mapRequest(row: RequestRow): OsvRuntimePersistedSynchronizationRequest {
  return requireOk(
    createOsvRuntimePersistedSynchronizationRequest({
      id: row.id,
      jobType: row.jobType,
      jobSchemaVersion: row.jobSchemaVersion,
      synchronizationReason: row.synchronizationReason,
      workScope: row.workScope,
      leaseScope: row.leaseScope,
      catalogScope: row.catalogScope,
      versionSetFingerprint: row.versionSetFingerprint,
      requestedAt: toIsoUtc(row.requestedAt),
      correlationId: row.correlationId,
      canaryPolicyIdentifier: row.canaryPolicyIdentifier,
      requestKind: row.requestKind,
      schedulerWindowId: row.schedulerWindowId,
      operatorRequestId: row.operatorRequestId,
      requestState: row.requestState,
      createdAt: toIsoUtc(row.createdAt),
    }),
    'request',
  );
}

export function mapRun(row: RunRow): OsvRuntimePersistedSynchronizationRun {
  return requireOk(
    createOsvRuntimePersistedSynchronizationRun({
      id: row.id,
      requestId: row.requestId,
      workScope: row.workScope,
      leaseScope: row.leaseScope,
      synchronizationReason: row.synchronizationReason,
      paginationPolicyIdentifier: row.paginationPolicyIdentifier,
      versionSetFingerprint: row.versionSetFingerprint,
      runtimeArchitectureIdentifier: row.runtimeArchitectureIdentifier,
      synchronizationAlgorithmIdentifier: row.synchronizationAlgorithmIdentifier,
      retryPolicyIdentifier: row.retryPolicyIdentifier,
      state: row.state,
      startedAt: row.startedAt === null ? null : toIsoUtc(row.startedAt),
      terminalAt: row.terminalAt === null ? null : toIsoUtc(row.terminalAt),
      terminalCode: row.terminalCode,
      retryDisposition: row.retryDisposition,
      lastAcceptedStage: row.lastAcceptedStage,
      cancellationBoundary: row.cancellationBoundary,
      createdAt: toIsoUtc(row.createdAt),
      updatedAt: toIsoUtc(row.updatedAt),
    }),
    'run',
  );
}

export function mapLeaseProjection(row: LeaseRow): OsvRuntimeLeaseProjection {
  return requireOk(
    createOsvRuntimeLeaseProjection({
      state: row.state,
      runId: row.runId,
      leaseRevision: bigintToLeaseInteger(row.rowRevision),
      fencingToken: bigintToLeaseInteger(row.fencingToken),
      acquiredAt: toIsoUtc(row.acquiredAt),
      heartbeatAt: toIsoUtc(row.heartbeatAt),
      expiresAt: toIsoUtc(row.expiresAt),
      releasedAt: row.releasedAt === null ? null : toIsoUtc(row.releasedAt),
    }),
    'lease',
  );
}

export function mapAttempt(row: AttemptRow): OsvRuntimePersistedStageAttempt {
  return requireOk(
    createOsvRuntimePersistedStageAttempt({
      id: row.id,
      runId: row.runId,
      stage: row.stage,
      targetIdentityDigest: row.targetIdentityDigest,
      attemptOrdinal: row.attemptOrdinal,
      retryPolicyIdentifier: row.retryPolicyIdentifier,
      state: row.state,
      startedAt: row.startedAt === null ? null : toIsoUtc(row.startedAt),
      terminalAt: row.terminalAt === null ? null : toIsoUtc(row.terminalAt),
      failureCode: row.failureCode,
      failureCatalog: row.failureCatalog,
      retryDisposition: row.retryDisposition,
      nominalDelayMs: row.nominalDelayMs,
      selectedDelayMs: row.selectedDelayMs,
      retryNotBefore: row.retryNotBefore === null ? null : toIsoUtc(row.retryNotBefore),
      retryExhausted: row.retryExhausted,
      versionSetFingerprint: row.versionSetFingerprint,
      createdAt: toIsoUtc(row.createdAt),
    }),
    'attempt',
  );
}

export function holderDigestOf(row: LeaseRow): string {
  return row.holderTokenDigest;
}

function pick(row: Record<string, unknown>, camel: string, snake: string): unknown {
  if (Object.hasOwn(row, camel)) {
    return row[camel];
  }
  return row[snake];
}

function asDate(value: unknown): Date {
  if (value instanceof Date) {
    return value;
  }
  if (typeof value === 'string' || typeof value === 'number') {
    return new Date(value);
  }
  throw new OsvRuntimeCoordinationMappingError('timestamp mapping failed.');
}

function asDateOrNull(value: unknown): Date | null {
  if (value === null || value === undefined) {
    return null;
  }
  return asDate(value);
}

function asString(value: unknown): string {
  if (typeof value === 'string') {
    return value;
  }
  throw new OsvRuntimeCoordinationMappingError('string mapping failed.');
}

function asStringOrNull(value: unknown): string | null {
  if (value === null || value === undefined) {
    return null;
  }
  return asString(value);
}

function asBoolean(value: unknown): boolean {
  if (value === true || value === false) {
    return value;
  }
  if (value === 't' || value === 'true') {
    return true;
  }
  if (value === 'f' || value === 'false') {
    return false;
  }
  throw new OsvRuntimeCoordinationMappingError('boolean mapping failed.');
}

function asNumber(value: unknown): number {
  if (typeof value === 'number' && Number.isSafeInteger(value)) {
    return value;
  }
  if (typeof value === 'bigint') {
    if (value > BigInt(Number.MAX_SAFE_INTEGER) || value < BigInt(Number.MIN_SAFE_INTEGER)) {
      throw new OsvRuntimeCoordinationMappingError('integer mapping failed.');
    }
    return Number(value);
  }
  throw new OsvRuntimeCoordinationMappingError('integer mapping failed.');
}

function asLeaseInteger(value: unknown): bigint | string {
  if (typeof value === 'bigint') {
    if (value < 1n) {
      throw new OsvRuntimeCoordinationMappingError('lease integer mapping failed.');
    }
    return value;
  }
  if (typeof value === 'string' && /^[0-9]+$/.test(value)) {
    const parsed = BigInt(value);
    if (parsed < 1n) {
      throw new OsvRuntimeCoordinationMappingError('lease integer mapping failed.');
    }
    return parsed.toString();
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || value < 1) {
      throw new OsvRuntimeCoordinationMappingError('lease integer mapping failed.');
    }
    return BigInt(value);
  }
  throw new OsvRuntimeCoordinationMappingError('lease integer mapping failed.');
}

export function coerceLeaseRow(row: Record<string, unknown>): LeaseRow {
  return {
    scope: asString(pick(row, 'scope', 'scope')),
    runId: asString(pick(row, 'runId', 'run_id')),
    holderTokenDigest: asString(pick(row, 'holderTokenDigest', 'holder_token_digest')),
    rowRevision: asLeaseInteger(pick(row, 'rowRevision', 'row_revision')),
    fencingToken: asLeaseInteger(pick(row, 'fencingToken', 'fencing_token')),
    state: asString(pick(row, 'state', 'state')) as LeaseRow['state'],
    acquiredAt: asDate(pick(row, 'acquiredAt', 'acquired_at')),
    heartbeatAt: asDate(pick(row, 'heartbeatAt', 'heartbeat_at')),
    expiresAt: asDate(pick(row, 'expiresAt', 'expires_at')),
    releasedAt: asDateOrNull(pick(row, 'releasedAt', 'released_at')),
    releaseReason: asStringOrNull(
      pick(row, 'releaseReason', 'release_reason'),
    ) as LeaseRow['releaseReason'],
  };
}

export function coerceRunRow(row: Record<string, unknown>): RunRow {
  return {
    id: asString(pick(row, 'id', 'id')),
    requestId: asString(pick(row, 'requestId', 'request_id')),
    workScope: asString(pick(row, 'workScope', 'work_scope')) as RunRow['workScope'],
    leaseScope: asString(pick(row, 'leaseScope', 'lease_scope')),
    synchronizationReason: asString(
      pick(row, 'synchronizationReason', 'synchronization_reason'),
    ) as RunRow['synchronizationReason'],
    paginationPolicyIdentifier: asString(
      pick(row, 'paginationPolicyIdentifier', 'pagination_policy_identifier'),
    ),
    versionSetFingerprint: asString(pick(row, 'versionSetFingerprint', 'version_set_fingerprint')),
    runtimeArchitectureIdentifier: asString(
      pick(row, 'runtimeArchitectureIdentifier', 'runtime_architecture_identifier'),
    ),
    synchronizationAlgorithmIdentifier: asString(
      pick(row, 'synchronizationAlgorithmIdentifier', 'synchronization_algorithm_identifier'),
    ),
    retryPolicyIdentifier: asString(pick(row, 'retryPolicyIdentifier', 'retry_policy_identifier')),
    state: asString(pick(row, 'state', 'state')) as RunRow['state'],
    startedAt: asDateOrNull(pick(row, 'startedAt', 'started_at')),
    terminalAt: asDateOrNull(pick(row, 'terminalAt', 'terminal_at')),
    terminalCode: asStringOrNull(pick(row, 'terminalCode', 'terminal_code')),
    retryDisposition: asStringOrNull(
      pick(row, 'retryDisposition', 'retry_disposition'),
    ) as RunRow['retryDisposition'],
    lastAcceptedStage: asStringOrNull(
      pick(row, 'lastAcceptedStage', 'last_accepted_stage'),
    ) as RunRow['lastAcceptedStage'],
    cancellationBoundary: asStringOrNull(
      pick(row, 'cancellationBoundary', 'cancellation_boundary'),
    ),
    createdAt: asDate(pick(row, 'createdAt', 'created_at')),
    updatedAt: asDate(pick(row, 'updatedAt', 'updated_at')),
  };
}

export function coerceAttemptRow(row: Record<string, unknown>): AttemptRow {
  return {
    id: asString(pick(row, 'id', 'id')),
    runId: asString(pick(row, 'runId', 'run_id')),
    stage: asString(pick(row, 'stage', 'stage')) as AttemptRow['stage'],
    targetIdentityDigest: asStringOrNull(
      pick(row, 'targetIdentityDigest', 'target_identity_digest'),
    ),
    attemptOrdinal: asNumber(pick(row, 'attemptOrdinal', 'attempt_ordinal')),
    retryPolicyIdentifier: asString(pick(row, 'retryPolicyIdentifier', 'retry_policy_identifier')),
    state: asString(pick(row, 'state', 'state')) as AttemptRow['state'],
    startedAt: asDateOrNull(pick(row, 'startedAt', 'started_at')),
    terminalAt: asDateOrNull(pick(row, 'terminalAt', 'terminal_at')),
    failureCode: asStringOrNull(pick(row, 'failureCode', 'failure_code')),
    failureCatalog: asStringOrNull(pick(row, 'failureCatalog', 'failure_catalog')),
    retryDisposition: asString(
      pick(row, 'retryDisposition', 'retry_disposition'),
    ) as AttemptRow['retryDisposition'],
    nominalDelayMs: asNumber(pick(row, 'nominalDelayMs', 'nominal_delay_ms')),
    selectedDelayMs: asNumber(pick(row, 'selectedDelayMs', 'selected_delay_ms')),
    retryNotBefore: asDateOrNull(pick(row, 'retryNotBefore', 'retry_not_before')),
    retryExhausted: asBoolean(pick(row, 'retryExhausted', 'retry_exhausted')),
    versionSetFingerprint: asString(pick(row, 'versionSetFingerprint', 'version_set_fingerprint')),
    createdAt: asDate(pick(row, 'createdAt', 'created_at')),
  };
}
