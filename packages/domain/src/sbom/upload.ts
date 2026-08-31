import type { Clock } from '../clock.js';
import { JSON_SCHEMA_VERSION_V1, type OutboxPayloadJson } from '../json-documents.js';
import type { AssetRepository, CreateOutboxEventInput } from '../ports.js';
import { err, ok, type Result } from '../result.js';
import type { SbomIngestionRecord, SbomRecord } from '../records.js';
import {
  session8IngestionStates,
  type Session8IngestionState,
  type SbomIngestionState,
} from '../lifecycle.js';
import { sbomDuplicateAudit, sbomUploadedAudit } from './audit.js';
import {
  authorizeSbomUpload,
  type AuthorizedSbomUploadActor,
  type SbomUploadActor,
} from './authorization.js';
import { fingerprintUploadBody } from './body-fingerprint.js';
import {
  SBOM_APPROVED_CONTENT_TYPES,
  SBOM_INGESTION_REQUESTED_EVENT_TYPE,
  SBOM_UPLOAD_ACCEPTED_STATUS,
  SBOM_UPLOAD_IDEMPOTENCY_RESPONSE_SCHEMA_VERSION,
  type SbomApprovedContentType,
} from './constants.js';
import {
  ASSET_ARCHIVED,
  ASSET_NOT_FOUND,
  isSbomEvidenceConflictError,
  SBOM_UPLOAD_CLIENT_ABORTED,
  SBOM_UPLOAD_IDEMPOTENCY_CONFLICT,
  SBOM_UPLOAD_IN_PROGRESS,
  SBOM_UPLOAD_INTERNAL,
  SBOM_UPLOAD_MISSING_INGESTION,
  SBOM_UPLOAD_POSSIBLE_ORPHAN,
  SBOM_UPLOAD_REPLAY_UNAVAILABLE,
  sbomUploadFailure,
  type SbomUploadFailure,
} from './errors.js';
import {
  hashFinalFingerprint,
  hashReservationFingerprint,
  resolveIdempotencyKeyHash,
  sbomUploadIdempotencyScope,
  type HashedIdempotencyKey,
  type SecretIdempotencyKey,
} from './idempotency.js';
import { buildFinalSbomObjectKey, buildTemporarySbomObjectKey } from './object-keys.js';
import type {
  ClassifiedStorageFailure,
  HashFreeIdempotencyReservationInput,
  ObjectByteStream,
  SbomObjectStoragePort,
  SbomUploadIdempotencyPort,
  SbomUploadRepositories,
  SbomUploadUnitOfWork,
  StorageFailureCategory,
} from './ports.js';

export type SbomUploadAccepted = {
  sbomId: string;
  ingestionId: string;
  assetId: string;
  state: Session8IngestionState;
  specificationType: 'cyclonedx';
  sha256: string;
  byteLength: number;
  source: 'upload';
  receivedAt: string;
};

export type UploadSbomInput = {
  actor: SbomUploadActor;
  assetId: string;
  idempotencyKey: HashedIdempotencyKey | SecretIdempotencyKey;
  contentType: SbomApprovedContentType;
  declaredByteLength?: number;
  body: ObjectByteStream;
  signal?: AbortSignal;
  maxBytes: number;
  parserVersion: string;
  normalizationVersion: string;
  idempotencyTtlMs: number;
  correlationId: string;
  requestId?: string;
};

export type SbomUploadLogger = {
  warn(bindings: Record<string, string | number | boolean | null>, message: string): void;
};

export type UploadSbomDependencies = {
  clock: Clock;
  createId: () => string;
  assets: Pick<AssetRepository, 'findById'>;
  uploadIdempotency: SbomUploadIdempotencyPort;
  sbomMetadata: {
    findByAssetAndHash(
      organizationId: string,
      assetId: string,
      sha256: string,
    ): Promise<SbomRecord | undefined>;
    findByAssetAndId(
      organizationId: string,
      assetId: string,
      sbomId: string,
    ): Promise<SbomRecord | undefined>;
  };
  ingestions: {
    findByAssetAndId(
      organizationId: string,
      assetId: string,
      ingestionId: string,
    ): Promise<SbomIngestionRecord | undefined>;
    findCurrentForSbom(
      organizationId: string,
      sbomId: string,
    ): Promise<SbomIngestionRecord | undefined>;
  };
  storage: SbomObjectStoragePort;
  unitOfWork: SbomUploadUnitOfWork;
  logger?: SbomUploadLogger;
};

class SbomUploadTransactionAbort extends Error {
  public constructor(public readonly failure: SbomUploadFailure) {
    super(failure.message);
    this.name = 'SbomUploadTransactionAbort';
  }
}

export function createUploadSbomUseCase(dependencies: UploadSbomDependencies) {
  return {
    execute(input: UploadSbomInput): Promise<Result<SbomUploadAccepted, SbomUploadFailure>> {
      return executeUploadSbom(dependencies, input);
    },
  };
}

async function executeUploadSbom(
  dependencies: UploadSbomDependencies,
  input: UploadSbomInput,
): Promise<Result<SbomUploadAccepted, SbomUploadFailure>> {
  const authorized = authorizeSbomUpload(input.actor);
  if (!authorized.ok) {
    return err(sbomUploadFailure(authorized.error, 'forbidden'));
  }

  const keyHash = resolveIdempotencyKeyHash(input.idempotencyKey);

  if (!isApprovedContentType(input.contentType)) {
    return err({
      code: 'validation',
      message: 'Content type is not an approved CycloneDX JSON type.',
      outcome: 'storage_failed',
    });
  }

  const actor = authorized.value;
  const asset = await dependencies.assets.findById(actor.organizationId, input.assetId);
  if (asset === undefined) {
    return err(sbomUploadFailure(ASSET_NOT_FOUND, 'not_found'));
  }
  if (asset.lifecycleStatus === 'archived' || asset.archivedAt !== null) {
    return err(sbomUploadFailure(ASSET_ARCHIVED, 'archived'));
  }

  const reservationInput = reservationArgs(actor.organizationId, input, keyHash, dependencies);
  const reserved = await dependencies.uploadIdempotency.reserveStarted(reservationInput);

  if (reserved.kind === 'unexpired_started') {
    return err(SBOM_UPLOAD_IN_PROGRESS);
  }
  if (reserved.kind === 'conflict') {
    return err(SBOM_UPLOAD_IDEMPOTENCY_CONFLICT);
  }
  if (reserved.kind === 'reclaimable_expired') {
    const reclaimed = await dependencies.uploadIdempotency.reclaimExpiredStarted(reservationInput);
    if (!reclaimed.ok) {
      return err(SBOM_UPLOAD_IN_PROGRESS);
    }
    return storePromoteAndFinalize(dependencies, input, actor, keyHash, reservationInput);
  }
  if (reserved.kind === 'completed') {
    return replayCompletedUpload(dependencies, input, actor, keyHash);
  }

  return storePromoteAndFinalize(dependencies, input, actor, keyHash, reservationInput);
}

async function replayCompletedUpload(
  dependencies: UploadSbomDependencies,
  input: UploadSbomInput,
  actor: AuthorizedSbomUploadActor,
  keyHash: string,
): Promise<Result<SbomUploadAccepted, SbomUploadFailure>> {
  const fingerprinted = await fingerprintUploadBody({
    body: input.body,
    maxBytes: input.maxBytes,
    ...(input.declaredByteLength === undefined
      ? {}
      : { declaredByteLength: input.declaredByteLength }),
    ...(input.signal === undefined ? {} : { signal: input.signal }),
  });
  if (!fingerprinted.ok) {
    return err(mapStorageFailure(fingerprinted.error.category));
  }

  const finalFingerprint = hashFinalFingerprint({
    assetId: input.assetId,
    contentType: input.contentType,
    sha256: fingerprinted.value.sha256,
    byteLength: fingerprinted.value.observedByteLength,
  });
  const replay = await dependencies.uploadIdempotency.resolveCompletedReplay({
    organizationId: actor.organizationId,
    scope: sbomUploadIdempotencyScope(input.assetId),
    keyHash,
    finalFingerprint,
  });
  if (!replay.ok) {
    return err(SBOM_UPLOAD_REPLAY_UNAVAILABLE);
  }
  if (replay.value.kind === 'fingerprint_mismatch') {
    return err(SBOM_UPLOAD_IDEMPOTENCY_CONFLICT);
  }

  return reconstructAccepted(
    dependencies,
    actor.organizationId,
    input.assetId,
    replay.value.response.sbomId,
    replay.value.response.ingestionId,
  );
}

async function storePromoteAndFinalize(
  dependencies: UploadSbomDependencies,
  input: UploadSbomInput,
  actor: AuthorizedSbomUploadActor,
  keyHash: string,
  reservationInput: HashFreeIdempotencyReservationInput,
): Promise<Result<SbomUploadAccepted, SbomUploadFailure>> {
  const uploadId = dependencies.createId();
  const temporaryObjectKey = buildTemporarySbomObjectKey({
    organizationId: actor.organizationId,
    assetId: input.assetId,
    uploadId,
  });

  const put = await dependencies.storage.putTemporaryObject({
    temporaryObjectKey,
    body: input.body,
    contentType: input.contentType,
    maxBytes: input.maxBytes,
    ...(input.declaredByteLength === undefined
      ? {}
      : { declaredByteLength: input.declaredByteLength }),
    ...(input.signal === undefined ? {} : { signal: input.signal }),
  });
  if (!put.ok) {
    await bestEffortDeleteTemporary(dependencies, temporaryObjectKey, input);
    return err(mapStorageFailure(put.error.category));
  }

  const sha256 = put.value.sha256;
  const byteLength = put.value.observedByteLength;
  const finalObjectKey = buildFinalSbomObjectKey({
    organizationId: actor.organizationId,
    assetId: input.assetId,
    sha256,
  });
  const finalFingerprint = hashFinalFingerprint({
    assetId: input.assetId,
    contentType: input.contentType,
    sha256,
    byteLength,
  });

  const promoted = await dependencies.storage.promoteTemporaryObject({
    temporaryObjectKey,
    finalObjectKey,
    expectedSha256: sha256,
    expectedByteLength: byteLength,
    contentType: input.contentType,
    ...(input.signal === undefined ? {} : { signal: input.signal }),
  });
  if (!promoted.ok) {
    await bestEffortDeleteTemporary(dependencies, temporaryObjectKey, input);
    return err(mapStorageFailure(promoted.error.category));
  }

  const existing = await dependencies.sbomMetadata.findByAssetAndHash(
    actor.organizationId,
    input.assetId,
    sha256,
  );

  let finalized: Result<SbomUploadAccepted, SbomUploadFailure>;
  try {
    if (existing !== undefined) {
      finalized = await finalizeDuplicate(
        dependencies,
        input,
        actor,
        keyHash,
        reservationInput,
        finalFingerprint,
        existing,
      );
    } else {
      finalized = await finalizeNewEvidence(
        dependencies,
        input,
        actor,
        keyHash,
        reservationInput,
        finalFingerprint,
        finalObjectKey,
        sha256,
        byteLength,
      );
    }
  } catch (error) {
    if (isSbomEvidenceConflictError(error)) {
      const raced = await dependencies.sbomMetadata.findByAssetAndHash(
        actor.organizationId,
        input.assetId,
        sha256,
      );
      if (raced === undefined) {
        await bestEffortDeleteTemporary(dependencies, temporaryObjectKey, input);
        return err(SBOM_UPLOAD_INTERNAL);
      }
      try {
        finalized = await finalizeDuplicate(
          dependencies,
          input,
          actor,
          keyHash,
          reservationInput,
          finalFingerprint,
          raced,
        );
      } catch (duplicateError) {
        await bestEffortDeleteTemporary(dependencies, temporaryObjectKey, input);
        return mapTransactionFailure(duplicateError);
      }
    } else {
      await bestEffortDeleteTemporary(dependencies, temporaryObjectKey, input);
      return mapTransactionFailure(error);
    }
  }

  await bestEffortDeleteTemporary(dependencies, temporaryObjectKey, input);
  return finalized;
}

async function finalizeNewEvidence(
  dependencies: UploadSbomDependencies,
  input: UploadSbomInput,
  actor: AuthorizedSbomUploadActor,
  keyHash: string,
  reservationInput: HashFreeIdempotencyReservationInput,
  finalFingerprint: string,
  finalObjectKey: string,
  sha256: string,
  byteLength: number,
): Promise<Result<SbomUploadAccepted, SbomUploadFailure>> {
  const receivedAt = dependencies.clock.now();
  return dependencies.unitOfWork.runInTransaction(async (repos) => {
    const sbom = await repos.sbomMetadata.insert({
      organizationId: actor.organizationId,
      assetId: input.assetId,
      objectKey: finalObjectKey,
      sha256,
      byteLength,
      declaredContentType: input.contentType,
      specificationType: 'cyclonedx',
      source: 'upload',
      uploadedByMembershipId: actor.membershipId,
      capturedAt: null,
      receivedAt,
    });

    const ingestion = await repos.ingestions.createAccepted({
      organizationId: actor.organizationId,
      sbomId: sbom.id,
      assetId: input.assetId,
      parserVersion: input.parserVersion,
      normalizationVersion: input.normalizationVersion,
    });
    if (!ingestion.ok) {
      throw new SbomUploadTransactionAbort(SBOM_UPLOAD_INTERNAL);
    }

    await repos.auditEvents.append(
      sbomUploadedAudit(
        actor,
        auditMetadata(input, sbom, ingestion.value),
        requestContext(input),
        receivedAt,
      ),
    );

    const finalized = await repos.uploadIdempotency.finalizeCompleted({
      organizationId: actor.organizationId,
      scope: reservationInput.scope,
      keyHash,
      reservationFingerprint: reservationInput.reservationFingerprint,
      finalFingerprint,
      responseStatus: SBOM_UPLOAD_ACCEPTED_STATUS,
      response: {
        schemaVersion: SBOM_UPLOAD_IDEMPOTENCY_RESPONSE_SCHEMA_VERSION,
        sbomId: sbom.id,
        ingestionId: ingestion.value.id,
      },
    });
    if (!finalized.ok) {
      throw new SbomUploadTransactionAbort(SBOM_UPLOAD_POSSIBLE_ORPHAN);
    }

    await repos.outboxEvents.create(
      ingestionRequestedOutbox(actor.organizationId, input, sbom, ingestion.value, receivedAt),
    );

    return requireAccepted(sbom, ingestion.value);
  });
}

async function finalizeDuplicate(
  dependencies: UploadSbomDependencies,
  input: UploadSbomInput,
  actor: AuthorizedSbomUploadActor,
  keyHash: string,
  reservationInput: HashFreeIdempotencyReservationInput,
  finalFingerprint: string,
  existing: SbomRecord,
): Promise<Result<SbomUploadAccepted, SbomUploadFailure>> {
  const occurredAt = dependencies.clock.now();
  return dependencies.unitOfWork.runInTransaction(async (repos) => {
    const current = await repos.ingestions.findCurrentForSbom(actor.organizationId, existing.id);
    if (current === undefined) {
      throw new SbomUploadTransactionAbort(SBOM_UPLOAD_MISSING_INGESTION);
    }
    if (current.assetId !== input.assetId) {
      throw new SbomUploadTransactionAbort(SBOM_UPLOAD_INTERNAL);
    }

    await repos.auditEvents.append(
      sbomDuplicateAudit(
        actor,
        auditMetadata(input, existing, current),
        requestContext(input),
        occurredAt,
      ),
    );

    const finalized = await repos.uploadIdempotency.finalizeCompleted({
      organizationId: actor.organizationId,
      scope: reservationInput.scope,
      keyHash,
      reservationFingerprint: reservationInput.reservationFingerprint,
      finalFingerprint,
      responseStatus: SBOM_UPLOAD_ACCEPTED_STATUS,
      response: {
        schemaVersion: SBOM_UPLOAD_IDEMPOTENCY_RESPONSE_SCHEMA_VERSION,
        sbomId: existing.id,
        ingestionId: current.id,
      },
    });
    if (!finalized.ok) {
      throw new SbomUploadTransactionAbort(SBOM_UPLOAD_POSSIBLE_ORPHAN);
    }

    return requireAccepted(existing, current);
  });
}

async function reconstructAccepted(
  dependencies: UploadSbomDependencies,
  organizationId: string,
  assetId: string,
  sbomId: string,
  ingestionId: string,
): Promise<Result<SbomUploadAccepted, SbomUploadFailure>> {
  const sbom = await dependencies.sbomMetadata.findByAssetAndId(organizationId, assetId, sbomId);
  if (sbom === undefined) {
    return err(SBOM_UPLOAD_REPLAY_UNAVAILABLE);
  }
  const ingestion = await dependencies.ingestions.findByAssetAndId(
    organizationId,
    assetId,
    ingestionId,
  );
  if (ingestion === undefined || ingestion.sbomId !== sbom.id) {
    return err(SBOM_UPLOAD_REPLAY_UNAVAILABLE);
  }
  return toAccepted(sbom, ingestion);
}

function requireAccepted(
  sbom: SbomRecord,
  ingestion: SbomIngestionRecord,
): Result<SbomUploadAccepted, SbomUploadFailure> {
  const accepted = toAccepted(sbom, ingestion);
  if (!accepted.ok) {
    throw new SbomUploadTransactionAbort(accepted.error);
  }
  return accepted;
}

function toAccepted(
  sbom: SbomRecord,
  ingestion: SbomIngestionRecord,
): Result<SbomUploadAccepted, SbomUploadFailure> {
  if (!isSession8IngestionState(ingestion.state)) {
    return err(SBOM_UPLOAD_REPLAY_UNAVAILABLE);
  }
  return ok({
    sbomId: sbom.id,
    ingestionId: ingestion.id,
    assetId: sbom.assetId,
    state: ingestion.state,
    specificationType: 'cyclonedx',
    sha256: sbom.sha256,
    byteLength: sbom.byteLength,
    source: 'upload',
    receivedAt: sbom.receivedAt.toISOString(),
  });
}

function isSession8IngestionState(state: SbomIngestionState): state is Session8IngestionState {
  return (session8IngestionStates as readonly string[]).includes(state);
}

function auditMetadata(
  input: UploadSbomInput,
  sbom: SbomRecord,
  ingestion: SbomIngestionRecord,
): {
  assetId: string;
  sbomId: string;
  ingestionId: string;
  byteLength: number;
  sha256: string;
  declaredContentType: string;
  parserVersion: string;
} {
  return {
    assetId: input.assetId,
    sbomId: sbom.id,
    ingestionId: ingestion.id,
    byteLength: sbom.byteLength,
    sha256: sbom.sha256,
    declaredContentType: sbom.declaredContentType,
    parserVersion: ingestion.parserVersion,
  };
}

function requestContext(input: UploadSbomInput): { correlationId: string; requestId?: string } {
  return {
    correlationId: input.correlationId,
    ...(input.requestId === undefined ? {} : { requestId: input.requestId }),
  };
}

function ingestionRequestedOutbox(
  organizationId: string,
  input: UploadSbomInput,
  sbom: SbomRecord,
  ingestion: SbomIngestionRecord,
  occurredAt: Date,
): CreateOutboxEventInput {
  const payload: OutboxPayloadJson = {
    schemaVersion: JSON_SCHEMA_VERSION_V1,
    ids: {
      organizationId,
      assetId: input.assetId,
      sbomId: sbom.id,
      ingestionId: ingestion.id,
    },
    metadata: {
      parserVersion: input.parserVersion,
      attemptNumber: ingestion.attemptNumber,
    },
  };

  return {
    organizationId,
    aggregateType: 'sbom_ingestion',
    aggregateId: ingestion.id,
    eventType: SBOM_INGESTION_REQUESTED_EVENT_TYPE,
    payload,
    dedupeKey: `${organizationId}:sbom.ingest:${sbom.id}:${input.parserVersion}`,
    occurredAt,
    status: 'pending',
  };
}

function reservationArgs(
  organizationId: string,
  input: UploadSbomInput,
  keyHash: string,
  dependencies: UploadSbomDependencies,
): HashFreeIdempotencyReservationInput {
  return {
    organizationId,
    scope: sbomUploadIdempotencyScope(input.assetId),
    keyHash,
    reservationFingerprint: hashReservationFingerprint({
      assetId: input.assetId,
      contentType: input.contentType,
    }),
    expiresAt: new Date(dependencies.clock.now().getTime() + input.idempotencyTtlMs),
  };
}

async function bestEffortDeleteTemporary(
  dependencies: UploadSbomDependencies,
  temporaryObjectKey: string,
  input: UploadSbomInput,
): Promise<void> {
  const deleted = await dependencies.storage.deleteTemporaryObject({
    temporaryObjectKey,
  });
  if (!deleted.ok) {
    dependencies.logger?.warn(
      {
        requestId: input.requestId ?? null,
        correlationId: input.correlationId,
        assetId: input.assetId,
      },
      'Temporary SBOM object cleanup failed.',
    );
  }
}

function mapTransactionFailure(error: unknown): Result<SbomUploadAccepted, SbomUploadFailure> {
  if (error instanceof SbomUploadTransactionAbort) {
    return err(error.failure);
  }
  if (isSbomEvidenceConflictError(error)) {
    return err(SBOM_UPLOAD_INTERNAL);
  }
  return err(SBOM_UPLOAD_POSSIBLE_ORPHAN);
}

function mapStorageFailure(category: StorageFailureCategory): SbomUploadFailure {
  switch (category) {
    case 'aborted':
      return SBOM_UPLOAD_CLIENT_ABORTED;
    case 'size_limit':
      return {
        code: 'validation',
        message: 'Upload exceeds the configured size limit.',
        outcome: 'storage_failed',
      };
    case 'invalid_content':
      return {
        code: 'validation',
        message: 'Upload content is not accepted.',
        outcome: 'storage_failed',
      };
    case 'timeout':
    case 'storage_unavailable':
    case 'copy_failed':
    case 'bucket_missing':
    case 'object_missing':
    case 'access_denied':
    case 'internal':
      return {
        code: 'internal',
        message: 'Object storage is unavailable.',
        outcome: 'storage_failed',
      };
    default: {
      const exhaustive: never = category;
      return exhaustive;
    }
  }
}

function isApprovedContentType(value: string): value is SbomApprovedContentType {
  return (SBOM_APPROVED_CONTENT_TYPES as readonly string[]).includes(value);
}

export type { ClassifiedStorageFailure, SbomUploadRepositories };
