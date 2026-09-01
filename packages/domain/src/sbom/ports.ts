import type { AssetRepository, AuditAppendRepository, OutboxRepository } from '../ports.js';
import type { Result } from '../result.js';
import type {
  BackgroundJobRecord,
  ComponentOccurrenceRecord,
  DependencyRelationshipRecord,
  OutboxEventRecord,
  SbomIngestionRecord,
  SbomRecord,
} from '../records.js';
import type { Page, PageRequest } from '../pagination.js';
import type { GraphCompleteness } from '../lifecycle.js';
import { SBOM_UPLOAD_IDEMPOTENCY_RESPONSE_SCHEMA_VERSION } from './constants.js';
import type { SafeFailureCategory, SafeFailureCode } from './failures.js';
import type { NormalizedComponentGraph } from './graph.js';
import type { Session8IngestionCommand, Session8IngestionSnapshot } from './transitions.js';
import type { SbomListQuery, SbomListPage, SbomParserLimits } from './types.js';

export type ObjectByteStream = AsyncIterable<Uint8Array>;

/**
 * Provider-neutral object-storage failures. These are not Session 8 public
 * SafeFailureCode values; later batches map them at the HTTP boundary.
 */
export const storageFailureCategories = [
  'bucket_missing',
  'object_missing',
  'access_denied',
  'timeout',
  'aborted',
  'size_limit',
  'invalid_content',
  'copy_failed',
  'storage_unavailable',
  'internal',
] as const;

export type StorageFailureCategory = (typeof storageFailureCategories)[number];

export type ClassifiedStorageFailure = {
  category: StorageFailureCategory;
};

export function isStorageFailureCategory(value: string): value is StorageFailureCategory {
  return (storageFailureCategories as readonly string[]).includes(value);
}

export type ObjectStoragePrivacyAssumptions = {
  bucketPrivate: true;
  publicAccessDisabled: true;
  signedUrlsDisabled: true;
};

export type ObjectStorageExistence = { exists: true; byteLength: number } | { exists: false };

export type PutTemporaryObjectInput = {
  temporaryObjectKey: string;
  body: ObjectByteStream;
  contentType: string;
  maxBytes: number;
  declaredByteLength?: number;
  signal?: AbortSignal;
};

export type PutTemporaryObjectResult = {
  sha256: string;
  observedByteLength: number;
};

export type PromoteObjectInput = {
  temporaryObjectKey: string;
  finalObjectKey: string;
  expectedSha256: string;
  expectedByteLength: number;
  contentType: string;
  signal?: AbortSignal;
};

export type HeadObjectInput = {
  finalObjectKey: string;
  signal?: AbortSignal;
};

export type DeleteTemporaryObjectInput = {
  temporaryObjectKey: string;
  signal?: AbortSignal;
};

export type GetObjectInput = {
  finalObjectKey: string;
  maxBytes: number;
  expectedByteLength?: number;
  expectedSha256?: string;
  signal?: AbortSignal;
};

export type GetObjectCompletion = {
  observedByteLength: number;
  sha256?: string;
};

/**
 * Streaming GetObject handle. `declaredByteLength` is Head/Get metadata and may
 * be absent. `completion` resolves only after successful end-of-stream and
 * rejects on abort, timeout, size mismatch, or hash mismatch. Abandoning the
 * body requires `cancel()` so the socket is destroyed.
 */
export type GetObjectResult = {
  body: ObjectByteStream;
  declaredByteLength?: number;
  completion: Promise<GetObjectCompletion>;
  cancel: () => Promise<void>;
};

export type InitializeDevelopmentBucketInput = {
  explicitlyAllowed: true;
  bucket: string;
};

/**
 * Provider-neutral object-storage capabilities. Implementations must not leak
 * AWS SDK command, input, output, or error types through this port.
 * Object keys are internal DTOs and must not appear in public API contracts or
 * generic logs.
 */
export type SbomObjectStoragePort = {
  verifyBucketAvailability(input?: {
    signal?: AbortSignal;
  }): Promise<Result<ObjectStoragePrivacyAssumptions, ClassifiedStorageFailure>>;
  initializeDevelopmentBucket(
    input: InitializeDevelopmentBucketInput,
  ): Promise<Result<void, ClassifiedStorageFailure>>;
  putTemporaryObject(
    input: PutTemporaryObjectInput,
  ): Promise<Result<PutTemporaryObjectResult, ClassifiedStorageFailure>>;
  promoteTemporaryObject(
    input: PromoteObjectInput,
  ): Promise<Result<void, ClassifiedStorageFailure>>;
  headFinalObject(
    input: HeadObjectInput,
  ): Promise<Result<ObjectStorageExistence, ClassifiedStorageFailure>>;
  deleteTemporaryObject(
    input: DeleteTemporaryObjectInput,
  ): Promise<Result<void, ClassifiedStorageFailure>>;
  getObject(input: GetObjectInput): Promise<Result<GetObjectResult, ClassifiedStorageFailure>>;
};

export type HashFreeIdempotencyReservationInput = {
  organizationId: string;
  scope: string;
  keyHash: string;
  reservationFingerprint: string;
  expiresAt: Date;
};

export type SbomUploadIdempotencyResponseIds = {
  schemaVersion: typeof SBOM_UPLOAD_IDEMPOTENCY_RESPONSE_SCHEMA_VERSION;
  sbomId: string;
  ingestionId: string;
};

export type IdempotencyReservationRecord = {
  id: string;
  organizationId: string;
  scope: string;
  keyHash: string;
  reservationFingerprint: string;
  status: 'started' | 'completed' | 'conflict';
  expiresAt: Date;
  completedAt: Date | null;
  response: SbomUploadIdempotencyResponseIds | null;
  finalFingerprint: string | null;
};

export type ReserveStartedResult =
  | { kind: 'acquired'; record: IdempotencyReservationRecord }
  | { kind: 'unexpired_started'; record: IdempotencyReservationRecord }
  | { kind: 'reclaimable_expired'; record: IdempotencyReservationRecord }
  | { kind: 'completed'; record: IdempotencyReservationRecord }
  | { kind: 'conflict'; record: IdempotencyReservationRecord };

export type FinalizeIdempotencyInput = {
  organizationId: string;
  scope: string;
  keyHash: string;
  reservationFingerprint: string;
  finalFingerprint: string;
  response: SbomUploadIdempotencyResponseIds;
  responseStatus: number;
};

export type ResolveCompletedReplayInput = {
  organizationId: string;
  scope: string;
  keyHash: string;
  finalFingerprint: string;
};

export type ResolveCompletedReplayResult =
  | { kind: 'replay'; response: SbomUploadIdempotencyResponseIds; responseStatus: number }
  | { kind: 'fingerprint_mismatch' };

/**
 * Upload idempotency reservation. No method accepts a raw header value.
 * Callers supply only keyHash (SHA-256 of a domain-separated key).
 */
export type SbomUploadIdempotencyPort = {
  reserveStarted(input: HashFreeIdempotencyReservationInput): Promise<ReserveStartedResult>;
  findUnexpiredStarted(
    input: HashFreeIdempotencyReservationInput,
  ): Promise<IdempotencyReservationRecord | undefined>;
  reclaimExpiredStarted(
    input: HashFreeIdempotencyReservationInput,
  ): Promise<Result<IdempotencyReservationRecord>>;
  finalizeCompleted(input: FinalizeIdempotencyInput): Promise<Result<IdempotencyReservationRecord>>;
  resolveCompletedReplay(
    input: ResolveCompletedReplayInput,
  ): Promise<Result<ResolveCompletedReplayResult>>;
};

export type PersistSbomMetadataInput = {
  organizationId: string;
  assetId: string;
  objectKey: string;
  sha256: string;
  byteLength: number;
  declaredContentType: string;
  specificationType: 'cyclonedx';
  source: 'upload' | 'reprocess';
  uploadedByMembershipId: string | null;
  capturedAt: Date | null;
  receivedAt: Date;
};

export type SbomUploadRepositories = {
  assets: Pick<AssetRepository, 'findById'>;
  sbomMetadata: SbomMetadataPersistencePort;
  ingestions: SbomIngestionPersistencePort;
  uploadIdempotency: SbomUploadIdempotencyPort;
  auditEvents: AuditAppendRepository;
  outboxEvents: OutboxRepository;
};

/**
 * PostgreSQL-only unit of work for SBOM upload finalization.
 * Callers must not invoke object storage, Redis, or queues inside the callback.
 */
export type SbomUploadUnitOfWork = {
  runInTransaction<T>(work: (repos: SbomUploadRepositories) => Promise<T>): Promise<T>;
};

export type SbomMetadataPersistencePort = {
  /**
   * Insert SBOM metadata. Unique (organization, asset, sha256) collisions throw
   * SbomEvidenceConflictError so the surrounding transaction rolls back.
   */
  insert(input: PersistSbomMetadataInput): Promise<SbomRecord>;
  findById(organizationId: string, sbomId: string): Promise<SbomRecord | undefined>;
  findByAssetAndId(
    organizationId: string,
    assetId: string,
    sbomId: string,
  ): Promise<SbomRecord | undefined>;
  findByAssetAndHash(
    organizationId: string,
    assetId: string,
    sha256: string,
  ): Promise<SbomRecord | undefined>;
  listForAsset(
    organizationId: string,
    assetId: string,
    query?: SbomListQuery,
  ): Promise<SbomListPage>;
  recordSuccessfulParser(
    organizationId: string,
    sbomId: string,
    parserVersion: string,
    specificationVersion: SbomRecord['specificationVersion'],
  ): Promise<Result<SbomRecord>>;
};

export type CreateAcceptedIngestionInput = {
  organizationId: string;
  sbomId: string;
  assetId: string;
  parserVersion: string;
  normalizationVersion: string;
};

export type SbomIngestionPersistencePort = {
  createAccepted(input: CreateAcceptedIngestionInput): Promise<Result<SbomIngestionRecord>>;
  findById(organizationId: string, ingestionId: string): Promise<SbomIngestionRecord | undefined>;
  findByAssetAndId(
    organizationId: string,
    assetId: string,
    ingestionId: string,
  ): Promise<SbomIngestionRecord | undefined>;
  findCurrentForSbom(
    organizationId: string,
    sbomId: string,
  ): Promise<SbomIngestionRecord | undefined>;
  applyTransition(
    organizationId: string,
    ingestionId: string,
    expectedVersion: number,
    command: Session8IngestionCommand,
  ): Promise<Result<{ record: SbomIngestionRecord; snapshot: Session8IngestionSnapshot }>>;
};

export type PersistOwnedBackgroundJob = {
  jobId: string;
  workerIdentifier: string;
  completedAt: Date;
};

export type PersistComponentGraphInput = {
  organizationId: string;
  assetId: string;
  sbomId: string;
  sbomIngestionId: string;
  graph: NormalizedComponentGraph;
  correlationId: string;
  ownedJob?: PersistOwnedBackgroundJob;
};

/**
 * Insert-once graph persistence. Graph rows are inserted once; a completed
 * ingestion replay is a no-op; graph rows are never deleted and rebuilt; an
 * incompatible terminal ingestion is rejected; partial failure rolls back the
 * transaction. Callers pass a validated NormalizedComponentGraph, never raw bytes.
 */
export type ComponentGraphPersistencePort = {
  persistOnceForIngestion(input: PersistComponentGraphInput): Promise<Result<void>>;
  listOccurrencesForIngestion(
    organizationId: string,
    sbomIngestionId: string,
    page?: PageRequest,
  ): Promise<Page<ComponentOccurrenceRecord>>;
  listEdgesForIngestion(
    organizationId: string,
    sbomIngestionId: string,
    page?: PageRequest,
  ): Promise<Page<DependencyRelationshipRecord>>;
};

export type ClaimableOutboxEvent = {
  id: string;
  organizationId: string | null;
  aggregateType: string;
  aggregateId: string;
  eventType: string;
  dedupeKey: string;
  availableAt: Date;
  attemptCount: number;
};

export type OutboxRelayClaim = {
  eventId: string;
  leaseExpiresAt: Date;
  claimedAt: Date;
  attemptCount: number;
};

export type ClaimOutboxBatchInput = {
  limit: number;
  now: Date;
  leaseExpiresAt: Date;
};

export type ClaimedOutboxEvent = ClaimableOutboxEvent & OutboxRelayClaim;

export type MarkOutboxProcessedInput = {
  organizationId: string | null;
  eventId: string;
  acceptedAt: Date;
  queueJobId: string;
};

export type OutboxDeliveryFailureInput = {
  organizationId: string | null;
  eventId: string;
  failureCategory: SafeFailureCategory;
  failureCode: SafeFailureCode;
  availableAt: Date;
};

export type OutboxDeadLetterInput = {
  organizationId: string | null;
  eventId: string;
  failureCategory: SafeFailureCategory;
  failureCode: SafeFailureCode;
};

export type ExpireOutboxLeaseInput = {
  organizationId: string | null;
  eventId: string;
  now: Date;
};

/**
 * Outbox relay persistence. queueJobId is a deterministic string for a future
 * queue adapter. This port does not expose BullMQ job objects. Claim is atomic:
 * due pending rows and expired claimed rows are selected in two bounded branches
 * then locked with FOR UPDATE SKIP LOCKED. Pending work is preferred so expired
 * claimed work cannot starve it.
 */
export type OutboxRelayPersistencePort = {
  claimDueBatch(input: ClaimOutboxBatchInput): Promise<readonly ClaimedOutboxEvent[]>;
  expireLease(input: ExpireOutboxLeaseInput): Promise<Result<void>>;
  markProcessedAfterQueueAcceptance(
    input: MarkOutboxProcessedInput,
  ): Promise<Result<OutboxEventRecord>>;
  markRetryableDeliveryFailure(
    input: OutboxDeliveryFailureInput,
  ): Promise<Result<OutboxEventRecord>>;
  markDeadLetter(input: OutboxDeadLetterInput): Promise<Result<OutboxEventRecord>>;
  listProcessedAwaitingBackgroundJob(input: {
    limit: number;
  }): Promise<readonly ClaimableOutboxEvent[]>;
};

export type OutboxQueueJob = {
  jobId: string;
  jobType: string;
  organizationId: string | null;
  outboxEventId: string;
  aggregateType: string;
  aggregateId: string;
  eventType: string;
  dedupeKey: string;
};

export type OutboxQueuePublishResult =
  { ok: true; duplicate: boolean } | { ok: false; retryable: true };

/**
 * Queue adapter used by the outbox relay. Implementations live outside
 * packages/domain and must not be invoked from inside a PostgreSQL transaction.
 */
export type OutboxQueuePublisherPort = {
  publish(job: OutboxQueueJob): Promise<OutboxQueuePublishResult>;
};

export function deterministicOutboxQueueJobId(
  event: Pick<ClaimableOutboxEvent, 'id' | 'eventType'>,
): string {
  return `${event.eventType}__${event.id}`;
}

export type QueueBackgroundJobInput = {
  organizationId: string | null;
  outboxEventId: string;
  jobType: string;
  dedupeKey: string;
};

export type QueuedBackgroundJob = {
  id: string;
  organizationId: string | null;
  jobType: string;
  status: 'queued';
  attempt: number;
};

export type ClaimBackgroundJobInput = {
  organizationId: string | null;
  jobId: string;
  workerIdentifier: string;
  now: Date;
  leaseExpiresAt: Date;
};

export type BackgroundJobExecutionClaim = {
  jobId: string;
  workerIdentifier: string;
  leaseExpiresAt: Date;
  attempt: number;
};

export type BackgroundJobLease = {
  jobId: string;
  workerIdentifier: string;
  leaseExpiresAt: Date;
};

export type RenewBackgroundJobLeaseInput = {
  organizationId: string | null;
  jobId: string;
  workerIdentifier: string;
  now: Date;
  leaseExpiresAt: Date;
};

export type RetryBackgroundJobInput = {
  organizationId: string | null;
  jobId: string;
  workerIdentifier: string;
  failureCategory: string;
  failureCode: string;
  /**
   * Not persisted on BackgroundJob. Intelligence fetch-layer delay uses
   * SyncRun.nextAttemptAt. Session 8 callers may still supply a Date.
   */
  availableAt: Date;
};

export type SucceedBackgroundJobInput = {
  organizationId: string | null;
  jobId: string;
  workerIdentifier: string;
  completedAt: Date;
  graphCompleteness?: GraphCompleteness;
};

export type TerminalBackgroundJobFailureInput = {
  organizationId: string | null;
  jobId: string;
  workerIdentifier: string;
  failureCategory: string;
  failureCode: string;
  completedAt: Date;
};

export type LookupTerminalBackgroundJobInput = {
  organizationId: string | null;
  jobType: string;
  dedupeKey: string;
};

export type LookupBackgroundJobByOutboxInput = {
  organizationId: string | null;
  outboxEventId: string;
};

export type LookupBackgroundJobByIdInput = {
  organizationId: string | null;
  jobId: string;
};

/**
 * BackgroundJob execution. Worker leases live here, not on SbomIngestion.
 * This port does not expose BullMQ types. `availableAt` on retry is not
 * persisted; intelligence delay authority is SyncRun.nextAttemptAt.
 */
export type BackgroundJobExecutionPort = {
  enqueueQueued(input: QueueBackgroundJobInput): Promise<QueuedBackgroundJob>;
  findById(input: LookupBackgroundJobByIdInput): Promise<BackgroundJobRecord | undefined>;
  findByOutboxEventId(
    input: LookupBackgroundJobByOutboxInput,
  ): Promise<BackgroundJobRecord | undefined>;
  claimExecution(input: ClaimBackgroundJobInput): Promise<Result<BackgroundJobExecutionClaim>>;
  renewLease(input: RenewBackgroundJobLeaseInput): Promise<Result<BackgroundJobLease>>;
  markRetry(input: RetryBackgroundJobInput): Promise<Result<QueuedBackgroundJob>>;
  markSucceeded(input: SucceedBackgroundJobInput): Promise<Result<BackgroundJobRecord>>;
  markTerminalFailure(
    input: TerminalBackgroundJobFailureInput,
  ): Promise<Result<BackgroundJobRecord>>;
  findIdempotentTerminal(
    input: LookupTerminalBackgroundJobInput,
  ): Promise<BackgroundJobRecord | undefined>;
};

export type SbomDocumentParseInput = {
  bytes: ArrayBuffer;
  expectedSha256: string;
  byteLength: number;
  limits: SbomParserLimits;
  parserVersion: string;
  normalizationVersion: string;
};

export type SbomDocumentParseResult =
  { ok: true; graph: NormalizedComponentGraph } | { ok: false; code: SafeFailureCode };

/**
 * Isolate parser adapter. Domain does not import worker_threads, Ajv, or
 * @patchpilot/sbom.
 */
export type SbomDocumentParserPort = {
  parse(input: SbomDocumentParseInput): Promise<SbomDocumentParseResult>;
};

export type SbomIngestionProcessorRepositories = {
  ingestions: SbomIngestionPersistencePort;
  backgroundJobs: BackgroundJobExecutionPort;
  auditEvents: AuditAppendRepository;
};

/**
 * PostgreSQL-only unit of work for processor terminal and retry outcomes.
 * Callers must not invoke object storage, Redis, or queues inside the callback.
 */
export type SbomIngestionProcessorUnitOfWork = {
  runInTransaction<T>(work: (repos: SbomIngestionProcessorRepositories) => Promise<T>): Promise<T>;
};
