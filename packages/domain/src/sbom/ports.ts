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
import type { SbomListQuery, SbomListPage } from './types.js';

export type ObjectByteStream = AsyncIterable<Uint8Array>;

export type ClassifiedStorageFailure = {
  category: Extract<SafeFailureCategory, 'storage' | 'timeout' | 'internal'>;
  code: Extract<
    SafeFailureCode,
    'storage_timeout' | 'object_missing' | 'hash_mismatch' | 'processing_failed'
  >;
};

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
  signal?: AbortSignal;
};

export type PromoteObjectInput = {
  temporaryObjectKey: string;
  finalObjectKey: string;
  expectedSha256: string;
  expectedByteLength: number;
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
  signal?: AbortSignal;
};

export type GetObjectResult = {
  body: ObjectByteStream;
  byteLength: number;
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
  ): Promise<Result<void, ClassifiedStorageFailure>>;
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
  status: 'started' | 'completed';
  expiresAt: Date;
  completedAt: Date | null;
  response: SbomUploadIdempotencyResponseIds | null;
  finalFingerprint: string | null;
};

export type ReserveStartedResult =
  | { kind: 'acquired'; record: IdempotencyReservationRecord }
  | { kind: 'unexpired_started'; record: IdempotencyReservationRecord }
  | { kind: 'reclaimable_expired'; record: IdempotencyReservationRecord }
  | { kind: 'completed'; record: IdempotencyReservationRecord };

export type FinalizeIdempotencyInput = {
  organizationId: string;
  scope: string;
  keyHash: string;
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

export type SbomMetadataPersistencePort = {
  insert(input: PersistSbomMetadataInput): Promise<SbomRecord>;
  findById(organizationId: string, sbomId: string): Promise<SbomRecord | undefined>;
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
};

export type SbomIngestionPersistencePort = {
  createAccepted(input: CreateAcceptedIngestionInput): Promise<Result<SbomIngestionRecord>>;
  findById(organizationId: string, ingestionId: string): Promise<SbomIngestionRecord | undefined>;
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

export type PersistComponentGraphInput = {
  organizationId: string;
  assetId: string;
  sbomId: string;
  sbomIngestionId: string;
  graph: NormalizedComponentGraph;
};

export type ComponentGraphPersistencePort = {
  replaceForIngestion(input: PersistComponentGraphInput): Promise<Result<void>>;
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

export type ClaimOutboxInput = {
  eventId: string;
  now: Date;
  leaseExpiresAt: Date;
};

export type MarkOutboxProcessedInput = {
  eventId: string;
  acceptedAt: Date;
  queueJobId: string;
};

export type OutboxDeliveryFailureInput = {
  eventId: string;
  failureCategory: SafeFailureCategory;
  failureCode: SafeFailureCode;
  availableAt: Date;
};

export type OutboxDeadLetterInput = {
  eventId: string;
  failureCategory: SafeFailureCategory;
  failureCode: SafeFailureCode;
};

/**
 * Outbox relay persistence. queueJobId is a deterministic string for a future
 * queue adapter. This port does not expose BullMQ job objects.
 */
export type OutboxRelayPersistencePort = {
  listClaimable(input: { limit: number; now: Date }): Promise<readonly ClaimableOutboxEvent[]>;
  claim(input: ClaimOutboxInput): Promise<Result<OutboxRelayClaim>>;
  expireLease(input: { eventId: string; now: Date }): Promise<Result<void>>;
  markProcessedAfterQueueAcceptance(
    input: MarkOutboxProcessedInput,
  ): Promise<Result<OutboxEventRecord>>;
  markRetryableDeliveryFailure(
    input: OutboxDeliveryFailureInput,
  ): Promise<Result<OutboxEventRecord>>;
  markDeadLetter(input: OutboxDeadLetterInput): Promise<Result<OutboxEventRecord>>;
};

export function deterministicOutboxQueueJobId(
  event: Pick<ClaimableOutboxEvent, 'id' | 'eventType'>,
): string {
  return `${event.eventType}:${event.id}`;
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
  jobId: string;
  workerIdentifier: string;
  now: Date;
  leaseExpiresAt: Date;
};

export type RetryBackgroundJobInput = {
  jobId: string;
  failureCategory: SafeFailureCategory;
  failureCode: SafeFailureCode;
  availableAt: Date;
};

export type SucceedBackgroundJobInput = {
  jobId: string;
  completedAt: Date;
  graphCompleteness?: GraphCompleteness;
};

export type TerminalBackgroundJobFailureInput = {
  jobId: string;
  failureCategory: SafeFailureCategory;
  failureCode: SafeFailureCode;
  completedAt: Date;
};

export type LookupTerminalBackgroundJobInput = {
  organizationId: string | null;
  jobType: string;
  dedupeKey: string;
};

/**
 * BackgroundJob execution. Worker leases live here, not on SbomIngestion.
 * This port does not expose BullMQ types.
 */
export type BackgroundJobExecutionPort = {
  enqueueQueued(input: QueueBackgroundJobInput): Promise<QueuedBackgroundJob>;
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
