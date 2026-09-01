import type { Result } from '../result.js';
import type {
  IntelligenceNotModifiedReason,
  IntelligenceProvider,
  IntelligenceSourceIdentifier,
  IntelligenceSyncRunState,
} from './constants.js';
import type { IntelligenceSafeFailureCategory, IntelligenceSafeFailureCode } from './failures.js';
import type { IntelligenceProviderFreshness } from './freshness.js';
import type { CalendarDate, CanonicalCve } from './normalize.js';
import type {
  FinalIntelligenceSnapshotObjectKey,
  IntelligenceSnapshotObjectKeyBuilderPort,
  TemporaryIntelligenceSnapshotObjectKey,
} from './object-keys.js';
import type {
  IntelligenceSnapshotIdentity,
  IntelligenceSnapshotRecord,
  IntelligenceSyncRunRecord,
  KevCurrentMembership,
  KevGenerationRecord,
  KevNormalizedEntryRecord,
} from './records.js';
import type { IntelligenceSyncRequestPort } from './scheduler.js';
import type { IntelligenceSyncRunCommand, IntelligenceSyncRunSnapshot } from './transitions.js';

export type IntelligenceByteStream = AsyncIterable<Uint8Array>;

export type IntelligenceStreamCompletion = {
  observedByteLength: number;
  sha256: string;
};

export type IntelligenceHttpRetryPolicy = {
  maxRetries: number;
  backoffFloorMs: number;
  backoffCeilingMs: number;
};

/**
 * Provider-neutral HTTP request. The URL is resolved inside the adapter
 * from the closed provider and source identifiers. Callers cannot pass a URL.
 * Session 9 does not send If-None-Match or If-Modified-Since.
 */
export type IntelligenceProviderHttpRequest = {
  provider: IntelligenceProvider;
  sourceIdentifier: IntelligenceSourceIdentifier;
  maxBytes: number;
  connectTimeoutMs: number;
  totalTimeoutMs: number;
  retryPolicy: IntelligenceHttpRetryPolicy;
  correlationId: string;
  signal?: AbortSignal;
};

export type IntelligenceProviderHttpCompletion = IntelligenceStreamCompletion;

export type IntelligenceProviderHttpSuccess = {
  kind: 'response';
  status: 200;
  declaredContentType: string | null;
  declaredByteLength: number | null;
  etagHash: string | null;
  lastModified: Date | null;
  body: IntelligenceByteStream;
  completion: Promise<IntelligenceStreamCompletion>;
  cancel: () => Promise<void>;
};

export type IntelligenceProviderHttpNotModified = {
  kind: 'not_modified';
  status: 304;
  etagHash: string | null;
  lastModified: Date | null;
};

export type IntelligenceProviderHttpFailure = {
  kind: 'failure';
  category: IntelligenceSafeFailureCategory;
  code: IntelligenceSafeFailureCode;
  retryAfterMs?: number;
};

export type IntelligenceProviderHttpResult =
  | IntelligenceProviderHttpSuccess
  | IntelligenceProviderHttpNotModified
  | IntelligenceProviderHttpFailure;

export type IntelligenceProviderHttpPort = {
  fetchCatalog(request: IntelligenceProviderHttpRequest): Promise<IntelligenceProviderHttpResult>;
};

export type IntelligenceSnapshotStorageFailure = {
  category: IntelligenceSafeFailureCategory;
  code: IntelligenceSafeFailureCode;
};

export type PutTemporaryIntelligenceSnapshotInput = {
  temporaryObjectKey: TemporaryIntelligenceSnapshotObjectKey;
  body: IntelligenceByteStream;
  contentType: string;
  maxBytes: number;
  declaredByteLength?: number;
  signal?: AbortSignal;
};

export type PutTemporaryIntelligenceSnapshotResult = {
  sha256: string;
  observedByteLength: number;
};

export type PromoteIntelligenceSnapshotInput = {
  temporaryObjectKey: TemporaryIntelligenceSnapshotObjectKey;
  finalObjectKey: FinalIntelligenceSnapshotObjectKey;
  expectedSha256: string;
  expectedByteLength: number;
  contentType: string;
  signal?: AbortSignal;
};

export type PromoteIntelligenceSnapshotResult = {
  outcome: 'copied' | 'reused';
  temporaryCleanup: 'deleted' | 'failed';
};

export type HeadIntelligenceSnapshotInput = {
  finalObjectKey: FinalIntelligenceSnapshotObjectKey;
  signal?: AbortSignal;
};

export type IntelligenceSnapshotExistence =
  | {
      exists: true;
      byteLength: number;
      sha256: string;
      declaredContentType: string | null;
      detectedContentType: string | null;
      provider: 'cisa_kev';
      sourceIdentifier: 'cisa_kev_json_catalog';
    }
  | { exists: false };

export type GetIntelligenceSnapshotInput = {
  finalObjectKey: FinalIntelligenceSnapshotObjectKey;
  maxBytes: number;
  expectedByteLength?: number;
  expectedSha256?: string;
  signal?: AbortSignal;
};

export type GetIntelligenceSnapshotResult = {
  body: IntelligenceByteStream;
  declaredByteLength?: number;
  completion: Promise<IntelligenceStreamCompletion>;
  cancel: () => Promise<void>;
};

export type DeleteTemporaryIntelligenceSnapshotInput = {
  temporaryObjectKey: TemporaryIntelligenceSnapshotObjectKey;
  signal?: AbortSignal;
};

export type IntelligenceSnapshotPrivacyAssumptions = {
  bucketPrivate: true;
  publicAccessDisabled: true;
  signedUrlsDisabled: true;
};

export type InitializeIntelligenceDevelopmentBucketInput = {
  explicitlyAllowed: true;
  bucket: string;
};

export type IntelligenceSnapshotStoragePort = {
  verifyPrivateStorageAvailability(input?: {
    signal?: AbortSignal;
  }): Promise<Result<IntelligenceSnapshotPrivacyAssumptions, IntelligenceSnapshotStorageFailure>>;
  initializeDevelopmentBucket(
    input: InitializeIntelligenceDevelopmentBucketInput,
  ): Promise<Result<void, IntelligenceSnapshotStorageFailure>>;
  putTemporarySnapshot(
    input: PutTemporaryIntelligenceSnapshotInput,
  ): Promise<Result<PutTemporaryIntelligenceSnapshotResult, IntelligenceSnapshotStorageFailure>>;
  promoteTemporarySnapshot(
    input: PromoteIntelligenceSnapshotInput,
  ): Promise<Result<PromoteIntelligenceSnapshotResult, IntelligenceSnapshotStorageFailure>>;
  headFinalSnapshot(
    input: HeadIntelligenceSnapshotInput,
  ): Promise<Result<IntelligenceSnapshotExistence, IntelligenceSnapshotStorageFailure>>;
  getFinalSnapshot(
    input: GetIntelligenceSnapshotInput,
  ): Promise<Result<GetIntelligenceSnapshotResult, IntelligenceSnapshotStorageFailure>>;
  deleteTemporarySnapshot(
    input: DeleteTemporaryIntelligenceSnapshotInput,
  ): Promise<Result<void, IntelligenceSnapshotStorageFailure>>;
};

export type CompareAndSetSyncRunInput = {
  syncRunId: string;
  expectedState: IntelligenceSyncRunState;
  expectedVersion: number;
  command: IntelligenceSyncRunCommand;
};

export type ClaimIntelligenceSyncRunInput = {
  syncRunId: string;
  expectedState: 'requested' | 'retry_wait';
  expectedVersion: number;
  claimedAt: Date;
};

export type IntelligenceSyncRunPersistencePort = {
  createRequested(record: IntelligenceSyncRunRecord): Promise<Result<IntelligenceSyncRunRecord>>;
  findById(id: string): Promise<IntelligenceSyncRunRecord | undefined>;
  findLatestByProviderAndSource(
    provider: IntelligenceProvider,
    sourceIdentifier: IntelligenceSourceIdentifier,
  ): Promise<IntelligenceSyncRunRecord | undefined>;
  claimRequestedOrRetryWait(
    input: ClaimIntelligenceSyncRunInput,
  ): Promise<Result<IntelligenceSyncRunRecord>>;
  applyCompareAndSetTransition(
    input: CompareAndSetSyncRunInput,
  ): Promise<Result<IntelligenceSyncRunSnapshot>>;
  recordRetryWait(input: CompareAndSetSyncRunInput): Promise<Result<IntelligenceSyncRunRecord>>;
  recordSnapshotStored(
    input: CompareAndSetSyncRunInput,
  ): Promise<Result<IntelligenceSyncRunRecord>>;
  recordParsing(input: CompareAndSetSyncRunInput): Promise<Result<IntelligenceSyncRunRecord>>;
  recordGenerationStaging(
    input: CompareAndSetSyncRunInput,
  ): Promise<Result<IntelligenceSyncRunRecord>>;
  recordActivationStarted(
    input: CompareAndSetSyncRunInput,
  ): Promise<Result<IntelligenceSyncRunRecord>>;
  completeRun(input: CompareAndSetSyncRunInput): Promise<Result<IntelligenceSyncRunRecord>>;
  completeNotModified(input: CompareAndSetSyncRunInput): Promise<Result<IntelligenceSyncRunRecord>>;
  quarantineRun(input: CompareAndSetSyncRunInput): Promise<Result<IntelligenceSyncRunRecord>>;
  failRun(input: CompareAndSetSyncRunInput): Promise<Result<IntelligenceSyncRunRecord>>;
  findTerminalById(id: string): Promise<IntelligenceSyncRunRecord | undefined>;
};

export type InsertIntelligenceSnapshotInput = IntelligenceSnapshotRecord;

export type InsertOrReuseIntelligenceSnapshotResult = {
  record: IntelligenceSnapshotRecord;
  reused: boolean;
};

export type IntelligenceSnapshotPersistencePort = {
  findByProviderSourceAndSha256(
    identity: IntelligenceSnapshotIdentity,
  ): Promise<IntelligenceSnapshotRecord | undefined>;
  insertImmutable(
    record: InsertIntelligenceSnapshotInput,
  ): Promise<Result<IntelligenceSnapshotRecord>>;
  insertOrReuse(
    record: InsertIntelligenceSnapshotInput,
  ): Promise<Result<InsertOrReuseIntelligenceSnapshotResult>>;
  findById(id: string): Promise<IntelligenceSnapshotRecord | undefined>;
  verifyIdentity(
    id: string,
    identity: IntelligenceSnapshotIdentity,
  ): Promise<Result<IntelligenceSnapshotRecord>>;
};

export type CreateStagingKevGenerationInput = {
  id: string;
  syncRunId: string;
  snapshotId: string;
  provider: 'cisa_kev';
  sourceIdentifier: 'cisa_kev_json_catalog';
  expectedEntryCount: number;
  parserVersion: string;
  normalizationVersion: string;
  createdAt: Date;
};

export type StageKevEntryBatchInput = {
  generationId: string;
  snapshotId: string;
  provider: 'cisa_kev';
  sourceIdentifier: 'cisa_kev_json_catalog';
  maxBatchSize: number;
  entries: readonly KevNormalizedEntryRecord[];
};

export type MarkKevGenerationCompleteInput = {
  generationId: string;
  expectedEntryCount: number;
  actualStagedDistinctCveCount: number;
  parserVersion: string;
  normalizationVersion: string;
  catalogVersion: string;
  catalogReleasedAt: Date;
  completedAt: Date;
};

export type IntelligenceJobOwnership = {
  jobId: string;
  workerIdentifier: string;
  organizationId: null;
  jobType: 'intelligence.sync';
};

export type ActivateKevGenerationInput = {
  generationId: string;
  expectedEntryCount: number;
  parserVersion: string;
  normalizationVersion: string;
  provider: 'cisa_kev';
  sourceIdentifier: 'cisa_kev_json_catalog';
  snapshotId: string;
  previousActiveGenerationId: string | null;
  expectedSourceVersion: number;
  activatedAt: Date;
  acceptedEntryCount: number;
  warningCount: number;
  correlationId: string;
  syncRunId: string;
  expectedSyncRunState: 'activating';
  expectedSyncRunVersion: number;
  backgroundJob?: IntelligenceJobOwnership;
};

export type ActivateKevGenerationResult = {
  outcome: 'activated' | 'idempotent_replay';
  generation: KevGenerationRecord;
  syncRun: IntelligenceSyncRunRecord;
};

export type ListActiveKevEntriesQuery = {
  provider: 'cisa_kev';
  sourceIdentifier: 'cisa_kev_json_catalog';
  limit: number;
  afterOrdinal?: number;
  afterId?: string;
};

export type ListActiveKevEntriesPage = {
  items: KevCurrentMembership[];
  nextOrdinal: number | null;
  nextId: string | null;
};

export type AbandonKevGenerationInput = {
  generationId: string;
  expectedState: 'staging' | 'complete';
  abandonedAt: Date;
};

/**
 * Generation persistence. `activateCompleteGeneration` is the only
 * reader-visible current-catalog mutation: it atomically activates the
 * complete generation, supersedes `previousActiveGenerationId` when that id is
 * the current active row (or requires that no active generation exists when
 * the id is null), and switches current membership. Readers must never
 * observe two active generations or a staging generation. Partial failure
 * rolls back. `markGenerationSuperseded` is not a standalone current-catalog
 * write. Adapters refuse when `intelligence_source.active_generation_id`
 * references the generation. Atomic activation inlines supersede with the
 * pointer switch.
 */
export type IntelligenceGenerationPersistencePort = {
  createStagingGeneration(
    input: CreateStagingKevGenerationInput,
  ): Promise<Result<KevGenerationRecord>>;
  stageBoundedEntryBatch(
    input: StageKevEntryBatchInput,
  ): Promise<Result<{ stagedEntryCount: number }>>;
  inspectStagedCounts(
    generationId: string,
  ): Promise<{ stagedEntryCount: number; distinctCveCount: number } | undefined>;
  markGenerationComplete(
    input: MarkKevGenerationCompleteInput,
  ): Promise<Result<KevGenerationRecord>>;
  activateCompleteGeneration(
    input: ActivateKevGenerationInput,
  ): Promise<Result<ActivateKevGenerationResult>>;
  findActiveGeneration(
    provider: 'cisa_kev',
    sourceIdentifier: 'cisa_kev_json_catalog',
  ): Promise<KevGenerationRecord | undefined>;
  listActiveEntries(query: ListActiveKevEntriesQuery): Promise<ListActiveKevEntriesPage>;
  markGenerationSuperseded(
    generationId: string,
    supersededAt: Date,
  ): Promise<Result<KevGenerationRecord>>;
  abandonIncompleteGeneration(
    input: AbandonKevGenerationInput,
  ): Promise<Result<KevGenerationRecord>>;
  findStaleIncompleteGenerations(olderThan: Date): Promise<KevGenerationRecord[]>;
};

export type MarkIntelligenceAttemptStartedInput = {
  provider: IntelligenceProvider;
  sourceIdentifier: IntelligenceSourceIdentifier;
  attemptedAt: Date;
};

export type MarkSuccessfulIntelligenceGenerationInput = {
  provider: IntelligenceProvider;
  sourceIdentifier: IntelligenceSourceIdentifier;
  completedAt: Date;
  catalogVersion: string;
  catalogReleasedAt: Date | null;
  entryCount: number;
};

export type MarkIntelligenceNotModifiedInput = {
  provider: IntelligenceProvider;
  sourceIdentifier: IntelligenceSourceIdentifier;
  completedAt: Date;
  reason: IntelligenceNotModifiedReason;
  priorAcceptedGenerationId: string;
};

export type MarkIntelligenceDegradedFailureInput = {
  provider: IntelligenceProvider;
  sourceIdentifier: IntelligenceSourceIdentifier;
  failedAt: Date;
  failureCode: IntelligenceSafeFailureCode;
};

export type IntelligenceSourceFreshnessPort = {
  loadCurrentProviderStatus(
    provider: IntelligenceProvider,
    sourceIdentifier: IntelligenceSourceIdentifier,
    now: Date,
  ): Promise<IntelligenceProviderFreshness>;
  markAttemptStarted(
    input: MarkIntelligenceAttemptStartedInput,
  ): Promise<Result<IntelligenceProviderFreshness>>;
  markSuccessfulCompletedGeneration(
    input: MarkSuccessfulIntelligenceGenerationInput,
  ): Promise<Result<IntelligenceProviderFreshness>>;
  markNotModified(
    input: MarkIntelligenceNotModifiedInput,
  ): Promise<Result<IntelligenceProviderFreshness>>;
  markDegradedFailure(
    input: MarkIntelligenceDegradedFailureInput,
  ): Promise<Result<IntelligenceProviderFreshness>>;
};

export type CompleteIntelligenceNotModifiedInput = {
  syncRunId: string;
  expectedState: IntelligenceSyncRunState;
  expectedVersion: number;
  completedAt: Date;
  reason: IntelligenceNotModifiedReason;
  priorAcceptedGenerationId: string;
  correlationId: string;
  backgroundJob?: IntelligenceJobOwnership;
};

export type PersistRequestedIntelligenceSyncInput = {
  provider: 'cisa_kev';
  sourceIdentifier: 'cisa_kev_json_catalog';
  syncRunId: string;
  requestedAt: Date;
  correlationId: string;
  parserVersion: string;
  normalizationVersion: string;
  dedupeKey: string;
};

export type PersistRequestedIntelligenceSyncResult =
  | { outcome: 'created'; syncRun: IntelligenceSyncRunRecord }
  | { outcome: 'existing_inflight'; syncRun: IntelligenceSyncRunRecord };

export type IntelligenceSchedulerPersistencePort = {
  requestSync(
    input: PersistRequestedIntelligenceSyncInput,
  ): Promise<Result<PersistRequestedIntelligenceSyncResult>>;
};

export type IntelligenceFailureTransitionInput = {
  syncRunId: string;
  expectedState: IntelligenceSyncRunState;
  expectedVersion: number;
  completedAt: Date;
  failureCode: IntelligenceSafeFailureCode;
  correlationId: string;
  backgroundJob?: IntelligenceJobOwnership;
};

export type IntelligenceRetryWaitTransitionInput = {
  syncRunId: string;
  expectedState: IntelligenceSyncRunState;
  expectedVersion: number;
  nextAttemptAt: Date;
  failureCode: IntelligenceSafeFailureCode;
  attemptedAt: Date;
};

/**
 * PostgreSQL-only unit of work for scheduler, activation, not-modified,
 * retry-wait, failure, and quarantine. Inputs do not accept provider HTTP,
 * object storage, Redis, BullMQ, or parser handles.
 */
export type IntelligenceSyncUnitOfWork = {
  requestSync(
    input: PersistRequestedIntelligenceSyncInput,
  ): Promise<Result<PersistRequestedIntelligenceSyncResult>>;
  activateCompleteGeneration(
    input: ActivateKevGenerationInput,
  ): Promise<Result<ActivateKevGenerationResult>>;
  completeNotModified(
    input: CompleteIntelligenceNotModifiedInput,
  ): Promise<Result<IntelligenceSyncRunRecord>>;
  recordRetryWait(
    input: IntelligenceRetryWaitTransitionInput,
  ): Promise<Result<IntelligenceSyncRunRecord>>;
  failRun(input: IntelligenceFailureTransitionInput): Promise<Result<IntelligenceSyncRunRecord>>;
  quarantineRun(
    input: IntelligenceFailureTransitionInput,
  ): Promise<Result<IntelligenceSyncRunRecord>>;
};

export type { IntelligenceSnapshotObjectKeyBuilderPort, IntelligenceSyncRequestPort };

export type IntelligenceKevEntryReadModel = {
  normalizedCve: CanonicalCve;
  dateAdded: CalendarDate;
  dueDate: CalendarDate;
};
