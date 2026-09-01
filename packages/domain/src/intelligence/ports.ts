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
  IntelligenceSnapshotObjectKey,
  IntelligenceSnapshotObjectKeyBuilderPort,
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

export type IntelligenceHttpRetryPolicy = {
  maxRetries: number;
  backoffFloorMs: number;
  backoffCeilingMs: number;
};

export type IntelligenceConditionalValidators = {
  etagHash?: string;
  lastModified?: Date;
};

/**
 * Provider-neutral HTTP request. The URL is resolved inside a future adapter
 * from the closed provider and source identifiers. Callers cannot pass a URL.
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
  conditional?: IntelligenceConditionalValidators;
};

export type IntelligenceProviderHttpCompletion = {
  observedByteLength: number;
  sha256: string;
};

export type IntelligenceOpaqueEtag = {
  kind: 'opaque_hash';
  sha256: string;
};

export type IntelligenceProviderHttpSuccess = {
  kind: 'response';
  status: 200;
  declaredContentType: string | null;
  declaredByteLength: number | null;
  etag: IntelligenceOpaqueEtag | null;
  lastModified: Date | null;
  body: IntelligenceByteStream;
  completion: Promise<IntelligenceProviderHttpCompletion>;
  cancel: () => Promise<void>;
};

export type IntelligenceProviderHttpNotModified = {
  kind: 'not_modified';
  status: 304;
  etag: IntelligenceOpaqueEtag | null;
  lastModified: Date | null;
};

export type IntelligenceProviderHttpFailure = {
  kind: 'failure';
  category: IntelligenceSafeFailureCategory;
  code: IntelligenceSafeFailureCode;
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
  temporaryObjectKey: IntelligenceSnapshotObjectKey;
  body: IntelligenceByteStream;
  contentType: string;
  maxBytes: number;
  signal?: AbortSignal;
};

export type PutTemporaryIntelligenceSnapshotResult = {
  sha256: string;
  observedByteLength: number;
};

export type PromoteIntelligenceSnapshotInput = {
  temporaryObjectKey: IntelligenceSnapshotObjectKey;
  finalObjectKey: IntelligenceSnapshotObjectKey;
  expectedSha256: string;
  expectedByteLength: number;
  contentType: string;
  signal?: AbortSignal;
};

export type HeadIntelligenceSnapshotInput = {
  finalObjectKey: IntelligenceSnapshotObjectKey;
  signal?: AbortSignal;
};

export type IntelligenceSnapshotExistence =
  { exists: true; byteLength: number } | { exists: false };

export type GetIntelligenceSnapshotInput = {
  finalObjectKey: IntelligenceSnapshotObjectKey;
  maxBytes: number;
  expectedByteLength?: number;
  expectedSha256?: string;
  signal?: AbortSignal;
};

export type GetIntelligenceSnapshotResult = {
  body: IntelligenceByteStream;
  declaredByteLength?: number;
  completion: Promise<IntelligenceProviderHttpCompletion>;
  cancel: () => Promise<void>;
};

export type DeleteTemporaryIntelligenceSnapshotInput = {
  temporaryObjectKey: IntelligenceSnapshotObjectKey;
  signal?: AbortSignal;
};

export type IntelligenceSnapshotPrivacyAssumptions = {
  bucketPrivate: true;
  publicAccessDisabled: true;
  signedUrlsDisabled: true;
};

export type IntelligenceSnapshotStoragePort = {
  verifyPrivateStorageAvailability(input?: {
    signal?: AbortSignal;
  }): Promise<Result<IntelligenceSnapshotPrivacyAssumptions, IntelligenceSnapshotStorageFailure>>;
  putTemporarySnapshot(
    input: PutTemporaryIntelligenceSnapshotInput,
  ): Promise<Result<PutTemporaryIntelligenceSnapshotResult, IntelligenceSnapshotStorageFailure>>;
  promoteTemporarySnapshot(
    input: PromoteIntelligenceSnapshotInput,
  ): Promise<Result<void, IntelligenceSnapshotStorageFailure>>;
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
  command: IntelligenceSyncRunCommand;
};

export type ClaimIntelligenceSyncRunInput = {
  syncRunId: string;
  expectedState: 'requested' | 'retry_wait';
  claimedAt: Date;
  leaseExpiresAt: Date;
};

export type RenewIntelligenceSyncRunLeaseInput = {
  syncRunId: string;
  expectedState: IntelligenceSyncRunState;
  leaseExpiresAt: Date;
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
  renewExecutionLease(
    input: RenewIntelligenceSyncRunLeaseInput,
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

export type IntelligenceSnapshotPersistencePort = {
  findByProviderSourceAndSha256(
    identity: IntelligenceSnapshotIdentity,
  ): Promise<IntelligenceSnapshotRecord | undefined>;
  insertImmutable(
    record: InsertIntelligenceSnapshotInput,
  ): Promise<Result<IntelligenceSnapshotRecord>>;
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
  expectedEntryCount: number;
  parserVersion: string;
  normalizationVersion: string;
  createdAt: Date;
};

export type StageKevEntryBatchInput = {
  generationId: string;
  snapshotId: string;
  entries: readonly KevNormalizedEntryRecord[];
};

export type MarkKevGenerationCompleteInput = {
  generationId: string;
  expectedEntryCount: number;
  actualStagedDistinctCveCount: number;
  parserVersion: string;
  normalizationVersion: string;
  completedAt: Date;
};

export type ActivateKevGenerationInput = {
  generationId: string;
  expectedEntryCount: number;
  actualStagedDistinctCveCount: number;
  parserVersion: string;
  normalizationVersion: string;
  provider: 'cisa_kev';
  sourceIdentifier: 'cisa_kev_json_catalog';
  snapshotId: string;
  previousActiveGenerationId: string | null;
  activatedAt: Date;
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
  expectedState: 'staging';
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
 * write; adapters use it only inside that atomic activation.
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
  ): Promise<Result<KevGenerationRecord>>;
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

export type { IntelligenceSnapshotObjectKeyBuilderPort, IntelligenceSyncRequestPort };

export type IntelligenceKevEntryReadModel = {
  normalizedCve: CanonicalCve;
  dateAdded: CalendarDate;
  dueDate: CalendarDate;
};
