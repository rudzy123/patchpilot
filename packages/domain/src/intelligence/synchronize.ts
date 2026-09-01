import type { Clock } from '../clock.js';
import type { BackgroundJobRecord } from '../records.js';
import { err, ok, type Result } from '../result.js';
import type { BackgroundJobExecutionPort } from '../sbom/ports.js';
import {
  CISA_KEV_SOURCE_IDENTIFIER,
  INTELLIGENCE_PARSER_RESULT_MAX_SERIALIZED_BYTES,
  INTELLIGENCE_SAFE_CONTENT_TYPE_LABELS,
  INTELLIGENCE_SYNC_JOB_TYPE,
  INTELLIGENCE_SYNC_REQUESTED_EVENT_TYPE,
  UUID_PATTERN,
  type IntelligenceSafeContentTypeLabel,
} from './constants.js';
import { classifyIntelligenceSafeFailure, type IntelligenceSafeFailureCode } from './failures.js';
import {
  createIntelligenceLeaseHeartbeat,
  type IntelligenceLeaseHeartbeat,
  type IntelligenceLeaseHeartbeatScheduler,
} from './lease-heartbeat.js';
import { parseUtcInstant } from './normalize.js';
import { createIntelligenceSnapshotObjectKeyBuilder } from './object-keys.js';
import { parsePersistedIntelligenceSyncRequestedOutboxPayload } from './outbox.js';
import type {
  IntelligenceGenerationPersistencePort,
  IntelligenceKevParserPort,
  IntelligenceKevParserSuccess,
  IntelligenceKevParsedEntry,
  IntelligenceOutboxLookupPort,
  IntelligenceProviderHttpPort,
  IntelligenceSnapshotPersistencePort,
  IntelligenceSnapshotStoragePort,
  IntelligenceSourceFreshnessPort,
  IntelligenceSyncRunPersistencePort,
  IntelligenceSyncUnitOfWork,
  IntelligenceJobOwnership,
} from './ports.js';
import { type CalendarDate, type CanonicalCve } from './normalize.js';
import {
  validateKevNormalizedEntryRecord,
  type IntelligenceSnapshotRecord,
  type IntelligenceSyncRunRecord,
  type KevGenerationRecord,
  type KevNormalizedEntryRecord,
} from './records.js';
import { collectBoundedKevSnapshotBuffer } from './stream-buffer.js';
import {
  decideCatalogRegression,
  decideContentHashNotModified,
  intelligenceRetryWaitDelayMs,
  sumParserWarningCounts,
} from './sync-decisions.js';
import { attemptsRemain, mapIntelligenceSyncFailure } from './sync-failures.js';
import { isIntelligenceTerminalSyncRunState } from './transitions.js';
import { verifyDenseStagedPrefix } from './staging-resume.js';

export type CisaKevSynchronizationConfig = {
  parserVersion: string;
  normalizationVersion: string;
  kevResponseMaxBytes: number;
  kevParserTimeoutMs: number;
  kevJobLeaseMs: number;
  maxStagedRowsPerTransaction: number;
  syncMaxAttempts: number;
  syncRetryWaitFloorMs: number;
  syncRetryWaitCeilingMs: number;
  jobLeaseRenewalIntervalMs: number;
  httpConnectTimeoutMs: number;
  httpTotalTimeoutMs: number;
  httpRetryCount: number;
  httpBackoffFloorMs: number;
  httpBackoffCeilingMs: number;
  kevMaxVulnerabilityCount: number;
  kevMaxTextFieldBytes: number;
  kevMaxCweCount: number;
  kevJsonMaxDepth: number;
  kevJsonMaxNodes: number;
  kevJsonMaxStringBytes: number;
};

export type SynchronizeCisaKevInput = {
  syncRunId: string;
  backgroundJobId: string;
  workerIdentifier: string;
  signal?: AbortSignal;
};

export type CisaKevSynchronizationOutcome =
  | { kind: 'completed'; acceptedEntryCount: number; warningCount: number }
  | { kind: 'not_modified'; reason: 'content_sha256_unchanged' }
  | { kind: 'already_complete' }
  | { kind: 'retry_wait'; code: IntelligenceSafeFailureCode; nextAttemptAt: Date }
  | { kind: 'job_retry'; code: IntelligenceSafeFailureCode }
  | { kind: 'failed'; code: IntelligenceSafeFailureCode }
  | { kind: 'quarantined'; code: IntelligenceSafeFailureCode }
  | { kind: 'rejected'; code: IntelligenceSafeFailureCode }
  | { kind: 'inconsistent' };

export type CisaKevSynchronizationLogger = {
  info(bindings: Record<string, string | number | boolean | null>, message: string): void;
  warn(bindings: Record<string, string | number | boolean | null>, message: string): void;
};

export type CisaKevSynchronizationDependencies = {
  clock: Clock;
  createId: () => string;
  config: CisaKevSynchronizationConfig;
  jobs: BackgroundJobExecutionPort;
  outbox: IntelligenceOutboxLookupPort;
  syncRuns: IntelligenceSyncRunPersistencePort;
  snapshots: IntelligenceSnapshotPersistencePort;
  generations: IntelligenceGenerationPersistencePort;
  freshness: IntelligenceSourceFreshnessPort;
  http: IntelligenceProviderHttpPort;
  storage: IntelligenceSnapshotStoragePort;
  parser: IntelligenceKevParserPort;
  unitOfWork: IntelligenceSyncUnitOfWork;
  logger?: CisaKevSynchronizationLogger;
  leaseScheduler?: IntelligenceLeaseHeartbeatScheduler;
};

export type CisaKevSynchronizationService = {
  execute(input: SynchronizeCisaKevInput): Promise<CisaKevSynchronizationOutcome>;
};

export function createCisaKevSynchronizationService(
  dependencies: CisaKevSynchronizationDependencies,
): CisaKevSynchronizationService {
  return {
    execute(input) {
      return executeSynchronization(dependencies, input);
    },
  };
}

type ExecutionContext = {
  job: BackgroundJobRecord;
  syncRun: IntelligenceSyncRunRecord;
  ownership: IntelligenceJobOwnership;
  heartbeat: IntelligenceLeaseHeartbeat;
};

function isUuid(value: string): boolean {
  return UUID_PATTERN.test(value);
}

function ownershipFrom(
  job: BackgroundJobRecord,
  workerIdentifier: string,
): IntelligenceJobOwnership {
  return {
    jobId: job.id,
    workerIdentifier,
    organizationId: null,
    jobType: 'intelligence.sync',
  };
}

function parserLimits(config: CisaKevSynchronizationConfig) {
  return {
    maxBytes: config.kevResponseMaxBytes,
    jsonMaxDepth: config.kevJsonMaxDepth,
    jsonMaxNodes: config.kevJsonMaxNodes,
    jsonMaxStringBytes: config.kevJsonMaxStringBytes,
    maxVulnerabilityCount: config.kevMaxVulnerabilityCount,
    maxTextFieldBytes: config.kevMaxTextFieldBytes,
    maxCweCount: config.kevMaxCweCount,
    maxSerializedResultBytes: INTELLIGENCE_PARSER_RESULT_MAX_SERIALIZED_BYTES,
  };
}

function safeContentType(value: string | null): IntelligenceSafeContentTypeLabel | null {
  if (value === null) {
    return null;
  }
  return (INTELLIGENCE_SAFE_CONTENT_TYPE_LABELS as readonly string[]).includes(value)
    ? (value as IntelligenceSafeContentTypeLabel)
    : null;
}

async function executeSynchronization(
  dependencies: CisaKevSynchronizationDependencies,
  input: SynchronizeCisaKevInput,
): Promise<CisaKevSynchronizationOutcome> {
  const precheck = await authoritativePrecheck(dependencies, input);
  if (!precheck.ok) {
    return precheck.outcome;
  }

  const heartbeat = createIntelligenceLeaseHeartbeat({
    jobs: dependencies.jobs,
    ownership: {
      jobId: precheck.job.id,
      workerIdentifier: input.workerIdentifier,
      organizationId: null,
    },
    clock: dependencies.clock,
    leaseMs: dependencies.config.kevJobLeaseMs,
    intervalMs: dependencies.config.jobLeaseRenewalIntervalMs,
    ...(dependencies.leaseScheduler === undefined
      ? {}
      : { scheduler: dependencies.leaseScheduler }),
    ...(input.signal === undefined ? {} : { parentSignal: input.signal }),
  });

  const context: ExecutionContext = {
    job: precheck.job,
    syncRun: precheck.syncRun,
    ownership: ownershipFrom(precheck.job, input.workerIdentifier),
    heartbeat,
  };

  try {
    heartbeat.start();
    const initial = await heartbeat.renewNow();
    if (!initial.ok) {
      return { kind: 'rejected', code: 'request_cancelled' };
    }
    return await dispatch(dependencies, context);
  } finally {
    heartbeat.stop();
  }
}

async function authoritativePrecheck(
  dependencies: CisaKevSynchronizationDependencies,
  input: SynchronizeCisaKevInput,
): Promise<
  | { ok: true; job: BackgroundJobRecord; syncRun: IntelligenceSyncRunRecord }
  | { ok: false; outcome: CisaKevSynchronizationOutcome }
> {
  if (
    !isUuid(input.syncRunId) ||
    !isUuid(input.backgroundJobId) ||
    input.workerIdentifier.length === 0
  ) {
    return { ok: false, outcome: { kind: 'rejected', code: 'invalid_provider_source' } };
  }

  const job = await dependencies.jobs.findById({
    organizationId: null,
    jobId: input.backgroundJobId,
  });
  if (job === undefined) {
    return { ok: false, outcome: { kind: 'rejected', code: 'processing_failed' } };
  }
  if (job.organizationId !== null || job.jobType !== INTELLIGENCE_SYNC_JOB_TYPE) {
    return { ok: false, outcome: { kind: 'rejected', code: 'invalid_provider_source' } };
  }
  if (job.id !== input.backgroundJobId) {
    return { ok: false, outcome: { kind: 'rejected', code: 'processing_failed' } };
  }
  if (job.outboxEventId === null) {
    return { ok: false, outcome: { kind: 'rejected', code: 'processing_failed' } };
  }

  const event = await dependencies.outbox.findById({
    organizationId: null,
    eventId: job.outboxEventId,
  });
  if (event === undefined || event.organizationId !== null) {
    return { ok: false, outcome: { kind: 'rejected', code: 'processing_failed' } };
  }
  if (event.eventType !== INTELLIGENCE_SYNC_REQUESTED_EVENT_TYPE) {
    return { ok: false, outcome: { kind: 'rejected', code: 'invalid_provider_source' } };
  }
  const payload = parsePersistedIntelligenceSyncRequestedOutboxPayload(event.payload);
  if (!payload.ok) {
    return { ok: false, outcome: { kind: 'rejected', code: 'invalid_provider_source' } };
  }
  if (
    payload.value.syncRunId !== input.syncRunId ||
    payload.value.syncRunId !== event.aggregateId ||
    payload.value.provider !== 'cisa_kev' ||
    payload.value.sourceIdentifier !== CISA_KEV_SOURCE_IDENTIFIER
  ) {
    return { ok: false, outcome: { kind: 'rejected', code: 'invalid_provider_source' } };
  }

  const syncRun = await dependencies.syncRuns.findById(input.syncRunId);
  if (syncRun === undefined) {
    return { ok: false, outcome: { kind: 'rejected', code: 'processing_failed' } };
  }
  if (syncRun.provider !== 'cisa_kev' || syncRun.sourceIdentifier !== CISA_KEV_SOURCE_IDENTIFIER) {
    return { ok: false, outcome: { kind: 'rejected', code: 'invalid_provider_source' } };
  }
  if (
    syncRun.parserVersion !== dependencies.config.parserVersion ||
    syncRun.normalizationVersion !== dependencies.config.normalizationVersion
  ) {
    return { ok: false, outcome: { kind: 'failed', code: 'processing_failed' } };
  }

  if (isIntelligenceTerminalSyncRunState(syncRun.state)) {
    return {
      ok: false,
      outcome: await reconcileTerminal(dependencies, job, syncRun, input.workerIdentifier),
    };
  }

  if (job.status !== 'running' || job.workerIdentifier !== input.workerIdentifier) {
    return { ok: false, outcome: { kind: 'rejected', code: 'request_cancelled' } };
  }
  const now = dependencies.clock.now();
  if (job.leaseExpiresAt === null || job.leaseExpiresAt.getTime() <= now.getTime()) {
    return { ok: false, outcome: { kind: 'rejected', code: 'request_cancelled' } };
  }
  if (!Number.isSafeInteger(job.attempt) || job.attempt < 1) {
    return { ok: false, outcome: { kind: 'rejected', code: 'processing_failed' } };
  }
  if (syncRun.executionAttempt > job.attempt) {
    return { ok: false, outcome: { kind: 'rejected', code: 'processing_failed' } };
  }

  if (
    syncRun.state === 'retry_wait' &&
    syncRun.nextAttemptAt !== null &&
    syncRun.nextAttemptAt.getTime() > now.getTime()
  ) {
    return {
      ok: false,
      outcome: {
        kind: 'retry_wait',
        code: syncRun.failureCode ?? 'request_cancelled',
        nextAttemptAt: syncRun.nextAttemptAt,
      },
    };
  }

  return { ok: true, job, syncRun };
}

async function reconcileTerminal(
  dependencies: CisaKevSynchronizationDependencies,
  job: BackgroundJobRecord,
  syncRun: IntelligenceSyncRunRecord,
  workerIdentifier: string,
): Promise<CisaKevSynchronizationOutcome> {
  const now = dependencies.clock.now();
  if (syncRun.state === 'completed') {
    if (job.status === 'running' && job.workerIdentifier === workerIdentifier) {
      await dependencies.jobs.markSucceeded({
        organizationId: null,
        jobId: job.id,
        workerIdentifier,
        completedAt: now,
      });
    }
    return { kind: 'already_complete' };
  }
  if (syncRun.state === 'not_modified') {
    if (job.status === 'running' && job.workerIdentifier === workerIdentifier) {
      await dependencies.jobs.markSucceeded({
        organizationId: null,
        jobId: job.id,
        workerIdentifier,
        completedAt: now,
      });
    }
    return { kind: 'already_complete' };
  }
  const code = syncRun.failureCode ?? 'processing_failed';
  const classification = classifyIntelligenceSafeFailure(code);
  if (job.status === 'running' && job.workerIdentifier === workerIdentifier) {
    await dependencies.jobs.markTerminalFailure({
      organizationId: null,
      jobId: job.id,
      workerIdentifier,
      failureCategory: classification.category,
      failureCode: code,
      completedAt: now,
    });
  }
  if (syncRun.state === 'quarantined') {
    return { kind: 'quarantined', code };
  }
  return { kind: 'failed', code };
}

async function dispatch(
  dependencies: CisaKevSynchronizationDependencies,
  context: ExecutionContext,
): Promise<CisaKevSynchronizationOutcome> {
  switch (context.syncRun.state) {
    case 'requested':
    case 'retry_wait':
      return fetchFromClaim(dependencies, context);
    case 'fetching':
      return fetchCatalog(dependencies, context);
    case 'stored':
    case 'parsing':
    case 'staging':
      return parseAndStage(dependencies, context);
    case 'activating':
      return activate(dependencies, context);
    default:
      return { kind: 'rejected', code: 'processing_failed' };
  }
}

async function fetchFromClaim(
  dependencies: CisaKevSynchronizationDependencies,
  context: ExecutionContext,
): Promise<CisaKevSynchronizationOutcome> {
  const claimed = await dependencies.unitOfWork.claimFetchingAttempt({
    syncRunId: context.syncRun.id,
    expectedState: context.syncRun.state === 'retry_wait' ? 'retry_wait' : 'requested',
    expectedVersion: context.syncRun.version,
    claimedAt: dependencies.clock.now(),
    correlationId: context.syncRun.correlationId,
  });
  if (!claimed.ok) {
    const reloaded = await dependencies.syncRuns.findById(context.syncRun.id);
    if (reloaded === undefined) {
      return { kind: 'failed', code: 'persistence_failed' };
    }
    context.syncRun = reloaded;
    if (reloaded.state === 'fetching' && reloaded.executionAttempt === context.job.attempt) {
      return fetchCatalog(dependencies, context);
    }
    return dispatch(dependencies, context);
  }
  if (claimed.value.executionAttempt > context.job.attempt) {
    return { kind: 'inconsistent' };
  }
  context.syncRun = claimed.value;
  return fetchCatalog(dependencies, context);
}

async function fetchCatalog(
  dependencies: CisaKevSynchronizationDependencies,
  context: ExecutionContext,
): Promise<CisaKevSynchronizationOutcome> {
  const renewed = await context.heartbeat.renewNow();
  if (!renewed.ok) {
    return applyFailure(dependencies, context, 'request_cancelled', 'pre_snapshot');
  }

  await dependencies.freshness.markAttemptStarted({
    provider: 'cisa_kev',
    sourceIdentifier: CISA_KEV_SOURCE_IDENTIFIER,
    attemptedAt: dependencies.clock.now(),
  });

  const http = await dependencies.http.fetchCatalog({
    provider: 'cisa_kev',
    sourceIdentifier: CISA_KEV_SOURCE_IDENTIFIER,
    maxBytes: dependencies.config.kevResponseMaxBytes,
    connectTimeoutMs: dependencies.config.httpConnectTimeoutMs,
    totalTimeoutMs: dependencies.config.httpTotalTimeoutMs,
    retryPolicy: {
      maxRetries: dependencies.config.httpRetryCount,
      backoffFloorMs: dependencies.config.httpBackoffFloorMs,
      backoffCeilingMs: dependencies.config.httpBackoffCeilingMs,
    },
    correlationId: context.syncRun.correlationId,
    signal: context.heartbeat.signal,
  });

  if (http.kind === 'not_modified') {
    return applyFailure(dependencies, context, 'provider_client_error', 'pre_snapshot');
  }
  if (http.kind === 'failure') {
    return applyFailure(dependencies, context, http.code, 'pre_snapshot');
  }

  const afterHttp = await context.heartbeat.renewNow();
  if (!afterHttp.ok) {
    await http.cancel();
    return applyFailure(dependencies, context, 'request_cancelled', 'pre_snapshot');
  }

  const keys = createIntelligenceSnapshotObjectKeyBuilder();
  const uploadId = dependencies.createId();
  const temporary = keys.buildTemporary(uploadId);
  if (!temporary.ok) {
    await http.cancel();
    return applyFailure(dependencies, context, 'processing_failed', 'pre_snapshot');
  }

  const declaredContentType = safeContentType(http.declaredContentType);
  if (http.declaredContentType !== null && declaredContentType === null) {
    await http.cancel();
    await bestEffortDeleteTemp(dependencies, temporary.value, context);
    return applyFailure(dependencies, context, 'content_type_invalid', 'pre_snapshot');
  }

  const put = await dependencies.storage.putTemporarySnapshot({
    temporaryObjectKey: temporary.value,
    body: http.body,
    contentType: declaredContentType ?? 'application/json',
    maxBytes: dependencies.config.kevResponseMaxBytes,
    ...(http.declaredByteLength === null ? {} : { declaredByteLength: http.declaredByteLength }),
    signal: context.heartbeat.signal,
  });
  const httpCompletion = await http.completion;
  if (!put.ok) {
    await bestEffortDeleteTemp(dependencies, temporary.value, context);
    return applyFailure(dependencies, context, put.error.code, 'pre_snapshot');
  }
  if (
    put.value.observedByteLength !== httpCompletion.observedByteLength ||
    put.value.sha256 !== httpCompletion.sha256
  ) {
    await bestEffortDeleteTemp(dependencies, temporary.value, context);
    return applyFailure(dependencies, context, 'hash_mismatch', 'pre_snapshot');
  }

  const beforePromote = await context.heartbeat.renewNow();
  if (!beforePromote.ok) {
    await bestEffortDeleteTemp(dependencies, temporary.value, context);
    return applyFailure(dependencies, context, 'request_cancelled', 'pre_snapshot');
  }

  const finalKey = keys.buildFinal(put.value.sha256);
  if (!finalKey.ok) {
    await bestEffortDeleteTemp(dependencies, temporary.value, context);
    return applyFailure(dependencies, context, 'processing_failed', 'pre_snapshot');
  }

  const promoted = await dependencies.storage.promoteTemporarySnapshot({
    temporaryObjectKey: temporary.value,
    finalObjectKey: finalKey.value,
    expectedSha256: put.value.sha256,
    expectedByteLength: put.value.observedByteLength,
    contentType: declaredContentType ?? 'application/json',
    signal: context.heartbeat.signal,
  });
  if (!promoted.ok) {
    await bestEffortDeleteTemp(dependencies, temporary.value, context);
    return applyFailure(dependencies, context, promoted.error.code, 'pre_snapshot');
  }

  const head = await dependencies.storage.headFinalSnapshot({
    finalObjectKey: finalKey.value,
    signal: context.heartbeat.signal,
  });
  if (!head.ok || !head.value.exists) {
    return applyFailure(dependencies, context, 'snapshot_storage_failed', 'pre_snapshot');
  }
  if (
    head.value.sha256 !== put.value.sha256 ||
    head.value.byteLength !== put.value.observedByteLength ||
    head.value.provider !== 'cisa_kev' ||
    head.value.sourceIdentifier !== CISA_KEV_SOURCE_IDENTIFIER
  ) {
    return applyFailure(dependencies, context, 'hash_mismatch', 'pre_snapshot');
  }

  const afterMetaPrep = await context.heartbeat.renewNow();
  if (!afterMetaPrep.ok) {
    return applyFailure(dependencies, context, 'request_cancelled', 'pre_snapshot');
  }

  const now = dependencies.clock.now();
  const snapshotRecord: IntelligenceSnapshotRecord = {
    id: dependencies.createId(),
    provider: 'cisa_kev',
    sourceIdentifier: CISA_KEV_SOURCE_IDENTIFIER,
    responseSha256: put.value.sha256,
    byteLength: put.value.observedByteLength,
    declaredContentType,
    detectedContentType: safeContentType(head.value.detectedContentType),
    objectKey: finalKey.value,
    retrievedAt: now,
    storedAt: now,
    etagHash: http.etagHash,
    lastModified: http.lastModified,
    creatingSyncRunId: context.syncRun.id,
    createdAt: now,
  };

  const activeGeneration = await dependencies.generations.findActiveGeneration(
    'cisa_kev',
    CISA_KEV_SOURCE_IDENTIFIER,
  );
  let notModified:
    | {
        priorAcceptedGenerationId: string;
        reason: 'content_sha256_unchanged';
        completedAt: Date;
        backgroundJob: IntelligenceJobOwnership;
      }
    | undefined;
  if (activeGeneration !== undefined) {
    const activeSnapshot = await dependencies.snapshots.findById(activeGeneration.snapshotId);
    const decision = decideContentHashNotModified({
      activeGeneration,
      activeSnapshot,
      fetchedSnapshotSha256: snapshotRecord.responseSha256,
      syncRunParserVersion: context.syncRun.parserVersion,
      syncRunNormalizationVersion: context.syncRun.normalizationVersion,
    });
    if (decision.kind === 'not_modified') {
      notModified = {
        priorAcceptedGenerationId: decision.priorAcceptedGenerationId,
        reason: decision.reason,
        completedAt: now,
        backgroundJob: context.ownership,
      };
    }
  }

  const stored = await dependencies.unitOfWork.storeFetchedSnapshot({
    snapshot: snapshotRecord,
    syncRunId: context.syncRun.id,
    expectedState: 'fetching',
    expectedVersion: context.syncRun.version,
    correlationId: context.syncRun.correlationId,
    ...(notModified === undefined ? {} : { notModified }),
  });
  if (!stored.ok) {
    return applyFailure(dependencies, context, 'persistence_failed', 'pre_snapshot');
  }
  context.syncRun = stored.value.syncRun;
  if (stored.value.outcome === 'not_modified') {
    logSafe(dependencies, context, 'info', 'intelligence sync not modified');
    return { kind: 'not_modified', reason: 'content_sha256_unchanged' };
  }

  const afterStored = await context.heartbeat.renewNow();
  if (!afterStored.ok) {
    return applyFailure(dependencies, context, 'request_cancelled', 'post_snapshot');
  }
  return parseAndStage(dependencies, context);
}

async function parseAndStage(
  dependencies: CisaKevSynchronizationDependencies,
  context: ExecutionContext,
): Promise<CisaKevSynchronizationOutcome> {
  if (context.syncRun.snapshotId === null) {
    return applyFailure(dependencies, context, 'snapshot_missing', 'post_snapshot');
  }
  const snapshot = await dependencies.snapshots.findById(context.syncRun.snapshotId);
  if (snapshot === undefined) {
    return applyFailure(dependencies, context, 'snapshot_missing', 'post_snapshot');
  }

  const beforeGet = await context.heartbeat.renewNow();
  if (!beforeGet.ok) {
    return applyFailure(dependencies, context, 'request_cancelled', 'post_snapshot');
  }

  const got = await dependencies.storage.getFinalSnapshot({
    finalObjectKey: snapshot.objectKey,
    maxBytes: dependencies.config.kevResponseMaxBytes,
    expectedByteLength: snapshot.byteLength,
    expectedSha256: snapshot.responseSha256,
    signal: context.heartbeat.signal,
  });
  if (!got.ok) {
    return applyFailure(dependencies, context, got.error.code, 'post_snapshot');
  }

  const collected = await collectBoundedKevSnapshotBuffer({
    result: got.value,
    maxBytes: dependencies.config.kevResponseMaxBytes,
    expectedSha256: snapshot.responseSha256,
    expectedByteLength: snapshot.byteLength,
    ...(got.value.declaredByteLength === undefined
      ? {}
      : { declaredByteLength: got.value.declaredByteLength }),
  });
  if (!collected.ok) {
    return applyFailure(dependencies, context, collected.error.code, 'post_snapshot');
  }

  if (context.syncRun.state === 'stored') {
    const parsing = await dependencies.syncRuns.recordParsing({
      syncRunId: context.syncRun.id,
      expectedState: 'stored',
      expectedVersion: context.syncRun.version,
      command: { type: 'start_parsing' },
    });
    if (parsing.ok) {
      context.syncRun = parsing.value;
    } else {
      const reloaded = await dependencies.syncRuns.findById(context.syncRun.id);
      if (
        reloaded === undefined ||
        (reloaded.state !== 'parsing' && reloaded.state !== 'staging')
      ) {
        return applyFailure(dependencies, context, 'persistence_failed', 'post_snapshot');
      }
      context.syncRun = reloaded;
    }
  }

  const beforeParse = await context.heartbeat.renewNow();
  if (!beforeParse.ok) {
    return applyFailure(dependencies, context, 'request_cancelled', 'post_snapshot');
  }

  const parsed = await dependencies.parser.parse(
    {
      requestId: dependencies.createId(),
      bytes: collected.value.bytes,
      expectedSha256: snapshot.responseSha256,
      expectedByteLength: snapshot.byteLength,
      limits: parserLimits(dependencies.config),
      parserVersion: context.syncRun.parserVersion,
      normalizationVersion: context.syncRun.normalizationVersion,
    },
    {
      timeoutMs: dependencies.config.kevParserTimeoutMs,
      signal: context.heartbeat.signal,
    },
  );

  const afterParse = await context.heartbeat.renewNow();
  if (!afterParse.ok) {
    return applyFailure(dependencies, context, 'request_cancelled', 'post_snapshot');
  }

  if (!parsed.ok) {
    const code =
      context.heartbeat.signal.aborted &&
      (parsed.code === 'parser_timeout' || parsed.code === 'request_cancelled')
        ? 'request_cancelled'
        : parsed.code;
    return applyFailure(dependencies, context, code, 'post_snapshot');
  }

  const parserCheck = verifyParserSuccess(parsed, context.syncRun, dependencies.config);
  if (!parserCheck.ok) {
    return applyFailure(dependencies, context, parserCheck.code, 'post_snapshot');
  }

  const activeGeneration = await dependencies.generations.findActiveGeneration(
    'cisa_kev',
    CISA_KEV_SOURCE_IDENTIFIER,
  );
  const activeSnapshot =
    activeGeneration === undefined
      ? undefined
      : await dependencies.snapshots.findById(activeGeneration.snapshotId);
  const releasedAt = parseUtcInstant(parsed.catalogReleasedAt);
  if (!releasedAt.ok) {
    return applyFailure(dependencies, context, 'catalog_release_date_invalid', 'post_snapshot');
  }
  const regression = decideCatalogRegression({
    activeGeneration,
    catalogReleasedAt: releasedAt.value,
    snapshotSha256: snapshot.responseSha256,
    activeSnapshotSha256: activeSnapshot?.responseSha256,
    syncRunParserVersion: context.syncRun.parserVersion,
    syncRunNormalizationVersion: context.syncRun.normalizationVersion,
  });
  if (regression.kind === 'quarantine') {
    return applyFailure(dependencies, context, regression.code, 'post_snapshot');
  }

  return stageGeneration(dependencies, context, {
    snapshot,
    parsed,
    warningCount: parserCheck.warningCount,
    catalogReleasedAt: releasedAt.value,
  });
}

function verifyParserSuccess(
  parsed: IntelligenceKevParserSuccess,
  syncRun: IntelligenceSyncRunRecord,
  config: CisaKevSynchronizationConfig,
): { ok: true; warningCount: number } | { ok: false; code: IntelligenceSafeFailureCode } {
  if (
    parsed.parserVersion !== syncRun.parserVersion ||
    parsed.normalizationVersion !== syncRun.normalizationVersion
  ) {
    return { ok: false, code: 'processing_failed' };
  }
  if (parsed.expectedEntryCount !== parsed.entryCount) {
    return { ok: false, code: 'count_mismatch' };
  }
  if (parsed.serializedResultBytes > INTELLIGENCE_PARSER_RESULT_MAX_SERIALIZED_BYTES) {
    return { ok: false, code: 'normalized_output_too_large' };
  }
  const warnings = sumParserWarningCounts(parsed.warnings);
  if (!warnings.ok) {
    return warnings;
  }
  if (warnings.count > parsed.entryCount) {
    return { ok: false, code: 'processing_failed' };
  }
  if (parsed.entryCount > config.kevMaxVulnerabilityCount) {
    return { ok: false, code: 'vulnerability_count_limit' };
  }
  return { ok: true, warningCount: warnings.count };
}

async function stageGeneration(
  dependencies: CisaKevSynchronizationDependencies,
  context: ExecutionContext,
  input: {
    snapshot: IntelligenceSnapshotRecord;
    parsed: IntelligenceKevParserSuccess;
    warningCount: number;
    catalogReleasedAt: Date;
  },
): Promise<CisaKevSynchronizationOutcome> {
  let generation: KevGenerationRecord;
  if (context.syncRun.generationId === null) {
    const created = await dependencies.unitOfWork.createStagingGenerationAndRun({
      generation: {
        id: dependencies.createId(),
        syncRunId: context.syncRun.id,
        snapshotId: input.snapshot.id,
        provider: 'cisa_kev',
        sourceIdentifier: CISA_KEV_SOURCE_IDENTIFIER,
        expectedEntryCount: input.parsed.expectedEntryCount,
        parserVersion: context.syncRun.parserVersion,
        normalizationVersion: context.syncRun.normalizationVersion,
        catalogVersion: input.parsed.catalogVersion,
        catalogReleasedAt: input.catalogReleasedAt,
        createdAt: dependencies.clock.now(),
      },
      syncRunId: context.syncRun.id,
      expectedState: 'parsing',
      expectedVersion: context.syncRun.version,
    });
    if (!created.ok) {
      const existing = await dependencies.generations.findBySyncRunId(context.syncRun.id);
      if (existing === undefined) {
        return applyFailure(dependencies, context, 'persistence_failed', 'post_snapshot');
      }
      generation = existing;
      const reloaded = await dependencies.syncRuns.findById(context.syncRun.id);
      if (reloaded === undefined) {
        return applyFailure(dependencies, context, 'persistence_failed', 'post_snapshot');
      }
      context.syncRun = reloaded;
    } else {
      generation = created.value.generation;
      context.syncRun = created.value.syncRun;
    }
  } else {
    const existing = await dependencies.generations.findById(context.syncRun.generationId);
    if (existing === undefined) {
      return applyFailure(dependencies, context, 'generation_incomplete', 'post_snapshot');
    }
    generation = existing;
  }

  if (
    generation.syncRunId !== context.syncRun.id ||
    generation.snapshotId !== input.snapshot.id ||
    generation.parserVersion !== context.syncRun.parserVersion ||
    generation.normalizationVersion !== context.syncRun.normalizationVersion ||
    generation.expectedEntryCount !== input.parsed.expectedEntryCount
  ) {
    return applyFailure(dependencies, context, 'generation_incomplete', 'post_snapshot');
  }
  if (generation.state !== 'staging' && generation.state !== 'complete') {
    return applyFailure(dependencies, context, 'generation_incomplete', 'post_snapshot');
  }

  if (generation.state === 'staging') {
    const prefixRows = await dependencies.generations.inspectStagedPrefix({
      generationId: generation.id,
      snapshotId: input.snapshot.id,
      fromOrdinal: 0,
      limit: dependencies.config.kevMaxVulnerabilityCount,
    });
    const counts = await dependencies.generations.inspectStagedCounts(generation.id);
    if (counts === undefined) {
      return applyFailure(dependencies, context, 'generation_incomplete', 'post_snapshot');
    }
    const prefix = verifyDenseStagedPrefix({
      staged: prefixRows,
      parsed: input.parsed.entries,
      authoritativeCount: counts.stagedEntryCount,
    });
    if (!prefix.ok) {
      return applyFailure(dependencies, context, prefix.code, 'post_snapshot');
    }

    let cursor = prefix.resumeOrdinal;
    while (cursor < input.parsed.entries.length) {
      const lease = await context.heartbeat.renewNow();
      if (!lease.ok) {
        return applyFailure(dependencies, context, 'request_cancelled', 'post_snapshot');
      }
      const reloadedRun = await dependencies.syncRuns.findById(context.syncRun.id);
      if (
        reloadedRun === undefined ||
        reloadedRun.state !== 'staging' ||
        reloadedRun.generationId !== generation.id
      ) {
        return applyFailure(dependencies, context, 'generation_incomplete', 'post_snapshot');
      }
      context.syncRun = reloadedRun;
      const batch = input.parsed.entries.slice(
        cursor,
        cursor + dependencies.config.maxStagedRowsPerTransaction,
      );
      const mapped = mapEntries(
        batch,
        generation.id,
        input.snapshot.id,
        dependencies.createId,
        dependencies.clock.now(),
      );
      if (!mapped.ok) {
        return applyFailure(dependencies, context, 'generation_incomplete', 'post_snapshot');
      }
      const staged = await dependencies.generations.stageBoundedEntryBatch({
        generationId: generation.id,
        snapshotId: input.snapshot.id,
        provider: 'cisa_kev',
        sourceIdentifier: CISA_KEV_SOURCE_IDENTIFIER,
        maxBatchSize: dependencies.config.maxStagedRowsPerTransaction,
        entries: mapped.value,
      });
      if (!staged.ok) {
        return applyFailure(dependencies, context, 'persistence_failed', 'post_snapshot');
      }
      cursor += batch.length;
      const afterBatch = await context.heartbeat.renewNow();
      if (!afterBatch.ok) {
        return applyFailure(dependencies, context, 'request_cancelled', 'post_snapshot');
      }
    }

    const beforeComplete = await context.heartbeat.renewNow();
    if (!beforeComplete.ok) {
      return applyFailure(dependencies, context, 'request_cancelled', 'post_snapshot');
    }
    const finalCounts = await dependencies.generations.inspectStagedCounts(generation.id);
    if (
      finalCounts === undefined ||
      finalCounts.stagedEntryCount !== input.parsed.expectedEntryCount ||
      finalCounts.distinctCveCount !== input.parsed.expectedEntryCount
    ) {
      return applyFailure(dependencies, context, 'generation_incomplete', 'post_snapshot');
    }
    const completed = await dependencies.unitOfWork.completeStagedGeneration({
      generation: {
        generationId: generation.id,
        expectedEntryCount: input.parsed.expectedEntryCount,
        actualStagedDistinctCveCount: finalCounts.distinctCveCount,
        parserVersion: context.syncRun.parserVersion,
        normalizationVersion: context.syncRun.normalizationVersion,
        catalogVersion: input.parsed.catalogVersion,
        catalogReleasedAt: input.catalogReleasedAt,
        completedAt: dependencies.clock.now(),
      },
      syncRunId: context.syncRun.id,
      expectedState: 'staging',
      expectedVersion: context.syncRun.version,
      correlationId: context.syncRun.correlationId,
      warningCount: input.warningCount,
    });
    if (!completed.ok) {
      const reloaded = await dependencies.syncRuns.findById(context.syncRun.id);
      if (reloaded === undefined) {
        return applyFailure(dependencies, context, 'persistence_failed', 'post_snapshot');
      }
      context.syncRun = reloaded;
      if (reloaded.state !== 'activating' && reloaded.state !== 'completed') {
        return applyFailure(dependencies, context, 'persistence_failed', 'post_snapshot');
      }
    } else {
      context.syncRun = completed.value.syncRun;
    }
  }

  return activate(dependencies, context, input.warningCount);
}

function mapEntries(
  entries: readonly IntelligenceKevParsedEntry[],
  generationId: string,
  snapshotId: string,
  createId: () => string,
  createdAt: Date,
): Result<KevNormalizedEntryRecord[], { code: IntelligenceSafeFailureCode }> {
  const mapped: KevNormalizedEntryRecord[] = [];
  for (const entry of entries) {
    const record: KevNormalizedEntryRecord = {
      id: createId(),
      generationId,
      snapshotId,
      ordinal: entry.ordinal,
      normalizedCve: entry.normalizedCve as CanonicalCve,
      vendorProject: entry.vendorProject,
      product: entry.product,
      vulnerabilityName: entry.vulnerabilityName,
      dateAdded: entry.dateAdded as CalendarDate,
      shortDescription: entry.shortDescription,
      requiredAction: entry.requiredAction,
      dueDate: entry.dueDate as CalendarDate,
      knownRansomwareCampaignUse: entry.knownRansomwareCampaignUse,
      rawKnownRansomwareCampaignUse: entry.rawKnownRansomwareCampaignUse,
      notes: entry.notes,
      cwes: entry.cwes,
      createdAt,
    };
    const validated = validateKevNormalizedEntryRecord(record);
    if (!validated.ok) {
      return err({ code: 'generation_incomplete' });
    }
    mapped.push(validated.value);
  }
  return ok(mapped);
}

async function activate(
  dependencies: CisaKevSynchronizationDependencies,
  context: ExecutionContext,
  parsedWarningCount?: number,
): Promise<CisaKevSynchronizationOutcome> {
  const reloaded = await dependencies.syncRuns.findById(context.syncRun.id);
  if (reloaded === undefined) {
    return applyFailure(dependencies, context, 'persistence_failed', 'post_snapshot');
  }
  context.syncRun = reloaded;
  if (reloaded.state === 'completed') {
    return reconcileTerminal(
      dependencies,
      context.job,
      reloaded,
      context.ownership.workerIdentifier,
    );
  }
  if (reloaded.generationId === null || reloaded.snapshotId === null) {
    return { kind: 'inconsistent' };
  }
  const generation = await dependencies.generations.findById(reloaded.generationId);
  if (generation === undefined) {
    return applyFailure(dependencies, context, 'generation_incomplete', 'post_snapshot');
  }
  if (generation.state === 'active') {
    return { kind: 'inconsistent' };
  }
  if (generation.state !== 'complete') {
    return applyFailure(dependencies, context, 'generation_incomplete', 'post_snapshot');
  }

  const warningCount = parsedWarningCount ?? reloaded.warningCount ?? 0;

  if (reloaded.state === 'staging') {
    const activating = await dependencies.syncRuns.recordActivationStarted({
      syncRunId: reloaded.id,
      expectedState: 'staging',
      expectedVersion: reloaded.version,
      command: {
        type: 'start_activating',
        generationComplete: true,
        warningCount,
      },
    });
    if (activating.ok) {
      context.syncRun = activating.value;
    } else {
      const again = await dependencies.syncRuns.findById(reloaded.id);
      if (again === undefined) {
        return applyFailure(dependencies, context, 'persistence_failed', 'post_snapshot');
      }
      context.syncRun = again;
    }
  }

  const beforeActivate = await context.heartbeat.renewNow();
  if (!beforeActivate.ok) {
    return applyFailure(dependencies, context, 'request_cancelled', 'post_snapshot');
  }

  const pointer = await dependencies.freshness.loadCisaKevSourcePointer();
  if (pointer === undefined) {
    return applyFailure(dependencies, context, 'persistence_failed', 'post_snapshot');
  }
  if (context.syncRun.state !== 'activating') {
    if (context.syncRun.state === 'completed') {
      return reconcileTerminal(
        dependencies,
        context.job,
        context.syncRun,
        context.ownership.workerIdentifier,
      );
    }
    return applyFailure(dependencies, context, 'activation_conflict', 'post_snapshot');
  }

  const result = await dependencies.unitOfWork.activateCompleteGeneration({
    generationId: generation.id,
    expectedEntryCount: generation.expectedEntryCount,
    parserVersion: generation.parserVersion,
    normalizationVersion: generation.normalizationVersion,
    provider: 'cisa_kev',
    sourceIdentifier: CISA_KEV_SOURCE_IDENTIFIER,
    snapshotId: generation.snapshotId,
    previousActiveGenerationId: pointer.activeGenerationId,
    expectedSourceVersion: pointer.version,
    activatedAt: dependencies.clock.now(),
    acceptedEntryCount: generation.expectedEntryCount,
    warningCount,
    correlationId: context.syncRun.correlationId,
    syncRunId: context.syncRun.id,
    expectedSyncRunState: 'activating',
    expectedSyncRunVersion: context.syncRun.version,
    backgroundJob: context.ownership,
  });
  if (!result.ok) {
    const latest = await dependencies.syncRuns.findById(context.syncRun.id);
    if (
      latest !== undefined &&
      latest.state === 'completed' &&
      latest.generationId === generation.id
    ) {
      return reconcileTerminal(
        dependencies,
        context.job,
        latest,
        context.ownership.workerIdentifier,
      );
    }
    return applyFailure(dependencies, context, 'activation_conflict', 'post_snapshot');
  }
  logSafe(dependencies, context, 'info', 'intelligence sync completed');
  return {
    kind: 'completed',
    acceptedEntryCount: result.value.syncRun.acceptedEntryCount ?? generation.expectedEntryCount,
    warningCount: result.value.syncRun.warningCount ?? 0,
  };
}

async function applyFailure(
  dependencies: CisaKevSynchronizationDependencies,
  context: ExecutionContext,
  code: IntelligenceSafeFailureCode,
  layer: 'pre_snapshot' | 'post_snapshot',
): Promise<CisaKevSynchronizationOutcome> {
  const remaining = attemptsRemain(context.job.attempt, dependencies.config.syncMaxAttempts);
  const mapped = mapIntelligenceSyncFailure({ code, layer, attemptsRemaining: remaining });
  const now = dependencies.clock.now();
  const classification = classifyIntelligenceSafeFailure(code);

  if (mapped.kind === 'retry_wait') {
    const delay = intelligenceRetryWaitDelayMs(context.job.attempt, {
      floorMs: dependencies.config.syncRetryWaitFloorMs,
      ceilingMs: dependencies.config.syncRetryWaitCeilingMs,
    });
    const nextAttemptAt = new Date(now.getTime() + delay);
    const waited = await dependencies.unitOfWork.recordRetryWait({
      syncRunId: context.syncRun.id,
      expectedState: context.syncRun.state,
      expectedVersion: context.syncRun.version,
      nextAttemptAt,
      failureCode: code,
      attemptedAt: now,
      backgroundJob: context.ownership,
    });
    if (!waited.ok) {
      const reloaded = await dependencies.syncRuns.findById(context.syncRun.id);
      if (reloaded !== undefined && isIntelligenceTerminalSyncRunState(reloaded.state)) {
        return reconcileTerminal(
          dependencies,
          context.job,
          reloaded,
          context.ownership.workerIdentifier,
        );
      }
      return { kind: 'job_retry', code: 'persistence_failed' };
    }
    logSafe(dependencies, context, 'warn', 'intelligence sync retry wait');
    return { kind: 'retry_wait', code, nextAttemptAt };
  }

  if (mapped.kind === 'job_retry') {
    await dependencies.freshness.markDegradedFailure({
      provider: 'cisa_kev',
      sourceIdentifier: CISA_KEV_SOURCE_IDENTIFIER,
      failedAt: now,
      failureCode: code,
    });
    const retried = await dependencies.jobs.markRetry({
      organizationId: null,
      jobId: context.job.id,
      workerIdentifier: context.ownership.workerIdentifier,
      failureCategory: classification.category,
      failureCode: code,
      availableAt: now,
    });
    if (!retried.ok) {
      return { kind: 'rejected', code: 'request_cancelled' };
    }
    logSafe(dependencies, context, 'warn', 'intelligence sync job retry');
    return { kind: 'job_retry', code };
  }

  const transition =
    mapped.kind === 'quarantined'
      ? dependencies.unitOfWork.quarantineRun.bind(dependencies.unitOfWork)
      : dependencies.unitOfWork.failRun.bind(dependencies.unitOfWork);
  const terminal = await transition({
    syncRunId: context.syncRun.id,
    expectedState: context.syncRun.state,
    expectedVersion: context.syncRun.version,
    completedAt: now,
    failureCode: code,
    correlationId: context.syncRun.correlationId,
    backgroundJob: context.ownership,
  });
  if (!terminal.ok) {
    const reloaded = await dependencies.syncRuns.findById(context.syncRun.id);
    if (reloaded !== undefined && isIntelligenceTerminalSyncRunState(reloaded.state)) {
      return reconcileTerminal(
        dependencies,
        context.job,
        reloaded,
        context.ownership.workerIdentifier,
      );
    }
    return { kind: 'job_retry', code: 'persistence_failed' };
  }
  logSafe(dependencies, context, 'warn', 'intelligence sync terminal failure');
  return mapped.kind === 'quarantined' ? { kind: 'quarantined', code } : { kind: 'failed', code };
}

async function bestEffortDeleteTemp(
  dependencies: CisaKevSynchronizationDependencies,
  temporaryObjectKey: Parameters<
    IntelligenceSnapshotStoragePort['deleteTemporarySnapshot']
  >[0]['temporaryObjectKey'],
  context: ExecutionContext,
): Promise<void> {
  try {
    await dependencies.storage.deleteTemporarySnapshot({
      temporaryObjectKey,
      signal: context.heartbeat.signal,
    });
  } catch {
    logSafe(dependencies, context, 'warn', 'intelligence temporary snapshot cleanup failed');
  }
}

function logSafe(
  dependencies: CisaKevSynchronizationDependencies,
  context: ExecutionContext,
  level: 'info' | 'warn',
  message: string,
): void {
  const bindings = {
    syncRunId: context.syncRun.id,
    backgroundJobId: context.job.id,
    state: context.syncRun.state,
    correlationId: context.syncRun.correlationId,
  };
  if (level === 'info') {
    dependencies.logger?.info(bindings, message);
    return;
  }
  dependencies.logger?.warn(bindings, message);
}
