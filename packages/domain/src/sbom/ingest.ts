import type { Clock } from '../clock.js';
import type { SbomIngestionRecord } from '../records.js';
import {
  sbomIngestionFailedAudit,
  sbomIngestionQuarantinedAudit,
  sbomIngestionRejectedAudit,
} from './audit.js';
import { classifySafeFailure, isSafeFailureCode, type SafeFailureCode } from './failures.js';
import { parseSbomIngestJobPayload, type SbomIngestJobPayload } from './ingest-job.js';
import { isFinalSbomObjectKey } from './object-keys.js';
import { readVerifiedObjectBuffer } from './object-bytes.js';
import type {
  BackgroundJobExecutionPort,
  ClassifiedStorageFailure,
  ComponentGraphPersistencePort,
  SbomDocumentParserPort,
  SbomIngestionPersistencePort,
  SbomIngestionProcessorUnitOfWork,
  SbomMetadataPersistencePort,
  SbomObjectStoragePort,
  StorageFailureCategory,
} from './ports.js';
import { isSession8TerminalState } from './transitions.js';
import type { SbomParserLimits } from './types.js';

export type ProcessSbomIngestionOutcome =
  | { kind: 'completed' }
  | { kind: 'already_complete' }
  | { kind: 'rejected'; code: SafeFailureCode }
  | { kind: 'quarantined'; code: SafeFailureCode }
  | { kind: 'failed'; code: SafeFailureCode }
  | { kind: 'retry'; code: SafeFailureCode }
  | { kind: 'skipped' };

export type ProcessSbomIngestionLogger = {
  warn(bindings: Record<string, unknown>, message: string): void;
};

export type ProcessSbomIngestionOptions = {
  workerIdentifier: string;
  processingLeaseMs: number;
  parserLimits: SbomParserLimits;
};

export type ProcessSbomIngestionDependencies = {
  clock: Clock;
  jobs: BackgroundJobExecutionPort;
  ingestions: SbomIngestionPersistencePort;
  sbomMetadata: SbomMetadataPersistencePort;
  storage: SbomObjectStoragePort;
  parser: SbomDocumentParserPort;
  graph: ComponentGraphPersistencePort;
  processorWork: SbomIngestionProcessorUnitOfWork;
  options: ProcessSbomIngestionOptions;
  logger?: ProcessSbomIngestionLogger;
};

export function mapStorageFailureToSafeCode(category: StorageFailureCategory): SafeFailureCode {
  switch (category) {
    case 'object_missing':
      return 'object_missing';
    case 'timeout':
    case 'aborted':
    case 'storage_unavailable':
      return 'storage_timeout';
    case 'invalid_content':
      return 'hash_mismatch';
    case 'size_limit':
      return 'payload_too_large';
    case 'bucket_missing':
    case 'access_denied':
    case 'copy_failed':
    case 'internal':
      return 'processing_failed';
  }
}

export function createProcessSbomIngestionUseCase(dependencies: ProcessSbomIngestionDependencies) {
  return {
    execute(rawPayload: unknown): Promise<ProcessSbomIngestionOutcome> {
      return processSbomIngestion(dependencies, rawPayload);
    },
  };
}

async function processSbomIngestion(
  dependencies: ProcessSbomIngestionDependencies,
  rawPayload: unknown,
): Promise<ProcessSbomIngestionOutcome> {
  const parsed = parseSbomIngestJobPayload(rawPayload);
  if (!parsed.ok) {
    dependencies.logger?.warn({ reason: 'invalid_payload' }, 'sbom ingest job payload rejected');
    return { kind: 'skipped' };
  }
  const payload = parsed.value;

  const job = await dependencies.jobs.findByOutboxEventId({
    organizationId: payload.organizationId,
    outboxEventId: payload.outboxEventId,
  });
  if (job === undefined || job.organizationId !== payload.organizationId) {
    return { kind: 'retry', code: 'queue_unavailable' };
  }
  if (job.jobType !== 'sbom.ingest') {
    return { kind: 'skipped' };
  }
  if (job.status === 'succeeded') {
    return { kind: 'already_complete' };
  }
  if (job.status === 'failed' || job.status === 'dead_lettered' || job.status === 'cancelled') {
    return { kind: 'failed', code: asSafeCode(job.failureCode) };
  }

  const now = dependencies.clock.now();
  const claim = await dependencies.jobs.claimExecution({
    organizationId: job.organizationId,
    jobId: job.id,
    workerIdentifier: dependencies.options.workerIdentifier,
    now,
    leaseExpiresAt: new Date(now.getTime() + dependencies.options.processingLeaseMs),
  });
  if (!claim.ok) {
    return { kind: 'retry', code: 'queue_unavailable' };
  }

  const ingestion = await dependencies.ingestions.findById(
    payload.organizationId,
    payload.aggregateId,
  );
  if (ingestion === undefined || ingestion.organizationId !== payload.organizationId) {
    return finalizeByCode(dependencies, {
      payload,
      jobId: job.id,
      sbomId: payload.aggregateId,
      ingestionVersion: 0,
      parserVersion: '0',
      code: 'processing_failed',
    });
  }

  if (ingestion.state === 'completed') {
    await dependencies.jobs.markSucceeded({
      organizationId: ingestion.organizationId,
      jobId: job.id,
      workerIdentifier: claim.value.workerIdentifier,
      completedAt: now,
    });
    return { kind: 'already_complete' };
  }

  if (isSession8TerminalState(ingestion.state)) {
    return alignTerminalJob(dependencies, {
      organizationId: ingestion.organizationId,
      jobId: job.id,
      workerIdentifier: claim.value.workerIdentifier,
      code: asSafeCode(ingestion.failureCode),
    });
  }

  const current = await loadProcessingIngestion(dependencies, {
    payload,
    jobId: job.id,
    workerIdentifier: claim.value.workerIdentifier,
    ingestion,
    now,
  });
  if ('kind' in current) {
    return current;
  }

  const sbom = await dependencies.sbomMetadata.findByAssetAndId(
    current.organizationId,
    current.assetId,
    current.sbomId,
  );
  if (sbom === undefined || sbom.organizationId !== current.organizationId) {
    return finalizeByCode(dependencies, {
      payload,
      jobId: job.id,
      sbomId: current.sbomId,
      ingestionVersion: current.version,
      parserVersion: current.parserVersion,
      code: 'object_missing',
    });
  }
  if (!isFinalSbomObjectKey(sbom.objectKey)) {
    return finalizeByCode(dependencies, {
      payload,
      jobId: job.id,
      sbomId: sbom.id,
      ingestionVersion: current.version,
      parserVersion: current.parserVersion,
      code: 'processing_failed',
    });
  }

  const downloaded = await dependencies.storage.getObject({
    finalObjectKey: sbom.objectKey,
    maxBytes: dependencies.options.parserLimits.maxBytes,
    expectedByteLength: sbom.byteLength,
    expectedSha256: sbom.sha256,
  });
  if (!downloaded.ok) {
    return handleStorageFailure(dependencies, {
      payload,
      jobId: job.id,
      sbomId: sbom.id,
      ingestionVersion: current.version,
      parserVersion: current.parserVersion,
      failure: downloaded.error,
    });
  }

  const verified = await readVerifiedObjectBuffer(downloaded.value, {
    sha256: sbom.sha256,
    byteLength: sbom.byteLength,
    maxBytes: dependencies.options.parserLimits.maxBytes,
  });
  if (!verified.ok) {
    return finalizeByCode(dependencies, {
      payload,
      jobId: job.id,
      sbomId: sbom.id,
      ingestionVersion: current.version,
      parserVersion: current.parserVersion,
      code: verified.error.code,
    });
  }

  const parsedDocument = await dependencies.parser.parse({
    bytes: verified.value.bytes,
    expectedSha256: sbom.sha256,
    byteLength: sbom.byteLength,
    limits: dependencies.options.parserLimits,
    parserVersion: current.parserVersion,
    normalizationVersion: current.normalizationVersion,
  });
  if (!parsedDocument.ok) {
    return finalizeByCode(dependencies, {
      payload,
      jobId: job.id,
      sbomId: sbom.id,
      ingestionVersion: current.version,
      parserVersion: current.parserVersion,
      code: parsedDocument.code,
    });
  }

  const persisted = await dependencies.graph.persistOnceForIngestion({
    organizationId: current.organizationId,
    assetId: current.assetId,
    sbomId: sbom.id,
    sbomIngestionId: current.id,
    graph: parsedDocument.graph,
    correlationId: payload.outboxEventId,
    ownedJob: {
      jobId: job.id,
      workerIdentifier: claim.value.workerIdentifier,
      completedAt: dependencies.clock.now(),
    },
  });
  if (!persisted.ok) {
    return handlePersistFailure(dependencies, {
      payload,
      jobId: job.id,
      workerIdentifier: claim.value.workerIdentifier,
      sbomId: sbom.id,
      ingestion: current,
      persistCode: persisted.error.code,
    });
  }
  return { kind: 'completed' };
}

async function loadProcessingIngestion(
  dependencies: ProcessSbomIngestionDependencies,
  input: {
    payload: SbomIngestJobPayload;
    jobId: string;
    workerIdentifier: string;
    ingestion: SbomIngestionRecord;
    now: Date;
  },
): Promise<SbomIngestionRecord | ProcessSbomIngestionOutcome> {
  const { ingestion } = input;
  if (ingestion.state === 'processing') {
    return ingestion;
  }
  if (ingestion.state !== 'accepted' && ingestion.state !== 'queued') {
    return ingestion;
  }

  const started = await dependencies.ingestions.applyTransition(
    ingestion.organizationId,
    ingestion.id,
    ingestion.version,
    { type: 'start_processing', startedAt: input.now, stage: 'validate' },
  );
  if (started.ok) {
    return started.value.record;
  }

  const reloaded = await dependencies.ingestions.findById(ingestion.organizationId, ingestion.id);
  if (reloaded?.state === 'processing') {
    return reloaded;
  }
  if (reloaded?.state === 'completed') {
    await dependencies.jobs.markSucceeded({
      organizationId: ingestion.organizationId,
      jobId: input.jobId,
      workerIdentifier: input.workerIdentifier,
      completedAt: input.now,
    });
    return { kind: 'already_complete' };
  }
  if (reloaded !== undefined && isSession8TerminalState(reloaded.state)) {
    return alignTerminalJob(dependencies, {
      organizationId: ingestion.organizationId,
      jobId: input.jobId,
      workerIdentifier: input.workerIdentifier,
      code: asSafeCode(reloaded.failureCode),
    });
  }

  await dependencies.jobs.markRetry({
    organizationId: input.payload.organizationId,
    jobId: input.jobId,
    failureCategory: classifySafeFailure('queue_unavailable').category,
    failureCode: 'queue_unavailable',
    availableAt: input.now,
  });
  return { kind: 'retry', code: 'queue_unavailable' };
}

async function handlePersistFailure(
  dependencies: ProcessSbomIngestionDependencies,
  input: {
    payload: SbomIngestJobPayload;
    jobId: string;
    workerIdentifier: string;
    sbomId: string;
    ingestion: SbomIngestionRecord;
    persistCode: string;
  },
): Promise<ProcessSbomIngestionOutcome> {
  if (input.persistCode === 'validation') {
    return finalizeByCode(dependencies, {
      payload: input.payload,
      jobId: input.jobId,
      sbomId: input.sbomId,
      ingestionVersion: input.ingestion.version,
      parserVersion: input.ingestion.parserVersion,
      code: 'processing_failed',
    });
  }

  const latest = await dependencies.ingestions.findById(
    input.ingestion.organizationId,
    input.ingestion.id,
  );
  if (latest?.state === 'completed') {
    await dependencies.jobs.markSucceeded({
      organizationId: input.ingestion.organizationId,
      jobId: input.jobId,
      workerIdentifier: input.workerIdentifier,
      completedAt: dependencies.clock.now(),
    });
    return { kind: 'already_complete' };
  }
  if (latest !== undefined && isSession8TerminalState(latest.state)) {
    return alignTerminalJob(dependencies, {
      organizationId: input.ingestion.organizationId,
      jobId: input.jobId,
      workerIdentifier: input.workerIdentifier,
      code: asSafeCode(latest.failureCode),
    });
  }

  return releaseForRetry(dependencies, {
    payload: input.payload,
    jobId: input.jobId,
    sbomId: input.sbomId,
    ingestionVersion: input.ingestion.version,
    parserVersion: input.ingestion.parserVersion,
    code: 'storage_timeout',
  });
}

type ProcessorFailureInput = {
  payload: SbomIngestJobPayload;
  jobId: string;
  sbomId: string;
  ingestionVersion: number;
  parserVersion: string;
  code: SafeFailureCode;
};

async function handleStorageFailure(
  dependencies: ProcessSbomIngestionDependencies,
  input: Omit<ProcessorFailureInput, 'code'> & { failure: ClassifiedStorageFailure },
): Promise<ProcessSbomIngestionOutcome> {
  return finalizeByCode(dependencies, {
    payload: input.payload,
    jobId: input.jobId,
    sbomId: input.sbomId,
    ingestionVersion: input.ingestionVersion,
    parserVersion: input.parserVersion,
    code: mapStorageFailureToSafeCode(input.failure.category),
  });
}

async function finalizeByCode(
  dependencies: ProcessSbomIngestionDependencies,
  input: ProcessorFailureInput,
): Promise<ProcessSbomIngestionOutcome> {
  const outcome = classifySafeFailure(input.code).outcome;
  if (outcome === 'retryable_infrastructure') {
    return releaseForRetry(dependencies, input);
  }
  return finalizeTerminal(dependencies, input);
}

async function releaseForRetry(
  dependencies: ProcessSbomIngestionDependencies,
  input: ProcessorFailureInput,
): Promise<ProcessSbomIngestionOutcome> {
  const classification = classifySafeFailure(input.code);
  const now = dependencies.clock.now();
  await dependencies.processorWork.runInTransaction(async (repos) => {
    await repos.ingestions.applyTransition(
      input.payload.organizationId,
      input.payload.aggregateId,
      input.ingestionVersion,
      { type: 'release_for_retry', failureCode: input.code },
    );
    await repos.backgroundJobs.markRetry({
      organizationId: input.payload.organizationId,
      jobId: input.jobId,
      failureCategory: classification.category,
      failureCode: input.code,
      availableAt: now,
    });
  });
  return { kind: 'retry', code: input.code };
}

async function finalizeTerminal(
  dependencies: ProcessSbomIngestionDependencies,
  input: ProcessorFailureInput,
): Promise<ProcessSbomIngestionOutcome> {
  const classification = classifySafeFailure(input.code);
  const commandType =
    classification.outcome === 'rejected'
      ? 'reject'
      : classification.outcome === 'quarantined'
        ? 'quarantine'
        : 'fail';
  const kind =
    commandType === 'reject'
      ? 'rejected'
      : commandType === 'quarantine'
        ? 'quarantined'
        : 'failed';
  const now = dependencies.clock.now();
  const auditInput = {
    organizationId: input.payload.organizationId,
    sbomId: input.sbomId,
    ingestionId: input.payload.aggregateId,
    correlationId: input.payload.outboxEventId,
    parserVersion: input.parserVersion,
    occurredAt: now,
    failureCode: input.code,
  };
  const audit =
    kind === 'rejected'
      ? sbomIngestionRejectedAudit(auditInput)
      : kind === 'quarantined'
        ? sbomIngestionQuarantinedAudit(auditInput)
        : sbomIngestionFailedAudit(auditInput);

  await dependencies.processorWork.runInTransaction(async (repos) => {
    await repos.ingestions.applyTransition(
      input.payload.organizationId,
      input.payload.aggregateId,
      input.ingestionVersion,
      { type: commandType, completedAt: now, failureCode: input.code },
    );
    await repos.auditEvents.append(audit);
    await repos.backgroundJobs.markTerminalFailure({
      organizationId: input.payload.organizationId,
      jobId: input.jobId,
      workerIdentifier: dependencies.options.workerIdentifier,
      failureCategory: classification.category,
      failureCode: input.code,
      completedAt: now,
    });
  });
  return { kind, code: input.code };
}

async function alignTerminalJob(
  dependencies: ProcessSbomIngestionDependencies,
  input: {
    organizationId: string;
    jobId: string;
    workerIdentifier: string;
    code: SafeFailureCode;
  },
): Promise<ProcessSbomIngestionOutcome> {
  const classification = classifySafeFailure(input.code);
  const now = dependencies.clock.now();
  await dependencies.jobs.markTerminalFailure({
    organizationId: input.organizationId,
    jobId: input.jobId,
    workerIdentifier: input.workerIdentifier,
    failureCategory: classification.category,
    failureCode: input.code,
    completedAt: now,
  });
  const kind =
    classification.outcome === 'rejected'
      ? 'rejected'
      : classification.outcome === 'quarantined'
        ? 'quarantined'
        : 'failed';
  return { kind, code: input.code };
}

function asSafeCode(value: string | null): SafeFailureCode {
  if (value !== null && isSafeFailureCode(value)) {
    return value;
  }
  return 'processing_failed';
}
