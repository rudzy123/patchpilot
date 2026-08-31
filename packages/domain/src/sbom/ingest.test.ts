import { createHash, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { JSON_SCHEMA_VERSION_V1 } from '../json-documents.js';
import type { AppendAuditEventInput } from '../ports.js';
import { err, ok } from '../result.js';
import type {
  AuditEventRecord,
  BackgroundJobRecord,
  SbomIngestionRecord,
  SbomRecord,
} from '../records.js';
import { applySession8IngestionTransition, type Session8IngestionSnapshot } from './transitions.js';
import { buildFinalSbomObjectKey } from './object-keys.js';
import {
  createProcessSbomIngestionUseCase,
  type ProcessSbomIngestionDependencies,
} from './ingest.js';
import { parseSbomIngestJobPayload } from './ingest-job.js';
import type {
  BackgroundJobExecutionPort,
  ClassifiedStorageFailure,
  ComponentGraphPersistencePort,
  GetObjectResult,
  SbomDocumentParserPort,
  SbomIngestionPersistencePort,
  SbomMetadataPersistencePort,
  SbomObjectStoragePort,
} from './ports.js';
import type { NormalizedComponentGraph } from './graph.js';
import type { SbomParserLimits } from './types.js';
import { SBOM_INGEST_JOB_TYPE, SBOM_INGESTION_REQUESTED_EVENT_TYPE } from './constants.js';

const NOW = new Date('2026-08-31T16:00:00.000Z');
const ORG_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const ORG_B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const ASSET_A = '11111111-1111-4111-8111-111111111111';
const SBOM_A = '22222222-2222-4222-8222-222222222222';
const INGESTION_A = '33333333-3333-4333-8333-333333333333';
const OUTBOX_A = '44444444-4444-4444-8444-444444444444';
const JOB_A = '55555555-5555-4555-8555-555555555555';
const WORKER = 'worker-1';
const BODY = new TextEncoder().encode('{"bomFormat":"CycloneDX","specVersion":"1.6"}');
const SHA = createHash('sha256').update(BODY).digest('hex');
const OBJECT_KEY = buildFinalSbomObjectKey({
  organizationId: ORG_A,
  assetId: ASSET_A,
  sha256: SHA,
});
const PARSER_VERSION = '0.1.0';
const NORMALIZATION_VERSION = '1';
const LIMITS: SbomParserLimits = {
  maxBytes: 1024,
  jsonMaxDepth: 8,
  jsonMaxNodes: 1000,
  jsonMaxStringBytes: 1024,
  maxComponents: 10,
  maxDependencyEdges: 10,
  maxBomRefBytes: 64,
  maxPurlBytes: 64,
  maxComponentNameChars: 64,
  maxVersionChars: 32,
  maxMetadataTools: 4,
  maxExternalRefsPerComponent: 4,
  maxPropertiesPerComponent: 4,
};

const EMPTY_GRAPH: NormalizedComponentGraph = {
  specificationVersion: '1.6',
  graphCompleteness: 'empty',
  components: [],
  edges: [],
  warnings: [],
  componentCount: 0,
  dependencyEdgeCount: 0,
  warningCount: 0,
  capturedAt: null,
  parserVersion: PARSER_VERSION,
  normalizationVersion: NORMALIZATION_VERSION,
};

function payload(overrides: Record<string, unknown> = {}) {
  return {
    organizationId: ORG_A,
    outboxEventId: OUTBOX_A,
    aggregateType: 'sbom_ingestion',
    aggregateId: INGESTION_A,
    eventType: SBOM_INGESTION_REQUESTED_EVENT_TYPE,
    dedupeKey: `${ORG_A}:sbom.ingest:${SBOM_A}:${PARSER_VERSION}`,
    ...overrides,
  };
}

describe('process SBOM ingestion use case', () => {
  it('skips an invalid payload without claiming a job', async () => {
    const harness = createHarness();
    const result = await harness.execute({ extra: true, ...payload() });
    expect(result).toEqual({ kind: 'skipped' });
    expect(harness.claimCalls).toBe(0);
    expect(harness.storage.getCalls).toBe(0);
  });

  it('retries when the background job is missing without marking retry', async () => {
    const harness = createHarness({ job: undefined });
    const result = await harness.execute(payload());
    expect(result).toEqual({ kind: 'retry', code: 'queue_unavailable' });
    expect(harness.retryCalls).toBe(0);
  });

  it('retries competing claims and does not read storage', async () => {
    const harness = createHarness({ claimConflict: true });
    const result = await harness.execute(payload());
    expect(result).toEqual({ kind: 'retry', code: 'queue_unavailable' });
    expect(harness.storage.getCalls).toBe(0);
    expect(harness.retryCalls).toBe(0);
  });

  it('does not treat a payload organization as authorization', async () => {
    const harness = createHarness({
      job: jobRecord({ organizationId: ORG_B }),
    });
    const result = await harness.execute(payload({ organizationId: ORG_A }));
    expect(result).toEqual({ kind: 'retry', code: 'queue_unavailable' });
    expect(harness.storage.getCalls).toBe(0);
  });

  it('gets the stored object key, not a payload-supplied key', async () => {
    const harness = createHarness();
    const result = await harness.execute(
      payload({ objectKey: 'org/attacker/assets/x/sboms/sha256/' + 'b'.repeat(64) }),
    );
    expect(result).toEqual({ kind: 'skipped' });
    const accepted = parseSbomIngestJobPayload(payload());
    expect(accepted.ok).toBe(true);
    const okResult = await harness.execute(payload());
    expect(okResult).toEqual({ kind: 'completed' });
    expect(harness.storage.keys).toEqual([OBJECT_KEY]);
  });

  it('rejects a stored object key whose tenant scope disagrees with the SBOM row', async () => {
    const mismatchedKey = buildFinalSbomObjectKey({
      organizationId: ORG_B,
      assetId: ASSET_A,
      sha256: SHA,
    });
    const harness = createHarness({ objectKey: mismatchedKey });
    const result = await harness.execute(payload());
    expect(result).toEqual({ kind: 'failed', code: 'processing_failed' });
    expect(harness.storage.getCalls).toBe(0);
    expect(harness.ingestion?.state).toBe('failed');
  });

  it('quarantines a hash mismatch after GET', async () => {
    const harness = createHarness({
      body: new TextEncoder().encode('{"tampered":true}'),
    });
    const result = await harness.execute(payload());
    expect(result).toEqual({ kind: 'quarantined', code: 'hash_mismatch' });
    expect(harness.ingestion?.state).toBe('quarantined');
    expect(harness.job?.status).toBe('failed');
    expect(harness.audits.map((row) => row.action)).toEqual(['sbom.ingestion.quarantined']);
  });

  it('rejects parser validation failures and quarantines parser timeouts', async () => {
    const rejected = createHarness({
      parser: async () => ({ ok: false, code: 'schema_invalid' }),
    });
    expect(await rejected.execute(payload())).toEqual({
      kind: 'rejected',
      code: 'schema_invalid',
    });
    expect(rejected.ingestion?.state).toBe('rejected');

    const timedOut = createHarness({
      parser: async () => ({ ok: false, code: 'parser_timeout' }),
    });
    expect(await timedOut.execute(payload())).toEqual({
      kind: 'quarantined',
      code: 'parser_timeout',
    });
    expect(timedOut.ingestion?.state).toBe('quarantined');
  });

  it('persists the graph outside storage I/O and is a no-op on completed replay', async () => {
    const harness = createHarness();
    const first = await harness.execute(payload());
    expect(first).toEqual({ kind: 'completed' });
    expect(harness.operations).toEqual([
      'jobs.findByOutboxEventId',
      'jobs.claimExecution',
      'ingestions.findById',
      'ingestions.applyTransition:start_processing',
      'sbomMetadata.findByAssetAndId',
      'storage.getObject',
      'parser.parse',
      'graph.persistOnceForIngestion',
    ]);
    expect(harness.storageCallsDuringPersist).toBe(0);
    expect(harness.persistInput?.ownedJob?.jobId).toBe(JOB_A);
    expect(harness.job?.status).toBe('succeeded');

    harness.storage.getCalls = 0;
    const replay = await harness.execute(payload());
    expect(replay).toEqual({ kind: 'already_complete' });
    expect(harness.storage.getCalls).toBe(0);
  });

  it('marks a completed ingestion succeeded without re-reading storage', async () => {
    const harness = createHarness({ ingestionState: 'completed' });
    const result = await harness.execute(payload());
    expect(result).toEqual({ kind: 'already_complete' });
    expect(harness.storage.getCalls).toBe(0);
    expect(harness.job?.status).toBe('succeeded');
  });

  it('releases a claimed job for retry on storage timeout', async () => {
    const harness = createHarness({
      storageFailure: { category: 'timeout' },
    });
    const result = await harness.execute(payload());
    expect(result).toEqual({ kind: 'retry', code: 'storage_timeout' });
    expect(harness.retryCalls).toBe(1);
    expect(harness.ingestion?.state).toBe('queued');
    expect(harness.job?.status).toBe('queued');
  });

  it('keeps Redis, BullMQ, and process.env out of the use case', () => {
    const source = readFileSync(join(dirname(fileURLToPath(import.meta.url)), 'ingest.ts'), 'utf8');
    expect(source).not.toMatch(/bullmq|ioredis|Prisma|process\.env|worker_threads|@aws-sdk/);
  });
});

function jobRecord(overrides: Partial<BackgroundJobRecord> = {}): BackgroundJobRecord {
  return {
    id: JOB_A,
    organizationId: ORG_A,
    outboxEventId: OUTBOX_A,
    jobType: SBOM_INGEST_JOB_TYPE,
    status: 'queued',
    attempt: 0,
    startedAt: null,
    leaseExpiresAt: null,
    completedAt: null,
    failureCategory: null,
    failureCode: null,
    workerIdentifier: null,
    createdAt: NOW,
    ...overrides,
  };
}

function sbomRecord(objectKey: string = OBJECT_KEY): SbomRecord {
  return {
    id: SBOM_A,
    organizationId: ORG_A,
    assetId: ASSET_A,
    objectKey,
    sha256: SHA,
    byteLength: BODY.byteLength,
    declaredContentType: 'application/json',
    specificationType: 'cyclonedx',
    specificationVersion: null,
    source: 'upload',
    originalFilename: null,
    uploadedByMembershipId: null,
    capturedAt: null,
    receivedAt: NOW,
    parserVersionLastSucceeded: null,
    createdAt: NOW,
  };
}

function ingestionRecord(state: SbomIngestionRecord['state'] = 'accepted'): SbomIngestionRecord {
  return {
    id: INGESTION_A,
    organizationId: ORG_A,
    sbomId: SBOM_A,
    assetId: ASSET_A,
    state,
    stage: state === 'processing' || state === 'completed' ? 'validate' : null,
    attemptNumber: 0,
    parserVersion: PARSER_VERSION,
    normalizationVersion: NORMALIZATION_VERSION,
    idempotencyKey: null,
    startedAt: state === 'accepted' || state === 'queued' ? null : NOW,
    completedAt: state === 'completed' ? NOW : null,
    graphCompleteness: state === 'completed' ? 'empty' : null,
    componentCount: state === 'completed' ? 0 : null,
    dependencyEdgeCount: state === 'completed' ? 0 : null,
    warningCount: state === 'completed' ? 0 : null,
    failureCategory: null,
    failureCode: null,
    quarantineReason: null,
    leaseExpiresAt: null,
    version: 1,
    createdAt: NOW,
    updatedAt: NOW,
  };
}

function snapshotOf(record: SbomIngestionRecord): Session8IngestionSnapshot {
  return {
    state: record.state,
    stage: record.stage,
    startedAt: record.startedAt,
    completedAt: record.completedAt,
    graphCompleteness: record.graphCompleteness,
    componentCount: record.componentCount,
    dependencyEdgeCount: record.dependencyEdgeCount,
    warningCount: record.warningCount,
    failureCategory: record.failureCategory,
    failureCode: record.failureCode,
  };
}

function applySnapshot(record: SbomIngestionRecord, snapshot: Session8IngestionSnapshot): void {
  record.state = snapshot.state;
  record.stage = snapshot.stage;
  record.startedAt = snapshot.startedAt;
  record.completedAt = snapshot.completedAt;
  record.graphCompleteness = snapshot.graphCompleteness;
  record.componentCount = snapshot.componentCount;
  record.dependencyEdgeCount = snapshot.dependencyEdgeCount;
  record.warningCount = snapshot.warningCount;
  record.failureCategory = snapshot.failureCategory;
  record.failureCode = snapshot.failureCode;
  record.version += 1;
  record.updatedAt = NOW;
}

function streamOf(bytes: Uint8Array): GetObjectResult {
  return {
    body: (async function* () {
      yield bytes;
    })(),
    completion: Promise.resolve({
      observedByteLength: bytes.byteLength,
      sha256: createHash('sha256').update(bytes).digest('hex'),
    }),
    cancel: async () => undefined,
  };
}

function createHarness(
  options: {
    job?: BackgroundJobRecord | undefined;
    claimConflict?: boolean;
    ingestionState?: SbomIngestionRecord['state'];
    objectKey?: string;
    body?: Uint8Array;
    storageFailure?: ClassifiedStorageFailure;
    parser?: SbomDocumentParserPort['parse'];
  } = {},
) {
  const operations: string[] = [];
  const keys: string[] = [];
  const audits: AppendAuditEventInput[] = [];
  let storageCallsDuringPersist = 0;
  let retryCalls = 0;
  let claimCalls = 0;
  let persistInput:
    Parameters<ComponentGraphPersistencePort['persistOnceForIngestion']>[0] | undefined;
  const job =
    options.job === undefined && 'job' in options ? undefined : (options.job ?? jobRecord());
  const ingestion = ingestionRecord(options.ingestionState ?? 'accepted');
  const sbom = sbomRecord(options.objectKey);
  const body = options.body ?? BODY;
  const storage: SbomObjectStoragePort & { getCalls: number; keys: string[] } = {
    getCalls: 0,
    keys,
    verifyBucketAvailability: async () =>
      ok({ bucketPrivate: true, publicAccessDisabled: true, signedUrlsDisabled: true }),
    initializeDevelopmentBucket: async () => ok(undefined),
    putTemporaryObject: async () => err({ category: 'internal' }),
    promoteTemporaryObject: async () => err({ category: 'internal' }),
    headFinalObject: async () => err({ category: 'internal' }),
    deleteTemporaryObject: async () => err({ category: 'internal' }),
    async getObject(input) {
      this.getCalls += 1;
      keys.push(input.finalObjectKey);
      operations.push('storage.getObject');
      if (options.storageFailure !== undefined) {
        return err(options.storageFailure);
      }
      return ok(streamOf(body));
    },
  };

  const jobs: BackgroundJobExecutionPort = {
    async enqueueQueued() {
      throw new Error('enqueueQueued is not used by the processor');
    },
    async findByOutboxEventId(input) {
      operations.push('jobs.findByOutboxEventId');
      if (job === undefined || job.outboxEventId !== input.outboxEventId) {
        return undefined;
      }
      if (job.organizationId !== input.organizationId) {
        return undefined;
      }
      return job;
    },
    async claimExecution() {
      claimCalls += 1;
      operations.push('jobs.claimExecution');
      if (job === undefined || options.claimConflict === true) {
        return err({ code: 'conflict', message: 'Background job was not claimed.' });
      }
      job.status = 'running';
      job.workerIdentifier = WORKER;
      job.leaseExpiresAt = new Date(NOW.getTime() + 60_000);
      job.startedAt = NOW;
      job.attempt += 1;
      return ok({
        jobId: job.id,
        workerIdentifier: WORKER,
        leaseExpiresAt: job.leaseExpiresAt,
        attempt: job.attempt,
      });
    },
    async renewLease() {
      return err({ code: 'conflict', message: 'unused' });
    },
    async markRetry(input) {
      retryCalls += 1;
      operations.push('jobs.markRetry');
      if (job === undefined || job.id !== input.jobId) {
        return err({ code: 'not_found', message: 'Background job was not found.' });
      }
      job.status = 'queued';
      job.workerIdentifier = null;
      job.leaseExpiresAt = null;
      job.failureCategory = input.failureCategory;
      job.failureCode = input.failureCode;
      return ok({
        id: job.id,
        organizationId: job.organizationId,
        jobType: job.jobType,
        status: 'queued',
        attempt: job.attempt,
      });
    },
    async markSucceeded(input) {
      operations.push('jobs.markSucceeded');
      if (job === undefined) {
        return err({ code: 'not_found', message: 'Background job was not found.' });
      }
      job.status = 'succeeded';
      job.completedAt = input.completedAt;
      job.leaseExpiresAt = null;
      job.failureCategory = null;
      job.failureCode = null;
      return ok(job);
    },
    async markTerminalFailure(input) {
      operations.push('jobs.markTerminalFailure');
      if (job === undefined) {
        return err({ code: 'not_found', message: 'Background job was not found.' });
      }
      job.status = 'failed';
      job.completedAt = input.completedAt;
      job.leaseExpiresAt = null;
      job.failureCategory = input.failureCategory;
      job.failureCode = input.failureCode;
      return ok(job);
    },
    async findIdempotentTerminal() {
      return undefined;
    },
  };

  const ingestions: SbomIngestionPersistencePort = {
    async createAccepted() {
      return err({ code: 'internal', message: 'unused' });
    },
    async findById(organizationId, ingestionId) {
      operations.push('ingestions.findById');
      if (ingestion.organizationId !== organizationId || ingestion.id !== ingestionId) {
        return undefined;
      }
      return ingestion;
    },
    async findByAssetAndId() {
      return undefined;
    },
    async findCurrentForSbom() {
      return undefined;
    },
    async applyTransition(organizationId, ingestionId, expectedVersion, command) {
      operations.push(`ingestions.applyTransition:${command.type}`);
      if (
        ingestion.organizationId !== organizationId ||
        ingestion.id !== ingestionId ||
        ingestion.version !== expectedVersion
      ) {
        return err({ code: 'conflict', message: 'version mismatch' });
      }
      const next = applySession8IngestionTransition(snapshotOf(ingestion), command);
      if (!next.ok) {
        return next;
      }
      applySnapshot(ingestion, next.value);
      return ok({ record: ingestion, snapshot: next.value });
    },
  };

  const sbomMetadata: SbomMetadataPersistencePort = {
    async insert() {
      throw new Error('unused');
    },
    async findById() {
      return undefined;
    },
    async findByAssetAndId(organizationId, assetId, sbomId) {
      operations.push('sbomMetadata.findByAssetAndId');
      if (
        sbom.organizationId !== organizationId ||
        sbom.assetId !== assetId ||
        sbom.id !== sbomId
      ) {
        return undefined;
      }
      return sbom;
    },
    async findByAssetAndHash() {
      return undefined;
    },
    async listForAsset() {
      return { items: [], nextCursor: undefined };
    },
    async recordSuccessfulParser() {
      return err({ code: 'internal', message: 'unused' });
    },
  };

  const parser: SbomDocumentParserPort = {
    parse: async (input) => {
      operations.push('parser.parse');
      if (options.parser !== undefined) {
        return options.parser(input);
      }
      return { ok: true, graph: EMPTY_GRAPH };
    },
  };

  const graph: ComponentGraphPersistencePort = {
    async persistOnceForIngestion(input) {
      const getsBeforePersist = storage.getCalls;
      operations.push('graph.persistOnceForIngestion');
      persistInput = input;
      storageCallsDuringPersist = storage.getCalls - getsBeforePersist;
      if (ingestion.state === 'completed') {
        return ok(undefined);
      }
      const completed = applySession8IngestionTransition(snapshotOf(ingestion), {
        type: 'complete',
        completedAt: NOW,
        graphCompleteness: input.graph.graphCompleteness,
        componentCount: input.graph.componentCount,
        dependencyEdgeCount: input.graph.dependencyEdgeCount,
        warningCount: input.graph.warningCount,
      });
      if (!completed.ok) {
        return completed;
      }
      applySnapshot(ingestion, completed.value);
      if (input.ownedJob !== undefined && job !== undefined) {
        job.status = 'succeeded';
        job.completedAt = input.ownedJob.completedAt;
        job.leaseExpiresAt = null;
      }
      return ok(undefined);
    },
    async listOccurrencesForIngestion() {
      return { items: [], nextCursor: undefined };
    },
    async listEdgesForIngestion() {
      return { items: [], nextCursor: undefined };
    },
  };

  const dependencies: ProcessSbomIngestionDependencies = {
    clock: { now: () => NOW },
    jobs,
    ingestions,
    sbomMetadata,
    storage,
    parser,
    graph,
    processorWork: {
      async runInTransaction(work) {
        return work({
          ingestions,
          backgroundJobs: jobs,
          auditEvents: {
            async append(event: AppendAuditEventInput): Promise<AuditEventRecord> {
              audits.push(event);
              return {
                id: randomUUID(),
                actorType: event.actorType,
                actorUserId: event.actorUserId ?? null,
                organizationId: event.organizationId ?? null,
                actorMembershipId: event.actorMembershipId ?? null,
                action: event.action,
                subjectType: event.subjectType,
                subjectId: event.subjectId,
                occurredAt: event.occurredAt ?? NOW,
                correlationId: event.correlationId,
                requestId: event.requestId ?? null,
                sourceIp: event.sourceIp ?? null,
                userAgent: event.userAgent ?? null,
                payload: event.payload,
                schemaVersion: event.schemaVersion ?? JSON_SCHEMA_VERSION_V1,
                retentionCategory: event.retentionCategory ?? 'security',
              };
            },
            async findById() {
              return undefined;
            },
            async listForOrganization() {
              return { items: [], nextCursor: undefined };
            },
          },
        });
      },
    },
    options: {
      workerIdentifier: WORKER,
      processingLeaseMs: 60_000,
      parserLimits: LIMITS,
    },
  };

  return {
    operations,
    audits,
    storage,
    get keys() {
      return keys;
    },
    get claimCalls() {
      return claimCalls;
    },
    get retryCalls() {
      return retryCalls;
    },
    get storageCallsDuringPersist() {
      return storageCallsDuringPersist;
    },
    get persistInput() {
      return persistInput;
    },
    get job() {
      return job;
    },
    get ingestion() {
      return ingestion;
    },
    execute(raw: unknown) {
      return createProcessSbomIngestionUseCase(dependencies).execute(raw);
    },
  };
}
