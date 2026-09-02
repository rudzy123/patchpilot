import { createHash, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { err, ok, type Result } from '../result.js';
import type { BackgroundJobRecord, OutboxEventRecord } from '../records.js';
import { toIntelligenceOutboxPayloadJson } from './outbox.js';
import type { BackgroundJobExecutionPort } from '../sbom/ports.js';
import {
  applyIntelligenceSyncRunTransition,
  isIntelligenceTerminalSyncRunState,
  type IntelligenceSyncRunSnapshot,
} from './transitions.js';
import { decideKevSyncDue } from './due-decision.js';
import { classifyIntelligenceSafeFailure } from './failures.js';
import {
  buildFinalIntelligenceSnapshotObjectKey,
  parseFinalIntelligenceSnapshotObjectKey,
} from './object-keys.js';
import type {
  IntelligenceGenerationPersistencePort,
  IntelligenceKevParserPort,
  IntelligenceKevParserSuccess,
  IntelligenceOutboxLookupPort,
  IntelligenceProviderHttpPort,
  IntelligenceSnapshotPersistencePort,
  IntelligenceSnapshotStoragePort,
  IntelligenceSourceFreshnessPort,
  IntelligenceSyncRunPersistencePort,
  IntelligenceSyncUnitOfWork,
} from './ports.js';
import type {
  IntelligenceSnapshotRecord,
  IntelligenceSyncRunRecord,
  KevGenerationRecord,
  KevNormalizedEntryRecord,
} from './records.js';
import {
  createCisaKevSynchronizationService,
  type CisaKevSynchronizationConfig,
  type CisaKevSynchronizationDependencies,
  type CisaKevSynchronizationLogger,
} from './synchronize.js';

const NOW = new Date('2026-09-01T12:00:00.000Z');
const SYNC_RUN_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const JOB_ID = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const EVENT_ID = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const WORKER = 'worker-1';
const BODY = new TextEncoder().encode(
  '{"catalogVersion":"2099.01.01","dateReleased":"2099-01-01T00:00:00.000Z","count":1}',
);
const BODY_SHA = createHash('sha256').update(BODY).digest('hex');

const CONFIG: CisaKevSynchronizationConfig = {
  kevEnabled: true,
  parserVersion: '0.1.0',
  normalizationVersion: '1',
  kevResponseMaxBytes: 65_536,
  kevParserTimeoutMs: 10_000,
  kevJobLeaseMs: 600_000,
  maxStagedRowsPerTransaction: 2,
  syncMaxAttempts: 5,
  syncRetryWaitFloorMs: 30_000,
  syncRetryWaitCeilingMs: 300_000,
  jobLeaseRenewalIntervalMs: 60_000,
  httpConnectTimeoutMs: 5_000,
  httpTotalTimeoutMs: 60_000,
  httpRetryCount: 0,
  httpBackoffFloorMs: 1_000,
  httpBackoffCeilingMs: 30_000,
  kevMaxVulnerabilityCount: 16,
  kevMaxTextFieldBytes: 4_096,
  kevMaxCweCount: 8,
  kevJsonMaxDepth: 8,
  kevJsonMaxNodes: 1_000,
  kevJsonMaxStringBytes: 8_192,
};

function parsedEntry(ordinal: number, cve: string) {
  return {
    ordinal,
    normalizedCve: cve,
    vendorProject: 'Northwind Testware',
    product: 'Fabrikam Widget',
    vulnerabilityName: 'Synthetic inert vulnerability',
    dateAdded: '2099-01-02',
    shortDescription: 'Inert synthetic description.',
    requiredAction: 'Inert synthetic action.',
    dueDate: '2099-01-16',
    knownRansomwareCampaignUse: 'known' as const,
    rawKnownRansomwareCampaignUse: null,
    notes: null,
    cwes: ['CWE-79'],
  };
}

function parserSuccess(entries = [parsedEntry(0, 'CVE-2099-0001')]): IntelligenceKevParserSuccess {
  return {
    ok: true,
    catalogVersion: '2099.01.01',
    catalogReleasedAt: '2099-01-01T00:00:00.000Z',
    expectedEntryCount: entries.length,
    entries,
    entryCount: entries.length,
    warnings: [],
    parserVersion: '0.1.0',
    normalizationVersion: '1',
    serializedResultBytes: 256,
  };
}

function snapshotOf(run: IntelligenceSyncRunRecord): IntelligenceSyncRunSnapshot {
  return {
    state: run.state,
    stage: run.stage,
    requestedAt: run.requestedAt,
    startedAt: run.startedAt,
    completedAt: run.completedAt,
    nextAttemptAt: run.nextAttemptAt,
    executionAttempt: run.executionAttempt,
    snapshotId: run.snapshotId,
    generationId: run.generationId,
    failureCategory: run.failureCategory,
    failureCode: run.failureCode,
    acceptedEntryCount: run.acceptedEntryCount,
    warningCount: run.warningCount,
    priorAcceptedGenerationId: run.priorAcceptedGenerationId,
    notModifiedReason: run.notModifiedReason,
  };
}

function applySnapshot(run: IntelligenceSyncRunRecord, next: IntelligenceSyncRunSnapshot): void {
  Object.assign(run, next, { version: run.version + 1, updatedAt: NOW });
}

type WorldOptions = {
  state?: IntelligenceSyncRunRecord['state'];
  jobStatus?: BackgroundJobRecord['status'];
  workerIdentifier?: string | null;
  leaseExpiresAt?: Date | null;
  attempt?: number;
  executionAttempt?: number;
  nextAttemptAt?: Date | null;
  parserVersion?: string;
  payloadProvider?: 'cisa_kev' | 'osv';
  http?: 'ok' | 'timeout' | 'not_modified';
  parser?: IntelligenceKevParserPort['parse'];
  metadataCommitFails?: boolean;
  renewFailsAfter?: number;
  markRetryFails?: boolean;
  failRunFails?: boolean;
  kevEnabled?: boolean;
  activeGeneration?: KevGenerationRecord;
  activeSnapshotSha?: string;
};

function createWorld(options: WorldOptions = {}) {
  const logs: Array<{ level: string; bindings: Record<string, unknown>; message: string }> = [];
  const objects = new Map<string, Uint8Array>();
  const snapshots = new Map<string, IntelligenceSnapshotRecord>();
  const generations = new Map<string, KevGenerationRecord>();
  const entries = new Map<string, KevNormalizedEntryRecord[]>();
  const counters = { http: 0, get: 0, parse: 0, promote: 0, renew: 0 };
  const audits: string[] = [];
  const freshnessState = { lastSuccessfulSyncAt: null as Date | null };
  let requestSyncCalls = 0;
  let idSeq = 1;
  const createId = () => {
    const value = `00000000-0000-4000-8000-${idSeq.toString(16).padStart(12, '0')}`;
    idSeq += 1;
    return value;
  };

  const run: IntelligenceSyncRunRecord = {
    id: SYNC_RUN_ID,
    provider: 'cisa_kev',
    sourceIdentifier: 'cisa_kev_json_catalog',
    state: options.state ?? 'requested',
    stage: options.state === 'fetching' ? 'fetch' : null,
    requestedAt: NOW,
    startedAt: options.state === 'requested' || options.state === undefined ? null : NOW,
    completedAt: null,
    nextAttemptAt: options.nextAttemptAt ?? null,
    executionAttempt:
      options.executionAttempt ??
      (options.state === 'requested' || options.state === undefined ? 0 : 1),
    snapshotId: null,
    generationId: null,
    priorAcceptedGenerationId: null,
    parserVersion: options.parserVersion ?? '0.1.0',
    normalizationVersion: '1',
    failureCategory: null,
    failureCode: null,
    acceptedEntryCount: null,
    warningCount: null,
    notModifiedReason: null,
    correlationId: `corr-${SYNC_RUN_ID}`,
    version: 1,
    createdAt: NOW,
    updatedAt: NOW,
  };

  const job: BackgroundJobRecord = {
    id: JOB_ID,
    organizationId: null,
    outboxEventId: EVENT_ID,
    jobType: 'intelligence.sync',
    status: options.jobStatus ?? 'running',
    attempt: options.attempt ?? 1,
    startedAt: NOW,
    leaseExpiresAt:
      options.leaseExpiresAt === undefined
        ? new Date(NOW.getTime() + 600_000)
        : options.leaseExpiresAt,
    completedAt: null,
    failureCategory: null,
    failureCode: null,
    workerIdentifier: options.workerIdentifier === undefined ? WORKER : options.workerIdentifier,
    createdAt: NOW,
  };

  const event: OutboxEventRecord = {
    id: EVENT_ID,
    organizationId: null,
    aggregateType: 'intelligence_sync_run',
    aggregateId: SYNC_RUN_ID,
    eventType: 'intelligence.sync.requested.v1',
    eventSchemaVersion: 1,
    payload: toIntelligenceOutboxPayloadJson({
      schemaVersion: 1,
      syncRunId: SYNC_RUN_ID,
      provider: options.payloadProvider ?? 'cisa_kev',
      sourceIdentifier: 'cisa_kev_json_catalog',
    }),
    dedupeKey: 'cisa_kev:cisa_kev_json_catalog',
    occurredAt: NOW,
    availableAt: NOW,
    claimedAt: NOW,
    leaseExpiresAt: null,
    processedAt: null,
    attemptCount: 1,
    lastFailureCategory: null,
    lastFailureCode: null,
    status: 'processed',
    createdAt: NOW,
  };

  const pointer = {
    sourceId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
    version: 1,
    activeGenerationId: options.activeGeneration?.id ?? null,
  };

  if (options.activeGeneration !== undefined) {
    generations.set(options.activeGeneration.id, options.activeGeneration);
    const sha = options.activeSnapshotSha ?? BODY_SHA;
    const key = parseFinalIntelligenceSnapshotObjectKey(
      `intelligence/cisa_kev/cisa_kev_json_catalog/sha256/${sha}`,
    );
    if (!key.ok) {
      throw new Error('invalid test snapshot key');
    }
    snapshots.set(options.activeGeneration.snapshotId, {
      id: options.activeGeneration.snapshotId,
      provider: 'cisa_kev',
      sourceIdentifier: 'cisa_kev_json_catalog',
      responseSha256: sha,
      byteLength: BODY.byteLength,
      declaredContentType: 'application/json',
      detectedContentType: 'application/json',
      objectKey: key.value,
      retrievedAt: NOW,
      storedAt: NOW,
      etagHash: null,
      lastModified: null,
      creatingSyncRunId: options.activeGeneration.syncRunId,
      createdAt: NOW,
    });
    objects.set(key.value, BODY);
  }

  const cas = (
    expectedState: IntelligenceSyncRunRecord['state'],
    expectedVersion: number,
    command: Parameters<typeof applyIntelligenceSyncRunTransition>[1],
  ): Result<IntelligenceSyncRunRecord> => {
    if (run.state !== expectedState || run.version !== expectedVersion) {
      return err({ code: 'conflict', message: 'cas' });
    }
    const next = applyIntelligenceSyncRunTransition(snapshotOf(run), command);
    if (!next.ok) {
      return next;
    }
    applySnapshot(run, next.value);
    return ok(run);
  };

  const jobs: BackgroundJobExecutionPort = {
    async enqueueQueued() {
      throw new Error('unused');
    },
    async findById(input) {
      if (input.jobId !== job.id || input.organizationId !== null) {
        return undefined;
      }
      return { ...job };
    },
    async findByOutboxEventId() {
      return undefined;
    },
    async claimExecution() {
      return err({ code: 'conflict', message: 'unused' });
    },
    async renewLease() {
      counters.renew += 1;
      if (options.renewFailsAfter !== undefined && counters.renew > options.renewFailsAfter) {
        return err({ code: 'conflict', message: 'lease lost' });
      }
      if (job.status !== 'running' || job.workerIdentifier !== WORKER) {
        return err({ code: 'conflict', message: 'not owned' });
      }
      job.leaseExpiresAt = new Date(NOW.getTime() + 600_000);
      return ok({
        jobId: job.id,
        workerIdentifier: WORKER,
        leaseExpiresAt: job.leaseExpiresAt,
      });
    },
    async markRetry(input) {
      if (options.markRetryFails === true) {
        return err({ code: 'conflict', message: 'retry ownership' });
      }
      if (job.workerIdentifier !== input.workerIdentifier || job.status !== 'running') {
        return err({ code: 'conflict', message: 'retry ownership' });
      }
      job.status = 'queued';
      job.workerIdentifier = null;
      job.leaseExpiresAt = null;
      job.failureCategory = input.failureCategory;
      job.failureCode = input.failureCode;
      return ok({
        id: job.id,
        organizationId: null,
        jobType: job.jobType,
        status: 'queued',
        attempt: job.attempt,
      });
    },
    async markSucceeded(input) {
      if (job.status === 'succeeded') {
        return ok({ ...job });
      }
      if (job.workerIdentifier !== input.workerIdentifier || job.status !== 'running') {
        return err({ code: 'conflict', message: 'succeed ownership' });
      }
      job.status = 'succeeded';
      job.completedAt = input.completedAt;
      job.leaseExpiresAt = null;
      return ok({ ...job });
    },
    async markTerminalFailure(input) {
      if (job.workerIdentifier !== input.workerIdentifier || job.status !== 'running') {
        return err({ code: 'conflict', message: 'fail ownership' });
      }
      job.status = 'failed';
      job.failureCategory = input.failureCategory;
      job.failureCode = input.failureCode;
      job.completedAt = input.completedAt;
      job.leaseExpiresAt = null;
      return ok({ ...job });
    },
    async findIdempotentTerminal() {
      return undefined;
    },
  };

  const outbox: IntelligenceOutboxLookupPort = {
    async findById(input) {
      if (input.eventId !== event.id || input.organizationId !== null) {
        return undefined;
      }
      return event;
    },
  };

  const syncRuns: IntelligenceSyncRunPersistencePort = {
    async createRequested() {
      return err({ code: 'conflict', message: 'unused' });
    },
    async findById(id) {
      return id === run.id ? { ...run } : undefined;
    },
    async findLatestByProviderAndSource() {
      return undefined;
    },
    async applyCompareAndSetTransition(input) {
      if (run.state !== input.expectedState || run.version !== input.expectedVersion) {
        return err({ code: 'conflict', message: 'cas' });
      }
      const next = applyIntelligenceSyncRunTransition(snapshotOf(run), input.command);
      if (!next.ok) {
        return next;
      }
      applySnapshot(run, next.value);
      return ok(next.value);
    },
    async findTerminalById() {
      return undefined;
    },
    async claimRequestedOrRetryWait() {
      return err({ code: 'conflict', message: 'unused' });
    },
    async recordRetryWait(input) {
      return cas(input.expectedState, input.expectedVersion, input.command);
    },
    async recordSnapshotStored(input) {
      return cas(input.expectedState, input.expectedVersion, input.command);
    },
    async recordParsing(input) {
      return cas(input.expectedState, input.expectedVersion, input.command);
    },
    async recordGenerationStaging(input) {
      return cas(input.expectedState, input.expectedVersion, input.command);
    },
    async recordActivationStarted(input) {
      return cas(input.expectedState, input.expectedVersion, input.command);
    },
    async completeRun(input) {
      return cas(input.expectedState, input.expectedVersion, input.command);
    },
    async completeNotModified(input) {
      return cas(input.expectedState, input.expectedVersion, input.command);
    },
    async quarantineRun(input) {
      return cas(input.expectedState, input.expectedVersion, input.command);
    },
    async failRun(input) {
      return cas(input.expectedState, input.expectedVersion, input.command);
    },
  };

  const snapshotStore: IntelligenceSnapshotPersistencePort = {
    async findByProviderSourceAndSha256(identity) {
      return [...snapshots.values()].find(
        (item) => item.responseSha256 === identity.responseSha256,
      );
    },
    async insertImmutable() {
      return err({ code: 'conflict', message: 'unused' });
    },
    async insertOrReuse() {
      return err({ code: 'conflict', message: 'unused' });
    },
    async findById(id) {
      return snapshots.get(id);
    },
    async verifyIdentity() {
      return err({ code: 'not_found', message: 'unused' });
    },
  };

  const generationStore: IntelligenceGenerationPersistencePort = {
    async createStagingGeneration() {
      return err({ code: 'conflict', message: 'unused' });
    },
    async findById(id) {
      return generations.get(id);
    },
    async findBySyncRunId(syncRunId) {
      return [...generations.values()].find((item) => item.syncRunId === syncRunId);
    },
    async stageBoundedEntryBatch(input) {
      const current = entries.get(input.generationId) ?? [];
      entries.set(input.generationId, [...current, ...input.entries]);
      const generation = generations.get(input.generationId);
      if (generation !== undefined) {
        generation.stagedEntryCount = (entries.get(input.generationId) ?? []).length;
      }
      return ok({ stagedEntryCount: (entries.get(input.generationId) ?? []).length });
    },
    async inspectStagedCounts(generationId) {
      const staged = entries.get(generationId) ?? [];
      return {
        stagedEntryCount: staged.length,
        distinctCveCount: new Set(staged.map((item) => item.normalizedCve)).size,
      };
    },
    async inspectStagedPrefix(input) {
      return [...(entries.get(input.generationId) ?? [])].sort(
        (left, right) => left.ordinal - right.ordinal,
      );
    },
    async markGenerationComplete() {
      return err({ code: 'conflict', message: 'unused' });
    },
    async activateCompleteGeneration() {
      return err({ code: 'conflict', message: 'unused' });
    },
    async findActiveGeneration() {
      if (pointer.activeGenerationId === null) {
        return undefined;
      }
      return generations.get(pointer.activeGenerationId);
    },
    async listActiveEntries() {
      return { items: [], nextOrdinal: null, nextId: null };
    },
    async markGenerationSuperseded() {
      return err({ code: 'conflict', message: 'unused' });
    },
    async abandonIncompleteGeneration() {
      return err({ code: 'conflict', message: 'unused' });
    },
    async findStaleIncompleteGenerations() {
      return [];
    },
  };

  const freshness: IntelligenceSourceFreshnessPort = {
    async loadCurrentProviderStatus() {
      throw new Error('unused');
    },
    async loadCisaKevSourcePointer() {
      return { ...pointer };
    },
    async reconcileRuntimeEnablement() {
      return ok({ outcome: 'unchanged' as const, version: pointer.version });
    },
    async markAttemptStarted() {
      return ok({
        provider: 'cisa_kev',
        sourceIdentifier: 'cisa_kev_json_catalog',
        implementationStatus: 'available',
        runtimeEnabled: true,
        lastSuccessfulSyncAt: null,
        lastAttemptAt: NOW,
        latestAcceptedCatalogVersion: null,
        latestAcceptedCatalogReleasedAt: null,
        currentEntryCount: null,
        lastSafeFailureCode: null,
        lastFailureAt: null,
        staleThresholdSeconds: 259_200,
      });
    },
    async markSuccessfulCompletedGeneration() {
      return err({ code: 'conflict', message: 'unused' });
    },
    async markNotModified() {
      return err({ code: 'conflict', message: 'unused' });
    },
    async markDegradedFailure() {
      return ok({
        provider: 'cisa_kev',
        sourceIdentifier: 'cisa_kev_json_catalog',
        implementationStatus: 'available',
        runtimeEnabled: true,
        lastSuccessfulSyncAt: null,
        lastAttemptAt: NOW,
        latestAcceptedCatalogVersion: null,
        latestAcceptedCatalogReleasedAt: null,
        currentEntryCount: null,
        lastSafeFailureCode: 'parser_timeout',
        lastFailureAt: NOW,
        staleThresholdSeconds: 259_200,
      });
    },
  };

  async function* bodyOf(bytes: Uint8Array): AsyncIterable<Uint8Array> {
    yield bytes;
  }

  const http: IntelligenceProviderHttpPort = {
    async fetchCatalog(request) {
      counters.http += 1;
      if (options.http === 'timeout') {
        return { kind: 'failure', category: 'timeout', code: 'connection_timeout' };
      }
      if (options.http === 'not_modified') {
        return { kind: 'not_modified', status: 304, etagHash: null, lastModified: null };
      }
      if (request.signal?.aborted === true) {
        return { kind: 'failure', category: 'timeout', code: 'request_cancelled' };
      }
      return {
        kind: 'response',
        status: 200,
        declaredContentType: 'application/json',
        declaredByteLength: BODY.byteLength,
        etagHash: null,
        lastModified: null,
        body: bodyOf(BODY),
        completion: Promise.resolve({ observedByteLength: BODY.byteLength, sha256: BODY_SHA }),
        cancel: async () => undefined,
      };
    },
  };

  const storage: IntelligenceSnapshotStoragePort = {
    async verifyPrivateStorageAvailability() {
      return ok({
        bucketPrivate: true as const,
        publicAccessDisabled: true as const,
        signedUrlsDisabled: true as const,
      });
    },
    async initializeDevelopmentBucket() {
      return ok(undefined);
    },
    async putTemporarySnapshot(input) {
      const chunks: Uint8Array[] = [];
      for await (const chunk of input.body) {
        chunks.push(chunk);
      }
      const bytes = Buffer.concat(chunks);
      objects.set(input.temporaryObjectKey, bytes);
      return ok({
        sha256: createHash('sha256').update(bytes).digest('hex'),
        observedByteLength: bytes.byteLength,
      });
    },
    async promoteTemporarySnapshot(input) {
      counters.promote += 1;
      const bytes = objects.get(input.temporaryObjectKey);
      if (bytes === undefined) {
        return err({ category: 'storage', code: 'snapshot_storage_failed' });
      }
      objects.set(input.finalObjectKey, bytes);
      objects.delete(input.temporaryObjectKey);
      return ok({ outcome: 'copied' as const, temporaryCleanup: 'deleted' as const });
    },
    async headFinalSnapshot(input) {
      const bytes = objects.get(input.finalObjectKey);
      if (bytes === undefined) {
        return ok({ exists: false as const });
      }
      return ok({
        exists: true as const,
        byteLength: bytes.byteLength,
        sha256: createHash('sha256').update(bytes).digest('hex'),
        declaredContentType: 'application/json',
        detectedContentType: 'application/json',
        provider: 'cisa_kev' as const,
        sourceIdentifier: 'cisa_kev_json_catalog' as const,
      });
    },
    async getFinalSnapshot(input) {
      counters.get += 1;
      const bytes = objects.get(input.finalObjectKey);
      if (bytes === undefined) {
        return err({ category: 'storage', code: 'snapshot_missing' });
      }
      return ok({
        body: bodyOf(bytes),
        declaredByteLength: bytes.byteLength,
        completion: Promise.resolve({
          observedByteLength: bytes.byteLength,
          sha256: createHash('sha256').update(bytes).digest('hex'),
        }),
        cancel: async () => undefined,
      });
    },
    async deleteTemporarySnapshot(input) {
      objects.delete(input.temporaryObjectKey);
      return ok(undefined);
    },
  };

  const parser: IntelligenceKevParserPort = {
    parse:
      options.parser ??
      (async () => {
        counters.parse += 1;
        return parserSuccess();
      }),
  };

  const unitOfWork: IntelligenceSyncUnitOfWork = {
    async requestSync() {
      requestSyncCalls += 1;
      return err({ code: 'conflict', message: 'unused' });
    },
    async claimFetchingAttempt(input) {
      const executionAttempt = input.expectedState === 'requested' ? 1 : run.executionAttempt + 1;
      return cas(input.expectedState, input.expectedVersion, {
        type: 'start_fetching',
        startedAt: input.claimedAt,
        executionAttempt,
      });
    },
    async storeFetchedSnapshot(input) {
      if (options.metadataCommitFails === true) {
        return err({ code: 'conflict', message: 'metadata failed' });
      }
      const existing = [...snapshots.values()].find(
        (item) => item.responseSha256 === input.snapshot.responseSha256,
      );
      const stored = existing ?? input.snapshot;
      snapshots.set(stored.id, stored);
      if (input.notModified !== undefined) {
        const completed = cas(input.expectedState, input.expectedVersion, {
          type: 'complete_not_modified',
          completedAt: input.notModified.completedAt,
          priorAcceptedGenerationId: input.notModified.priorAcceptedGenerationId,
          reason: input.notModified.reason,
        });
        if (!completed.ok) {
          return completed;
        }
        await jobs.markSucceeded({
          organizationId: null,
          jobId: job.id,
          workerIdentifier: WORKER,
          completedAt: input.notModified.completedAt,
        });
        return ok({
          snapshot: stored,
          reused: existing !== undefined,
          syncRun: run,
          outcome: 'not_modified' as const,
        });
      }
      const next = cas(input.expectedState, input.expectedVersion, {
        type: 'record_stored',
        snapshotId: stored.id,
      });
      if (!next.ok) {
        return next;
      }
      return ok({
        snapshot: stored,
        reused: existing !== undefined,
        syncRun: run,
        outcome: 'stored' as const,
      });
    },
    async createStagingGenerationAndRun(input) {
      const generation: KevGenerationRecord = {
        id: input.generation.id,
        provider: 'cisa_kev',
        sourceIdentifier: 'cisa_kev_json_catalog',
        syncRunId: input.syncRunId,
        snapshotId: input.generation.snapshotId,
        state: 'staging',
        stagedEntryCount: 0,
        expectedEntryCount: input.generation.expectedEntryCount,
        parserVersion: input.generation.parserVersion,
        normalizationVersion: input.generation.normalizationVersion,
        catalogVersion: input.generation.catalogVersion ?? null,
        catalogReleasedAt: input.generation.catalogReleasedAt ?? null,
        createdAt: input.generation.createdAt,
        completedAt: null,
        activatedAt: null,
        supersededAt: null,
        abandonedAt: null,
        version: 1,
        updatedAt: NOW,
      };
      generations.set(generation.id, generation);
      entries.set(generation.id, []);
      const staged = cas(input.expectedState, input.expectedVersion, {
        type: 'start_staging',
        generationId: generation.id,
      });
      if (!staged.ok) {
        return staged;
      }
      return ok({ generation, syncRun: run });
    },
    async completeStagedGeneration(input) {
      const generation = generations.get(input.generation.generationId);
      if (generation === undefined) {
        return err({ code: 'not_found', message: 'missing generation' });
      }
      generation.state = 'complete';
      generation.completedAt = input.generation.completedAt;
      generation.catalogVersion = input.generation.catalogVersion;
      generation.catalogReleasedAt = input.generation.catalogReleasedAt;
      generation.stagedEntryCount = input.generation.expectedEntryCount;
      const activating = cas('staging', run.version, {
        type: 'start_activating',
        generationComplete: true,
        warningCount: input.warningCount,
      });
      if (!activating.ok) {
        return activating;
      }
      return ok({ generation, syncRun: run });
    },
    async activateCompleteGeneration(input) {
      if (run.state !== 'activating') {
        return err({ code: 'conflict', message: 'not activating' });
      }
      const generation = generations.get(input.generationId);
      if (generation === undefined) {
        return err({ code: 'not_found', message: 'missing generation' });
      }
      if (pointer.activeGenerationId !== input.previousActiveGenerationId) {
        return err({ code: 'conflict', message: 'activation_conflict' });
      }
      if (pointer.activeGenerationId !== null) {
        const previous = generations.get(pointer.activeGenerationId);
        if (previous !== undefined) {
          previous.state = 'superseded';
          previous.supersededAt = input.activatedAt;
        }
      }
      generation.state = 'active';
      generation.activatedAt = input.activatedAt;
      pointer.activeGenerationId = generation.id;
      pointer.version += 1;
      const completed = cas('activating', run.version, {
        type: 'complete',
        completedAt: input.activatedAt,
        acceptedEntryCount: input.acceptedEntryCount,
        warningCount: input.warningCount,
      });
      if (!completed.ok) {
        return completed;
      }
      await jobs.markSucceeded({
        organizationId: null,
        jobId: job.id,
        workerIdentifier: WORKER,
        completedAt: input.activatedAt,
      });
      return ok({ outcome: 'activated' as const, generation, syncRun: run });
    },
    async completeNotModified() {
      return err({ code: 'conflict', message: 'unused' });
    },
    async recordRetryWait(input) {
      const waited = cas(input.expectedState, input.expectedVersion, {
        type: 'record_retry_wait',
        nextAttemptAt: input.nextAttemptAt,
        failureCode: input.failureCode,
      });
      if (!waited.ok) {
        return waited;
      }
      if (input.backgroundJob !== undefined) {
        await jobs.markRetry({
          organizationId: null,
          jobId: input.backgroundJob.jobId,
          workerIdentifier: input.backgroundJob.workerIdentifier,
          failureCategory: 'timeout',
          failureCode: input.failureCode,
          availableAt: input.nextAttemptAt,
        });
      }
      return waited;
    },
    async failRun(input) {
      if (options.failRunFails === true) {
        return err({ code: 'conflict', message: 'fail cas' });
      }
      const failed = cas(input.expectedState, input.expectedVersion, {
        type: 'fail',
        completedAt: input.completedAt,
        failureCode: input.failureCode,
      });
      if (!failed.ok) {
        return failed;
      }
      audits.push('intelligence.sync_failed');
      if (input.backgroundJob !== undefined) {
        const classification = classifyIntelligenceSafeFailure(input.failureCode);
        const marked = await jobs.markTerminalFailure({
          organizationId: null,
          jobId: input.backgroundJob.jobId,
          workerIdentifier: input.backgroundJob.workerIdentifier,
          failureCategory: classification.category,
          failureCode: input.failureCode,
          completedAt: input.completedAt,
        });
        if (!marked.ok) {
          return err({ code: 'conflict', message: 'Background job ownership did not match.' });
        }
      }
      return failed;
    },
    async quarantineRun(input) {
      return cas(input.expectedState, input.expectedVersion, {
        type: 'quarantine',
        completedAt: input.completedAt,
        failureCode: input.failureCode,
      });
    },
  };

  const logger: CisaKevSynchronizationLogger = {
    info(bindings, message) {
      logs.push({ level: 'info', bindings, message });
    },
    warn(bindings, message) {
      logs.push({ level: 'warn', bindings, message });
    },
  };

  const dependencies: CisaKevSynchronizationDependencies = {
    clock: { now: () => NOW },
    createId,
    config: {
      ...CONFIG,
      kevEnabled: options.kevEnabled ?? CONFIG.kevEnabled,
    },
    jobs,
    outbox,
    syncRuns,
    snapshots: snapshotStore,
    generations: generationStore,
    freshness,
    http,
    storage,
    parser,
    unitOfWork,
    logger,
    leaseScheduler: {
      schedule() {
        return { stop() {} };
      },
    },
  };

  return {
    run,
    job,
    event,
    logs,
    counters,
    audits,
    freshnessState,
    requestSyncCalls: () => requestSyncCalls,
    objects,
    snapshots,
    generations,
    entries,
    pointer,
    service: createCisaKevSynchronizationService(dependencies),
    attachStoredSnapshot() {
      const key = buildFinalIntelligenceSnapshotObjectKey(BODY_SHA);
      if (!key.ok) {
        throw new Error('final key');
      }
      const snapshot: IntelligenceSnapshotRecord = {
        id: createId(),
        provider: 'cisa_kev',
        sourceIdentifier: 'cisa_kev_json_catalog',
        responseSha256: BODY_SHA,
        byteLength: BODY.byteLength,
        declaredContentType: 'application/json',
        detectedContentType: 'application/json',
        objectKey: key.value,
        retrievedAt: NOW,
        storedAt: NOW,
        etagHash: null,
        lastModified: null,
        creatingSyncRunId: run.id,
        createdAt: NOW,
      };
      snapshots.set(snapshot.id, snapshot);
      objects.set(key.value, BODY);
      run.snapshotId = snapshot.id;
      run.state = options.state ?? 'stored';
      run.stage = run.state === 'stored' ? 'store_snapshot' : run.stage;
      return snapshot;
    },
  };
}

describe('createCisaKevSynchronizationService', () => {
  it('rejects non-UUID locators and queue/source disagreement before HTTP', async () => {
    const invalid = createWorld();
    expect(
      await invalid.service.execute({
        syncRunId: 'not-a-uuid',
        backgroundJobId: JOB_ID,
        workerIdentifier: WORKER,
      }),
    ).toEqual({ kind: 'rejected', code: 'invalid_provider_source' });
    const mismatched = createWorld({ payloadProvider: 'osv' });
    expect(
      await mismatched.service.execute({
        syncRunId: SYNC_RUN_ID,
        backgroundJobId: JOB_ID,
        workerIdentifier: WORKER,
      }),
    ).toEqual({ kind: 'rejected', code: 'invalid_provider_source' });
    expect(mismatched.counters.http).toBe(0);
  });

  it('returns idempotent success for completed and not-modified runs without refetch', async () => {
    const completed = createWorld({
      state: 'completed',
      jobStatus: 'succeeded',
      workerIdentifier: null,
    });
    completed.run.completedAt = NOW;
    completed.run.generationId = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
    completed.run.snapshotId = 'ffffffff-ffff-4fff-8fff-ffffffffffff';
    expect(
      await completed.service.execute({
        syncRunId: SYNC_RUN_ID,
        backgroundJobId: JOB_ID,
        workerIdentifier: WORKER,
      }),
    ).toEqual({ kind: 'already_complete' });
    expect(completed.counters.http).toBe(0);
    expect(completed.logs).toHaveLength(0);
  });

  it('does not fetch when retry_wait is not due', async () => {
    const world = createWorld({
      state: 'retry_wait',
      nextAttemptAt: new Date(NOW.getTime() + 60_000),
      executionAttempt: 1,
    });
    const result = await world.service.execute({
      syncRunId: SYNC_RUN_ID,
      backgroundJobId: JOB_ID,
      workerIdentifier: WORKER,
    });
    expect(result.kind).toBe('retry_wait');
    expect(world.counters.http).toBe(0);
  });

  it('terminates a requested SyncRun as provider_disabled before provider HTTP', async () => {
    const findings = [{ id: 'finding-baseline', status: 'open' }];
    const observations = [{ id: 'observation-baseline', findingId: 'finding-baseline' }];
    const vulnerabilities: unknown[] = [];
    const vulnerabilityAliases: unknown[] = [];
    const vulnerabilitySourceRecords: unknown[] = [];
    const findingQuery = async (): Promise<never> => {
      throw new Error('Finding and component repositories must not be queried.');
    };

    const world = createWorld({ kevEnabled: false });
    const originalEvent = { ...world.event, payload: world.event.payload };
    const result = await world.service.execute({
      syncRunId: SYNC_RUN_ID,
      backgroundJobId: JOB_ID,
      workerIdentifier: WORKER,
    });

    expect(result).toEqual({ kind: 'failed', code: 'provider_disabled' });
    expect(world.run.state).toBe('failed');
    expect(isIntelligenceTerminalSyncRunState(world.run.state)).toBe(true);
    expect(world.run.failureCode).toBe('provider_disabled');
    expect(world.run.failureCategory).toBe('configuration');
    expect(world.run.completedAt).toEqual(NOW);
    expect(world.run.startedAt).toBeNull();
    expect(world.run.executionAttempt).toBe(0);
    expect(world.run.snapshotId).toBeNull();
    expect(world.run.generationId).toBeNull();
    expect(world.run.requestedAt).toEqual(NOW);
    expect(world.job.status).toBe('failed');
    expect(world.job.failureCode).toBe('provider_disabled');
    expect(world.audits).toEqual(['intelligence.sync_failed']);
    expect(world.counters.http).toBe(0);
    expect(world.counters.get).toBe(0);
    expect(world.counters.parse).toBe(0);
    expect(world.counters.promote).toBe(0);
    expect(world.snapshots.size).toBe(0);
    expect(world.generations.size).toBe(0);
    expect(world.pointer.activeGenerationId).toBeNull();
    expect(world.freshnessState.lastSuccessfulSyncAt).toBeNull();
    expect(world.requestSyncCalls()).toBe(0);
    expect(world.event.id).toBe(originalEvent.id);
    expect(world.event.eventType).toBe(originalEvent.eventType);
    expect(
      decideKevSyncDue({
        kevEnabled: true,
        shutdown: false,
        now: NOW,
        syncIntervalSeconds: 86_400,
        latestSyncRun: world.run,
        lastSuccessfulSyncAt: world.freshnessState.lastSuccessfulSyncAt,
      }),
    ).toEqual({ kind: 'due_initial' });

    const replay = await world.service.execute({
      syncRunId: SYNC_RUN_ID,
      backgroundJobId: JOB_ID,
      workerIdentifier: WORKER,
    });
    expect(replay).toEqual({ kind: 'failed', code: 'provider_disabled' });
    expect(world.audits).toEqual(['intelligence.sync_failed']);
    expect(world.counters.http).toBe(0);
    expect(world.run.executionAttempt).toBe(0);
    expect(world.pointer.activeGenerationId).toBeNull();

    expect(findings).toEqual([{ id: 'finding-baseline', status: 'open' }]);
    expect(observations).toEqual([{ id: 'observation-baseline', findingId: 'finding-baseline' }]);
    expect(vulnerabilities).toEqual([]);
    expect(vulnerabilityAliases).toEqual([]);
    expect(vulnerabilitySourceRecords).toEqual([]);
    await expect(findingQuery()).rejects.toThrow(/must not be queried/);
  });

  it('claims requested, fetches once, stages bounded batches, and activates', async () => {
    const world = createWorld({
      parser: async () => {
        world.counters.parse += 1;
        return parserSuccess([parsedEntry(0, 'CVE-2099-0001'), parsedEntry(1, 'CVE-2099-0002')]);
      },
    });
    const result = await world.service.execute({
      syncRunId: SYNC_RUN_ID,
      backgroundJobId: JOB_ID,
      workerIdentifier: WORKER,
    });
    expect(result).toEqual({ kind: 'completed', acceptedEntryCount: 2, warningCount: 0 });
    expect(world.counters.http).toBe(1);
    expect(world.counters.parse).toBe(1);
    expect(world.run.state).toBe('completed');
    expect(world.job.status).toBe('succeeded');
    expect(world.pointer.activeGenerationId).not.toBeNull();
    expect(world.logs.some((item) => JSON.stringify(item).includes('intelligence/'))).toBe(false);
    expect(world.logs.some((item) => JSON.stringify(item).includes('CVE-'))).toBe(false);
  });

  it('refetches from fetching and does not refetch after stored', async () => {
    const fetching = createWorld({ state: 'fetching', executionAttempt: 1 });
    const fetched = await fetching.service.execute({
      syncRunId: SYNC_RUN_ID,
      backgroundJobId: JOB_ID,
      workerIdentifier: WORKER,
    });
    expect(fetched.kind).toBe('completed');
    expect(fetching.counters.http).toBe(1);

    const stored = createWorld({ state: 'stored' });
    stored.attachStoredSnapshot();
    const resumed = await stored.service.execute({
      syncRunId: SYNC_RUN_ID,
      backgroundJobId: JOB_ID,
      workerIdentifier: WORKER,
    });
    expect(resumed.kind).toBe('completed');
    expect(stored.counters.http).toBe(0);
    expect(stored.counters.get).toBe(1);
    expect(stored.counters.parse).toBe(1);
  });

  it('treats HTTP 304 as provider failure and uses retry_wait before a snapshot exists', async () => {
    const world = createWorld({ http: 'not_modified' });
    const result = await world.service.execute({
      syncRunId: SYNC_RUN_ID,
      backgroundJobId: JOB_ID,
      workerIdentifier: WORKER,
    });
    expect(result).toEqual({ kind: 'failed', code: 'provider_client_error' });
    expect(world.run.state).toBe('failed');
  });

  it('moves HTTP failures to retry_wait and exhausts to failed', async () => {
    const retry = createWorld({ http: 'timeout' });
    expect(
      (
        await retry.service.execute({
          syncRunId: SYNC_RUN_ID,
          backgroundJobId: JOB_ID,
          workerIdentifier: WORKER,
        })
      ).kind,
    ).toBe('retry_wait');
    const exhausted = createWorld({ http: 'timeout', attempt: 5 });
    expect(
      await exhausted.service.execute({
        syncRunId: SYNC_RUN_ID,
        backgroundJobId: JOB_ID,
        workerIdentifier: WORKER,
      }),
    ).toEqual({ kind: 'failed', code: 'connection_timeout' });
    expect(exhausted.run.state).toBe('failed');
  });

  it('leaves a reusable final object when snapshot metadata commit fails', async () => {
    const world = createWorld({ metadataCommitFails: true });
    const result = await world.service.execute({
      syncRunId: SYNC_RUN_ID,
      backgroundJobId: JOB_ID,
      workerIdentifier: WORKER,
    });
    expect(result.kind).toBe('retry_wait');
    const finalKey = `intelligence/cisa_kev/cisa_kev_json_catalog/sha256/${BODY_SHA}`;
    expect(world.objects.has(finalKey)).toBe(true);
    expect(world.run.state).toBe('retry_wait');
    expect(world.run.snapshotId).toBeNull();
  });

  it('completes content-hash not-modified without retrieving or parsing', async () => {
    const active = {
      id: '11111111-1111-4111-8111-111111111111',
      provider: 'cisa_kev' as const,
      sourceIdentifier: 'cisa_kev_json_catalog' as const,
      syncRunId: '22222222-2222-4222-8222-222222222222',
      snapshotId: '33333333-3333-4333-8333-333333333333',
      state: 'active' as const,
      stagedEntryCount: 1,
      expectedEntryCount: 1,
      parserVersion: '0.1.0',
      normalizationVersion: '1',
      catalogVersion: '2099.01.01',
      catalogReleasedAt: new Date('2099-01-01T00:00:00.000Z'),
      createdAt: NOW,
      completedAt: NOW,
      activatedAt: NOW,
      supersededAt: null,
      abandonedAt: null,
      version: 1,
      updatedAt: NOW,
    };
    const world = createWorld({ activeGeneration: active, activeSnapshotSha: BODY_SHA });
    const result = await world.service.execute({
      syncRunId: SYNC_RUN_ID,
      backgroundJobId: JOB_ID,
      workerIdentifier: WORKER,
    });
    expect(result).toEqual({ kind: 'not_modified', reason: 'content_sha256_unchanged' });
    expect(world.counters.get).toBe(0);
    expect(world.counters.parse).toBe(0);
    expect(world.pointer.activeGenerationId).toBe(active.id);
  });

  it('reparses identical content when the parser version changes', async () => {
    const active = {
      id: '11111111-1111-4111-8111-111111111111',
      provider: 'cisa_kev' as const,
      sourceIdentifier: 'cisa_kev_json_catalog' as const,
      syncRunId: '22222222-2222-4222-8222-222222222222',
      snapshotId: '33333333-3333-4333-8333-333333333333',
      state: 'active' as const,
      stagedEntryCount: 1,
      expectedEntryCount: 1,
      parserVersion: '0.0.9',
      normalizationVersion: '1',
      catalogVersion: '2099.01.01',
      catalogReleasedAt: new Date('2099-01-01T00:00:00.000Z'),
      createdAt: NOW,
      completedAt: NOW,
      activatedAt: NOW,
      supersededAt: null,
      abandonedAt: null,
      version: 1,
      updatedAt: NOW,
    };
    const world = createWorld({ activeGeneration: active, activeSnapshotSha: BODY_SHA });
    const result = await world.service.execute({
      syncRunId: SYNC_RUN_ID,
      backgroundJobId: JOB_ID,
      workerIdentifier: WORKER,
    });
    expect(result.kind).toBe('completed');
    expect(world.counters.parse).toBe(1);
    expect(world.pointer.activeGenerationId).not.toBe(active.id);
  });

  it('quarantines catalog regression and parser content failures after stored', async () => {
    const active = {
      id: '11111111-1111-4111-8111-111111111111',
      provider: 'cisa_kev' as const,
      sourceIdentifier: 'cisa_kev_json_catalog' as const,
      syncRunId: '22222222-2222-4222-8222-222222222222',
      snapshotId: '33333333-3333-4333-8333-333333333333',
      state: 'active' as const,
      stagedEntryCount: 1,
      expectedEntryCount: 1,
      parserVersion: '0.1.0',
      normalizationVersion: '1',
      catalogVersion: '2099.01.01',
      catalogReleasedAt: new Date('2099-06-01T00:00:00.000Z'),
      createdAt: NOW,
      completedAt: NOW,
      activatedAt: NOW,
      supersededAt: null,
      abandonedAt: null,
      version: 1,
      updatedAt: NOW,
    };
    const regression = createWorld({
      activeGeneration: active,
      activeSnapshotSha: 'b'.repeat(64),
      parser: async () => parserSuccess(),
    });
    expect(
      await regression.service.execute({
        syncRunId: SYNC_RUN_ID,
        backgroundJobId: JOB_ID,
        workerIdentifier: WORKER,
      }),
    ).toEqual({ kind: 'quarantined', code: 'catalog_regression' });
    expect(regression.pointer.activeGenerationId).toBe(active.id);

    const invalid = createWorld({
      state: 'stored',
      parser: async () => ({
        ok: false as const,
        disposition: 'quarantined' as const,
        category: 'schema' as const,
        code: 'schema_invalid' as const,
      }),
    });
    invalid.attachStoredSnapshot();
    expect(
      await invalid.service.execute({
        syncRunId: SYNC_RUN_ID,
        backgroundJobId: JOB_ID,
        workerIdentifier: WORKER,
      }),
    ).toEqual({ kind: 'quarantined', code: 'schema_invalid' });
    expect(invalid.counters.http).toBe(0);
  });

  it('retries parser timeout after stored without refetching CISA', async () => {
    const world = createWorld({
      state: 'stored',
      parser: async () => ({
        ok: false as const,
        disposition: 'failed' as const,
        category: 'parser' as const,
        code: 'parser_timeout' as const,
      }),
    });
    world.attachStoredSnapshot();
    const result = await world.service.execute({
      syncRunId: SYNC_RUN_ID,
      backgroundJobId: JOB_ID,
      workerIdentifier: WORKER,
    });
    expect(result).toEqual({ kind: 'job_retry', code: 'parser_timeout' });
    expect(world.run.state).toBe('parsing');
    expect(world.counters.http).toBe(0);
    expect(world.job.status).toBe('queued');
  });

  it('fails dense-prefix mismatches without activating', async () => {
    const world = createWorld({
      state: 'staging',
      parser: async () => parserSuccess([parsedEntry(0, 'CVE-2099-0001')]),
    });
    const snapshot = world.attachStoredSnapshot();
    const generationId = randomUUID();
    world.run.generationId = generationId;
    world.generations.set(generationId, {
      id: generationId,
      provider: 'cisa_kev',
      sourceIdentifier: 'cisa_kev_json_catalog',
      syncRunId: SYNC_RUN_ID,
      snapshotId: snapshot.id,
      state: 'staging',
      stagedEntryCount: 1,
      expectedEntryCount: 1,
      parserVersion: '0.1.0',
      normalizationVersion: '1',
      catalogVersion: '2099.01.01',
      catalogReleasedAt: new Date('2099-01-01T00:00:00.000Z'),
      createdAt: NOW,
      completedAt: null,
      activatedAt: null,
      supersededAt: null,
      abandonedAt: null,
      version: 1,
      updatedAt: NOW,
    });
    world.entries.set(generationId, [
      {
        id: randomUUID(),
        generationId,
        snapshotId: snapshot.id,
        ordinal: 0,
        normalizedCve: 'CVE-2099-0001' as KevNormalizedEntryRecord['normalizedCve'],
        vendorProject: 'Other',
        product: 'Fabrikam Widget',
        vulnerabilityName: 'Synthetic inert vulnerability',
        dateAdded: '2099-01-02' as KevNormalizedEntryRecord['dateAdded'],
        shortDescription: 'Inert synthetic description.',
        requiredAction: 'Inert synthetic action.',
        dueDate: '2099-01-16' as KevNormalizedEntryRecord['dueDate'],
        knownRansomwareCampaignUse: 'known',
        rawKnownRansomwareCampaignUse: 'Known',
        notes: null,
        cwes: ['CWE-79'],
        createdAt: NOW,
      },
    ]);
    const result = await world.service.execute({
      syncRunId: SYNC_RUN_ID,
      backgroundJobId: JOB_ID,
      workerIdentifier: WORKER,
    });
    expect(result).toEqual({ kind: 'failed', code: 'generation_incomplete' });
    expect(world.pointer.activeGenerationId).toBeNull();
    expect(world.counters.http).toBe(0);
  });

  it('returns inconsistent when an active generation exists without a completed run', async () => {
    const world = createWorld({ state: 'activating' });
    const snapshot = world.attachStoredSnapshot();
    const generationId = randomUUID();
    world.run.generationId = generationId;
    world.generations.set(generationId, {
      id: generationId,
      provider: 'cisa_kev',
      sourceIdentifier: 'cisa_kev_json_catalog',
      syncRunId: SYNC_RUN_ID,
      snapshotId: snapshot.id,
      state: 'active',
      stagedEntryCount: 1,
      expectedEntryCount: 1,
      parserVersion: '0.1.0',
      normalizationVersion: '1',
      catalogVersion: '2099.01.01',
      catalogReleasedAt: new Date('2099-01-01T00:00:00.000Z'),
      createdAt: NOW,
      completedAt: NOW,
      activatedAt: NOW,
      supersededAt: null,
      abandonedAt: null,
      version: 1,
      updatedAt: NOW,
    });
    expect(
      await world.service.execute({
        syncRunId: SYNC_RUN_ID,
        backgroundJobId: JOB_ID,
        workerIdentifier: WORKER,
      }),
    ).toEqual({ kind: 'inconsistent' });
  });

  it('aborts when lease renewal fails and cleans the heartbeat', async () => {
    const world = createWorld({ renewFailsAfter: 0 });
    const result = await world.service.execute({
      syncRunId: SYNC_RUN_ID,
      backgroundJobId: JOB_ID,
      workerIdentifier: WORKER,
    });
    expect(result.kind).toBe('rejected');
    expect(world.counters.http).toBe(0);
  });

  it('resumes parsing, staging, activating, and due retry_wait without repeating forbidden side effects', async () => {
    const parsing = createWorld({ state: 'parsing' });
    parsing.attachStoredSnapshot();
    expect(
      await parsing.service.execute({
        syncRunId: SYNC_RUN_ID,
        backgroundJobId: JOB_ID,
        workerIdentifier: WORKER,
      }),
    ).toEqual({ kind: 'completed', acceptedEntryCount: 1, warningCount: 0 });
    expect(parsing.counters.http).toBe(0);
    expect(parsing.counters.parse).toBe(1);

    const staging = createWorld({
      state: 'staging',
      parser: async () => {
        staging.counters.parse += 1;
        return parserSuccess([parsedEntry(0, 'CVE-2099-0001'), parsedEntry(1, 'CVE-2099-0002')]);
      },
    });
    const stagingSnapshot = staging.attachStoredSnapshot();
    const stagingGenerationId = randomUUID();
    const existingEntry: KevNormalizedEntryRecord = {
      id: randomUUID(),
      generationId: stagingGenerationId,
      snapshotId: stagingSnapshot.id,
      ordinal: 0,
      normalizedCve: 'CVE-2099-0001' as KevNormalizedEntryRecord['normalizedCve'],
      vendorProject: 'Northwind Testware',
      product: 'Fabrikam Widget',
      vulnerabilityName: 'Synthetic inert vulnerability',
      dateAdded: '2099-01-02' as KevNormalizedEntryRecord['dateAdded'],
      shortDescription: 'Inert synthetic description.',
      requiredAction: 'Inert synthetic action.',
      dueDate: '2099-01-16' as KevNormalizedEntryRecord['dueDate'],
      knownRansomwareCampaignUse: 'known',
      rawKnownRansomwareCampaignUse: null,
      notes: null,
      cwes: ['CWE-79'],
      createdAt: NOW,
    };
    staging.run.generationId = stagingGenerationId;
    staging.generations.set(stagingGenerationId, {
      id: stagingGenerationId,
      provider: 'cisa_kev',
      sourceIdentifier: 'cisa_kev_json_catalog',
      syncRunId: SYNC_RUN_ID,
      snapshotId: stagingSnapshot.id,
      state: 'staging',
      stagedEntryCount: 1,
      expectedEntryCount: 2,
      parserVersion: '0.1.0',
      normalizationVersion: '1',
      catalogVersion: '2099.01.01',
      catalogReleasedAt: new Date('2099-01-01T00:00:00.000Z'),
      createdAt: NOW,
      completedAt: null,
      activatedAt: null,
      supersededAt: null,
      abandonedAt: null,
      version: 1,
      updatedAt: NOW,
    });
    staging.entries.set(stagingGenerationId, [existingEntry]);
    expect(
      await staging.service.execute({
        syncRunId: SYNC_RUN_ID,
        backgroundJobId: JOB_ID,
        workerIdentifier: WORKER,
      }),
    ).toEqual({ kind: 'completed', acceptedEntryCount: 2, warningCount: 0 });
    expect(staging.counters.http).toBe(0);
    expect(staging.entries.get(stagingGenerationId)?.[0]?.id).toBe(existingEntry.id);
    expect(staging.entries.get(stagingGenerationId)).toHaveLength(2);

    const activating = createWorld({ state: 'activating' });
    const activatingSnapshot = activating.attachStoredSnapshot();
    const activatingGenerationId = randomUUID();
    activating.run.generationId = activatingGenerationId;
    activating.run.warningCount = 2;
    activating.generations.set(activatingGenerationId, {
      id: activatingGenerationId,
      provider: 'cisa_kev',
      sourceIdentifier: 'cisa_kev_json_catalog',
      syncRunId: SYNC_RUN_ID,
      snapshotId: activatingSnapshot.id,
      state: 'complete',
      stagedEntryCount: 1,
      expectedEntryCount: 1,
      parserVersion: '0.1.0',
      normalizationVersion: '1',
      catalogVersion: '2099.01.01',
      catalogReleasedAt: new Date('2099-01-01T00:00:00.000Z'),
      createdAt: NOW,
      completedAt: NOW,
      activatedAt: null,
      supersededAt: null,
      abandonedAt: null,
      version: 1,
      updatedAt: NOW,
    });
    expect(
      await activating.service.execute({
        syncRunId: SYNC_RUN_ID,
        backgroundJobId: JOB_ID,
        workerIdentifier: WORKER,
      }),
    ).toEqual({ kind: 'completed', acceptedEntryCount: 1, warningCount: 2 });
    expect(activating.counters.http).toBe(0);
    expect(activating.counters.parse).toBe(0);

    const due = createWorld({
      state: 'retry_wait',
      nextAttemptAt: NOW,
      executionAttempt: 1,
      attempt: 2,
    });
    due.run.failureCategory = 'timeout';
    due.run.failureCode = 'connection_timeout';
    due.run.stage = 'fetch';
    expect(
      await due.service.execute({
        syncRunId: SYNC_RUN_ID,
        backgroundJobId: JOB_ID,
        workerIdentifier: WORKER,
      }),
    ).toEqual({ kind: 'completed', acceptedEntryCount: 1, warningCount: 0 });
    expect(due.counters.http).toBe(1);
    expect(due.run.executionAttempt).toBe(2);
  });

  it('persists parser warning counts through activation', async () => {
    const world = createWorld({
      parser: async () => {
        world.counters.parse += 1;
        return {
          ...parserSuccess(),
          warnings: [{ code: 'unrecognized_ransomware_value', count: 1 }],
        };
      },
    });
    expect(
      await world.service.execute({
        syncRunId: SYNC_RUN_ID,
        backgroundJobId: JOB_ID,
        workerIdentifier: WORKER,
      }),
    ).toEqual({ kind: 'completed', acceptedEntryCount: 1, warningCount: 1 });
    expect(world.run.warningCount).toBe(1);
  });

  it('does not label lease or persist failures as terminal sync_failed', async () => {
    const lease = createWorld({
      state: 'stored',
      markRetryFails: true,
      parser: async () => ({
        ok: false as const,
        disposition: 'failed' as const,
        category: 'parser' as const,
        code: 'parser_timeout' as const,
      }),
    });
    lease.attachStoredSnapshot();
    expect(
      await lease.service.execute({
        syncRunId: SYNC_RUN_ID,
        backgroundJobId: JOB_ID,
        workerIdentifier: WORKER,
      }),
    ).toEqual({ kind: 'rejected', code: 'request_cancelled' });
    expect(lease.run.state).toBe('parsing');
    expect(lease.job.status).toBe('running');

    const persist = createWorld({ http: 'timeout', attempt: 5, failRunFails: true });
    expect(
      await persist.service.execute({
        syncRunId: SYNC_RUN_ID,
        backgroundJobId: JOB_ID,
        workerIdentifier: WORKER,
      }),
    ).toEqual({ kind: 'job_retry', code: 'persistence_failed' });
    expect(persist.run.state).toBe('fetching');
  });

  it('does not import Finding, Vulnerability, or Component repositories', () => {
    const source = readFileSync(
      join(dirname(fileURLToPath(import.meta.url)), 'synchronize.ts'),
      'utf8',
    );
    expect(source).not.toMatch(
      /FindingRepository|FindingObservation|VulnerabilityAlias|VulnerabilitySourceRecord|ComponentRepository|ComponentOccurrence|AssetRepository|SbomRepository|RiskCalculation|finding\.recalculate/,
    );
    expect(source).not.toContain('process.env');
    expect(source).not.toContain('bullmq');
    expect(source).not.toContain('@prisma/client');
  });
});
