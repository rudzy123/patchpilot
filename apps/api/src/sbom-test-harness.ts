import { createHash, randomUUID } from 'node:crypto';

import {
  createSystemClock,
  JSON_SCHEMA_VERSION_V1,
  SbomEvidenceConflictError,
  SBOM_LIST_DEFAULT_LIMIT,
  type AppendAuditEventInput,
  type AssetRecord,
  type AuditEventRecord,
  type Clock,
  type CreateOutboxEventInput,
  type IdempotencyReservationRecord,
  type OutboxEventRecord,
  type PersistSbomMetadataInput,
  type SbomIngestionRecord,
  type SbomListQuery,
  type SbomObjectStoragePort,
  type SbomRecord,
  type SbomSummaryRecord,
  type SbomUploadIdempotencyPort,
  type SbomUploadRepositories,
  type SbomUploadUnitOfWork,
} from '@patchpilot/domain';

import { createMemoryAssetInventory, type MemoryAssetInventory } from './asset-test-harness.js';
import { createSbomRuntime, type SbomRuntime } from './sbom-runtime.js';

const NOW = new Date('2026-08-31T13:00:00.000Z');

export type MemorySbomInventory = {
  assets: MemoryAssetInventory;
  runtime: SbomRuntime;
  sboms: Map<string, SbomRecord>;
  ingestions: Map<string, SbomIngestionRecord>;
  storage: SbomObjectStoragePort & { objects: Map<string, Uint8Array> };
  outbox: OutboxEventRecord[];
  audit: AuditEventRecord[];
};

export function createMemorySbomInventory(clock: Clock = createSystemClock()): MemorySbomInventory {
  const assets = createMemoryAssetInventory(clock);
  const sboms = new Map<string, SbomRecord>();
  const ingestions = new Map<string, SbomIngestionRecord>();
  const auditEvents: AuditEventRecord[] = [];
  const outboxEvents: OutboxEventRecord[] = [];
  const assetPort = {
    async findById(organizationId: string, id: string) {
      const detail = assets.assets.get(id);
      if (detail === undefined || detail.organizationId !== organizationId) {
        return undefined;
      }
      return toAssetRecord(detail);
    },
  };
  const storage = createMemoryStorage();
  const idempotency = createMemoryIdempotency();
  const sbomMetadata = createMemorySbomMetadata(sboms);
  const ingestionPort = createMemoryIngestions(ingestions);
  const audit = createMemoryAudit(auditEvents, clock);
  const outbox = createMemoryOutbox(outboxEvents, clock);
  const unitOfWork: SbomUploadUnitOfWork = {
    async runInTransaction(work) {
      const repos: SbomUploadRepositories = {
        assets: assetPort,
        sbomMetadata,
        ingestions: ingestionPort,
        uploadIdempotency: idempotency,
        auditEvents: audit,
        outboxEvents: outbox,
      };
      return work(repos);
    },
  };

  return {
    assets,
    sboms,
    ingestions,
    storage,
    outbox: outboxEvents,
    audit: auditEvents,
    runtime: createSbomRuntime({
      clock,
      createId: () => randomUUID(),
      assets: assetPort,
      uploadIdempotency: idempotency,
      sbomMetadata,
      ingestions: ingestionPort,
      storage,
      unitOfWork,
    }),
  };
}

function toAssetRecord(detail: {
  id: string;
  organizationId: string;
  name: string;
  description: string | null;
  assetType: AssetRecord['assetType'];
  lifecycleStatus: AssetRecord['lifecycleStatus'];
  environment: { id: string } | null;
  owningTeam: { id: string } | null;
  businessCriticality: AssetRecord['businessCriticality'];
  internetExposure: AssetRecord['internetExposure'];
  dataClassification: AssetRecord['dataClassification'];
  repositoryUrl: string | null;
  deploymentContext: string | null;
  lastObservedAt: Date | null;
  lastSuccessfulSbomIngestionId: string | null;
  lastSuccessfulSbomIngestionAt: Date | null;
  archivedAt: Date | null;
  version: number;
  createdAt: Date;
  updatedAt: Date;
}): AssetRecord {
  return {
    id: detail.id,
    organizationId: detail.organizationId,
    name: detail.name,
    description: detail.description,
    assetType: detail.assetType,
    lifecycleStatus: detail.lifecycleStatus,
    environmentId: detail.environment?.id ?? null,
    owningTeamId: detail.owningTeam?.id ?? null,
    businessCriticality: detail.businessCriticality,
    internetExposure: detail.internetExposure,
    dataClassification: detail.dataClassification,
    repositoryUrl: detail.repositoryUrl,
    deploymentContext: detail.deploymentContext,
    lastObservedAt: detail.lastObservedAt,
    lastSuccessfulSbomIngestionId: detail.lastSuccessfulSbomIngestionId,
    lastSuccessfulSbomIngestionAt: detail.lastSuccessfulSbomIngestionAt,
    archivedAt: detail.archivedAt,
    version: detail.version,
    createdAt: detail.createdAt,
    updatedAt: detail.updatedAt,
  };
}

function createMemoryStorage(): SbomObjectStoragePort & { objects: Map<string, Uint8Array> } {
  const objects = new Map<string, Uint8Array>();
  return {
    objects,
    async verifyBucketAvailability() {
      return {
        ok: true,
        value: { bucketPrivate: true, publicAccessDisabled: true, signedUrlsDisabled: true },
      };
    },
    async initializeDevelopmentBucket() {
      return { ok: true, value: undefined };
    },
    async putTemporaryObject(input) {
      const chunks: Uint8Array[] = [];
      let observed = 0;
      for await (const chunk of input.body) {
        observed += chunk.byteLength;
        if (observed > input.maxBytes) {
          return { ok: false, error: { category: 'size_limit' as const } };
        }
        chunks.push(chunk);
      }
      const bytes = concat(chunks);
      if (input.declaredByteLength !== undefined && bytes.byteLength !== input.declaredByteLength) {
        return { ok: false, error: { category: 'invalid_content' as const } };
      }
      objects.set(input.temporaryObjectKey, bytes);
      return {
        ok: true,
        value: {
          sha256: createHash('sha256').update(bytes).digest('hex'),
          observedByteLength: bytes.byteLength,
        },
      };
    },
    async promoteTemporaryObject(input) {
      const bytes = objects.get(input.temporaryObjectKey);
      if (bytes === undefined) {
        return { ok: false, error: { category: 'object_missing' as const } };
      }
      objects.set(input.finalObjectKey, bytes);
      return { ok: true, value: undefined };
    },
    async headFinalObject() {
      return { ok: true, value: { exists: false } };
    },
    async deleteTemporaryObject(input) {
      objects.delete(input.temporaryObjectKey);
      return { ok: true, value: undefined };
    },
    async getObject() {
      return { ok: false, error: { category: 'internal' as const } };
    },
  };
}

function createMemoryIdempotency(): SbomUploadIdempotencyPort {
  const records = new Map<string, IdempotencyReservationRecord>();
  return {
    async reserveStarted(input) {
      const key = `${input.organizationId}:${input.scope}:${input.keyHash}`;
      const existing = records.get(key);
      if (existing === undefined) {
        const record: IdempotencyReservationRecord = {
          id: randomUUID(),
          organizationId: input.organizationId,
          scope: input.scope,
          keyHash: input.keyHash,
          reservationFingerprint: input.reservationFingerprint,
          status: 'started',
          expiresAt: input.expiresAt,
          completedAt: null,
          response: null,
          finalFingerprint: null,
        };
        records.set(key, record);
        return { kind: 'acquired', record };
      }
      if (existing.status === 'completed') {
        return { kind: 'completed', record: existing };
      }
      if (existing.status === 'started' && existing.expiresAt.getTime() > Date.now()) {
        if (existing.reservationFingerprint !== input.reservationFingerprint) {
          return { kind: 'conflict', record: existing };
        }
        return { kind: 'unexpired_started', record: existing };
      }
      if (existing.status === 'started' && existing.expiresAt.getTime() <= Date.now()) {
        return { kind: 'reclaimable_expired', record: existing };
      }
      return { kind: 'conflict', record: existing };
    },
    async findUnexpiredStarted(input) {
      const existing = records.get(`${input.organizationId}:${input.scope}:${input.keyHash}`);
      if (existing?.status === 'started' && existing.expiresAt.getTime() > Date.now()) {
        return existing;
      }
      return undefined;
    },
    async reclaimExpiredStarted(input) {
      const existing = records.get(`${input.organizationId}:${input.scope}:${input.keyHash}`);
      if (
        existing === undefined ||
        existing.status !== 'started' ||
        existing.expiresAt.getTime() > Date.now()
      ) {
        return { ok: false, error: { code: 'conflict', message: 'not reclaimed' } };
      }
      existing.reservationFingerprint = input.reservationFingerprint;
      existing.expiresAt = input.expiresAt;
      return { ok: true, value: existing };
    },
    async finalizeCompleted(input) {
      const existing = records.get(`${input.organizationId}:${input.scope}:${input.keyHash}`);
      if (
        existing === undefined ||
        existing.status !== 'started' ||
        existing.reservationFingerprint !== input.reservationFingerprint
      ) {
        return {
          ok: false,
          error: { code: 'conflict', message: 'Idempotency reservation could not be finalized.' },
        };
      }
      existing.status = 'completed';
      existing.finalFingerprint = input.finalFingerprint;
      existing.reservationFingerprint = input.finalFingerprint;
      existing.completedAt = NOW;
      existing.response = input.response;
      return { ok: true, value: existing };
    },
    async resolveCompletedReplay(input) {
      const existing = records.get(`${input.organizationId}:${input.scope}:${input.keyHash}`);
      if (existing === undefined || existing.status !== 'completed' || existing.response === null) {
        return { ok: false, error: { code: 'not_found', message: 'not found' } };
      }
      if (existing.finalFingerprint !== input.finalFingerprint) {
        return { ok: true, value: { kind: 'fingerprint_mismatch' } };
      }
      return {
        ok: true,
        value: { kind: 'replay', response: existing.response, responseStatus: 202 },
      };
    },
  };
}

function createMemorySbomMetadata(sboms: Map<string, SbomRecord>) {
  return {
    async insert(input: PersistSbomMetadataInput): Promise<SbomRecord> {
      const existing = [...sboms.values()].find(
        (row) =>
          row.organizationId === input.organizationId &&
          row.assetId === input.assetId &&
          row.sha256 === input.sha256,
      );
      if (existing !== undefined) {
        throw new SbomEvidenceConflictError();
      }
      const record: SbomRecord = {
        id: randomUUID(),
        organizationId: input.organizationId,
        assetId: input.assetId,
        objectKey: input.objectKey,
        sha256: input.sha256,
        byteLength: input.byteLength,
        declaredContentType: input.declaredContentType,
        specificationType: input.specificationType,
        specificationVersion: null,
        source: input.source,
        originalFilename: null,
        uploadedByMembershipId: input.uploadedByMembershipId,
        capturedAt: input.capturedAt,
        receivedAt: input.receivedAt,
        parserVersionLastSucceeded: null,
        createdAt: NOW,
      };
      sboms.set(record.id, record);
      return record;
    },
    async findById(organizationId: string, sbomId: string) {
      const row = sboms.get(sbomId);
      return row?.organizationId === organizationId ? row : undefined;
    },
    async findByAssetAndId(organizationId: string, assetId: string, sbomId: string) {
      const row = sboms.get(sbomId);
      return row?.organizationId === organizationId && row.assetId === assetId ? row : undefined;
    },
    async findByAssetAndHash(organizationId: string, assetId: string, sha256: string) {
      return [...sboms.values()].find(
        (row) =>
          row.organizationId === organizationId && row.assetId === assetId && row.sha256 === sha256,
      );
    },
    async listForAsset(organizationId: string, assetId: string, query?: SbomListQuery) {
      const limit = query?.limit ?? SBOM_LIST_DEFAULT_LIMIT;
      let items = [...sboms.values()]
        .filter((row) => row.organizationId === organizationId && row.assetId === assetId)
        .sort((left, right) => {
          const received = right.receivedAt.getTime() - left.receivedAt.getTime();
          return received === 0 ? right.id.localeCompare(left.id) : received;
        });
      const cursor = query?.cursor;
      if (cursor !== undefined) {
        const cursorTime = Date.parse(cursor.r);
        items = items.filter(
          (row) =>
            row.receivedAt.getTime() < cursorTime ||
            (row.receivedAt.getTime() === cursorTime && row.id < cursor.i),
        );
      }
      const page = items.slice(0, limit);
      const last = page[page.length - 1];
      return {
        items: page.map(toSummary),
        nextCursor:
          items.length > limit && last !== undefined
            ? { v: 1 as const, r: last.receivedAt.toISOString(), i: last.id }
            : undefined,
      };
    },
    async recordSuccessfulParser() {
      return { ok: false as const, error: { code: 'internal' as const, message: 'unused' } };
    },
  };
}

function createMemoryIngestions(ingestions: Map<string, SbomIngestionRecord>) {
  return {
    async createAccepted(input: {
      organizationId: string;
      sbomId: string;
      assetId: string;
      parserVersion: string;
      normalizationVersion: string;
    }) {
      const record: SbomIngestionRecord = {
        id: randomUUID(),
        organizationId: input.organizationId,
        sbomId: input.sbomId,
        assetId: input.assetId,
        state: 'accepted',
        stage: 'validate',
        attemptNumber: 1,
        parserVersion: input.parserVersion,
        normalizationVersion: input.normalizationVersion,
        idempotencyKey: null,
        startedAt: null,
        completedAt: null,
        graphCompleteness: null,
        componentCount: null,
        dependencyEdgeCount: null,
        warningCount: null,
        failureCategory: null,
        failureCode: null,
        quarantineReason: null,
        leaseExpiresAt: null,
        version: 1,
        createdAt: NOW,
        updatedAt: NOW,
      };
      ingestions.set(record.id, record);
      return { ok: true as const, value: record };
    },
    async findById(organizationId: string, ingestionId: string) {
      const row = ingestions.get(ingestionId);
      return row?.organizationId === organizationId ? row : undefined;
    },
    async findByAssetAndId(organizationId: string, assetId: string, ingestionId: string) {
      const row = ingestions.get(ingestionId);
      return row?.organizationId === organizationId && row.assetId === assetId ? row : undefined;
    },
    async findCurrentForSbom(organizationId: string, sbomId: string) {
      return [...ingestions.values()]
        .filter((row) => row.organizationId === organizationId && row.sbomId === sbomId)
        .sort((left, right) => right.createdAt.getTime() - left.createdAt.getTime())[0];
    },
    async applyTransition() {
      return { ok: false as const, error: { code: 'conflict' as const, message: 'unused' } };
    },
  };
}

function createMemoryAudit(events: AuditEventRecord[], clock: Clock) {
  return {
    async append(input: AppendAuditEventInput) {
      const record: AuditEventRecord = {
        id: randomUUID(),
        organizationId: input.organizationId ?? null,
        actorUserId: input.actorUserId ?? null,
        actorMembershipId: input.actorMembershipId ?? null,
        actorType: input.actorType,
        action: input.action,
        subjectType: input.subjectType,
        subjectId: input.subjectId,
        occurredAt: input.occurredAt ?? clock.now(),
        requestId: input.requestId ?? null,
        correlationId: input.correlationId,
        sourceIp: input.sourceIp ?? null,
        userAgent: input.userAgent ?? null,
        payload: input.payload,
        schemaVersion: input.schemaVersion ?? JSON_SCHEMA_VERSION_V1,
        retentionCategory: input.retentionCategory ?? 'security',
      };
      events.push(record);
      return record;
    },
    async findById() {
      return undefined;
    },
    async listForOrganization() {
      return { items: [], nextCursor: undefined };
    },
  };
}

function createMemoryOutbox(events: OutboxEventRecord[], clock: Clock) {
  return {
    async create(input: CreateOutboxEventInput) {
      const now = clock.now();
      const record: OutboxEventRecord = {
        id: randomUUID(),
        organizationId: input.organizationId ?? null,
        aggregateType: input.aggregateType,
        aggregateId: input.aggregateId,
        eventType: input.eventType,
        eventSchemaVersion: input.eventSchemaVersion ?? JSON_SCHEMA_VERSION_V1,
        payload: input.payload,
        dedupeKey: input.dedupeKey,
        occurredAt: input.occurredAt ?? now,
        availableAt: input.availableAt ?? now,
        claimedAt: null,
        leaseExpiresAt: null,
        processedAt: null,
        attemptCount: 0,
        lastFailureCategory: null,
        lastFailureCode: null,
        status: input.status ?? 'pending',
        createdAt: now,
      };
      events.push(record);
      return record;
    },
    async findById() {
      return undefined;
    },
    async listForOrganization() {
      return { items: [], nextCursor: undefined };
    },
  };
}

function toSummary(row: SbomRecord): SbomSummaryRecord {
  return {
    id: row.id,
    organizationId: row.organizationId,
    assetId: row.assetId,
    sha256: row.sha256,
    byteLength: row.byteLength,
    specificationType: row.specificationType,
    specificationVersion: row.specificationVersion,
    source: row.source,
    receivedAt: row.receivedAt,
    capturedAt: row.capturedAt,
    parserVersionLastSucceeded: row.parserVersionLastSucceeded,
  };
}

function concat(chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((sum, chunk) => sum + chunk.byteLength, 0);
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return bytes;
}
