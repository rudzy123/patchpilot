import { createHash, randomUUID } from 'node:crypto';

import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { PrismaClient } from '@prisma/client';
import {
  createCisaKevSynchronizationService,
  createEvaluateKevSyncScheduleUseCase,
  createRelayOutboxBatchUseCase,
  type CisaKevSynchronizationConfig,
  type IntelligenceKevParserSuccess,
  type IntelligenceProviderHttpPort,
  type IntelligenceSnapshotStoragePort,
  type OutboxQueueJob,
} from '@patchpilot/domain';

import { PrismaBackgroundJobExecution } from './background-job-execution.js';
import {
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
} from './integration-database.js';
import { createIntelligencePersistence } from './intelligence-persistence.js';
import { createSbomPersistence } from './sbom-persistence.js';
import {
  KEV_NORMALIZATION_VERSION,
  KEV_PARSER_VERSION,
  NOW,
  failInflightSyncRuns,
  seedZeroFindingBaseline,
} from './intelligence-test-fixture.js';

const WORKER = 'kev-scheduler-runtime';
const BODY = new TextEncoder().encode(
  '{"catalogVersion":"2099.01.01","dateReleased":"2099-01-01T00:00:00.000Z","count":1}',
);

const CONFIG: CisaKevSynchronizationConfig = {
  kevEnabled: true,
  parserVersion: KEV_PARSER_VERSION,
  normalizationVersion: KEV_NORMALIZATION_VERSION,
  kevResponseMaxBytes: 65_536,
  kevParserTimeoutMs: 10_000,
  kevJobLeaseMs: 600_000,
  maxStagedRowsPerTransaction: 50,
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

function parserSuccess(): IntelligenceKevParserSuccess {
  return {
    ok: true,
    catalogVersion: '2099.01.01',
    catalogReleasedAt: '2099-01-01T00:00:00.000Z',
    expectedEntryCount: 1,
    entries: [
      {
        ordinal: 0,
        normalizedCve: 'CVE-2099-0001',
        vendorProject: 'Northwind Testware',
        product: 'Fabrikam Widget',
        vulnerabilityName: 'Synthetic inert vulnerability',
        dateAdded: '2099-01-02',
        shortDescription: 'Inert synthetic description.',
        requiredAction: 'Inert synthetic action.',
        dueDate: '2099-01-16',
        knownRansomwareCampaignUse: 'known',
        rawKnownRansomwareCampaignUse: null,
        notes: null,
        cwes: ['CWE-79'],
      },
    ],
    entryCount: 1,
    warnings: [],
    parserVersion: KEV_PARSER_VERSION,
    normalizationVersion: KEV_NORMALIZATION_VERSION,
    serializedResultBytes: 256,
  };
}

async function* bodyOf(bytes: Uint8Array): AsyncIterable<Uint8Array> {
  yield bytes;
}

describe('KEV scheduler to activation runtime path', () => {
  let databaseName: string;
  let admin: PrismaClient;
  let prisma: PrismaClient;
  let baseline: {
    findingCount: number;
    observationCount: number;
    vulnerabilityCount: number;
  };

  beforeAll(async () => {
    const ephemeral = await createEphemeralDatabase('it');
    databaseName = ephemeral.databaseName;
    admin = ephemeral.admin;
    await deployMigrations(ephemeral.databaseUrl);
    prisma = new PrismaClient({ datasourceUrl: ephemeral.databaseUrl });
    await seedZeroFindingBaseline(prisma);
    baseline = {
      findingCount: await prisma.finding.count(),
      observationCount: await prisma.findingObservation.count(),
      vulnerabilityCount: await prisma.vulnerability.count(),
    };
  });

  afterAll(async () => {
    await prisma.$disconnect();
    await dropEphemeralDatabase(admin, databaseName);
    await admin.$disconnect();
  });

  beforeEach(async () => {
    await failInflightSyncRuns(prisma);
  });

  async function assertZeroFindingUnchanged() {
    expect(await prisma.finding.count()).toBe(baseline.findingCount);
    expect(await prisma.findingObservation.count()).toBe(baseline.observationCount);
    expect(await prisma.vulnerability.count()).toBe(baseline.vulnerabilityCount);
    expect(await prisma.vulnerabilityAlias.count()).toBe(0);
    expect(await prisma.vulnerabilitySourceRecord.count()).toBe(0);
    expect(await prisma.outboxEvent.count({ where: { eventType: 'finding.recalculate' } })).toBe(0);
  }

  function createPorts() {
    const catalogSha = createHash('sha256').update(BODY).digest('hex');
    const objects = new Map<string, Uint8Array>();
    const counters = { http: 0, parse: 0 };
    const http: IntelligenceProviderHttpPort = {
      async fetchCatalog() {
        counters.http += 1;
        return {
          kind: 'response',
          status: 200,
          declaredContentType: 'application/json',
          declaredByteLength: BODY.byteLength,
          etagHash: null,
          lastModified: null,
          body: bodyOf(BODY),
          completion: Promise.resolve({
            observedByteLength: BODY.byteLength,
            sha256: catalogSha,
          }),
          cancel: async () => undefined,
        };
      },
    };
    const storage: IntelligenceSnapshotStoragePort = {
      async verifyPrivateStorageAvailability() {
        return {
          ok: true,
          value: { bucketPrivate: true, publicAccessDisabled: true, signedUrlsDisabled: true },
        };
      },
      async initializeDevelopmentBucket() {
        return { ok: true, value: undefined };
      },
      async putTemporarySnapshot(input) {
        const chunks: Uint8Array[] = [];
        for await (const chunk of input.body) {
          chunks.push(chunk);
        }
        const bytes = Buffer.concat(chunks);
        objects.set(input.temporaryObjectKey, bytes);
        return {
          ok: true as const,
          value: {
            sha256: createHash('sha256').update(bytes).digest('hex'),
            observedByteLength: bytes.byteLength,
          },
        };
      },
      async promoteTemporarySnapshot(input) {
        const bytes = objects.get(input.temporaryObjectKey);
        if (bytes === undefined) {
          return {
            ok: false as const,
            error: { category: 'storage' as const, code: 'snapshot_storage_failed' as const },
          };
        }
        objects.set(input.finalObjectKey, bytes);
        objects.delete(input.temporaryObjectKey);
        return {
          ok: true as const,
          value: { outcome: 'copied' as const, temporaryCleanup: 'deleted' as const },
        };
      },
      async headFinalSnapshot(input) {
        const bytes = objects.get(input.finalObjectKey);
        if (bytes === undefined) {
          return { ok: true as const, value: { exists: false as const } };
        }
        return {
          ok: true as const,
          value: {
            exists: true as const,
            byteLength: bytes.byteLength,
            sha256: createHash('sha256').update(bytes).digest('hex'),
            declaredContentType: 'application/json',
            detectedContentType: 'application/json',
            provider: 'cisa_kev' as const,
            sourceIdentifier: 'cisa_kev_json_catalog' as const,
          },
        };
      },
      async getFinalSnapshot(input) {
        const bytes = objects.get(input.finalObjectKey);
        if (bytes === undefined) {
          return {
            ok: false as const,
            error: { category: 'storage' as const, code: 'snapshot_missing' as const },
          };
        }
        return {
          ok: true as const,
          value: {
            body: bodyOf(bytes),
            declaredByteLength: bytes.byteLength,
            completion: Promise.resolve({
              observedByteLength: bytes.byteLength,
              sha256: createHash('sha256').update(bytes).digest('hex'),
            }),
            cancel: async () => undefined,
          },
        };
      },
      async deleteTemporarySnapshot(input) {
        objects.delete(input.temporaryObjectKey);
        return { ok: true as const, value: undefined };
      },
    };
    return {
      counters,
      http,
      storage,
      parser: {
        async parse() {
          counters.parse += 1;
          return parserSuccess();
        },
      },
    };
  }

  it('creates one scheduled run, relays intelligence.sync, and activates a KEV generation', async () => {
    const adapters = createIntelligencePersistence(prisma);
    const jobs = new PrismaBackgroundJobExecution(prisma);
    const sbom = createSbomPersistence(prisma);
    const clock = { now: () => NOW };
    const published: OutboxQueueJob[] = [];
    const evaluate = createEvaluateKevSyncScheduleUseCase({
      clock,
      createId: () => randomUUID(),
      kevEnabled: true,
      syncIntervalSeconds: 86_400,
      parserVersion: KEV_PARSER_VERSION,
      normalizationVersion: KEV_NORMALIZATION_VERSION,
      syncRuns: adapters.syncRuns,
      freshness: adapters.freshness,
      scheduler: adapters.scheduler,
    });
    const first = await evaluate.execute({ shutdown: false });
    expect(first.kind).toBe('due_initial');
    if (first.kind !== 'due_initial') {
      throw new Error('expected due_initial');
    }
    const duplicate = await evaluate.execute({ shutdown: false });
    expect(duplicate.kind === 'inflight' || duplicate.kind === 'existing_inflight').toBe(true);
    expect(await prisma.vulnerabilitySyncRun.count()).toBe(1);
    expect(
      await prisma.auditEvent.count({
        where: { action: 'intelligence.sync_requested', subjectId: first.syncRunId },
      }),
    ).toBe(1);
    const event = await prisma.outboxEvent.findFirstOrThrow({
      where: { eventType: 'intelligence.sync.requested.v1', aggregateId: first.syncRunId },
    });
    expect(event.organizationId).toBeNull();
    expect(event.status).toBe('pending');
    const relay = createRelayOutboxBatchUseCase({
      clock,
      outbox: sbom.outboxRelay,
      queue: {
        publish: async (job) => {
          published.push(job);
          return { ok: true, duplicate: false };
        },
      },
      backgroundJobs: jobs,
    });
    const relayed = await relay.execute();
    expect(relayed.published).toBe(1);
    expect(published[0]?.jobType).toBe('intelligence.sync');
    expect(published[0]?.organizationId).toBeNull();
    expect(JSON.stringify(published[0])).not.toMatch(/https:\/\/|objectKey|etag|CVE-/i);
    const processed = await prisma.outboxEvent.findUniqueOrThrow({ where: { id: event.id } });
    expect(processed.status).toBe('processed');
    const runAfterRelay = await adapters.syncRuns.findById(first.syncRunId);
    expect(runAfterRelay?.state).toBe('requested');
    expect(runAfterRelay?.state).not.toBe('completed');
    expect(runAfterRelay?.completedAt).toBeNull();
    const job = await jobs.findByOutboxEventId({
      organizationId: null,
      outboxEventId: event.id,
    });
    expect(job?.jobType).toBe('intelligence.sync');
    expect(job?.organizationId).toBeNull();
    if (job === undefined) {
      throw new Error('background job missing after relay');
    }
    const claimed = await jobs.claimExecution({
      organizationId: null,
      jobId: job.id,
      workerIdentifier: WORKER,
      now: NOW,
      leaseExpiresAt: new Date(NOW.getTime() + 600_000),
    });
    expect(claimed.ok).toBe(true);
    const ports = createPorts();
    const service = createCisaKevSynchronizationService({
      clock,
      createId: () => randomUUID(),
      config: CONFIG,
      jobs,
      outbox: adapters.outbox,
      syncRuns: adapters.syncRuns,
      snapshots: adapters.snapshots,
      generations: adapters.generations,
      freshness: adapters.freshness,
      http: ports.http,
      storage: ports.storage,
      parser: ports.parser,
      unitOfWork: adapters.unitOfWork,
    });
    const outcome = await service.execute({
      syncRunId: first.syncRunId,
      backgroundJobId: job.id,
      workerIdentifier: WORKER,
    });
    expect(outcome.kind).toBe('completed');
    expect(ports.counters.http).toBe(1);
    const completed = await adapters.syncRuns.findById(first.syncRunId);
    expect(completed?.state).toBe('completed');
    const source = await prisma.intelligenceSource.findUniqueOrThrow({
      where: { providerKey: 'cisa_kev' },
    });
    expect(source.activeGenerationId).not.toBeNull();
    const notDue = await evaluate.execute({ shutdown: false });
    expect(notDue.kind).toBe('not_due');
    await assertZeroFindingUnchanged();
  });
});
