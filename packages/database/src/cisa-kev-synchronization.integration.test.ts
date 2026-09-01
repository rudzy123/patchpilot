import { createHash, randomUUID } from 'node:crypto';

import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { PrismaClient } from '@prisma/client';
import {
  createCisaKevSynchronizationService,
  type CisaKevSynchronizationConfig,
  type IntelligenceKevParserSuccess,
  type IntelligenceProviderHttpPort,
  type IntelligenceSnapshotStoragePort,
} from '@patchpilot/domain';

import { PrismaBackgroundJobExecution } from './background-job-execution.js';
import {
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
} from './integration-database.js';
import { createIntelligencePersistence } from './intelligence-persistence.js';
import {
  KEV_NORMALIZATION_VERSION,
  KEV_PARSER_VERSION,
  NOW,
  failInflightSyncRuns,
  seedZeroFindingBaseline,
} from './intelligence-test-fixture.js';

const WORKER = 'kev-sync-worker';
const BODY = new TextEncoder().encode(
  '{"catalogVersion":"2099.01.01","dateReleased":"2099-01-01T00:00:00.000Z","count":1}',
);
const BODY_B = new TextEncoder().encode(
  '{"catalogVersion":"2099.02.01","dateReleased":"2099-02-01T00:00:00.000Z","count":1}',
);

const CONFIG: CisaKevSynchronizationConfig = {
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
    warnings: [{ code: 'unrecognized_ransomware_value', count: 1 }],
    parserVersion: KEV_PARSER_VERSION,
    normalizationVersion: KEV_NORMALIZATION_VERSION,
    serializedResultBytes: 256,
  };
}

async function* bodyOf(bytes: Uint8Array): AsyncIterable<Uint8Array> {
  yield bytes;
}

describe('CISA KEV synchronization service persistence', () => {
  let databaseName: string;
  let admin: PrismaClient;
  let prisma: PrismaClient;
  let baseline: Awaited<ReturnType<typeof seedZeroFindingBaseline>> & {
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
    const seeded = await seedZeroFindingBaseline(prisma);
    baseline = {
      ...seeded,
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
    expect(await prisma.outboxEvent.count({ where: { eventType: 'finding.recalculate' } })).toBe(0);
    expect(await prisma.vulnerability.count()).toBe(baseline.vulnerabilityCount);
    expect(await prisma.vulnerabilityAlias.count()).toBe(0);
    expect(await prisma.vulnerabilitySourceRecord.count()).toBe(0);
    expect(await prisma.component.count()).toBeGreaterThan(0);
  }

  function createPorts(options: {
    http?: 'ok' | 'timeout';
    parse?: 'ok' | 'timeout';
    body?: Uint8Array;
  }) {
    const catalog = options.body ?? BODY;
    const catalogSha = createHash('sha256').update(catalog).digest('hex');
    const objects = new Map<string, Uint8Array>();
    const counters = { http: 0, get: 0, parse: 0 };
    const http: IntelligenceProviderHttpPort = {
      async fetchCatalog(request) {
        counters.http += 1;
        if (options.http === 'timeout') {
          return { kind: 'failure', category: 'timeout', code: 'connection_timeout' };
        }
        if (request.signal?.aborted === true) {
          return { kind: 'failure', category: 'timeout', code: 'request_cancelled' };
        }
        return {
          kind: 'response',
          status: 200,
          declaredContentType: 'application/json',
          declaredByteLength: catalog.byteLength,
          etagHash: null,
          lastModified: null,
          body: bodyOf(catalog),
          completion: Promise.resolve({
            observedByteLength: catalog.byteLength,
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
        counters.get += 1;
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
      objects,
      http,
      storage,
      parser: {
        async parse() {
          counters.parse += 1;
          if (options.parse === 'timeout') {
            return {
              ok: false as const,
              disposition: 'failed' as const,
              category: 'parser' as const,
              code: 'parser_timeout' as const,
            };
          }
          return parserSuccess();
        },
      },
    };
  }

  async function startRun() {
    await failInflightSyncRuns(prisma);
    const adapters = createIntelligencePersistence(prisma);
    const jobs = new PrismaBackgroundJobExecution(prisma);
    const syncRunId = randomUUID();
    const requested = await adapters.unitOfWork.requestSync({
      provider: 'cisa_kev',
      sourceIdentifier: 'cisa_kev_json_catalog',
      syncRunId,
      requestedAt: NOW,
      correlationId: `corr-${syncRunId}`,
      parserVersion: KEV_PARSER_VERSION,
      normalizationVersion: KEV_NORMALIZATION_VERSION,
      dedupeKey: `sync-${syncRunId}`,
    });
    if (!requested.ok || requested.value.outcome !== 'created') {
      throw new Error(
        `requestSync failed: ${requested.ok ? requested.value.outcome : requested.error.message}`,
      );
    }
    const event = await prisma.outboxEvent.findFirstOrThrow({
      where: { aggregateId: syncRunId, eventType: 'intelligence.sync.requested.v1' },
    });
    const job = await prisma.backgroundJob.create({
      data: {
        organizationId: null,
        outboxEventId: event.id,
        jobType: 'intelligence.sync',
        status: 'running',
        workerIdentifier: WORKER,
        attempt: 1,
        startedAt: NOW,
        leaseExpiresAt: new Date(NOW.getTime() + 600_000),
      },
    });
    return { adapters, jobs, syncRunId, jobId: job.id, run: requested.value.syncRun };
  }

  it('activates the first catalog and then treats duplicate content as not-modified', async () => {
    const firstPorts = createPorts({ http: 'ok', parse: 'ok' });
    const first = await startRun();
    const firstService = createCisaKevSynchronizationService({
      clock: { now: () => NOW },
      createId: () => randomUUID(),
      config: CONFIG,
      jobs: first.jobs,
      outbox: first.adapters.outbox,
      syncRuns: first.adapters.syncRuns,
      snapshots: first.adapters.snapshots,
      generations: first.adapters.generations,
      freshness: first.adapters.freshness,
      http: firstPorts.http,
      storage: firstPorts.storage,
      parser: firstPorts.parser,
      unitOfWork: first.adapters.unitOfWork,
      leaseScheduler: {
        schedule() {
          return { stop() {} };
        },
      },
    });
    const completed = await firstService.execute({
      syncRunId: first.syncRunId,
      backgroundJobId: first.jobId,
      workerIdentifier: WORKER,
    });
    expect(completed).toEqual({ kind: 'completed', acceptedEntryCount: 1, warningCount: 1 });
    expect(firstPorts.counters.http).toBe(1);
    expect(firstPorts.counters.parse).toBe(1);
    const active = await first.adapters.generations.findActiveGeneration(
      'cisa_kev',
      'cisa_kev_json_catalog',
    );
    expect(active?.state).toBe('active');
    expect(active?.expectedEntryCount).toBe(1);

    const secondPorts = createPorts({ http: 'ok', parse: 'ok' });
    for (const [key, value] of firstPorts.objects) {
      secondPorts.objects.set(key, value);
    }
    const second = await startRun();
    const secondService = createCisaKevSynchronizationService({
      clock: { now: () => NOW },
      createId: () => randomUUID(),
      config: CONFIG,
      jobs: second.jobs,
      outbox: second.adapters.outbox,
      syncRuns: second.adapters.syncRuns,
      snapshots: second.adapters.snapshots,
      generations: second.adapters.generations,
      freshness: second.adapters.freshness,
      http: secondPorts.http,
      storage: secondPorts.storage,
      parser: secondPorts.parser,
      unitOfWork: second.adapters.unitOfWork,
      leaseScheduler: {
        schedule() {
          return { stop() {} };
        },
      },
    });
    const notModified = await secondService.execute({
      syncRunId: second.syncRunId,
      backgroundJobId: second.jobId,
      workerIdentifier: WORKER,
    });
    expect(notModified).toEqual({ kind: 'not_modified', reason: 'content_sha256_unchanged' });
    expect(secondPorts.counters.parse).toBe(0);
    expect(secondPorts.counters.get).toBe(0);
    const stillActive = await second.adapters.generations.findActiveGeneration(
      'cisa_kev',
      'cisa_kev_json_catalog',
    );
    expect(stillActive?.id).toBe(active?.id);
    await assertZeroFindingUnchanged();
  });

  it('uses retry_wait for HTTP failure before a snapshot and job_retry after stored', async () => {
    const timeoutPorts = createPorts({ http: 'timeout', parse: 'ok' });
    const timeoutRun = await startRun();
    const timeoutService = createCisaKevSynchronizationService({
      clock: { now: () => NOW },
      createId: () => randomUUID(),
      config: CONFIG,
      jobs: timeoutRun.jobs,
      outbox: timeoutRun.adapters.outbox,
      syncRuns: timeoutRun.adapters.syncRuns,
      snapshots: timeoutRun.adapters.snapshots,
      generations: timeoutRun.adapters.generations,
      freshness: timeoutRun.adapters.freshness,
      http: timeoutPorts.http,
      storage: timeoutPorts.storage,
      parser: timeoutPorts.parser,
      unitOfWork: timeoutRun.adapters.unitOfWork,
      leaseScheduler: {
        schedule() {
          return { stop() {} };
        },
      },
    });
    const waited = await timeoutService.execute({
      syncRunId: timeoutRun.syncRunId,
      backgroundJobId: timeoutRun.jobId,
      workerIdentifier: WORKER,
    });
    expect(waited.kind).toBe('retry_wait');
    const timeoutState = await timeoutRun.adapters.syncRuns.findById(timeoutRun.syncRunId);
    expect(timeoutState?.state).toBe('retry_wait');
    expect(timeoutState?.snapshotId).toBeNull();

    const storedPorts = createPorts({ http: 'ok', parse: 'timeout', body: BODY_B });
    const storedRun = await startRun();
    const storedService = createCisaKevSynchronizationService({
      clock: { now: () => NOW },
      createId: () => randomUUID(),
      config: CONFIG,
      jobs: storedRun.jobs,
      outbox: storedRun.adapters.outbox,
      syncRuns: storedRun.adapters.syncRuns,
      snapshots: storedRun.adapters.snapshots,
      generations: storedRun.adapters.generations,
      freshness: storedRun.adapters.freshness,
      http: storedPorts.http,
      storage: storedPorts.storage,
      parser: storedPorts.parser,
      unitOfWork: storedRun.adapters.unitOfWork,
      leaseScheduler: {
        schedule() {
          return { stop() {} };
        },
      },
    });
    const retried = await storedService.execute({
      syncRunId: storedRun.syncRunId,
      backgroundJobId: storedRun.jobId,
      workerIdentifier: WORKER,
    });
    expect(retried).toEqual({ kind: 'job_retry', code: 'parser_timeout' });
    expect(storedPorts.counters.http).toBe(1);
    const after = await storedRun.adapters.syncRuns.findById(storedRun.syncRunId);
    expect(after?.state).toBe('parsing');
    expect(after?.snapshotId).not.toBeNull();
    await assertZeroFindingUnchanged();
  });
});
