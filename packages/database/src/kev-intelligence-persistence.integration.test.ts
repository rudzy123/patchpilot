import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { PrismaClient } from '@prisma/client';
import { INTELLIGENCE_KEV_STALE_THRESHOLD_SECONDS_DEFAULT } from '@patchpilot/config';
import {
  INTELLIGENCE_PARTIAL_ACTIVATION_INCONSISTENT,
  deriveIntelligenceProviderHealthStatus,
  parseFinalIntelligenceSnapshotObjectKey,
  type IntelligenceSnapshotRecord,
  type Result,
} from '@patchpilot/domain';

import {
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
} from './integration-database.js';
import { createIntelligencePersistence } from './intelligence-persistence.js';
import {
  CATALOG_VERSION,
  KEV_NORMALIZATION_VERSION,
  KEV_OBJECT_KEY,
  KEV_PARSER_VERSION,
  NOW,
  failInflightSyncRuns,
  seedZeroFindingBaseline,
  syntheticKevEntry,
  uniqueKevSha,
} from './intelligence-test-fixture.js';

const packageSrc = path.resolve(path.dirname(fileURLToPath(import.meta.url)));
const domainPorts = path.resolve(packageSrc, '../../domain/src/intelligence/ports.ts');

function requireOk<T>(result: Result<T>, label: string): T {
  if (!result.ok) {
    throw new Error(`${label}: ${result.error.code} ${result.error.message}`);
  }
  return result.value;
}

function snapshotRecord(creatingSyncRunId: string, sha256: string): IntelligenceSnapshotRecord {
  const objectKey = parseFinalIntelligenceSnapshotObjectKey(KEV_OBJECT_KEY);
  if (!objectKey.ok) {
    throw new Error(objectKey.error.message);
  }
  return {
    id: randomUUID(),
    provider: 'cisa_kev',
    sourceIdentifier: 'cisa_kev_json_catalog',
    responseSha256: sha256,
    byteLength: 2048,
    declaredContentType: 'application/json',
    detectedContentType: 'application/json',
    objectKey: objectKey.value,
    retrievedAt: NOW,
    storedAt: NOW,
    etagHash: 'e'.repeat(64),
    lastModified: NOW,
    creatingSyncRunId,
    createdAt: NOW,
  };
}

describe('session 9 KEV intelligence persistence adapters', () => {
  let databaseName: string;
  let admin: PrismaClient;
  let prisma: PrismaClient;
  let baseline: Awaited<ReturnType<typeof seedZeroFindingBaseline>> & {
    findingCount: number;
    observationCount: number;
    vulnerabilityCount: number;
  };

  async function failInflightRuns() {
    await failInflightSyncRuns(prisma);
  }

  beforeAll(async () => {
    const ephemeral = await createEphemeralDatabase('it');
    databaseName = ephemeral.databaseName;
    admin = ephemeral.admin;
    await deployMigrations(ephemeral.databaseUrl);
    prisma = new PrismaClient({
      datasources: { db: { url: ephemeral.databaseUrl } },
    });
    const seeded = await seedZeroFindingBaseline(prisma);
    baseline = {
      ...seeded,
      findingCount: await prisma.finding.count(),
      observationCount: await prisma.findingObservation.count(),
      vulnerabilityCount: await prisma.vulnerability.count(),
    };
  });

  beforeEach(async () => {
    await failInflightRuns();
  });

  afterAll(async () => {
    if (prisma !== undefined) {
      await prisma.$disconnect();
    }
    if (admin !== undefined && databaseName !== undefined) {
      await dropEphemeralDatabase(admin, databaseName);
    }
  });

  async function assertZeroFindingUnchanged() {
    expect(await prisma.finding.count()).toBe(baseline.findingCount);
    expect(await prisma.findingObservation.count()).toBe(baseline.observationCount);
    const finding = await prisma.finding.findUniqueOrThrow({
      where: { id: baseline.finding.id },
    });
    expect(finding.assetId).toBe(baseline.finding.assetId);
    expect(finding.vulnerabilityId).toBe(baseline.finding.vulnerabilityId);
    expect(finding.componentId).toBe(baseline.finding.componentId);
    const observation = await prisma.findingObservation.findUniqueOrThrow({
      where: { id: baseline.observation.id },
    });
    expect(observation.result).toBe(baseline.observation.result);
    expect(observation.method).toBe(baseline.observation.method);
    expect(await prisma.outboxEvent.count({ where: { eventType: 'finding.recalculate' } })).toBe(0);
    expect(await prisma.vulnerability.count()).toBe(baseline.vulnerabilityCount);
    expect(await prisma.vulnerability.count({ where: { cveId: { startsWith: 'CVE-' } } })).toBe(0);
    expect(await prisma.vulnerabilityAlias.count()).toBe(0);
    expect(await prisma.vulnerabilitySourceRecord.count()).toBe(0);
  }

  async function requestFetchingRun(dedupeKey = `dedupe-${randomUUID()}`) {
    await failInflightRuns();
    const adapters = createIntelligencePersistence(prisma);
    const syncRunId = randomUUID();
    const requested = requireOk(
      await adapters.unitOfWork.requestSync({
        provider: 'cisa_kev',
        sourceIdentifier: 'cisa_kev_json_catalog',
        syncRunId,
        requestedAt: NOW,
        correlationId: `corr-${syncRunId}`,
        parserVersion: KEV_PARSER_VERSION,
        normalizationVersion: KEV_NORMALIZATION_VERSION,
        dedupeKey,
      }),
      'requestSync',
    );
    expect(requested.outcome).toBe('created');
    const claimed = requireOk(
      await adapters.syncRuns.claimRequestedOrRetryWait({
        syncRunId: requested.syncRun.id,
        expectedState: 'requested',
        expectedVersion: requested.syncRun.version,
        claimedAt: NOW,
      }),
      'claim',
    );
    return { adapters, run: claimed };
  }

  async function storeAndParse(
    adapters: ReturnType<typeof createIntelligencePersistence>,
    runId: string,
    sha256: string,
  ) {
    const run = await adapters.syncRuns.findById(runId);
    if (run === undefined) {
      throw new Error('missing run');
    }
    const inserted = requireOk(
      await adapters.snapshots.insertOrReuse(snapshotRecord(run.id, sha256)),
      'insert snapshot',
    );
    const stored = requireOk(
      await adapters.syncRuns.recordSnapshotStored({
        syncRunId: run.id,
        expectedState: run.state,
        expectedVersion: run.version,
        command: { type: 'record_stored', snapshotId: inserted.record.id },
      }),
      'stored',
    );
    const parsing = requireOk(
      await adapters.syncRuns.recordParsing({
        syncRunId: stored.id,
        expectedState: stored.state,
        expectedVersion: stored.version,
        command: { type: 'start_parsing' },
      }),
      'parsing',
    );
    return { snapshot: inserted, parsing };
  }

  async function stageCompleteAndActivate(input: {
    adapters: ReturnType<typeof createIntelligencePersistence>;
    runId: string;
    snapshotId: string;
    cves: readonly string[];
    previousActiveGenerationId: string | null;
    expectedSourceVersion: number;
    backgroundJob?: { jobId: string; workerIdentifier: string };
    correlationId?: string;
  }) {
    const { adapters } = input;
    const generationId = randomUUID();
    const created = requireOk(
      await adapters.generations.createStagingGeneration({
        id: generationId,
        syncRunId: input.runId,
        snapshotId: input.snapshotId,
        provider: 'cisa_kev',
        sourceIdentifier: 'cisa_kev_json_catalog',
        expectedEntryCount: input.cves.length,
        parserVersion: KEV_PARSER_VERSION,
        normalizationVersion: KEV_NORMALIZATION_VERSION,
        createdAt: NOW,
      }),
      'create staging',
    );
    const run = await adapters.syncRuns.findById(input.runId);
    if (run === undefined) {
      throw new Error('missing run');
    }
    const staging = requireOk(
      await adapters.syncRuns.recordGenerationStaging({
        syncRunId: run.id,
        expectedState: run.state,
        expectedVersion: run.version,
        command: { type: 'start_staging', generationId: created.id },
      }),
      'start staging',
    );
    requireOk(
      await adapters.generations.stageBoundedEntryBatch({
        generationId: created.id,
        snapshotId: input.snapshotId,
        provider: 'cisa_kev',
        sourceIdentifier: 'cisa_kev_json_catalog',
        maxBatchSize: 16,
        entries: input.cves.map((normalizedCve, ordinal) =>
          syntheticKevEntry({
            generationId: created.id,
            snapshotId: input.snapshotId,
            ordinal,
            normalizedCve,
          }),
        ),
      }),
      'stage batch',
    );
    requireOk(
      await adapters.generations.markGenerationComplete({
        generationId: created.id,
        expectedEntryCount: input.cves.length,
        actualStagedDistinctCveCount: input.cves.length,
        parserVersion: KEV_PARSER_VERSION,
        normalizationVersion: KEV_NORMALIZATION_VERSION,
        catalogVersion: CATALOG_VERSION,
        catalogReleasedAt: NOW,
        completedAt: NOW,
      }),
      'complete generation',
    );
    const activating = requireOk(
      await adapters.syncRuns.recordActivationStarted({
        syncRunId: staging.id,
        expectedState: staging.state,
        expectedVersion: staging.version,
        command: { type: 'start_activating', generationComplete: true, warningCount: 0 },
      }),
      'start activating',
    );
    const activated = requireOk(
      await adapters.unitOfWork.activateCompleteGeneration({
        generationId: created.id,
        expectedEntryCount: input.cves.length,
        parserVersion: KEV_PARSER_VERSION,
        normalizationVersion: KEV_NORMALIZATION_VERSION,
        provider: 'cisa_kev',
        sourceIdentifier: 'cisa_kev_json_catalog',
        snapshotId: input.snapshotId,
        previousActiveGenerationId: input.previousActiveGenerationId,
        expectedSourceVersion: input.expectedSourceVersion,
        activatedAt: NOW,
        acceptedEntryCount: input.cves.length,
        warningCount: 0,
        correlationId: input.correlationId ?? `corr-act-${created.id}`,
        syncRunId: activating.id,
        expectedSyncRunState: 'activating',
        expectedSyncRunVersion: activating.version,
        ...(input.backgroundJob === undefined
          ? {}
          : {
              backgroundJob: {
                jobId: input.backgroundJob.jobId,
                workerIdentifier: input.backgroundJob.workerIdentifier,
                organizationId: null,
                jobType: 'intelligence.sync' as const,
              },
            }),
      }),
      'activate',
    );
    return { generation: created, activated };
  }

  it('keeps adapter sources free of HTTP, storage, Redis, BullMQ, and parser runtimes', async () => {
    const files = [
      'intelligence-persistence.ts',
      'intelligence-mappers.ts',
      'intelligence-test-fixture.ts',
    ];
    const banned =
      /ioredis|bullmq|@aws-sdk|S3Client|MinIO|worker_threads|parseKevCatalog|FindingRepository|FindingObservationRepository|ComponentRepository|https\.request|\bfetch\s*\(/;
    for (const file of files) {
      const source = readFileSync(path.join(packageSrc, file), 'utf8');
      expect(source, file).not.toMatch(banned);
      expect(source, file).not.toContain('process.env');
    }
    const ports = readFileSync(domainPorts, 'utf8');
    expect(ports).toContain('Inputs do not accept provider HTTP');
    expect(ports).toContain('object storage, Redis, BullMQ, or parser handles');
    expect(ports).not.toMatch(/ActivateKevGenerationInput[\s\S]{0,800}httpPort/);
    expect(ports).not.toContain('renewExecutionLease');
    await assertZeroFindingUnchanged();
  });

  it('creates a requested run with a system audit and outbox event, and rejects a duplicate inflight request', async () => {
    const adapters = createIntelligencePersistence(prisma);
    const syncRunId = randomUUID();
    const created = requireOk(
      await adapters.unitOfWork.requestSync({
        provider: 'cisa_kev',
        sourceIdentifier: 'cisa_kev_json_catalog',
        syncRunId,
        requestedAt: NOW,
        correlationId: `corr-${syncRunId}`,
        parserVersion: KEV_PARSER_VERSION,
        normalizationVersion: KEV_NORMALIZATION_VERSION,
        dedupeKey: `dedupe-${syncRunId}`,
      }),
      'first request',
    );
    expect(created.outcome).toBe('created');
    expect(created.syncRun.state).toBe('requested');
    expect(created.syncRun.parserVersion).toBe(KEV_PARSER_VERSION);
    const audits = await prisma.auditEvent.findMany({
      where: { action: 'intelligence.sync_requested', subjectId: syncRunId },
    });
    expect(audits).toHaveLength(1);
    expect(audits[0]?.actorType).toBe('system');
    expect(audits[0]?.organizationId).toBeNull();
    const outbox = await prisma.outboxEvent.findMany({
      where: { eventType: 'intelligence.sync.requested.v1', aggregateId: syncRunId },
    });
    expect(outbox).toHaveLength(1);
    expect(outbox[0]?.organizationId).toBeNull();
    const duplicate = requireOk(
      await adapters.unitOfWork.requestSync({
        provider: 'cisa_kev',
        sourceIdentifier: 'cisa_kev_json_catalog',
        syncRunId: randomUUID(),
        requestedAt: NOW,
        correlationId: `corr-${randomUUID()}`,
        parserVersion: KEV_PARSER_VERSION,
        normalizationVersion: KEV_NORMALIZATION_VERSION,
        dedupeKey: `dedupe-${randomUUID()}`,
      }),
      'duplicate request',
    );
    expect(duplicate.outcome).toBe('existing_inflight');
    expect(duplicate.syncRun.id).toBe(syncRunId);
    expect(
      await prisma.auditEvent.count({
        where: { action: 'intelligence.sync_requested' },
      }),
    ).toBe(1);
    await prisma.vulnerabilitySyncRun.update({
      where: { id: syncRunId },
      data: {
        state: 'failed',
        startedAt: NOW,
        completedAt: NOW,
        executionAttempt: 1,
        failureCategory: 'internal',
        failureCode: 'processing_failed',
      },
    });
    await assertZeroFindingUnchanged();
  });

  it('lets one concurrent scheduler request win', async () => {
    const adapters = createIntelligencePersistence(prisma);
    const firstId = randomUUID();
    const secondId = randomUUID();
    const [left, right] = await Promise.all([
      adapters.unitOfWork.requestSync({
        provider: 'cisa_kev',
        sourceIdentifier: 'cisa_kev_json_catalog',
        syncRunId: firstId,
        requestedAt: NOW,
        correlationId: `corr-${firstId}`,
        parserVersion: KEV_PARSER_VERSION,
        normalizationVersion: KEV_NORMALIZATION_VERSION,
        dedupeKey: `dedupe-concurrent-${firstId}`,
      }),
      adapters.unitOfWork.requestSync({
        provider: 'cisa_kev',
        sourceIdentifier: 'cisa_kev_json_catalog',
        syncRunId: secondId,
        requestedAt: NOW,
        correlationId: `corr-${secondId}`,
        parserVersion: KEV_PARSER_VERSION,
        normalizationVersion: KEV_NORMALIZATION_VERSION,
        dedupeKey: `dedupe-concurrent-${secondId}`,
      }),
    ]);
    const outcomes = [requireOk(left, 'left'), requireOk(right, 'right')];
    expect(outcomes.filter((item) => item.outcome === 'created')).toHaveLength(1);
    expect(outcomes.filter((item) => item.outcome === 'existing_inflight')).toHaveLength(1);
    const winner = outcomes.find((item) => item.outcome === 'created');
    if (winner === undefined) {
      throw new Error('missing winner');
    }
    expect(
      await prisma.auditEvent.count({
        where: { action: 'intelligence.sync_requested', subjectId: winner.syncRun.id },
      }),
    ).toBe(1);
    await prisma.vulnerabilitySyncRun.update({
      where: { id: winner.syncRun.id },
      data: {
        state: 'failed',
        startedAt: NOW,
        completedAt: NOW,
        executionAttempt: 1,
        failureCategory: 'internal',
        failureCode: 'processing_failed',
      },
    });
    await assertZeroFindingUnchanged();
  });

  it('rejects a SyncRun CAS race and a terminal reopen', async () => {
    const { adapters, run } = await requestFetchingRun();
    const [first, second] = await Promise.all([
      adapters.syncRuns.recordRetryWait({
        syncRunId: run.id,
        expectedState: 'fetching',
        expectedVersion: run.version,
        command: {
          type: 'record_retry_wait',
          nextAttemptAt: NOW,
          failureCode: 'connection_timeout',
        },
      }),
      adapters.syncRuns.recordRetryWait({
        syncRunId: run.id,
        expectedState: 'fetching',
        expectedVersion: run.version,
        command: {
          type: 'record_retry_wait',
          nextAttemptAt: NOW,
          failureCode: 'connection_timeout',
        },
      }),
    ]);
    const results = [first, second];
    expect(results.filter((item) => item.ok)).toHaveLength(1);
    expect(results.filter((item) => !item.ok)).toHaveLength(1);
    const winner = results.find((item) => item.ok);
    if (winner === undefined || !winner.ok) {
      throw new Error('CAS winner missing');
    }
    const reopen = await adapters.syncRuns.failRun({
      syncRunId: winner.value.id,
      expectedState: 'fetching',
      expectedVersion: winner.value.version,
      command: { type: 'fail', completedAt: NOW, failureCode: 'processing_failed' },
    });
    expect(reopen.ok).toBe(false);
    const failed = requireOk(
      await adapters.unitOfWork.failRun({
        syncRunId: winner.value.id,
        expectedState: 'retry_wait',
        expectedVersion: winner.value.version,
        completedAt: NOW,
        failureCode: 'processing_failed',
        correlationId: `corr-fail-${winner.value.id}`,
      }),
      'fail after retry',
    );
    expect(failed.state).toBe('failed');
    const terminalReopen = await adapters.syncRuns.claimRequestedOrRetryWait({
      syncRunId: failed.id,
      expectedState: 'requested',
      expectedVersion: failed.version,
      claimedAt: NOW,
    });
    expect(terminalReopen.ok).toBe(false);
    await assertZeroFindingUnchanged();
  });

  it('inserts a snapshot once, reuses it when parser version would change, and rejects mutation', async () => {
    const { adapters, run } = await requestFetchingRun();
    const sha = uniqueKevSha();
    const first = requireOk(
      await adapters.snapshots.insertOrReuse(snapshotRecord(run.id, sha)),
      'first snapshot',
    );
    expect(first.reused).toBe(false);
    const reused = requireOk(
      await adapters.snapshots.insertOrReuse(snapshotRecord(run.id, sha)),
      'reuse snapshot',
    );
    expect(reused.reused).toBe(true);
    expect(reused.record.id).toBe(first.record.id);
    await expect(
      prisma.vulnerabilityProviderSnapshot.update({
        where: { id: first.record.id },
        data: { byteLength: 9 },
      }),
    ).rejects.toThrow();
    await prisma.vulnerabilitySyncRun.update({
      where: { id: run.id },
      data: {
        state: 'failed',
        completedAt: NOW,
        failureCategory: 'internal',
        failureCode: 'processing_failed',
      },
    });
    await assertZeroFindingUnchanged();
  });

  it('stages a bounded batch atomically and inspects actual counts', async () => {
    const { adapters, run } = await requestFetchingRun();
    const { snapshot, parsing } = await storeAndParse(adapters, run.id, uniqueKevSha());
    const generationId = randomUUID();
    requireOk(
      await adapters.generations.createStagingGeneration({
        id: generationId,
        syncRunId: parsing.id,
        snapshotId: snapshot.record.id,
        provider: 'cisa_kev',
        sourceIdentifier: 'cisa_kev_json_catalog',
        expectedEntryCount: 2,
        parserVersion: KEV_PARSER_VERSION,
        normalizationVersion: KEV_NORMALIZATION_VERSION,
        createdAt: NOW,
      }),
      'staging gen',
    );
    const oversized = await adapters.generations.stageBoundedEntryBatch({
      generationId,
      snapshotId: snapshot.record.id,
      provider: 'cisa_kev',
      sourceIdentifier: 'cisa_kev_json_catalog',
      maxBatchSize: 1,
      entries: [
        syntheticKevEntry({
          generationId,
          snapshotId: snapshot.record.id,
          ordinal: 0,
          normalizedCve: 'CVE-2024-10001',
        }),
        syntheticKevEntry({
          generationId,
          snapshotId: snapshot.record.id,
          ordinal: 1,
          normalizedCve: 'CVE-2024-10002',
        }),
      ],
    });
    expect(oversized.ok).toBe(false);
    expect(await prisma.kevEntry.count({ where: { generationId } })).toBe(0);
    const first = requireOk(
      await adapters.generations.stageBoundedEntryBatch({
        generationId,
        snapshotId: snapshot.record.id,
        provider: 'cisa_kev',
        sourceIdentifier: 'cisa_kev_json_catalog',
        maxBatchSize: 2,
        entries: [
          syntheticKevEntry({
            generationId,
            snapshotId: snapshot.record.id,
            ordinal: 0,
            normalizedCve: 'CVE-2024-10001',
          }),
        ],
      }),
      'first batch',
    );
    expect(first.stagedEntryCount).toBe(1);
    const duplicate = await adapters.generations.stageBoundedEntryBatch({
      generationId,
      snapshotId: snapshot.record.id,
      provider: 'cisa_kev',
      sourceIdentifier: 'cisa_kev_json_catalog',
      maxBatchSize: 2,
      entries: [
        syntheticKevEntry({
          generationId,
          snapshotId: snapshot.record.id,
          ordinal: 1,
          normalizedCve: 'CVE-2024-10001',
        }),
      ],
    });
    expect(duplicate.ok).toBe(false);
    expect(await prisma.kevEntry.count({ where: { generationId } })).toBe(1);
    const second = requireOk(
      await adapters.generations.stageBoundedEntryBatch({
        generationId,
        snapshotId: snapshot.record.id,
        provider: 'cisa_kev',
        sourceIdentifier: 'cisa_kev_json_catalog',
        maxBatchSize: 2,
        entries: [
          syntheticKevEntry({
            generationId,
            snapshotId: snapshot.record.id,
            ordinal: 1,
            normalizedCve: 'CVE-2024-10002',
          }),
        ],
      }),
      'second batch',
    );
    expect(second.stagedEntryCount).toBe(2);
    const counts = await adapters.generations.inspectStagedCounts(generationId);
    expect(counts).toEqual({ stagedEntryCount: 2, distinctCveCount: 2 });
    requireOk(
      await adapters.generations.markGenerationComplete({
        generationId,
        expectedEntryCount: 2,
        actualStagedDistinctCveCount: 2,
        parserVersion: KEV_PARSER_VERSION,
        normalizationVersion: KEV_NORMALIZATION_VERSION,
        catalogVersion: CATALOG_VERSION,
        catalogReleasedAt: NOW,
        completedAt: NOW,
      }),
      'complete',
    );
    await prisma.vulnerabilitySyncRun.update({
      where: { id: parsing.id },
      data: {
        state: 'failed',
        completedAt: NOW,
        failureCategory: 'internal',
        failureCode: 'processing_failed',
      },
    });
    await assertZeroFindingUnchanged();
  });

  it('activates the first complete generation and replaces a prior active catalog', async () => {
    const first = await requestFetchingRun();
    const stored = await storeAndParse(first.adapters, first.run.id, uniqueKevSha());
    const source = await prisma.intelligenceSource.findUniqueOrThrow({
      where: { providerKey: 'cisa_kev' },
    });
    const activated = await stageCompleteAndActivate({
      adapters: first.adapters,
      runId: first.run.id,
      snapshotId: stored.snapshot.record.id,
      cves: ['CVE-2024-20001'],
      previousActiveGenerationId: null,
      expectedSourceVersion: source.version,
    });
    expect(activated.activated.outcome).toBe('activated');
    expect(activated.activated.generation.state).toBe('active');
    const kevUpdated = await prisma.auditEvent.findMany({
      where: { action: 'intelligence.kev_updated' },
    });
    expect(kevUpdated.length).toBeGreaterThan(0);
    expect(kevUpdated[kevUpdated.length - 1]?.subjectType).toBe('intelligence_source');
    expect(kevUpdated[kevUpdated.length - 1]?.subjectId).toBe(source.id);
    const second = await requestFetchingRun();
    const secondStored = await storeAndParse(second.adapters, second.run.id, uniqueKevSha());
    const sourceAfter = await prisma.intelligenceSource.findUniqueOrThrow({
      where: { providerKey: 'cisa_kev' },
    });
    const replaced = await stageCompleteAndActivate({
      adapters: second.adapters,
      runId: second.run.id,
      snapshotId: secondStored.snapshot.record.id,
      cves: ['CVE-2024-20002', 'CVE-2024-20003'],
      previousActiveGenerationId: activated.generation.id,
      expectedSourceVersion: sourceAfter.version,
    });
    expect(replaced.activated.outcome).toBe('activated');
    const previous = await prisma.kevGeneration.findUniqueOrThrow({
      where: { id: activated.generation.id },
    });
    expect(previous.state).toBe('superseded');
    const active = await second.adapters.generations.findActiveGeneration(
      'cisa_kev',
      'cisa_kev_json_catalog',
    );
    expect(active?.id).toBe(replaced.generation.id);
    const listed = await second.adapters.generations.listActiveEntries({
      provider: 'cisa_kev',
      sourceIdentifier: 'cisa_kev_json_catalog',
      limit: 10,
    });
    expect(listed.items.map((item) => item.normalizedCve)).toEqual([
      'CVE-2024-20002',
      'CVE-2024-20003',
    ]);
    await assertZeroFindingUnchanged();
  });

  it('rejects a stale previous pointer, incomplete activation, and an entry-count mismatch', async () => {
    const adapters = createIntelligencePersistence(prisma);
    const current = await adapters.generations.findActiveGeneration(
      'cisa_kev',
      'cisa_kev_json_catalog',
    );
    const source = await prisma.intelligenceSource.findUniqueOrThrow({
      where: { providerKey: 'cisa_kev' },
    });
    const fetching = await requestFetchingRun();
    const stored = await storeAndParse(fetching.adapters, fetching.run.id, uniqueKevSha());
    const generationId = randomUUID();
    requireOk(
      await fetching.adapters.generations.createStagingGeneration({
        id: generationId,
        syncRunId: fetching.run.id,
        snapshotId: stored.snapshot.record.id,
        provider: 'cisa_kev',
        sourceIdentifier: 'cisa_kev_json_catalog',
        expectedEntryCount: 1,
        parserVersion: KEV_PARSER_VERSION,
        normalizationVersion: KEV_NORMALIZATION_VERSION,
        createdAt: NOW,
      }),
      'incomplete gen',
    );
    const incomplete = await fetching.adapters.unitOfWork.activateCompleteGeneration({
      generationId,
      expectedEntryCount: 1,
      parserVersion: KEV_PARSER_VERSION,
      normalizationVersion: KEV_NORMALIZATION_VERSION,
      provider: 'cisa_kev',
      sourceIdentifier: 'cisa_kev_json_catalog',
      snapshotId: stored.snapshot.record.id,
      previousActiveGenerationId: current?.id ?? null,
      expectedSourceVersion: source.version,
      activatedAt: NOW,
      acceptedEntryCount: 1,
      warningCount: 0,
      correlationId: `corr-incomplete-${generationId}`,
      syncRunId: fetching.run.id,
      expectedSyncRunState: 'activating',
      expectedSyncRunVersion: fetching.run.version,
    });
    expect(incomplete.ok).toBe(false);
    await prisma.vulnerabilitySyncRun.update({
      where: { id: fetching.run.id },
      data: {
        state: 'failed',
        completedAt: NOW,
        failureCategory: 'internal',
        failureCode: 'processing_failed',
      },
    });

    const stale = await requestFetchingRun();
    const staleStored = await storeAndParse(stale.adapters, stale.run.id, uniqueKevSha());
    const staleAttempt = await stageCompleteAndActivate({
      adapters: stale.adapters,
      runId: stale.run.id,
      snapshotId: staleStored.snapshot.record.id,
      cves: ['CVE-2024-30001'],
      previousActiveGenerationId: null,
      expectedSourceVersion: source.version,
    }).catch((error: unknown) => error);
    expect(staleAttempt).toBeInstanceOf(Error);

    const mismatch = await requestFetchingRun();
    const mismatchStored = await storeAndParse(mismatch.adapters, mismatch.run.id, uniqueKevSha());
    const mismatchGen = randomUUID();
    requireOk(
      await mismatch.adapters.generations.createStagingGeneration({
        id: mismatchGen,
        syncRunId: mismatch.run.id,
        snapshotId: mismatchStored.snapshot.record.id,
        provider: 'cisa_kev',
        sourceIdentifier: 'cisa_kev_json_catalog',
        expectedEntryCount: 1,
        parserVersion: KEV_PARSER_VERSION,
        normalizationVersion: KEV_NORMALIZATION_VERSION,
        createdAt: NOW,
      }),
      'mismatch gen',
    );
    const mismatchRun = await mismatch.adapters.syncRuns.findById(mismatch.run.id);
    if (mismatchRun === undefined) {
      throw new Error('missing mismatch run');
    }
    requireOk(
      await mismatch.adapters.syncRuns.recordGenerationStaging({
        syncRunId: mismatchRun.id,
        expectedState: mismatchRun.state,
        expectedVersion: mismatchRun.version,
        command: { type: 'start_staging', generationId: mismatchGen },
      }),
      'mismatch staging',
    );
    requireOk(
      await mismatch.adapters.generations.stageBoundedEntryBatch({
        generationId: mismatchGen,
        snapshotId: mismatchStored.snapshot.record.id,
        provider: 'cisa_kev',
        sourceIdentifier: 'cisa_kev_json_catalog',
        maxBatchSize: 2,
        entries: [
          syntheticKevEntry({
            generationId: mismatchGen,
            snapshotId: mismatchStored.snapshot.record.id,
            ordinal: 0,
            normalizedCve: 'CVE-2024-30002',
          }),
        ],
      }),
      'mismatch stage',
    );
    requireOk(
      await mismatch.adapters.generations.markGenerationComplete({
        generationId: mismatchGen,
        expectedEntryCount: 1,
        actualStagedDistinctCveCount: 1,
        parserVersion: KEV_PARSER_VERSION,
        normalizationVersion: KEV_NORMALIZATION_VERSION,
        catalogVersion: CATALOG_VERSION,
        catalogReleasedAt: NOW,
        completedAt: NOW,
      }),
      'mismatch complete',
    );
    await prisma.kevEntry.create({
      data: {
        generationId: mismatchGen,
        ordinal: 1,
        normalizedCve: 'CVE-2024-30003',
        vendorProject: 'Vendor',
        product: 'Product',
        vulnerabilityName: 'Name',
        dateAdded: '2024-01-15',
        shortDescription: 'desc',
        requiredAction: 'patch',
        dueDate: '2024-02-15',
        knownRansomwareCampaignUse: 'unknown',
      },
    });
    const stagingRun = await mismatch.adapters.syncRuns.findById(mismatch.run.id);
    if (stagingRun === undefined) {
      throw new Error('missing staging run');
    }
    const activating = requireOk(
      await mismatch.adapters.syncRuns.recordActivationStarted({
        syncRunId: stagingRun.id,
        expectedState: stagingRun.state,
        expectedVersion: stagingRun.version,
        command: { type: 'start_activating', generationComplete: true, warningCount: 0 },
      }),
      'mismatch activating',
    );
    const sourceNow = await prisma.intelligenceSource.findUniqueOrThrow({
      where: { providerKey: 'cisa_kev' },
    });
    const counted = await mismatch.adapters.unitOfWork.activateCompleteGeneration({
      generationId: mismatchGen,
      expectedEntryCount: 1,
      parserVersion: KEV_PARSER_VERSION,
      normalizationVersion: KEV_NORMALIZATION_VERSION,
      provider: 'cisa_kev',
      sourceIdentifier: 'cisa_kev_json_catalog',
      snapshotId: mismatchStored.snapshot.record.id,
      previousActiveGenerationId: sourceNow.activeGenerationId,
      expectedSourceVersion: sourceNow.version,
      activatedAt: NOW,
      acceptedEntryCount: 1,
      warningCount: 0,
      correlationId: `corr-mismatch-${mismatchGen}`,
      syncRunId: activating.id,
      expectedSyncRunState: 'activating',
      expectedSyncRunVersion: activating.version,
    });
    expect(counted.ok).toBe(false);
    expect(sourceNow.activeGenerationId).toBe(
      (
        await prisma.intelligenceSource.findUniqueOrThrow({
          where: { providerKey: 'cisa_kev' },
        })
      ).activeGenerationId,
    );
    await prisma.vulnerabilitySyncRun.update({
      where: { id: mismatch.run.id },
      data: {
        state: 'failed',
        completedAt: NOW,
        failureCategory: 'internal',
        failureCode: 'processing_failed',
      },
    });
    await assertZeroFindingUnchanged();
  });

  it('rolls back activation when audit insert fails and when job ownership does not match', async () => {
    const sourceBefore = await prisma.intelligenceSource.findUniqueOrThrow({
      where: { providerKey: 'cisa_kev' },
    });
    const fetching = await requestFetchingRun();
    const stored = await storeAndParse(fetching.adapters, fetching.run.id, uniqueKevSha());
    const correlationId = 'fail-kev-audit';
    await prisma.$executeRaw`
      CREATE OR REPLACE FUNCTION patchpilot_test_fail_kev_audit()
      RETURNS trigger
      LANGUAGE plpgsql
      SET search_path = pg_catalog, public
      AS $$
      BEGIN
        IF NEW.correlation_id = 'fail-kev-audit' THEN
          RAISE EXCEPTION 'forced audit failure';
        END IF;
        RETURN NEW;
      END;
      $$
    `;
    await prisma.$executeRaw`
      CREATE TRIGGER patchpilot_test_fail_kev_audit
      BEFORE INSERT ON audit_event
      FOR EACH ROW
      EXECUTE FUNCTION patchpilot_test_fail_kev_audit()
    `;
    try {
      await expect(
        stageCompleteAndActivate({
          adapters: fetching.adapters,
          runId: fetching.run.id,
          snapshotId: stored.snapshot.record.id,
          cves: ['CVE-2024-40001'],
          previousActiveGenerationId: sourceBefore.activeGenerationId,
          expectedSourceVersion: sourceBefore.version,
          correlationId,
        }),
      ).rejects.toThrow(/forced audit failure/);
      const sourceAfter = await prisma.intelligenceSource.findUniqueOrThrow({
        where: { providerKey: 'cisa_kev' },
      });
      expect(sourceAfter.activeGenerationId).toBe(sourceBefore.activeGenerationId);
      expect(sourceAfter.version).toBe(sourceBefore.version);
    } finally {
      await prisma.$executeRaw`DROP TRIGGER IF EXISTS patchpilot_test_fail_kev_audit ON audit_event`;
      await prisma.$executeRaw`DROP FUNCTION IF EXISTS patchpilot_test_fail_kev_audit()`;
    }
    await prisma.vulnerabilitySyncRun.update({
      where: { id: fetching.run.id },
      data: {
        state: 'failed',
        completedAt: NOW,
        failureCategory: 'internal',
        failureCode: 'processing_failed',
      },
    });

    const jobRun = await requestFetchingRun();
    const jobStored = await storeAndParse(jobRun.adapters, jobRun.run.id, uniqueKevSha());
    const job = await prisma.backgroundJob.create({
      data: {
        organizationId: null,
        jobType: 'intelligence.sync',
        status: 'running',
        workerIdentifier: 'worker-a',
        startedAt: NOW,
        leaseExpiresAt: new Date(NOW.getTime() + 60_000),
      },
    });
    const sourceNow = await prisma.intelligenceSource.findUniqueOrThrow({
      where: { providerKey: 'cisa_kev' },
    });
    await expect(
      stageCompleteAndActivate({
        adapters: jobRun.adapters,
        runId: jobRun.run.id,
        snapshotId: jobStored.snapshot.record.id,
        cves: ['CVE-2024-40002'],
        previousActiveGenerationId: sourceNow.activeGenerationId,
        expectedSourceVersion: sourceNow.version,
        backgroundJob: { jobId: job.id, workerIdentifier: 'worker-b' },
      }),
    ).rejects.toThrow();
    const pointer = await prisma.intelligenceSource.findUniqueOrThrow({
      where: { providerKey: 'cisa_kev' },
    });
    expect(pointer.activeGenerationId).toBe(sourceNow.activeGenerationId);
    expect(pointer.version).toBe(sourceNow.version);
    await prisma.vulnerabilitySyncRun.update({
      where: { id: jobRun.run.id },
      data: {
        state: 'failed',
        completedAt: NOW,
        failureCategory: 'internal',
        failureCode: 'processing_failed',
      },
    });
    await assertZeroFindingUnchanged();
  });

  it('replays a completed activation idempotently and fails a partial active-without-completed run', async () => {
    const source = await prisma.intelligenceSource.findUniqueOrThrow({
      where: { providerKey: 'cisa_kev' },
    });
    const fetching = await requestFetchingRun();
    const stored = await storeAndParse(fetching.adapters, fetching.run.id, uniqueKevSha());
    const first = await stageCompleteAndActivate({
      adapters: fetching.adapters,
      runId: fetching.run.id,
      snapshotId: stored.snapshot.record.id,
      cves: ['CVE-2024-50001'],
      previousActiveGenerationId: source.activeGenerationId,
      expectedSourceVersion: source.version,
    });
    const auditCount = await prisma.auditEvent.count({
      where: { action: 'intelligence.kev_updated' },
    });
    const replay = requireOk(
      await fetching.adapters.unitOfWork.activateCompleteGeneration({
        generationId: first.generation.id,
        expectedEntryCount: 1,
        parserVersion: KEV_PARSER_VERSION,
        normalizationVersion: KEV_NORMALIZATION_VERSION,
        provider: 'cisa_kev',
        sourceIdentifier: 'cisa_kev_json_catalog',
        snapshotId: stored.snapshot.record.id,
        previousActiveGenerationId: first.activated.generation.id,
        expectedSourceVersion: (
          await prisma.intelligenceSource.findUniqueOrThrow({
            where: { providerKey: 'cisa_kev' },
          })
        ).version,
        activatedAt: NOW,
        acceptedEntryCount: 1,
        warningCount: 0,
        correlationId: `corr-replay-${first.generation.id}`,
        syncRunId: first.activated.syncRun.id,
        expectedSyncRunState: 'activating',
        expectedSyncRunVersion: first.activated.syncRun.version,
      }),
      'replay',
    );
    expect(replay.outcome).toBe('idempotent_replay');
    expect(await prisma.auditEvent.count({ where: { action: 'intelligence.kev_updated' } })).toBe(
      auditCount,
    );

    const partial = await requestFetchingRun();
    const active = await partial.adapters.generations.findActiveGeneration(
      'cisa_kev',
      'cisa_kev_json_catalog',
    );
    if (active === undefined) {
      throw new Error('expected an active generation');
    }
    const partialResult = await partial.adapters.unitOfWork.activateCompleteGeneration({
      generationId: active.id,
      expectedEntryCount: active.expectedEntryCount,
      parserVersion: KEV_PARSER_VERSION,
      normalizationVersion: KEV_NORMALIZATION_VERSION,
      provider: 'cisa_kev',
      sourceIdentifier: 'cisa_kev_json_catalog',
      snapshotId: active.snapshotId,
      previousActiveGenerationId: active.id,
      expectedSourceVersion: (
        await prisma.intelligenceSource.findUniqueOrThrow({
          where: { providerKey: 'cisa_kev' },
        })
      ).version,
      activatedAt: NOW,
      acceptedEntryCount: active.expectedEntryCount,
      warningCount: 0,
      correlationId: `corr-partial-${partial.run.id}`,
      syncRunId: partial.run.id,
      expectedSyncRunState: 'activating',
      expectedSyncRunVersion: partial.run.version,
    });
    expect(partialResult.ok).toBe(false);
    const stillRunning = await prisma.vulnerabilitySyncRun.findUniqueOrThrow({
      where: { id: partial.run.id },
    });
    expect(stillRunning.state).not.toBe('completed');
    await prisma.vulnerabilitySyncRun.update({
      where: { id: partial.run.id },
      data: {
        state: 'failed',
        completedAt: NOW,
        failureCategory: 'internal',
        failureCode: 'processing_failed',
      },
    });
    await assertZeroFindingUnchanged();
  });

  it('pages active entries by ordinal and id and hides non-active generations', async () => {
    const source = await prisma.intelligenceSource.findUniqueOrThrow({
      where: { providerKey: 'cisa_kev' },
    });
    const fetching = await requestFetchingRun();
    const stored = await storeAndParse(fetching.adapters, fetching.run.id, uniqueKevSha());
    await stageCompleteAndActivate({
      adapters: fetching.adapters,
      runId: fetching.run.id,
      snapshotId: stored.snapshot.record.id,
      cves: ['CVE-2024-70001', 'CVE-2024-70002', 'CVE-2024-70003'],
      previousActiveGenerationId: source.activeGenerationId,
      expectedSourceVersion: source.version,
    });
    const adapters = createIntelligencePersistence(prisma);
    const page = await adapters.generations.listActiveEntries({
      provider: 'cisa_kev',
      sourceIdentifier: 'cisa_kev_json_catalog',
      limit: 1,
    });
    expect(page.items).toHaveLength(1);
    expect(page.nextOrdinal).not.toBeNull();
    const next = await adapters.generations.listActiveEntries({
      provider: 'cisa_kev',
      sourceIdentifier: 'cisa_kev_json_catalog',
      limit: 1,
      ...(page.nextOrdinal === null || page.nextId === null
        ? {}
        : { afterOrdinal: page.nextOrdinal, afterId: page.nextId }),
    });
    expect(next.items).toHaveLength(1);
    expect(next.items[0]?.normalizedCve).not.toBe(page.items[0]?.normalizedCve);
    const hidden = await prisma.kevEntry.findMany({
      where: { generation: { state: { in: ['staging', 'complete', 'superseded', 'abandoned'] } } },
      take: 1,
    });
    expect(hidden.length).toBeGreaterThan(0);
    expect(
      page.items.some((item) => item.generationId === hidden[0]?.generationId) ||
        next.items.some((item) => item.generationId === hidden[0]?.generationId),
    ).toBe(false);
    await assertZeroFindingUnchanged();
  });

  it('preserves the active pointer on not-modified and advances freshness only then', async () => {
    const adapters = createIntelligencePersistence(prisma);
    const sourceBefore = await prisma.intelligenceSource.findUniqueOrThrow({
      where: { providerKey: 'cisa_kev' },
    });
    expect(sourceBefore.activeGenerationId).not.toBeNull();
    const fetching = await requestFetchingRun();
    const later = new Date('2026-09-01T13:00:00.000Z');
    const notModified = requireOk(
      await adapters.unitOfWork.completeNotModified({
        syncRunId: fetching.run.id,
        expectedState: 'fetching',
        expectedVersion: fetching.run.version,
        completedAt: later,
        reason: 'content_sha256_unchanged',
        priorAcceptedGenerationId: sourceBefore.activeGenerationId ?? '',
        correlationId: `corr-notmod-${fetching.run.id}`,
      }),
      'not modified',
    );
    expect(notModified.state).toBe('not_modified');
    const sourceAfter = await prisma.intelligenceSource.findUniqueOrThrow({
      where: { providerKey: 'cisa_kev' },
    });
    expect(sourceAfter.activeGenerationId).toBe(sourceBefore.activeGenerationId);
    expect(sourceAfter.lastSuccessfulSyncAt?.toISOString()).toBe(later.toISOString());
    expect(sourceAfter.lastAttemptAt?.toISOString()).toBe(later.toISOString());

    const failing = await requestFetchingRun();
    const failedAt = new Date('2026-09-01T14:00:00.000Z');
    requireOk(
      await adapters.unitOfWork.failRun({
        syncRunId: failing.run.id,
        expectedState: 'fetching',
        expectedVersion: failing.run.version,
        completedAt: failedAt,
        failureCode: 'processing_failed',
        correlationId: `corr-failed-${failing.run.id}`,
      }),
      'fail',
    );
    const afterFail = await prisma.intelligenceSource.findUniqueOrThrow({
      where: { providerKey: 'cisa_kev' },
    });
    expect(afterFail.lastSuccessfulSyncAt?.toISOString()).toBe(later.toISOString());
    expect(afterFail.activeGenerationId).toBe(sourceBefore.activeGenerationId);
    expect(afterFail.lastFailureCode).toBe('processing_failed');

    const recovered = await requestFetchingRun();
    const recoveredAt = new Date('2026-09-01T14:30:00.000Z');
    requireOk(
      await adapters.unitOfWork.completeNotModified({
        syncRunId: recovered.run.id,
        expectedState: 'fetching',
        expectedVersion: recovered.run.version,
        completedAt: recoveredAt,
        reason: 'content_sha256_unchanged',
        priorAcceptedGenerationId: afterFail.activeGenerationId ?? '',
        correlationId: `corr-notmod-after-fail-${recovered.run.id}`,
      }),
      'not modified after failure',
    );
    const afterRecovery = await prisma.intelligenceSource.findUniqueOrThrow({
      where: { providerKey: 'cisa_kev' },
    });
    expect(afterRecovery.lastSuccessfulSyncAt?.toISOString()).toBe(recoveredAt.toISOString());
    expect(afterRecovery.lastFailureCode).toBe('processing_failed');
    expect(afterRecovery.activeGenerationId).toBe(sourceBefore.activeGenerationId);

    const quarantining = await requestFetchingRun();
    requireOk(
      await adapters.unitOfWork.quarantineRun({
        syncRunId: quarantining.run.id,
        expectedState: 'fetching',
        expectedVersion: quarantining.run.version,
        completedAt: new Date('2026-09-01T15:00:00.000Z'),
        failureCode: 'schema_invalid',
        correlationId: `corr-quar-${quarantining.run.id}`,
      }),
      'quarantine',
    );
    const afterQuarantine = await prisma.intelligenceSource.findUniqueOrThrow({
      where: { providerKey: 'cisa_kev' },
    });
    expect(afterQuarantine.lastSuccessfulSyncAt?.toISOString()).toBe(recoveredAt.toISOString());
    await assertZeroFindingUnchanged();
  });

  it('derives disabled, deferred, never-synchronized, current, and stale health without exposing snapshot internals', async () => {
    const adapters = createIntelligencePersistence(prisma);
    const disabled = await adapters.freshness.loadCurrentProviderStatus(
      'cisa_kev',
      'cisa_kev_json_catalog',
      NOW,
    );
    expect(disabled.implementationStatus).toBe('disabled');
    expect(
      deriveIntelligenceProviderHealthStatus({
        provider: 'cisa_kev',
        implementationStatus: disabled.implementationStatus,
        lastSuccessfulSyncAt: disabled.lastSuccessfulSyncAt,
        staleThresholdSeconds: disabled.staleThresholdSeconds,
        now: NOW,
      }),
    ).toEqual({ healthStatus: 'disabled', stale: false });
    expect(disabled).not.toHaveProperty('objectKey');
    expect(disabled).not.toHaveProperty('etag');
    expect(disabled).not.toHaveProperty('etagHash');
    expect(disabled).not.toHaveProperty('sourceUrl');

    const osv = await adapters.freshness.loadCurrentProviderStatus(
      'osv',
      'cisa_kev_json_catalog',
      NOW,
    );
    expect(
      deriveIntelligenceProviderHealthStatus({
        provider: 'osv',
        implementationStatus: osv.implementationStatus,
        lastSuccessfulSyncAt: osv.lastSuccessfulSyncAt,
        staleThresholdSeconds: osv.staleThresholdSeconds,
        now: NOW,
      }),
    ).toEqual({ healthStatus: 'deferred', stale: false });

    await prisma.intelligenceSource.update({
      where: { providerKey: 'cisa_kev' },
      data: { state: 'enabled' },
    });
    const enabled = await adapters.freshness.loadCurrentProviderStatus(
      'cisa_kev',
      'cisa_kev_json_catalog',
      NOW,
    );
    expect(enabled.staleThresholdSeconds).toBe(INTELLIGENCE_KEV_STALE_THRESHOLD_SECONDS_DEFAULT);
    expect(enabled.lastSuccessfulSyncAt).not.toBeNull();
    expect(
      deriveIntelligenceProviderHealthStatus({
        provider: 'cisa_kev',
        implementationStatus: enabled.implementationStatus,
        lastSuccessfulSyncAt: enabled.lastSuccessfulSyncAt,
        staleThresholdSeconds: enabled.staleThresholdSeconds,
        now: NOW,
      }).healthStatus,
    ).toBe('current');
    const lastSuccessfulSyncAt = enabled.lastSuccessfulSyncAt;
    if (lastSuccessfulSyncAt === null) {
      throw new Error('expected lastSuccessfulSyncAt after an accepted KEV catalog');
    }
    const staleNow = new Date(
      lastSuccessfulSyncAt.getTime() +
        (INTELLIGENCE_KEV_STALE_THRESHOLD_SECONDS_DEFAULT + 1) * 1000,
    );
    expect(
      deriveIntelligenceProviderHealthStatus({
        provider: 'cisa_kev',
        implementationStatus: enabled.implementationStatus,
        lastSuccessfulSyncAt: enabled.lastSuccessfulSyncAt,
        staleThresholdSeconds: enabled.staleThresholdSeconds,
        now: staleNow,
      }),
    ).toEqual({ healthStatus: 'stale', stale: true });
    await prisma.intelligenceSource.update({
      where: { providerKey: 'cisa_kev' },
      data: { state: 'disabled' },
    });
    await assertZeroFindingUnchanged();
  });

  it('lets one of two activation contenders win', async () => {
    const source = await prisma.intelligenceSource.findUniqueOrThrow({
      where: { providerKey: 'cisa_kev' },
    });
    const fetching = await requestFetchingRun();
    const stored = await storeAndParse(fetching.adapters, fetching.run.id, uniqueKevSha());
    const generationId = randomUUID();
    requireOk(
      await fetching.adapters.generations.createStagingGeneration({
        id: generationId,
        syncRunId: fetching.run.id,
        snapshotId: stored.snapshot.record.id,
        provider: 'cisa_kev',
        sourceIdentifier: 'cisa_kev_json_catalog',
        expectedEntryCount: 1,
        parserVersion: KEV_PARSER_VERSION,
        normalizationVersion: KEV_NORMALIZATION_VERSION,
        createdAt: NOW,
      }),
      'contender gen',
    );
    const run = await fetching.adapters.syncRuns.findById(fetching.run.id);
    if (run === undefined) {
      throw new Error('missing run');
    }
    const staging = requireOk(
      await fetching.adapters.syncRuns.recordGenerationStaging({
        syncRunId: run.id,
        expectedState: run.state,
        expectedVersion: run.version,
        command: { type: 'start_staging', generationId },
      }),
      'contender staging',
    );
    requireOk(
      await fetching.adapters.generations.stageBoundedEntryBatch({
        generationId,
        snapshotId: stored.snapshot.record.id,
        provider: 'cisa_kev',
        sourceIdentifier: 'cisa_kev_json_catalog',
        maxBatchSize: 1,
        entries: [
          syntheticKevEntry({
            generationId,
            snapshotId: stored.snapshot.record.id,
            ordinal: 0,
            normalizedCve: 'CVE-2024-60001',
          }),
        ],
      }),
      'contender stage',
    );
    requireOk(
      await fetching.adapters.generations.markGenerationComplete({
        generationId,
        expectedEntryCount: 1,
        actualStagedDistinctCveCount: 1,
        parserVersion: KEV_PARSER_VERSION,
        normalizationVersion: KEV_NORMALIZATION_VERSION,
        catalogVersion: CATALOG_VERSION,
        catalogReleasedAt: NOW,
        completedAt: NOW,
      }),
      'contender complete',
    );
    const activating = requireOk(
      await fetching.adapters.syncRuns.recordActivationStarted({
        syncRunId: staging.id,
        expectedState: staging.state,
        expectedVersion: staging.version,
        command: { type: 'start_activating', generationComplete: true, warningCount: 0 },
      }),
      'contender activating',
    );
    const input = {
      generationId,
      expectedEntryCount: 1,
      parserVersion: KEV_PARSER_VERSION,
      normalizationVersion: KEV_NORMALIZATION_VERSION,
      provider: 'cisa_kev' as const,
      sourceIdentifier: 'cisa_kev_json_catalog' as const,
      snapshotId: stored.snapshot.record.id,
      previousActiveGenerationId: source.activeGenerationId,
      expectedSourceVersion: source.version,
      activatedAt: NOW,
      acceptedEntryCount: 1,
      warningCount: 0,
      correlationId: `corr-contender-${generationId}`,
      syncRunId: activating.id,
      expectedSyncRunState: 'activating' as const,
      expectedSyncRunVersion: activating.version,
    };
    const [left, right] = await Promise.all([
      fetching.adapters.unitOfWork.activateCompleteGeneration(input),
      fetching.adapters.unitOfWork.activateCompleteGeneration(input),
    ]);
    const outcomes = [left, right].flatMap((item) => (item.ok ? [item.value.outcome] : []));
    expect(outcomes).toContain('activated');
    expect(
      outcomes.filter((item) => item === 'activated' || item === 'idempotent_replay'),
    ).toHaveLength(2);
    await assertZeroFindingUnchanged();
  });

  it('refuses completeRun and replay when the generation was never activated', async () => {
    const sourceBefore = await prisma.intelligenceSource.findUniqueOrThrow({
      where: { providerKey: 'cisa_kev' },
    });
    const { adapters, run } = await requestFetchingRun();
    const stored = await storeAndParse(adapters, run.id, uniqueKevSha());
    const generationId = randomUUID();
    requireOk(
      await adapters.generations.createStagingGeneration({
        id: generationId,
        syncRunId: run.id,
        snapshotId: stored.snapshot.record.id,
        provider: 'cisa_kev',
        sourceIdentifier: 'cisa_kev_json_catalog',
        expectedEntryCount: 1,
        parserVersion: KEV_PARSER_VERSION,
        normalizationVersion: KEV_NORMALIZATION_VERSION,
        createdAt: NOW,
      }),
      'unactivated gen',
    );
    const staging = requireOk(
      await adapters.syncRuns.recordGenerationStaging({
        syncRunId: run.id,
        expectedState: stored.parsing.state,
        expectedVersion: stored.parsing.version,
        command: { type: 'start_staging', generationId },
      }),
      'unactivated staging',
    );
    requireOk(
      await adapters.generations.stageBoundedEntryBatch({
        generationId,
        snapshotId: stored.snapshot.record.id,
        provider: 'cisa_kev',
        sourceIdentifier: 'cisa_kev_json_catalog',
        maxBatchSize: 1,
        entries: [
          syntheticKevEntry({
            generationId,
            snapshotId: stored.snapshot.record.id,
            ordinal: 0,
            normalizedCve: 'CVE-2024-70001',
          }),
        ],
      }),
      'unactivated stage',
    );
    requireOk(
      await adapters.generations.markGenerationComplete({
        generationId,
        expectedEntryCount: 1,
        actualStagedDistinctCveCount: 1,
        parserVersion: KEV_PARSER_VERSION,
        normalizationVersion: KEV_NORMALIZATION_VERSION,
        catalogVersion: CATALOG_VERSION,
        catalogReleasedAt: NOW,
        completedAt: NOW,
      }),
      'unactivated complete',
    );
    const activating = requireOk(
      await adapters.syncRuns.recordActivationStarted({
        syncRunId: staging.id,
        expectedState: staging.state,
        expectedVersion: staging.version,
        command: { type: 'start_activating', generationComplete: true, warningCount: 0 },
      }),
      'unactivated activating',
    );
    const completed = await adapters.syncRuns.completeRun({
      syncRunId: activating.id,
      expectedState: 'activating',
      expectedVersion: activating.version,
      command: {
        type: 'complete',
        completedAt: NOW,
        acceptedEntryCount: 1,
        warningCount: 0,
      },
    });
    expect(completed.ok).toBe(false);
    const stillActivating = await prisma.vulnerabilitySyncRun.findUniqueOrThrow({
      where: { id: run.id },
    });
    expect(stillActivating.state).toBe('activating');
    await prisma.vulnerabilitySyncRun.update({
      where: { id: run.id },
      data: {
        state: 'completed',
        stage: 'finalize',
        completedAt: NOW,
        acceptedEntryCount: 1,
        warningCount: 0,
      },
    });
    const replay = await adapters.unitOfWork.activateCompleteGeneration({
      generationId,
      expectedEntryCount: 1,
      parserVersion: KEV_PARSER_VERSION,
      normalizationVersion: KEV_NORMALIZATION_VERSION,
      provider: 'cisa_kev',
      sourceIdentifier: 'cisa_kev_json_catalog',
      snapshotId: stored.snapshot.record.id,
      previousActiveGenerationId: sourceBefore.activeGenerationId,
      expectedSourceVersion: sourceBefore.version,
      activatedAt: NOW,
      acceptedEntryCount: 1,
      warningCount: 0,
      correlationId: `corr-unactivated-${generationId}`,
      syncRunId: run.id,
      expectedSyncRunState: 'activating',
      expectedSyncRunVersion: activating.version,
    });
    expect(replay.ok).toBe(false);
    if (!replay.ok) {
      expect(replay.error).toEqual(INTELLIGENCE_PARTIAL_ACTIVATION_INCONSISTENT);
    }
    const sourceAfter = await prisma.intelligenceSource.findUniqueOrThrow({
      where: { providerKey: 'cisa_kev' },
    });
    expect(sourceAfter.activeGenerationId).toBe(sourceBefore.activeGenerationId);
    await assertZeroFindingUnchanged();
  });

  it('refuses standalone supersede of the active pointer', async () => {
    const adapters = createIntelligencePersistence(prisma);
    const active = await adapters.generations.findActiveGeneration(
      'cisa_kev',
      'cisa_kev_json_catalog',
    );
    if (active === undefined) {
      throw new Error('expected an active generation');
    }
    const result = await adapters.generations.markGenerationSuperseded(active.id, NOW);
    expect(result.ok).toBe(false);
    const still = await adapters.generations.findActiveGeneration(
      'cisa_kev',
      'cisa_kev_json_catalog',
    );
    expect(still?.id).toBe(active.id);
    await assertZeroFindingUnchanged();
  });

  it('serializes staging against complete and can abandon a never-activated complete generation', async () => {
    const { adapters, run } = await requestFetchingRun();
    const stored = await storeAndParse(adapters, run.id, uniqueKevSha());
    const generationId = randomUUID();
    requireOk(
      await adapters.generations.createStagingGeneration({
        id: generationId,
        syncRunId: run.id,
        snapshotId: stored.snapshot.record.id,
        provider: 'cisa_kev',
        sourceIdentifier: 'cisa_kev_json_catalog',
        expectedEntryCount: 1,
        parserVersion: KEV_PARSER_VERSION,
        normalizationVersion: KEV_NORMALIZATION_VERSION,
        createdAt: NOW,
      }),
      'race gen',
    );
    requireOk(
      await adapters.syncRuns.recordGenerationStaging({
        syncRunId: run.id,
        expectedState: stored.parsing.state,
        expectedVersion: stored.parsing.version,
        command: { type: 'start_staging', generationId },
      }),
      'race staging',
    );
    requireOk(
      await adapters.generations.stageBoundedEntryBatch({
        generationId,
        snapshotId: stored.snapshot.record.id,
        provider: 'cisa_kev',
        sourceIdentifier: 'cisa_kev_json_catalog',
        maxBatchSize: 1,
        entries: [
          syntheticKevEntry({
            generationId,
            snapshotId: stored.snapshot.record.id,
            ordinal: 0,
            normalizedCve: 'CVE-2024-80001',
          }),
        ],
      }),
      'race first entry',
    );
    const extra = syntheticKevEntry({
      generationId,
      snapshotId: stored.snapshot.record.id,
      ordinal: 1,
      normalizedCve: 'CVE-2024-80002',
    });
    const [stageResult, completeResult] = await Promise.all([
      adapters.generations.stageBoundedEntryBatch({
        generationId,
        snapshotId: stored.snapshot.record.id,
        provider: 'cisa_kev',
        sourceIdentifier: 'cisa_kev_json_catalog',
        maxBatchSize: 1,
        entries: [extra],
      }),
      adapters.generations.markGenerationComplete({
        generationId,
        expectedEntryCount: 1,
        actualStagedDistinctCveCount: 1,
        parserVersion: KEV_PARSER_VERSION,
        normalizationVersion: KEV_NORMALIZATION_VERSION,
        catalogVersion: CATALOG_VERSION,
        catalogReleasedAt: NOW,
        completedAt: NOW,
      }),
    ]);
    const generation = await prisma.kevGeneration.findUniqueOrThrow({
      where: { id: generationId },
    });
    const count = await prisma.kevEntry.count({ where: { generationId } });
    if (generation.state === 'complete') {
      expect(completeResult.ok).toBe(true);
      expect(count).toBe(1);
    } else {
      expect(generation.state).toBe('staging');
      expect(count).toBeLessThanOrEqual(2);
      if (count !== 1) {
        expect(completeResult.ok).toBe(false);
      }
    }
    expect(stageResult.ok || completeResult.ok).toBe(true);
    if (generation.state === 'complete') {
      const abandoned = requireOk(
        await adapters.generations.abandonIncompleteGeneration({
          generationId,
          expectedState: 'complete',
          abandonedAt: NOW,
        }),
        'abandon complete',
      );
      expect(abandoned.state).toBe('abandoned');
    } else {
      const abandoned = requireOk(
        await adapters.generations.abandonIncompleteGeneration({
          generationId,
          expectedState: 'staging',
          abandonedAt: NOW,
        }),
        'abandon staging after race',
      );
      expect(abandoned.state).toBe('abandoned');
    }
    await prisma.vulnerabilitySyncRun.update({
      where: { id: run.id },
      data: {
        state: 'failed',
        completedAt: NOW,
        failureCategory: 'internal',
        failureCode: 'processing_failed',
      },
    });
    await assertZeroFindingUnchanged();
  });

  it('claims fetching, stores snapshot metadata atomically, and inspects a dense staged prefix', async () => {
    await failInflightRuns();
    const adapters = createIntelligencePersistence(prisma);
    const syncRunId = randomUUID();
    const requested = requireOk(
      await adapters.unitOfWork.requestSync({
        provider: 'cisa_kev',
        sourceIdentifier: 'cisa_kev_json_catalog',
        syncRunId,
        requestedAt: NOW,
        correlationId: `corr-${syncRunId}`,
        parserVersion: KEV_PARSER_VERSION,
        normalizationVersion: KEV_NORMALIZATION_VERSION,
        dedupeKey: `claim-${syncRunId}`,
      }),
      'request for claimFetchingAttempt',
    );
    const fetching = requireOk(
      await adapters.unitOfWork.claimFetchingAttempt({
        syncRunId,
        expectedState: 'requested',
        expectedVersion: requested.syncRun.version,
        claimedAt: NOW,
        correlationId: `corr-${syncRunId}`,
      }),
      'claimFetchingAttempt',
    );
    expect(fetching.state).toBe('fetching');
    expect(fetching.executionAttempt).toBe(1);

    const sha256 = uniqueKevSha();
    const stored = requireOk(
      await adapters.unitOfWork.storeFetchedSnapshot({
        snapshot: snapshotRecord(syncRunId, sha256),
        syncRunId,
        expectedState: 'fetching',
        expectedVersion: fetching.version,
        correlationId: `corr-${syncRunId}`,
      }),
      'storeFetchedSnapshot',
    );
    expect(stored.outcome).toBe('stored');
    expect(stored.syncRun.state).toBe('stored');
    expect(stored.syncRun.snapshotId).toBe(stored.snapshot.id);
    const audits = await prisma.auditEvent.findMany({
      where: { action: 'intelligence.snapshot_stored', correlationId: `corr-${syncRunId}` },
    });
    expect(audits.length).toBeGreaterThanOrEqual(1);

    const parsing = requireOk(
      await adapters.syncRuns.recordParsing({
        syncRunId,
        expectedState: 'stored',
        expectedVersion: stored.syncRun.version,
        command: { type: 'start_parsing' },
      }),
      'parsing after store',
    );
    const staged = requireOk(
      await adapters.unitOfWork.createStagingGenerationAndRun({
        generation: {
          id: randomUUID(),
          syncRunId,
          snapshotId: stored.snapshot.id,
          provider: 'cisa_kev',
          sourceIdentifier: 'cisa_kev_json_catalog',
          expectedEntryCount: 1,
          parserVersion: KEV_PARSER_VERSION,
          normalizationVersion: KEV_NORMALIZATION_VERSION,
          catalogVersion: CATALOG_VERSION,
          catalogReleasedAt: NOW,
          createdAt: NOW,
        },
        syncRunId,
        expectedState: 'parsing',
        expectedVersion: parsing.version,
      }),
      'createStagingGenerationAndRun',
    );
    expect(staged.syncRun.state).toBe('staging');
    const entry = syntheticKevEntry({
      generationId: staged.generation.id,
      snapshotId: stored.snapshot.id,
      ordinal: 0,
      normalizedCve: 'CVE-2024-90001',
    });
    requireOk(
      await adapters.generations.stageBoundedEntryBatch({
        generationId: staged.generation.id,
        snapshotId: stored.snapshot.id,
        provider: 'cisa_kev',
        sourceIdentifier: 'cisa_kev_json_catalog',
        maxBatchSize: 16,
        entries: [entry],
      }),
      'stage one',
    );
    const prefix = await adapters.generations.inspectStagedPrefix({
      generationId: staged.generation.id,
      snapshotId: stored.snapshot.id,
      fromOrdinal: 0,
      limit: 16,
    });
    expect(prefix).toHaveLength(1);
    expect(prefix[0]?.ordinal).toBe(0);
    expect(prefix[0]?.normalizedCve).toBe('CVE-2024-90001');
    const completed = requireOk(
      await adapters.unitOfWork.completeStagedGeneration({
        generation: {
          generationId: staged.generation.id,
          expectedEntryCount: 1,
          actualStagedDistinctCveCount: 1,
          parserVersion: KEV_PARSER_VERSION,
          normalizationVersion: KEV_NORMALIZATION_VERSION,
          catalogVersion: CATALOG_VERSION,
          catalogReleasedAt: NOW,
          completedAt: NOW,
        },
        syncRunId,
        expectedState: 'staging',
        expectedVersion: staged.syncRun.version,
        correlationId: `corr-${syncRunId}`,
        warningCount: 0,
      }),
      'completeStagedGeneration',
    );
    expect(completed.generation.state).toBe('complete');
    expect(completed.syncRun.state).toBe('activating');
    expect(completed.syncRun.warningCount).toBe(0);
    const normalizationAudits = await prisma.auditEvent.findMany({
      where: {
        action: 'intelligence.normalization_completed',
        correlationId: `corr-${syncRunId}`,
      },
    });
    expect(normalizationAudits).toHaveLength(1);
    await prisma.vulnerabilitySyncRun.update({
      where: { id: syncRunId },
      data: {
        state: 'failed',
        completedAt: NOW,
        failureCategory: 'internal',
        failureCode: 'processing_failed',
      },
    });
    await assertZeroFindingUnchanged();
  });
});
