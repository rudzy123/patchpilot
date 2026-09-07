/**
 * Session 12 Batch 8-R disabled OSV runtime composition rehearsal.
 *
 * Synthetic RUSTSEC bytes only. Scripted listing and retrieval. Disposable
 * MinIO, shared PostgreSQL, and isolated parser worker. No contact with
 * storage.googleapis.com or osv.dev. No catalog activation, matching,
 * Findings, scheduler, Outbox, or OSV enablement.
 *
 * Verification execution imports the unexported factory from the compiled
 * package dist so constructed payload and holder-token identity matches
 * Batch 7 adapters. That path is not a public package export. Worker
 * `tsconfig.json` excludes this file so typecheck does not depend on
 * another package's dist internals. Worker production startup does not
 * import the factory.
 */

import { createHash, randomUUID } from 'node:crypto';
import https from 'node:https';

import { loadServerConfigFrom } from '@patchpilot/config';
import {
  createOsvAcquisitionPersistence,
  createOsvAcquisitionResumeInspection,
  createOsvRuntimeCoordinationPersistence,
  getPrismaClient,
} from '@patchpilot/database';
import {
  createOsvAttachedBodyReadPort,
  createS3OsvAdvisoryObjectStorage,
} from '@patchpilot/integrations';
import { createFoundationTestEnv } from '@patchpilot/test-utils';
import {
  createClosedOsvRuntimeSyncJobInput,
  createOsvAdvisoryParserHost,
  createOsvArtifactAttachmentService,
  createOsvGenerationBoundValidatedRetrieval,
  createOsvListedObjectObservation,
  createOsvListingPage,
  createOsvListingPageTransportSuccess,
  createOsvRuntimeJobIdempotencyIdentity,
  createOsvRuntimeSyncJobPayload,
  digestOsvProviderObjectKey,
  OSV_RUNTIME_DISABLED_COMPOSITION_STATUS,
} from '@patchpilot/vulnerability-intelligence';
import { createOsvDisabledRuntimeSynchronizationForVerification } from '../../../packages/vulnerability-intelligence/dist/osv/runtime-coordination/disabled-runtime-synchronization.js';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';

const originalHttpsRequest = https.request;
const TS = '2026-09-07T12:00:00Z';
const SYNTHETIC_GENERATION = '1234567890123456789';
const CANARY_ID = 'RUSTSEC-2000-0001';
const CANARY_KEY = `crates.io/${CANARY_ID}.json`;

function expectOk<T>(
  result: { ok: true; value: T } | { ok: false; code: string },
  label: string,
): T {
  if (!result.ok) {
    throw new Error(`${label}: ${result.code}`);
  }
  return result.value;
}

describe('Session 12 Batch 8 disabled runtime composition', { timeout: 120_000 }, () => {
  const config = loadServerConfigFrom(createFoundationTestEnv());
  const prisma = getPrismaClient({ databaseUrl: config.databaseUrl });
  const syntheticBody = new TextEncoder().encode(
    JSON.stringify({
      id: CANARY_ID,
      modified: '2026-01-01T00:00:00Z',
      summary: 'Synthetic Batch 8 canary advisory',
      affected: [],
    }),
  );
  const syntheticSha = createHash('sha256').update(syntheticBody).digest('hex');
  let host: ReturnType<typeof createOsvAdvisoryParserHost> | undefined;
  let findingCount = 0;
  let tenantCount = 0;
  let activationCount = 0;
  let pointerCount = 0;

  beforeAll(async () => {
    https.request = ((..._args: Parameters<typeof https.request>) => {
      throw new Error('provider contact is forbidden');
    }) as typeof https.request;
    findingCount = await prisma.finding.count();
    tenantCount = await prisma.organization.count();
    activationCount = await prisma.osvActivationRecord.count();
    pointerCount = await prisma.osvActiveCatalogPointer.count();
    const storage = createS3OsvAdvisoryObjectStorage({
      endpoint: config.objectStorage.endpoint,
      region: config.objectStorage.region,
      accessKey: config.objectStorage.accessKey,
      secretKey: config.objectStorage.secretKey,
      bucket: config.objectStorage.bucket,
      useSsl: config.objectStorage.useSsl,
      connectionTimeoutMs: config.objectStorage.connectionTimeoutMs,
      operationTimeoutMs: config.intelligence.objectStorageTimeoutMs,
      deploymentEnvironment: config.deploymentEnvironment,
      allowDevelopmentAdapters: config.allowDevelopmentAdapters,
    });
    const initialized = await storage.initializeDevelopmentBucket({
      explicitlyAllowed: true,
      bucket: config.objectStorage.bucket,
    });
    expect(initialized.ok).toBe(true);
    storage.destroy();
  });

  afterEach(async () => {
    if (host !== undefined) {
      await host.shutdown();
      host = undefined;
    }
    await prisma.$executeRaw`TRUNCATE TABLE "osv_runtime_stage_attempt" CASCADE`;
    await prisma.$executeRaw`TRUNCATE TABLE "osv_runtime_synchronization_run" CASCADE`;
    await prisma.$executeRaw`TRUNCATE TABLE "osv_runtime_synchronization_request" CASCADE`;
    await prisma.$executeRaw`TRUNCATE TABLE "osv_runtime_lease_projection"`;
  });

  afterAll(async () => {
    https.request = originalHttpsRequest;
    if (host !== undefined) {
      await host.shutdown();
    }
  });

  it('keeps composition production-unreachable', () => {
    expect(OSV_RUNTIME_DISABLED_COMPOSITION_STATUS).toBe(
      'disabled_runtime_composition_explicitly_invoked_production_unreachable',
    );
  });

  it('rehearses canary inventory and acquisition without activation, Findings, or provider contact', async () => {
    const catalogGenerationId = randomUUID();
    const observation = expectOk(
      createOsvListedObjectObservation({
        objectKey: CANARY_KEY,
        generation: SYNTHETIC_GENERATION,
        declaredSizeBytes: syntheticBody.byteLength,
      }),
      'observation',
    );
    const page = expectOk(
      createOsvListingPage({
        providerPrefix: 'crates.io/',
        items: [observation],
        itemCount: 1,
        complete: true,
      }),
      'page',
    );
    const success = expectOk(
      createOsvListingPageTransportSuccess({
        page,
        responseByteCount: 64,
      }),
      'listing success',
    );
    let listingCalls = 0;
    const listingPage = {
      async listPage() {
        listingCalls += 1;
        return success;
      },
    };
    const persistence = createOsvAcquisitionPersistence(prisma);
    const coordination = createOsvRuntimeCoordinationPersistence(prisma);
    const storage = createS3OsvAdvisoryObjectStorage({
      endpoint: config.objectStorage.endpoint,
      region: config.objectStorage.region,
      accessKey: config.objectStorage.accessKey,
      secretKey: config.objectStorage.secretKey,
      bucket: config.objectStorage.bucket,
      useSsl: config.objectStorage.useSsl,
      connectionTimeoutMs: config.objectStorage.connectionTimeoutMs,
      operationTimeoutMs: config.intelligence.objectStorageTimeoutMs,
      deploymentEnvironment: config.deploymentEnvironment,
      allowDevelopmentAdapters: config.allowDevelopmentAdapters,
    });
    const attachment = createOsvArtifactAttachmentService({
      store: storage,
      persistence,
    });
    host = createOsvAdvisoryParserHost();
    const service = createOsvDisabledRuntimeSynchronizationForVerification({
      coordination,
      listingPage,
      acquisition: {
        catalogGenerations: persistence.catalogGenerations,
        inventory: persistence.inventory,
        providerObjects: persistence.providerObjects,
        bodySnapshots: persistence.bodySnapshots,
        parserAttempts: persistence.parserAttempts,
        parsedRevisions: persistence.parsedRevisions,
        memberships: persistence.memberships,
        quarantine: persistence.quarantine,
        reconciliation: persistence.reconciliation,
        inspection: createOsvAcquisitionResumeInspection(prisma),
        retrieval: {
          async retrieveGenerationBoundObject() {
            return createOsvGenerationBoundValidatedRetrieval({
              sourceIdentifier: 'rustsec_advisory_database',
              providerObjectKeyDigest: digestOsvProviderObjectKey(CANARY_KEY),
              providerObjectKey: CANARY_KEY,
              generation: SYNTHETIC_GENERATION,
              declaredSizeBytes: syntheticBody.byteLength,
              receivedSizeBytes: syntheticBody.byteLength,
              sha256: syntheticSha,
              bytes: syntheticBody,
            });
          },
        },
        attachment,
        parser: host,
        readAttachedBody: createOsvAttachedBodyReadPort(storage),
      },
    });
    const job = expectOk(
      createOsvRuntimeSyncJobPayload(
        createClosedOsvRuntimeSyncJobInput({
          synchronizationReason: 'operator_canary',
          requestedAt: TS,
          correlationId: randomUUID(),
        }),
      ),
      'payload',
    );
    const idempotency = expectOk(
      createOsvRuntimeJobIdempotencyIdentity({
        workScope: job.workScope,
        reason: job.synchronizationReason,
        versionSetFingerprint: job.versionSetFingerprint,
        requestKind: 'operator_request',
        schedulerWindowId: null,
        operatorRequestId: randomUUID(),
      }),
      'idempotency',
    );
    const input = {
      payload: job,
      idempotency,
      catalogGenerationId,
    };
    try {
      const first = await service.synchronize(input);
      const second = await service.synchronize(input);
      expect(first.primaryCode).toBe('completed');
      expect(first.requestId).toBe(second.requestId);
      expect(first.runId).toBe(second.runId);
      expect(first.acquisition.activatesCatalog).toBe(false);
      expect(first.listingExecutedAgainstProvider).toBe(false);
      expect(first.automaticRetryExecuted).toBe(false);
      expect(listingCalls).toBe(2);
      expect(await prisma.finding.count()).toBe(findingCount);
      expect(await prisma.organization.count()).toBe(tenantCount);
      expect(await prisma.osvActivationRecord.count()).toBe(activationCount);
      expect(await prisma.osvActiveCatalogPointer.count()).toBe(pointerCount);
    } finally {
      await cleanupAcquisition(storage, catalogGenerationId, syntheticSha);
      storage.destroy();
    }
  });

  async function cleanupAcquisition(
    storage: ReturnType<typeof createS3OsvAdvisoryObjectStorage>,
    catalogGenerationId: string,
    bodySha: string,
  ): Promise<void> {
    const digest = digestOsvProviderObjectKey(CANARY_KEY);
    async function deleteObject(objectKey: string): Promise<void> {
      const deleted = await storage.deleteDevelopmentOwnedObject({
        explicitlyAllowed: true,
        objectKey,
      });
      if (!deleted.ok) {
        throw new Error(`osv_disabled_runtime_cleanup_delete_failed:${deleted.code}`);
      }
    }
    const attempts = await prisma.osvParserAttempt.findMany({
      where: { snapshot: { contentSha256: bodySha } },
      select: { id: true, parsedRevisionId: true, snapshotId: true },
    });
    const parsedRevisions = await prisma.osvParsedAdvisoryRevision.findMany({
      where: { snapshot: { contentSha256: bodySha } },
      select: { id: true, documentAttachmentId: true },
    });
    await prisma.osvProviderPresenceObservation.deleteMany({
      where: { catalogGenerationId },
    });
    await prisma.osvQuarantineRecord.deleteMany({
      where: { catalogGenerationId },
    });
    await prisma.osvCatalogMembership.deleteMany({
      where: {
        OR: [{ catalogGenerationId }, { revisionId: { in: parsedRevisions.map((row) => row.id) } }],
      },
    });
    await prisma.osvParserAttempt.updateMany({
      where: { id: { in: attempts.map((row) => row.id) } },
      data: { parsedRevisionId: null },
    });
    await prisma.osvParsedAdvisoryRevision.deleteMany({
      where: { snapshot: { contentSha256: bodySha } },
    });
    await prisma.osvParserAttempt.deleteMany({
      where: { id: { in: attempts.map((row) => row.id) } },
    });
    const snapshots = await prisma.osvProviderBodySnapshot.findMany({
      where: { contentSha256: bodySha },
      select: { id: true, attachmentId: true },
    });
    await prisma.osvProviderBodySnapshot.deleteMany({
      where: { contentSha256: bodySha },
    });
    const attachmentIds = [
      ...snapshots.map((row) => row.attachmentId),
      ...parsedRevisions.map((row) => row.documentAttachmentId),
    ];
    const attachments = await prisma.osvObjectAttachment.findMany({
      where: {
        OR: [
          { id: { in: attachmentIds } },
          { objectKey: { startsWith: 'intelligence/osv/' }, contentSha256: bodySha },
        ],
      },
    });
    for (const row of attachments) {
      await deleteObject(row.objectKey);
    }
    await prisma.osvObjectAttachment.deleteMany({
      where: { id: { in: attachments.map((row) => row.id) } },
    });
    await prisma.osvProviderGeneration.deleteMany({
      where: { providerObjectKeyDigest: digest },
    });
    const inventoryRuns = await prisma.osvInventoryRun.findMany({
      where: { catalogGenerationId },
      select: { id: true },
    });
    await prisma.osvInventoryObjectObservation.deleteMany({
      where: { inventoryRunId: { in: inventoryRuns.map((row) => row.id) } },
    });
    await prisma.osvInventoryPrefixPass.deleteMany({
      where: { inventoryRunId: { in: inventoryRuns.map((row) => row.id) } },
    });
    await prisma.osvInventoryRun.deleteMany({
      where: { catalogGenerationId },
    });
    await prisma.osvReconciliation.deleteMany({
      where: { catalogGenerationId },
    });
    await prisma.osvAcquisitionCompleteness.deleteMany({
      where: { catalogGenerationId },
    });
    await prisma.osvActivationRecord.deleteMany({
      where: { candidateGenerationId: catalogGenerationId },
    });
    await prisma.osvCatalogGeneration.deleteMany({
      where: { id: catalogGenerationId },
    });
    await prisma.osvProviderObject.deleteMany({
      where: { providerObjectKeyDigest: digest },
    });
    await deleteObject(`intelligence/osv/advisory_body/sha256/${bodySha}`);
  }
});
