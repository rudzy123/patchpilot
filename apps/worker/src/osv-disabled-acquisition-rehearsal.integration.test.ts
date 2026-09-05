/**
 * Session 11 Batch 6C disabled end-to-end OSV acquisition rehearsal.
 *
 * Test-only complete-inventory contract. Synthetic GHSA/MAL bytes only.
 * Authorized scripted retrieval (no storage.googleapis.com). Disposable
 * MinIO, PostgreSQL, and isolated parser worker. No catalog activation,
 * matching, Findings, scheduler, Outbox, or OSV enablement.
 */

import { createHash, randomUUID } from 'node:crypto';
import https from 'node:https';
import { inspect } from 'node:util';

import { loadServerConfigFrom } from '@patchpilot/config';
import {
  createOsvAcquisitionPersistence,
  createOsvAcquisitionResumeInspection,
  getPrismaClient,
} from '@patchpilot/database';
import {
  createOsvAttachedBodyReadPort,
  createS3OsvAdvisoryObjectStorage,
} from '@patchpilot/integrations';
import { createFoundationTestEnv } from '@patchpilot/test-utils';
import {
  authorizeOsvGenerationBoundRetrieval,
  createOsvAdvisoryParserHost,
  createOsvArtifactAttachmentService,
  createOsvDisabledAcquisitionOrchestrator,
  createOsvGenerationBoundValidatedRetrieval,
  createOsvListedObjectObservation,
  digestOsvProviderObjectKey,
  encodeOsvParsedAdvisoryDocument,
  OSV_ADVISORY_PARSER_PROTOCOL_IDENTIFIER,
  OSV_ADVISORY_PARSER_RESOURCE_POLICY_IDENTIFIER,
  OSV_CATALOG_SYNC_ALGORITHM_IDENTIFIER,
  OSV_DISABLED_ACQUISITION_ORCHESTRATION_POLICY_IDENTIFIER,
  OSV_ELIGIBLE_BODY_SCOPE_IDENTIFIER,
  OSV_GCS_LISTING_PROTOCOL_VERSION,
  OSV_GENERATION_BOUND_RETRIEVAL_POLICY_IDENTIFIER,
  OSV_INVENTORY_SCOPE_IDENTIFIER,
  OSV_OBJECT_STORAGE_LAYOUT_VERSION,
  OSV_PARSED_ADVISORY_DOCUMENT_IDENTIFIER,
  OSV_PROVIDER_IDENTIFIER,
  OSV_SCHEMA_VERSION_TAG,
  OSV_SOURCE_LICENSE_REGISTRY_IDENTIFIER,
  OSV_TRANSPORT_POLICY_VERSION,
} from '@patchpilot/vulnerability-intelligence';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';

const TS = '2026-09-05T18:00:00.000Z';
const SYNTHETIC_GENERATION = '1234567890123456789';
const PARSED_DOCUMENT = encodeOsvParsedAdvisoryDocument({
  documentIdentifier: OSV_PARSED_ADVISORY_DOCUMENT_IDENTIFIER,
});
if (!PARSED_DOCUMENT.ok) {
  throw new Error('parsed document fixture');
}
const PARSED_DOCUMENT_SHA256 = PARSED_DOCUMENT.value.sha256;

type TrackedRun = {
  catalogGenerationId: string;
  inventoryRunId: string;
  objectKey: string;
  bodySha: string;
};

const tracked: TrackedRun[] = [];
const httpsHosts: string[] = [];
const originalHttpsRequest = https.request;

function syntheticAdvisory(id: string, token: string): Uint8Array {
  return new TextEncoder().encode(
    JSON.stringify({
      id,
      modified: '2026-01-01T00:00:00Z',
      summary: `Synthetic rehearsal advisory ${token}`,
    }),
  );
}

function leakHaystack(value: unknown): string {
  return `${JSON.stringify(value)}\n${inspect(value)}\n${String(value)}`;
}

describe('Session 11 Batch 6C disabled OSV acquisition rehearsal', () => {
  const config = loadServerConfigFrom(createFoundationTestEnv());
  const prisma = getPrismaClient({ databaseUrl: config.databaseUrl });
  const objectStore = storage(false);
  const trackedStores: ReturnType<typeof createS3OsvAdvisoryObjectStorage>[] = [];
  let host: ReturnType<typeof createOsvAdvisoryParserHost> | undefined;
  const tenantBaseline = {
    organizations: 0,
    findings: 0,
    vulnerabilities: 0,
    components: 0,
    evidence: 0,
  };

  function storage(track = true) {
    const created = createS3OsvAdvisoryObjectStorage({
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
    if (track) {
      trackedStores.push(created);
    }
    return created;
  }

  function requestBase(
    observations: ReturnType<typeof createOsvListedObjectObservation>[],
    extra: Record<string, unknown> = {},
  ) {
    const listed = observations.map((item) => {
      if (!item.ok) {
        throw new Error(item.code);
      }
      return item.value;
    });
    return {
      policyIdentifier: OSV_DISABLED_ACQUISITION_ORCHESTRATION_POLICY_IDENTIFIER,
      catalogGenerationId: randomUUID(),
      inventoryRunId: randomUUID(),
      providerIdentifier: OSV_PROVIDER_IDENTIFIER,
      inventoryScopeIdentifier: OSV_INVENTORY_SCOPE_IDENTIFIER,
      eligibleBodyScopeIdentifier: OSV_ELIGIBLE_BODY_SCOPE_IDENTIFIER,
      sourceLicenseRegistryIdentifier: OSV_SOURCE_LICENSE_REGISTRY_IDENTIFIER,
      listingProtocolIdentifier: OSV_GCS_LISTING_PROTOCOL_VERSION,
      transportPolicyIdentifier: OSV_TRANSPORT_POLICY_VERSION,
      retrievalPolicyIdentifier: OSV_GENERATION_BOUND_RETRIEVAL_POLICY_IDENTIFIER,
      parserProtocolIdentifier: OSV_ADVISORY_PARSER_PROTOCOL_IDENTIFIER,
      parserResourcePolicyIdentifier: OSV_ADVISORY_PARSER_RESOURCE_POLICY_IDENTIFIER,
      osvSchemaRevision: OSV_SCHEMA_VERSION_TAG,
      parsedDocumentFormatIdentifier: OSV_PARSED_ADVISORY_DOCUMENT_IDENTIFIER,
      objectStorageLayoutIdentifier: OSV_OBJECT_STORAGE_LAYOUT_VERSION,
      synchronizationAlgorithmIdentifier: OSV_CATALOG_SYNC_ALGORITHM_IDENTIFIER,
      inventoryCompletenessClaim: 'complete_comparable_inventory' as const,
      observations: listed,
      createdAt: TS,
      retrievedAt: TS,
      signal: new AbortController().signal,
      ...extra,
    };
  }

  function createAuthorizedRetrieval(
    bodies: Map<string, Uint8Array>,
    abortOnRetrieve?: AbortController,
  ) {
    let attempts = 0;
    return {
      attempts: () => attempts,
      port: {
        async retrieveGenerationBoundObject(input: unknown) {
          attempts += 1;
          const authorized = authorizeOsvGenerationBoundRetrieval(input);
          if (!authorized.ok) {
            return authorized;
          }
          abortOnRetrieve?.abort();
          const record =
            typeof input === 'object' && input !== null ? (input as Record<string, unknown>) : {};
          const objectKey = typeof record['objectKey'] === 'string' ? record['objectKey'] : '';
          const generation = typeof record['generation'] === 'string' ? record['generation'] : '';
          const declared =
            typeof record['expectedDeclaredByteCount'] === 'number'
              ? record['expectedDeclaredByteCount']
              : 0;
          const bytes = bodies.get(objectKey);
          if (bytes === undefined) {
            throw new Error('osv_rehearsal_missing_scripted_body');
          }
          return createOsvGenerationBoundValidatedRetrieval({
            sourceIdentifier: authorized.value.sourceIdentifier,
            providerObjectKeyDigest: digestOsvProviderObjectKey(objectKey),
            providerObjectKey: objectKey,
            generation,
            declaredSizeBytes: declared,
            receivedSizeBytes: bytes.byteLength,
            sha256: createHash('sha256').update(bytes).digest('hex'),
            bytes,
          });
        },
      },
    };
  }

  async function compose(
    bodies: Map<string, Uint8Array>,
    options: {
      failAttachedFinalizeOnce?: boolean;
      abortOnRetrieve?: AbortController;
    } = {},
  ) {
    const persistence = createOsvAcquisitionPersistence(prisma);
    const objectStore = storage();
    host = createOsvAdvisoryParserHost();
    const retrieval = createAuthorizedRetrieval(bodies, options.abortOnRetrieve);
    let failAttached = options.failAttachedFinalizeOnce === true;
    const bodySnapshots = {
      reserveImmutableGeneration: (
        generation: Parameters<typeof persistence.bodySnapshots.reserveImmutableGeneration>[0],
      ) => persistence.bodySnapshots.reserveImmutableGeneration(generation),
      loadByGeneration: (
        generation: Parameters<typeof persistence.bodySnapshots.loadByGeneration>[0],
      ) => persistence.bodySnapshots.loadByGeneration(generation),
      attachImmutableSnapshot: async (
        snapshot: Parameters<typeof persistence.bodySnapshots.attachImmutableSnapshot>[0],
      ) => {
        if (failAttached && snapshot.attachment.state === 'attached') {
          failAttached = false;
          return { ok: false as const, code: 'completeness_failed' as const };
        }
        return persistence.bodySnapshots.attachImmutableSnapshot(snapshot);
      },
    };
    const attachmentPersistence = {
      bodySnapshots,
      attachments: persistence.attachments,
      parsedRevisions: persistence.parsedRevisions,
    };
    return {
      persistence,
      retrieval,
      objectStore,
      orchestrator: createOsvDisabledAcquisitionOrchestrator({
        catalogGenerations: persistence.catalogGenerations,
        inventory: persistence.inventory,
        providerObjects: persistence.providerObjects,
        bodySnapshots,
        parserAttempts: persistence.parserAttempts,
        parsedRevisions: persistence.parsedRevisions,
        memberships: persistence.memberships,
        quarantine: persistence.quarantine,
        reconciliation: persistence.reconciliation,
        presence: persistence.presence,
        inspection: createOsvAcquisitionResumeInspection(prisma),
        retrieval: retrieval.port,
        attachment: createOsvArtifactAttachmentService({
          store: objectStore,
          persistence: attachmentPersistence,
        }),
        parser: host,
        readAttachedBody: createOsvAttachedBodyReadPort(objectStore),
      }),
    };
  }

  async function deleteObject(key: string): Promise<void> {
    const deleted = await objectStore.deleteDevelopmentOwnedObject({
      explicitlyAllowed: true,
      objectKey: key,
    });
    if (!deleted.ok) {
      throw new Error(`osv_rehearsal_cleanup_delete_failed:${deleted.code}`);
    }
  }

  async function cleanupRun(run: TrackedRun): Promise<void> {
    const digest = digestOsvProviderObjectKey(run.objectKey);
    await prisma.osvProviderPresenceObservation.deleteMany({
      where: { catalogGenerationId: run.catalogGenerationId },
    });
    await prisma.osvQuarantineRecord.deleteMany({
      where: { catalogGenerationId: run.catalogGenerationId },
    });
    await prisma.osvCatalogMembership.deleteMany({
      where: { catalogGenerationId: run.catalogGenerationId },
    });
    const attempts = await prisma.osvParserAttempt.findMany({
      where: { snapshot: { contentSha256: run.bodySha } },
      select: { id: true, parsedRevisionId: true, snapshotId: true },
    });
    await prisma.osvParserAttempt.updateMany({
      where: { id: { in: attempts.map((row) => row.id) } },
      data: { parsedRevisionId: null },
    });
    await prisma.osvParsedAdvisoryRevision.deleteMany({
      where: { snapshot: { contentSha256: run.bodySha } },
    });
    await prisma.osvParserAttempt.deleteMany({
      where: { id: { in: attempts.map((row) => row.id) } },
    });
    const snapshots = await prisma.osvProviderBodySnapshot.findMany({
      where: { contentSha256: run.bodySha },
      select: { id: true, attachmentId: true, providerGenerationId: true },
    });
    await prisma.osvProviderBodySnapshot.deleteMany({
      where: { contentSha256: run.bodySha },
    });
    const attachmentIds = snapshots.map((row) => row.attachmentId);
    const bodyAttachments = await prisma.osvObjectAttachment.findMany({
      where: {
        OR: [
          { id: { in: attachmentIds } },
          { objectKey: { startsWith: 'intelligence/osv/' }, contentSha256: run.bodySha },
        ],
      },
    });
    for (const row of bodyAttachments) {
      await deleteObject(row.objectKey);
    }
    await prisma.osvObjectAttachment.deleteMany({
      where: { id: { in: bodyAttachments.map((row) => row.id) } },
    });
    await prisma.osvProviderGeneration.deleteMany({
      where: { providerObjectKeyDigest: digest },
    });
    const inventoryRuns = await prisma.osvInventoryRun.findMany({
      where: { catalogGenerationId: run.catalogGenerationId },
      select: { id: true },
    });
    await prisma.osvInventoryObjectObservation.deleteMany({
      where: { inventoryRunId: { in: inventoryRuns.map((row) => row.id) } },
    });
    await prisma.osvInventoryPrefixPass.deleteMany({
      where: { inventoryRunId: { in: inventoryRuns.map((row) => row.id) } },
    });
    await prisma.osvInventoryRun.deleteMany({
      where: { catalogGenerationId: run.catalogGenerationId },
    });
    await prisma.osvReconciliation.deleteMany({
      where: { catalogGenerationId: run.catalogGenerationId },
    });
    await prisma.osvAcquisitionCompleteness.deleteMany({
      where: { catalogGenerationId: run.catalogGenerationId },
    });
    await prisma.osvActivationRecord.deleteMany({
      where: { candidateGenerationId: run.catalogGenerationId },
    });
    await prisma.osvCatalogGeneration.deleteMany({
      where: { id: run.catalogGenerationId },
    });
    await prisma.osvProviderObject.deleteMany({
      where: { providerObjectKeyDigest: digest },
    });
    await deleteObject(`intelligence/osv/advisory_body/sha256/${run.bodySha}`);
  }

  async function cleanupSharedParsedDocument(): Promise<void> {
    const remaining = await prisma.osvParsedAdvisoryRevision.count({
      where: { documentAttachment: { contentSha256: PARSED_DOCUMENT_SHA256 } },
    });
    if (remaining > 0) {
      return;
    }
    const parsedAttachments = await prisma.osvObjectAttachment.findMany({
      where: {
        contentSha256: PARSED_DOCUMENT_SHA256,
        storageKind: 'parsed_advisory',
      },
    });
    for (const row of parsedAttachments) {
      await deleteObject(row.objectKey);
    }
    await prisma.osvObjectAttachment.deleteMany({
      where: { id: { in: parsedAttachments.map((row) => row.id) } },
    });
    await deleteObject(`intelligence/osv/parsed_advisory/sha256/${PARSED_DOCUMENT_SHA256}`);
  }

  beforeAll(async () => {
    https.request = ((...args: Parameters<typeof https.request>) => {
      const options = args[0];
      const hostName =
        typeof options === 'object' && options !== null && 'hostname' in options
          ? String(options.hostname)
          : String(options);
      httpsHosts.push(hostName);
      throw new Error('osv_rehearsal_external_https_forbidden');
    }) as typeof https.request;
    const initialized = await storage().initializeDevelopmentBucket({
      explicitlyAllowed: true,
      bucket: config.objectStorage.bucket,
    });
    expect(initialized.ok).toBe(true);
    tenantBaseline.organizations = await prisma.organization.count();
    tenantBaseline.findings = await prisma.finding.count();
    tenantBaseline.vulnerabilities = await prisma.vulnerability.count();
    tenantBaseline.components = await prisma.component.count();
    tenantBaseline.evidence = await prisma.evidence.count();
  });

  afterEach(async () => {
    if (host !== undefined) {
      await host.shutdown();
      host = undefined;
    }
    while (trackedStores.length > 0) {
      trackedStores.pop()?.destroy();
    }
  });

  afterAll(async () => {
    https.request = originalHttpsRequest;
    const errors: string[] = [];
    try {
      for (const run of tracked) {
        await cleanupRun(run);
      }
      await cleanupSharedParsedDocument();
    } catch (error: unknown) {
      errors.push(error instanceof Error ? error.message : 'cleanup_failed');
    }
    objectStore.destroy();
    if (host !== undefined) {
      await host.shutdown();
    }
    expect(errors).toEqual([]);
  });

  it('reaches ready_for_activation on a synthetic complete-inventory candidate without activating', async () => {
    const token = randomUUID().replaceAll('-', '').slice(0, 8).toUpperCase();
    const syntheticId = `GHSA-T6C0-${token.slice(0, 4)}-${token.slice(4, 8)}`;
    const objectKey = `npm/${syntheticId}.json`;
    const body = syntheticAdvisory(syntheticId, token);
    const bodySha = createHash('sha256').update(body).digest('hex');
    const listed = createOsvListedObjectObservation({
      objectKey,
      generation: SYNTHETIC_GENERATION,
      declaredSizeBytes: body.byteLength,
    });
    const input = requestBase([listed]);
    tracked.push({
      catalogGenerationId: input.catalogGenerationId,
      inventoryRunId: input.inventoryRunId,
      objectKey,
      bodySha,
    });
    const composed = await compose(new Map([[objectKey, body]]));
    const pointerBefore = await prisma.osvActiveCatalogPointer.count();
    const activationBefore = await prisma.osvActivationRecord.count();
    const result = await composed.orchestrator.processBoundedCandidateGeneration(input);

    expect(result.listingExecuted).toBe(false);
    expect(result.automaticRetryExecuted).toBe(false);
    expect(result.activatesCatalog).toBe(false);
    expect(result.authorizesMatching).toBe(false);
    expect(result.createsFinding).toBe(false);
    expect(result.workItems[0]?.state).toBe('complete');
    expect(result.workItems[0]?.membershipCreated).toBe(true);
    expect(result.candidateReadiness).toBe('ready_for_activation');
    expect(result.lifecycleState).toBe('ready_for_activation');
    expect(composed.retrieval.attempts()).toBe(1);

    const generation = await prisma.osvCatalogGeneration.findUniqueOrThrow({
      where: { id: input.catalogGenerationId },
    });
    expect(generation.lifecycleState).toBe('ready_for_activation');
    expect(
      await prisma.osvCatalogMembership.count({
        where: { catalogGenerationId: input.catalogGenerationId },
      }),
    ).toBe(1);
    expect(await prisma.osvActivationRecord.count()).toBe(activationBefore);
    expect(await prisma.osvActiveCatalogPointer.count()).toBe(pointerBefore);
    expect(
      await prisma.osvActivationRecord.count({
        where: { candidateGenerationId: input.catalogGenerationId },
      }),
    ).toBe(0);
    expect(await prisma.finding.count()).toBe(tenantBaseline.findings);
    expect(await prisma.vulnerability.count()).toBe(tenantBaseline.vulnerabilities);
    expect(await prisma.organization.count()).toBe(tenantBaseline.organizations);
    expect(await prisma.component.count()).toBe(tenantBaseline.components);
    expect(await prisma.evidence.count()).toBe(tenantBaseline.evidence);

    const haystack = leakHaystack(result);
    expect(haystack).not.toContain(objectKey);
    expect(haystack).not.toContain(body.toString());
    expect(haystack).not.toContain('storage.googleapis.com');
    expect(haystack).not.toContain('osv.dev');
    expect(haystack).not.toContain(config.objectStorage.bucket);
    expect(httpsHosts).toEqual([]);
  }, 60_000);

  it('replays the same synthetic candidate without a second retrieval or membership', async () => {
    const token = randomUUID().replaceAll('-', '').slice(0, 8).toUpperCase();
    const syntheticId = `GHSA-T6C0-${token.slice(0, 4)}-${token.slice(4, 8)}`;
    const objectKey = `npm/${syntheticId}.json`;
    const body = syntheticAdvisory(syntheticId, token);
    const bodySha = createHash('sha256').update(body).digest('hex');
    const listed = createOsvListedObjectObservation({
      objectKey,
      generation: SYNTHETIC_GENERATION,
      declaredSizeBytes: body.byteLength,
    });
    const input = requestBase([listed]);
    tracked.push({
      catalogGenerationId: input.catalogGenerationId,
      inventoryRunId: input.inventoryRunId,
      objectKey,
      bodySha,
    });
    const composed = await compose(new Map([[objectKey, body]]));
    const first = await composed.orchestrator.processBoundedCandidateGeneration(input);
    const second = await composed.orchestrator.processBoundedCandidateGeneration(input);
    expect(first.candidateReadiness).toBe('ready_for_activation');
    expect(second.candidateReadiness).toBe('ready_for_activation');
    expect(second.workItems[0]?.alreadyApplied).toBe(true);
    expect(composed.retrieval.attempts()).toBe(1);
    expect(
      await prisma.osvCatalogMembership.count({
        where: { catalogGenerationId: input.catalogGenerationId },
      }),
    ).toBe(1);
    expect(second.activatesCatalog).toBe(false);
    expect(httpsHosts).toEqual([]);
  }, 60_000);

  it('classifies mixed unauthorized observations with zero HTTP attempts for ineligible items', async () => {
    const token = randomUUID().replaceAll('-', '').slice(0, 8).toUpperCase();
    const syntheticId = `GHSA-T6C0-${token.slice(0, 4)}-${token.slice(4, 8)}`;
    const objectKey = `npm/${syntheticId}.json`;
    const body = syntheticAdvisory(syntheticId, token);
    const bodySha = createHash('sha256').update(body).digest('hex');
    const input = requestBase([
      createOsvListedObjectObservation({
        objectKey,
        generation: SYNTHETIC_GENERATION,
        declaredSizeBytes: body.byteLength,
      }),
      createOsvListedObjectObservation({
        objectKey: 'npm/OSV-2024-0001.json',
        generation: '1',
        declaredSizeBytes: 12,
      }),
      createOsvListedObjectObservation({
        objectKey: 'npm/ECHO-2024-0001.json',
        generation: '1',
        declaredSizeBytes: 12,
      }),
      createOsvListedObjectObservation({
        objectKey: 'npm/CVE-2024-0001.json',
        generation: '1',
        declaredSizeBytes: 12,
      }),
    ]);
    tracked.push({
      catalogGenerationId: input.catalogGenerationId,
      inventoryRunId: input.inventoryRunId,
      objectKey,
      bodySha,
    });
    const composed = await compose(new Map([[objectKey, body]]));
    const result = await composed.orchestrator.processBoundedCandidateGeneration(input);
    expect(result.workItems).toHaveLength(4);
    expect(result.workItems.filter((item) => item.state === 'complete')).toHaveLength(1);
    expect(result.workItems.filter((item) => item.state === 'retrieval_skipped')).toHaveLength(2);
    expect(result.workItems.filter((item) => item.state === 'quarantined')).toHaveLength(1);
    expect(composed.retrieval.attempts()).toBe(1);
    expect(result.candidateReadiness).toBe('not_ready');
    expect(result.activatesCatalog).toBe(false);
  }, 60_000);

  it('recovers staged PostgreSQL after the attached MinIO object already exists', async () => {
    const token = randomUUID().replaceAll('-', '').slice(0, 8).toUpperCase();
    const syntheticId = `GHSA-T6C0-${token.slice(0, 4)}-${token.slice(4, 8)}`;
    const objectKey = `npm/${syntheticId}.json`;
    const body = syntheticAdvisory(syntheticId, token);
    const bodySha = createHash('sha256').update(body).digest('hex');
    const listed = createOsvListedObjectObservation({
      objectKey,
      generation: SYNTHETIC_GENERATION,
      declaredSizeBytes: body.byteLength,
    });
    const input = requestBase([listed]);
    tracked.push({
      catalogGenerationId: input.catalogGenerationId,
      inventoryRunId: input.inventoryRunId,
      objectKey,
      bodySha,
    });
    const interrupted = await compose(new Map([[objectKey, body]]), {
      failAttachedFinalizeOnce: true,
    });
    const first = await interrupted.orchestrator.processBoundedCandidateGeneration(input);
    expect(first.workItems[0]?.state).toBe('failed');
    expect(first.automaticRetryExecuted).toBe(false);
    expect(first.candidateReadiness).toBe('not_ready');
    const resumed = await compose(new Map([[objectKey, body]]));
    const second = await resumed.orchestrator.processBoundedCandidateGeneration(input);
    expect(second.workItems[0]?.state).toBe('complete');
    expect(second.candidateReadiness).toBe('ready_for_activation');
    expect(second.activatesCatalog).toBe(false);
    expect(resumed.retrieval.attempts()).toBe(0);
  }, 60_000);

  it('fails closed on conflicting declared size without last-write-wins', async () => {
    const token = randomUUID().replaceAll('-', '').slice(0, 8).toUpperCase();
    const syntheticId = `GHSA-T6C0-${token.slice(0, 4)}-${token.slice(4, 8)}`;
    const objectKey = `npm/${syntheticId}.json`;
    const body = syntheticAdvisory(syntheticId, token);
    const bodySha = createHash('sha256').update(body).digest('hex');
    const listed = createOsvListedObjectObservation({
      objectKey,
      generation: SYNTHETIC_GENERATION,
      declaredSizeBytes: body.byteLength,
    });
    const firstInput = requestBase([listed]);
    tracked.push({
      catalogGenerationId: firstInput.catalogGenerationId,
      inventoryRunId: firstInput.inventoryRunId,
      objectKey,
      bodySha,
    });
    const composed = await compose(new Map([[objectKey, body]]));
    const first = await composed.orchestrator.processBoundedCandidateGeneration(firstInput);
    expect(first.candidateReadiness).toBe('ready_for_activation');
    const conflict = requestBase([
      createOsvListedObjectObservation({
        objectKey,
        generation: SYNTHETIC_GENERATION,
        declaredSizeBytes: body.byteLength + 1,
      }),
    ]);
    tracked.push({
      catalogGenerationId: conflict.catalogGenerationId,
      inventoryRunId: conflict.inventoryRunId,
      objectKey,
      bodySha,
    });
    const second = await composed.orchestrator.processBoundedCandidateGeneration(conflict);
    expect(
      second.workItems[0]?.state === 'quarantined' || second.workItems[0]?.state === 'failed',
    ).toBe(true);
    expect(second.candidateReadiness).toBe('not_ready');
    expect(
      await prisma.osvCatalogMembership.count({
        where: { catalogGenerationId: firstInput.catalogGenerationId },
      }),
    ).toBe(1);
    expect(
      await prisma.osvCatalogMembership.count({
        where: { catalogGenerationId: conflict.catalogGenerationId },
      }),
    ).toBe(0);
    expect(second.activatesCatalog).toBe(false);
  }, 60_000);

  it('quarantines a schema-invalid advisory and leaves the candidate incomplete', async () => {
    const token = randomUUID().replaceAll('-', '').slice(0, 8).toUpperCase();
    const syntheticId = `GHSA-T6C0-${token.slice(0, 4)}-${token.slice(4, 8)}`;
    const objectKey = `npm/${syntheticId}.json`;
    const body = new TextEncoder().encode(JSON.stringify({ id: syntheticId }));
    const bodySha = createHash('sha256').update(body).digest('hex');
    const listed = createOsvListedObjectObservation({
      objectKey,
      generation: SYNTHETIC_GENERATION,
      declaredSizeBytes: body.byteLength,
    });
    const input = requestBase([listed]);
    tracked.push({
      catalogGenerationId: input.catalogGenerationId,
      inventoryRunId: input.inventoryRunId,
      objectKey,
      bodySha,
    });
    const composed = await compose(new Map([[objectKey, body]]));
    const result = await composed.orchestrator.processBoundedCandidateGeneration(input);
    expect(result.workItems[0]?.state).toBe('quarantined');
    expect(result.candidateReadiness).toBe('not_ready');
    expect(result.workItems[0]?.membershipCreated).toBe(false);
    expect(
      await prisma.osvQuarantineRecord.count({
        where: { catalogGenerationId: input.catalogGenerationId },
      }),
    ).toBeGreaterThan(0);
    expect(
      await prisma.osvCatalogMembership.count({
        where: { catalogGenerationId: input.catalogGenerationId },
      }),
    ).toBe(0);
    expect(result.activatesCatalog).toBe(false);
  }, 60_000);

  it('cancels before invocation and after retrieval without activating', async () => {
    const token = randomUUID().replaceAll('-', '').slice(0, 8).toUpperCase();
    const syntheticId = `GHSA-T6C0-${token.slice(0, 4)}-${token.slice(4, 8)}`;
    const objectKey = `npm/${syntheticId}.json`;
    const body = syntheticAdvisory(syntheticId, token);
    const bodySha = createHash('sha256').update(body).digest('hex');
    const listed = createOsvListedObjectObservation({
      objectKey,
      generation: SYNTHETIC_GENERATION,
      declaredSizeBytes: body.byteLength,
    });
    const aborted = new AbortController();
    aborted.abort();
    const beforeInput = requestBase([listed], { signal: aborted.signal });
    tracked.push({
      catalogGenerationId: beforeInput.catalogGenerationId,
      inventoryRunId: beforeInput.inventoryRunId,
      objectKey,
      bodySha,
    });
    const beforeCompose = await compose(new Map([[objectKey, body]]));
    const before = await beforeCompose.orchestrator.processBoundedCandidateGeneration(beforeInput);
    expect(before.cancelled).toBe(true);
    expect(before.workItems).toHaveLength(0);
    expect(beforeCompose.retrieval.attempts()).toBe(0);

    const during = new AbortController();
    const duringInput = requestBase([listed], { signal: during.signal });
    tracked.push({
      catalogGenerationId: duringInput.catalogGenerationId,
      inventoryRunId: duringInput.inventoryRunId,
      objectKey,
      bodySha,
    });
    const duringCompose = await compose(new Map([[objectKey, body]]), {
      abortOnRetrieve: during,
    });
    const cancelled =
      await duringCompose.orchestrator.processBoundedCandidateGeneration(duringInput);
    expect(cancelled.cancelled).toBe(true);
    expect(cancelled.automaticRetryExecuted).toBe(false);
    expect(cancelled.activatesCatalog).toBe(false);
    expect(cancelled.candidateReadiness).toBe('not_ready');
  }, 60_000);

  it('parses a synthetic MAL advisory without matching or Finding authorization', async () => {
    const token = randomUUID().replaceAll('-', '').slice(0, 8).toUpperCase();
    const syntheticId = `MAL-2026-${token.slice(0, 4)}`;
    const objectKey = `npm/${syntheticId}.json`;
    const body = syntheticAdvisory(syntheticId, token);
    const bodySha = createHash('sha256').update(body).digest('hex');
    const listed = createOsvListedObjectObservation({
      objectKey,
      generation: SYNTHETIC_GENERATION,
      declaredSizeBytes: body.byteLength,
    });
    const input = requestBase([listed]);
    tracked.push({
      catalogGenerationId: input.catalogGenerationId,
      inventoryRunId: input.inventoryRunId,
      objectKey,
      bodySha,
    });
    const composed = await compose(new Map([[objectKey, body]]));
    const result = await composed.orchestrator.processBoundedCandidateGeneration(input);
    expect(result.workItems[0]?.state).toBe('complete');
    expect(result.authorizesMatching).toBe(false);
    expect(result.createsFinding).toBe(false);
    expect(result.workItems[0]?.authorizesMatching).toBe(false);
    expect(result.activatesCatalog).toBe(false);
  }, 60_000);

  it('settles concurrent identical invocations without duplicate membership or activation', async () => {
    const token = randomUUID().replaceAll('-', '').slice(0, 8).toUpperCase();
    const syntheticId = `GHSA-T6C0-${token.slice(0, 4)}-${token.slice(4, 8)}`;
    const objectKey = `npm/${syntheticId}.json`;
    const body = syntheticAdvisory(syntheticId, token);
    const bodySha = createHash('sha256').update(body).digest('hex');
    const listed = createOsvListedObjectObservation({
      objectKey,
      generation: SYNTHETIC_GENERATION,
      declaredSizeBytes: body.byteLength,
    });
    const input = requestBase([listed]);
    tracked.push({
      catalogGenerationId: input.catalogGenerationId,
      inventoryRunId: input.inventoryRunId,
      objectKey,
      bodySha,
    });
    const composed = await compose(new Map([[objectKey, body]]));
    const first = await composed.orchestrator.processBoundedCandidateGeneration(input);
    expect(first.workItems[0]?.state).toBe('complete');
    const [left, right] = await Promise.all([
      composed.orchestrator.processBoundedCandidateGeneration(input),
      composed.orchestrator.processBoundedCandidateGeneration(input),
    ]);
    expect(left.activatesCatalog).toBe(false);
    expect(right.activatesCatalog).toBe(false);
    expect(left.createsFinding).toBe(false);
    expect(right.createsFinding).toBe(false);
    expect(
      await prisma.osvCatalogMembership.count({
        where: { catalogGenerationId: input.catalogGenerationId },
      }),
    ).toBe(1);
    expect(
      await prisma.osvActivationRecord.count({
        where: { candidateGenerationId: input.catalogGenerationId },
      }),
    ).toBe(0);
  }, 60_000);

  it('does not import the rehearsal from production worker runtime', async () => {
    const { readFileSync } = await import('node:fs');
    const { dirname, join } = await import('node:path');
    const { fileURLToPath } = await import('node:url');
    const src = dirname(fileURLToPath(import.meta.url));
    for (const name of [
      'main.ts',
      'app.ts',
      'intelligence-composition.ts',
      'intelligence-runtime.ts',
    ]) {
      const source = readFileSync(join(src, name), 'utf8');
      expect(source).not.toContain('createOsvDisabledAcquisitionOrchestrator');
      expect(source).not.toContain('processBoundedCandidateGeneration');
    }
  });
});
