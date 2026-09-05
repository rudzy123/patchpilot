/**
 * Session 11 Batch 6B disabled OSV acquisition composition rehearsal.
 *
 * Synthetic GHSA bytes only. Fake generation-bound retrieval. Real disposable
 * MinIO object storage, PostgreSQL persistence, and isolated parser worker.
 * No contact with storage.googleapis.com or osv.dev. No catalog activation.
 * No Findings. OSV remains disabled.
 */

import { createHash, randomUUID } from 'node:crypto';

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
  createOsvAdvisoryParserHost,
  createOsvArtifactAttachmentService,
  createOsvDisabledAcquisitionOrchestrator,
  createOsvGenerationBoundValidatedRetrieval,
  createOsvListedObjectObservation,
  digestOsvProviderObjectKey,
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
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

const TS = '2026-09-05T18:00:00.000Z';
const SYNTHETIC_ID = 'GHSA-AAAA-BBBB-CCCC';
const SYNTHETIC_KEY = `npm/${SYNTHETIC_ID}.json`;
const SYNTHETIC_GENERATION = '1234567890123456789';

describe('disabled OSV acquisition MinIO and PostgreSQL composition', () => {
  const config = loadServerConfigFrom(createFoundationTestEnv());
  const prisma = getPrismaClient({ databaseUrl: config.databaseUrl });
  const generationId = randomUUID();
  const inventoryRunId = randomUUID();
  const syntheticBody = new TextEncoder().encode(
    JSON.stringify({
      id: SYNTHETIC_ID,
      modified: '2026-01-01T00:00:00Z',
      summary: `Synthetic composition advisory ${generationId}`,
      affected: [],
    }),
  );
  const syntheticSha = createHash('sha256').update(syntheticBody).digest('hex');
  let host: ReturnType<typeof createOsvAdvisoryParserHost> | undefined;

  beforeAll(async () => {
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
  });

  afterAll(async () => {
    if (host !== undefined) {
      await host.shutdown();
    }
  });

  it('attaches, parses, persists membership, and reconciles without activating or contacting GCS', async () => {
    const listed = createOsvListedObjectObservation({
      objectKey: SYNTHETIC_KEY,
      generation: SYNTHETIC_GENERATION,
      declaredSizeBytes: syntheticBody.byteLength,
    });
    expect(listed.ok).toBe(true);
    if (!listed.ok) {
      return;
    }
    const persistence = createOsvAcquisitionPersistence(prisma);
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
    const orchestrator = createOsvDisabledAcquisitionOrchestrator({
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
            sourceIdentifier: 'github_advisory_database',
            providerObjectKeyDigest: digestOsvProviderObjectKey(SYNTHETIC_KEY),
            providerObjectKey: SYNTHETIC_KEY,
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
    });

    const result = await orchestrator.processBoundedCandidateGeneration({
      policyIdentifier: OSV_DISABLED_ACQUISITION_ORCHESTRATION_POLICY_IDENTIFIER,
      catalogGenerationId: generationId,
      inventoryRunId,
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
      inventoryCompletenessClaim: 'complete_comparable_inventory',
      observations: [listed.value],
      createdAt: TS,
      retrievedAt: TS,
      signal: new AbortController().signal,
    });

    expect(result.listingExecuted).toBe(false);
    expect(result.automaticRetryExecuted).toBe(false);
    expect(result.activatesCatalog).toBe(false);
    expect(result.authorizesMatching).toBe(false);
    expect(result.createsFinding).toBe(false);
    expect(result.workItems[0]?.state).toBe('complete');
    expect(result.workItems[0]?.membershipCreated).toBe(true);
    expect(result.candidateReadiness).toBe('ready_for_activation');
    expect(result.lifecycleState).toBe('ready_for_activation');

    const activations = await prisma.osvActivationRecord.findMany({
      where: { candidateGenerationId: generationId },
    });
    expect(activations).toEqual([]);
    const pointers = await prisma.osvActiveCatalogPointer.findMany({
      where: { generationId },
    });
    expect(pointers).toEqual([]);
  }, 60_000);
});
