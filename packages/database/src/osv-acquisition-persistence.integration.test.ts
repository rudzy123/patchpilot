import { randomUUID } from 'node:crypto';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { PrismaClient } from '@prisma/client';
import {
  OSV_ACTIVATION_REASON_CODE,
  OSV_ADVISORY_PARSER_PROTOCOL_IDENTIFIER,
  OSV_ADVISORY_PARSER_RESOURCE_POLICY_IDENTIFIER,
  OSV_ADVISORY_PARSER_SCHEMA_REVISION_IDENTIFIER,
  OSV_CATALOG_VERSION_SET_V1,
  OSV_ELIGIBLE_BODY_SCOPE_IDENTIFIER,
  OSV_GCS_LISTING_PROTOCOL_VERSION,
  OSV_INVENTORY_PASS_COUNT_V1,
  OSV_INVENTORY_SCOPE_IDENTIFIER,
  OSV_PARSED_ADVISORY_DOCUMENT_IDENTIFIER,
  OSV_PROVIDER_IDENTIFIER,
  OSV_SCHEMA_COMMIT_SHA,
  OSV_SNAPSHOT_CONTENT_ENCODING,
  OSV_SNAPSHOT_CONTENT_TYPE,
  OSV_SOURCE_LICENSE_REGISTRY_IDENTIFIER,
  OSV_TRANSPORT_POLICY_VERSION,
  createOsvAcquisitionCompleteness,
  createOsvActivationRequest,
  createOsvCatalogGeneration,
  createOsvFinalObjectLocator,
  createOsvInventoryClassificationCounts,
  createOsvInventoryObjectObservation,
  createOsvInventoryPrefixPass,
  createOsvInventoryRun,
  createOsvMatchingCompleteness,
  createOsvObjectAttachment,
  createOsvParsedAdvisoryRevision,
  createOsvParserAttempt,
  createOsvProviderBodySnapshot,
  createOsvProviderGenerationIdentity,
  createOsvProviderObjectIdentity,
  createOsvQuarantineRecord,
  createOsvTemporaryObjectLocator,
  fingerprintOsvCatalogScope,
  reconcileOsvGenerationCounts,
  transitionOsvCatalogGeneration,
  type OsvCatalogGeneration,
  type OsvIdempotencyResult,
  type OsvPersistenceResult,
} from '@patchpilot/vulnerability-intelligence';

import { createOsvAcquisitionPersistence } from './osv-acquisition-persistence.js';
import {
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
} from './integration-database.js';

const TS = '2026-09-04T18:00:00.000Z';
const TS_LATER = '2026-09-04T18:05:00.000Z';
const SHA_A = 'a'.repeat(64);
const SHA_B = 'b'.repeat(64);
const SHA_C = 'c'.repeat(64);
const SCOPE = fingerprintOsvCatalogScope(OSV_CATALOG_VERSION_SET_V1);
const KEY = 'npm/GHSA-aaaa-bbbb-cccc.json';

type Adapters = ReturnType<typeof createOsvAcquisitionPersistence>;

function requireValue<T>(result: OsvPersistenceResult<T>, label: string): T {
  if (!result.ok) {
    throw new Error(`${label}: ${result.code}`);
  }
  return result.value;
}

function requireIdem(result: OsvPersistenceResult<OsvIdempotencyResult>, label: string) {
  return requireValue(result, label);
}

function completenessBundle(generationId: string, status: 'not_started' | 'complete') {
  const requiredCount = 0;
  const observedCount = 0;
  const dimension = (name: 'inventory' | 'eligible_body' | 'parser' | 'parsed_catalog') =>
    requireValue(
      createOsvAcquisitionCompleteness({
        dimension: name,
        status,
        catalogGenerationId: generationId,
        requiredCount,
        observedCount,
        discrepancyCodes: [],
      }),
      name,
    );
  return {
    inventory: dimension('inventory'),
    eligibleBody: dimension('eligible_body'),
    parser: dimension('parser'),
    parsedCatalog: dimension('parsed_catalog'),
    matching: requireValue(
      createOsvMatchingCompleteness({
        dimension: 'matching',
        status: 'not_in_scope',
        catalogGenerationId: generationId,
      }),
      'matching',
    ),
  };
}

function plannedGeneration(id: string): OsvCatalogGeneration {
  return requireValue(
    createOsvCatalogGeneration({
      id,
      versionSet: OSV_CATALOG_VERSION_SET_V1,
      lifecycleState: 'planned',
      completeness: completenessBundle(id, 'not_started'),
      version: 1,
      createdAt: TS,
      readyAt: null,
      activatedAt: null,
      supersededAt: null,
      failedAt: null,
      cancelledAt: null,
      quarantinedAt: null,
    }),
    'planned generation',
  );
}

function emptyReconciliation(generationId: string) {
  return requireValue(
    reconcileOsvGenerationCounts({
      catalogGenerationId: generationId,
      acceptedListedCount: 0,
      eligibleCount: 0,
      ineligibleCount: 0,
      legalReviewCount: 0,
      unknownCount: 0,
      ambiguousCount: 0,
      listingRejectedCount: 0,
      attachedEligibleSnapshotCount: 0,
      missingEligibleSnapshotCount: 0,
      nonEligibleSnapshotCount: 0,
      parserSuccessCount: 0,
      parserFailureCount: 0,
      quarantinedSnapshotCount: 0,
      acceptedRevisionCount: 0,
      withdrawnRevisionCount: 0,
      membershipCount: 0,
      providerAbsentCount: 0,
      immutableConflictCount: 0,
      blockingQuarantineCount: 0,
      failClosedRetrievedBodyCount: 0,
      pinMismatchCount: 0,
    }),
    'reconciliation',
  );
}

async function seedReadyGeneration(adapters: Adapters, id: string): Promise<OsvCatalogGeneration> {
  const planned = plannedGeneration(id);
  requireIdem(await adapters.catalogGenerations.createPlanned(planned), 'create planned');
  const acquiring = requireValue(
    transitionOsvCatalogGeneration(planned, { type: 'start_acquiring', occurredAt: TS }),
    'acquiring',
  );
  requireIdem(
    await adapters.catalogGenerations.compareAndSetLifecycle(acquiring, 1),
    'cas acquiring',
  );
  const ready = requireValue(
    transitionOsvCatalogGeneration(acquiring, {
      type: 'mark_ready_for_activation',
      occurredAt: TS,
      completeness: completenessBundle(id, 'complete'),
      reconciliation: emptyReconciliation(id),
    }),
    'ready',
  );
  requireIdem(
    await adapters.reconciliation.freezeReadyGeneration({
      generation: ready,
      reconciliation: emptyReconciliation(id),
      expectedVersion: 2,
    }),
    'freeze',
  );
  const stored = requireValue(await adapters.catalogGenerations.loadById(id), 'seed load');
  if (stored.lifecycleState !== 'ready_for_activation') {
    throw new Error(`seed lifecycle ${stored.lifecycleState}`);
  }
  return stored;
}

async function race<T>(left: () => Promise<T>, right: () => Promise<T>): Promise<[T, T]> {
  let release!: () => void;
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  const pending = [
    (async () => {
      await gate;
      return left();
    })(),
    (async () => {
      await gate;
      return right();
    })(),
  ] as const;
  release();
  return Promise.all(pending);
}

describe('OSV acquisition PostgreSQL adapters', { timeout: 120_000 }, () => {
  let databaseName: string;
  let admin: PrismaClient;
  let prisma: PrismaClient;
  let adapters: Adapters;

  beforeAll(async () => {
    const ephemeral = await createEphemeralDatabase('it');
    databaseName = ephemeral.databaseName;
    admin = ephemeral.admin;
    await deployMigrations(ephemeral.databaseUrl);
    prisma = new PrismaClient({
      datasources: { db: { url: ephemeral.databaseUrl } },
    });
    adapters = createOsvAcquisitionPersistence(prisma);
  });

  afterAll(async () => {
    if (prisma !== undefined) {
      await prisma.$disconnect();
    }
    if (admin !== undefined && databaseName !== undefined) {
      await dropEphemeralDatabase(admin, databaseName);
    }
  });

  it('constructs adapters without seeding an active catalog', async () => {
    expect(adapters.catalogGenerations).toBeDefined();
    expect(adapters.activePointer).toBeDefined();
    expect(await prisma.osvActiveCatalogPointer.count()).toBe(0);
    expect(await prisma.osvActivationRecord.count()).toBe(0);
    expect(await prisma.finding.count()).toBe(0);
  });

  it('creates a planned generation and treats identical repeats as already_applied', async () => {
    const id = randomUUID();
    const generation = plannedGeneration(id);
    expect(
      requireIdem(await adapters.catalogGenerations.createPlanned(generation), 'first').status,
    ).toBe('created');
    expect(
      requireIdem(await adapters.catalogGenerations.createPlanned(generation), 'repeat').status,
    ).toBe('already_applied');
    const loaded = requireValue(await adapters.catalogGenerations.loadById(id), 'load');
    expect(loaded.scopeFingerprint).toBe(SCOPE);
    expect(loaded.lifecycleState).toBe('planned');
  });

  it('rejects skipped transitions from planned to ready_for_activation', async () => {
    const id = randomUUID();
    const planned = plannedGeneration(id);
    requireIdem(await adapters.catalogGenerations.createPlanned(planned), 'planned');
    const skipped = transitionOsvCatalogGeneration(planned, {
      type: 'mark_ready_for_activation',
      occurredAt: TS,
      completeness: completenessBundle(id, 'complete'),
      reconciliation: emptyReconciliation(id),
    });
    expect(skipped.ok).toBe(false);
    if (!skipped.ok) {
      expect(skipped.code).toBe('skipped_transition');
    }
    const readyDirect = await adapters.catalogGenerations.compareAndSetLifecycle(
      requireValue(
        createOsvCatalogGeneration({
          id,
          versionSet: OSV_CATALOG_VERSION_SET_V1,
          lifecycleState: 'ready_for_activation',
          completeness: completenessBundle(id, 'complete'),
          version: 2,
          createdAt: TS,
          readyAt: TS,
          activatedAt: null,
          supersededAt: null,
          failedAt: null,
          cancelledAt: null,
          quarantinedAt: null,
        }),
        'direct ready',
      ),
      1,
    );
    expect(readyDirect.ok).toBe(false);
    if (!readyDirect.ok) {
      expect(readyDirect.code).toBe('skipped_transition');
    }
  });

  it('records inventory observations idempotently and detects immutable conflicts', async () => {
    const generationId = randomUUID();
    requireIdem(
      await adapters.catalogGenerations.createPlanned(plannedGeneration(generationId)),
      'gen',
    );
    const runId = randomUUID();
    const running = requireValue(
      createOsvInventoryRun({
        id: runId,
        catalogGenerationId: generationId,
        state: 'running',
        inventoryScope: OSV_INVENTORY_SCOPE_IDENTIFIER,
        listingProtocol: OSV_GCS_LISTING_PROTOCOL_VERSION,
        transportPolicy: OSV_TRANSPORT_POLICY_VERSION,
        sourceLicenseRegistry: OSV_SOURCE_LICENSE_REGISTRY_IDENTIFIER,
        passCount: OSV_INVENTORY_PASS_COUNT_V1,
        startedAt: TS,
        completedAt: null,
        acceptedListedCount: 0,
        listingRejectedCount: 0,
        classificationCounts: requireValue(
          createOsvInventoryClassificationCounts({
            eligible: 0,
            ineligible: 0,
            legalReview: 0,
            unknown: 0,
            ambiguous: 0,
          }),
          'counts',
        ),
        convergence: 'not_comparable',
        prefixPasses: [],
      }),
      'run',
    );
    expect(requireIdem(await adapters.inventory.createRun(running), 'create run').status).toBe(
      'created',
    );
    expect(requireIdem(await adapters.inventory.createRun(running), 'repeat run').status).toBe(
      'already_applied',
    );
    const pass = requireValue(
      createOsvInventoryPrefixPass({
        inventoryRunId: runId,
        providerPrefix: 'npm/',
        passNumber: 1,
        listingProtocol: OSV_GCS_LISTING_PROTOCOL_VERSION,
        transportPolicy: OSV_TRANSPORT_POLICY_VERSION,
        sourceLicenseRegistry: OSV_SOURCE_LICENSE_REGISTRY_IDENTIFIER,
        inventoryScope: OSV_INVENTORY_SCOPE_IDENTIFIER,
        pageCount: 1,
        responseByteCount: 12,
        acceptedItemCount: 0,
        listingRejectedCount: 0,
        terminalPageObserved: true,
        completeness: 'complete',
      }),
      'pass',
    );
    expect(requireIdem(await adapters.inventory.recordPrefixPass(pass), 'pass').status).toBe(
      'created',
    );
    expect(requireIdem(await adapters.inventory.recordPrefixPass(pass), 'pass repeat').status).toBe(
      'already_applied',
    );
    const observation = requireValue(
      createOsvInventoryObjectObservation({
        inventoryRunId: runId,
        providerObjectKeyDigest: SHA_A,
        providerGeneration: '1',
        providerPrefix: 'npm/',
        declaredByteCount: 1,
        classificationStatus: 'eligible',
        sourceIdentifier: 'github_advisory_database',
        etagMetadata: null,
        md5HashMetadata: null,
      }),
      'observation',
    );
    expect(requireIdem(await adapters.inventory.recordObservation(observation), 'obs').status).toBe(
      'created',
    );
    expect(
      requireIdem(await adapters.inventory.recordObservation(observation), 'obs repeat').status,
    ).toBe('already_applied');
    const conflict = await adapters.inventory.recordObservation(
      requireValue(
        createOsvInventoryObjectObservation({
          inventoryRunId: runId,
          providerObjectKeyDigest: SHA_A,
          providerGeneration: '1',
          providerPrefix: 'npm/',
          declaredByteCount: 2,
          classificationStatus: 'eligible',
          sourceIdentifier: 'github_advisory_database',
          etagMetadata: null,
          md5HashMetadata: null,
        }),
        'conflict obs',
      ),
    );
    expect(conflict.ok).toBe(true);
    if (conflict.ok) {
      expect(conflict.value.status).toBe('immutable_conflict');
    }
  });

  it('reserves provider objects and generations with immutable conflict detection', async () => {
    const identity = requireValue(
      createOsvProviderObjectIdentity({
        providerIdentifier: OSV_PROVIDER_IDENTIFIER,
        providerObjectKey: KEY,
      }),
      'object identity',
    );
    expect(requireIdem(await adapters.providerObjects.insertOnce(identity), 'object').status).toBe(
      'created',
    );
    expect(
      requireIdem(await adapters.providerObjects.insertOnce(identity), 'object repeat').status,
    ).toBe('already_applied');
    const stored = await prisma.osvProviderObject.findUnique({
      where: {
        providerIdentifier_providerObjectKeyDigest: {
          providerIdentifier: OSV_PROVIDER_IDENTIFIER,
          providerObjectKeyDigest: identity.providerObjectKeyDigest,
        },
      },
    });
    expect(stored).not.toBeNull();
    if (stored === null) {
      return;
    }
    const generation = requireValue(
      createOsvProviderGenerationIdentity({
        providerObjectId: stored.id,
        providerObjectKeyDigest: identity.providerObjectKeyDigest,
        providerGeneration: '42',
      }),
      'generation',
    );
    const [left, right] = await race(
      () => adapters.bodySnapshots.reserveImmutableGeneration(generation),
      () => adapters.bodySnapshots.reserveImmutableGeneration(generation),
    );
    const statuses = [requireIdem(left, 'left').status, requireIdem(right, 'right').status].sort();
    expect(statuses).toEqual(['already_applied', 'created']);
    const conflicting = requireValue(
      createOsvProviderGenerationIdentity({
        providerObjectId: stored.id,
        providerObjectKeyDigest: SHA_B,
        providerGeneration: '42',
      }),
      'conflict generation',
    );
    const conflict = await adapters.bodySnapshots.reserveImmutableGeneration(conflicting);
    expect(conflict.ok).toBe(true);
    if (conflict.ok) {
      expect(conflict.value.status).toBe('immutable_conflict');
    }
  });

  it('attaches snapshot metadata without body bytes and rejects conflicting hashes', async () => {
    const identity = requireValue(
      createOsvProviderObjectIdentity({
        providerIdentifier: OSV_PROVIDER_IDENTIFIER,
        providerObjectKey: `npm/GHSA-bbbb-cccc-dddd.json`,
      }),
      'object',
    );
    requireIdem(await adapters.providerObjects.insertOnce(identity), 'insert object');
    const stored = await prisma.osvProviderObject.findUniqueOrThrow({
      where: {
        providerIdentifier_providerObjectKeyDigest: {
          providerIdentifier: OSV_PROVIDER_IDENTIFIER,
          providerObjectKeyDigest: identity.providerObjectKeyDigest,
        },
      },
    });
    const generation = requireValue(
      createOsvProviderGenerationIdentity({
        providerObjectId: stored.id,
        providerObjectKeyDigest: identity.providerObjectKeyDigest,
        providerGeneration: '7',
      }),
      'generation',
    );
    requireIdem(await adapters.bodySnapshots.reserveImmutableGeneration(generation), 'reserve');
    const uploadId = randomUUID();
    const stagedLocator = requireValue(
      createOsvTemporaryObjectLocator({ storageKind: 'advisory_body', uploadId }),
      'tmp locator',
    );
    const stagedAttachment = requireValue(
      createOsvObjectAttachment({
        id: randomUUID(),
        locator: stagedLocator,
        contentSha256: SHA_A,
        byteCount: 8,
        contentType: OSV_SNAPSHOT_CONTENT_TYPE,
        contentEncoding: OSV_SNAPSHOT_CONTENT_ENCODING,
        state: 'staged',
      }),
      'staged attachment',
    );
    const snapshotId = randomUUID();
    const staged = requireValue(
      createOsvProviderBodySnapshot({
        id: snapshotId,
        providerObjectId: stored.id,
        providerObjectKeyDigest: identity.providerObjectKeyDigest,
        providerGeneration: '7',
        contentSha256: SHA_A,
        receivedByteCount: 8,
        declaredByteCount: 8,
        contentType: OSV_SNAPSHOT_CONTENT_TYPE,
        contentEncoding: OSV_SNAPSHOT_CONTENT_ENCODING,
        sourceIdentifier: 'github_advisory_database',
        registryIdentifier: OSV_SOURCE_LICENSE_REGISTRY_IDENTIFIER,
        eligibleBodyScope: OSV_ELIGIBLE_BODY_SCOPE_IDENTIFIER,
        transportPolicy: OSV_TRANSPORT_POLICY_VERSION,
        retrievedAt: TS,
        attachment: stagedAttachment,
        classificationStatus: 'eligible',
      }),
      'staged snapshot',
    );
    expect(
      requireIdem(await adapters.bodySnapshots.attachImmutableSnapshot(staged), 'stage').status,
    ).toBe('created');
    const finalLocator = requireValue(
      createOsvFinalObjectLocator({ storageKind: 'advisory_body', contentSha256: SHA_A }),
      'final locator',
    );
    const attached = requireValue(
      createOsvObjectAttachment({
        id: stagedAttachment.identity.value,
        locator: finalLocator,
        contentSha256: SHA_A,
        byteCount: 8,
        contentType: OSV_SNAPSHOT_CONTENT_TYPE,
        contentEncoding: OSV_SNAPSHOT_CONTENT_ENCODING,
        state: 'attached',
      }),
      'attached',
    );
    const finalized = requireValue(
      createOsvProviderBodySnapshot({
        id: snapshotId,
        providerObjectId: stored.id,
        providerObjectKeyDigest: identity.providerObjectKeyDigest,
        providerGeneration: '7',
        contentSha256: SHA_A,
        receivedByteCount: 8,
        declaredByteCount: 8,
        contentType: OSV_SNAPSHOT_CONTENT_TYPE,
        contentEncoding: OSV_SNAPSHOT_CONTENT_ENCODING,
        sourceIdentifier: 'github_advisory_database',
        registryIdentifier: OSV_SOURCE_LICENSE_REGISTRY_IDENTIFIER,
        eligibleBodyScope: OSV_ELIGIBLE_BODY_SCOPE_IDENTIFIER,
        transportPolicy: OSV_TRANSPORT_POLICY_VERSION,
        retrievedAt: TS,
        attachment: attached,
        classificationStatus: 'eligible',
      }),
      'final snapshot',
    );
    expect(
      requireIdem(await adapters.bodySnapshots.attachImmutableSnapshot(finalized), 'attach').status,
    ).toBe('created');
    expect(
      requireIdem(await adapters.bodySnapshots.attachImmutableSnapshot(finalized), 'attach repeat')
        .status,
    ).toBe('already_applied');
  });

  it('atomically attaches a parsed revision to a successful attempt and rolls back failed attempts', async () => {
    const identity = requireValue(
      createOsvProviderObjectIdentity({
        providerIdentifier: OSV_PROVIDER_IDENTIFIER,
        providerObjectKey: 'npm/GHSA-cccc-dddd-eeee.json',
      }),
      'object',
    );
    requireIdem(await adapters.providerObjects.insertOnce(identity), 'object');
    const stored = await prisma.osvProviderObject.findUniqueOrThrow({
      where: {
        providerIdentifier_providerObjectKeyDigest: {
          providerIdentifier: OSV_PROVIDER_IDENTIFIER,
          providerObjectKeyDigest: identity.providerObjectKeyDigest,
        },
      },
    });
    const generation = requireValue(
      createOsvProviderGenerationIdentity({
        providerObjectId: stored.id,
        providerObjectKeyDigest: identity.providerObjectKeyDigest,
        providerGeneration: '9',
      }),
      'generation',
    );
    requireIdem(await adapters.bodySnapshots.reserveImmutableGeneration(generation), 'reserve');
    const locator = requireValue(
      createOsvFinalObjectLocator({ storageKind: 'advisory_body', contentSha256: SHA_A }),
      'locator',
    );
    const attachment = requireValue(
      createOsvObjectAttachment({
        id: randomUUID(),
        locator,
        contentSha256: SHA_A,
        byteCount: 4,
        contentType: OSV_SNAPSHOT_CONTENT_TYPE,
        contentEncoding: OSV_SNAPSHOT_CONTENT_ENCODING,
        state: 'attached',
      }),
      'attachment',
    );
    const snapshotId = randomUUID();
    const snapshot = requireValue(
      createOsvProviderBodySnapshot({
        id: snapshotId,
        providerObjectId: stored.id,
        providerObjectKeyDigest: identity.providerObjectKeyDigest,
        providerGeneration: '9',
        contentSha256: SHA_A,
        receivedByteCount: 4,
        declaredByteCount: 4,
        contentType: OSV_SNAPSHOT_CONTENT_TYPE,
        contentEncoding: OSV_SNAPSHOT_CONTENT_ENCODING,
        sourceIdentifier: 'github_advisory_database',
        registryIdentifier: OSV_SOURCE_LICENSE_REGISTRY_IDENTIFIER,
        eligibleBodyScope: OSV_ELIGIBLE_BODY_SCOPE_IDENTIFIER,
        transportPolicy: OSV_TRANSPORT_POLICY_VERSION,
        retrievedAt: TS,
        attachment,
        classificationStatus: 'eligible',
      }),
      'snapshot',
    );
    requireIdem(await adapters.bodySnapshots.attachImmutableSnapshot(snapshot), 'snapshot');
    const failedAttempt = requireValue(
      createOsvParserAttempt({
        id: randomUUID(),
        snapshotId,
        protocolIdentifier: OSV_ADVISORY_PARSER_PROTOCOL_IDENTIFIER,
        schemaRevision: OSV_ADVISORY_PARSER_SCHEMA_REVISION_IDENTIFIER,
        schemaCommit: OSV_SCHEMA_COMMIT_SHA,
        resourcePolicy: OSV_ADVISORY_PARSER_RESOURCE_POLICY_IDENTIFIER,
        registryIdentifier: OSV_SOURCE_LICENSE_REGISTRY_IDENTIFIER,
        sourceIdentifier: 'github_advisory_database',
        inputSha256: SHA_A,
        inputByteCount: 4,
        attemptNumber: 1,
        resultState: 'failed',
        failureKind: 'schema_validation_failed',
        warningCodes: [],
        workerLifecycleOutcome: 'terminated',
        parsedRevisionId: null,
        correlationId: randomUUID(),
        startedAt: TS,
        completedAt: TS_LATER,
      }),
      'failed attempt',
    );
    requireIdem(await adapters.parserAttempts.recordAttempt(failedAttempt), 'failed attempt');
    const successId = randomUUID();
    const succeeded = requireValue(
      createOsvParserAttempt({
        id: successId,
        snapshotId,
        protocolIdentifier: OSV_ADVISORY_PARSER_PROTOCOL_IDENTIFIER,
        schemaRevision: OSV_ADVISORY_PARSER_SCHEMA_REVISION_IDENTIFIER,
        schemaCommit: OSV_SCHEMA_COMMIT_SHA,
        resourcePolicy: OSV_ADVISORY_PARSER_RESOURCE_POLICY_IDENTIFIER,
        registryIdentifier: OSV_SOURCE_LICENSE_REGISTRY_IDENTIFIER,
        sourceIdentifier: 'github_advisory_database',
        inputSha256: SHA_A,
        inputByteCount: 4,
        attemptNumber: 2,
        resultState: 'succeeded',
        failureKind: null,
        warningCodes: [],
        workerLifecycleOutcome: 'reused',
        parsedRevisionId: null,
        correlationId: randomUUID(),
        startedAt: TS,
        completedAt: TS_LATER,
      }),
      'success attempt',
    );
    requireIdem(await adapters.parserAttempts.recordAttempt(succeeded), 'success attempt');
    const documentLocator = requireValue(
      createOsvFinalObjectLocator({ storageKind: 'parsed_advisory', contentSha256: SHA_B }),
      'doc locator',
    );
    const documentAttachment = requireValue(
      createOsvObjectAttachment({
        id: randomUUID(),
        locator: documentLocator,
        contentSha256: SHA_B,
        byteCount: 4,
        contentType: OSV_SNAPSHOT_CONTENT_TYPE,
        contentEncoding: OSV_SNAPSHOT_CONTENT_ENCODING,
        state: 'attached',
      }),
      'doc attachment',
    );
    const revisionId = randomUUID();
    const revision = requireValue(
      createOsvParsedAdvisoryRevision({
        id: revisionId,
        snapshotId,
        parserAttemptId: successId,
        providerObjectId: stored.id,
        providerObjectKeyDigest: identity.providerObjectKeyDigest,
        providerGeneration: '9',
        documentIdentifier: OSV_PARSED_ADVISORY_DOCUMENT_IDENTIFIER,
        protocolIdentifier: OSV_ADVISORY_PARSER_PROTOCOL_IDENTIFIER,
        schemaRevision: OSV_ADVISORY_PARSER_SCHEMA_REVISION_IDENTIFIER,
        schemaCommit: OSV_SCHEMA_COMMIT_SHA,
        resourcePolicy: OSV_ADVISORY_PARSER_RESOURCE_POLICY_IDENTIFIER,
        registryIdentifier: OSV_SOURCE_LICENSE_REGISTRY_IDENTIFIER,
        sourceIdentifier: 'github_advisory_database',
        contentSha256: SHA_A,
        parsedOutputSha256: SHA_B,
        parsedTopLevelOsvId: 'SYNTH0',
        publishedAt: null,
        modifiedAt: null,
        withdrawnAt: null,
        structuralCounts: {
          aliasCount: 0,
          relatedCount: 0,
          affectedPackageCount: 0,
          rangeCount: 0,
          eventCount: 0,
          explicitVersionCount: 0,
          referenceCount: 0,
          creditCount: 0,
          severityCount: 0,
        },
        normalizationState: 'uninterpreted_structural',
        documentAttachment,
      }),
      'revision',
    );
    const failedAttach = await adapters.parsedRevisions.attachRevision(
      requireValue(
        createOsvParsedAdvisoryRevision({
          ...{
            id: randomUUID(),
            snapshotId,
            parserAttemptId: failedAttempt.identity.value,
            providerObjectId: stored.id,
            providerObjectKeyDigest: identity.providerObjectKeyDigest,
            providerGeneration: '9',
            documentIdentifier: OSV_PARSED_ADVISORY_DOCUMENT_IDENTIFIER,
            protocolIdentifier: OSV_ADVISORY_PARSER_PROTOCOL_IDENTIFIER,
            schemaRevision: OSV_ADVISORY_PARSER_SCHEMA_REVISION_IDENTIFIER,
            schemaCommit: OSV_SCHEMA_COMMIT_SHA,
            resourcePolicy: OSV_ADVISORY_PARSER_RESOURCE_POLICY_IDENTIFIER,
            registryIdentifier: OSV_SOURCE_LICENSE_REGISTRY_IDENTIFIER,
            sourceIdentifier: 'github_advisory_database',
            contentSha256: SHA_A,
            parsedOutputSha256: SHA_B,
            parsedTopLevelOsvId: 'SYNTH0',
            publishedAt: null,
            modifiedAt: null,
            withdrawnAt: null,
            structuralCounts: {
              aliasCount: 0,
              relatedCount: 0,
              affectedPackageCount: 0,
              rangeCount: 0,
              eventCount: 0,
              explicitVersionCount: 0,
              referenceCount: 0,
              creditCount: 0,
              severityCount: 0,
            },
            normalizationState: 'uninterpreted_structural',
            documentAttachment: requireValue(
              createOsvObjectAttachment({
                id: randomUUID(),
                locator: documentLocator,
                contentSha256: SHA_B,
                byteCount: 4,
                contentType: OSV_SNAPSHOT_CONTENT_TYPE,
                contentEncoding: OSV_SNAPSHOT_CONTENT_ENCODING,
                state: 'attached',
              }),
              'failed doc',
            ),
          },
        }),
        'failed revision',
      ),
    );
    expect(failedAttach.ok).toBe(false);
    expect(await prisma.osvParsedAdvisoryRevision.count({ where: { snapshotId } })).toBe(0);
    const [left, right] = await race(
      () => adapters.parsedRevisions.attachRevision(revision),
      () => adapters.parsedRevisions.attachRevision(revision),
    );
    expect(left.ok).toBe(true);
    expect(right.ok).toBe(true);
    if (left.ok && right.ok) {
      expect([left.value.status, right.value.status].sort()).toEqual([
        'already_applied',
        'created',
      ]);
    }
    expect(await prisma.osvParsedAdvisoryRevision.count({ where: { snapshotId } })).toBe(1);
    expect(
      await prisma.osvObjectAttachment.count({ where: { id: documentAttachment.identity.value } }),
    ).toBe(1);
    const linked = await prisma.osvParserAttempt.findUniqueOrThrow({ where: { id: successId } });
    expect(linked.parsedRevisionId).toBe(revisionId);
    const failedRow = await prisma.osvParserAttempt.findUniqueOrThrow({
      where: { id: failedAttempt.identity.value },
    });
    expect(failedRow.parsedRevisionId).toBeNull();
    const repeated = await adapters.parsedRevisions.attachRevision(revision);
    expect(repeated.ok).toBe(true);
    if (repeated.ok) {
      expect(repeated.value.status).toBe('already_applied');
    }
    const conflictingAttachment = requireValue(
      createOsvObjectAttachment({
        id: randomUUID(),
        locator: requireValue(
          createOsvFinalObjectLocator({ storageKind: 'parsed_advisory', contentSha256: SHA_C }),
          'conflict locator',
        ),
        contentSha256: SHA_C,
        byteCount: 4,
        contentType: OSV_SNAPSHOT_CONTENT_TYPE,
        contentEncoding: OSV_SNAPSHOT_CONTENT_ENCODING,
        state: 'attached',
      }),
      'conflict attachment',
    );
    const conflicting = requireValue(
      createOsvParsedAdvisoryRevision({
        id: revisionId,
        snapshotId,
        parserAttemptId: successId,
        providerObjectId: stored.id,
        providerObjectKeyDigest: identity.providerObjectKeyDigest,
        providerGeneration: '9',
        documentIdentifier: OSV_PARSED_ADVISORY_DOCUMENT_IDENTIFIER,
        protocolIdentifier: OSV_ADVISORY_PARSER_PROTOCOL_IDENTIFIER,
        schemaRevision: OSV_ADVISORY_PARSER_SCHEMA_REVISION_IDENTIFIER,
        schemaCommit: OSV_SCHEMA_COMMIT_SHA,
        resourcePolicy: OSV_ADVISORY_PARSER_RESOURCE_POLICY_IDENTIFIER,
        registryIdentifier: OSV_SOURCE_LICENSE_REGISTRY_IDENTIFIER,
        sourceIdentifier: 'github_advisory_database',
        contentSha256: SHA_A,
        parsedOutputSha256: SHA_C,
        parsedTopLevelOsvId: 'SYNTH0',
        publishedAt: null,
        modifiedAt: null,
        withdrawnAt: null,
        structuralCounts: {
          aliasCount: 0,
          relatedCount: 0,
          affectedPackageCount: 0,
          rangeCount: 0,
          eventCount: 0,
          explicitVersionCount: 0,
          referenceCount: 0,
          creditCount: 0,
          severityCount: 0,
        },
        normalizationState: 'uninterpreted_structural',
        documentAttachment: conflictingAttachment,
      }),
      'conflicting revision',
    );
    const conflicted = await adapters.parsedRevisions.attachRevision(conflicting);
    expect(conflicted.ok).toBe(true);
    if (conflicted.ok) {
      expect(conflicted.value.status).toBe('immutable_conflict');
    }
    const storedRevision = await prisma.osvParsedAdvisoryRevision.findUniqueOrThrow({
      where: { id: revisionId },
    });
    expect(storedRevision.parsedOutputSha256).toBe(SHA_B);
    expect(await prisma.osvParsedAdvisoryRevision.count({ where: { snapshotId } })).toBe(1);
  });

  it('activates the first generation with a null previous pointer and rejects cross-scope candidates', async () => {
    const firstId = randomUUID();
    const ready = await seedReadyGeneration(adapters, firstId);
    const request = requireValue(
      createOsvActivationRequest({
        id: randomUUID(),
        scopeFingerprint: SCOPE,
        candidateGenerationId: firstId,
        expectedPointerVersion: 1,
        versionSet: OSV_CATALOG_VERSION_SET_V1,
        reconciliation: emptyReconciliation(firstId),
        activatedAt: TS,
        reasonCode: OSV_ACTIVATION_REASON_CODE,
      }),
      'activation request',
    );
    const activated = requireValue(
      await adapters.activePointer.activateReadyGeneration({ request, candidate: ready }),
      'activate',
    );
    expect(activated.outcome).toBe('activated');
    expect(activated.previousGenerationId).toBeNull();
    expect(activated.findingCreated).toBe(false);
    expect(activated.matchingTriggered).toBe(false);
    const pointer = requireValue(await adapters.activePointer.readCurrent(SCOPE), 'pointer');
    expect(pointer.generationId).toBe(firstId);
    expect(pointer.version).toBe(2);
    const replay = requireValue(
      await adapters.activePointer.activateReadyGeneration({ request, candidate: ready }),
      'replay',
    );
    expect(replay.outcome).toBe('already_active');
    expect(
      await prisma.osvActivationRecord.count({ where: { candidateGenerationId: firstId } }),
    ).toBe(1);

    const otherId = randomUUID();
    const other = plannedGeneration(otherId);
    requireIdem(await adapters.catalogGenerations.createPlanned(other), 'other planned');
    await prisma.osvCatalogGeneration.update({
      where: { id: otherId },
      data: { scopeFingerprint: 'c'.repeat(64) },
    });
    const cross = await adapters.activePointer.activateReadyGeneration({
      request: requireValue(
        createOsvActivationRequest({
          id: randomUUID(),
          scopeFingerprint: SCOPE,
          candidateGenerationId: otherId,
          expectedPointerVersion: pointer.version,
          versionSet: OSV_CATALOG_VERSION_SET_V1,
          reconciliation: emptyReconciliation(otherId),
          activatedAt: TS_LATER,
          reasonCode: OSV_ACTIVATION_REASON_CODE,
        }),
        'cross request',
      ),
      candidate: other,
    });
    expect(cross.ok).toBe(true);
    if (cross.ok) {
      expect(cross.value.outcome).toBe('version_mismatch');
    }
    expect(
      requireValue(await adapters.activePointer.readCurrent(SCOPE), 'unchanged').generationId,
    ).toBe(firstId);
    expect(
      await prisma.osvActivationRecord.count({ where: { candidateGenerationId: otherId } }),
    ).toBe(0);
  });

  it('supersedes a same-scope previous generation and rejects stale pointers and quarantine', async () => {
    const firstId = randomUUID();
    const first = await seedReadyGeneration(adapters, firstId);
    requireValue(
      await adapters.activePointer.activateReadyGeneration({
        request: requireValue(
          createOsvActivationRequest({
            id: randomUUID(),
            scopeFingerprint: SCOPE,
            candidateGenerationId: firstId,
            expectedPointerVersion: (await adapters.activePointer.readCurrent(SCOPE)).ok
              ? requireValue(await adapters.activePointer.readCurrent(SCOPE), 'v').version
              : 1,
            versionSet: OSV_CATALOG_VERSION_SET_V1,
            reconciliation: emptyReconciliation(firstId),
            activatedAt: TS,
            reasonCode: OSV_ACTIVATION_REASON_CODE,
          }),
          'first request',
        ),
        candidate: first,
      }),
      'first activate',
    );
    const pointer = requireValue(await adapters.activePointer.readCurrent(SCOPE), 'pointer');
    const secondId = randomUUID();
    const second = await seedReadyGeneration(adapters, secondId);
    const stale = await adapters.activePointer.activateReadyGeneration({
      request: requireValue(
        createOsvActivationRequest({
          id: randomUUID(),
          scopeFingerprint: SCOPE,
          candidateGenerationId: secondId,
          expectedPointerVersion: 1,
          versionSet: OSV_CATALOG_VERSION_SET_V1,
          reconciliation: emptyReconciliation(secondId),
          activatedAt: TS_LATER,
          reasonCode: OSV_ACTIVATION_REASON_CODE,
        }),
        'stale request',
      ),
      candidate: second,
    });
    expect(stale.ok).toBe(true);
    if (stale.ok) {
      expect(stale.value.outcome).toBe('stale_pointer');
    }
    requireIdem(
      await adapters.quarantine.recordQuarantine(
        requireValue(
          createOsvQuarantineRecord({
            id: randomUUID(),
            catalogGenerationId: secondId,
            providerObjectKeyDigest: null,
            snapshotId: null,
            parserAttemptId: null,
            revisionId: null,
            reasonCode: 'generation_content_conflict',
            originatingPhase: 'reconciliation',
            recordedAt: TS,
          }),
          'quarantine',
        ),
      ),
      'quarantine',
    );
    const blocked = await adapters.activePointer.activateReadyGeneration({
      request: requireValue(
        createOsvActivationRequest({
          id: randomUUID(),
          scopeFingerprint: SCOPE,
          candidateGenerationId: secondId,
          expectedPointerVersion: pointer.version,
          versionSet: OSV_CATALOG_VERSION_SET_V1,
          reconciliation: emptyReconciliation(secondId),
          activatedAt: TS_LATER,
          reasonCode: OSV_ACTIVATION_REASON_CODE,
        }),
        'blocked request',
      ),
      candidate: second,
    });
    expect(blocked.ok === false || (blocked.ok && blocked.value.outcome !== 'activated')).toBe(
      true,
    );
    expect(
      requireValue(await adapters.activePointer.readCurrent(SCOPE), 'still first').generationId,
    ).toBe(pointer.generationId);
  });

  it('runs concurrent identical generation transitions as one created and one already_applied', async () => {
    const id = randomUUID();
    const planned = plannedGeneration(id);
    requireIdem(await adapters.catalogGenerations.createPlanned(planned), 'planned');
    const acquiring = requireValue(
      transitionOsvCatalogGeneration(planned, { type: 'start_acquiring', occurredAt: TS }),
      'acquiring',
    );
    const [left, right] = await race(
      () => adapters.catalogGenerations.compareAndSetLifecycle(acquiring, 1),
      () => adapters.catalogGenerations.compareAndSetLifecycle(acquiring, 1),
    );
    const statuses = [requireIdem(left, 'left').status, requireIdem(right, 'right').status].sort();
    expect(statuses[0] === 'already_applied' || statuses[0] === 'created').toBe(true);
    expect(statuses[1] === 'already_applied' || statuses[1] === 'created').toBe(true);
    const loaded = requireValue(await adapters.catalogGenerations.loadById(id), 'loaded');
    expect(loaded.lifecycleState).toBe('acquiring');
    expect(loaded.version).toBe(2);
  });

  it('does not write Findings, Vulnerabilities, or tenant rows', async () => {
    expect(await prisma.finding.count()).toBe(0);
    expect(await prisma.findingObservation.count()).toBe(0);
    expect(await prisma.evidence.count()).toBe(0);
    expect(await prisma.riskCalculation.count()).toBe(0);
    expect(await prisma.vulnerability.count()).toBe(0);
    expect(await prisma.organization.count()).toBe(0);
  });
});
