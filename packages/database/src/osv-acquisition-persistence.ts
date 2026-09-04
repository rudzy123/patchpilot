/**
 * Session 11 Batch 5D PostgreSQL adapters for OSV acquisition persistence.
 *
 * Implements committed Batch 5B ports against the frozen Batch 5C schema.
 * No object storage, provider retrieval, synchronization, matching, or Findings.
 */

import { Prisma, type PrismaClient } from '@prisma/client';
import {
  OSV_CATALOG_VERSION_SET_V1,
  activationCompletenessGatesPass,
  compareOsvBodySnapshots,
  compareOsvParsedRevisions,
  compileOsvSynchronizationLease,
  createOsvAcquisitionRun,
  createOsvActivationRequest,
  createOsvActiveCatalogPointer,
  createOsvCatalogGeneration,
  createOsvFinalObjectLocator,
  createOsvIdempotencyResult,
  createOsvInventoryObjectObservation,
  createOsvInventoryRun,
  createOsvParsedAdvisoryRevision,
  createOsvParserAttempt,
  createOsvProviderBodySnapshot,
  createOsvProviderObjectIdentity,
  createOsvProviderPresenceObservation,
  createOsvQuarantineRecord,
  createOsvTemporaryObjectLocator,
  encodeOsvCatalogVersionSet,
  evaluateOsvCatalogActivation,
  isOsvActivationRequest,
  isOsvCatalogGeneration,
  isOsvInventoryObjectObservation,
  isOsvInventoryPrefixPass,
  isOsvInventoryRun,
  isOsvParsedAdvisoryRevision,
  isOsvParserAttempt,
  isOsvProviderBodySnapshot,
  isOsvProviderGenerationIdentity,
  isOsvProviderObjectIdentity,
  isOsvProviderPresenceObservation,
  isOsvQuarantineRecord,
  isOsvReconciliationResult,
  readOsvProviderObjectKeyForPersistence,
  reconcileOsvGenerationCounts,
  transitionOsvAttachmentState,
  type OsvAcquisitionRun,
  type OsvAcquisitionRunRepository,
  type OsvActivationRequest,
  type OsvActivationResult,
  type OsvActiveCatalogPointer,
  type OsvActiveCatalogPointerRepository,
  type OsvAdvisoryObjectStoragePort,
  type OsvCatalogGeneration,
  type OsvCatalogGenerationRepository,
  type OsvCatalogMembershipRepository,
  type OsvIdempotencyResult,
  type OsvInventoryPersistence,
  type OsvParsedAdvisoryRevision,
  type OsvParsedAdvisoryRevisionRepository,
  type OsvParserAttempt,
  type OsvParserAttemptRepository,
  type OsvPersistenceRejectionCode,
  type OsvPersistenceResult,
  type OsvPresenceObservationRepository,
  type OsvObjectAttachmentRepository,
  type OsvProviderBodySnapshot,
  type OsvProviderBodySnapshotRepository,
  type OsvProviderGenerationIdentity,
  type OsvProviderObjectIdentity,
  type OsvProviderObjectRepository,
  type OsvQuarantineRecord,
  type OsvQuarantineRepository,
  type OsvReconciliationRepository,
} from '@patchpilot/vulnerability-intelligence';

import {
  attachmentTransitionAllowed,
  catalogGenerationTransitionAllowed as graphAllowsCatalogTransition,
  activationPrerequisitesSatisfied,
} from './osv-acquisition-graphs.js';
import {
  isForeignKeyViolation,
  isSerializationConflict,
  isUniqueViolation,
  translateDatabaseFailure,
} from './osv-acquisition-errors.js';
import { SHA256_HEX, UUID_PATTERN } from './guards.js';
import {
  OsvAcquisitionMappingError,
  emptyCompletenessRows,
  familyToColumns,
  fromIsoUtc,
  mapAttachment,
  mapCatalogGeneration,
  mapInventoryRun,
  mapObservation,
  mapParsedRevision,
  mapParserAttempt,
  mapPointer,
  mapPresence,
  mapQuarantine,
  mapReconciliation,
  mapSnapshot,
  toIsoUtc,
  versionSetColumns,
} from './osv-acquisition-mappers.js';
import { isRootPrismaClient, type PrismaClientLike } from './guards.js';

const ROOT_CLIENT_REQUIRED = 'OSV acquisition persistence requires the root database client.';
const INFLIGHT_STATES = ['requested', 'running', 'retry_wait'] as const;
const MAX_TRANSACTION_ATTEMPTS = 1;

export type OsvAcquisitionPersistenceAdapters = {
  readonly catalogGenerations: OsvCatalogGenerationRepository;
  readonly acquisitionRuns: OsvAcquisitionRunRepository;
  readonly inventory: OsvInventoryPersistence;
  readonly providerObjects: OsvProviderObjectRepository;
  readonly bodySnapshots: OsvProviderBodySnapshotRepository;
  readonly attachments: OsvObjectAttachmentRepository;
  readonly parserAttempts: OsvParserAttemptRepository;
  readonly parsedRevisions: OsvParsedAdvisoryRevisionRepository;
  readonly memberships: OsvCatalogMembershipRepository;
  readonly presence: OsvPresenceObservationRepository;
  readonly quarantine: OsvQuarantineRepository;
  readonly reconciliation: OsvReconciliationRepository;
  readonly activePointer: OsvActiveCatalogPointerRepository;
  readonly locators: OsvAdvisoryObjectStoragePort;
};

export function createOsvAcquisitionPersistence(
  client: PrismaClient,
): OsvAcquisitionPersistenceAdapters {
  if (client === null || client === undefined || !isRootPrismaClient(client)) {
    throw new OsvAcquisitionPersistenceFailure(ROOT_CLIENT_REQUIRED);
  }
  return createOsvAcquisitionPersistenceForClient(client);
}

export function createOsvAcquisitionPersistenceForClient(
  client: PrismaClientLike,
): OsvAcquisitionPersistenceAdapters {
  return {
    catalogGenerations: new PrismaOsvCatalogGenerationRepository(client),
    acquisitionRuns: new PrismaOsvAcquisitionRunRepository(client),
    inventory: new PrismaOsvInventoryPersistence(client),
    providerObjects: new PrismaOsvProviderObjectRepository(client),
    bodySnapshots: new PrismaOsvProviderBodySnapshotRepository(client),
    attachments: new PrismaOsvObjectAttachmentRepository(client),
    parserAttempts: new PrismaOsvParserAttemptRepository(client),
    parsedRevisions: new PrismaOsvParsedAdvisoryRevisionRepository(client),
    memberships: new PrismaOsvCatalogMembershipRepository(client),
    presence: new PrismaOsvPresenceObservationRepository(client),
    quarantine: new PrismaOsvQuarantineRepository(client),
    reconciliation: new PrismaOsvReconciliationRepository(client),
    activePointer: new PrismaOsvActiveCatalogPointerRepository(client),
    locators: new PrismaOsvLocatorCompiler(),
  };
}

class OsvAcquisitionPersistenceFailure extends Error {
  public constructor(message: string) {
    super(message);
    this.name = 'OsvAcquisitionPersistenceFailure';
  }
}

class OsvTransactionRollback extends Error {
  public constructor(public readonly result: OsvPersistenceResult<never>) {
    super('osv_transaction_rollback');
    this.name = 'OsvTransactionRollback';
  }
}

function okResult<T>(value: T): OsvPersistenceResult<T> {
  return { ok: true, value };
}

function fail(code: OsvPersistenceRejectionCode): OsvPersistenceResult<never> {
  return { ok: false, code };
}

function idem(
  status: OsvIdempotencyResult['status'],
  operation: OsvIdempotencyResult['operation'],
): OsvPersistenceResult<OsvIdempotencyResult> {
  return createOsvIdempotencyResult({ status, operation });
}

async function resolveParsedRevisionUniqueConflict(
  client: PrismaClientLike,
  incoming: OsvParsedAdvisoryRevision,
): Promise<OsvPersistenceResult<OsvIdempotencyResult>> {
  const existing = await client.osvParsedAdvisoryRevision.findUnique({
    where: {
      snapshotId_protocolIdentifier_schemaRevision_schemaCommit_resourcePolicy_registryIdentifier: {
        snapshotId: incoming.snapshotId,
        protocolIdentifier: incoming.protocolIdentifier,
        schemaRevision: incoming.schemaRevision,
        schemaCommit: incoming.schemaCommit,
        resourcePolicy: incoming.resourcePolicy,
        registryIdentifier: incoming.registryIdentifier,
      },
    },
    include: { documentAttachment: true, providerGeneration: true },
  });
  if (existing === null) {
    return fail('invalid_state');
  }
  const mapped = mapParsedRevision({
    ...existing,
    providerObjectId: existing.providerGeneration.providerObjectId,
    providerObjectKeyDigest: existing.providerGeneration.providerObjectKeyDigest,
    providerGeneration: existing.providerGeneration.providerGeneration,
  });
  return revisionComparisonResult(compareOsvParsedRevisions(mapped, incoming));
}

function revisionComparisonResult(
  comparison: OsvPersistenceResult<'already_applied'>,
): OsvPersistenceResult<OsvIdempotencyResult> {
  if (comparison.ok) {
    return idem('already_applied', 'parsed_revision');
  }
  if (comparison.code === 'immutable_conflict') {
    return idem('immutable_conflict', 'parsed_revision');
  }
  return comparison;
}

function unwrapTransactionError(error: unknown): unknown {
  let current: unknown = error;
  for (let depth = 0; depth < 8; depth += 1) {
    if (
      current instanceof OsvTransactionRollback ||
      current instanceof OsvAcquisitionMappingError
    ) {
      return current;
    }
    if (current instanceof Error && current.cause !== undefined && current.cause !== current) {
      current = current.cause;
      continue;
    }
    return current;
  }
  return error;
}

function mapCaught(error: unknown): OsvPersistenceResult<never> {
  const unwrapped = unwrapTransactionError(error);
  if (unwrapped instanceof OsvTransactionRollback) {
    return unwrapped.result;
  }
  if (unwrapped instanceof OsvAcquisitionMappingError) {
    return fail('invalid_field');
  }
  return fail(translateDatabaseFailure(unwrapped));
}

async function withTransaction<T>(
  client: PrismaClientLike,
  work: (tx: Prisma.TransactionClient) => Promise<OsvPersistenceResult<T>>,
  isolation: Prisma.TransactionIsolationLevel | undefined = undefined,
): Promise<OsvPersistenceResult<T>> {
  if (!isRootPrismaClient(client)) {
    return fail('invalid_state');
  }
  let attempt = 0;
  while (attempt < MAX_TRANSACTION_ATTEMPTS) {
    attempt += 1;
    try {
      return await client.$transaction(
        async (tx) => {
          const result = await work(tx);
          if (!result.ok) {
            throw new OsvTransactionRollback(result);
          }
          return result;
        },
        isolation === undefined ? undefined : { isolationLevel: isolation },
      );
    } catch (error) {
      const unwrapped = unwrapTransactionError(error);
      if (unwrapped instanceof OsvTransactionRollback) {
        return unwrapped.result;
      }
      if (isSerializationConflict(unwrapped) && attempt < MAX_TRANSACTION_ATTEMPTS) {
        continue;
      }
      return mapCaught(unwrapped);
    }
  }
  return fail('stale_pointer');
}

async function acquireCatalogSyncLock(
  tx: Prisma.TransactionClient,
  scopeFingerprint: string,
): Promise<void> {
  const lease = compileOsvSynchronizationLease({
    scopeFingerprint,
    acquisitionRunId: '00000000-0000-4000-8000-000000000000',
  });
  const lockName = lease.ok ? lease.value.lockName : `osv_catalog_sync:${scopeFingerprint}`;
  await tx.$queryRaw`
    SELECT 1::int AS locked
    FROM (
      SELECT pg_advisory_xact_lock(hashtext(${lockName}))
    ) AS taken
  `;
}

class PrismaOsvLocatorCompiler implements OsvAdvisoryObjectStoragePort {
  public compileTemporaryLocator(input: {
    readonly storageKind: 'advisory_body' | 'parsed_advisory';
    readonly uploadId: string;
  }): OsvPersistenceResult<{
    readonly kind: 'osv_object_storage_locator';
    readonly storageKind: 'advisory_body' | 'parsed_advisory';
    readonly role: 'temporary' | 'final';
    readonly objectKey: string;
    readonly contentSha256: string | null;
    readonly uploadId: string | null;
  }> {
    return createOsvTemporaryObjectLocator(input);
  }

  public compileFinalLocator(input: {
    readonly storageKind: 'advisory_body' | 'parsed_advisory';
    readonly contentSha256: string;
  }): OsvPersistenceResult<{
    readonly kind: 'osv_object_storage_locator';
    readonly storageKind: 'advisory_body' | 'parsed_advisory';
    readonly role: 'temporary' | 'final';
    readonly objectKey: string;
    readonly contentSha256: string | null;
    readonly uploadId: string | null;
  }> {
    return createOsvFinalObjectLocator(input);
  }
}

class PrismaOsvCatalogGenerationRepository implements OsvCatalogGenerationRepository {
  public constructor(private readonly client: PrismaClientLike) {}

  public async createPlanned(
    generation: OsvCatalogGeneration,
  ): Promise<OsvPersistenceResult<OsvIdempotencyResult>> {
    if (!isOsvCatalogGeneration(generation)) {
      const parsed = createOsvCatalogGeneration(generation);
      if (!parsed.ok) {
        return parsed;
      }
      return this.createPlanned(parsed.value);
    }
    if (generation.lifecycleState !== 'planned') {
      return fail('invalid_state');
    }
    if (
      encodeOsvCatalogVersionSet(generation.versionSet) !==
      encodeOsvCatalogVersionSet(OSV_CATALOG_VERSION_SET_V1)
    ) {
      return fail('mixed_version_set');
    }
    try {
      const result = await withTransaction(this.client, async (tx) => {
        await tx.osvCatalogGeneration.create({
          data: {
            id: generation.identity.value,
            scopeFingerprint: generation.scopeFingerprint,
            ...versionSetColumns(),
            lifecycleState: 'planned',
            version: generation.version,
            createdAt: fromIsoUtc(generation.createdAt),
          },
        });
        await tx.osvAcquisitionCompleteness.createMany({
          data: emptyCompletenessRows(generation.identity.value).map((row) => ({
            catalogGenerationId: row.catalogGenerationId,
            dimension: row.dimension,
            status: row.status,
            requiredCount: row.requiredCount,
            observedCount: row.observedCount,
            discrepancyCodes: [...row.discrepancyCodes],
            blocksActivation: row.dimension !== 'matching',
            malMatchingProhibited: row.dimension === 'matching',
          })),
        });
        return idem('created', 'reconciliation');
      });
      if (!result.ok && result.code === 'immutable_conflict') {
        return this.reloadGenerationIdempotency(generation);
      }
      return result;
    } catch (error) {
      if (isUniqueViolation(error)) {
        return this.reloadGenerationIdempotency(generation);
      }
      return mapCaught(error);
    }
  }

  public async loadById(generationId: string): Promise<OsvPersistenceResult<OsvCatalogGeneration>> {
    if (!UUID_PATTERN.test(generationId)) {
      return fail('invalid_uuid');
    }
    try {
      const loaded = await this.loadRow(generationId);
      if (loaded === null) {
        return fail('invalid_state');
      }
      return okResult(loaded);
    } catch (error) {
      return mapCaught(error);
    }
  }

  public async loadByScopeFingerprint(
    scopeFingerprint: string,
  ): Promise<OsvPersistenceResult<readonly OsvCatalogGeneration[]>> {
    if (!SHA256_HEX.test(scopeFingerprint)) {
      return fail('invalid_sha256');
    }
    try {
      const rows = await this.client.osvCatalogGeneration.findMany({
        where: { scopeFingerprint },
        include: { completenessRows: true },
        orderBy: { createdAt: 'asc' },
      });
      return okResult(rows.map((row) => mapCatalogGeneration(row)));
    } catch (error) {
      return mapCaught(error);
    }
  }

  public async compareAndSetLifecycle(
    generation: OsvCatalogGeneration,
    expectedVersion: number,
  ): Promise<OsvPersistenceResult<OsvIdempotencyResult>> {
    if (!isOsvCatalogGeneration(generation)) {
      const parsed = createOsvCatalogGeneration(generation);
      if (!parsed.ok) {
        return parsed;
      }
      return this.compareAndSetLifecycle(parsed.value, expectedVersion);
    }
    if (!Number.isSafeInteger(expectedVersion) || expectedVersion < 1) {
      return fail('unsafe_integer');
    }
    if (
      encodeOsvCatalogVersionSet(generation.versionSet) !==
      encodeOsvCatalogVersionSet(OSV_CATALOG_VERSION_SET_V1)
    ) {
      return fail('mixed_version_set');
    }
    try {
      const current = await this.loadRow(generation.identity.value);
      if (current === null) {
        return fail('invalid_state');
      }
      if (
        current.lifecycleState === generation.lifecycleState &&
        current.version === generation.version
      ) {
        return idem('already_applied', 'reconciliation');
      }
      if (current.version !== expectedVersion) {
        return fail('invalid_state');
      }
      if (!graphAllowsCatalogTransition(current.lifecycleState, generation.lifecycleState)) {
        return fail(
          current.lifecycleState === 'planned' &&
            generation.lifecycleState === 'ready_for_activation'
            ? 'skipped_transition'
            : 'invalid_transition',
        );
      }
      if (generation.version !== expectedVersion + 1) {
        return fail('invalid_field');
      }
      const updated = await this.client.osvCatalogGeneration.updateMany({
        where: { id: generation.identity.value, version: expectedVersion },
        data: {
          lifecycleState: generation.lifecycleState,
          version: generation.version,
          readyAt: generation.readyAt === null ? null : fromIsoUtc(generation.readyAt),
          activatedAt: generation.activatedAt === null ? null : fromIsoUtc(generation.activatedAt),
          supersededAt:
            generation.supersededAt === null ? null : fromIsoUtc(generation.supersededAt),
          failedAt: generation.failedAt === null ? null : fromIsoUtc(generation.failedAt),
          cancelledAt: generation.cancelledAt === null ? null : fromIsoUtc(generation.cancelledAt),
          quarantinedAt:
            generation.quarantinedAt === null ? null : fromIsoUtc(generation.quarantinedAt),
        },
      });
      if (updated.count === 0) {
        const raced = await this.loadRow(generation.identity.value);
        if (
          raced !== null &&
          raced.lifecycleState === generation.lifecycleState &&
          raced.version === generation.version
        ) {
          return idem('already_applied', 'reconciliation');
        }
        return fail('invalid_state');
      }
      return idem('created', 'reconciliation');
    } catch (error) {
      return mapCaught(error);
    }
  }

  private async loadRow(id: string): Promise<OsvCatalogGeneration | null> {
    const row = await this.client.osvCatalogGeneration.findUnique({
      where: { id },
      include: { completenessRows: true },
    });
    return row === null ? null : mapCatalogGeneration(row);
  }

  private async reloadGenerationIdempotency(
    generation: OsvCatalogGeneration,
  ): Promise<OsvPersistenceResult<OsvIdempotencyResult>> {
    const existing = await this.loadRow(generation.identity.value);
    if (existing === null) {
      return fail('invalid_state');
    }
    if (
      existing.lifecycleState === generation.lifecycleState &&
      existing.scopeFingerprint === generation.scopeFingerprint &&
      encodeOsvCatalogVersionSet(existing.versionSet) ===
        encodeOsvCatalogVersionSet(generation.versionSet)
    ) {
      return idem('already_applied', 'reconciliation');
    }
    return idem('immutable_conflict', 'reconciliation');
  }
}

class PrismaOsvAcquisitionRunRepository implements OsvAcquisitionRunRepository {
  public constructor(private readonly client: PrismaClientLike) {}

  public async reserveInflight(
    run: OsvAcquisitionRun,
  ): Promise<OsvPersistenceResult<OsvIdempotencyResult>> {
    const parsed = createOsvAcquisitionRun({
      id: run.identity.value,
      catalogGenerationId: run.catalogGenerationId,
      versionSet: OSV_CATALOG_VERSION_SET_V1,
      state: run.state,
      attemptNumber: run.attemptNumber,
      correlationId: run.correlationId,
      requestedAt: run.requestedAt,
    });
    if (!parsed.ok) {
      return parsed;
    }
    if (!(INFLIGHT_STATES as readonly string[]).includes(parsed.value.state)) {
      return fail('invalid_state');
    }
    try {
      const result = await withTransaction(this.client, async (tx) => {
        await acquireCatalogSyncLock(tx, parsed.value.scopeFingerprint);
        await tx.osvAcquisitionRun.create({
          data: {
            id: parsed.value.identity.value,
            catalogGenerationId: parsed.value.catalogGenerationId,
            scopeFingerprint: parsed.value.scopeFingerprint,
            state: parsed.value.state,
            attemptNumber: parsed.value.attemptNumber,
            correlationId: parsed.value.correlationId,
            requestedAt: fromIsoUtc(parsed.value.requestedAt),
          },
        });
        return idem('created', 'inventory_observation');
      });
      if (!result.ok && result.code === 'immutable_conflict') {
        const existing = await this.loadInflightByScope(parsed.value.scopeFingerprint);
        if (!existing.ok) {
          return existing;
        }
        if (
          existing.value !== null &&
          existing.value.identity.value === parsed.value.identity.value &&
          existing.value.attemptNumber === parsed.value.attemptNumber &&
          existing.value.state === parsed.value.state
        ) {
          return idem('already_applied', 'inventory_observation');
        }
        return idem('immutable_conflict', 'inventory_observation');
      }
      return result;
    } catch (error) {
      if (isUniqueViolation(error)) {
        const existing = await this.loadInflightByScope(parsed.value.scopeFingerprint);
        if (!existing.ok) {
          return existing;
        }
        if (
          existing.value !== null &&
          existing.value.identity.value === parsed.value.identity.value &&
          existing.value.attemptNumber === parsed.value.attemptNumber &&
          existing.value.state === parsed.value.state
        ) {
          return idem('already_applied', 'inventory_observation');
        }
        return idem('immutable_conflict', 'inventory_observation');
      }
      return mapCaught(error);
    }
  }

  public async loadInflightByScope(
    scopeFingerprint: string,
  ): Promise<OsvPersistenceResult<OsvAcquisitionRun | null>> {
    if (!SHA256_HEX.test(scopeFingerprint)) {
      return fail('invalid_sha256');
    }
    try {
      const row = await this.client.osvAcquisitionRun.findFirst({
        where: {
          scopeFingerprint,
          state: { in: [...INFLIGHT_STATES] },
        },
        orderBy: { requestedAt: 'asc' },
      });
      if (row === null) {
        return okResult(null);
      }
      return createOsvAcquisitionRun({
        id: row.id,
        catalogGenerationId: row.catalogGenerationId,
        versionSet: OSV_CATALOG_VERSION_SET_V1,
        state: row.state,
        attemptNumber: row.attemptNumber,
        correlationId: row.correlationId,
        requestedAt: toIsoUtc(row.requestedAt),
      });
    } catch (error) {
      return mapCaught(error);
    }
  }
}

class PrismaOsvInventoryPersistence implements OsvInventoryPersistence {
  public constructor(private readonly client: PrismaClientLike) {}

  public async createRun(
    run: Parameters<OsvInventoryPersistence['createRun']>[0],
  ): Promise<OsvPersistenceResult<OsvIdempotencyResult>> {
    const parsed = isOsvInventoryRun(run) ? okResult(run) : createOsvInventoryRun(run);
    if (!parsed.ok) {
      return parsed;
    }
    const failureCode = inferInventoryFailureCode(parsed.value);
    if (parsed.value.state === 'failed' && failureCode === null) {
      return fail('invalid_state');
    }
    try {
      const existing = await this.client.osvInventoryRun.findUnique({
        where: { id: parsed.value.identity.value },
        include: { prefixPasses: true },
      });
      if (existing !== null) {
        const mapped = mapInventoryRun(existing);
        if (inventoryRunsAgree(mapped, parsed.value)) {
          return idem('already_applied', 'inventory_observation');
        }
        if (existing.state === 'running' && parsed.value.state === 'complete') {
          return this.completeRun(parsed.value);
        }
        return idem('immutable_conflict', 'inventory_observation');
      }
      await this.client.osvInventoryRun.create({
        data: {
          id: parsed.value.identity.value,
          catalogGenerationId: parsed.value.catalogGenerationId,
          state: parsed.value.state,
          inventoryScope: parsed.value.inventoryScope,
          listingProtocol: parsed.value.listingProtocol,
          transportPolicy: parsed.value.transportPolicy,
          sourceLicenseRegistry: parsed.value.sourceLicenseRegistry,
          passCount: parsed.value.passCount,
          startedAt: fromIsoUtc(parsed.value.startedAt),
          completedAt:
            parsed.value.completedAt === null ? null : fromIsoUtc(parsed.value.completedAt),
          acceptedListedCount: parsed.value.acceptedListedCount,
          listingRejectedCount: parsed.value.listingRejectedCount,
          eligibleCount: parsed.value.classificationCounts.eligible,
          ineligibleCount: parsed.value.classificationCounts.ineligible,
          legalReviewCount: parsed.value.classificationCounts.legalReview,
          unknownCount: parsed.value.classificationCounts.unknown,
          ambiguousCount: parsed.value.classificationCounts.ambiguous,
          convergence: parsed.value.convergence,
          failureCode,
        },
      });
      for (const pass of parsed.value.prefixPasses) {
        const recorded = await this.recordPrefixPass(pass);
        if (!recorded.ok) {
          return recorded;
        }
      }
      return idem('created', 'inventory_observation');
    } catch (error) {
      if (isUniqueViolation(error)) {
        const raced = await this.client.osvInventoryRun.findUnique({
          where: { id: parsed.value.identity.value },
          include: { prefixPasses: true },
        });
        if (raced === null) {
          return fail('invalid_state');
        }
        const mapped = mapInventoryRun(raced);
        if (inventoryRunsAgree(mapped, parsed.value)) {
          return idem('already_applied', 'inventory_observation');
        }
        if (raced.state === 'running' && parsed.value.state === 'complete') {
          return this.completeRun(parsed.value);
        }
        return idem('immutable_conflict', 'inventory_observation');
      }
      return mapCaught(error);
    }
  }

  public async recordPrefixPass(
    pass: Parameters<OsvInventoryPersistence['recordPrefixPass']>[0],
  ): Promise<OsvPersistenceResult<OsvIdempotencyResult>> {
    const parsed = isOsvInventoryPrefixPass(pass) ? okResult(pass) : fail('invalid_field');
    if (!parsed.ok) {
      return parsed;
    }
    try {
      await this.client.osvInventoryPrefixPass.create({
        data: {
          inventoryRunId: parsed.value.identity.inventoryRunId,
          providerPrefix: parsed.value.identity.providerPrefix,
          passNumber: parsed.value.identity.passNumber,
          listingProtocol: parsed.value.listingProtocol,
          transportPolicy: parsed.value.transportPolicy,
          sourceLicenseRegistry: parsed.value.sourceLicenseRegistry,
          inventoryScope: parsed.value.inventoryScope,
          pageCount: parsed.value.pageCount,
          responseByteCount: parsed.value.responseByteCount,
          acceptedItemCount: parsed.value.acceptedItemCount,
          listingRejectedCount: parsed.value.listingRejectedCount,
          terminalPageObserved: parsed.value.terminalPageObserved,
          completeness: parsed.value.completeness,
        },
      });
      return idem('created', 'inventory_observation');
    } catch (error) {
      if (isUniqueViolation(error)) {
        const existing = await this.client.osvInventoryPrefixPass.findUnique({
          where: {
            inventoryRunId_providerPrefix_passNumber: {
              inventoryRunId: parsed.value.identity.inventoryRunId,
              providerPrefix: parsed.value.identity.providerPrefix,
              passNumber: parsed.value.identity.passNumber,
            },
          },
        });
        if (existing === null) {
          return fail('invalid_state');
        }
        if (
          existing.pageCount === parsed.value.pageCount &&
          existing.responseByteCount === parsed.value.responseByteCount &&
          existing.acceptedItemCount === parsed.value.acceptedItemCount &&
          existing.listingRejectedCount === parsed.value.listingRejectedCount &&
          existing.terminalPageObserved === parsed.value.terminalPageObserved &&
          existing.completeness === parsed.value.completeness
        ) {
          return idem('already_applied', 'inventory_observation');
        }
        return idem('immutable_conflict', 'inventory_observation');
      }
      return mapCaught(error);
    }
  }

  public async recordObservation(
    observation: Parameters<OsvInventoryPersistence['recordObservation']>[0],
  ): Promise<OsvPersistenceResult<OsvIdempotencyResult>> {
    const parsed = isOsvInventoryObjectObservation(observation)
      ? okResult(observation)
      : createOsvInventoryObjectObservation(observation);
    if (!parsed.ok) {
      return parsed;
    }
    try {
      await this.client.osvInventoryObjectObservation.create({
        data: {
          inventoryRunId: parsed.value.inventoryRunId,
          providerObjectKeyDigest: parsed.value.providerObjectKeyDigest,
          providerGeneration: parsed.value.providerGeneration,
          providerPrefix: parsed.value.providerPrefix,
          declaredByteCount: parsed.value.declaredByteCount,
          classificationStatus: parsed.value.classificationStatus,
          sourceIdentifier: parsed.value.sourceIdentifier,
          etagMetadata: parsed.value.etagMetadata,
          md5HashMetadata: parsed.value.md5HashMetadata,
        },
      });
      return idem('created', 'inventory_observation');
    } catch (error) {
      if (isUniqueViolation(error)) {
        const existing = await this.client.osvInventoryObjectObservation.findUnique({
          where: {
            inventoryRunId_providerObjectKeyDigest_providerGeneration: {
              inventoryRunId: parsed.value.inventoryRunId,
              providerObjectKeyDigest: parsed.value.providerObjectKeyDigest,
              providerGeneration: parsed.value.providerGeneration,
            },
          },
        });
        if (existing === null) {
          return fail('invalid_state');
        }
        const mapped = mapObservation(existing);
        if (
          mapped.classificationStatus === parsed.value.classificationStatus &&
          mapped.declaredByteCount === parsed.value.declaredByteCount &&
          mapped.sourceIdentifier === parsed.value.sourceIdentifier &&
          mapped.etagMetadata === parsed.value.etagMetadata &&
          mapped.md5HashMetadata === parsed.value.md5HashMetadata &&
          mapped.providerPrefix === parsed.value.providerPrefix
        ) {
          return idem('already_applied', 'inventory_observation');
        }
        return idem('immutable_conflict', 'inventory_observation');
      }
      return mapCaught(error);
    }
  }

  public async loadRun(
    inventoryRunId: string,
  ): Promise<OsvPersistenceResult<ReturnType<typeof mapInventoryRun>>> {
    if (!UUID_PATTERN.test(inventoryRunId)) {
      return fail('invalid_uuid');
    }
    try {
      const row = await this.client.osvInventoryRun.findUnique({
        where: { id: inventoryRunId },
        include: { prefixPasses: true },
      });
      if (row === null) {
        return fail('invalid_state');
      }
      return okResult(mapInventoryRun(row));
    } catch (error) {
      return mapCaught(error);
    }
  }

  private async completeRun(
    run: ReturnType<typeof mapInventoryRun>,
  ): Promise<OsvPersistenceResult<OsvIdempotencyResult>> {
    const updated = await this.client.osvInventoryRun.updateMany({
      where: { id: run.identity.value, state: 'running' },
      data: {
        state: 'complete',
        completedAt: run.completedAt === null ? null : fromIsoUtc(run.completedAt),
        acceptedListedCount: run.acceptedListedCount,
        listingRejectedCount: run.listingRejectedCount,
        eligibleCount: run.classificationCounts.eligible,
        ineligibleCount: run.classificationCounts.ineligible,
        legalReviewCount: run.classificationCounts.legalReview,
        unknownCount: run.classificationCounts.unknown,
        ambiguousCount: run.classificationCounts.ambiguous,
        convergence: run.convergence,
        failureCode: null,
      },
    });
    if (updated.count === 0) {
      return fail('invalid_state');
    }
    return idem('created', 'inventory_observation');
  }
}

function inferInventoryFailureCode(
  run: ReturnType<typeof mapInventoryRun>,
):
  | 'incomplete_pass'
  | 'divergent_passes'
  | 'listing_rejected'
  | 'classification_mismatch'
  | 'cancelled'
  | null {
  if (run.state === 'cancelled') {
    return 'cancelled';
  }
  if (run.state !== 'failed') {
    return null;
  }
  if (run.listingRejectedCount !== 0) {
    return 'listing_rejected';
  }
  if (run.convergence === 'divergent') {
    return 'divergent_passes';
  }
  return 'incomplete_pass';
}

function inventoryRunsAgree(
  left: ReturnType<typeof mapInventoryRun>,
  right: ReturnType<typeof mapInventoryRun>,
): boolean {
  return (
    left.identity.value === right.identity.value &&
    left.catalogGenerationId === right.catalogGenerationId &&
    left.state === right.state &&
    left.acceptedListedCount === right.acceptedListedCount &&
    left.listingRejectedCount === right.listingRejectedCount &&
    left.convergence === right.convergence &&
    left.classificationCounts.eligible === right.classificationCounts.eligible &&
    left.classificationCounts.ineligible === right.classificationCounts.ineligible &&
    left.classificationCounts.legalReview === right.classificationCounts.legalReview &&
    left.classificationCounts.unknown === right.classificationCounts.unknown &&
    left.classificationCounts.ambiguous === right.classificationCounts.ambiguous
  );
}

class PrismaOsvProviderObjectRepository implements OsvProviderObjectRepository {
  public constructor(private readonly client: PrismaClientLike) {}

  public async insertOnce(
    identity: OsvProviderObjectIdentity,
  ): Promise<OsvPersistenceResult<OsvIdempotencyResult>> {
    const parsed = isOsvProviderObjectIdentity(identity)
      ? okResult(identity)
      : createOsvProviderObjectIdentity(identity);
    if (!parsed.ok) {
      return parsed;
    }
    const key = readOsvProviderObjectKeyForPersistence(parsed.value);
    if (!key.ok) {
      return key;
    }
    const family = familyToColumns(parsed.value.filenameFamily);
    try {
      await this.client.osvProviderObject.create({
        data: {
          providerIdentifier: parsed.value.providerIdentifier,
          providerObjectKey: key.value,
          providerObjectKeyDigest: parsed.value.providerObjectKeyDigest,
          providerPrefix: parsed.value.providerPrefix,
          familyKind: family.familyKind,
          familyValue: family.familyValue,
        },
      });
      return idem('created', 'provider_generation_metadata');
    } catch (error) {
      if (isUniqueViolation(error)) {
        const existing = await this.client.osvProviderObject.findUnique({
          where: {
            providerIdentifier_providerObjectKeyDigest: {
              providerIdentifier: parsed.value.providerIdentifier,
              providerObjectKeyDigest: parsed.value.providerObjectKeyDigest,
            },
          },
        });
        if (existing === null) {
          return fail('invalid_state');
        }
        if (
          existing.providerObjectKey === key.value &&
          existing.providerPrefix === parsed.value.providerPrefix &&
          existing.familyKind === family.familyKind &&
          existing.familyValue === family.familyValue
        ) {
          return idem('already_applied', 'provider_generation_metadata');
        }
        return idem('immutable_conflict', 'provider_generation_metadata');
      }
      return mapCaught(error);
    }
  }
}

class PrismaOsvProviderBodySnapshotRepository implements OsvProviderBodySnapshotRepository {
  public constructor(private readonly client: PrismaClientLike) {}

  public async reserveImmutableGeneration(
    generation: OsvProviderGenerationIdentity,
  ): Promise<OsvPersistenceResult<OsvIdempotencyResult>> {
    const parsed = isOsvProviderGenerationIdentity(generation)
      ? okResult(generation)
      : fail('invalid_field');
    if (!parsed.ok) {
      return parsed;
    }
    try {
      await this.client.osvProviderGeneration.create({
        data: {
          providerObjectId: parsed.value.providerObjectId,
          providerObjectKeyDigest: parsed.value.providerObjectKeyDigest,
          providerGeneration: parsed.value.providerGeneration,
        },
      });
      return idem('created', 'provider_generation_metadata');
    } catch (error) {
      if (isUniqueViolation(error)) {
        const existing = await this.client.osvProviderGeneration.findUnique({
          where: {
            providerObjectId_providerGeneration: {
              providerObjectId: parsed.value.providerObjectId,
              providerGeneration: parsed.value.providerGeneration,
            },
          },
        });
        if (existing === null) {
          return fail('invalid_state');
        }
        if (existing.providerObjectKeyDigest === parsed.value.providerObjectKeyDigest) {
          return idem('already_applied', 'provider_generation_metadata');
        }
        return idem('immutable_conflict', 'provider_generation_metadata');
      }
      return mapCaught(error);
    }
  }

  public async attachImmutableSnapshot(
    snapshot: OsvProviderBodySnapshot,
  ): Promise<OsvPersistenceResult<OsvIdempotencyResult>> {
    const parsed = isOsvProviderBodySnapshot(snapshot)
      ? okResult(snapshot)
      : createOsvProviderBodySnapshot(snapshot as never);
    if (!parsed.ok) {
      return parsed;
    }
    try {
      const result = await withTransaction(this.client, async (tx) => {
        const generation = await tx.osvProviderGeneration.findUnique({
          where: {
            providerObjectId_providerGeneration: {
              providerObjectId: parsed.value.providerGeneration.providerObjectId,
              providerGeneration: parsed.value.providerGeneration.providerGeneration,
            },
          },
          include: { bodySnapshot: { include: { attachment: true } } },
        });
        if (generation === null) {
          return fail('invalid_state');
        }
        if (
          generation.providerObjectKeyDigest !==
          parsed.value.providerGeneration.providerObjectKeyDigest
        ) {
          return fail('immutable_conflict');
        }
        if (generation.bodySnapshot !== null) {
          const existing = mapSnapshot({
            ...generation.bodySnapshot,
            providerObjectId: generation.providerObjectId,
            providerObjectKeyDigest: generation.providerObjectKeyDigest,
            providerGeneration: generation.providerGeneration,
            classificationStatus: 'eligible',
            attachment: generation.bodySnapshot.attachment,
          });
          if (
            existing.attachment.state === 'staged' &&
            parsed.value.attachment.state === 'attached'
          ) {
            if (
              existing.contentSha256 !== parsed.value.contentSha256 ||
              existing.receivedByteCount !== parsed.value.receivedByteCount ||
              existing.declaredByteCount !== parsed.value.declaredByteCount ||
              existing.contentType !== parsed.value.contentType ||
              existing.contentEncoding !== parsed.value.contentEncoding ||
              existing.attachment.contentSha256 !== parsed.value.attachment.contentSha256 ||
              existing.attachment.byteCount !== parsed.value.attachment.byteCount ||
              existing.attachment.contentType !== parsed.value.attachment.contentType
            ) {
              return fail('immutable_conflict');
            }
            return this.finalizeAttachment(tx, existing.attachment, parsed.value);
          }
          const comparison = compareOsvBodySnapshots(existing, parsed.value);
          if (comparison.ok) {
            return idem('already_applied', 'body_attachment');
          }
          return comparison;
        }
        await tx.osvObjectAttachment.create({
          data: attachmentWriteData(parsed.value.attachment),
        });
        await tx.osvProviderBodySnapshot.create({
          data: {
            id: parsed.value.identity.value,
            providerGenerationId: generation.id,
            attachmentId: parsed.value.attachment.identity.value,
            contentSha256: parsed.value.contentSha256,
            receivedByteCount: parsed.value.receivedByteCount,
            declaredByteCount: parsed.value.declaredByteCount,
            contentType: parsed.value.contentType,
            contentEncoding: parsed.value.contentEncoding,
            sourceIdentifier: parsed.value.sourceIdentifier,
            registryIdentifier: parsed.value.registryIdentifier,
            eligibleBodyScope: parsed.value.eligibleBodyScope,
            transportPolicy: parsed.value.transportPolicy,
            retrievedAt: fromIsoUtc(parsed.value.retrievedAt),
            classificationStatus: 'eligible',
          },
        });
        return idem('created', 'body_attachment');
      });
      if (!result.ok && result.code === 'immutable_conflict') {
        const generation = await this.client.osvProviderGeneration.findUnique({
          where: {
            providerObjectId_providerGeneration: {
              providerObjectId: parsed.value.providerGeneration.providerObjectId,
              providerGeneration: parsed.value.providerGeneration.providerGeneration,
            },
          },
          include: { bodySnapshot: { include: { attachment: true } } },
        });
        if (generation?.bodySnapshot !== undefined && generation.bodySnapshot !== null) {
          const existing = mapSnapshot({
            ...generation.bodySnapshot,
            providerObjectId: generation.providerObjectId,
            providerObjectKeyDigest: generation.providerObjectKeyDigest,
            providerGeneration: generation.providerGeneration,
            classificationStatus: 'eligible',
            attachment: generation.bodySnapshot.attachment,
          });
          const comparison = compareOsvBodySnapshots(existing, parsed.value);
          if (comparison.ok) {
            return idem('already_applied', 'body_attachment');
          }
          return comparison;
        }
      }
      return result;
    } catch (error) {
      if (isUniqueViolation(error)) {
        return fail('immutable_conflict');
      }
      return mapCaught(error);
    }
  }

  private async finalizeAttachment(
    tx: Prisma.TransactionClient,
    current: ReturnType<typeof mapAttachment>,
    incoming: OsvProviderBodySnapshot,
  ): Promise<OsvPersistenceResult<OsvIdempotencyResult>> {
    if (!attachmentTransitionAllowed(current.state, 'attached')) {
      return fail('invalid_transition');
    }
    const next = transitionOsvAttachmentState(current, 'attached', incoming.attachment.locator);
    if (!next.ok) {
      return next;
    }
    const updated = await tx.osvObjectAttachment.updateMany({
      where: { id: current.identity.value, state: 'staged' },
      data: {
        role: next.value.locator.role,
        objectKey: next.value.locator.objectKey,
        locatorContentSha256: next.value.locator.contentSha256,
        uploadId: next.value.locator.uploadId,
        state: 'attached',
        cleanupEligible: false,
      },
    });
    if (updated.count === 0) {
      return fail('invalid_state');
    }
    return idem('created', 'body_attachment');
  }

  public async loadByGeneration(
    generation: OsvProviderGenerationIdentity,
  ): Promise<OsvPersistenceResult<OsvProviderBodySnapshot | null>> {
    const parsed = isOsvProviderGenerationIdentity(generation)
      ? okResult(generation)
      : fail('invalid_field');
    if (!parsed.ok) {
      return parsed;
    }
    try {
      const row = await this.client.osvProviderGeneration.findUnique({
        where: {
          providerObjectId_providerGeneration: {
            providerObjectId: parsed.value.providerObjectId,
            providerGeneration: parsed.value.providerGeneration,
          },
        },
        include: { bodySnapshot: { include: { attachment: true } } },
      });
      if (row === null || row.bodySnapshot === null) {
        return okResult(null);
      }
      if (row.providerObjectKeyDigest !== parsed.value.providerObjectKeyDigest) {
        return fail('immutable_conflict');
      }
      return okResult(
        mapSnapshot({
          ...row.bodySnapshot,
          providerObjectId: row.providerObjectId,
          providerObjectKeyDigest: row.providerObjectKeyDigest,
          providerGeneration: row.providerGeneration,
          classificationStatus: 'eligible',
          attachment: row.bodySnapshot.attachment,
        }),
      );
    } catch (error) {
      return mapCaught(error);
    }
  }
}

class PrismaOsvObjectAttachmentRepository implements OsvObjectAttachmentRepository {
  public constructor(private readonly client: PrismaClientLike) {}

  public async inspect(
    id: string,
  ): Promise<OsvPersistenceResult<ReturnType<typeof mapAttachment> | null>> {
    if (!UUID_PATTERN.test(id)) {
      return fail('invalid_uuid');
    }
    try {
      const row = await this.client.osvObjectAttachment.findUnique({ where: { id } });
      if (row === null) {
        return okResult(null);
      }
      return okResult(mapAttachment(row));
    } catch (error) {
      return mapCaught(error);
    }
  }

  public async markOrphaned(id: string): Promise<OsvPersistenceResult<OsvIdempotencyResult>> {
    return this.transitionTerminal(id, 'orphaned');
  }

  public async markRejected(id: string): Promise<OsvPersistenceResult<OsvIdempotencyResult>> {
    return this.transitionTerminal(id, 'rejected');
  }

  private async transitionTerminal(
    id: string,
    nextState: 'orphaned' | 'rejected',
  ): Promise<OsvPersistenceResult<OsvIdempotencyResult>> {
    if (!UUID_PATTERN.test(id)) {
      return fail('invalid_uuid');
    }
    try {
      const row = await this.client.osvObjectAttachment.findUnique({ where: { id } });
      if (row === null) {
        return fail('invalid_state');
      }
      const current = mapAttachment(row);
      if (current.state === nextState) {
        return idem('already_applied', 'object_attachment');
      }
      if (!attachmentTransitionAllowed(current.state, nextState)) {
        return fail('invalid_transition');
      }
      const next = transitionOsvAttachmentState(current, nextState);
      if (!next.ok) {
        return next;
      }
      const updated = await this.client.osvObjectAttachment.updateMany({
        where: { id, state: 'staged' },
        data: {
          state: nextState,
          cleanupEligible: true,
        },
      });
      if (updated.count === 0) {
        return fail('invalid_state');
      }
      return idem('created', 'object_attachment');
    } catch (error) {
      return mapCaught(error);
    }
  }
}

function attachmentWriteData(attachment: ReturnType<typeof mapAttachment>) {
  return {
    id: attachment.identity.value,
    storageKind: attachment.locator.storageKind,
    role: attachment.locator.role,
    objectKey: attachment.locator.objectKey,
    locatorContentSha256: attachment.locator.contentSha256,
    uploadId: attachment.locator.uploadId,
    contentSha256: attachment.contentSha256,
    byteCount: attachment.byteCount,
    contentType: attachment.contentType,
    contentEncoding: attachment.contentEncoding,
    state: attachment.state,
    cleanupEligible: attachment.cleanupEligible,
  };
}

class PrismaOsvParserAttemptRepository implements OsvParserAttemptRepository {
  public constructor(private readonly client: PrismaClientLike) {}

  public async recordAttempt(
    attempt: OsvParserAttempt,
  ): Promise<OsvPersistenceResult<OsvIdempotencyResult>> {
    const parsed = isOsvParserAttempt(attempt)
      ? okResult(attempt)
      : createOsvParserAttempt(attempt);
    if (!parsed.ok) {
      return parsed;
    }
    try {
      const existing = await this.client.osvParserAttempt.findUnique({
        where: {
          snapshotId_attemptNumber: {
            snapshotId: parsed.value.snapshotId,
            attemptNumber: parsed.value.attemptNumber,
          },
        },
      });
      if (existing !== null) {
        return compareAttempts(mapParserAttempt(existing), parsed.value);
      }
      await this.client.osvParserAttempt.create({
        data: {
          id: parsed.value.identity.value,
          snapshotId: parsed.value.snapshotId,
          protocolIdentifier: parsed.value.protocolIdentifier,
          schemaRevision: parsed.value.schemaRevision,
          schemaCommit: parsed.value.schemaCommit,
          resourcePolicy: parsed.value.resourcePolicy,
          registryIdentifier: parsed.value.registryIdentifier,
          sourceIdentifier: parsed.value.sourceIdentifier,
          inputSha256: parsed.value.inputSha256,
          inputByteCount: parsed.value.inputByteCount,
          attemptNumber: parsed.value.attemptNumber,
          resultState: parsed.value.resultState,
          failureKind: parsed.value.failureKind,
          retryability: parsed.value.retryability,
          phase: parsed.value.phase,
          terminationRequired: parsed.value.terminationRequired,
          warningCodes: [...parsed.value.warningCodes],
          workerLifecycleOutcome: parsed.value.workerLifecycleOutcome,
          parsedRevisionId: null,
          correlationId: parsed.value.correlationId,
          startedAt: fromIsoUtc(parsed.value.startedAt),
          completedAt: fromIsoUtc(parsed.value.completedAt),
        },
      });
      return idem('created', 'parser_attempt');
    } catch (error) {
      if (isUniqueViolation(error)) {
        const existing = await this.client.osvParserAttempt.findUnique({
          where: {
            snapshotId_attemptNumber: {
              snapshotId: parsed.value.snapshotId,
              attemptNumber: parsed.value.attemptNumber,
            },
          },
        });
        if (existing === null) {
          return fail('invalid_state');
        }
        return compareAttempts(mapParserAttempt(existing), parsed.value);
      }
      return mapCaught(error);
    }
  }
}

function compareAttempts(
  existing: OsvParserAttempt,
  incoming: OsvParserAttempt,
): OsvPersistenceResult<OsvIdempotencyResult> {
  if (existing.resultState !== incoming.resultState) {
    return idem('immutable_conflict', 'parser_attempt');
  }
  if (existing.failureKind !== incoming.failureKind) {
    return idem('immutable_conflict', 'parser_attempt');
  }
  if (
    existing.inputSha256 !== incoming.inputSha256 ||
    existing.inputByteCount !== incoming.inputByteCount ||
    existing.protocolIdentifier !== incoming.protocolIdentifier ||
    existing.schemaRevision !== incoming.schemaRevision ||
    existing.resourcePolicy !== incoming.resourcePolicy
  ) {
    return idem('immutable_conflict', 'parser_attempt');
  }
  if (
    existing.parsedRevisionId !== null &&
    incoming.parsedRevisionId !== null &&
    existing.parsedRevisionId !== incoming.parsedRevisionId
  ) {
    return idem('immutable_conflict', 'parser_attempt');
  }
  return idem('already_applied', 'parser_attempt');
}

class PrismaOsvParsedAdvisoryRevisionRepository implements OsvParsedAdvisoryRevisionRepository {
  public constructor(private readonly client: PrismaClientLike) {}

  public async attachRevision(
    revision: OsvParsedAdvisoryRevision,
  ): Promise<OsvPersistenceResult<OsvIdempotencyResult>> {
    const parsed = isOsvParsedAdvisoryRevision(revision)
      ? okResult(revision)
      : createOsvParsedAdvisoryRevision(revision as never);
    if (!parsed.ok) {
      return parsed;
    }
    try {
      const result = await withTransaction(this.client, async (tx) => {
        const attempt = await tx.osvParserAttempt.findUnique({
          where: { id: parsed.value.parserAttemptId },
        });
        if (attempt === null) {
          return fail('invalid_state');
        }
        if (attempt.resultState !== 'succeeded' || attempt.failureKind !== null) {
          return fail('invalid_transition');
        }
        if (attempt.snapshotId !== parsed.value.snapshotId) {
          return fail('scope_mismatch');
        }
        if (attempt.parsedRevisionId !== null) {
          const linked = await tx.osvParsedAdvisoryRevision.findUnique({
            where: { id: attempt.parsedRevisionId },
            include: { documentAttachment: true, providerGeneration: true },
          });
          if (linked === null) {
            return fail('invalid_state');
          }
          return revisionComparisonResult(
            compareOsvParsedRevisions(
              mapParsedRevision({
                ...linked,
                providerObjectId: linked.providerGeneration.providerObjectId,
                providerObjectKeyDigest: linked.providerGeneration.providerObjectKeyDigest,
                providerGeneration: linked.providerGeneration.providerGeneration,
              }),
              parsed.value,
            ),
          );
        }
        const existingRevision = await tx.osvParsedAdvisoryRevision.findUnique({
          where: {
            snapshotId_protocolIdentifier_schemaRevision_schemaCommit_resourcePolicy_registryIdentifier:
              {
                snapshotId: parsed.value.snapshotId,
                protocolIdentifier: parsed.value.protocolIdentifier,
                schemaRevision: parsed.value.schemaRevision,
                schemaCommit: parsed.value.schemaCommit,
                resourcePolicy: parsed.value.resourcePolicy,
                registryIdentifier: parsed.value.registryIdentifier,
              },
          },
          include: { documentAttachment: true, providerGeneration: true },
        });
        if (existingRevision !== null) {
          return revisionComparisonResult(
            compareOsvParsedRevisions(
              mapParsedRevision({
                ...existingRevision,
                providerObjectId: existingRevision.providerGeneration.providerObjectId,
                providerObjectKeyDigest:
                  existingRevision.providerGeneration.providerObjectKeyDigest,
                providerGeneration: existingRevision.providerGeneration.providerGeneration,
              }),
              parsed.value,
            ),
          );
        }
        const generation = await tx.osvProviderGeneration.findUnique({
          where: {
            providerObjectId_providerGeneration: {
              providerObjectId: parsed.value.providerGeneration.providerObjectId,
              providerGeneration: parsed.value.providerGeneration.providerGeneration,
            },
          },
        });
        if (generation === null) {
          return fail('invalid_generation');
        }
        if (
          generation.providerObjectKeyDigest !==
          parsed.value.providerGeneration.providerObjectKeyDigest
        ) {
          return fail('immutable_conflict');
        }
        await tx.osvObjectAttachment.create({
          data: attachmentWriteData(parsed.value.documentAttachment),
        });
        await tx.osvParsedAdvisoryRevision.create({
          data: {
            id: parsed.value.identity.value,
            snapshotId: parsed.value.snapshotId,
            parserAttemptId: parsed.value.parserAttemptId,
            providerGenerationId: generation.id,
            documentAttachmentId: parsed.value.documentAttachment.identity.value,
            documentIdentifier: parsed.value.documentIdentifier,
            protocolIdentifier: parsed.value.protocolIdentifier,
            schemaRevision: parsed.value.schemaRevision,
            schemaCommit: parsed.value.schemaCommit,
            resourcePolicy: parsed.value.resourcePolicy,
            registryIdentifier: parsed.value.registryIdentifier,
            sourceIdentifier: parsed.value.sourceIdentifier,
            contentSha256: parsed.value.contentSha256,
            parsedOutputSha256: parsed.value.parsedOutputSha256,
            parsedTopLevelOsvId: parsed.value.parsedTopLevelOsvId,
            publishedAt:
              parsed.value.publishedAt === null ? null : fromIsoUtc(parsed.value.publishedAt),
            modifiedAt:
              parsed.value.modifiedAt === null ? null : fromIsoUtc(parsed.value.modifiedAt),
            withdrawnAt:
              parsed.value.withdrawnAt === null ? null : fromIsoUtc(parsed.value.withdrawnAt),
            withdrawn: parsed.value.withdrawn,
            aliasCount: parsed.value.structuralCounts.aliasCount,
            relatedCount: parsed.value.structuralCounts.relatedCount,
            affectedPackageCount: parsed.value.structuralCounts.affectedPackageCount,
            rangeCount: parsed.value.structuralCounts.rangeCount,
            eventCount: parsed.value.structuralCounts.eventCount,
            explicitVersionCount: parsed.value.structuralCounts.explicitVersionCount,
            referenceCount: parsed.value.structuralCounts.referenceCount,
            creditCount: parsed.value.structuralCounts.creditCount,
            severityCount: parsed.value.structuralCounts.severityCount,
            normalizationState: parsed.value.normalizationState,
          },
        });
        const linked = await tx.osvParserAttempt.updateMany({
          where: { id: attempt.id, parsedRevisionId: null },
          data: { parsedRevisionId: parsed.value.identity.value },
        });
        if (linked.count !== 1) {
          return fail('invalid_state');
        }
        return idem('created', 'parsed_revision');
      });
      if (!result.ok && result.code === 'immutable_conflict') {
        return resolveParsedRevisionUniqueConflict(this.client, parsed.value);
      }
      return result;
    } catch (error) {
      if (isUniqueViolation(error)) {
        return resolveParsedRevisionUniqueConflict(this.client, parsed.value);
      }
      return mapCaught(error);
    }
  }
}

class PrismaOsvCatalogMembershipRepository implements OsvCatalogMembershipRepository {
  public constructor(private readonly client: PrismaClientLike) {}

  public async attachMembership(input: {
    readonly catalogGenerationId: string;
    readonly revisionId: string;
  }): Promise<OsvPersistenceResult<OsvIdempotencyResult>> {
    if (typeof input.catalogGenerationId !== 'string' || typeof input.revisionId !== 'string') {
      return fail('invalid_uuid');
    }
    try {
      await this.client.osvCatalogMembership.create({
        data: {
          catalogGenerationId: input.catalogGenerationId,
          revisionId: input.revisionId,
        },
      });
      return idem('created', 'parsed_revision');
    } catch (error) {
      if (isUniqueViolation(error)) {
        const existing = await this.client.osvCatalogMembership.findUnique({
          where: {
            catalogGenerationId_revisionId: {
              catalogGenerationId: input.catalogGenerationId,
              revisionId: input.revisionId,
            },
          },
        });
        if (existing === null) {
          return fail('invalid_state');
        }
        return idem('already_applied', 'parsed_revision');
      }
      if (isForeignKeyViolation(error)) {
        return fail('scope_mismatch');
      }
      return mapCaught(error);
    }
  }
}

function quarantineTargetCount(record: OsvQuarantineRecord): number {
  return (
    (record.providerObjectKeyDigest === null ? 0 : 1) +
    (record.snapshotId === null ? 0 : 1) +
    (record.parserAttemptId === null ? 0 : 1) +
    (record.revisionId === null ? 0 : 1)
  );
}

class PrismaOsvQuarantineRepository implements OsvQuarantineRepository {
  public constructor(private readonly client: PrismaClientLike) {}

  public async recordQuarantine(
    record: OsvQuarantineRecord,
  ): Promise<OsvPersistenceResult<OsvIdempotencyResult>> {
    const parsed = isOsvQuarantineRecord(record)
      ? okResult(record)
      : createOsvQuarantineRecord(record);
    if (!parsed.ok) {
      return parsed;
    }
    const targets = quarantineTargetCount(parsed.value);
    if (targets > 1) {
      return fail('invalid_field');
    }
    try {
      await this.client.osvQuarantineRecord.create({
        data: {
          id: parsed.value.identity.value,
          catalogGenerationId: parsed.value.catalogGenerationId,
          providerObjectKeyDigest: parsed.value.providerObjectKeyDigest,
          snapshotId: parsed.value.snapshotId,
          parserAttemptId: parsed.value.parserAttemptId,
          revisionId: parsed.value.revisionId,
          reasonCode: parsed.value.reasonCode,
          originatingPhase: parsed.value.originatingPhase,
          diagnosticCode: parsed.value.diagnosticCode,
          recordedAt: fromIsoUtc(parsed.value.recordedAt),
          blocksActivation: true,
        },
      });
      return idem('created', 'inventory_observation');
    } catch (error) {
      if (isUniqueViolation(error)) {
        const existing = await this.client.osvQuarantineRecord.findUnique({
          where: { id: parsed.value.identity.value },
        });
        if (existing === null) {
          return fail('invalid_state');
        }
        const mapped = mapQuarantine(existing);
        if (
          mapped.catalogGenerationId === parsed.value.catalogGenerationId &&
          mapped.reasonCode === parsed.value.reasonCode &&
          mapped.originatingPhase === parsed.value.originatingPhase &&
          mapped.snapshotId === parsed.value.snapshotId &&
          mapped.parserAttemptId === parsed.value.parserAttemptId &&
          mapped.revisionId === parsed.value.revisionId &&
          mapped.providerObjectKeyDigest === parsed.value.providerObjectKeyDigest
        ) {
          return idem('already_applied', 'inventory_observation');
        }
        return idem('immutable_conflict', 'inventory_observation');
      }
      return mapCaught(error);
    }
  }
}

class PrismaOsvPresenceObservationRepository implements OsvPresenceObservationRepository {
  public constructor(private readonly client: PrismaClientLike) {}

  public async recordPresence(
    observation: Parameters<OsvPresenceObservationRepository['recordPresence']>[0],
  ): Promise<OsvPersistenceResult<OsvIdempotencyResult>> {
    const parsed = isOsvProviderPresenceObservation(observation)
      ? okResult(observation)
      : createOsvProviderPresenceObservation(observation);
    if (!parsed.ok) {
      return parsed;
    }
    if (parsed.value.kind === 'provider_absent_observed') {
      const inventory = await this.client.osvInventoryRun.findFirst({
        where: {
          catalogGenerationId: parsed.value.catalogGenerationId,
          state: 'complete',
          convergence: 'converged',
        },
        include: {
          observations: {
            where: { providerObjectKeyDigest: parsed.value.providerObjectKeyDigest },
            take: 1,
          },
        },
      });
      if (inventory === null) {
        return fail('invalid_state');
      }
      if (inventory.observations.length !== 0) {
        return fail('invalid_state');
      }
    } else {
      const listed = await this.client.osvInventoryObjectObservation.findFirst({
        where: {
          providerObjectKeyDigest: parsed.value.providerObjectKeyDigest,
          inventoryRun: { catalogGenerationId: parsed.value.catalogGenerationId },
        },
      });
      if (listed === null) {
        return fail('invalid_state');
      }
    }
    try {
      await this.client.osvProviderPresenceObservation.create({
        data: {
          catalogGenerationId: parsed.value.catalogGenerationId,
          providerObjectId: parsed.value.providerObjectId,
          providerObjectKeyDigest: parsed.value.providerObjectKeyDigest,
          kind: parsed.value.kind,
          recordedAt: fromIsoUtc(parsed.value.recordedAt),
          historicalSnapshotId: parsed.value.historicalSnapshotId,
          historicalRevisionId: parsed.value.historicalRevisionId,
        },
      });
      return idem('created', 'inventory_observation');
    } catch (error) {
      if (isUniqueViolation(error)) {
        const existing = await this.client.osvProviderPresenceObservation.findUnique({
          where: {
            catalogGenerationId_providerObjectId_kind: {
              catalogGenerationId: parsed.value.catalogGenerationId,
              providerObjectId: parsed.value.providerObjectId,
              kind: parsed.value.kind,
            },
          },
        });
        if (existing === null) {
          return fail('invalid_state');
        }
        const mapped = mapPresence(existing);
        if (
          mapped.providerObjectKeyDigest === parsed.value.providerObjectKeyDigest &&
          mapped.historicalSnapshotId === parsed.value.historicalSnapshotId &&
          mapped.historicalRevisionId === parsed.value.historicalRevisionId
        ) {
          return idem('already_applied', 'inventory_observation');
        }
        return idem('immutable_conflict', 'inventory_observation');
      }
      return mapCaught(error);
    }
  }
}

class PrismaOsvReconciliationRepository implements OsvReconciliationRepository {
  public constructor(private readonly client: PrismaClientLike) {}

  public async freezeReadyGeneration(input: {
    readonly generation: OsvCatalogGeneration;
    readonly reconciliation: Parameters<
      OsvReconciliationRepository['freezeReadyGeneration']
    >[0]['reconciliation'];
    readonly expectedVersion: number;
  }): Promise<OsvPersistenceResult<OsvIdempotencyResult>> {
    const parsedGeneration = isOsvCatalogGeneration(input.generation)
      ? okResult(input.generation)
      : createOsvCatalogGeneration(input.generation);
    if (!parsedGeneration.ok) {
      return parsedGeneration;
    }
    const gen = parsedGeneration.value;
    if (!isOsvReconciliationResult(input.reconciliation)) {
      return fail('invalid_field');
    }
    const reconciled = reconcileOsvGenerationCounts(input.reconciliation.counts);
    if (!reconciled.ok) {
      return reconciled;
    }
    if (gen.lifecycleState !== 'ready_for_activation') {
      return fail('generation_not_ready');
    }
    if (!reconciled.value.passed || reconciled.value.blocksActivation) {
      return fail('completeness_failed');
    }
    if (!activationCompletenessGatesPass(gen.completeness)) {
      return fail('completeness_failed');
    }
    if (!Number.isSafeInteger(input.expectedVersion) || input.expectedVersion < 1) {
      return fail('unsafe_integer');
    }
    try {
      const result = await withTransaction(this.client, async (tx) => {
        const current = await tx.osvCatalogGeneration.findUnique({
          where: { id: gen.identity.value },
          include: { completenessRows: true, reconciliation: true },
        });
        if (current === null) {
          return fail('invalid_state');
        }
        if (current.version !== input.expectedVersion) {
          return fail('invalid_state');
        }
        if (current.reconciliation !== null) {
          const mapped = mapReconciliation(current.reconciliation);
          if (
            mapped.passed === reconciled.value.passed &&
            mapped.counts.acceptedListedCount === reconciled.value.counts.acceptedListedCount &&
            mapped.counts.eligibleCount === reconciled.value.counts.eligibleCount &&
            mapped.counts.acceptedRevisionCount === reconciled.value.counts.acceptedRevisionCount
          ) {
            return idem('already_applied', 'reconciliation');
          }
          return idem('immutable_conflict', 'reconciliation');
        }
        if (!graphAllowsCatalogTransition(current.lifecycleState, 'ready_for_activation')) {
          return fail('invalid_transition');
        }
        await tx.osvReconciliation.create({
          data: {
            catalogGenerationId: reconciled.value.catalogGenerationId,
            acceptedListedCount: reconciled.value.counts.acceptedListedCount,
            eligibleCount: reconciled.value.counts.eligibleCount,
            ineligibleCount: reconciled.value.counts.ineligibleCount,
            legalReviewCount: reconciled.value.counts.legalReviewCount,
            unknownCount: reconciled.value.counts.unknownCount,
            ambiguousCount: reconciled.value.counts.ambiguousCount,
            listingRejectedCount: reconciled.value.counts.listingRejectedCount,
            attachedEligibleSnapshotCount: reconciled.value.counts.attachedEligibleSnapshotCount,
            missingEligibleSnapshotCount: reconciled.value.counts.missingEligibleSnapshotCount,
            nonEligibleSnapshotCount: reconciled.value.counts.nonEligibleSnapshotCount,
            parserSuccessCount: reconciled.value.counts.parserSuccessCount,
            parserFailureCount: reconciled.value.counts.parserFailureCount,
            quarantinedSnapshotCount: reconciled.value.counts.quarantinedSnapshotCount,
            acceptedRevisionCount: reconciled.value.counts.acceptedRevisionCount,
            withdrawnRevisionCount: reconciled.value.counts.withdrawnRevisionCount,
            membershipCount: reconciled.value.counts.membershipCount,
            providerAbsentCount: reconciled.value.counts.providerAbsentCount,
            immutableConflictCount: reconciled.value.counts.immutableConflictCount,
            blockingQuarantineCount: reconciled.value.counts.blockingQuarantineCount,
            failClosedRetrievedBodyCount: reconciled.value.counts.failClosedRetrievedBodyCount,
            pinMismatchCount: reconciled.value.counts.pinMismatchCount,
            passed: reconciled.value.passed,
            discrepancyCodes: [...reconciled.value.discrepancyCodes],
            blocksActivation: reconciled.value.blocksActivation,
            matchingCompleteness: 'not_in_scope',
          },
        });
        for (const dimension of [
          'inventory',
          'eligible_body',
          'parser',
          'parsed_catalog',
        ] as const) {
          const row =
            dimension === 'inventory'
              ? gen.completeness.inventory
              : dimension === 'eligible_body'
                ? gen.completeness.eligibleBody
                : dimension === 'parser'
                  ? gen.completeness.parser
                  : gen.completeness.parsedCatalog;
          const completenessUpdated = await tx.osvAcquisitionCompleteness.updateMany({
            where: { catalogGenerationId: gen.identity.value, dimension },
            data: {
              status: row.status,
              requiredCount: row.requiredCount,
              observedCount: row.observedCount,
              discrepancyCodes: [...row.discrepancyCodes],
              blocksActivation: row.blocksActivation,
            },
          });
          if (completenessUpdated.count !== 1) {
            return fail('invalid_state');
          }
        }
        const moved = await tx.osvCatalogGeneration.updateMany({
          where: { id: gen.identity.value, version: input.expectedVersion },
          data: {
            lifecycleState: 'ready_for_activation',
            version: gen.version,
            readyAt: gen.readyAt === null ? null : fromIsoUtc(gen.readyAt),
          },
        });
        if (moved.count !== 1) {
          return fail('invalid_state');
        }
        return idem('created', 'reconciliation');
      });
      if (!result.ok && result.code === 'immutable_conflict') {
        const existing = await this.client.osvReconciliation.findUnique({
          where: { catalogGenerationId: gen.identity.value },
        });
        if (existing !== null) {
          const mapped = mapReconciliation(existing);
          if (
            mapped.passed === reconciled.value.passed &&
            mapped.counts.acceptedListedCount === reconciled.value.counts.acceptedListedCount &&
            mapped.counts.eligibleCount === reconciled.value.counts.eligibleCount &&
            mapped.counts.acceptedRevisionCount === reconciled.value.counts.acceptedRevisionCount &&
            mapped.counts.immutableConflictCount ===
              reconciled.value.counts.immutableConflictCount &&
            mapped.counts.blockingQuarantineCount ===
              reconciled.value.counts.blockingQuarantineCount
          ) {
            return idem('already_applied', 'reconciliation');
          }
          return idem('immutable_conflict', 'reconciliation');
        }
      }
      return result;
    } catch (error) {
      return mapCaught(error);
    }
  }

  public async loadFrozen(
    catalogGenerationId: string,
  ): Promise<OsvPersistenceResult<ReturnType<typeof mapReconciliation>>> {
    try {
      const row = await this.client.osvReconciliation.findUnique({
        where: { catalogGenerationId },
      });
      if (row === null) {
        return fail('invalid_state');
      }
      return okResult(mapReconciliation(row));
    } catch (error) {
      return mapCaught(error);
    }
  }
}

class PrismaOsvActiveCatalogPointerRepository implements OsvActiveCatalogPointerRepository {
  public constructor(private readonly client: PrismaClientLike) {}

  public async loadForUpdate(
    scopeFingerprint: string,
  ): Promise<OsvPersistenceResult<OsvActiveCatalogPointer>> {
    if (!SHA256_HEX.test(scopeFingerprint)) {
      return fail('invalid_sha256');
    }
    if (!isRootPrismaClient(this.client)) {
      return this.readCurrent(scopeFingerprint);
    }
    try {
      return await this.client.$transaction(async (tx) => {
        await tx.$queryRaw`
          SELECT scope_fingerprint
          FROM osv_active_catalog_pointer
          WHERE scope_fingerprint = ${scopeFingerprint}
          FOR UPDATE
        `;
        const row = await tx.osvActiveCatalogPointer.findUnique({
          where: { scopeFingerprint },
        });
        if (row === null) {
          return createOsvActiveCatalogPointer({
            scopeFingerprint,
            generationId: null,
            version: 1,
            updatedAt: '1970-01-01T00:00:00.000Z',
          });
        }
        return okResult(mapPointer(row));
      });
    } catch (error) {
      return mapCaught(error);
    }
  }

  public async readCurrent(
    scopeFingerprint: string,
  ): Promise<OsvPersistenceResult<OsvActiveCatalogPointer>> {
    if (!SHA256_HEX.test(scopeFingerprint)) {
      return fail('invalid_sha256');
    }
    try {
      const row = await this.client.osvActiveCatalogPointer.findUnique({
        where: { scopeFingerprint },
      });
      if (row === null) {
        return createOsvActiveCatalogPointer({
          scopeFingerprint,
          generationId: null,
          version: 1,
          updatedAt: '1970-01-01T00:00:00.000Z',
        });
      }
      return okResult(mapPointer(row));
    } catch (error) {
      return mapCaught(error);
    }
  }

  public async activateReadyGeneration(input: {
    readonly request: OsvActivationRequest;
    readonly candidate: OsvCatalogGeneration;
  }): Promise<OsvPersistenceResult<OsvActivationResult>> {
    if (!isOsvActivationRequest(input.request)) {
      const parsed = createOsvActivationRequest(input.request);
      if (!parsed.ok) {
        return parsed;
      }
      return this.activateReadyGeneration({ request: parsed.value, candidate: input.candidate });
    }
    const parsedCandidate = isOsvCatalogGeneration(input.candidate)
      ? okResult(input.candidate)
      : createOsvCatalogGeneration(input.candidate);
    if (!parsedCandidate.ok) {
      return parsedCandidate;
    }
    const readyCandidate = parsedCandidate.value;
    if (!isRootPrismaClient(this.client)) {
      return fail('invalid_state');
    }
    try {
      const result = await withTransaction(
        this.client,
        async (tx) => {
          await acquireCatalogSyncLock(tx, input.request.scopeFingerprint);
          await tx.$queryRaw`
            SELECT scope_fingerprint
            FROM osv_active_catalog_pointer
            WHERE scope_fingerprint = ${input.request.scopeFingerprint}
            FOR UPDATE
          `;
          const pointerRow = await tx.osvActiveCatalogPointer.findUnique({
            where: { scopeFingerprint: input.request.scopeFingerprint },
          });
          const pointer =
            pointerRow === null
              ? createOsvActiveCatalogPointer({
                  scopeFingerprint: input.request.scopeFingerprint,
                  generationId: null,
                  version: 1,
                  updatedAt: '1970-01-01T00:00:00.000Z',
                })
              : okResult(mapPointer(pointerRow));
          if (!pointer.ok) {
            return pointer;
          }
          const storedCandidate = await tx.osvCatalogGeneration.findUnique({
            where: { id: readyCandidate.identity.value },
            include: { completenessRows: true, reconciliation: true },
          });
          if (storedCandidate === null) {
            return fail('invalid_state');
          }
          if (storedCandidate.scopeFingerprint !== input.request.scopeFingerprint) {
            const mismatchPointer = createOsvActiveCatalogPointer({
              scopeFingerprint: storedCandidate.scopeFingerprint,
              generationId: null,
              version: pointer.value.version,
              updatedAt: pointer.value.updatedAt,
            });
            if (!mismatchPointer.ok) {
              return mismatchPointer;
            }
            return evaluateOsvCatalogActivation({
              request: input.request,
              pointer: mismatchPointer.value,
              candidate: readyCandidate,
              completeness: readyCandidate.completeness,
            });
          }
          let mappedCandidate: OsvCatalogGeneration;
          try {
            mappedCandidate = mapCatalogGeneration(storedCandidate);
          } catch (error) {
            if (error instanceof OsvAcquisitionMappingError) {
              return fail('invalid_field');
            }
            throw error;
          }
          const existingHistory = await tx.osvActivationRecord.findUnique({
            where: { id: input.request.identity.value },
          });
          if (existingHistory !== null) {
            if (
              existingHistory.candidateGenerationId === mappedCandidate.identity.value &&
              existingHistory.scopeFingerprint === input.request.scopeFingerprint &&
              existingHistory.outcome === 'activated' &&
              pointer.value.generationId === mappedCandidate.identity.value &&
              mappedCandidate.lifecycleState === 'active'
            ) {
              const replayPointer = createOsvActiveCatalogPointer({
                scopeFingerprint: input.request.scopeFingerprint,
                generationId: mappedCandidate.identity.value,
                version: input.request.expectedPointerVersion,
                updatedAt: input.request.activatedAt,
              });
              if (!replayPointer.ok) {
                return replayPointer;
              }
              return evaluateOsvCatalogActivation({
                request: input.request,
                pointer: replayPointer.value,
                candidate: mappedCandidate,
                completeness: mappedCandidate.completeness,
              });
            }
            return fail('immutable_conflict');
          }
          const previousId = pointer.value.generationId;
          if (previousId !== null) {
            const previous = await tx.osvCatalogGeneration.findUnique({
              where: { id: previousId },
            });
            if (previous === null) {
              return fail('scope_mismatch');
            }
            if (
              previous.scopeFingerprint !== input.request.scopeFingerprint ||
              previous.scopeFingerprint !== pointer.value.scopeFingerprint
            ) {
              return fail('scope_mismatch');
            }
          }
          const blockingQuarantine = await tx.osvQuarantineRecord.count({
            where: {
              catalogGenerationId: mappedCandidate.identity.value,
              blocksActivation: true,
            },
          });
          const evaluated = evaluateOsvCatalogActivation({
            request: input.request,
            pointer: pointer.value,
            candidate: mappedCandidate,
            completeness: mappedCandidate.completeness,
          });
          if (!evaluated.ok) {
            return evaluated;
          }
          if (evaluated.value.outcome !== 'activated') {
            return evaluated;
          }
          if (blockingQuarantine > 0) {
            return fail('quarantine_blocked');
          }
          const reconciliationRow = storedCandidate.reconciliation;
          if (reconciliationRow === null) {
            return fail('completeness_failed');
          }
          const storedReconciliation = mapReconciliation(reconciliationRow);
          if (
            storedReconciliation.passed !== input.request.reconciliation.passed ||
            storedReconciliation.blocksActivation !==
              input.request.reconciliation.blocksActivation ||
            storedReconciliation.counts.acceptedListedCount !==
              input.request.reconciliation.counts.acceptedListedCount ||
            storedReconciliation.counts.immutableConflictCount !==
              input.request.reconciliation.counts.immutableConflictCount ||
            storedReconciliation.counts.blockingQuarantineCount !==
              input.request.reconciliation.counts.blockingQuarantineCount
          ) {
            return fail('immutable_conflict');
          }
          if (storedReconciliation.counts.immutableConflictCount > 0) {
            return fail('immutable_conflict');
          }
          if (
            !activationPrerequisitesSatisfied({
              inventoryComplete: mappedCandidate.completeness.inventory.status === 'complete',
              eligibleBodiesComplete:
                mappedCandidate.completeness.eligibleBody.status === 'complete',
              parserComplete: mappedCandidate.completeness.parser.status === 'complete',
              parsedCatalogComplete:
                mappedCandidate.completeness.parsedCatalog.status === 'complete',
              acceptedReconciliation: storedReconciliation.passed,
              noBlockingQuarantine: true,
              noImmutableConflict: true,
              versionSetConsistent:
                encodeOsvCatalogVersionSet(mappedCandidate.versionSet) ===
                encodeOsvCatalogVersionSet(input.request.versionSet),
              candidateReadyForActivation:
                mappedCandidate.lifecycleState === 'ready_for_activation',
            })
          ) {
            return fail('completeness_failed');
          }
          await tx.osvActivationRecord.create({
            data: {
              id: input.request.identity.value,
              scopeFingerprint: input.request.scopeFingerprint,
              candidateGenerationId: mappedCandidate.identity.value,
              previousGenerationId: pointer.value.generationId,
              expectedPointerVersion: input.request.expectedPointerVersion,
              resultingPointerVersion: evaluated.value.pointer.version,
              activatedAt: fromIsoUtc(input.request.activatedAt),
              reasonCode: input.request.reasonCode,
              outcome: 'activated',
            },
          });
          // One partial unique index allows a single active generation per scope.
          // Supersede the previous row before marking the candidate active.
          if (pointer.value.generationId !== null) {
            const superseded = await tx.osvCatalogGeneration.updateMany({
              where: {
                id: pointer.value.generationId,
                lifecycleState: 'active',
                scopeFingerprint: input.request.scopeFingerprint,
              },
              data: {
                lifecycleState: 'superseded',
                supersededAt: fromIsoUtc(input.request.activatedAt),
                version: { increment: 1 },
              },
            });
            if (superseded.count !== 1) {
              return fail('scope_mismatch');
            }
          }
          const activated = await tx.osvCatalogGeneration.updateMany({
            where: {
              id: mappedCandidate.identity.value,
              lifecycleState: 'ready_for_activation',
            },
            data: {
              lifecycleState: 'active',
              version: mappedCandidate.version + 1,
              activatedAt: fromIsoUtc(input.request.activatedAt),
            },
          });
          if (activated.count !== 1) {
            return fail('invalid_state');
          }
          if (pointerRow === null) {
            await tx.osvActiveCatalogPointer.create({
              data: {
                scopeFingerprint: evaluated.value.pointer.scopeFingerprint,
                generationId: mappedCandidate.identity.value,
                version: evaluated.value.pointer.version,
                updatedAt: fromIsoUtc(evaluated.value.pointer.updatedAt),
              },
            });
          } else {
            const swapped = await tx.osvActiveCatalogPointer.updateMany({
              where: {
                scopeFingerprint: input.request.scopeFingerprint,
                version: input.request.expectedPointerVersion,
              },
              data: {
                generationId: mappedCandidate.identity.value,
                version: evaluated.value.pointer.version,
                updatedAt: fromIsoUtc(evaluated.value.pointer.updatedAt),
              },
            });
            if (swapped.count !== 1) {
              return fail('stale_pointer');
            }
          }
          return evaluated;
        },
        Prisma.TransactionIsolationLevel.Serializable,
      );
      if (!result.ok && result.code === 'immutable_conflict') {
        const history = await this.client.osvActivationRecord.findUnique({
          where: { id: input.request.identity.value },
        });
        if (
          history !== null &&
          history.candidateGenerationId === readyCandidate.identity.value &&
          history.scopeFingerprint === input.request.scopeFingerprint &&
          history.outcome === 'activated'
        ) {
          const stored = await this.client.osvCatalogGeneration.findUnique({
            where: { id: readyCandidate.identity.value },
            include: { completenessRows: true },
          });
          if (stored === null) {
            return fail('stale_pointer');
          }
          const mapped = mapCatalogGeneration(stored);
          const livePointer = await this.readCurrent(input.request.scopeFingerprint);
          if (!livePointer.ok) {
            return livePointer;
          }
          if (livePointer.value.generationId !== mapped.identity.value) {
            return fail('stale_pointer');
          }
          const replayPointer = createOsvActiveCatalogPointer({
            scopeFingerprint: input.request.scopeFingerprint,
            generationId: mapped.identity.value,
            version: input.request.expectedPointerVersion,
            updatedAt: input.request.activatedAt,
          });
          if (!replayPointer.ok) {
            return replayPointer;
          }
          return evaluateOsvCatalogActivation({
            request: input.request,
            pointer: replayPointer.value,
            candidate: mapped,
            completeness: mapped.completeness,
          });
        }
        return fail('stale_pointer');
      }
      return result;
    } catch (error) {
      if (isUniqueViolation(error)) {
        return fail('stale_pointer');
      }
      return mapCaught(error);
    }
  }
}
