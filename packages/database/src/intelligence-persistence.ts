import { Prisma } from '@prisma/client';
import {
  INTELLIGENCE_KEV_MAX_VULNERABILITY_COUNT_MAX,
  INTELLIGENCE_KEV_STALE_THRESHOLD_SECONDS_DEFAULT,
  INTELLIGENCE_MAX_STAGED_ROWS_PER_TRANSACTION_MAX,
} from '@patchpilot/config';
import {
  CISA_KEV_SOURCE_IDENTIFIER,
  INTELLIGENCE_ACTIVATION_CONFLICT,
  INTELLIGENCE_AUDIT_SUBJECT_TYPE,
  INTELLIGENCE_GENERATION_COUNT_MISMATCH,
  INTELLIGENCE_GENERATION_INCOMPLETE,
  INTELLIGENCE_PARTIAL_ACTIVATION_INCONSISTENT,
  INTELLIGENCE_RETRY_RECONCILE_BATCH_LIMIT,
  INTELLIGENCE_SYNC_JOB_TYPE,
  INTELLIGENCE_SYNC_REQUESTED_EVENT_TYPE,
  INTELLIGENCE_TERMINAL_STATE,
  applyIntelligenceSyncRunTransition,
  classifyIntelligenceSafeFailure,
  createRequestedIntelligenceSyncRunRecord,
  err,
  intelligenceKevUpdatedAudit,
  intelligenceNormalizationCompletedAudit,
  intelligenceSnapshotStoredAudit,
  intelligenceSyncCompletedAudit,
  intelligenceSyncFailedAudit,
  intelligenceSyncNotModifiedAudit,
  intelligenceSyncQuarantinedAudit,
  intelligenceSyncRequestedAudit,
  intelligenceSyncStartedAudit,
  isIntelligenceTerminalSyncRunState,
  ok,
  validateIntelligenceSnapshotRecord,
  validateKevNormalizedEntryRecord,
  createIntelligenceSyncRequestedOutboxEvent,
  parseIntelligenceSyncJobPayload,
  parseIntelligenceSyncRequestedOutboxPayload,
  type ActivateKevGenerationInput,
  type ActivateKevGenerationResult,
  type ClaimFetchingAttemptInput,
  type ClaimIntelligenceSyncRunInput,
  type CompareAndSetSyncRunInput,
  type CompleteIntelligenceNotModifiedInput,
  type CompleteStagedGenerationInput,
  type CreateStagingGenerationAndRunInput,
  type CreateStagingKevGenerationInput,
  type InspectStagedKevPrefixInput,
  type IntelligenceFailureTransitionInput,
  type IntelligenceGenerationPersistencePort,
  type IntelligenceJobOwnership,
  type IntelligenceOutboxLookupPort,
  type IntelligenceProvider,
  type IntelligenceProviderFreshness,
  type IntelligenceRedeliveryPersistencePort,
  type IntelligenceRetryWaitTransitionInput,
  type IntelligenceSchedulerPersistencePort,
  type IntelligenceSnapshotIdentity,
  type IntelligenceSnapshotPersistencePort,
  type IntelligenceSnapshotRecord,
  type IntelligenceSourceFreshnessPort,
  type IntelligenceSourceIdentifier,
  type IntelligenceSourcePointer,
  type IntelligenceSyncRunPersistencePort,
  type IntelligenceSyncRunRecord,
  type IntelligenceSyncUnitOfWork,
  type InsertOrReuseIntelligenceSnapshotResult,
  type KevGenerationRecord,
  type KevNormalizedEntryRecord,
  type ListActiveKevEntriesPage,
  type ListActiveKevEntriesQuery,
  type ListDueIntelligenceRedeliveriesInput,
  type MarkIntelligenceAttemptStartedInput,
  type MarkIntelligenceDegradedFailureInput,
  type MarkIntelligenceNotModifiedInput,
  type MarkKevGenerationCompleteInput,
  type MarkSuccessfulIntelligenceGenerationInput,
  type PersistRequestedIntelligenceSyncInput,
  type PersistRequestedIntelligenceSyncResult,
  type ReconcileIntelligenceSourceEnablementInput,
  type ReconcileIntelligenceSourceEnablementResult,
  type Result,
  type StageKevEntryBatchInput,
  type StoreFetchedSnapshotInput,
  type StoreFetchedSnapshotResult,
  type AbandonKevGenerationInput,
  type AppError,
  type CanonicalCve,
  intelligenceValidationError,
} from '@patchpilot/domain';

import { PrismaBackgroundJobExecution } from './background-job-execution.js';
import type { PrismaClientLike } from './guards.js';
import { isRootPrismaClient, isUuid, requireSha256, requireVersionLabel } from './guards.js';
import {
  mapIntelligenceSnapshot,
  mapIntelligenceSyncRun,
  mapKevEntry,
  mapKevGeneration,
  mapProviderKey,
  toIntelligenceSyncRunSnapshot,
} from './intelligence-mappers.js';
import { mapOutboxEvent } from './mappers.js';
import { organizationWhere } from './outbox-relay-persistence.js';
import { createRepositories } from './repositories.js';

const CISA_KEV = 'cisa_kev' as const;
const TERMINAL_SYNC_STATES = ['completed', 'not_modified', 'failed', 'quarantined'] as const;

export type IntelligencePersistenceAdapters = {
  syncRuns: IntelligenceSyncRunPersistencePort;
  snapshots: IntelligenceSnapshotPersistencePort;
  generations: IntelligenceGenerationPersistencePort;
  freshness: IntelligenceSourceFreshnessPort;
  scheduler: IntelligenceSchedulerPersistencePort;
  unitOfWork: IntelligenceSyncUnitOfWork;
  outbox: IntelligenceOutboxLookupPort;
  redelivery: IntelligenceRedeliveryPersistencePort;
};

export function createIntelligencePersistence(
  client: PrismaClientLike,
): IntelligencePersistenceAdapters {
  const syncRuns = new PrismaIntelligenceSyncRunPersistence(client);
  const snapshots = new PrismaIntelligenceSnapshotPersistence(client);
  const generations = new PrismaIntelligenceGenerationPersistence(client);
  const freshness = new PrismaIntelligenceSourceFreshness(client);
  const unitOfWork = new PrismaIntelligenceSyncUnitOfWork(client);
  const outbox = new PrismaIntelligenceOutboxLookup(client);
  const redelivery = new PrismaIntelligenceRedeliveryPersistence(client);
  return {
    syncRuns,
    snapshots,
    generations,
    freshness,
    scheduler: unitOfWork,
    unitOfWork,
    outbox,
    redelivery,
  };
}

class IntelligenceTransactionRollback extends Error {
  public constructor(public readonly failure: { ok: false; error: AppError }) {
    super(failure.error.message);
    this.name = 'IntelligenceTransactionRollback';
  }
}

function isUniqueViolation(error: unknown): boolean {
  return error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002';
}

function isTransactionRollback(error: unknown): error is IntelligenceTransactionRollback {
  return error instanceof IntelligenceTransactionRollback;
}

function requireUuid(value: string, fieldName: string): string {
  if (!isUuid(value)) {
    throw new Error(`${fieldName} must be a UUID.`);
  }
  return value;
}

async function loadSyncRun(
  client: PrismaClientLike,
  id: string,
): Promise<IntelligenceSyncRunRecord | undefined> {
  const row = await client.vulnerabilitySyncRun.findUnique({ where: { id } });
  return row === null ? undefined : mapIntelligenceSyncRun(row);
}

async function casSyncRun(
  client: PrismaClientLike,
  input: CompareAndSetSyncRunInput,
): Promise<Result<IntelligenceSyncRunRecord>> {
  const current = await loadSyncRun(client, input.syncRunId);
  if (current === undefined) {
    return err({ code: 'not_found', message: 'Sync-run was not found.' });
  }
  if (isIntelligenceTerminalSyncRunState(current.state) && current.state !== input.expectedState) {
    return err(INTELLIGENCE_TERMINAL_STATE);
  }
  if (current.state !== input.expectedState || current.version !== input.expectedVersion) {
    return err({ code: 'conflict', message: 'Sync-run compare-and-set did not match.' });
  }
  const next = applyIntelligenceSyncRunTransition(
    toIntelligenceSyncRunSnapshot(current),
    input.command,
  );
  if (!next.ok) {
    return next;
  }
  if (next.value.state === 'completed' && next.value.generationId !== null) {
    const generation = await client.kevGeneration.findUnique({
      where: { id: next.value.generationId },
    });
    if (generation === null || !generationWasActivated(generation)) {
      return err(INTELLIGENCE_PARTIAL_ACTIVATION_INCONSISTENT);
    }
  }
  const updated = await client.vulnerabilitySyncRun.updateMany({
    where: {
      id: input.syncRunId,
      state: input.expectedState,
      version: input.expectedVersion,
    },
    data: {
      state: next.value.state,
      stage: next.value.stage,
      startedAt: next.value.startedAt,
      completedAt: next.value.completedAt,
      nextAttemptAt: next.value.nextAttemptAt,
      executionAttempt: next.value.executionAttempt,
      snapshotId: next.value.snapshotId,
      generationId: next.value.generationId,
      priorAcceptedGenerationId: next.value.priorAcceptedGenerationId,
      failureCategory: next.value.failureCategory,
      failureCode: next.value.failureCode,
      acceptedEntryCount: next.value.acceptedEntryCount,
      warningCount: next.value.warningCount,
      notModifiedReason: next.value.notModifiedReason,
      version: { increment: 1 },
    },
  });
  if (updated.count !== 1) {
    return err({ code: 'conflict', message: 'Sync-run compare-and-set did not match.' });
  }
  const reloaded = await loadSyncRun(client, input.syncRunId);
  if (reloaded === undefined) {
    return err({ code: 'not_found', message: 'Sync-run was not found after update.' });
  }
  return ok(reloaded);
}

class PrismaIntelligenceSyncRunPersistence implements IntelligenceSyncRunPersistencePort {
  public constructor(private readonly client: PrismaClientLike) {}

  public async createRequested(
    record: IntelligenceSyncRunRecord,
  ): Promise<Result<IntelligenceSyncRunRecord>> {
    const created = createRequestedIntelligenceSyncRunRecord({
      id: record.id,
      provider: record.provider,
      sourceIdentifier: record.sourceIdentifier,
      requestedAt: record.requestedAt,
      correlationId: record.correlationId,
      parserVersion: record.parserVersion,
      normalizationVersion: record.normalizationVersion,
    });
    if (!created.ok) {
      return created;
    }
    try {
      const row = await this.client.vulnerabilitySyncRun.create({
        data: {
          id: created.value.id,
          providerKey: CISA_KEV,
          sourceIdentifier: CISA_KEV_SOURCE_IDENTIFIER,
          state: 'requested',
          requestedAt: created.value.requestedAt,
          parserVersion: requireVersionLabel(created.value.parserVersion, 'parserVersion'),
          normalizationVersion: requireVersionLabel(
            created.value.normalizationVersion,
            'normalizationVersion',
          ),
          correlationId: created.value.correlationId,
          version: 1,
        },
      });
      return ok(mapIntelligenceSyncRun(row));
    } catch (error) {
      if (isUniqueViolation(error)) {
        return err({ code: 'conflict', message: 'An in-flight KEV sync-run already exists.' });
      }
      throw error;
    }
  }

  public async findById(id: string): Promise<IntelligenceSyncRunRecord | undefined> {
    return loadSyncRun(this.client, id);
  }

  public async findLatestByProviderAndSource(
    provider: IntelligenceProvider,
    sourceIdentifier: IntelligenceSourceIdentifier,
  ): Promise<IntelligenceSyncRunRecord | undefined> {
    if (provider !== CISA_KEV || sourceIdentifier !== CISA_KEV_SOURCE_IDENTIFIER) {
      return undefined;
    }
    const row = await this.client.vulnerabilitySyncRun.findFirst({
      where: { providerKey: CISA_KEV, sourceIdentifier: CISA_KEV_SOURCE_IDENTIFIER },
      orderBy: [{ requestedAt: 'desc' }, { id: 'desc' }],
    });
    return row === null ? undefined : mapIntelligenceSyncRun(row);
  }

  public async claimRequestedOrRetryWait(
    input: ClaimIntelligenceSyncRunInput,
  ): Promise<Result<IntelligenceSyncRunRecord>> {
    const current = await loadSyncRun(this.client, input.syncRunId);
    if (current === undefined) {
      return err({ code: 'not_found', message: 'Sync-run was not found.' });
    }
    const nextAttempt = input.expectedState === 'requested' ? 1 : current.executionAttempt + 1;
    return casSyncRun(this.client, {
      syncRunId: input.syncRunId,
      expectedState: input.expectedState,
      expectedVersion: input.expectedVersion,
      command: {
        type: 'start_fetching',
        startedAt: input.claimedAt,
        executionAttempt: nextAttempt,
      },
    });
  }

  public async applyCompareAndSetTransition(input: CompareAndSetSyncRunInput) {
    const result = await casSyncRun(this.client, input);
    if (!result.ok) {
      return result;
    }
    return ok(toIntelligenceSyncRunSnapshot(result.value));
  }

  public async recordRetryWait(input: CompareAndSetSyncRunInput) {
    return casSyncRun(this.client, input);
  }

  public async recordSnapshotStored(input: CompareAndSetSyncRunInput) {
    return casSyncRun(this.client, input);
  }

  public async recordParsing(input: CompareAndSetSyncRunInput) {
    return casSyncRun(this.client, input);
  }

  public async recordGenerationStaging(input: CompareAndSetSyncRunInput) {
    return casSyncRun(this.client, input);
  }

  public async recordActivationStarted(input: CompareAndSetSyncRunInput) {
    return casSyncRun(this.client, input);
  }

  public async completeRun(input: CompareAndSetSyncRunInput) {
    return casSyncRun(this.client, input);
  }

  public async completeNotModified(input: CompareAndSetSyncRunInput) {
    return casSyncRun(this.client, input);
  }

  public async quarantineRun(input: CompareAndSetSyncRunInput) {
    return casSyncRun(this.client, input);
  }

  public async failRun(input: CompareAndSetSyncRunInput) {
    return casSyncRun(this.client, input);
  }

  public async findTerminalById(id: string): Promise<IntelligenceSyncRunRecord | undefined> {
    const row = await this.client.vulnerabilitySyncRun.findFirst({
      where: { id, state: { in: [...TERMINAL_SYNC_STATES] } },
    });
    return row === null ? undefined : mapIntelligenceSyncRun(row);
  }
}

class PrismaIntelligenceSnapshotPersistence implements IntelligenceSnapshotPersistencePort {
  public constructor(private readonly client: PrismaClientLike) {}

  public async findByProviderSourceAndSha256(
    identity: IntelligenceSnapshotIdentity,
  ): Promise<IntelligenceSnapshotRecord | undefined> {
    if (identity.provider !== CISA_KEV) {
      return undefined;
    }
    const row = await this.client.vulnerabilityProviderSnapshot.findFirst({
      where: {
        providerKey: CISA_KEV,
        sourceIdentifier: identity.sourceIdentifier,
        responseSha256: requireSha256(identity.responseSha256, 'responseSha256'),
      },
    });
    return row === null ? undefined : mapIntelligenceSnapshot(row);
  }

  public async insertImmutable(
    record: IntelligenceSnapshotRecord,
  ): Promise<Result<IntelligenceSnapshotRecord>> {
    const validated = validateIntelligenceSnapshotRecord(record);
    if (!validated.ok) {
      return validated;
    }
    try {
      const row = await this.client.vulnerabilityProviderSnapshot.create({
        data: snapshotCreateData(validated.value),
      });
      return ok(mapIntelligenceSnapshot(row));
    } catch (error) {
      if (isUniqueViolation(error)) {
        return err({ code: 'conflict', message: 'Snapshot natural key already exists.' });
      }
      throw error;
    }
  }

  public async insertOrReuse(
    record: IntelligenceSnapshotRecord,
  ): Promise<Result<InsertOrReuseIntelligenceSnapshotResult>> {
    const validated = validateIntelligenceSnapshotRecord(record);
    if (!validated.ok) {
      return validated;
    }
    const identity = {
      provider: validated.value.provider,
      sourceIdentifier: validated.value.sourceIdentifier,
      responseSha256: validated.value.responseSha256,
    };
    const existing = await this.findByProviderSourceAndSha256(identity);
    if (existing !== undefined) {
      return ok({ record: existing, reused: true });
    }
    // Find-then-insert is the sequential path. Concurrent writers use
    // ON CONFLICT DO NOTHING so a unique race does not abort a PostgreSQL
    // interactive transaction (SQLSTATE 25P02 after a caught unique violation).
    const written = await this.client.vulnerabilityProviderSnapshot.createMany({
      data: [snapshotCreateData(validated.value)],
      skipDuplicates: true,
    });
    const loaded = await this.findByProviderSourceAndSha256(identity);
    if (loaded === undefined) {
      return err({ code: 'conflict', message: 'Snapshot unique conflict could not be loaded.' });
    }
    return ok({ record: loaded, reused: written.count === 0 });
  }

  public async findById(id: string): Promise<IntelligenceSnapshotRecord | undefined> {
    const row = await this.client.vulnerabilityProviderSnapshot.findUnique({ where: { id } });
    return row === null ? undefined : mapIntelligenceSnapshot(row);
  }

  public async verifyIdentity(
    id: string,
    identity: IntelligenceSnapshotIdentity,
  ): Promise<Result<IntelligenceSnapshotRecord>> {
    const record = await this.findById(id);
    if (record === undefined) {
      return err({ code: 'not_found', message: 'Snapshot was not found.' });
    }
    if (
      record.provider !== identity.provider ||
      record.sourceIdentifier !== identity.sourceIdentifier ||
      record.responseSha256 !== identity.responseSha256
    ) {
      return err(intelligenceValidationError('Snapshot identity does not match.'));
    }
    return ok(record);
  }
}

function snapshotCreateData(record: IntelligenceSnapshotRecord) {
  return {
    id: record.id,
    providerKey: CISA_KEV,
    sourceIdentifier: CISA_KEV_SOURCE_IDENTIFIER,
    responseSha256: record.responseSha256,
    byteLength: record.byteLength,
    declaredContentType: record.declaredContentType,
    detectedContentType: record.detectedContentType,
    objectKey: record.objectKey,
    retrievedAt: record.retrievedAt,
    storedAt: record.storedAt,
    etagHash: record.etagHash,
    lastModified: record.lastModified,
    creatingSyncRunId: record.creatingSyncRunId,
    createdAt: record.createdAt,
  };
}

async function inspectCounts(
  client: PrismaClientLike,
  generationId: string,
): Promise<{ stagedEntryCount: number; distinctCveCount: number }> {
  const rows = await client.$queryRaw<Array<{ staged: number; distinct_cves: number }>>`
    SELECT COUNT(*)::int AS staged, COUNT(DISTINCT "normalized_cve")::int AS distinct_cves
    FROM "kev_entry"
    WHERE "generation_id" = ${generationId}::uuid
  `;
  const row = rows[0];
  if (row === undefined) {
    return { stagedEntryCount: 0, distinctCveCount: 0 };
  }
  return { stagedEntryCount: row.staged, distinctCveCount: row.distinct_cves };
}

type LockedKevGeneration = {
  id: string;
  state: string;
  version: number;
  snapshotId: string;
  expectedEntryCount: number;
  parserVersion: string;
  normalizationVersion: string;
};

async function lockKevGeneration(
  tx: PrismaClientLike,
  generationId: string,
): Promise<LockedKevGeneration | undefined> {
  const rows = await tx.$queryRaw<
    Array<{
      id: string;
      state: string;
      version: number;
      snapshot_id: string;
      expected_entry_count: number;
      parser_version: string;
      normalization_version: string;
    }>
  >`
    SELECT
      "id",
      "state"::text AS "state",
      "version",
      "snapshot_id",
      "expected_entry_count",
      "parser_version",
      "normalization_version"
    FROM "kev_generation"
    WHERE "id" = ${generationId}::uuid
    FOR UPDATE
  `;
  const row = rows[0];
  if (row === undefined) {
    return undefined;
  }
  return {
    id: row.id,
    state: row.state,
    version: row.version,
    snapshotId: row.snapshot_id,
    expectedEntryCount: row.expected_entry_count,
    parserVersion: row.parser_version,
    normalizationVersion: row.normalization_version,
  };
}

function generationWasActivated(generation: { state: string; activatedAt: Date | null }): boolean {
  return (
    (generation.state === 'active' || generation.state === 'superseded') &&
    generation.activatedAt !== null
  );
}

class PrismaIntelligenceGenerationPersistence implements IntelligenceGenerationPersistencePort {
  public constructor(private readonly client: PrismaClientLike) {}

  public async createStagingGeneration(
    input: CreateStagingKevGenerationInput,
  ): Promise<Result<KevGenerationRecord>> {
    if (input.provider !== CISA_KEV || input.sourceIdentifier !== CISA_KEV_SOURCE_IDENTIFIER) {
      return err(intelligenceValidationError('Only the official KEV JSON catalog may stage.'));
    }
    if (
      !Number.isInteger(input.expectedEntryCount) ||
      input.expectedEntryCount < 0 ||
      input.expectedEntryCount > INTELLIGENCE_KEV_MAX_VULNERABILITY_COUNT_MAX
    ) {
      return err(
        intelligenceValidationError('Expected entry count exceeds the SQL safety ceiling.'),
      );
    }
    try {
      const row = await this.client.kevGeneration.create({
        data: {
          id: requireUuid(input.id, 'generationId'),
          providerKey: CISA_KEV,
          sourceIdentifier: CISA_KEV_SOURCE_IDENTIFIER,
          syncRunId: requireUuid(input.syncRunId, 'syncRunId'),
          snapshotId: requireUuid(input.snapshotId, 'snapshotId'),
          state: 'staging',
          expectedEntryCount: input.expectedEntryCount,
          stagedEntryCount: 0,
          parserVersion: requireVersionLabel(input.parserVersion, 'parserVersion'),
          normalizationVersion: requireVersionLabel(
            input.normalizationVersion,
            'normalizationVersion',
          ),
          ...(input.catalogVersion === undefined ? {} : { catalogVersion: input.catalogVersion }),
          ...(input.catalogReleasedAt === undefined
            ? {}
            : { catalogReleasedAt: input.catalogReleasedAt }),
          createdAt: input.createdAt,
        },
      });
      return ok(mapKevGeneration(row));
    } catch (error) {
      if (isUniqueViolation(error)) {
        return err({ code: 'conflict', message: 'A generation already exists for this sync-run.' });
      }
      throw error;
    }
  }

  public async findById(generationId: string): Promise<KevGenerationRecord | undefined> {
    const row = await this.client.kevGeneration.findUnique({ where: { id: generationId } });
    return row === null ? undefined : mapKevGeneration(row);
  }

  public async findBySyncRunId(syncRunId: string): Promise<KevGenerationRecord | undefined> {
    const row = await this.client.kevGeneration.findUnique({ where: { syncRunId } });
    return row === null ? undefined : mapKevGeneration(row);
  }

  public async inspectStagedPrefix(
    input: InspectStagedKevPrefixInput,
  ): Promise<KevNormalizedEntryRecord[]> {
    if (
      !Number.isInteger(input.limit) ||
      input.limit < 1 ||
      input.limit > INTELLIGENCE_KEV_MAX_VULNERABILITY_COUNT_MAX
    ) {
      return [];
    }
    const rows = await this.client.kevEntry.findMany({
      where: {
        generationId: input.generationId,
        ordinal: { gte: input.fromOrdinal },
      },
      include: { cwes: { orderBy: { ordinal: 'asc' } } },
      orderBy: { ordinal: 'asc' },
      take: input.limit,
    });
    return rows.map((row) => mapKevEntry(row, input.snapshotId));
  }

  public async stageBoundedEntryBatch(
    input: StageKevEntryBatchInput,
  ): Promise<Result<{ stagedEntryCount: number }>> {
    if (input.provider !== CISA_KEV || input.sourceIdentifier !== CISA_KEV_SOURCE_IDENTIFIER) {
      return err(intelligenceValidationError('Only the official KEV JSON catalog may stage.'));
    }
    if (
      !Number.isInteger(input.maxBatchSize) ||
      input.maxBatchSize < 1 ||
      input.maxBatchSize > INTELLIGENCE_MAX_STAGED_ROWS_PER_TRANSACTION_MAX
    ) {
      return err(
        intelligenceValidationError('Staging batch maximum is outside the approved bound.'),
      );
    }
    if (input.entries.length > input.maxBatchSize) {
      return err(intelligenceValidationError('Staging batch exceeds the caller-provided maximum.'));
    }
    const work = async (tx: PrismaClientLike): Promise<Result<{ stagedEntryCount: number }>> => {
      const generation = await lockKevGeneration(tx, input.generationId);
      if (
        generation === undefined ||
        generation.state !== 'staging' ||
        generation.snapshotId !== input.snapshotId
      ) {
        return err({
          code: 'conflict',
          message: 'Staging generation was not found or is not in staging.',
        });
      }
      for (const entry of input.entries) {
        if (entry.generationId !== input.generationId || entry.snapshotId !== input.snapshotId) {
          return err(
            intelligenceValidationError(
              'Staged entries must match generation and snapshot identity.',
            ),
          );
        }
        const validated = validateKevNormalizedEntryRecord(entry);
        if (!validated.ok) {
          return validated;
        }
      }
      try {
        for (const entry of input.entries) {
          await tx.kevEntry.create({
            data: {
              id: entry.id,
              generationId: entry.generationId,
              ordinal: entry.ordinal,
              normalizedCve: entry.normalizedCve,
              vendorProject: entry.vendorProject,
              product: entry.product,
              vulnerabilityName: entry.vulnerabilityName,
              dateAdded: entry.dateAdded,
              shortDescription: entry.shortDescription,
              requiredAction: entry.requiredAction,
              dueDate: entry.dueDate,
              knownRansomwareCampaignUse: entry.knownRansomwareCampaignUse,
              rawKnownRansomwareCampaignUse: entry.rawKnownRansomwareCampaignUse,
              notes: entry.notes,
              createdAt: entry.createdAt,
              cwes: {
                create: entry.cwes.map((normalizedCwe, ordinal) => ({
                  ordinal,
                  normalizedCwe,
                  createdAt: entry.createdAt,
                })),
              },
            },
          });
        }
      } catch (error) {
        if (isUniqueViolation(error)) {
          return err(intelligenceValidationError('duplicate_cve'));
        }
        throw error;
      }
      const counts = await inspectCounts(tx, input.generationId);
      await tx.kevGeneration.update({
        where: { id: input.generationId },
        data: { stagedEntryCount: counts.stagedEntryCount },
      });
      return ok({ stagedEntryCount: counts.stagedEntryCount });
    };
    return runInClientTransaction(this.client, work);
  }

  public async inspectStagedCounts(generationId: string) {
    const generation = await this.client.kevGeneration.findUnique({ where: { id: generationId } });
    if (generation === null) {
      return undefined;
    }
    return inspectCounts(this.client, generationId);
  }

  public async markGenerationComplete(
    input: MarkKevGenerationCompleteInput,
  ): Promise<Result<KevGenerationRecord>> {
    return runInClientTransaction(this.client, async (tx) => {
      const generation = await lockKevGeneration(tx, input.generationId);
      if (generation === undefined) {
        return err({ code: 'not_found', message: 'Generation was not found.' });
      }
      if (generation.state !== 'staging') {
        return err(INTELLIGENCE_GENERATION_INCOMPLETE);
      }
      const counts = await inspectCounts(tx, input.generationId);
      if (
        counts.distinctCveCount !== input.expectedEntryCount ||
        counts.stagedEntryCount !== input.expectedEntryCount ||
        counts.distinctCveCount !== input.actualStagedDistinctCveCount ||
        generation.expectedEntryCount !== input.expectedEntryCount ||
        generation.parserVersion !== input.parserVersion ||
        generation.normalizationVersion !== input.normalizationVersion
      ) {
        return err(INTELLIGENCE_GENERATION_COUNT_MISMATCH);
      }
      const updated = await tx.kevGeneration.updateMany({
        where: { id: input.generationId, state: 'staging', version: generation.version },
        data: {
          state: 'complete',
          stagedEntryCount: counts.stagedEntryCount,
          catalogVersion: input.catalogVersion,
          catalogReleasedAt: input.catalogReleasedAt,
          completedAt: input.completedAt,
          version: { increment: 1 },
        },
      });
      if (updated.count !== 1) {
        return err({ code: 'conflict', message: 'Generation compare-and-set did not match.' });
      }
      const reloaded = await tx.kevGeneration.findUniqueOrThrow({
        where: { id: input.generationId },
      });
      return ok(mapKevGeneration(reloaded));
    });
  }

  public async activateCompleteGeneration(input: ActivateKevGenerationInput) {
    return activateCompleteGenerationTx(this.client, input);
  }

  public async findActiveGeneration(
    provider: 'cisa_kev',
    sourceIdentifier: 'cisa_kev_json_catalog',
  ) {
    if (provider !== CISA_KEV || sourceIdentifier !== CISA_KEV_SOURCE_IDENTIFIER) {
      return undefined;
    }
    const source = await this.client.intelligenceSource.findUnique({
      where: { providerKey: CISA_KEV },
    });
    if (source?.activeGenerationId === null || source === null) {
      return undefined;
    }
    const generation = await this.client.kevGeneration.findFirst({
      where: {
        id: source.activeGenerationId,
        providerKey: CISA_KEV,
        sourceIdentifier: CISA_KEV_SOURCE_IDENTIFIER,
        state: 'active',
      },
    });
    return generation === null ? undefined : mapKevGeneration(generation);
  }

  public async listActiveEntries(
    query: ListActiveKevEntriesQuery,
  ): Promise<ListActiveKevEntriesPage> {
    if (query.limit < 1 || query.limit > 100) {
      return { items: [], nextOrdinal: null, nextId: null };
    }
    const active = await this.findActiveGeneration(query.provider, query.sourceIdentifier);
    if (active === undefined) {
      return { items: [], nextOrdinal: null, nextId: null };
    }
    const afterOrdinal = query.afterOrdinal;
    const afterId = query.afterId;
    const rows = await this.client.kevEntry.findMany({
      where: {
        generationId: active.id,
        ...(afterOrdinal === undefined || afterId === undefined
          ? {}
          : {
              OR: [
                { ordinal: { gt: afterOrdinal } },
                { ordinal: afterOrdinal, id: { gt: afterId } },
              ],
            }),
      },
      orderBy: [{ ordinal: 'asc' }, { id: 'asc' }],
      take: query.limit + 1,
    });
    const page = rows.slice(0, query.limit);
    const extra = rows[query.limit];
    const last = page[page.length - 1];
    return {
      items: page.map((row) => ({
        provider: CISA_KEV,
        sourceIdentifier: CISA_KEV_SOURCE_IDENTIFIER,
        generationId: active.id,
        snapshotId: active.snapshotId,
        normalizedCve: row.normalizedCve as CanonicalCve,
        ordinal: row.ordinal,
      })),
      nextOrdinal: extra === undefined || last === undefined ? null : last.ordinal,
      nextId: extra === undefined || last === undefined ? null : last.id,
    };
  }

  public async markGenerationSuperseded(
    generationId: string,
    supersededAt: Date,
  ): Promise<Result<KevGenerationRecord>> {
    return runInClientTransaction(this.client, async (tx) => {
      const source = await lockCisaKevSource(tx);
      if (source.activeGenerationId === generationId) {
        return err({
          code: 'conflict',
          message: 'The active KEV pointer cannot be superseded outside atomic activation.',
        });
      }
      const generation = await tx.kevGeneration.findUnique({ where: { id: generationId } });
      if (generation === null) {
        return err({ code: 'not_found', message: 'Generation was not found.' });
      }
      if (generation.state !== 'active') {
        return err(intelligenceValidationError('Only an active KEV generation can be superseded.'));
      }
      const updated = await tx.kevGeneration.updateMany({
        where: { id: generationId, state: 'active', version: generation.version },
        data: {
          state: 'superseded',
          supersededAt,
          version: { increment: 1 },
        },
      });
      if (updated.count !== 1) {
        return err({ code: 'conflict', message: 'Generation compare-and-set did not match.' });
      }
      return ok(
        mapKevGeneration(await tx.kevGeneration.findUniqueOrThrow({ where: { id: generationId } })),
      );
    });
  }

  public async abandonIncompleteGeneration(
    input: AbandonKevGenerationInput,
  ): Promise<Result<KevGenerationRecord>> {
    const generation = await this.client.kevGeneration.findUnique({
      where: { id: input.generationId },
    });
    if (generation === null) {
      return err({ code: 'not_found', message: 'Generation was not found.' });
    }
    if (generation.state !== input.expectedState) {
      return err({
        code: 'conflict',
        message: 'Generation is not in the expected incomplete state.',
      });
    }
    const updated = await this.client.kevGeneration.updateMany({
      where: {
        id: input.generationId,
        state: input.expectedState,
        version: generation.version,
        activatedAt: null,
        supersededAt: null,
      },
      data: {
        state: 'abandoned',
        abandonedAt: input.abandonedAt,
        version: { increment: 1 },
      },
    });
    if (updated.count !== 1) {
      return err({ code: 'conflict', message: 'Generation compare-and-set did not match.' });
    }
    return ok(
      mapKevGeneration(
        await this.client.kevGeneration.findUniqueOrThrow({ where: { id: input.generationId } }),
      ),
    );
  }

  public async findStaleIncompleteGenerations(olderThan: Date) {
    const rows = await this.client.kevGeneration.findMany({
      where: {
        state: { in: ['staging', 'complete'] },
        createdAt: { lt: olderThan },
        intelligenceSources: { none: {} },
      },
      orderBy: { createdAt: 'asc' },
    });
    return rows.map(mapKevGeneration);
  }
}

class PrismaIntelligenceSourceFreshness implements IntelligenceSourceFreshnessPort {
  public constructor(private readonly client: PrismaClientLike) {}

  public async loadCurrentProviderStatus(
    provider: IntelligenceProvider,
    sourceIdentifier: IntelligenceSourceIdentifier,
    _now: Date,
  ): Promise<IntelligenceProviderFreshness> {
    if (provider === 'osv') {
      return {
        provider: 'osv',
        sourceIdentifier: null,
        implementationStatus: 'deferred',
        runtimeEnabled: false,
        lastSuccessfulSyncAt: null,
        lastAttemptAt: null,
        latestAcceptedCatalogVersion: null,
        latestAcceptedCatalogReleasedAt: null,
        currentEntryCount: null,
        lastSafeFailureCode: null,
        lastFailureAt: null,
        staleThresholdSeconds: INTELLIGENCE_KEV_STALE_THRESHOLD_SECONDS_DEFAULT,
      };
    }
    const source = await this.client.intelligenceSource.findUnique({
      where: { providerKey: mapProviderKey(provider) },
      include: { activeGeneration: true },
    });
    const disabled = source === null || source.state === 'disabled';
    const generation = source?.activeGeneration ?? null;
    return {
      provider: CISA_KEV,
      sourceIdentifier,
      implementationStatus: disabled ? 'disabled' : 'available',
      runtimeEnabled: !disabled,
      lastSuccessfulSyncAt: source?.lastSuccessfulSyncAt ?? null,
      lastAttemptAt: source?.lastAttemptAt ?? null,
      latestAcceptedCatalogVersion: generation?.catalogVersion ?? null,
      latestAcceptedCatalogReleasedAt: generation?.catalogReleasedAt ?? null,
      currentEntryCount: generation?.expectedEntryCount ?? null,
      lastSafeFailureCode: source?.lastFailureCode ?? null,
      lastFailureAt: source?.lastFailureAt ?? null,
      staleThresholdSeconds: INTELLIGENCE_KEV_STALE_THRESHOLD_SECONDS_DEFAULT,
    };
  }

  public async loadCisaKevSourcePointer(): Promise<IntelligenceSourcePointer | undefined> {
    const source = await this.client.intelligenceSource.findUnique({
      where: { providerKey: CISA_KEV },
    });
    if (source === null) {
      return undefined;
    }
    return {
      sourceId: source.id,
      version: source.version,
      activeGenerationId: source.activeGenerationId,
    };
  }

  public async reconcileRuntimeEnablement(
    input: ReconcileIntelligenceSourceEnablementInput,
  ): Promise<Result<ReconcileIntelligenceSourceEnablementResult>> {
    if (input.provider !== CISA_KEV) {
      return err(intelligenceValidationError('OSV enablement cannot be reconciled in Session 9.'));
    }
    const desired = input.enabled ? 'enabled' : 'disabled';
    const source = await this.client.intelligenceSource.findUnique({
      where: { providerKey: CISA_KEV },
    });
    if (source === null) {
      return err({
        code: 'not_found',
        message: 'CISA KEV IntelligenceSource row is missing.',
      });
    }
    if (source.state === desired) {
      return ok({ outcome: 'unchanged' as const, version: source.version });
    }
    const updated = await this.client.intelligenceSource.updateMany({
      where: {
        providerKey: CISA_KEV,
        version: source.version,
        NOT: { state: desired },
      },
      data: {
        state: desired,
        version: { increment: 1 },
      },
    });
    if (updated.count !== 1) {
      const latest = await this.client.intelligenceSource.findUnique({
        where: { providerKey: CISA_KEV },
      });
      return ok({
        outcome: 'version_conflict' as const,
        version: latest?.version ?? source.version,
      });
    }
    return ok({ outcome: 'updated' as const, version: source.version + 1 });
  }

  public async markAttemptStarted(input: MarkIntelligenceAttemptStartedInput) {
    if (input.provider !== CISA_KEV) {
      return err(intelligenceValidationError('OSV cannot mark a Session 9 attempt.'));
    }
    await this.client.intelligenceSource.update({
      where: { providerKey: CISA_KEV },
      data: { lastAttemptAt: input.attemptedAt },
    });
    return ok(
      await this.loadCurrentProviderStatus(
        input.provider,
        input.sourceIdentifier,
        input.attemptedAt,
      ),
    );
  }

  public async markSuccessfulCompletedGeneration(input: MarkSuccessfulIntelligenceGenerationInput) {
    if (input.provider !== CISA_KEV) {
      return err(intelligenceValidationError('OSV cannot mark a Session 9 success.'));
    }
    await this.client.intelligenceSource.update({
      where: { providerKey: CISA_KEV },
      data: {
        lastSuccessfulSyncAt: input.completedAt,
        lastAttemptAt: input.completedAt,
      },
    });
    return ok(
      await this.loadCurrentProviderStatus(
        input.provider,
        input.sourceIdentifier,
        input.completedAt,
      ),
    );
  }

  public async markNotModified(input: MarkIntelligenceNotModifiedInput) {
    if (input.provider !== CISA_KEV) {
      return err(intelligenceValidationError('OSV cannot mark not-modified.'));
    }
    await this.client.intelligenceSource.update({
      where: { providerKey: CISA_KEV },
      data: {
        lastSuccessfulSyncAt: input.completedAt,
        lastAttemptAt: input.completedAt,
      },
    });
    return ok(
      await this.loadCurrentProviderStatus(
        input.provider,
        input.sourceIdentifier,
        input.completedAt,
      ),
    );
  }

  public async markDegradedFailure(input: MarkIntelligenceDegradedFailureInput) {
    if (input.provider !== CISA_KEV) {
      return err(intelligenceValidationError('OSV cannot mark a Session 9 failure.'));
    }
    await this.client.intelligenceSource.update({
      where: { providerKey: CISA_KEV },
      data: {
        lastAttemptAt: input.failedAt,
        lastFailureAt: input.failedAt,
        lastFailureCode: input.failureCode,
      },
    });
    return ok(
      await this.loadCurrentProviderStatus(input.provider, input.sourceIdentifier, input.failedAt),
    );
  }
}

class PrismaIntelligenceSyncUnitOfWork
  implements IntelligenceSyncUnitOfWork, IntelligenceSchedulerPersistencePort
{
  public constructor(private readonly client: PrismaClientLike) {}

  public async requestSync(
    input: PersistRequestedIntelligenceSyncInput,
  ): Promise<Result<PersistRequestedIntelligenceSyncResult>> {
    try {
      const result = await runInClientTransaction(this.client, (tx) => requestSyncTx(tx, input));
      if (result.ok || result.error.code !== 'conflict') {
        return result;
      }
    } catch (error) {
      if (!isUniqueViolation(error)) {
        throw error;
      }
    }
    const inflight = await this.client.vulnerabilitySyncRun.findFirst({
      where: {
        providerKey: CISA_KEV,
        sourceIdentifier: CISA_KEV_SOURCE_IDENTIFIER,
        state: { notIn: [...TERMINAL_SYNC_STATES] },
      },
      orderBy: [{ requestedAt: 'desc' }, { id: 'desc' }],
    });
    if (inflight !== null) {
      return ok({
        outcome: 'existing_inflight' as const,
        syncRun: mapIntelligenceSyncRun(inflight),
      });
    }
    const existingWindow = await this.client.outboxEvent.findFirst({
      where: {
        organizationId: null,
        eventType: INTELLIGENCE_SYNC_REQUESTED_EVENT_TYPE,
        dedupeKey: input.dedupeKey,
      },
    });
    if (existingWindow !== null) {
      return ok({ outcome: 'duplicate_window' as const });
    }
    return err({ code: 'conflict', message: 'Duplicate KEV sync request was not in-flight.' });
  }

  public async claimFetchingAttempt(input: ClaimFetchingAttemptInput) {
    return runInClientTransaction(this.client, (tx) => claimFetchingAttemptTx(tx, input));
  }

  public async storeFetchedSnapshot(input: StoreFetchedSnapshotInput) {
    return runInClientTransaction(this.client, (tx) => storeFetchedSnapshotTx(tx, input));
  }

  public async createStagingGenerationAndRun(input: CreateStagingGenerationAndRunInput) {
    return runInClientTransaction(this.client, (tx) => createStagingGenerationAndRunTx(tx, input));
  }

  public async completeStagedGeneration(input: CompleteStagedGenerationInput) {
    return runInClientTransaction(this.client, (tx) => completeStagedGenerationTx(tx, input));
  }

  public async activateCompleteGeneration(input: ActivateKevGenerationInput) {
    return activateCompleteGenerationTx(this.client, input);
  }

  public async completeNotModified(input: CompleteIntelligenceNotModifiedInput) {
    return runInClientTransaction(this.client, (tx) => completeNotModifiedTx(tx, input));
  }

  public async recordRetryWait(input: IntelligenceRetryWaitTransitionInput) {
    return runInClientTransaction(this.client, async (tx) => {
      const result = await casSyncRun(tx, {
        syncRunId: input.syncRunId,
        expectedState: input.expectedState,
        expectedVersion: input.expectedVersion,
        command: {
          type: 'record_retry_wait',
          nextAttemptAt: input.nextAttemptAt,
          failureCode: input.failureCode,
        },
      });
      if (!result.ok) {
        return result;
      }
      await tx.intelligenceSource.update({
        where: { providerKey: CISA_KEV },
        data: { lastAttemptAt: input.attemptedAt },
      });
      if (input.backgroundJob !== undefined) {
        const classification = classifyIntelligenceSafeFailure(input.failureCode);
        const jobs = new PrismaBackgroundJobExecution(tx);
        const retried = await jobs.markRetry({
          organizationId: null,
          jobId: input.backgroundJob.jobId,
          workerIdentifier: input.backgroundJob.workerIdentifier,
          failureCategory: classification.category,
          failureCode: input.failureCode,
          availableAt: input.nextAttemptAt,
        });
        if (!retried.ok) {
          return err({ code: 'conflict', message: 'Background job ownership did not match.' });
        }
      }
      return result;
    });
  }

  public async failRun(input: IntelligenceFailureTransitionInput) {
    return runInClientTransaction(this.client, (tx) => failOrQuarantineTx(tx, input, 'fail'));
  }

  public async quarantineRun(input: IntelligenceFailureTransitionInput) {
    return runInClientTransaction(this.client, (tx) => failOrQuarantineTx(tx, input, 'quarantine'));
  }
}

async function runInClientTransaction<T>(
  client: PrismaClientLike,
  work: (tx: PrismaClientLike) => Promise<Result<T>>,
): Promise<Result<T>> {
  const execute = async (tx: PrismaClientLike): Promise<Result<T>> => {
    const result = await work(tx);
    if (!result.ok) {
      throw new IntelligenceTransactionRollback(result);
    }
    return result;
  };
  try {
    if (isRootPrismaClient(client)) {
      return await client.$transaction(async (tx) => execute(tx));
    }
    return await execute(client);
  } catch (error) {
    if (isTransactionRollback(error)) {
      return error.failure;
    }
    throw error;
  }
}

async function requestSyncTx(
  tx: PrismaClientLike,
  input: PersistRequestedIntelligenceSyncInput,
): Promise<Result<PersistRequestedIntelligenceSyncResult>> {
  const payload = parseIntelligenceSyncRequestedOutboxPayload({
    schemaVersion: 1,
    syncRunId: input.syncRunId,
    provider: input.provider,
    sourceIdentifier: input.sourceIdentifier,
  });
  if (!payload.ok) {
    return payload;
  }
  const syncRuns = new PrismaIntelligenceSyncRunPersistence(tx);
  const created = createRequestedIntelligenceSyncRunRecord({
    id: input.syncRunId,
    provider: input.provider,
    sourceIdentifier: input.sourceIdentifier,
    requestedAt: input.requestedAt,
    correlationId: input.correlationId,
    parserVersion: input.parserVersion,
    normalizationVersion: input.normalizationVersion,
  });
  if (!created.ok) {
    return created;
  }
  const inserted = await syncRuns.createRequested(created.value);
  if (!inserted.ok) {
    return inserted;
  }
  const repos = createRepositories(tx);
  await repos.auditEvents.append(
    intelligenceSyncRequestedAudit(
      {
        provider: input.provider,
        sourceIdentifier: input.sourceIdentifier,
        syncRunId: input.syncRunId,
      },
      input.correlationId,
      input.requestedAt,
    ),
  );
  await repos.outboxEvents.create(
    createIntelligenceSyncRequestedOutboxEvent({
      syncRunId: input.syncRunId,
      payload: payload.value,
      dedupeKey: input.dedupeKey,
      occurredAt: input.requestedAt,
    }),
  );
  return ok({ outcome: 'created' as const, syncRun: inserted.value });
}

async function claimFetchingAttemptTx(
  tx: PrismaClientLike,
  input: ClaimFetchingAttemptInput,
): Promise<Result<IntelligenceSyncRunRecord>> {
  const current = await loadSyncRun(tx, input.syncRunId);
  if (current === undefined) {
    return err({ code: 'not_found', message: 'Sync-run was not found.' });
  }
  const executionAttempt = input.expectedState === 'requested' ? 1 : current.executionAttempt + 1;
  const claimed = await casSyncRun(tx, {
    syncRunId: input.syncRunId,
    expectedState: input.expectedState,
    expectedVersion: input.expectedVersion,
    command: {
      type: 'start_fetching',
      startedAt: input.claimedAt,
      executionAttempt,
    },
  });
  if (!claimed.ok) {
    return claimed;
  }
  await tx.intelligenceSource.update({
    where: { providerKey: CISA_KEV },
    data: { lastAttemptAt: input.claimedAt },
  });
  const repos = createRepositories(tx);
  await repos.auditEvents.append(
    intelligenceSyncStartedAudit(
      {
        provider: CISA_KEV,
        sourceIdentifier: CISA_KEV_SOURCE_IDENTIFIER,
        syncRunId: input.syncRunId,
        executionAttempt,
      },
      input.correlationId,
      input.claimedAt,
    ),
  );
  return claimed;
}

function reusedSnapshotMatches(
  existing: IntelligenceSnapshotRecord,
  candidate: IntelligenceSnapshotRecord,
): boolean {
  return (
    existing.provider === candidate.provider &&
    existing.sourceIdentifier === candidate.sourceIdentifier &&
    existing.responseSha256 === candidate.responseSha256 &&
    existing.byteLength === candidate.byteLength &&
    existing.objectKey === candidate.objectKey &&
    existing.declaredContentType === candidate.declaredContentType &&
    existing.detectedContentType === candidate.detectedContentType
  );
}

async function storeFetchedSnapshotTx(
  tx: PrismaClientLike,
  input: StoreFetchedSnapshotInput,
): Promise<Result<StoreFetchedSnapshotResult>> {
  const snapshots = new PrismaIntelligenceSnapshotPersistence(tx);
  const inserted = await snapshots.insertOrReuse(input.snapshot);
  if (!inserted.ok) {
    return inserted;
  }
  if (inserted.value.reused && !reusedSnapshotMatches(inserted.value.record, input.snapshot)) {
    return err({ code: 'conflict', message: 'Reused snapshot identity did not match.' });
  }

  if (input.notModified !== undefined) {
    const completed = await completeNotModifiedTx(tx, {
      syncRunId: input.syncRunId,
      expectedState: input.expectedState,
      expectedVersion: input.expectedVersion,
      completedAt: input.notModified.completedAt,
      reason: input.notModified.reason,
      priorAcceptedGenerationId: input.notModified.priorAcceptedGenerationId,
      correlationId: input.correlationId,
      ...(input.notModified.backgroundJob === undefined
        ? {}
        : { backgroundJob: input.notModified.backgroundJob }),
    });
    if (!completed.ok) {
      return completed;
    }
    return ok({
      snapshot: inserted.value.record,
      reused: inserted.value.reused,
      syncRun: completed.value,
      outcome: 'not_modified',
    });
  }

  const stored = await casSyncRun(tx, {
    syncRunId: input.syncRunId,
    expectedState: input.expectedState,
    expectedVersion: input.expectedVersion,
    command: { type: 'record_stored', snapshotId: inserted.value.record.id },
  });
  if (!stored.ok) {
    return stored;
  }
  await tx.intelligenceSource.update({
    where: { providerKey: CISA_KEV },
    data: { lastAttemptAt: input.snapshot.storedAt },
  });
  const repos = createRepositories(tx);
  await repos.auditEvents.append(
    intelligenceSnapshotStoredAudit(
      {
        provider: CISA_KEV,
        sourceIdentifier: CISA_KEV_SOURCE_IDENTIFIER,
        syncRunId: input.syncRunId,
        snapshotId: inserted.value.record.id,
        byteLength: inserted.value.record.byteLength,
        responseSha256: inserted.value.record.responseSha256,
      },
      input.correlationId,
      input.snapshot.storedAt,
    ),
  );
  return ok({
    snapshot: inserted.value.record,
    reused: inserted.value.reused,
    syncRun: stored.value,
    outcome: 'stored',
  });
}

async function createStagingGenerationAndRunTx(
  tx: PrismaClientLike,
  input: CreateStagingGenerationAndRunInput,
): Promise<Result<{ generation: KevGenerationRecord; syncRun: IntelligenceSyncRunRecord }>> {
  const generations = new PrismaIntelligenceGenerationPersistence(tx);
  let generation: KevGenerationRecord;
  const created = await generations.createStagingGeneration(input.generation);
  if (created.ok) {
    generation = created.value;
  } else if (created.error.code === 'conflict') {
    const existing = await generations.findBySyncRunId(input.syncRunId);
    if (existing === undefined) {
      return err({ code: 'conflict', message: 'A generation already exists for this sync-run.' });
    }
    generation = existing;
  } else {
    return created;
  }
  const staged = await casSyncRun(tx, {
    syncRunId: input.syncRunId,
    expectedState: input.expectedState,
    expectedVersion: input.expectedVersion,
    command: { type: 'start_staging', generationId: generation.id },
  });
  if (!staged.ok) {
    const current = await loadSyncRun(tx, input.syncRunId);
    if (
      current !== undefined &&
      current.state === 'staging' &&
      current.generationId === generation.id
    ) {
      return ok({ generation, syncRun: current });
    }
    return staged;
  }
  return ok({ generation, syncRun: staged.value });
}

async function completeStagedGenerationTx(
  tx: PrismaClientLike,
  input: CompleteStagedGenerationInput,
): Promise<Result<{ generation: KevGenerationRecord; syncRun: IntelligenceSyncRunRecord }>> {
  const generations = new PrismaIntelligenceGenerationPersistence(tx);
  const completed = await generations.markGenerationComplete(input.generation);
  if (!completed.ok) {
    return completed;
  }
  const repos = createRepositories(tx);
  await repos.auditEvents.append(
    intelligenceNormalizationCompletedAudit(
      {
        provider: CISA_KEV,
        sourceIdentifier: CISA_KEV_SOURCE_IDENTIFIER,
        syncRunId: input.syncRunId,
        generationId: input.generation.generationId,
        entryCount: input.generation.expectedEntryCount,
        warningCount: input.warningCount,
        parserVersion: input.generation.parserVersion,
        normalizationVersion: input.generation.normalizationVersion,
      },
      input.correlationId,
      input.generation.completedAt,
    ),
  );
  const activating = await casSyncRun(tx, {
    syncRunId: input.syncRunId,
    expectedState: input.expectedState,
    expectedVersion: input.expectedVersion,
    command: {
      type: 'start_activating',
      generationComplete: true,
      warningCount: input.warningCount,
    },
  });
  if (!activating.ok) {
    const current = await loadSyncRun(tx, input.syncRunId);
    if (
      current !== undefined &&
      current.state === 'activating' &&
      current.generationId === input.generation.generationId &&
      current.warningCount === input.warningCount
    ) {
      return ok({ generation: completed.value, syncRun: current });
    }
    return activating;
  }
  return ok({ generation: completed.value, syncRun: activating.value });
}

async function completeNotModifiedTx(
  tx: PrismaClientLike,
  input: CompleteIntelligenceNotModifiedInput,
): Promise<Result<IntelligenceSyncRunRecord>> {
  const locked = await lockCisaKevSource(tx);
  if (locked.activeGenerationId === null) {
    return err(intelligenceValidationError('not_modified requires an active KEV generation.'));
  }
  if (locked.activeGenerationId !== input.priorAcceptedGenerationId) {
    return err(INTELLIGENCE_ACTIVATION_CONFLICT);
  }
  const completed = await casSyncRun(tx, {
    syncRunId: input.syncRunId,
    expectedState: input.expectedState,
    expectedVersion: input.expectedVersion,
    command: {
      type: 'complete_not_modified',
      completedAt: input.completedAt,
      priorAcceptedGenerationId: input.priorAcceptedGenerationId,
      reason: input.reason,
    },
  });
  if (!completed.ok) {
    return completed;
  }
  await tx.intelligenceSource.update({
    where: { id: locked.id },
    data: {
      lastSuccessfulSyncAt: input.completedAt,
      lastAttemptAt: input.completedAt,
    },
  });
  const repos = createRepositories(tx);
  await repos.auditEvents.append(
    intelligenceSyncNotModifiedAudit(
      {
        provider: CISA_KEV,
        sourceIdentifier: CISA_KEV_SOURCE_IDENTIFIER,
        syncRunId: input.syncRunId,
        generationId: input.priorAcceptedGenerationId,
      },
      input.correlationId,
      input.completedAt,
    ),
  );
  if (input.backgroundJob !== undefined) {
    const jobResult = await completeOwnedJob(tx, input.backgroundJob, input.completedAt);
    if (!jobResult.ok) {
      return jobResult;
    }
  }
  return completed;
}

async function failOrQuarantineTx(
  tx: PrismaClientLike,
  input: IntelligenceFailureTransitionInput,
  kind: 'fail' | 'quarantine',
): Promise<Result<IntelligenceSyncRunRecord>> {
  const classification = classifyIntelligenceSafeFailure(input.failureCode);
  const result = await casSyncRun(tx, {
    syncRunId: input.syncRunId,
    expectedState: input.expectedState,
    expectedVersion: input.expectedVersion,
    command:
      kind === 'fail'
        ? { type: 'fail', completedAt: input.completedAt, failureCode: input.failureCode }
        : { type: 'quarantine', completedAt: input.completedAt, failureCode: input.failureCode },
  });
  if (!result.ok) {
    return result;
  }
  await tx.intelligenceSource.update({
    where: { providerKey: CISA_KEV },
    data: {
      lastAttemptAt: input.completedAt,
      lastFailureAt: input.completedAt,
      lastFailureCode: input.failureCode,
    },
  });
  const repos = createRepositories(tx);
  const audit = kind === 'fail' ? intelligenceSyncFailedAudit : intelligenceSyncQuarantinedAudit;
  await repos.auditEvents.append(
    audit(
      {
        provider: CISA_KEV,
        sourceIdentifier: CISA_KEV_SOURCE_IDENTIFIER,
        syncRunId: input.syncRunId,
        failureCode: input.failureCode,
      },
      input.correlationId,
      input.completedAt,
    ),
  );
  if (input.backgroundJob !== undefined) {
    const job = await tx.backgroundJob.updateMany({
      where: {
        id: input.backgroundJob.jobId,
        organizationId: null,
        jobType: INTELLIGENCE_SYNC_JOB_TYPE,
        workerIdentifier: input.backgroundJob.workerIdentifier,
        status: 'running',
      },
      data: {
        status: 'failed',
        completedAt: input.completedAt,
        leaseExpiresAt: null,
        failureCategory: classification.category,
        failureCode: input.failureCode,
      },
    });
    if (job.count !== 1) {
      return err({ code: 'conflict', message: 'Background job ownership did not match.' });
    }
  }
  return result;
}

async function activateCompleteGenerationTx(
  client: PrismaClientLike,
  input: ActivateKevGenerationInput,
): Promise<Result<ActivateKevGenerationResult>> {
  const existing = await loadSyncRun(client, input.syncRunId);
  if (
    existing !== undefined &&
    existing.state === 'completed' &&
    existing.generationId === input.generationId
  ) {
    const generation = await client.kevGeneration.findUnique({ where: { id: input.generationId } });
    if (generation === null) {
      return err({ code: 'not_found', message: 'Generation was not found.' });
    }
    if (!generationWasActivated(generation)) {
      return err(INTELLIGENCE_PARTIAL_ACTIVATION_INCONSISTENT);
    }
    return ok({
      outcome: 'idempotent_replay',
      generation: mapKevGeneration(generation),
      syncRun: existing,
    });
  }
  return runInClientTransaction(client, (tx) => activateInsideTransaction(tx, input));
}

async function activateInsideTransaction(
  tx: PrismaClientLike,
  input: ActivateKevGenerationInput,
): Promise<Result<ActivateKevGenerationResult>> {
  const source = await lockCisaKevSource(tx);
  const generationRow = await tx.kevGeneration.findFirst({
    where: {
      id: input.generationId,
      providerKey: CISA_KEV,
      sourceIdentifier: CISA_KEV_SOURCE_IDENTIFIER,
      snapshotId: input.snapshotId,
      syncRunId: input.syncRunId,
    },
  });
  if (generationRow === null) {
    return err({ code: 'not_found', message: 'Generation was not found.' });
  }
  const syncRun = await loadSyncRun(tx, input.syncRunId);
  if (syncRun === undefined) {
    return err({ code: 'not_found', message: 'Sync-run was not found.' });
  }
  if (
    generationRow.state === 'active' &&
    source.activeGenerationId === generationRow.id &&
    syncRun.state !== 'completed'
  ) {
    return err(INTELLIGENCE_PARTIAL_ACTIVATION_INCONSISTENT);
  }
  if (syncRun.state === 'completed' && syncRun.generationId === input.generationId) {
    if (!generationWasActivated(generationRow)) {
      return err(INTELLIGENCE_PARTIAL_ACTIVATION_INCONSISTENT);
    }
    return ok({
      outcome: 'idempotent_replay',
      generation: mapKevGeneration(generationRow),
      syncRun,
    });
  }
  if (generationRow.state !== 'complete' || generationRow.completedAt === null) {
    return err(INTELLIGENCE_GENERATION_INCOMPLETE);
  }
  if (generationRow.stagedEntryCount !== generationRow.expectedEntryCount) {
    return err(INTELLIGENCE_GENERATION_COUNT_MISMATCH);
  }
  const counts = await inspectCounts(tx, input.generationId);
  if (
    counts.distinctCveCount !== generationRow.expectedEntryCount ||
    counts.distinctCveCount !== input.expectedEntryCount
  ) {
    return err(INTELLIGENCE_GENERATION_COUNT_MISMATCH);
  }
  if (
    generationRow.parserVersion !== input.parserVersion ||
    generationRow.normalizationVersion !== input.normalizationVersion ||
    syncRun.parserVersion !== input.parserVersion ||
    syncRun.normalizationVersion !== input.normalizationVersion ||
    syncRun.snapshotId !== input.snapshotId
  ) {
    return err(intelligenceValidationError('Activation identity does not match the sync-run.'));
  }
  if (source.version !== input.expectedSourceVersion) {
    return err(INTELLIGENCE_ACTIVATION_CONFLICT);
  }
  if (
    (source.activeGenerationId === null && input.previousActiveGenerationId !== null) ||
    (source.activeGenerationId !== null &&
      source.activeGenerationId !== input.previousActiveGenerationId)
  ) {
    return err(INTELLIGENCE_ACTIVATION_CONFLICT);
  }
  if (input.previousActiveGenerationId !== null) {
    const previous = await tx.kevGeneration.findUnique({
      where: { id: input.previousActiveGenerationId },
    });
    if (previous === null || previous.state !== 'active') {
      return err(INTELLIGENCE_ACTIVATION_CONFLICT);
    }
    const superseded = await tx.kevGeneration.updateMany({
      where: { id: previous.id, state: 'active', version: previous.version },
      data: {
        state: 'superseded',
        supersededAt: input.activatedAt,
        version: { increment: 1 },
      },
    });
    if (superseded.count !== 1) {
      return err(INTELLIGENCE_ACTIVATION_CONFLICT);
    }
  }
  const activated = await tx.kevGeneration.updateMany({
    where: { id: input.generationId, state: 'complete', version: generationRow.version },
    data: {
      state: 'active',
      activatedAt: input.activatedAt,
      version: { increment: 1 },
    },
  });
  if (activated.count !== 1) {
    return err({ code: 'conflict', message: 'Generation compare-and-set did not match.' });
  }
  const pointer = await tx.intelligenceSource.updateMany({
    where: {
      id: source.id,
      version: input.expectedSourceVersion,
      ...(input.previousActiveGenerationId === null
        ? { activeGenerationId: null }
        : { activeGenerationId: input.previousActiveGenerationId }),
    },
    data: {
      activeGenerationId: input.generationId,
      version: { increment: 1 },
      lastSuccessfulSyncAt: input.activatedAt,
      lastAttemptAt: input.activatedAt,
    },
  });
  if (pointer.count !== 1) {
    return err(INTELLIGENCE_ACTIVATION_CONFLICT);
  }
  const completed = await casSyncRun(tx, {
    syncRunId: input.syncRunId,
    expectedState: input.expectedSyncRunState,
    expectedVersion: input.expectedSyncRunVersion,
    command: {
      type: 'complete',
      completedAt: input.activatedAt,
      acceptedEntryCount: input.acceptedEntryCount,
      warningCount: input.warningCount,
    },
  });
  if (!completed.ok) {
    return completed;
  }
  const repos = createRepositories(tx);
  await repos.auditEvents.append(
    intelligenceSyncCompletedAudit(
      {
        provider: CISA_KEV,
        sourceIdentifier: CISA_KEV_SOURCE_IDENTIFIER,
        syncRunId: input.syncRunId,
        snapshotId: input.snapshotId,
        generationId: input.generationId,
        entryCount: input.acceptedEntryCount,
        warningCount: input.warningCount,
        parserVersion: input.parserVersion,
        normalizationVersion: input.normalizationVersion,
      },
      input.correlationId,
      input.activatedAt,
    ),
  );
  await repos.auditEvents.append(
    intelligenceKevUpdatedAudit(
      {
        provider: CISA_KEV,
        sourceIdentifier: CISA_KEV_SOURCE_IDENTIFIER,
        syncRunId: input.syncRunId,
        intelligenceSourceId: source.id,
        snapshotId: input.snapshotId,
        generationId: input.generationId,
        entryCount: input.acceptedEntryCount,
        warningCount: input.warningCount,
      },
      input.correlationId,
      input.activatedAt,
    ),
  );
  if (input.backgroundJob !== undefined) {
    const jobResult = await completeOwnedJob(tx, input.backgroundJob, input.activatedAt);
    if (!jobResult.ok) {
      return jobResult;
    }
  }
  const active = await tx.kevGeneration.findUniqueOrThrow({ where: { id: input.generationId } });
  return ok({
    outcome: 'activated',
    generation: mapKevGeneration(active),
    syncRun: completed.value,
  });
}

async function lockCisaKevSource(tx: PrismaClientLike) {
  const rows = await tx.$queryRaw<
    Array<{
      id: string;
      version: number;
      active_generation_id: string | null;
    }>
  >`
    SELECT "id", "version", "active_generation_id"
    FROM "intelligence_source"
    WHERE "provider_key" = 'cisa_kev'
    FOR UPDATE
  `;
  const row = rows[0];
  if (row === undefined) {
    throw new Error('CISA KEV IntelligenceSource row is missing.');
  }
  return {
    id: row.id,
    version: row.version,
    activeGenerationId: row.active_generation_id,
  };
}

async function completeOwnedJob(
  tx: PrismaClientLike,
  ownership: IntelligenceJobOwnership,
  completedAt: Date,
): Promise<Result<void>> {
  if (ownership.organizationId !== null || ownership.jobType !== INTELLIGENCE_SYNC_JOB_TYPE) {
    return err({ code: 'conflict', message: 'Background job ownership did not match.' });
  }
  const job = await tx.backgroundJob.findFirst({
    where: {
      id: ownership.jobId,
      organizationId: null,
      jobType: INTELLIGENCE_SYNC_JOB_TYPE,
      workerIdentifier: ownership.workerIdentifier,
      status: 'running',
    },
  });
  if (job === null) {
    return err({ code: 'conflict', message: 'Background job ownership did not match.' });
  }
  const jobs = new PrismaBackgroundJobExecution(tx);
  const succeeded = await jobs.markSucceeded({
    organizationId: null,
    jobId: ownership.jobId,
    workerIdentifier: ownership.workerIdentifier,
    completedAt,
  });
  if (!succeeded.ok) {
    return err({ code: 'conflict', message: 'Background job ownership did not match.' });
  }
  return ok(undefined);
}

class PrismaIntelligenceOutboxLookup implements IntelligenceOutboxLookupPort {
  public constructor(private readonly client: PrismaClientLike) {}

  public async findById(input: { organizationId: null; eventId: string }) {
    const row = await this.client.outboxEvent.findFirst({
      where: { id: input.eventId, ...organizationWhere(input.organizationId) },
    });
    return row === null ? undefined : mapOutboxEvent(row);
  }
}

type RedeliveryRow = {
  syncRunId: string;
  backgroundJobId: string;
  outboxEventId: string;
  jobAttempt: number;
  jobStatus: 'queued' | 'running';
  syncRunState: string;
  nextAttemptAt: Date | null;
  leaseExpiresAt: Date | null;
  dedupeKey: string;
};

class PrismaIntelligenceRedeliveryPersistence implements IntelligenceRedeliveryPersistencePort {
  public constructor(private readonly client: PrismaClientLike) {}

  public async listDueRedeliveries(input: ListDueIntelligenceRedeliveriesInput) {
    const limit = Math.min(Math.max(1, input.limit), INTELLIGENCE_RETRY_RECONCILE_BATCH_LIMIT);
    const minAgeMs = Math.max(0, input.minAgeMs);
    const rows = await this.client.$queryRaw<RedeliveryRow[]>(Prisma.sql`
      SELECT
        vsr."id" AS "syncRunId",
        bj."id" AS "backgroundJobId",
        oe."id" AS "outboxEventId",
        bj."attempt" AS "jobAttempt",
        bj."status" AS "jobStatus",
        vsr."state" AS "syncRunState",
        vsr."next_attempt_at" AS "nextAttemptAt",
        bj."lease_expires_at" AS "leaseExpiresAt",
        oe."dedupe_key" AS "dedupeKey"
      FROM "vulnerability_sync_run" vsr
      INNER JOIN "outbox_event" oe
        ON oe."aggregate_id" = vsr."id"
        AND oe."organization_id" IS NULL
        AND oe."aggregate_type" = ${INTELLIGENCE_AUDIT_SUBJECT_TYPE}
        AND oe."event_type" = ${INTELLIGENCE_SYNC_REQUESTED_EVENT_TYPE}
      INNER JOIN "background_job" bj
        ON bj."outbox_event_id" = oe."id"
        AND bj."organization_id" IS NULL
        AND bj."job_type" = ${INTELLIGENCE_SYNC_JOB_TYPE}
      WHERE vsr."provider_key" = CAST(${CISA_KEV} AS "integration_provider_key")
        AND vsr."source_identifier" = ${CISA_KEV_SOURCE_IDENTIFIER}
        AND vsr."state" NOT IN ('completed', 'not_modified', 'failed', 'quarantined')
        AND bj."status" NOT IN ('failed', 'succeeded', 'dead_lettered', 'cancelled')
        AND (
          vsr."state" <> 'retry_wait'
          OR (
            vsr."next_attempt_at" IS NOT NULL
            AND vsr."next_attempt_at" <= ${input.now}
          )
        )
        AND (
          (
            vsr."state" = 'retry_wait'
            AND vsr."next_attempt_at" IS NOT NULL
            AND vsr."next_attempt_at" <= ${input.now}
            AND (
              bj."status" = 'queued'
              OR (
                bj."status" = 'running'
                AND bj."lease_expires_at" IS NOT NULL
                AND bj."lease_expires_at" < ${input.now}
              )
            )
          )
          OR (
            vsr."state" IN ('stored', 'parsing', 'staging', 'activating')
            AND bj."status" = 'queued'
          )
          OR (
            bj."status" = 'running'
            AND bj."lease_expires_at" IS NOT NULL
            AND bj."lease_expires_at" < ${input.now}
          )
          OR (
            bj."status" = 'queued'
            AND vsr."state" IN ('requested', 'fetching')
            AND bj."created_at" <= ${new Date(input.now.getTime() - minAgeMs)}
            AND oe."status" = 'processed'
          )
        )
      ORDER BY vsr."requested_at" ASC, vsr."id" ASC
      LIMIT ${limit}
    `);

    const candidates = [];
    for (const row of rows) {
      const locator = parseIntelligenceSyncJobPayload({
        organizationId: null,
        outboxEventId: row.outboxEventId,
        aggregateType: INTELLIGENCE_AUDIT_SUBJECT_TYPE,
        aggregateId: row.syncRunId,
        eventType: INTELLIGENCE_SYNC_REQUESTED_EVENT_TYPE,
        dedupeKey: row.dedupeKey,
      });
      if (!locator.ok) {
        continue;
      }
      if (row.jobStatus !== 'queued' && row.jobStatus !== 'running') {
        continue;
      }
      candidates.push({
        syncRunId: row.syncRunId,
        backgroundJobId: row.backgroundJobId,
        outboxEventId: row.outboxEventId,
        jobAttempt: row.jobAttempt,
        jobStatus: row.jobStatus,
        syncRunState: row.syncRunState as IntelligenceSyncRunRecord['state'],
        nextAttemptAt: row.nextAttemptAt,
        leaseExpiresAt: row.leaseExpiresAt,
        locator: locator.value,
      });
    }
    return candidates;
  }
}
