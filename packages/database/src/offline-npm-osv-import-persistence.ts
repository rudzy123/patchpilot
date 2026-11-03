/**
 * PostgreSQL batch and terminal audit for the deployment-local offline npm
 * OSV import. File revisions stay on the advisory revision adapter.
 * No network, object storage, queue, Finding, or Vulnerability write.
 *
 * Lock order inside each transaction:
 * 1. Validate the command.
 * 2. Take the correlation advisory lock.
 * 3. Classify replay or conflict.
 * 4. Insert at most one batch or one terminal audit.
 */

import { JSON_SCHEMA_VERSION_V1 } from '@patchpilot/domain';
import { Prisma, type PrismaClient } from '@prisma/client';
import {
  OFFLINE_NPM_ACCEPTED_SOURCE,
  OFFLINE_NPM_OSV_IMPORT_AUDIT_REASONS,
  OFFLINE_NPM_OSV_IMPORT_MAX_FILE_BYTES,
  OFFLINE_NPM_OSV_IMPORT_MAX_FILES,
  OSV_SOURCE_LICENSE_REGISTRY_IDENTIFIER,
  SUPERSESSION_NONE,
  compareOfflineNpmImportNames,
  type OfflineNpmImportSummary,
} from '@patchpilot/vulnerability-intelligence';

import {
  isAdvisoryRevisionUniqueViolation,
  translateAdvisoryRevisionPersistenceFailure,
} from './advisory-revision-persistence-errors.js';
import { asJsonObject } from './guards.js';

const STARTED_ACTION = 'intelligence.offline_npm_osv_import_started';
const COMPLETED_ACTION = 'intelligence.offline_npm_osv_import_completed';
const FILE_ACTION = 'intelligence.offline_npm_osv_file_imported';
const BATCH_SUBJECT = 'offline_advisory_import_batch';
const CORRELATION_LOCK_PREFIX = 'offline-npm-osv-correlation:';
const AUDIT_ACTIONS = [STARTED_ACTION, COMPLETED_ACTION, FILE_ACTION] as const;
const AUDIT_REASONS = new Set<string>(OFFLINE_NPM_OSV_IMPORT_AUDIT_REASONS);
const SHA256_HEX = /^[a-f0-9]{64}$/;
const UUID_TEXT = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const ADVISORY_ID = /^[A-Z0-9][A-Z0-9._+-]{0,511}$/;
const MAX_BYTE_LENGTH = OFFLINE_NPM_OSV_IMPORT_MAX_FILES * OFFLINE_NPM_OSV_IMPORT_MAX_FILE_BYTES;

export type OfflineNpmImportBatchBeginInput = {
  readonly correlationId: string;
  readonly manifestSha256: string;
  readonly byteLength: number;
};

export type OfflineNpmImportBatchBegin =
  | {
      readonly kind: 'started' | 'already_applied';
      readonly batchId: string;
      readonly retrievedAt: string;
    }
  | { readonly kind: 'immutable_conflict' }
  | { readonly kind: 'database_unavailable' }
  | { readonly kind: 'transaction_aborted' }
  | { readonly kind: 'internal_failure' };

export type OfflineNpmSupersessionInput = {
  readonly source: typeof OFFLINE_NPM_ACCEPTED_SOURCE;
  readonly advisoryId: string;
  readonly packageIdentityKey: string;
  readonly rawContentSha256: string;
};

export type OfflineNpmSupersessionResolution =
  | { readonly kind: 'ready'; readonly supersedesRevisionDigest: string }
  | { readonly kind: 'malformed_persisted_state' }
  | { readonly kind: 'database_unavailable' }
  | { readonly kind: 'transaction_aborted' }
  | { readonly kind: 'internal_failure' };

export type OfflineNpmImportBatchCompleteInput = {
  readonly batchId: string;
  readonly correlationId: string;
  readonly manifestSha256: string;
  readonly byteLength: number;
  readonly summary: OfflineNpmImportSummary;
};

export type OfflineNpmImportBatchComplete =
  | { readonly kind: 'recorded' | 'already_applied' }
  | { readonly kind: 'immutable_conflict' }
  | { readonly kind: 'database_unavailable' }
  | { readonly kind: 'transaction_aborted' }
  | { readonly kind: 'internal_failure' };

type PersistenceFailure = 'database_unavailable' | 'transaction_aborted' | 'internal_failure';

export type OfflineNpmOsvImportPersistence = {
  beginBatch(input: OfflineNpmImportBatchBeginInput): Promise<OfflineNpmImportBatchBegin>;
  resolveSupersession(
    input: OfflineNpmSupersessionInput,
  ): Promise<OfflineNpmSupersessionResolution>;
  completeBatch(input: OfflineNpmImportBatchCompleteInput): Promise<OfflineNpmImportBatchComplete>;
};

export function createOfflineNpmOsvImportPersistence(
  client: PrismaClient,
): OfflineNpmOsvImportPersistence {
  return {
    beginBatch(input) {
      return beginBatch(client, input);
    },
    resolveSupersession(input) {
      return resolveSupersession(client, input);
    },
    completeBatch(input) {
      return completeBatch(client, input);
    },
  };
}

async function beginBatch(
  client: PrismaClient,
  input: OfflineNpmImportBatchBeginInput,
): Promise<OfflineNpmImportBatchBegin> {
  if (!validBatchInput(input)) {
    return { kind: 'internal_failure' };
  }
  try {
    return await client.$transaction((tx) => insertBatch(tx, input), {
      maxWait: 5_000,
      timeout: 10_000,
    });
  } catch (error) {
    if (!isAdvisoryRevisionUniqueViolation(error)) {
      return { kind: classifyFailure(error) };
    }
  }
  try {
    return await client.$transaction((tx) => reloadBatch(tx, input), {
      maxWait: 5_000,
      timeout: 10_000,
    });
  } catch (error) {
    return { kind: classifyFailure(error) };
  }
}

async function insertBatch(
  tx: Prisma.TransactionClient,
  input: OfflineNpmImportBatchBeginInput,
): Promise<OfflineNpmImportBatchBegin> {
  await lockCorrelation(tx, input.correlationId);
  if (await correlationConflicts(tx, input.correlationId, input.manifestSha256)) {
    return { kind: 'immutable_conflict' };
  }
  const existing = await tx.offlineAdvisoryImportBatch.findUnique({
    where: { manifestSha256: input.manifestSha256 },
    select: { id: true, retrievedAt: true, sourceLicenseRegistryVersion: true },
  });
  if (existing !== null) {
    if (existing.sourceLicenseRegistryVersion !== OSV_SOURCE_LICENSE_REGISTRY_IDENTIFIER) {
      return { kind: 'internal_failure' };
    }
    return {
      kind: 'already_applied',
      batchId: existing.id,
      retrievedAt: existing.retrievedAt.toISOString(),
    };
  }
  const retrievedAt = await readClock(tx);
  const created = await tx.offlineAdvisoryImportBatch.create({
    data: {
      manifestSha256: input.manifestSha256,
      sourceLicenseRegistryVersion: OSV_SOURCE_LICENSE_REGISTRY_IDENTIFIER,
      retrievedAt,
    },
    select: { id: true, retrievedAt: true },
  });
  await tx.auditEvent.create({
    data: {
      actorType: 'system',
      action: STARTED_ACTION,
      subjectType: BATCH_SUBJECT,
      subjectId: created.id,
      correlationId: input.correlationId,
      schemaVersion: JSON_SCHEMA_VERSION_V1,
      retentionCategory: 'security',
      payload: auditPayload({
        manifestSha256: input.manifestSha256,
        byteLength: input.byteLength,
        advisoryIds: [],
        reasonCodes: ['started'],
        counts: { accepted: 0, skipped: 0, rejected: 0, failed: 0 },
      }),
    },
  });
  return {
    kind: 'started',
    batchId: created.id,
    retrievedAt: created.retrievedAt.toISOString(),
  };
}

async function reloadBatch(
  tx: Prisma.TransactionClient,
  input: OfflineNpmImportBatchBeginInput,
): Promise<OfflineNpmImportBatchBegin> {
  await lockCorrelation(tx, input.correlationId);
  if (await correlationConflicts(tx, input.correlationId, input.manifestSha256)) {
    return { kind: 'immutable_conflict' };
  }
  const existing = await tx.offlineAdvisoryImportBatch.findUnique({
    where: { manifestSha256: input.manifestSha256 },
    select: { id: true, retrievedAt: true, sourceLicenseRegistryVersion: true },
  });
  if (
    existing === null ||
    existing.sourceLicenseRegistryVersion !== OSV_SOURCE_LICENSE_REGISTRY_IDENTIFIER
  ) {
    return { kind: 'internal_failure' };
  }
  return {
    kind: 'already_applied',
    batchId: existing.id,
    retrievedAt: existing.retrievedAt.toISOString(),
  };
}

async function completeBatch(
  client: PrismaClient,
  input: OfflineNpmImportBatchCompleteInput,
): Promise<OfflineNpmImportBatchComplete> {
  if (!validBatchInput(input) || !UUID_TEXT.test(input.batchId)) {
    return { kind: 'internal_failure' };
  }
  try {
    return await client.$transaction((tx) => insertTerminal(tx, input), {
      maxWait: 5_000,
      timeout: 10_000,
    });
  } catch (error) {
    if (!isAdvisoryRevisionUniqueViolation(error)) {
      return { kind: classifyFailure(error) };
    }
  }
  try {
    const existing = await client.auditEvent.findFirst({
      where: {
        organizationId: null,
        action: COMPLETED_ACTION,
        subjectType: BATCH_SUBJECT,
        subjectId: input.batchId,
        correlationId: input.correlationId,
      },
      select: { id: true },
    });
    return existing === null ? { kind: 'internal_failure' } : { kind: 'already_applied' };
  } catch (error) {
    return { kind: classifyFailure(error) };
  }
}

async function insertTerminal(
  tx: Prisma.TransactionClient,
  input: OfflineNpmImportBatchCompleteInput,
): Promise<OfflineNpmImportBatchComplete> {
  await lockCorrelation(tx, input.correlationId);
  const batch = await tx.offlineAdvisoryImportBatch.findUnique({
    where: { id: input.batchId },
    select: { id: true, manifestSha256: true, sourceLicenseRegistryVersion: true },
  });
  if (
    batch === null ||
    batch.manifestSha256 !== input.manifestSha256 ||
    batch.sourceLicenseRegistryVersion !== OSV_SOURCE_LICENSE_REGISTRY_IDENTIFIER
  ) {
    return { kind: 'internal_failure' };
  }
  if (await correlationConflicts(tx, input.correlationId, input.manifestSha256)) {
    return { kind: 'immutable_conflict' };
  }
  const existing = await tx.auditEvent.findFirst({
    where: {
      organizationId: null,
      action: COMPLETED_ACTION,
      subjectType: BATCH_SUBJECT,
      subjectId: batch.id,
      correlationId: input.correlationId,
    },
    select: { id: true },
  });
  if (existing !== null) {
    return { kind: 'already_applied' };
  }
  const counts = summaryCounts(input.summary);
  if (counts === null) {
    return { kind: 'internal_failure' };
  }
  await tx.auditEvent.create({
    data: {
      actorType: 'system',
      action: COMPLETED_ACTION,
      subjectType: BATCH_SUBJECT,
      subjectId: batch.id,
      correlationId: input.correlationId,
      schemaVersion: JSON_SCHEMA_VERSION_V1,
      retentionCategory: 'security',
      payload: auditPayload({
        manifestSha256: batch.manifestSha256,
        byteLength: input.byteLength,
        advisoryIds: summaryAdvisoryIds(input.summary),
        reasonCodes: summaryReasonCodes(input.summary),
        counts,
      }),
    },
  });
  return { kind: 'recorded' };
}

async function resolveSupersession(
  client: PrismaClient,
  input: OfflineNpmSupersessionInput,
): Promise<OfflineNpmSupersessionResolution> {
  if (
    input.source !== OFFLINE_NPM_ACCEPTED_SOURCE ||
    !ADVISORY_ID.test(input.advisoryId) ||
    input.advisoryId.length > 512 ||
    input.packageIdentityKey.length < 1 ||
    input.packageIdentityKey.length > 1024 ||
    input.packageIdentityKey.includes('\0') ||
    !SHA256_HEX.test(input.rawContentSha256)
  ) {
    return { kind: 'internal_failure' };
  }
  try {
    const rows = await client.advisoryRevision.findMany({
      where: {
        source: input.source,
        advisoryId: input.advisoryId,
        packageIdentityKey: input.packageIdentityKey,
      },
      select: {
        id: true,
        revisionDigest: true,
        supersedesRevisionDigest: true,
        supersedesAdvisoryRevisionId: true,
        sourceProvenance: { select: { rawContentSha256: true } },
      },
    });
    const rawMatches = rows.filter(
      (row) => row.sourceProvenance?.rawContentSha256 === input.rawContentSha256,
    );
    if (rawMatches.length > 1) {
      return { kind: 'malformed_persisted_state' };
    }
    const matched = rawMatches[0];
    if (matched !== undefined) {
      return { kind: 'ready', supersedesRevisionDigest: matched.supersedesRevisionDigest };
    }
    const superseded = new Set(
      rows.flatMap((row) =>
        row.supersedesAdvisoryRevisionId === null ? [] : [row.supersedesAdvisoryRevisionId],
      ),
    );
    const tips = rows.filter((row) => !superseded.has(row.id));
    if (tips.length > 1) {
      return { kind: 'malformed_persisted_state' };
    }
    const tip = tips[0];
    if (tip !== undefined) {
      return { kind: 'ready', supersedesRevisionDigest: tip.revisionDigest };
    }
    return { kind: 'ready', supersedesRevisionDigest: SUPERSESSION_NONE };
  } catch (error) {
    return { kind: classifyFailure(error) };
  }
}

async function correlationConflicts(
  tx: Prisma.TransactionClient,
  correlationId: string,
  manifestSha256: string,
): Promise<boolean> {
  const events = await tx.auditEvent.findMany({
    where: {
      organizationId: null,
      correlationId,
      action: { in: [...AUDIT_ACTIONS] },
    },
    select: { action: true, subjectId: true },
  });
  const batchEvents = events.filter(
    (event) => event.action === STARTED_ACTION || event.action === COMPLETED_ACTION,
  );
  const fileEvents = events.filter((event) => event.action === FILE_ACTION);
  if (batchEvents.some((event) => !UUID_TEXT.test(event.subjectId))) {
    return true;
  }
  if (fileEvents.some((event) => !UUID_TEXT.test(event.subjectId))) {
    return true;
  }
  if (fileEvents.length > 0 && batchEvents.length === 0) {
    return true;
  }
  if (batchEvents.length === 0) {
    return false;
  }
  const batchIds = [...new Set(batchEvents.map((event) => event.subjectId))];
  const batches = await tx.offlineAdvisoryImportBatch.findMany({
    where: { id: { in: batchIds } },
    select: { id: true, manifestSha256: true },
  });
  if (batches.length !== batchIds.length) {
    return true;
  }
  return batches.some((batch) => batch.manifestSha256 !== manifestSha256);
}

async function lockCorrelation(tx: Prisma.TransactionClient, correlationId: string): Promise<void> {
  const key = `${CORRELATION_LOCK_PREFIX}${correlationId}`;
  await tx.$queryRaw`
    SELECT 1::int AS locked
    FROM (
      SELECT pg_advisory_xact_lock(hashtextextended(${key}, 0))
    ) AS taken
  `;
}

async function readClock(tx: Prisma.TransactionClient): Promise<Date> {
  const rows = await tx.$queryRaw<Array<{ retrieved_at: Date | string }>>`
    SELECT clock_timestamp() AS retrieved_at
  `;
  const value = rows[0]?.retrieved_at;
  let retrievedAt: Date | null = null;
  if (value instanceof Date) {
    retrievedAt = value;
  } else if (typeof value === 'string') {
    retrievedAt = new Date(value);
  }
  if (retrievedAt === null || Number.isNaN(retrievedAt.getTime())) {
    throw new Error('offline npm import clock unavailable');
  }
  return retrievedAt;
}

function auditPayload(input: {
  readonly manifestSha256: string;
  readonly byteLength: number;
  readonly advisoryIds: readonly string[];
  readonly reasonCodes: readonly string[];
  readonly counts: {
    readonly accepted: number;
    readonly skipped: number;
    readonly rejected: number;
    readonly failed: number;
  };
}): Prisma.InputJsonValue {
  return asJsonObject(
    {
      schemaVersion: JSON_SCHEMA_VERSION_V1,
      registryId: OSV_SOURCE_LICENSE_REGISTRY_IDENTIFIER,
      manifestSha256: input.manifestSha256,
      byteLength: input.byteLength,
      advisoryIds: [...input.advisoryIds],
      reasonCodes: [...input.reasonCodes],
      counts: input.counts,
    },
    'offline npm import audit',
  );
}

function summaryCounts(summary: OfflineNpmImportSummary): {
  readonly accepted: number;
  readonly skipped: number;
  readonly rejected: number;
  readonly failed: number;
} | null {
  const counts = {
    accepted: summary.accepted.count,
    skipped: summary.skipped.count,
    rejected: summary.rejected.count,
    failed: summary.failed.count,
  };
  if (
    !isCount(counts.accepted) ||
    !isCount(counts.skipped) ||
    !isCount(counts.rejected) ||
    !isCount(counts.failed)
  ) {
    return null;
  }
  return counts;
}

function summaryAdvisoryIds(summary: OfflineNpmImportSummary): string[] {
  const ids = [
    ...summary.accepted.advisoryIds,
    ...summary.skipped.advisoryIds,
    ...summary.rejected.advisoryIds,
    ...summary.failed.advisoryIds,
  ];
  return [...new Set(ids.filter((id) => ADVISORY_ID.test(id) && id.length <= 512))].sort(
    compareOfflineNpmImportNames,
  );
}

function summaryReasonCodes(summary: OfflineNpmImportSummary): string[] {
  const reasons = [
    ...summary.accepted.reasonCodes,
    ...summary.skipped.reasonCodes,
    ...summary.rejected.reasonCodes,
    ...summary.failed.reasonCodes,
  ];
  return [...new Set(reasons.filter((reason) => AUDIT_REASONS.has(reason)))].sort(
    compareOfflineNpmImportNames,
  );
}

function validBatchInput(input: {
  readonly correlationId: string;
  readonly manifestSha256: string;
  readonly byteLength: number;
}): boolean {
  return (
    UUID_TEXT.test(input.correlationId) &&
    SHA256_HEX.test(input.manifestSha256) &&
    Number.isSafeInteger(input.byteLength) &&
    input.byteLength >= 0 &&
    input.byteLength <= MAX_BYTE_LENGTH
  );
}

function isCount(value: number): boolean {
  return Number.isSafeInteger(value) && value >= 0 && value <= OFFLINE_NPM_OSV_IMPORT_MAX_FILES;
}

function classifyFailure(error: unknown): PersistenceFailure {
  const code = translateAdvisoryRevisionPersistenceFailure(error);
  if (code === 'database_unavailable') {
    return 'database_unavailable';
  }
  if (code === 'transaction_aborted' || code === 'timeout') {
    return 'transaction_aborted';
  }
  return 'internal_failure';
}
