import { SHA256_HEX_PATTERN, UUID_PATTERN } from '../sbom/constants.js';
import { err, ok, type Result } from '../result.js';
import {
  CISA_KEV_SOURCE_IDENTIFIER,
  INTELLIGENCE_CORRELATION_ID_PATTERN,
  INTELLIGENCE_CATALOG_VERSION_MAX_LENGTH,
  INTELLIGENCE_SAFE_CONTENT_TYPE_LABELS,
  INTELLIGENCE_VERSION_LABEL_MAX_LENGTH,
  INTELLIGENCE_VERSION_LABEL_PATTERN,
  intelligenceProviders,
  intelligenceSourceIdentifiers,
  kevGenerationStates,
  type IntelligenceNotModifiedReason,
  type IntelligenceProvider,
  type IntelligenceSafeContentTypeLabel,
  type IntelligenceSourceIdentifier,
  type IntelligenceSyncRunStage,
  type IntelligenceSyncRunState,
  type KevGenerationState,
  type KnownRansomwareCampaignUse,
} from './constants.js';
import {
  INTELLIGENCE_ABANDONED_GENERATION,
  INTELLIGENCE_GENERATION_COUNT_MISMATCH,
  INTELLIGENCE_GENERATION_INCOMPLETE,
  intelligenceValidationError,
} from './errors.js';
import type { IntelligenceSafeFailureCategory, IntelligenceSafeFailureCode } from './failures.js';
import {
  findDuplicateNormalizedCves,
  isNonNegativeSafeInteger,
  isPositiveSafeInteger,
  parseCalendarDate,
  parseCweList,
  parseUntrustedPlainText,
  type CalendarDate,
  type CanonicalCve,
} from './normalize.js';
import {
  parseFinalIntelligenceSnapshotObjectKey,
  type FinalIntelligenceSnapshotObjectKey,
} from './object-keys.js';

export function createRequestedIntelligenceSyncRunRecord(input: {
  id: string;
  provider: IntelligenceProvider;
  sourceIdentifier: IntelligenceSourceIdentifier;
  requestedAt: Date;
  correlationId: string;
  parserVersion: string;
  normalizationVersion: string;
}): Result<IntelligenceSyncRunRecord> {
  if (!isUuid(input.id)) {
    return err(intelligenceValidationError('Sync-run identifiers must be UUIDs.'));
  }
  if (!INTELLIGENCE_CORRELATION_ID_PATTERN.test(input.correlationId)) {
    return err(intelligenceValidationError('Correlation ID is not a bounded safe identifier.'));
  }
  if (input.provider === 'osv') {
    return err(intelligenceValidationError('OSV cannot create a Session 9 sync run.'));
  }
  if (!isVersionLabel(input.parserVersion) || !isVersionLabel(input.normalizationVersion)) {
    return err(intelligenceValidationError('Parser and normalization labels must be safe.'));
  }
  return ok({
    id: input.id,
    provider: input.provider,
    sourceIdentifier: input.sourceIdentifier,
    state: 'requested',
    stage: null,
    requestedAt: input.requestedAt,
    startedAt: null,
    completedAt: null,
    nextAttemptAt: null,
    executionAttempt: 0,
    snapshotId: null,
    generationId: null,
    priorAcceptedGenerationId: null,
    parserVersion: input.parserVersion,
    normalizationVersion: input.normalizationVersion,
    failureCategory: null,
    failureCode: null,
    acceptedEntryCount: null,
    warningCount: null,
    notModifiedReason: null,
    correlationId: input.correlationId,
    version: 1,
    createdAt: input.requestedAt,
    updatedAt: input.requestedAt,
  });
}

export type IntelligenceSyncRunRecord = {
  id: string;
  provider: IntelligenceProvider;
  sourceIdentifier: IntelligenceSourceIdentifier;
  state: IntelligenceSyncRunState;
  stage: IntelligenceSyncRunStage | null;
  requestedAt: Date;
  startedAt: Date | null;
  completedAt: Date | null;
  nextAttemptAt: Date | null;
  executionAttempt: number;
  snapshotId: string | null;
  generationId: string | null;
  priorAcceptedGenerationId: string | null;
  parserVersion: string;
  normalizationVersion: string;
  failureCategory: IntelligenceSafeFailureCategory | null;
  failureCode: IntelligenceSafeFailureCode | null;
  acceptedEntryCount: number | null;
  warningCount: number | null;
  notModifiedReason: IntelligenceNotModifiedReason | null;
  correlationId: string;
  version: number;
  createdAt: Date;
  updatedAt: Date;
};

export type IntelligenceSnapshotIdentity = {
  provider: IntelligenceProvider;
  sourceIdentifier: IntelligenceSourceIdentifier;
  responseSha256: string;
};

export type IntelligenceSnapshotRecord = {
  id: string;
  provider: IntelligenceProvider;
  sourceIdentifier: IntelligenceSourceIdentifier;
  responseSha256: string;
  byteLength: number;
  declaredContentType: IntelligenceSafeContentTypeLabel | null;
  detectedContentType: IntelligenceSafeContentTypeLabel | null;
  objectKey: FinalIntelligenceSnapshotObjectKey;
  retrievedAt: Date;
  storedAt: Date;
  etagHash: string | null;
  lastModified: Date | null;
  creatingSyncRunId: string;
  createdAt: Date;
};

export type KevGenerationRecord = {
  id: string;
  provider: 'cisa_kev';
  sourceIdentifier: typeof CISA_KEV_SOURCE_IDENTIFIER;
  syncRunId: string;
  snapshotId: string;
  state: KevGenerationState;
  stagedEntryCount: number;
  expectedEntryCount: number;
  parserVersion: string;
  normalizationVersion: string;
  catalogVersion: string | null;
  catalogReleasedAt: Date | null;
  createdAt: Date;
  completedAt: Date | null;
  activatedAt: Date | null;
  supersededAt: Date | null;
  abandonedAt: Date | null;
  version: number;
  updatedAt: Date;
};

export type KevNormalizedEntryRecord = {
  id: string;
  generationId: string;
  snapshotId: string;
  ordinal: number;
  normalizedCve: CanonicalCve;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: CalendarDate;
  shortDescription: string;
  requiredAction: string;
  dueDate: CalendarDate;
  knownRansomwareCampaignUse: KnownRansomwareCampaignUse;
  rawKnownRansomwareCampaignUse: string | null;
  notes: string | null;
  cwes: readonly string[];
  createdAt: Date;
};

export type KevCurrentMembership = {
  provider: 'cisa_kev';
  sourceIdentifier: typeof CISA_KEV_SOURCE_IDENTIFIER;
  generationId: string;
  snapshotId: string;
  normalizedCve: CanonicalCve;
  ordinal: number;
};

function isUuid(value: string): boolean {
  return UUID_PATTERN.test(value);
}

function isVersionLabel(value: string): boolean {
  return (
    value.length > 0 &&
    value.length <= INTELLIGENCE_VERSION_LABEL_MAX_LENGTH &&
    INTELLIGENCE_VERSION_LABEL_PATTERN.test(value)
  );
}

function isSafeContentType(value: string | null): value is IntelligenceSafeContentTypeLabel | null {
  return (
    value === null || (INTELLIGENCE_SAFE_CONTENT_TYPE_LABELS as readonly string[]).includes(value)
  );
}

export function snapshotNaturalIdentity(
  record: Pick<IntelligenceSnapshotRecord, 'provider' | 'sourceIdentifier' | 'responseSha256'>,
): IntelligenceSnapshotIdentity {
  return {
    provider: record.provider,
    sourceIdentifier: record.sourceIdentifier,
    responseSha256: record.responseSha256,
  };
}

export function validateIntelligenceSnapshotRecord(
  record: IntelligenceSnapshotRecord,
): Result<IntelligenceSnapshotRecord> {
  if (!isUuid(record.id) || !isUuid(record.creatingSyncRunId)) {
    return err(intelligenceValidationError('Snapshot identifiers must be UUIDs.'));
  }
  if (!(intelligenceProviders as readonly string[]).includes(record.provider)) {
    return err(intelligenceValidationError('Snapshot provider is not approved.'));
  }
  if (!(intelligenceSourceIdentifiers as readonly string[]).includes(record.sourceIdentifier)) {
    return err(intelligenceValidationError('Snapshot source identifier is not approved.'));
  }
  if (record.provider === 'osv') {
    return err(intelligenceValidationError('OSV snapshots are not a Session 9 runtime path.'));
  }
  if (!SHA256_HEX_PATTERN.test(record.responseSha256)) {
    return err(
      intelligenceValidationError('Snapshot SHA-256 must be 64 lowercase hex characters.'),
    );
  }
  if (record.etagHash !== null && !SHA256_HEX_PATTERN.test(record.etagHash)) {
    return err(intelligenceValidationError('ETag hash must be 64 lowercase hex characters.'));
  }
  if (!isPositiveSafeInteger(record.byteLength)) {
    return err(
      intelligenceValidationError('Snapshot byte length must be a positive safe integer.'),
    );
  }
  if (
    !isSafeContentType(record.declaredContentType) ||
    !isSafeContentType(record.detectedContentType)
  ) {
    return err(intelligenceValidationError('Snapshot content-type labels must be safe.'));
  }
  const objectKey = parseFinalIntelligenceSnapshotObjectKey(record.objectKey);
  if (!objectKey.ok) {
    return objectKey;
  }
  return ok(record);
}

export function snapshotIdentityFieldsAreImmutable(
  current: IntelligenceSnapshotIdentity,
  next: IntelligenceSnapshotIdentity,
): boolean {
  return (
    current.provider === next.provider &&
    current.sourceIdentifier === next.sourceIdentifier &&
    current.responseSha256 === next.responseSha256
  );
}

export function generationIsVisibleToReaders(state: KevGenerationState): boolean {
  return state === 'active' || state === 'superseded';
}

export function generationIsStagingInvisible(state: KevGenerationState): boolean {
  return state === 'staging';
}

export function canActivateKevGeneration(generation: KevGenerationRecord): Result<void> {
  if (generation.state === 'abandoned') {
    return err(INTELLIGENCE_ABANDONED_GENERATION);
  }
  if (generation.state !== 'complete') {
    return err(INTELLIGENCE_GENERATION_INCOMPLETE);
  }
  if (
    generation.completedAt === null ||
    generation.stagedEntryCount !== generation.expectedEntryCount ||
    !isNonNegativeSafeInteger(generation.stagedEntryCount) ||
    !isNonNegativeSafeInteger(generation.expectedEntryCount) ||
    generation.catalogVersion === null ||
    generation.catalogReleasedAt === null
  ) {
    return err(INTELLIGENCE_GENERATION_COUNT_MISMATCH);
  }
  if (
    generation.provider !== 'cisa_kev' ||
    generation.sourceIdentifier !== CISA_KEV_SOURCE_IDENTIFIER
  ) {
    return err(intelligenceValidationError('Only the official KEV JSON catalog may activate.'));
  }
  return ok(undefined);
}

export function canSupersedeActiveKevGeneration(
  currentActive: KevGenerationRecord,
  replacement: KevGenerationRecord,
): Result<void> {
  if (currentActive.state !== 'active') {
    return err(intelligenceValidationError('Only an active KEV generation can be superseded.'));
  }
  const activatable = canActivateKevGeneration(replacement);
  if (!activatable.ok) {
    return activatable;
  }
  if (
    currentActive.provider !== replacement.provider ||
    currentActive.sourceIdentifier !== replacement.sourceIdentifier
  ) {
    return err(
      intelligenceValidationError('Superseding generations must share provider and source.'),
    );
  }
  return ok(undefined);
}

export function validateKevGenerationRecord(
  generation: KevGenerationRecord,
): Result<KevGenerationRecord> {
  if (!isUuid(generation.id) || !isUuid(generation.syncRunId) || !isUuid(generation.snapshotId)) {
    return err(intelligenceValidationError('Generation identifiers must be UUIDs.'));
  }
  if (!(kevGenerationStates as readonly string[]).includes(generation.state)) {
    return err(intelligenceValidationError('Generation state is not in the closed set.'));
  }
  if (
    !isNonNegativeSafeInteger(generation.stagedEntryCount) ||
    !isNonNegativeSafeInteger(generation.expectedEntryCount)
  ) {
    return err(
      intelligenceValidationError('Generation counts must be non-negative safe integers.'),
    );
  }
  if (
    !isVersionLabel(generation.parserVersion) ||
    !isVersionLabel(generation.normalizationVersion)
  ) {
    return err(intelligenceValidationError('Parser and normalization labels must be safe.'));
  }
  if (generation.version < 1 || !Number.isInteger(generation.version)) {
    return err(intelligenceValidationError('Generation version must be an integer >= 1.'));
  }
  if (
    generation.catalogVersion !== null &&
    (generation.catalogVersion.length === 0 ||
      generation.catalogVersion.length > INTELLIGENCE_CATALOG_VERSION_MAX_LENGTH)
  ) {
    return err(intelligenceValidationError('Catalog version exceeds the bounded label length.'));
  }
  if (
    generation.completedAt !== null &&
    generation.completedAt.getTime() < generation.createdAt.getTime()
  ) {
    return err(intelligenceValidationError('completedAt cannot precede createdAt.'));
  }
  if (
    generation.activatedAt !== null &&
    (generation.completedAt === null ||
      generation.activatedAt.getTime() < generation.completedAt.getTime())
  ) {
    return err(intelligenceValidationError('activatedAt cannot precede completedAt.'));
  }
  if (
    generation.supersededAt !== null &&
    (generation.activatedAt === null ||
      generation.supersededAt.getTime() < generation.activatedAt.getTime())
  ) {
    return err(intelligenceValidationError('supersededAt cannot precede activatedAt.'));
  }
  if (generation.state === 'staging') {
    if (
      generation.completedAt !== null ||
      generation.activatedAt !== null ||
      generation.supersededAt !== null ||
      generation.abandonedAt !== null
    ) {
      return err(
        intelligenceValidationError('Staging generations cannot expose completion or activation.'),
      );
    }
  }
  if (generation.state === 'complete') {
    if (
      generation.completedAt === null ||
      generation.activatedAt !== null ||
      generation.supersededAt !== null ||
      generation.abandonedAt !== null ||
      generation.stagedEntryCount !== generation.expectedEntryCount ||
      generation.catalogVersion === null ||
      generation.catalogReleasedAt === null
    ) {
      return err(
        intelligenceValidationError('Complete generations must be finished and not yet current.'),
      );
    }
  }
  if (generation.state === 'active') {
    if (
      generation.activatedAt === null ||
      generation.completedAt === null ||
      generation.supersededAt !== null ||
      generation.abandonedAt !== null
    ) {
      return err(intelligenceValidationError('Active generations must be complete.'));
    }
    const activatable = canActivateKevGeneration({ ...generation, state: 'complete' });
    if (!activatable.ok) {
      return activatable;
    }
  }
  if (generation.state === 'superseded') {
    if (
      generation.activatedAt === null ||
      generation.completedAt === null ||
      generation.supersededAt === null ||
      generation.abandonedAt !== null ||
      generation.stagedEntryCount !== generation.expectedEntryCount ||
      generation.catalogVersion === null ||
      generation.catalogReleasedAt === null
    ) {
      return err(
        intelligenceValidationError('Superseded generations must have been previously current.'),
      );
    }
  }
  if (generation.state === 'abandoned') {
    if (
      generation.abandonedAt === null ||
      generation.activatedAt !== null ||
      generation.supersededAt !== null
    ) {
      return err(INTELLIGENCE_ABANDONED_GENERATION);
    }
  }
  return ok(generation);
}

export function validateKevNormalizedEntryRecord(
  entry: KevNormalizedEntryRecord,
): Result<KevNormalizedEntryRecord> {
  if (!isUuid(entry.id) || !isUuid(entry.generationId) || !isUuid(entry.snapshotId)) {
    return err(intelligenceValidationError('Entry identifiers must be UUIDs.'));
  }
  if (!isNonNegativeSafeInteger(entry.ordinal)) {
    return err(intelligenceValidationError('Entry ordinals must be non-negative safe integers.'));
  }
  const dateAdded = parseCalendarDate(entry.dateAdded);
  if (!dateAdded.ok) {
    return dateAdded;
  }
  const dueDate = parseCalendarDate(entry.dueDate);
  if (!dueDate.ok) {
    return dueDate;
  }
  const vendorProject = parseUntrustedPlainText(entry.vendorProject);
  if (!vendorProject.ok) {
    return vendorProject;
  }
  const product = parseUntrustedPlainText(entry.product);
  if (!product.ok) {
    return product;
  }
  const vulnerabilityName = parseUntrustedPlainText(entry.vulnerabilityName);
  if (!vulnerabilityName.ok) {
    return vulnerabilityName;
  }
  const shortDescription = parseUntrustedPlainText(entry.shortDescription);
  if (!shortDescription.ok) {
    return shortDescription;
  }
  const requiredAction = parseUntrustedPlainText(entry.requiredAction);
  if (!requiredAction.ok) {
    return requiredAction;
  }
  if (entry.notes !== null) {
    const notes = parseUntrustedPlainText(entry.notes);
    if (!notes.ok) {
      return notes;
    }
  }
  const cwes = parseCweList(entry.cwes);
  if (!cwes.ok) {
    return cwes;
  }
  if (
    entry.knownRansomwareCampaignUse === 'other' &&
    entry.rawKnownRansomwareCampaignUse === null
  ) {
    return err(
      intelligenceValidationError('other ransomware use must retain the raw provider value.'),
    );
  }
  if (
    entry.knownRansomwareCampaignUse !== 'other' &&
    entry.rawKnownRansomwareCampaignUse !== null
  ) {
    return err(
      intelligenceValidationError(
        'raw ransomware value is retained only when normalized value is other.',
      ),
    );
  }
  return ok(entry);
}

export function assertNoDuplicateNormalizedCves(
  entries: readonly { normalizedCve: string }[],
): Result<void> {
  const duplicates = findDuplicateNormalizedCves(entries);
  if (duplicates.length > 0) {
    return err(intelligenceValidationError('duplicate_cve'));
  }
  return ok(undefined);
}

export function toKevCurrentMembership(
  generation: KevGenerationRecord,
  entry: KevNormalizedEntryRecord,
): Result<KevCurrentMembership> {
  if (generation.state !== 'active') {
    return err({
      code: 'conflict',
      message: 'Staging KEV generations are invisible to catalog readers.',
    });
  }
  if (generation.id !== entry.generationId || generation.snapshotId !== entry.snapshotId) {
    return err(
      intelligenceValidationError('Membership requires generation and snapshot agreement.'),
    );
  }
  return ok({
    provider: 'cisa_kev',
    sourceIdentifier: CISA_KEV_SOURCE_IDENTIFIER,
    generationId: generation.id,
    snapshotId: generation.snapshotId,
    normalizedCve: entry.normalizedCve,
    ordinal: entry.ordinal,
  });
}
