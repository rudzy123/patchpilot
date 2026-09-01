import {
  CISA_KEV_SOURCE_IDENTIFIER,
  isIntelligenceSafeFailureCode,
  intelligenceSafeFailureCategories,
  parseIntelligenceSnapshotObjectKey,
  type CalendarDate,
  type CanonicalCve,
  type IntelligenceNotModifiedReason,
  type IntelligenceProvider,
  type IntelligenceSafeFailureCategory,
  type IntelligenceSafeFailureCode,
  type IntelligenceSnapshotRecord,
  type IntelligenceSyncRunRecord,
  type IntelligenceSyncRunSnapshot,
  type IntelligenceSyncRunStage,
  type IntelligenceSyncRunState,
  type KevGenerationRecord,
  type KevGenerationState,
  type KevNormalizedEntryRecord,
  type KnownRansomwareCampaignUse,
} from '@patchpilot/domain';

type SyncRunRow = {
  id: string;
  providerKey: 'osv' | 'cisa_kev' | 'reserved';
  sourceIdentifier: string;
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
  failureCategory: string | null;
  failureCode: string | null;
  acceptedEntryCount: number | null;
  warningCount: number | null;
  notModifiedReason: IntelligenceNotModifiedReason | null;
  correlationId: string;
  version: number;
  createdAt: Date;
  updatedAt: Date;
};

type SnapshotRow = {
  id: string;
  providerKey: 'osv' | 'cisa_kev' | 'reserved';
  sourceIdentifier: string;
  responseSha256: string;
  byteLength: number;
  declaredContentType: string | null;
  detectedContentType: string | null;
  objectKey: string;
  retrievedAt: Date;
  storedAt: Date;
  etagHash: string | null;
  lastModified: Date | null;
  creatingSyncRunId: string;
  createdAt: Date;
};

type GenerationRow = {
  id: string;
  providerKey: 'osv' | 'cisa_kev' | 'reserved';
  sourceIdentifier: string;
  syncRunId: string;
  snapshotId: string;
  state: KevGenerationState;
  expectedEntryCount: number;
  stagedEntryCount: number;
  parserVersion: string;
  normalizationVersion: string;
  catalogVersion: string | null;
  catalogReleasedAt: Date | null;
  completedAt: Date | null;
  activatedAt: Date | null;
  supersededAt: Date | null;
  abandonedAt: Date | null;
  version: number;
  createdAt: Date;
  updatedAt: Date;
};

type EntryRow = {
  id: string;
  generationId: string;
  ordinal: number;
  normalizedCve: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  requiredAction: string;
  dueDate: string;
  knownRansomwareCampaignUse: KnownRansomwareCampaignUse;
  rawKnownRansomwareCampaignUse: string | null;
  notes: string | null;
  createdAt: Date;
  cwes?: Array<{ normalizedCwe: string; ordinal: number }>;
};

function requireCisaKev(providerKey: 'osv' | 'cisa_kev' | 'reserved'): 'cisa_kev' {
  if (providerKey !== 'cisa_kev') {
    throw new Error('KEV persistence rows must use providerKey cisa_kev.');
  }
  return providerKey;
}

function requireCatalogSource(sourceIdentifier: string): typeof CISA_KEV_SOURCE_IDENTIFIER {
  if (sourceIdentifier !== CISA_KEV_SOURCE_IDENTIFIER) {
    throw new Error('KEV persistence rows must use cisa_kev_json_catalog.');
  }
  return CISA_KEV_SOURCE_IDENTIFIER;
}

function mapFailureCategory(value: string | null): IntelligenceSafeFailureCategory | null {
  if (value === null) {
    return null;
  }
  if (!(intelligenceSafeFailureCategories as readonly string[]).includes(value)) {
    throw new Error('Persisted failure category is not in the closed set.');
  }
  return value as IntelligenceSafeFailureCategory;
}

function mapFailureCode(value: string | null): IntelligenceSafeFailureCode | null {
  if (value === null) {
    return null;
  }
  if (!isIntelligenceSafeFailureCode(value)) {
    throw new Error('Persisted failure code is not in the closed set.');
  }
  return value;
}

export function mapIntelligenceSyncRun(row: SyncRunRow): IntelligenceSyncRunRecord {
  return {
    id: row.id,
    provider: requireCisaKev(row.providerKey),
    sourceIdentifier: requireCatalogSource(row.sourceIdentifier),
    state: row.state,
    stage: row.stage,
    requestedAt: row.requestedAt,
    startedAt: row.startedAt,
    completedAt: row.completedAt,
    nextAttemptAt: row.nextAttemptAt,
    executionAttempt: row.executionAttempt,
    snapshotId: row.snapshotId,
    generationId: row.generationId,
    priorAcceptedGenerationId: row.priorAcceptedGenerationId,
    parserVersion: row.parserVersion,
    normalizationVersion: row.normalizationVersion,
    failureCategory: mapFailureCategory(row.failureCategory),
    failureCode: mapFailureCode(row.failureCode),
    acceptedEntryCount: row.acceptedEntryCount,
    warningCount: row.warningCount,
    notModifiedReason: row.notModifiedReason,
    correlationId: row.correlationId,
    version: row.version,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

export function toIntelligenceSyncRunSnapshot(
  record: IntelligenceSyncRunRecord,
): IntelligenceSyncRunSnapshot {
  return {
    state: record.state,
    stage: record.stage,
    requestedAt: record.requestedAt,
    startedAt: record.startedAt,
    completedAt: record.completedAt,
    nextAttemptAt: record.nextAttemptAt,
    executionAttempt: record.executionAttempt,
    snapshotId: record.snapshotId,
    generationId: record.generationId,
    failureCategory: record.failureCategory,
    failureCode: record.failureCode,
    acceptedEntryCount: record.acceptedEntryCount,
    warningCount: record.warningCount,
    priorAcceptedGenerationId: record.priorAcceptedGenerationId,
    notModifiedReason: record.notModifiedReason,
  };
}

export function mapIntelligenceSnapshot(row: SnapshotRow): IntelligenceSnapshotRecord {
  const objectKey = parseIntelligenceSnapshotObjectKey(row.objectKey);
  if (!objectKey.ok) {
    throw new Error(objectKey.error.message);
  }
  const declared =
    row.declaredContentType === 'application/json' ||
    row.declaredContentType === 'application/json; charset=utf-8'
      ? row.declaredContentType
      : row.declaredContentType === null
        ? null
        : (() => {
            throw new Error('Persisted declared content type is not an approved label.');
          })();
  const detected =
    row.detectedContentType === 'application/json' ||
    row.detectedContentType === 'application/json; charset=utf-8'
      ? row.detectedContentType
      : row.detectedContentType === null
        ? null
        : (() => {
            throw new Error('Persisted detected content type is not an approved label.');
          })();
  return {
    id: row.id,
    provider: requireCisaKev(row.providerKey),
    sourceIdentifier: requireCatalogSource(row.sourceIdentifier),
    responseSha256: row.responseSha256,
    byteLength: row.byteLength,
    declaredContentType: declared,
    detectedContentType: detected,
    objectKey: objectKey.value,
    retrievedAt: row.retrievedAt,
    storedAt: row.storedAt,
    etagHash: row.etagHash,
    lastModified: row.lastModified,
    creatingSyncRunId: row.creatingSyncRunId,
    createdAt: row.createdAt,
  };
}

export function mapKevGeneration(row: GenerationRow): KevGenerationRecord {
  return {
    id: row.id,
    provider: requireCisaKev(row.providerKey),
    sourceIdentifier: requireCatalogSource(row.sourceIdentifier),
    syncRunId: row.syncRunId,
    snapshotId: row.snapshotId,
    state: row.state,
    expectedEntryCount: row.expectedEntryCount,
    stagedEntryCount: row.stagedEntryCount,
    parserVersion: row.parserVersion,
    normalizationVersion: row.normalizationVersion,
    catalogVersion: row.catalogVersion,
    catalogReleasedAt: row.catalogReleasedAt,
    createdAt: row.createdAt,
    completedAt: row.completedAt,
    activatedAt: row.activatedAt,
    supersededAt: row.supersededAt,
    abandonedAt: row.abandonedAt,
    version: row.version,
    updatedAt: row.updatedAt,
  };
}

export function mapKevEntry(row: EntryRow, snapshotId: string): KevNormalizedEntryRecord {
  const cwes = [...(row.cwes ?? [])]
    .sort((left, right) => left.ordinal - right.ordinal)
    .map((item) => item.normalizedCwe);
  return {
    id: row.id,
    generationId: row.generationId,
    snapshotId,
    ordinal: row.ordinal,
    normalizedCve: row.normalizedCve as CanonicalCve,
    vendorProject: row.vendorProject,
    product: row.product,
    vulnerabilityName: row.vulnerabilityName,
    dateAdded: row.dateAdded as CalendarDate,
    shortDescription: row.shortDescription,
    requiredAction: row.requiredAction,
    dueDate: row.dueDate as CalendarDate,
    knownRansomwareCampaignUse: row.knownRansomwareCampaignUse,
    rawKnownRansomwareCampaignUse: row.rawKnownRansomwareCampaignUse,
    notes: row.notes,
    cwes,
    createdAt: row.createdAt,
  };
}

export function mapProviderKey(provider: IntelligenceProvider): 'cisa_kev' | 'osv' {
  if (provider === 'cisa_kev' || provider === 'osv') {
    return provider;
  }
  throw new Error('Provider is not in the Session 9 closed set.');
}
