import { JSON_SCHEMA_VERSION_V1, type AuditPayloadJson } from '../json-documents.js';
import type { AppendAuditEventInput } from '../ports.js';
import {
  INTELLIGENCE_AUDIT_SUBJECT_TYPE,
  INTELLIGENCE_GENERATION_AUDIT_SUBJECT_TYPE,
  INTELLIGENCE_SNAPSHOT_AUDIT_SUBJECT_TYPE,
  INTELLIGENCE_SOURCE_AUDIT_SUBJECT_TYPE,
  type IntelligenceProvider,
  type IntelligenceSourceIdentifier,
} from './constants.js';
import type { IntelligenceSafeFailureCode } from './failures.js';

export const intelligenceAuditActions = {
  syncRequested: 'intelligence.sync_requested',
  syncStarted: 'intelligence.sync_started',
  snapshotStored: 'intelligence.snapshot_stored',
  normalizationCompleted: 'intelligence.normalization_completed',
  syncCompleted: 'intelligence.sync_completed',
  syncNotModified: 'intelligence.sync_not_modified',
  syncFailed: 'intelligence.sync_failed',
  syncQuarantined: 'intelligence.sync_quarantined',
  kevUpdated: 'intelligence.kev_updated',
} as const;

export type IntelligenceAuditAction =
  (typeof intelligenceAuditActions)[keyof typeof intelligenceAuditActions];

export type IntelligenceAuditCountMetadata = {
  provider: IntelligenceProvider;
  sourceIdentifier: IntelligenceSourceIdentifier;
  syncRunId: string;
  intelligenceSourceId?: string;
  snapshotId?: string;
  generationId?: string;
  byteLength?: number;
  responseSha256?: string;
  entryCount?: number;
  warningCount?: number;
  parserVersion?: string;
  normalizationVersion?: string;
  failureCode?: IntelligenceSafeFailureCode;
  durationMs?: number;
};

const FORBIDDEN_AUDIT_METADATA_KEYS = [
  'objectKey',
  'sourceUrl',
  'url',
  'etag',
  'rawEtag',
  'providerError',
  'error',
  'stack',
  'cves',
  'cveList',
  'findings',
  'findingId',
  'organizationId',
  'assetId',
  'sbomId',
  'componentId',
  'body',
  'rawBody',
] as const;

function toAuditPayload(metadata: IntelligenceAuditCountMetadata): AuditPayloadJson {
  const payloadMetadata: Record<string, string | number | boolean | null> = {
    provider: metadata.provider,
    sourceIdentifier: metadata.sourceIdentifier,
    syncRunId: metadata.syncRunId,
  };
  if (metadata.snapshotId !== undefined) {
    payloadMetadata['snapshotId'] = metadata.snapshotId;
  }
  if (metadata.generationId !== undefined) {
    payloadMetadata['generationId'] = metadata.generationId;
  }
  if (metadata.byteLength !== undefined) {
    payloadMetadata['byteLength'] = metadata.byteLength;
  }
  if (metadata.responseSha256 !== undefined) {
    payloadMetadata['responseSha256'] = metadata.responseSha256;
  }
  if (metadata.entryCount !== undefined) {
    payloadMetadata['entryCount'] = metadata.entryCount;
  }
  if (metadata.warningCount !== undefined) {
    payloadMetadata['warningCount'] = metadata.warningCount;
  }
  if (metadata.intelligenceSourceId !== undefined) {
    payloadMetadata['intelligenceSourceId'] = metadata.intelligenceSourceId;
  }
  if (metadata.parserVersion !== undefined) {
    payloadMetadata['parserVersion'] = metadata.parserVersion;
  }
  if (metadata.normalizationVersion !== undefined) {
    payloadMetadata['normalizationVersion'] = metadata.normalizationVersion;
  }
  if (metadata.failureCode !== undefined) {
    payloadMetadata['failureCode'] = metadata.failureCode;
  }
  if (metadata.durationMs !== undefined) {
    payloadMetadata['durationMs'] = metadata.durationMs;
  }
  return {
    schemaVersion: JSON_SCHEMA_VERSION_V1,
    metadata: payloadMetadata,
  };
}

function intelligenceSystemAudit(input: {
  action: IntelligenceAuditAction;
  subjectType: string;
  subjectId: string;
  correlationId: string;
  occurredAt: Date;
  metadata: IntelligenceAuditCountMetadata;
}): AppendAuditEventInput {
  return {
    actorType: 'system',
    action: input.action,
    subjectType: input.subjectType,
    subjectId: input.subjectId,
    occurredAt: input.occurredAt,
    correlationId: input.correlationId,
    payload: toAuditPayload(input.metadata),
    retentionCategory: 'security',
  };
}

export function intelligenceSyncRequestedAudit(
  metadata: IntelligenceAuditCountMetadata,
  correlationId: string,
  occurredAt: Date,
): AppendAuditEventInput {
  return intelligenceSystemAudit({
    action: intelligenceAuditActions.syncRequested,
    subjectType: INTELLIGENCE_AUDIT_SUBJECT_TYPE,
    subjectId: metadata.syncRunId,
    correlationId,
    occurredAt,
    metadata,
  });
}

export function intelligenceSyncStartedAudit(
  metadata: IntelligenceAuditCountMetadata,
  correlationId: string,
  occurredAt: Date,
): AppendAuditEventInput {
  return intelligenceSystemAudit({
    action: intelligenceAuditActions.syncStarted,
    subjectType: INTELLIGENCE_AUDIT_SUBJECT_TYPE,
    subjectId: metadata.syncRunId,
    correlationId,
    occurredAt,
    metadata,
  });
}

export function intelligenceSnapshotStoredAudit(
  metadata: IntelligenceAuditCountMetadata & { snapshotId: string },
  correlationId: string,
  occurredAt: Date,
): AppendAuditEventInput {
  return intelligenceSystemAudit({
    action: intelligenceAuditActions.snapshotStored,
    subjectType: INTELLIGENCE_SNAPSHOT_AUDIT_SUBJECT_TYPE,
    subjectId: metadata.snapshotId,
    correlationId,
    occurredAt,
    metadata,
  });
}

export function intelligenceNormalizationCompletedAudit(
  metadata: IntelligenceAuditCountMetadata & { generationId: string },
  correlationId: string,
  occurredAt: Date,
): AppendAuditEventInput {
  return intelligenceSystemAudit({
    action: intelligenceAuditActions.normalizationCompleted,
    subjectType: INTELLIGENCE_GENERATION_AUDIT_SUBJECT_TYPE,
    subjectId: metadata.generationId,
    correlationId,
    occurredAt,
    metadata,
  });
}

export function intelligenceSyncCompletedAudit(
  metadata: IntelligenceAuditCountMetadata,
  correlationId: string,
  occurredAt: Date,
): AppendAuditEventInput {
  return intelligenceSystemAudit({
    action: intelligenceAuditActions.syncCompleted,
    subjectType: INTELLIGENCE_AUDIT_SUBJECT_TYPE,
    subjectId: metadata.syncRunId,
    correlationId,
    occurredAt,
    metadata,
  });
}

export function intelligenceSyncNotModifiedAudit(
  metadata: IntelligenceAuditCountMetadata,
  correlationId: string,
  occurredAt: Date,
): AppendAuditEventInput {
  return intelligenceSystemAudit({
    action: intelligenceAuditActions.syncNotModified,
    subjectType: INTELLIGENCE_AUDIT_SUBJECT_TYPE,
    subjectId: metadata.syncRunId,
    correlationId,
    occurredAt,
    metadata,
  });
}

export function intelligenceSyncFailedAudit(
  metadata: IntelligenceAuditCountMetadata & { failureCode: IntelligenceSafeFailureCode },
  correlationId: string,
  occurredAt: Date,
): AppendAuditEventInput {
  return intelligenceSystemAudit({
    action: intelligenceAuditActions.syncFailed,
    subjectType: INTELLIGENCE_AUDIT_SUBJECT_TYPE,
    subjectId: metadata.syncRunId,
    correlationId,
    occurredAt,
    metadata,
  });
}

export function intelligenceSyncQuarantinedAudit(
  metadata: IntelligenceAuditCountMetadata & { failureCode: IntelligenceSafeFailureCode },
  correlationId: string,
  occurredAt: Date,
): AppendAuditEventInput {
  return intelligenceSystemAudit({
    action: intelligenceAuditActions.syncQuarantined,
    subjectType: INTELLIGENCE_AUDIT_SUBJECT_TYPE,
    subjectId: metadata.syncRunId,
    correlationId,
    occurredAt,
    metadata,
  });
}

export function intelligenceKevUpdatedAudit(
  metadata: IntelligenceAuditCountMetadata & { intelligenceSourceId: string },
  correlationId: string,
  occurredAt: Date,
): AppendAuditEventInput {
  return intelligenceSystemAudit({
    action: intelligenceAuditActions.kevUpdated,
    subjectType: INTELLIGENCE_SOURCE_AUDIT_SUBJECT_TYPE,
    subjectId: metadata.intelligenceSourceId,
    correlationId,
    occurredAt,
    metadata,
  });
}

export function auditMetadataContainsForbiddenField(
  metadata: Readonly<Record<string, unknown>>,
): boolean {
  return FORBIDDEN_AUDIT_METADATA_KEYS.some((key) => key in metadata);
}

export { FORBIDDEN_AUDIT_METADATA_KEYS };
