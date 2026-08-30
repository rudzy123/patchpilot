import type {
  ComponentOccurrenceRecord,
  ComponentRecord,
  ComponentVersion,
  DependencyRelationshipRecord,
  GraphCompleteness,
  SbomIngestionRecord,
  SbomRecord,
  SafeFailureCategory,
  SafeFailureCode,
  Session8IngestionSnapshot,
} from '@patchpilot/domain';
import {
  fromOccurrenceVersionColumns,
  graphCompletenessValues,
  safeFailureCategories,
  safeFailureCodes,
} from '@patchpilot/domain';

import { requireVersionLabel } from './guards.js';
import { mapSbom } from './mappers.js';

export { mapSbom };

export function mapSbomIngestion(row: {
  id: string;
  organizationId: string;
  sbomId: string;
  assetId: string;
  state: SbomIngestionRecord['state'];
  stage: SbomIngestionRecord['stage'];
  attemptNumber: number;
  parserVersion: string;
  normalizationVersion: string | null;
  idempotencyKey: string | null;
  startedAt: Date | null;
  completedAt: Date | null;
  graphCompleteness: GraphCompleteness | null;
  componentCount: number | null;
  dependencyEdgeCount: number | null;
  warningCount: number | null;
  failureCategory: string | null;
  failureCode: string | null;
  quarantineReason: string | null;
  leaseExpiresAt: Date | null;
  version: number;
  createdAt: Date;
  updatedAt: Date;
}): SbomIngestionRecord {
  return {
    id: row.id,
    organizationId: row.organizationId,
    sbomId: row.sbomId,
    assetId: row.assetId,
    state: row.state,
    stage: row.stage,
    attemptNumber: row.attemptNumber,
    parserVersion: row.parserVersion,
    normalizationVersion: requirePersistedNormalizationVersion(row.normalizationVersion),
    idempotencyKey: row.idempotencyKey,
    startedAt: row.startedAt,
    completedAt: row.completedAt,
    graphCompleteness: asGraphCompleteness(row.graphCompleteness),
    componentCount: row.componentCount,
    dependencyEdgeCount: row.dependencyEdgeCount,
    warningCount: row.warningCount,
    failureCategory: asSafeFailureCategory(row.failureCategory),
    failureCode: asSafeFailureCode(row.failureCode),
    quarantineReason: row.quarantineReason,
    leaseExpiresAt: row.leaseExpiresAt,
    version: row.version,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
  };
}

export function toIngestionSnapshot(record: SbomIngestionRecord): Session8IngestionSnapshot {
  return {
    state: record.state,
    stage: record.stage,
    startedAt: record.startedAt,
    completedAt: record.completedAt,
    graphCompleteness: record.graphCompleteness,
    componentCount: record.componentCount,
    dependencyEdgeCount: record.dependencyEdgeCount,
    warningCount: record.warningCount,
    failureCategory: record.failureCategory,
    failureCode: record.failureCode,
  };
}

export function mapComponent(row: {
  id: string;
  organizationId: string;
  identityKey: string;
  purl: string | null;
  ecosystem: string | null;
  namespace: string | null;
  name: string;
  identityState: ComponentRecord['identityState'];
  createdAt: Date;
}): ComponentRecord {
  return {
    id: row.id,
    organizationId: row.organizationId,
    identityKey: row.identityKey,
    purl: row.purl,
    ecosystem: row.ecosystem,
    namespace: row.namespace,
    name: row.name,
    identityState: row.identityState,
    createdAt: row.createdAt,
  };
}

export function mapComponentOccurrence(row: {
  id: string;
  organizationId: string;
  assetId: string;
  sbomId: string;
  sbomIngestionId: string;
  componentId: string;
  bomRef: string | null;
  version: string;
  versionKnown: boolean;
  versionedPurl: string | null;
  isDirect: boolean | null;
  createdAt: Date;
}): ComponentOccurrenceRecord {
  const version = mapOccurrenceVersion(row);
  return {
    id: row.id,
    organizationId: row.organizationId,
    assetId: row.assetId,
    sbomId: row.sbomId,
    sbomIngestionId: row.sbomIngestionId,
    componentId: row.componentId,
    bomRef: row.bomRef,
    version,
    versionedPurl: row.versionedPurl,
    isDirect: row.isDirect,
    createdAt: row.createdAt,
  };
}

export function mapDependencyRelationship(row: {
  id: string;
  organizationId: string;
  sbomId: string;
  sbomIngestionId: string;
  fromOccurrenceId: string;
  toOccurrenceId: string;
  relationshipType: DependencyRelationshipRecord['relationshipType'];
  createdAt: Date;
}): DependencyRelationshipRecord {
  return { ...row };
}

export function toSbomSummary(record: SbomRecord) {
  return {
    id: record.id,
    organizationId: record.organizationId,
    assetId: record.assetId,
    sha256: record.sha256,
    byteLength: record.byteLength,
    specificationType: record.specificationType,
    specificationVersion: record.specificationVersion,
    source: record.source,
    receivedAt: record.receivedAt,
    capturedAt: record.capturedAt,
    parserVersionLastSucceeded: record.parserVersionLastSucceeded,
  };
}

function requirePersistedNormalizationVersion(value: string | null): string {
  if (value === null) {
    throw new Error('normalizationVersion is required.');
  }
  return requireVersionLabel(value, 'normalizationVersion');
}

function mapOccurrenceVersion(row: { versionKnown: boolean; version: string }): ComponentVersion {
  const mapped = fromOccurrenceVersionColumns({
    versionKnown: row.versionKnown,
    version: row.version,
  });
  if (!mapped.ok) {
    throw new Error(mapped.error.message);
  }
  return mapped.value;
}

function asGraphCompleteness(value: GraphCompleteness | null): GraphCompleteness | null {
  if (value === null) {
    return null;
  }
  if ((graphCompletenessValues as readonly string[]).includes(value)) {
    return value;
  }
  throw new Error('Unsupported graph completeness value.');
}

function asSafeFailureCategory(value: string | null): SafeFailureCategory | null {
  if (value === null) {
    return null;
  }
  if ((safeFailureCategories as readonly string[]).includes(value)) {
    return value as SafeFailureCategory;
  }
  throw new Error('Unsupported failure category.');
}

function asSafeFailureCode(value: string | null): SafeFailureCode | null {
  if (value === null) {
    return null;
  }
  if ((safeFailureCodes as readonly string[]).includes(value)) {
    return value as SafeFailureCode;
  }
  throw new Error('Unsupported failure code.');
}
