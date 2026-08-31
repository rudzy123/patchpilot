import {
  encodeSbomListCursor,
  sbomDetailSchema,
  sbomIngestionStatusSchema,
  sbomListResponseSchema,
  sbomSummarySchema,
  sbomUploadAcceptedResponseSchema,
  type SbomDetail,
  type SbomIngestionStatus,
  type SbomListResponse,
  type SbomSummary,
  type SbomUploadAcceptedResponse,
} from '@patchpilot/contracts';
import type {
  SbomDetailRecord,
  SbomIngestionRecord,
  SbomListItemRecord,
  SbomQueryListPage,
  SbomRecord,
  SbomSummaryRecord,
  SbomUploadAccepted,
} from '@patchpilot/domain';

export function toSbomUploadAcceptedResponse(value: SbomUploadAccepted): SbomUploadAcceptedResponse {
  return sbomUploadAcceptedResponseSchema.parse({
    sbomId: value.sbomId,
    ingestionId: value.ingestionId,
    assetId: value.assetId,
    state: value.state,
    specificationType: value.specificationType,
    sha256: value.sha256,
    byteLength: value.byteLength,
    source: value.source,
    receivedAt: value.receivedAt,
  });
}

export function toSbomListResponse(page: SbomQueryListPage): SbomListResponse {
  return sbomListResponseSchema.parse({
    items: page.items.map(toSbomSummary),
    nextCursor: page.nextCursor === undefined ? null : encodeSbomListCursor(page.nextCursor),
  });
}

export function toSbomDetail(record: SbomDetailRecord): SbomDetail {
  return sbomDetailSchema.parse({
    ...toSbomSummary({ summary: toSummaryRecord(record.sbom), ingestion: record.currentIngestion }),
    currentIngestion: toSbomIngestionStatus(record.currentIngestion),
  });
}

export function toSbomIngestionStatus(record: SbomIngestionRecord): SbomIngestionStatus {
  return sbomIngestionStatusSchema.parse({
    id: record.id,
    sbomId: record.sbomId,
    assetId: record.assetId,
    state: record.state,
    stage: record.stage,
    graphCompleteness: record.graphCompleteness,
    componentCount: record.componentCount,
    dependencyEdgeCount: record.dependencyEdgeCount,
    warningCount: record.warningCount,
    parserVersion: record.parserVersion,
    failureCategory: record.failureCategory,
    failureCode: record.failureCode,
    startedAt: utcIso(record.startedAt),
    completedAt: utcIso(record.completedAt),
  });
}

function toSbomSummary(item: SbomListItemRecord): SbomSummary {
  const { summary, ingestion } = item;
  return sbomSummarySchema.parse({
    id: summary.id,
    assetId: summary.assetId,
    specificationType: summary.specificationType,
    specificationVersion: summary.specificationVersion,
    sha256: summary.sha256,
    byteLength: summary.byteLength,
    source: summary.source,
    receivedAt: summary.receivedAt.toISOString(),
    capturedAt: utcIso(summary.capturedAt),
    parserVersion: ingestion.parserVersion,
    ingestionId: ingestion.id,
    state: ingestion.state,
    stage: ingestion.stage,
    graphCompleteness: ingestion.graphCompleteness,
    componentCount: ingestion.componentCount,
    dependencyEdgeCount: ingestion.dependencyEdgeCount,
    warningCount: ingestion.warningCount,
    failureCategory: ingestion.failureCategory,
    failureCode: ingestion.failureCode,
  });
}

function toSummaryRecord(sbom: SbomRecord): SbomSummaryRecord {
  return {
    id: sbom.id,
    organizationId: sbom.organizationId,
    assetId: sbom.assetId,
    sha256: sbom.sha256,
    byteLength: sbom.byteLength,
    specificationType: sbom.specificationType,
    specificationVersion: sbom.specificationVersion,
    source: sbom.source,
    receivedAt: sbom.receivedAt,
    capturedAt: sbom.capturedAt,
    parserVersionLastSucceeded: sbom.parserVersionLastSucceeded,
  };
}

function utcIso(value: Date | null): string | null {
  return value === null ? null : value.toISOString();
}
