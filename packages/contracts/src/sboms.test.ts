import { describe, expect, it } from 'vitest';

import { encodeSbomListCursor } from '@patchpilot/domain';

import {
  assetSbomIdParamSchema,
  assetSbomIngestionIdParamSchema,
  cursorPaginationQuerySchema,
  graphCompletenessSchema,
  ingestionIdParamSchema,
  safeFailureCategorySchema,
  safeFailureCodeSchema,
  sbomDetailSchema,
  sbomIdParamSchema,
  sbomIngestionStatusSchema,
  sbomListQuerySchema,
  sbomListResponseSchema,
  sbomSummarySchema,
  sbomUploadAcceptedResponseSchema,
  supportedCycloneDxSpecificationVersionSchema,
} from './sboms.js';

const ASSET_ID = '44444444-4444-4444-8444-444444444444';
const SBOM_ID = '55555555-5555-4555-8555-555555555555';
const INGESTION_ID = '66666666-6666-4666-8666-666666666666';
const SHA = 'a'.repeat(64);
const RECEIVED_AT = '2026-08-29T16:00:00.000Z';

const FORBIDDEN_FIELDS = {
  objectKey: 'org/x/assets/y/sboms/sha256/' + SHA,
  storageBucket: 'patchpilot-dev',
  storageEndpoint: 'http://127.0.0.1:9000',
  filename: 'bom.json',
  originalFilename: 'bom.json',
  workerIdentifier: 'worker-1',
  leaseExpiresAt: RECEIVED_AT,
  leaseExpiresAtMs: 1,
  parserException: 'TypeError: boom',
  ajvErrors: [{ instancePath: '/components/0' }],
  schemaPath: '/properties/components',
  rawEvidence: '{ "bomFormat": "CycloneDX" }',
  auditPayload: { schemaVersion: 1, metadata: {} },
  queuePayload: { jobId: '1' },
  identityKey: 'purl:pkg:npm/left-pad',
};

function summary(overrides: Record<string, unknown> = {}) {
  return {
    id: SBOM_ID,
    assetId: ASSET_ID,
    specificationType: 'cyclonedx',
    specificationVersion: '1.6',
    sha256: SHA,
    byteLength: 128,
    source: 'upload',
    receivedAt: RECEIVED_AT,
    capturedAt: null,
    parserVersion: '0.1.0',
    ingestionId: INGESTION_ID,
    state: 'completed',
    stage: 'persist_graph',
    graphCompleteness: 'complete',
    componentCount: 2,
    dependencyEdgeCount: 1,
    warningCount: 0,
    failureCategory: null,
    failureCode: null,
    ...overrides,
  };
}

function ingestion(overrides: Record<string, unknown> = {}) {
  return {
    id: INGESTION_ID,
    sbomId: SBOM_ID,
    assetId: ASSET_ID,
    state: 'completed',
    stage: 'persist_graph',
    graphCompleteness: 'no_dependencies',
    componentCount: 1,
    dependencyEdgeCount: 0,
    warningCount: 0,
    parserVersion: '0.1.0',
    failureCategory: null,
    failureCode: null,
    startedAt: RECEIVED_AT,
    completedAt: RECEIVED_AT,
    ...overrides,
  };
}

describe('sbom route params and list query', () => {
  it('requires UUID identifiers and rejects extra fields', () => {
    expect(sbomIdParamSchema.parse({ sbomId: SBOM_ID })).toEqual({ sbomId: SBOM_ID });
    expect(ingestionIdParamSchema.parse({ ingestionId: INGESTION_ID })).toEqual({
      ingestionId: INGESTION_ID,
    });
    expect(assetSbomIdParamSchema.parse({ assetId: ASSET_ID, sbomId: SBOM_ID }).sbomId).toBe(
      SBOM_ID,
    );
    expect(
      assetSbomIngestionIdParamSchema.parse({ assetId: ASSET_ID, ingestionId: INGESTION_ID })
        .ingestionId,
    ).toBe(INGESTION_ID);
    expect(
      assetSbomIngestionIdParamSchema.safeParse({
        assetId: ASSET_ID,
        ingestionId: INGESTION_ID,
        organizationId: ASSET_ID,
      }).success,
    ).toBe(false);
    expect(sbomIdParamSchema.safeParse({ sbomId: 'not-a-uuid' }).success).toBe(false);
    expect(sbomIdParamSchema.safeParse({ sbomId: SBOM_ID, organizationId: ASSET_ID }).success).toBe(
      false,
    );
  });

  it('parses strict cursor pagination and list queries', () => {
    expect(cursorPaginationQuerySchema.parse({})).toEqual({});
    expect(sbomListQuerySchema.parse({})).toEqual({ limit: 20 });
    expect(sbomListQuerySchema.parse({ limit: '12' }).limit).toBe(12);

    const cursor = encodeSbomListCursor({ v: 1, r: RECEIVED_AT, i: SBOM_ID });
    expect(sbomListQuerySchema.parse({ cursor }).cursor).toEqual({
      v: 1,
      r: RECEIVED_AT,
      i: SBOM_ID,
    });
    expect(sbomListQuerySchema.safeParse({ limit: 0 }).success).toBe(false);
    expect(sbomListQuerySchema.safeParse({ limit: 101 }).success).toBe(false);
    expect(sbomListQuerySchema.safeParse({ cursor: 'not-a-cursor' }).success).toBe(false);
    expect(sbomListQuerySchema.safeParse({ organizationId: ASSET_ID }).success).toBe(false);
    expect(sbomListQuerySchema.safeParse({ filename: 'bom.json' }).success).toBe(false);
  });
});

describe('public sbom and ingestion contracts', () => {
  it('accepts upload, summary, detail, and status payloads', () => {
    expect(
      sbomUploadAcceptedResponseSchema.parse({
        sbomId: SBOM_ID,
        ingestionId: INGESTION_ID,
        assetId: ASSET_ID,
        state: 'accepted',
        specificationType: 'cyclonedx',
        sha256: SHA,
        byteLength: 128,
        source: 'upload',
        receivedAt: RECEIVED_AT,
      }).state,
    ).toBe('accepted');

    const parsedSummary = sbomSummarySchema.parse(summary());
    expect(parsedSummary.graphCompleteness).toBe('complete');
    expect(sbomIngestionStatusSchema.parse(ingestion()).id).toBe(INGESTION_ID);
    expect(
      sbomDetailSchema.parse({
        ...summary(),
        currentIngestion: ingestion(),
      }).currentIngestion.stage,
    ).toBe('persist_graph');
    expect(
      sbomListResponseSchema.parse({ items: [summary()], nextCursor: null }).items,
    ).toHaveLength(1);
  });

  it('rejects unknown fields and forbidden internal details', () => {
    for (const [field, value] of Object.entries(FORBIDDEN_FIELDS)) {
      expect(
        sbomUploadAcceptedResponseSchema.safeParse({
          sbomId: SBOM_ID,
          ingestionId: INGESTION_ID,
          assetId: ASSET_ID,
          state: 'accepted',
          specificationType: 'cyclonedx',
          sha256: SHA,
          byteLength: 128,
          source: 'upload',
          receivedAt: RECEIVED_AT,
          [field]: value,
        }).success,
        `upload ${field}`,
      ).toBe(false);
      expect(
        sbomSummarySchema.safeParse(summary({ [field]: value })).success,
        `summary ${field}`,
      ).toBe(false);
      expect(
        sbomIngestionStatusSchema.safeParse(ingestion({ [field]: value })).success,
        `status ${field}`,
      ).toBe(false);
      expect(
        sbomDetailSchema.safeParse({
          ...summary({ [field]: value }),
          currentIngestion: ingestion(),
        }).success,
        `detail ${field}`,
      ).toBe(false);
    }
  });

  it('closes supported specification versions and rejects CycloneDX 1.7', () => {
    expect(supportedCycloneDxSpecificationVersionSchema.parse('1.4')).toBe('1.4');
    expect(supportedCycloneDxSpecificationVersionSchema.parse('1.5')).toBe('1.5');
    expect(supportedCycloneDxSpecificationVersionSchema.parse('1.6')).toBe('1.6');
    expect(supportedCycloneDxSpecificationVersionSchema.safeParse('1.7').success).toBe(false);
    expect(supportedCycloneDxSpecificationVersionSchema.safeParse('1.3').success).toBe(false);
    expect(sbomSummarySchema.safeParse(summary({ specificationVersion: '1.7' })).success).toBe(
      false,
    );
  });

  it('closes graph completeness and safe failure catalogs', () => {
    expect(['empty', 'no_dependencies', 'partial', 'complete']).toEqual(
      graphCompletenessSchema.options,
    );
    expect(safeFailureCategorySchema.parse('poison')).toBe('poison');
    expect(safeFailureCodeSchema.parse('payload_too_large')).toBe('payload_too_large');
    expect(safeFailureCodeSchema.safeParse('ENOENT').success).toBe(false);
    expect(graphCompletenessSchema.safeParse('exhaustive').success).toBe(false);
  });
});
