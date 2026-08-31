import { describe, expect, it } from 'vitest';

import { mapSbomIngestion } from './sbom-mappers.js';

const createdAt = new Date('2026-08-30T12:00:00.000Z');

function ingestionRow(normalizationVersion: string | null) {
  return {
    id: '11111111-1111-4111-8111-111111111111',
    organizationId: '22222222-2222-4222-8222-222222222222',
    sbomId: '33333333-3333-4333-8333-333333333333',
    assetId: '44444444-4444-4444-8444-444444444444',
    state: 'accepted' as const,
    stage: null,
    attemptNumber: 1,
    parserVersion: '0.1.0',
    normalizationVersion,
    idempotencyKey: null,
    startedAt: null,
    completedAt: null,
    graphCompleteness: null,
    componentCount: null,
    dependencyEdgeCount: null,
    warningCount: null,
    failureCategory: null,
    failureCode: null,
    quarantineReason: null,
    leaseExpiresAt: null,
    version: 1,
    createdAt,
    updatedAt: createdAt,
  };
}

describe('sbom ingestion mapper', () => {
  it('maps a persisted bounded normalizationVersion without substituting a default', () => {
    const mapped = mapSbomIngestion(ingestionRow('1'));
    expect(mapped.normalizationVersion).toBe('1');
  });

  it('fails mapping when normalizationVersion is missing rather than defaulting', () => {
    expect(() => mapSbomIngestion(ingestionRow(null))).toThrow(/normalizationVersion is required/);
    expect(() => mapSbomIngestion(ingestionRow(''))).toThrow(/bounded version label/);
  });
});
