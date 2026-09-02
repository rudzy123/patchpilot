import { describe, expect, it } from 'vitest';

import {
  decideCatalogRegression,
  decideContentHashNotModified,
  intelligenceRetryWaitDelayMs,
  sumParserWarningCounts,
} from './sync-decisions.js';
import type { IntelligenceSnapshotRecord, KevGenerationRecord } from './records.js';

const NOW = new Date('2026-09-01T12:00:00.000Z');
const SHA_A = 'a'.repeat(64);
const SHA_B = 'b'.repeat(64);

function generation(overrides: Partial<KevGenerationRecord> = {}): KevGenerationRecord {
  return {
    id: '11111111-1111-4111-8111-111111111111',
    provider: 'cisa_kev',
    sourceIdentifier: 'cisa_kev_json_catalog',
    syncRunId: '22222222-2222-4222-8222-222222222222',
    snapshotId: '33333333-3333-4333-8333-333333333333',
    state: 'active',
    stagedEntryCount: 1,
    expectedEntryCount: 1,
    parserVersion: '0.1.0',
    normalizationVersion: '1',
    catalogVersion: '2026.08.01',
    catalogReleasedAt: NOW,
    createdAt: NOW,
    completedAt: NOW,
    activatedAt: NOW,
    supersededAt: null,
    abandonedAt: null,
    version: 1,
    updatedAt: NOW,
    ...overrides,
  };
}

function snapshot(sha256: string): IntelligenceSnapshotRecord {
  return {
    id: '33333333-3333-4333-8333-333333333333',
    provider: 'cisa_kev',
    sourceIdentifier: 'cisa_kev_json_catalog',
    responseSha256: sha256,
    byteLength: 12,
    declaredContentType: 'application/json',
    detectedContentType: 'application/json',
    objectKey:
      `intelligence/cisa_kev/cisa_kev_json_catalog/sha256/${sha256}` as IntelligenceSnapshotRecord['objectKey'],
    retrievedAt: NOW,
    storedAt: NOW,
    etagHash: null,
    lastModified: null,
    creatingSyncRunId: '22222222-2222-4222-8222-222222222222',
    createdAt: NOW,
  };
}

describe('KEV synchronization decisions', () => {
  it('treats identical content hash and versions as not-modified', () => {
    const decision = decideContentHashNotModified({
      activeGeneration: generation(),
      activeSnapshot: snapshot(SHA_A),
      fetchedSnapshotSha256: SHA_A,
      syncRunParserVersion: '0.1.0',
      syncRunNormalizationVersion: '1',
    });
    expect(decision).toEqual({
      kind: 'not_modified',
      reason: 'content_sha256_unchanged',
      priorAcceptedGenerationId: generation().id,
    });
  });

  it('reparses when parser or normalization versions differ', () => {
    expect(
      decideContentHashNotModified({
        activeGeneration: generation(),
        activeSnapshot: snapshot(SHA_A),
        fetchedSnapshotSha256: SHA_A,
        syncRunParserVersion: '0.2.0',
        syncRunNormalizationVersion: '1',
      }).kind,
    ).toBe('reprocess');
    expect(
      decideContentHashNotModified({
        activeGeneration: generation(),
        activeSnapshot: snapshot(SHA_A),
        fetchedSnapshotSha256: SHA_A,
        syncRunParserVersion: '0.1.0',
        syncRunNormalizationVersion: '2',
      }).kind,
    ).toBe('reprocess');
  });

  it('compares catalogReleasedAt instants and ignores catalogVersion text', () => {
    expect(
      decideCatalogRegression({
        activeGeneration: undefined,
        catalogReleasedAt: NOW,
        snapshotSha256: SHA_A,
        activeSnapshotSha256: undefined,
        syncRunParserVersion: '0.1.0',
        syncRunNormalizationVersion: '1',
      }).kind,
    ).toBe('stage');

    const earlier = new Date('2026-08-01T00:00:00.000Z');
    const later = new Date('2026-09-02T00:00:00.000Z');
    expect(
      decideCatalogRegression({
        activeGeneration: generation({ catalogReleasedAt: NOW, catalogVersion: '9999' }),
        catalogReleasedAt: earlier,
        snapshotSha256: SHA_B,
        activeSnapshotSha256: SHA_A,
        syncRunParserVersion: '0.1.0',
        syncRunNormalizationVersion: '1',
      }),
    ).toEqual({ kind: 'quarantine', code: 'catalog_regression' });
    expect(
      decideCatalogRegression({
        activeGeneration: generation({ catalogReleasedAt: NOW, catalogVersion: 'zzzz' }),
        catalogReleasedAt: later,
        snapshotSha256: SHA_B,
        activeSnapshotSha256: SHA_A,
        syncRunParserVersion: '0.1.0',
        syncRunNormalizationVersion: '1',
      }).kind,
    ).toBe('stage');
    expect(
      decideCatalogRegression({
        activeGeneration: generation(),
        catalogReleasedAt: NOW,
        snapshotSha256: SHA_B,
        activeSnapshotSha256: SHA_A,
        syncRunParserVersion: '0.1.0',
        syncRunNormalizationVersion: '1',
      }).kind,
    ).toBe('stage');
  });

  it('computes bounded retry-wait delay without sleeping', () => {
    expect(intelligenceRetryWaitDelayMs(1, { floorMs: 30_000, ceilingMs: 300_000 })).toBe(30_000);
    expect(intelligenceRetryWaitDelayMs(2, { floorMs: 30_000, ceilingMs: 300_000 })).toBe(60_000);
    expect(intelligenceRetryWaitDelayMs(8, { floorMs: 30_000, ceilingMs: 300_000 })).toBe(300_000);
  });

  it('sums warning counts with checked arithmetic', () => {
    expect(sumParserWarningCounts([{ code: 'unrecognized_ransomware_value', count: 2 }])).toEqual({
      ok: true,
      count: 2,
    });
    expect(
      sumParserWarningCounts([
        { code: 'a', count: 1 },
        { code: 'a', count: 1 },
      ]),
    ).toEqual({
      ok: false,
      code: 'processing_failed',
    });
  });
});
