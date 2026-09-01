import { describe, expect, it } from 'vitest';

import { buildFinalSbomObjectKey } from '../sbom/object-keys.js';
import { CISA_KEV_SOURCE_IDENTIFIER } from './constants.js';
import { parseIntelligenceSnapshotObjectKey } from './object-keys.js';
import {
  assertNoDuplicateNormalizedCves,
  canActivateKevGeneration,
  canSupersedeActiveKevGeneration,
  generationIsStagingInvisible,
  generationIsVisibleToReaders,
  snapshotIdentityFieldsAreImmutable,
  snapshotNaturalIdentity,
  toKevCurrentMembership,
  validateIntelligenceSnapshotRecord,
  validateKevGenerationRecord,
  validateKevNormalizedEntryRecord,
  type IntelligenceSnapshotRecord,
  type KevGenerationRecord,
  type KevNormalizedEntryRecord,
} from './records.js';
import type { CanonicalCve } from './normalize.js';
import { parseCalendarDate } from './normalize.js';

const SNAPSHOT_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const GENERATION_ID = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const SYNC_RUN_ID = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const ENTRY_ID = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
const SHA = 'a'.repeat(64);
const NOW = new Date('2026-08-31T16:00:00.000Z');

function snapshot(overrides: Partial<IntelligenceSnapshotRecord> = {}): IntelligenceSnapshotRecord {
  const objectKey = parseIntelligenceSnapshotObjectKey('kev-snapshot-opaque-internal-1');
  if (!objectKey.ok) {
    throw new Error('expected opaque key');
  }
  return {
    id: SNAPSHOT_ID,
    provider: 'cisa_kev',
    sourceIdentifier: CISA_KEV_SOURCE_IDENTIFIER,
    responseSha256: SHA,
    byteLength: 2048,
    declaredContentType: 'application/json',
    detectedContentType: 'application/json',
    objectKey: objectKey.value,
    retrievedAt: NOW,
    storedAt: NOW,
    parserVersion: '0.1.0',
    normalizationVersion: '1',
    catalogVersion: '2026.08.31',
    catalogReleasedAt: NOW,
    etagHash: 'b'.repeat(64),
    lastModified: NOW,
    creatingSyncRunId: SYNC_RUN_ID,
    createdAt: NOW,
    ...overrides,
  };
}

function generation(overrides: Partial<KevGenerationRecord> = {}): KevGenerationRecord {
  return {
    id: GENERATION_ID,
    provider: 'cisa_kev',
    sourceIdentifier: CISA_KEV_SOURCE_IDENTIFIER,
    syncRunId: SYNC_RUN_ID,
    snapshotId: SNAPSHOT_ID,
    state: 'complete',
    stagedEntryCount: 1,
    expectedEntryCount: 1,
    parserVersion: '0.1.0',
    normalizationVersion: '1',
    createdAt: NOW,
    completedAt: NOW,
    activatedAt: null,
    supersededAt: null,
    ...overrides,
  };
}

function entry(overrides: Partial<KevNormalizedEntryRecord> = {}): KevNormalizedEntryRecord {
  const dateAdded = parseCalendarDate('2024-01-15');
  const dueDate = parseCalendarDate('2024-02-15');
  if (!dateAdded.ok || !dueDate.ok) {
    throw new Error('expected calendar dates');
  }
  return {
    id: ENTRY_ID,
    generationId: GENERATION_ID,
    snapshotId: SNAPSHOT_ID,
    ordinal: 0,
    normalizedCve: 'CVE-2024-12345' as CanonicalCve,
    vendorProject: 'Example Vendor',
    product: 'Example Product',
    vulnerabilityName: 'Example Name',
    dateAdded: dateAdded.value,
    shortDescription: 'Plain description',
    requiredAction: 'Apply updates',
    dueDate: dueDate.value,
    knownRansomwareCampaignUse: 'unknown',
    rawKnownRansomwareCampaignUse: null,
    notes: '<b>notes</b>',
    cwes: ['CWE-79'],
    createdAt: NOW,
    ...overrides,
  };
}

describe('snapshot records', () => {
  it('validates SHA-256, positive byte length, and immutable identity', () => {
    expect(validateIntelligenceSnapshotRecord(snapshot()).ok).toBe(true);
    expect(validateIntelligenceSnapshotRecord(snapshot({ responseSha256: 'ABC' })).ok).toBe(false);
    expect(validateIntelligenceSnapshotRecord(snapshot({ byteLength: 0 })).ok).toBe(false);
    const identity = snapshotNaturalIdentity(snapshot());
    expect(identity).toEqual({
      provider: 'cisa_kev',
      sourceIdentifier: CISA_KEV_SOURCE_IDENTIFIER,
      responseSha256: SHA,
    });
    expect(snapshotIdentityFieldsAreImmutable(identity, identity)).toBe(true);
    expect(
      snapshotIdentityFieldsAreImmutable(identity, { ...identity, responseSha256: 'c'.repeat(64) }),
    ).toBe(false);
  });

  it('keeps object keys internal, opaque, and distinct from SBOM keys', () => {
    expect(parseIntelligenceSnapshotObjectKey('https://example.invalid/object').ok).toBe(false);
    expect(
      parseIntelligenceSnapshotObjectKey(
        buildFinalSbomObjectKey({
          organizationId: '11111111-1111-4111-8111-111111111111',
          assetId: '22222222-2222-4222-8222-222222222222',
          sha256: SHA,
        }),
      ).ok,
    ).toBe(false);
    const key = parseIntelligenceSnapshotObjectKey('kev-snapshot-opaque-internal-1');
    expect(key.ok).toBe(true);
    const record = snapshot();
    expect(Object.prototype.hasOwnProperty.call(record, 'organizationId')).toBe(false);
  });
});

describe('KEV generations', () => {
  it('keeps staging invisible and refuses incomplete or mismatched activation', () => {
    expect(generationIsStagingInvisible('staging')).toBe(true);
    expect(generationIsVisibleToReaders('staging')).toBe(false);
    expect(canActivateKevGeneration(generation({ state: 'staging', completedAt: null })).ok).toBe(
      false,
    );
    expect(
      canActivateKevGeneration(generation({ stagedEntryCount: 1, expectedEntryCount: 2 })).ok,
    ).toBe(false);
    expect(canActivateKevGeneration(generation({ state: 'abandoned' })).ok).toBe(false);
    expect(canActivateKevGeneration(generation()).ok).toBe(true);
    expect(validateKevGenerationRecord(generation({ completedAt: null })).ok).toBe(false);
    expect(
      validateKevGenerationRecord(generation({ stagedEntryCount: 1, expectedEntryCount: 2 })).ok,
    ).toBe(false);
    const active = generation({ state: 'active', activatedAt: NOW });
    expect(validateKevGenerationRecord(active).ok).toBe(true);
    expect(
      validateKevGenerationRecord({ ...active, supersededAt: NOW }).ok,
    ).toBe(false);
    expect(canSupersedeActiveKevGeneration(active, generation({ id: ENTRY_ID })).ok).toBe(true);
    expect(
      canSupersedeActiveKevGeneration(active, generation({ state: 'staging', completedAt: null }))
        .ok,
    ).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(active, 'vulnerabilityId')).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(active, 'findingId')).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(active, 'organizationId')).toBe(false);
  });
});

describe('KEV entries and current membership', () => {
  it('retains untrusted text, calendar dates, and no tenant associations', () => {
    const record = entry();
    expect(validateKevNormalizedEntryRecord(record).ok).toBe(true);
    expect(record.notes).toBe('<b>notes</b>');
    expect(record.dateAdded).toBe('2024-01-15');
    expect(Object.prototype.hasOwnProperty.call(record, 'organizationId')).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(record, 'findingId')).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(record, 'componentId')).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(record, 'vulnerabilityId')).toBe(false);
    const active = generation({ state: 'active', activatedAt: NOW });
    const membership = toKevCurrentMembership(active, record);
    expect(membership.ok).toBe(true);
    const stagingMembership = toKevCurrentMembership(generation({ state: 'staging' }), record);
    expect(stagingMembership.ok).toBe(false);
    expect(assertNoDuplicateNormalizedCves([record, { ...record, id: SNAPSHOT_ID }]).ok).toBe(
      false,
    );
  });
});
