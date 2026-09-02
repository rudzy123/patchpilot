import { describe, expect, it } from 'vitest';

import {
  CISA_KEV_SOURCE_IDENTIFIER,
  INTELLIGENCE_PROVIDER_STATUS_CACHE_CONTROL,
  intelligenceProviderDisplayNames,
  intelligencePublicFailureCodes,
} from '@patchpilot/domain';

import {
  expectedDisabledKevPublicStatus,
  expectedOsvPublicStatus,
  intelligenceDisplayName,
  intelligenceProviderDetailResponseSchema,
  intelligenceProviderListResponseSchema,
  intelligenceProviderParamSchema,
  intelligenceProviderStatusSchema,
  intelligencePublicFailureCodeSchema,
} from './intelligence.js';

const STALE_THRESHOLD = 259_200;
const SUCCESS_AT = '2026-08-31T16:00:00.000Z';
const FAILURE_AT = '2026-09-01T00:00:00.000Z';

const FORBIDDEN_FIELDS = {
  objectKey: 'intelligence/snapshots/sha256/' + 'a'.repeat(64),
  bucket: 'patchpilot',
  endpoint: 'http://127.0.0.1:9000',
  etag: '"abc"',
  rawEtag: '"abc"',
  etagHash: 'e'.repeat(64),
  lastModified: SUCCESS_AT,
  sourceUrl: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
  providerUrl:
    'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
  responseSha256: 'a'.repeat(64),
  parserVersion: '0.1.0',
  normalizationVersion: '1',
  byteLength: 2048,
  workerId: 'worker-1',
  workerIdentifier: 'worker-1',
  leaseExpiresAt: SUCCESS_AT,
  nextAttemptAt: SUCCESS_AT,
  queuePayload: { jobId: '1' },
  queueStatus: 'active',
  outboxEventId: '11111111-1111-4111-8111-111111111111',
  backgroundJobId: '22222222-2222-4222-8222-222222222222',
  intelligenceSourceId: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
  syncRunId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
  snapshotId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
  generationId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
  integrationId: 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee',
  membershipId: 'ffffffff-ffff-4fff-8fff-ffffffffffff',
  userId: '99999999-9999-4999-8999-999999999999',
  retryCount: 3,
  retryable: true,
  disposition: 'failed',
  category: 'network',
  rawError: 'ECONNRESET from provider',
  stack: 'Error: boom',
  responseExcerpt: '{"catalogVersion":',
  notes: 'Apply vendor patch',
  requiredAction: 'Apply updates',
  cves: ['CVE-2024-1234'],
  findingId: '33333333-3333-4333-8333-333333333333',
  organizationId: '44444444-4444-4444-8444-444444444444',
  assetId: '55555555-5555-4555-8555-555555555555',
  sbomId: '66666666-6666-4666-8666-666666666666',
  componentId: '77777777-7777-4777-8777-777777777777',
};

function kevNeverSynchronized() {
  return {
    provider: 'cisa_kev',
    displayName: intelligenceProviderDisplayNames.cisa_kev,
    runtimeEnabled: true,
    implementationStatus: 'available',
    healthStatus: 'never_synchronized',
    stale: false,
    staleThresholdSeconds: STALE_THRESHOLD,
    lastSuccessfulSyncAt: null,
    lastAttemptAt: null,
    latestAcceptedCatalogVersion: null,
    latestAcceptedCatalogReleasedAt: null,
    currentEntryCount: null,
    lastSafeFailureCode: null,
    lastFailureAt: null,
  };
}

function kevCurrent() {
  return {
    ...kevNeverSynchronized(),
    healthStatus: 'current',
    lastSuccessfulSyncAt: SUCCESS_AT,
    lastAttemptAt: SUCCESS_AT,
    latestAcceptedCatalogVersion: '2026.08.31',
    latestAcceptedCatalogReleasedAt: SUCCESS_AT,
    currentEntryCount: 1687,
  };
}

function kevStale() {
  return {
    ...kevCurrent(),
    healthStatus: 'stale',
    stale: true,
  };
}

function kevDegraded() {
  return {
    ...kevCurrent(),
    healthStatus: 'degraded',
    lastAttemptAt: FAILURE_AT,
    lastSafeFailureCode: 'provider_unavailable',
    lastFailureAt: FAILURE_AT,
  };
}

function kevDisabledWithHistory() {
  return {
    ...kevCurrent(),
    runtimeEnabled: false,
    implementationStatus: 'disabled',
    healthStatus: 'disabled',
    stale: false,
    lastSafeFailureCode: 'processing_failed',
    lastFailureAt: FAILURE_AT,
  };
}

describe('intelligence provider public contracts', () => {
  it('accepts the closed provider param set and rejects unknown providers', () => {
    expect(intelligenceProviderParamSchema.parse({ provider: 'cisa_kev' })).toEqual({
      provider: 'cisa_kev',
    });
    expect(intelligenceProviderParamSchema.parse({ provider: 'osv' }).provider).toBe('osv');
    expect(intelligenceProviderParamSchema.safeParse({ provider: 'nvd' }).success).toBe(false);
    expect(intelligenceProviderParamSchema.safeParse({ provider: 'github' }).success).toBe(false);
    expect(intelligenceProviderParamSchema.safeParse({ provider: 'CISA_KEV' }).success).toBe(false);
    expect(intelligenceProviderParamSchema.safeParse({ provider: 'cisa' }).success).toBe(false);
    expect(intelligenceProviderParamSchema.safeParse({ provider: 'kev' }).success).toBe(false);
    expect(intelligenceProviderParamSchema.safeParse({ provider: 'reserved' }).success).toBe(false);
    expect(
      intelligenceProviderParamSchema.safeParse({ provider: 'cisa_kev', extra: true }).success,
    ).toBe(false);
  });

  it('requires exactly two providers in cisa_kev then osv order', () => {
    const parsed = intelligenceProviderListResponseSchema.parse({
      providers: [kevNeverSynchronized(), expectedOsvPublicStatus(STALE_THRESHOLD)],
    });
    expect(parsed.providers).toHaveLength(2);
    expect(parsed.providers[0]?.provider).toBe('cisa_kev');
    expect(parsed.providers[1]?.provider).toBe('osv');
    expect(
      intelligenceProviderListResponseSchema.safeParse({
        providers: [kevNeverSynchronized(), kevNeverSynchronized()],
      }).success,
    ).toBe(false);
    expect(
      intelligenceProviderListResponseSchema.safeParse({
        providers: [expectedOsvPublicStatus(STALE_THRESHOLD), kevNeverSynchronized()],
      }).success,
    ).toBe(false);
    expect(
      intelligenceProviderListResponseSchema.safeParse({
        providers: [kevNeverSynchronized()],
      }).success,
    ).toBe(false);
  });

  it('rejects unknown fields and every forbidden internal field class', () => {
    for (const [key, value] of Object.entries(FORBIDDEN_FIELDS)) {
      expect(
        intelligenceProviderStatusSchema.safeParse({ ...kevNeverSynchronized(), [key]: value })
          .success,
        key,
      ).toBe(false);
      expect(
        intelligenceProviderDetailResponseSchema.safeParse({
          ...kevNeverSynchronized(),
          [key]: value,
        }).success,
        key,
      ).toBe(false);
    }
  });

  it('represents disabled KEV without history as not stale and not current', () => {
    const disabled = expectedDisabledKevPublicStatus(STALE_THRESHOLD);
    expect(disabled.implementationStatus).toBe('disabled');
    expect(disabled.healthStatus).toBe('disabled');
    expect(disabled.stale).toBe(false);
    expect(disabled.runtimeEnabled).toBe(false);
    expect(disabled.latestAcceptedCatalogVersion).toBeNull();
    expect(
      intelligenceProviderStatusSchema.safeParse({
        ...disabled,
        stale: true,
      }).success,
    ).toBe(false);
    expect(
      intelligenceProviderStatusSchema.safeParse({
        ...disabled,
        healthStatus: 'current',
      }).success,
    ).toBe(false);
  });

  it('allows disabled KEV with historical accepted catalog metadata', () => {
    const parsed = intelligenceProviderStatusSchema.parse(kevDisabledWithHistory());
    expect(parsed.healthStatus).toBe('disabled');
    expect(parsed.stale).toBe(false);
    expect(parsed.latestAcceptedCatalogVersion).toBe('2026.08.31');
    expect(parsed.currentEntryCount).toBe(1687);
    expect(parsed.lastSafeFailureCode).toBe('processing_failed');
  });

  it('represents deferred OSV as not healthy or synchronized and rejects attempt/failure fields', () => {
    const osv = expectedOsvPublicStatus(STALE_THRESHOLD);
    expect(osv.runtimeEnabled).toBe(false);
    expect(osv.lastSuccessfulSyncAt).toBeNull();
    expect(osv.lastAttemptAt).toBeNull();
    expect(osv.lastSafeFailureCode).toBeNull();
    expect(osv.lastFailureAt).toBeNull();
    expect(
      intelligenceProviderStatusSchema.safeParse({
        ...osv,
        healthStatus: 'current',
      }).success,
    ).toBe(false);
    expect(
      intelligenceProviderStatusSchema.safeParse({
        ...osv,
        lastSuccessfulSyncAt: SUCCESS_AT,
      }).success,
    ).toBe(false);
    expect(
      intelligenceProviderStatusSchema.safeParse({
        ...osv,
        lastAttemptAt: SUCCESS_AT,
      }).success,
    ).toBe(false);
    expect(
      intelligenceProviderStatusSchema.safeParse({
        ...osv,
        lastSafeFailureCode: 'provider_unavailable',
      }).success,
    ).toBe(false);
    expect(
      intelligenceProviderStatusSchema.safeParse({
        ...osv,
        lastFailureAt: FAILURE_AT,
      }).success,
    ).toBe(false);
  });

  it('treats absent accepted generation as never current, with nullable timestamps', () => {
    const parsed = intelligenceProviderStatusSchema.parse(kevNeverSynchronized());
    expect(parsed.lastSuccessfulSyncAt).toBeNull();
    expect(parsed.lastAttemptAt).toBeNull();
    expect(parsed.latestAcceptedCatalogReleasedAt).toBeNull();
    expect(parsed.healthStatus).toBe('never_synchronized');
    expect(
      intelligenceProviderStatusSchema.safeParse({
        ...kevNeverSynchronized(),
        healthStatus: 'current',
      }).success,
    ).toBe(false);
    expect(
      intelligenceProviderStatusSchema.safeParse({
        ...kevNeverSynchronized(),
        latestAcceptedCatalogVersion: '2026.08.31',
      }).success,
    ).toBe(false);
    expect(
      intelligenceProviderStatusSchema.parse({
        ...kevNeverSynchronized(),
        lastAttemptAt: FAILURE_AT,
        lastSafeFailureCode: 'provider_unavailable',
        lastFailureAt: FAILURE_AT,
      }).healthStatus,
    ).toBe('never_synchronized');
  });

  it('accepts current KEV status after an accepted generation', () => {
    const parsed = intelligenceProviderDetailResponseSchema.parse(kevCurrent());
    expect(parsed.healthStatus).toBe('current');
    expect(parsed.currentEntryCount).toBe(1687);
    expect(parsed.stale).toBe(false);
    expect(
      intelligenceProviderStatusSchema.safeParse({
        ...kevCurrent(),
        healthStatus: 'never_synchronized',
      }).success,
    ).toBe(false);
    expect(
      intelligenceProviderStatusSchema.safeParse({
        ...kevCurrent(),
        healthStatus: 'stale',
        stale: false,
      }).success,
    ).toBe(false);
    expect(
      intelligenceProviderStatusSchema.safeParse({
        ...kevCurrent(),
        latestAcceptedCatalogVersion: null,
      }).success,
    ).toBe(false);
    expect(
      intelligenceProviderStatusSchema.safeParse({
        ...kevCurrent(),
        latestAcceptedCatalogReleasedAt: null,
      }).success,
    ).toBe(false);
  });

  it('accepts stale KEV including later supporting failure context', () => {
    const parsed = intelligenceProviderStatusSchema.parse({
      ...kevStale(),
      lastSafeFailureCode: 'storage_unavailable',
      lastFailureAt: FAILURE_AT,
    });
    expect(parsed.healthStatus).toBe('stale');
    expect(parsed.stale).toBe(true);
    expect(
      intelligenceProviderStatusSchema.safeParse({
        ...kevStale(),
        stale: false,
      }).success,
    ).toBe(false);
  });

  it('accepts degraded KEV only with a mapped public failure code', () => {
    const parsed = intelligenceProviderStatusSchema.parse(kevDegraded());
    expect(parsed.healthStatus).toBe('degraded');
    expect(parsed.stale).toBe(false);
    expect(parsed.lastSafeFailureCode).toBe('provider_unavailable');
    expect(
      intelligenceProviderStatusSchema.safeParse({
        ...kevDegraded(),
        lastSafeFailureCode: null,
      }).success,
    ).toBe(false);
    expect(
      intelligenceProviderStatusSchema.safeParse({
        ...kevDegraded(),
        lastFailureAt: null,
      }).success,
    ).toBe(false);
    expect(
      intelligenceProviderStatusSchema.safeParse({
        ...kevDegraded(),
        stale: true,
      }).success,
    ).toBe(false);
  });

  it('closes the public failure-code allowlist and rejects internal codes', () => {
    expect([...intelligencePublicFailureCodes]).toEqual([
      'provider_unavailable',
      'synchronization_timeout',
      'invalid_provider_response',
      'storage_unavailable',
      'processing_failed',
      'catalog_regression',
    ]);
    expect(intelligencePublicFailureCodeSchema.parse('catalog_regression')).toBe(
      'catalog_regression',
    );
    expect(intelligencePublicFailureCodeSchema.safeParse('schema_invalid').success).toBe(false);
    expect(intelligencePublicFailureCodeSchema.safeParse('dns_rejected').success).toBe(false);
    expect(intelligencePublicFailureCodeSchema.safeParse('ECONNRESET').success).toBe(false);
    expect(intelligenceDisplayName('cisa_kev')).toBe('CISA Known Exploited Vulnerabilities');
    expect(INTELLIGENCE_PROVIDER_STATUS_CACHE_CONTROL).toBe('private, no-store');
    expect(CISA_KEV_SOURCE_IDENTIFIER).toBe('cisa_kev_json_catalog');
  });
});
