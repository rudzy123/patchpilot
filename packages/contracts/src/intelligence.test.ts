import { describe, expect, it } from 'vitest';

import {
  CISA_KEV_SOURCE_IDENTIFIER,
  INTELLIGENCE_PROVIDER_STATUS_CACHE_CONTROL,
  intelligenceProviderDisplayNames,
  intelligenceSafeFailureCodes,
} from '@patchpilot/domain';

import {
  expectedDisabledKevPublicStatus,
  expectedOsvPublicStatus,
  intelligenceDisplayName,
  intelligenceProviderDetailResponseSchema,
  intelligenceProviderListResponseSchema,
  intelligenceProviderParamSchema,
  intelligenceProviderStatusSchema,
  intelligenceSafeFailureCodeSchema,
} from './intelligence.js';

const STALE_THRESHOLD = 259_200;
const SUCCESS_AT = '2026-08-31T16:00:00.000Z';

const FORBIDDEN_FIELDS = {
  objectKey: 'intelligence/snapshots/sha256/' + 'a'.repeat(64),
  etag: '"abc"',
  rawEtag: '"abc"',
  sourceUrl: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
  workerId: 'worker-1',
  workerIdentifier: 'worker-1',
  leaseExpiresAt: SUCCESS_AT,
  queuePayload: { jobId: '1' },
  outboxEventId: '11111111-1111-4111-8111-111111111111',
  backgroundJobId: '22222222-2222-4222-8222-222222222222',
  retryCount: 3,
  rawError: 'ECONNRESET from provider',
  stack: 'Error: boom',
  responseExcerpt: '{"catalogVersion":',
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

describe('intelligence provider public contracts', () => {
  it('accepts the closed provider param set and rejects unknown providers', () => {
    expect(intelligenceProviderParamSchema.parse({ provider: 'cisa_kev' })).toEqual({
      provider: 'cisa_kev',
    });
    expect(intelligenceProviderParamSchema.parse({ provider: 'osv' }).provider).toBe('osv');
    expect(intelligenceProviderParamSchema.safeParse({ provider: 'nvd' }).success).toBe(false);
    expect(intelligenceProviderParamSchema.safeParse({ provider: 'github' }).success).toBe(false);
    expect(
      intelligenceProviderParamSchema.safeParse({ provider: 'cisa_kev', extra: true }).success,
    ).toBe(false);
  });

  it('accepts a strict provider list with deferred OSV and never-synchronized KEV', () => {
    const parsed = intelligenceProviderListResponseSchema.parse({
      providers: [kevNeverSynchronized(), expectedOsvPublicStatus(STALE_THRESHOLD)],
    });
    expect(parsed.providers).toHaveLength(2);
    expect(parsed.providers[1]?.implementationStatus).toBe('deferred');
    expect(parsed.providers[1]?.healthStatus).toBe('deferred');
    expect(parsed.providers[1]?.stale).toBe(false);
    expect(parsed.providers[0]?.healthStatus).toBe('never_synchronized');
    expect(
      intelligenceProviderListResponseSchema.safeParse({
        providers: [kevNeverSynchronized(), kevNeverSynchronized()],
      }).success,
    ).toBe(false);
  });

  it('rejects unknown fields, object keys, ETags, worker details, and tenant IDs', () => {
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

  it('represents disabled KEV as not stale and not current', () => {
    const disabled = expectedDisabledKevPublicStatus(STALE_THRESHOLD);
    expect(disabled.implementationStatus).toBe('disabled');
    expect(disabled.healthStatus).toBe('disabled');
    expect(disabled.stale).toBe(false);
    expect(disabled.runtimeEnabled).toBe(false);
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

  it('represents deferred OSV as not healthy or synchronized', () => {
    const osv = expectedOsvPublicStatus(STALE_THRESHOLD);
    expect(osv.runtimeEnabled).toBe(false);
    expect(osv.lastSuccessfulSyncAt).toBeNull();
    expect(osv.currentEntryCount).toBeNull();
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
  });

  it('closes the public safe failure code set and display names', () => {
    expect(intelligenceSafeFailureCodeSchema.parse('schema_invalid')).toBe('schema_invalid');
    expect(intelligenceSafeFailureCodeSchema.safeParse('ECONNRESET').success).toBe(false);
    expect([...intelligenceSafeFailureCodes]).toContain('catalog_regression');
    expect([...intelligenceSafeFailureCodes]).toContain('normalized_output_too_large');
    expect(intelligenceSafeFailureCodeSchema.parse('normalized_output_too_large')).toBe(
      'normalized_output_too_large',
    );
    expect(intelligenceDisplayName('cisa_kev')).toBe('CISA Known Exploited Vulnerabilities');
    expect(INTELLIGENCE_PROVIDER_STATUS_CACHE_CONTROL).toBe('private, no-store');
    expect(CISA_KEV_SOURCE_IDENTIFIER).toBe('cisa_kev_json_catalog');
  });
});
