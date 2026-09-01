import { describe, expect, it } from 'vitest';

import { deriveIntelligenceProviderHealthStatus } from './freshness.js';

const NOW = new Date('2026-08-31T16:00:00.000Z');

describe('intelligence provider freshness', () => {
  it('never marks deferred OSV or disabled KEV as stale or current', () => {
    expect(
      deriveIntelligenceProviderHealthStatus({
        provider: 'osv',
        implementationStatus: 'deferred',
        lastSuccessfulSyncAt: NOW,
        staleThresholdSeconds: 60,
        now: NOW,
      }),
    ).toEqual({ healthStatus: 'deferred', stale: false });
    expect(
      deriveIntelligenceProviderHealthStatus({
        provider: 'cisa_kev',
        implementationStatus: 'disabled',
        lastSuccessfulSyncAt: NOW,
        staleThresholdSeconds: 60,
        now: new Date('2026-09-10T16:00:00.000Z'),
      }),
    ).toEqual({ healthStatus: 'disabled', stale: false });
  });

  it('uses an injected now for stale calculation and never current without an accepted generation', () => {
    expect(
      deriveIntelligenceProviderHealthStatus({
        provider: 'cisa_kev',
        implementationStatus: 'available',
        lastSuccessfulSyncAt: null,
        staleThresholdSeconds: 60,
        now: NOW,
      }),
    ).toEqual({ healthStatus: 'never_synchronized', stale: false });
    expect(
      deriveIntelligenceProviderHealthStatus({
        provider: 'cisa_kev',
        implementationStatus: 'available',
        lastSuccessfulSyncAt: NOW,
        staleThresholdSeconds: 60,
        now: NOW,
      }),
    ).toEqual({ healthStatus: 'current', stale: false });
    expect(
      deriveIntelligenceProviderHealthStatus({
        provider: 'cisa_kev',
        implementationStatus: 'available',
        lastSuccessfulSyncAt: NOW,
        staleThresholdSeconds: 60,
        now: new Date(NOW.getTime() + 61_000),
      }),
    ).toEqual({ healthStatus: 'stale', stale: true });
  });
});
