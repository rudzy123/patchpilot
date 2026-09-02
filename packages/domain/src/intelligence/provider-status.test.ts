import { describe, expect, it } from 'vitest';

import { ORGANIZATION_CONTEXT_REQUIRED, PERMISSION_DENIED } from '../assets/errors.js';
import { INTELLIGENCE_READ_PERMISSION } from './constants.js';
import { INTELLIGENCE_STATUS_INCONSISTENT } from './errors.js';
import {
  authorizeIntelligenceRead,
  deriveCisaKevProviderStatus,
  intelligenceEnablementMismatches,
  synthesizeDeferredOsvStatus,
  type CisaKevStatusGeneration,
  type CisaKevStatusSnapshot,
  type IntelligenceStatusActor,
} from './provider-status.js';

const NOW = new Date('2026-09-02T12:00:00.000Z');
const SUCCESS_AT = new Date('2026-08-31T16:00:00.000Z');
const THRESHOLD = 259_200;
const GENERATION_ID = '11111111-1111-4111-8111-111111111111';

function actor(
  permissions: readonly string[] = [INTELLIGENCE_READ_PERMISSION],
): IntelligenceStatusActor {
  return {
    userId: 'user-1',
    sessionId: 'session-1',
    organizationId: 'org-1',
    membershipId: 'membership-1',
    permissions,
  };
}

type SnapshotOverrides = {
  sourceState?: string;
  lastSuccessfulSyncAt?: Date | null;
  lastAttemptAt?: Date | null;
  lastFailureAt?: Date | null;
  lastFailureCode?: string | null;
  activeGenerationId?: string | null;
  generation?: Partial<CisaKevStatusGeneration> | null;
};

function acceptedSnapshot(overrides: SnapshotOverrides = {}): CisaKevStatusSnapshot {
  const generationOverride = overrides.generation;
  return {
    sourceState: overrides.sourceState ?? 'enabled',
    lastSuccessfulSyncAt:
      overrides.lastSuccessfulSyncAt === undefined ? SUCCESS_AT : overrides.lastSuccessfulSyncAt,
    lastAttemptAt: overrides.lastAttemptAt === undefined ? SUCCESS_AT : overrides.lastAttemptAt,
    lastFailureAt: overrides.lastFailureAt === undefined ? null : overrides.lastFailureAt,
    lastFailureCode: overrides.lastFailureCode === undefined ? null : overrides.lastFailureCode,
    activeGenerationId:
      overrides.activeGenerationId === undefined ? GENERATION_ID : overrides.activeGenerationId,
    generation:
      generationOverride === null
        ? null
        : {
            state: generationOverride?.state ?? 'active',
            catalogVersion:
              generationOverride?.catalogVersion === undefined
                ? '2026.08.31'
                : generationOverride.catalogVersion,
            catalogReleasedAt:
              generationOverride?.catalogReleasedAt === undefined
                ? SUCCESS_AT
                : generationOverride.catalogReleasedAt,
            expectedEntryCount:
              generationOverride?.expectedEntryCount === undefined
                ? 1687
                : generationOverride.expectedEntryCount,
          },
  };
}

function emptySnapshot(overrides?: Partial<CisaKevStatusSnapshot>): CisaKevStatusSnapshot {
  return {
    sourceState: overrides?.sourceState ?? 'enabled',
    lastSuccessfulSyncAt: overrides?.lastSuccessfulSyncAt ?? null,
    lastAttemptAt: overrides?.lastAttemptAt ?? null,
    lastFailureAt: overrides?.lastFailureAt ?? null,
    lastFailureCode: overrides?.lastFailureCode ?? null,
    activeGenerationId: overrides?.activeGenerationId ?? null,
    generation: overrides?.generation ?? null,
  };
}

describe('intelligence provider-status derivation', () => {
  it('authorizes active Organization context and intelligence:read without using organizationId for data', () => {
    expect(authorizeIntelligenceRead(actor()).ok).toBe(true);
    expect(
      authorizeIntelligenceRead({
        ...actor(),
        organizationId: null,
        membershipId: null,
      }),
    ).toEqual({ ok: false, error: ORGANIZATION_CONTEXT_REQUIRED });
    expect(authorizeIntelligenceRead(actor(['integration:read']))).toEqual({
      ok: false,
      error: PERMISSION_DENIED,
    });
    expect(authorizeIntelligenceRead(actor(['finding:read']))).toEqual({
      ok: false,
      error: PERMISSION_DENIED,
    });
    expect(authorizeIntelligenceRead(actor(['sbom:read']))).toEqual({
      ok: false,
      error: PERMISSION_DENIED,
    });
    expect(authorizeIntelligenceRead(actor([]))).toEqual({
      ok: false,
      error: PERMISSION_DENIED,
    });
  });

  it('synthesizes deferred OSV status without catalog or failure fields', () => {
    expect(synthesizeDeferredOsvStatus(THRESHOLD)).toEqual({
      provider: 'osv',
      displayName: 'OSV',
      runtimeEnabled: false,
      implementationStatus: 'deferred',
      healthStatus: 'deferred',
      stale: false,
      staleThresholdSeconds: THRESHOLD,
      lastSuccessfulSyncAt: null,
      lastAttemptAt: null,
      latestAcceptedCatalogVersion: null,
      latestAcceptedCatalogReleasedAt: null,
      currentEntryCount: null,
      lastSafeFailureCode: null,
      lastFailureAt: null,
    });
  });

  it('returns never_synchronized for enabled CISA with no history', () => {
    const derived = deriveCisaKevProviderStatus({
      runtimeEnabled: true,
      staleThresholdSeconds: THRESHOLD,
      now: NOW,
      snapshot: emptySnapshot(),
    });
    expect(derived.ok).toBe(true);
    if (derived.ok) {
      expect(derived.value.implementationStatus).toBe('available');
      expect(derived.value.healthStatus).toBe('never_synchronized');
      expect(derived.value.stale).toBe(false);
      expect(derived.value.latestAcceptedCatalogVersion).toBeNull();
      expect(derived.value.currentEntryCount).toBeNull();
    }
  });

  it('preserves failed initial-sync supporting fields while remaining never_synchronized', () => {
    const failedAt = new Date('2026-09-01T00:00:00.000Z');
    const derived = deriveCisaKevProviderStatus({
      runtimeEnabled: true,
      staleThresholdSeconds: THRESHOLD,
      now: NOW,
      snapshot: emptySnapshot({
        lastAttemptAt: failedAt,
        lastFailureAt: failedAt,
        lastFailureCode: 'dns_rejected',
      }),
    });
    expect(derived.ok).toBe(true);
    if (derived.ok) {
      expect(derived.value.healthStatus).toBe('never_synchronized');
      expect(derived.value.lastSafeFailureCode).toBe('provider_unavailable');
      expect(derived.value.lastFailureAt).toEqual(failedAt);
    }
  });

  it('returns disabled without history and does not label the catalog stale', () => {
    const derived = deriveCisaKevProviderStatus({
      runtimeEnabled: false,
      staleThresholdSeconds: THRESHOLD,
      now: NOW,
      snapshot: emptySnapshot({ sourceState: 'enabled' }),
    });
    expect(derived.ok).toBe(true);
    if (derived.ok) {
      expect(derived.value.runtimeEnabled).toBe(false);
      expect(derived.value.implementationStatus).toBe('disabled');
      expect(derived.value.healthStatus).toBe('disabled');
      expect(derived.value.stale).toBe(false);
      expect(derived.value.lastSuccessfulSyncAt).toBeNull();
      expect(derived.value.currentEntryCount).toBeNull();
    }
    expect(intelligenceEnablementMismatches(false, 'enabled')).toBe(true);
  });

  it('preserves accepted catalog metadata when KEV is disabled with history', () => {
    const derived = deriveCisaKevProviderStatus({
      runtimeEnabled: false,
      staleThresholdSeconds: THRESHOLD,
      now: new Date('2026-10-01T00:00:00.000Z'),
      snapshot: acceptedSnapshot({
        lastFailureAt: NOW,
        lastFailureCode: 'provider_server_error',
      }),
    });
    expect(derived.ok).toBe(true);
    if (derived.ok) {
      expect(derived.value.healthStatus).toBe('disabled');
      expect(derived.value.stale).toBe(false);
      expect(derived.value.lastSuccessfulSyncAt).toEqual(SUCCESS_AT);
      expect(derived.value.latestAcceptedCatalogVersion).toBe('2026.08.31');
      expect(derived.value.latestAcceptedCatalogReleasedAt).toEqual(SUCCESS_AT);
      expect(derived.value.currentEntryCount).toBe(1687);
      expect(derived.value.lastSafeFailureCode).toBe('provider_unavailable');
      expect(derived.value.lastFailureAt).toEqual(NOW);
    }
  });

  it('returns current when freshness is within the threshold and no later failure exists', () => {
    const derived = deriveCisaKevProviderStatus({
      runtimeEnabled: true,
      staleThresholdSeconds: THRESHOLD,
      now: new Date(SUCCESS_AT.getTime() + THRESHOLD * 1000),
      snapshot: acceptedSnapshot(),
    });
    expect(derived.ok).toBe(true);
    if (derived.ok) {
      expect(derived.value.healthStatus).toBe('current');
      expect(derived.value.stale).toBe(false);
    }
  });

  it('returns stale when age exceeds the threshold and stale takes precedence over degraded', () => {
    const laterFailure = new Date(SUCCESS_AT.getTime() + 60_000);
    const derived = deriveCisaKevProviderStatus({
      runtimeEnabled: true,
      staleThresholdSeconds: THRESHOLD,
      now: new Date(SUCCESS_AT.getTime() + (THRESHOLD + 1) * 1000),
      snapshot: acceptedSnapshot({
        lastFailureAt: laterFailure,
        lastFailureCode: 'parser_crash',
      }),
    });
    expect(derived.ok).toBe(true);
    if (derived.ok) {
      expect(derived.value.healthStatus).toBe('stale');
      expect(derived.value.stale).toBe(true);
      expect(derived.value.lastSafeFailureCode).toBe('processing_failed');
    }
  });

  it('returns degraded when a later failure exists and freshness is not stale', () => {
    const laterFailure = new Date(SUCCESS_AT.getTime() + 60_000);
    const derived = deriveCisaKevProviderStatus({
      runtimeEnabled: true,
      staleThresholdSeconds: THRESHOLD,
      now: new Date(SUCCESS_AT.getTime() + 120_000),
      snapshot: acceptedSnapshot({
        lastAttemptAt: laterFailure,
        lastFailureAt: laterFailure,
        lastFailureCode: 'schema_invalid',
      }),
    });
    expect(derived.ok).toBe(true);
    if (derived.ok) {
      expect(derived.value.healthStatus).toBe('degraded');
      expect(derived.value.stale).toBe(false);
      expect(derived.value.lastSafeFailureCode).toBe('invalid_provider_response');
    }
  });

  it('does not treat equal failure and success timestamps as degraded', () => {
    const derived = deriveCisaKevProviderStatus({
      runtimeEnabled: true,
      staleThresholdSeconds: THRESHOLD,
      now: NOW,
      snapshot: acceptedSnapshot({
        lastFailureAt: SUCCESS_AT,
        lastFailureCode: 'dns_rejected',
      }),
    });
    expect(derived.ok).toBe(true);
    if (derived.ok) {
      expect(derived.value.healthStatus).toBe('current');
      expect(derived.value.lastSafeFailureCode).toBe('provider_unavailable');
    }
  });

  it('treats a future successful timestamp as current with elapsed age zero', () => {
    const futureSuccess = new Date(NOW.getTime() + 60_000);
    const derived = deriveCisaKevProviderStatus({
      runtimeEnabled: true,
      staleThresholdSeconds: 30,
      now: NOW,
      snapshot: acceptedSnapshot({
        lastSuccessfulSyncAt: futureSuccess,
        lastAttemptAt: futureSuccess,
        generation: { catalogReleasedAt: futureSuccess },
      }),
    });
    expect(derived.ok).toBe(true);
    if (derived.ok) {
      expect(derived.value.healthStatus).toBe('current');
      expect(derived.value.stale).toBe(false);
      expect(derived.value.lastSuccessfulSyncAt).toEqual(futureSuccess);
    }
  });

  it('maps unknown persisted failure codes to processing_failed', () => {
    const laterFailure = new Date(SUCCESS_AT.getTime() + 1_000);
    const derived = deriveCisaKevProviderStatus({
      runtimeEnabled: true,
      staleThresholdSeconds: THRESHOLD,
      now: NOW,
      snapshot: acceptedSnapshot({
        lastFailureAt: laterFailure,
        lastFailureCode: 'not_a_catalogued_code',
      }),
    });
    expect(derived.ok).toBe(true);
    if (derived.ok) {
      expect(derived.value.healthStatus).toBe('degraded');
      expect(derived.value.lastSafeFailureCode).toBe('processing_failed');
    }
  });

  it('fails safely for missing generation, non-active generation, and pointer/success mismatches', () => {
    expect(
      deriveCisaKevProviderStatus({
        runtimeEnabled: true,
        staleThresholdSeconds: THRESHOLD,
        now: NOW,
        snapshot: acceptedSnapshot({ generation: null }),
      }),
    ).toEqual({ ok: false, error: INTELLIGENCE_STATUS_INCONSISTENT });
    expect(
      deriveCisaKevProviderStatus({
        runtimeEnabled: true,
        staleThresholdSeconds: THRESHOLD,
        now: NOW,
        snapshot: acceptedSnapshot({ generation: { state: 'complete' } }),
      }),
    ).toEqual({ ok: false, error: INTELLIGENCE_STATUS_INCONSISTENT });
    expect(
      deriveCisaKevProviderStatus({
        runtimeEnabled: true,
        staleThresholdSeconds: THRESHOLD,
        now: NOW,
        snapshot: acceptedSnapshot({ lastSuccessfulSyncAt: null }),
      }),
    ).toEqual({ ok: false, error: INTELLIGENCE_STATUS_INCONSISTENT });
    expect(
      deriveCisaKevProviderStatus({
        runtimeEnabled: true,
        staleThresholdSeconds: THRESHOLD,
        now: NOW,
        snapshot: emptySnapshot({ lastSuccessfulSyncAt: SUCCESS_AT }),
      }),
    ).toEqual({ ok: false, error: INTELLIGENCE_STATUS_INCONSISTENT });
  });

  it('fails safely for missing catalog metadata, invalid counts, and unpaired failure fields', () => {
    expect(
      deriveCisaKevProviderStatus({
        runtimeEnabled: true,
        staleThresholdSeconds: THRESHOLD,
        now: NOW,
        snapshot: acceptedSnapshot({ generation: { catalogVersion: null } }),
      }),
    ).toEqual({ ok: false, error: INTELLIGENCE_STATUS_INCONSISTENT });
    expect(
      deriveCisaKevProviderStatus({
        runtimeEnabled: true,
        staleThresholdSeconds: THRESHOLD,
        now: NOW,
        snapshot: acceptedSnapshot({ generation: { catalogReleasedAt: null } }),
      }),
    ).toEqual({ ok: false, error: INTELLIGENCE_STATUS_INCONSISTENT });
    expect(
      deriveCisaKevProviderStatus({
        runtimeEnabled: true,
        staleThresholdSeconds: THRESHOLD,
        now: NOW,
        snapshot: acceptedSnapshot({ generation: { expectedEntryCount: -1 } }),
      }),
    ).toEqual({ ok: false, error: INTELLIGENCE_STATUS_INCONSISTENT });
    expect(
      deriveCisaKevProviderStatus({
        runtimeEnabled: true,
        staleThresholdSeconds: THRESHOLD,
        now: NOW,
        snapshot: acceptedSnapshot({ lastFailureAt: NOW, lastFailureCode: null }),
      }),
    ).toEqual({ ok: false, error: INTELLIGENCE_STATUS_INCONSISTENT });
  });
});
