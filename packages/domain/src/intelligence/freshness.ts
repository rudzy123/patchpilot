import {
  intelligenceProviderHealthStatuses,
  intelligenceProviderImplementationStatuses,
  type IntelligenceProvider,
  type IntelligenceProviderHealthStatus,
  type IntelligenceProviderImplementationStatus,
} from './constants.js';
import { isPositiveSafeInteger } from './normalize.js';

export type IntelligenceProviderFreshness = {
  provider: IntelligenceProvider;
  sourceIdentifier: 'cisa_kev_json_catalog' | null;
  implementationStatus: IntelligenceProviderImplementationStatus;
  runtimeEnabled: boolean;
  lastSuccessfulSyncAt: Date | null;
  lastAttemptAt: Date | null;
  latestAcceptedCatalogVersion: string | null;
  latestAcceptedCatalogReleasedAt: Date | null;
  currentEntryCount: number | null;
  lastSafeFailureCode: string | null;
  lastFailureAt: Date | null;
  staleThresholdSeconds: number;
};

export type DerivedIntelligenceProviderStatus = {
  healthStatus: IntelligenceProviderHealthStatus;
  stale: boolean;
};

export function deriveIntelligenceProviderHealthStatus(input: {
  provider: IntelligenceProvider;
  implementationStatus: IntelligenceProviderImplementationStatus;
  lastSuccessfulSyncAt: Date | null;
  staleThresholdSeconds: number;
  now: Date;
}): DerivedIntelligenceProviderStatus {
  if (input.provider === 'osv' || input.implementationStatus === 'deferred') {
    return { healthStatus: 'deferred', stale: false };
  }
  if (input.implementationStatus === 'disabled') {
    return { healthStatus: 'disabled', stale: false };
  }
  if (input.lastSuccessfulSyncAt === null) {
    return { healthStatus: 'never_synchronized', stale: false };
  }
  if (!isPositiveSafeInteger(input.staleThresholdSeconds)) {
    return { healthStatus: 'never_synchronized', stale: false };
  }
  const elapsedSeconds = (input.now.getTime() - input.lastSuccessfulSyncAt.getTime()) / 1000;
  const stale = elapsedSeconds > input.staleThresholdSeconds;
  return {
    healthStatus: stale ? 'stale' : 'current',
    stale,
  };
}

export function intelligenceFreshnessMayAdvanceForState(
  state:
    'completed' | 'not_modified' | 'failed' | 'quarantined' | 'staging' | 'disabled' | 'deferred',
): boolean {
  return state === 'completed' || state === 'not_modified';
}

export function isIntelligenceProviderHealthStatus(
  value: string,
): value is IntelligenceProviderHealthStatus {
  return (intelligenceProviderHealthStatuses as readonly string[]).includes(value);
}

export function isIntelligenceProviderImplementationStatus(
  value: string,
): value is IntelligenceProviderImplementationStatus {
  return (intelligenceProviderImplementationStatuses as readonly string[]).includes(value);
}
