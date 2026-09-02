import {
  intelligenceProviderListResponseSchema,
  intelligenceProviderStatusSchema,
  type IntelligenceProviderListResponse,
  type IntelligenceProviderStatus,
} from '@patchpilot/contracts';
import {
  formatUtcInstant,
  type IntelligenceProviderStatusList,
  type IntelligenceProviderStatusProjection,
} from '@patchpilot/domain';

export function toPublicProviderStatus(
  projection: IntelligenceProviderStatusProjection,
): IntelligenceProviderStatus {
  return intelligenceProviderStatusSchema.parse({
    provider: projection.provider,
    displayName: projection.displayName,
    runtimeEnabled: projection.runtimeEnabled,
    implementationStatus: projection.implementationStatus,
    healthStatus: projection.healthStatus,
    stale: projection.stale,
    staleThresholdSeconds: projection.staleThresholdSeconds,
    lastSuccessfulSyncAt: utcOrNull(projection.lastSuccessfulSyncAt),
    lastAttemptAt: utcOrNull(projection.lastAttemptAt),
    latestAcceptedCatalogVersion: projection.latestAcceptedCatalogVersion,
    latestAcceptedCatalogReleasedAt: utcOrNull(projection.latestAcceptedCatalogReleasedAt),
    currentEntryCount: projection.currentEntryCount,
    lastSafeFailureCode: projection.lastSafeFailureCode,
    lastFailureAt: utcOrNull(projection.lastFailureAt),
  });
}

export function toPublicProviderList(
  list: IntelligenceProviderStatusList,
): IntelligenceProviderListResponse {
  const first = list.providers[0];
  const second = list.providers[1];
  return intelligenceProviderListResponseSchema.parse({
    providers: [toPublicProviderStatus(first), toPublicProviderStatus(second)],
  });
}

function utcOrNull(value: Date | null): string | null {
  return value === null ? null : formatUtcInstant(value);
}
