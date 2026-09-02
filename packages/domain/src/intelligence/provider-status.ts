import { ORGANIZATION_CONTEXT_REQUIRED, PERMISSION_DENIED } from '../assets/errors.js';
import { err, ok, type Result } from '../result.js';
import {
  INTELLIGENCE_READ_PERMISSION,
  intelligenceProviderDisplayNames,
  type IntelligenceProvider,
  type IntelligenceProviderHealthStatus,
  type IntelligenceProviderImplementationStatus,
  type KevGenerationState,
} from './constants.js';
import { INTELLIGENCE_STATUS_INCONSISTENT } from './errors.js';
import { elapsedFreshnessAgeSeconds } from './freshness.js';
import { isNonNegativeSafeInteger } from './normalize.js';
import {
  mapInternalFailureCodeToPublic,
  type IntelligencePublicFailureCode,
} from './public-failure-codes.js';

export type IntelligenceStatusActor = {
  readonly userId: string;
  readonly sessionId: string;
  readonly organizationId: string | null;
  readonly membershipId: string | null;
  readonly permissions: readonly string[];
};

export type CisaKevStatusGeneration = {
  state: KevGenerationState;
  catalogVersion: string | null;
  catalogReleasedAt: Date | null;
  expectedEntryCount: number;
};

export type CisaKevStatusSnapshot = {
  sourceState: string;
  lastSuccessfulSyncAt: Date | null;
  lastAttemptAt: Date | null;
  lastFailureAt: Date | null;
  lastFailureCode: string | null;
  activeGenerationId: string | null;
  generation: CisaKevStatusGeneration | null;
};

export type IntelligenceProviderStatusProjection = {
  provider: IntelligenceProvider;
  displayName: string;
  runtimeEnabled: boolean;
  implementationStatus: IntelligenceProviderImplementationStatus;
  healthStatus: IntelligenceProviderHealthStatus;
  stale: boolean;
  staleThresholdSeconds: number;
  lastSuccessfulSyncAt: Date | null;
  lastAttemptAt: Date | null;
  latestAcceptedCatalogVersion: string | null;
  latestAcceptedCatalogReleasedAt: Date | null;
  currentEntryCount: number | null;
  lastSafeFailureCode: IntelligencePublicFailureCode | null;
  lastFailureAt: Date | null;
};

export function authorizeIntelligenceRead(
  actor: IntelligenceStatusActor,
): Result<IntelligenceStatusActor> {
  if (actor.organizationId === null || actor.membershipId === null) {
    return err(ORGANIZATION_CONTEXT_REQUIRED);
  }
  if (!actor.permissions.includes(INTELLIGENCE_READ_PERMISSION)) {
    return err(PERMISSION_DENIED);
  }
  return ok(actor);
}

export function intelligenceEnablementMismatches(
  runtimeEnabled: boolean,
  sourceState: string,
): boolean {
  return (
    (runtimeEnabled && sourceState === 'disabled') || (!runtimeEnabled && sourceState === 'enabled')
  );
}

export function synthesizeDeferredOsvStatus(
  staleThresholdSeconds: number,
): IntelligenceProviderStatusProjection {
  return {
    provider: 'osv',
    displayName: intelligenceProviderDisplayNames.osv,
    runtimeEnabled: false,
    implementationStatus: 'deferred',
    healthStatus: 'deferred',
    stale: false,
    staleThresholdSeconds,
    lastSuccessfulSyncAt: null,
    lastAttemptAt: null,
    latestAcceptedCatalogVersion: null,
    latestAcceptedCatalogReleasedAt: null,
    currentEntryCount: null,
    lastSafeFailureCode: null,
    lastFailureAt: null,
  };
}

export function deriveCisaKevProviderStatus(input: {
  runtimeEnabled: boolean;
  staleThresholdSeconds: number;
  now: Date;
  snapshot: CisaKevStatusSnapshot;
}): Result<IntelligenceProviderStatusProjection> {
  const failure = mappedFailure(input.snapshot.lastFailureCode, input.snapshot.lastFailureAt);
  if (!failure.ok) {
    return failure;
  }
  const history = acceptedCatalogHistory(input.snapshot);
  if (!history.ok) {
    return history;
  }

  const lastAttemptAt = input.snapshot.lastAttemptAt;
  const lastSafeFailureCode = failure.value.code;
  const lastFailureAt = failure.value.at;

  if (!input.runtimeEnabled) {
    return ok(
      kevProjection({
        runtimeEnabled: false,
        implementationStatus: 'disabled',
        healthStatus: 'disabled',
        stale: false,
        staleThresholdSeconds: input.staleThresholdSeconds,
        lastSuccessfulSyncAt: history.value?.lastSuccessfulSyncAt ?? null,
        lastAttemptAt,
        latestAcceptedCatalogVersion: history.value?.catalogVersion ?? null,
        latestAcceptedCatalogReleasedAt: history.value?.catalogReleasedAt ?? null,
        currentEntryCount: history.value?.expectedEntryCount ?? null,
        lastSafeFailureCode,
        lastFailureAt,
      }),
    );
  }

  if (history.value === null) {
    return ok(
      kevProjection({
        runtimeEnabled: true,
        implementationStatus: 'available',
        healthStatus: 'never_synchronized',
        stale: false,
        staleThresholdSeconds: input.staleThresholdSeconds,
        lastSuccessfulSyncAt: null,
        lastAttemptAt,
        latestAcceptedCatalogVersion: null,
        latestAcceptedCatalogReleasedAt: null,
        currentEntryCount: null,
        lastSafeFailureCode,
        lastFailureAt,
      }),
    );
  }

  const elapsed = elapsedFreshnessAgeSeconds(input.now, history.value.lastSuccessfulSyncAt);
  if (elapsed > input.staleThresholdSeconds) {
    return ok(
      kevProjection({
        runtimeEnabled: true,
        implementationStatus: 'available',
        healthStatus: 'stale',
        stale: true,
        staleThresholdSeconds: input.staleThresholdSeconds,
        lastSuccessfulSyncAt: history.value.lastSuccessfulSyncAt,
        lastAttemptAt,
        latestAcceptedCatalogVersion: history.value.catalogVersion,
        latestAcceptedCatalogReleasedAt: history.value.catalogReleasedAt,
        currentEntryCount: history.value.expectedEntryCount,
        lastSafeFailureCode,
        lastFailureAt,
      }),
    );
  }

  const laterFailure =
    lastFailureAt !== null &&
    lastFailureAt.getTime() > history.value.lastSuccessfulSyncAt.getTime();
  if (laterFailure) {
    if (lastSafeFailureCode === null) {
      return err(INTELLIGENCE_STATUS_INCONSISTENT);
    }
    return ok(
      kevProjection({
        runtimeEnabled: true,
        implementationStatus: 'available',
        healthStatus: 'degraded',
        stale: false,
        staleThresholdSeconds: input.staleThresholdSeconds,
        lastSuccessfulSyncAt: history.value.lastSuccessfulSyncAt,
        lastAttemptAt,
        latestAcceptedCatalogVersion: history.value.catalogVersion,
        latestAcceptedCatalogReleasedAt: history.value.catalogReleasedAt,
        currentEntryCount: history.value.expectedEntryCount,
        lastSafeFailureCode,
        lastFailureAt,
      }),
    );
  }

  return ok(
    kevProjection({
      runtimeEnabled: true,
      implementationStatus: 'available',
      healthStatus: 'current',
      stale: false,
      staleThresholdSeconds: input.staleThresholdSeconds,
      lastSuccessfulSyncAt: history.value.lastSuccessfulSyncAt,
      lastAttemptAt,
      latestAcceptedCatalogVersion: history.value.catalogVersion,
      latestAcceptedCatalogReleasedAt: history.value.catalogReleasedAt,
      currentEntryCount: history.value.expectedEntryCount,
      lastSafeFailureCode,
      lastFailureAt,
    }),
  );
}

type AcceptedCatalogHistory = {
  lastSuccessfulSyncAt: Date;
  catalogVersion: string;
  catalogReleasedAt: Date;
  expectedEntryCount: number;
};

function acceptedCatalogHistory(
  snapshot: CisaKevStatusSnapshot,
): Result<AcceptedCatalogHistory | null> {
  const hasPointer = snapshot.activeGenerationId !== null;
  const generation = snapshot.generation;
  if (hasPointer && generation === null) {
    return err(INTELLIGENCE_STATUS_INCONSISTENT);
  }
  if (!hasPointer && generation !== null) {
    return err(INTELLIGENCE_STATUS_INCONSISTENT);
  }
  if (generation === null) {
    if (snapshot.lastSuccessfulSyncAt !== null) {
      return err(INTELLIGENCE_STATUS_INCONSISTENT);
    }
    return ok(null);
  }
  if (generation.state !== 'active') {
    return err(INTELLIGENCE_STATUS_INCONSISTENT);
  }
  if (snapshot.lastSuccessfulSyncAt === null) {
    return err(INTELLIGENCE_STATUS_INCONSISTENT);
  }
  if (generation.catalogVersion === null || generation.catalogVersion.length === 0) {
    return err(INTELLIGENCE_STATUS_INCONSISTENT);
  }
  if (generation.catalogReleasedAt === null) {
    return err(INTELLIGENCE_STATUS_INCONSISTENT);
  }
  if (!isNonNegativeSafeInteger(generation.expectedEntryCount)) {
    return err(INTELLIGENCE_STATUS_INCONSISTENT);
  }
  return ok({
    lastSuccessfulSyncAt: snapshot.lastSuccessfulSyncAt,
    catalogVersion: generation.catalogVersion,
    catalogReleasedAt: generation.catalogReleasedAt,
    expectedEntryCount: generation.expectedEntryCount,
  });
}

function mappedFailure(
  lastFailureCode: string | null,
  lastFailureAt: Date | null,
): Result<{ code: IntelligencePublicFailureCode | null; at: Date | null }> {
  const codeMissing = lastFailureCode === null || lastFailureCode.length === 0;
  if (lastFailureAt === null && codeMissing) {
    return ok({ code: null, at: null });
  }
  if (lastFailureAt === null || codeMissing) {
    return err(INTELLIGENCE_STATUS_INCONSISTENT);
  }
  return ok({
    code: mapInternalFailureCodeToPublic(lastFailureCode),
    at: lastFailureAt,
  });
}

function kevProjection(
  fields: Omit<IntelligenceProviderStatusProjection, 'provider' | 'displayName'>,
): IntelligenceProviderStatusProjection {
  return {
    provider: 'cisa_kev',
    displayName: intelligenceProviderDisplayNames.cisa_kev,
    runtimeEnabled: fields.runtimeEnabled,
    implementationStatus: fields.implementationStatus,
    healthStatus: fields.healthStatus,
    stale: fields.stale,
    staleThresholdSeconds: fields.staleThresholdSeconds,
    lastSuccessfulSyncAt: fields.lastSuccessfulSyncAt,
    lastAttemptAt: fields.lastAttemptAt,
    latestAcceptedCatalogVersion: fields.latestAcceptedCatalogVersion,
    latestAcceptedCatalogReleasedAt: fields.latestAcceptedCatalogReleasedAt,
    currentEntryCount: fields.currentEntryCount,
    lastSafeFailureCode: fields.lastSafeFailureCode,
    lastFailureAt: fields.lastFailureAt,
  };
}
