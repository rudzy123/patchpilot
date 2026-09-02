import { err, ok, type Result } from '../result.js';
import {
  INTELLIGENCE_PROVIDER_NOT_FOUND,
  INTELLIGENCE_STATUS_INCONSISTENT,
  INTELLIGENCE_STATUS_UNAVAILABLE,
} from './errors.js';
import type { IntelligenceProvider } from './constants.js';
import {
  authorizeIntelligenceRead,
  deriveCisaKevProviderStatus,
  intelligenceEnablementMismatches,
  synthesizeDeferredOsvStatus,
  type CisaKevStatusSnapshot,
  type IntelligenceProviderStatusProjection,
  type IntelligenceStatusActor,
} from './provider-status.js';

export type IntelligenceStatusReadResult =
  | { kind: 'found'; snapshot: CisaKevStatusSnapshot }
  | { kind: 'missing_source' }
  | { kind: 'inconsistent' }
  | { kind: 'unavailable' };

export type IntelligenceProviderStatusReadPort = {
  loadCisaKevStatus(): Promise<IntelligenceStatusReadResult>;
};

export type IntelligenceStatusQueryLogger = {
  warn(bindings: Record<string, string | number | boolean | null>, message: string): void;
};

export type IntelligenceProviderStatusList = {
  providers: readonly [IntelligenceProviderStatusProjection, IntelligenceProviderStatusProjection];
};

export type IntelligenceStatusQueryDependencies = {
  status: IntelligenceProviderStatusReadPort;
  kevEnabled: boolean;
  staleThresholdSeconds: number;
  now: () => Date;
  logger?: IntelligenceStatusQueryLogger;
};

export type GetIntelligenceProviderStatusInput = {
  actor: IntelligenceStatusActor;
  provider: IntelligenceProvider;
};

export type ListIntelligenceProviderStatusInput = {
  actor: IntelligenceStatusActor;
};

export function createIntelligenceStatusQueryUseCase(
  dependencies: IntelligenceStatusQueryDependencies,
) {
  return {
    get(
      input: GetIntelligenceProviderStatusInput,
    ): Promise<Result<IntelligenceProviderStatusProjection>> {
      return executeGetProviderStatus(dependencies, input);
    },
    list(
      input: ListIntelligenceProviderStatusInput,
    ): Promise<Result<IntelligenceProviderStatusList>> {
      return executeListProviderStatus(dependencies, input);
    },
  };
}

async function executeGetProviderStatus(
  dependencies: IntelligenceStatusQueryDependencies,
  input: GetIntelligenceProviderStatusInput,
): Promise<Result<IntelligenceProviderStatusProjection>> {
  const authorized = authorizeIntelligenceRead(input.actor);
  if (!authorized.ok) {
    return authorized;
  }

  if (input.provider === 'osv') {
    return ok(synthesizeDeferredOsvStatus(dependencies.staleThresholdSeconds));
  }
  if (input.provider !== 'cisa_kev') {
    return err(INTELLIGENCE_PROVIDER_NOT_FOUND);
  }

  return loadDerivedKevStatus(dependencies);
}

async function executeListProviderStatus(
  dependencies: IntelligenceStatusQueryDependencies,
  input: ListIntelligenceProviderStatusInput,
): Promise<Result<IntelligenceProviderStatusList>> {
  const authorized = authorizeIntelligenceRead(input.actor);
  if (!authorized.ok) {
    return authorized;
  }

  const kev = await loadDerivedKevStatus(dependencies);
  if (!kev.ok) {
    return kev;
  }

  return ok({
    providers: [kev.value, synthesizeDeferredOsvStatus(dependencies.staleThresholdSeconds)],
  });
}

async function loadDerivedKevStatus(
  dependencies: IntelligenceStatusQueryDependencies,
): Promise<Result<IntelligenceProviderStatusProjection>> {
  let loaded: IntelligenceStatusReadResult;
  try {
    loaded = await dependencies.status.loadCisaKevStatus();
  } catch {
    return err(INTELLIGENCE_STATUS_UNAVAILABLE);
  }

  if (loaded.kind === 'missing_source' || loaded.kind === 'unavailable') {
    return err(INTELLIGENCE_STATUS_UNAVAILABLE);
  }
  if (loaded.kind === 'inconsistent') {
    return err(INTELLIGENCE_STATUS_INCONSISTENT);
  }

  if (
    dependencies.logger !== undefined &&
    intelligenceEnablementMismatches(dependencies.kevEnabled, loaded.snapshot.sourceState)
  ) {
    dependencies.logger.warn(
      { provider: 'cisa_kev' },
      'KEV runtime enablement differs from persisted source state',
    );
  }

  return deriveCisaKevProviderStatus({
    runtimeEnabled: dependencies.kevEnabled,
    staleThresholdSeconds: dependencies.staleThresholdSeconds,
    now: dependencies.now(),
    snapshot: loaded.snapshot,
  });
}
