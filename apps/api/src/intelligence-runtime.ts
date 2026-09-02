import {
  createIntelligenceStatusQueryUseCase,
  type IntelligenceProviderStatusReadPort,
  type IntelligenceStatusQueryLogger,
} from '@patchpilot/domain';

export type IntelligenceRuntime = {
  query: ReturnType<typeof createIntelligenceStatusQueryUseCase>;
};

export function createIntelligenceRuntime(dependencies: {
  status: IntelligenceProviderStatusReadPort;
  kevEnabled: boolean;
  staleThresholdSeconds: number;
  now: () => Date;
  logger?: IntelligenceStatusQueryLogger;
}): IntelligenceRuntime {
  return {
    query: createIntelligenceStatusQueryUseCase({
      status: dependencies.status,
      kevEnabled: dependencies.kevEnabled,
      staleThresholdSeconds: dependencies.staleThresholdSeconds,
      now: dependencies.now,
      ...(dependencies.logger === undefined ? {} : { logger: dependencies.logger }),
    }),
  };
}
