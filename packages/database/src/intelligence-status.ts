import type {
  IntelligenceProviderStatusReadPort,
  IntelligenceStatusReadResult,
  KevGenerationState,
} from '@patchpilot/domain';

import type { PrismaClientLike } from './guards.js';

export function createIntelligenceStatusReader(
  client: PrismaClientLike,
): IntelligenceProviderStatusReadPort {
  return new PrismaIntelligenceStatusReader(client);
}

class PrismaIntelligenceStatusReader implements IntelligenceProviderStatusReadPort {
  public constructor(private readonly client: PrismaClientLike) {}

  public async loadCisaKevStatus(): Promise<IntelligenceStatusReadResult> {
    try {
      const source = await this.client.intelligenceSource.findUnique({
        where: { providerKey: 'cisa_kev' },
        select: {
          state: true,
          lastSuccessfulSyncAt: true,
          lastAttemptAt: true,
          lastFailureAt: true,
          lastFailureCode: true,
          activeGenerationId: true,
          activeGeneration: {
            select: {
              state: true,
              catalogVersion: true,
              catalogReleasedAt: true,
              expectedEntryCount: true,
            },
          },
        },
      });
      if (source === null) {
        return { kind: 'missing_source' };
      }
      if (source.activeGenerationId !== null && source.activeGeneration === null) {
        return { kind: 'inconsistent' };
      }
      return {
        kind: 'found',
        snapshot: {
          sourceState: source.state,
          lastSuccessfulSyncAt: source.lastSuccessfulSyncAt,
          lastAttemptAt: source.lastAttemptAt,
          lastFailureAt: source.lastFailureAt,
          lastFailureCode: source.lastFailureCode,
          activeGenerationId: source.activeGenerationId,
          generation:
            source.activeGeneration === null
              ? null
              : {
                  state: source.activeGeneration.state as KevGenerationState,
                  catalogVersion: source.activeGeneration.catalogVersion,
                  catalogReleasedAt: source.activeGeneration.catalogReleasedAt,
                  expectedEntryCount: source.activeGeneration.expectedEntryCount,
                },
        },
      };
    } catch {
      return { kind: 'unavailable' };
    }
  }
}
