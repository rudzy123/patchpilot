/**
 * API-process composition root for one Product Match candidate page.
 * Route modules receive the bound runtime. They do not import the service
 * factory or the persistence adapter.
 */

import { createProductMatchCandidatePersistence } from '@patchpilot/database/product-match-candidate-persistence';
import {
  createProductMatchCandidateDiscovery,
  type ProductMatchCandidateServiceResult,
} from '@patchpilot/vulnerability-intelligence/product-match-candidates';

export type ProductMatchCandidateRuntimeResult = ProductMatchCandidateServiceResult;

export type ProductMatchCandidateExecuteInput = {
  readonly actor: {
    readonly userId: string;
    readonly sessionId: string;
    readonly organizationId: string;
    readonly membershipId: string;
    readonly role: 'owner' | 'admin' | 'member' | 'viewer';
  };
  readonly assetId: string;
  readonly limit: number;
  readonly cursor: string | null;
};

export type ProductMatchCandidateRuntime = {
  execute(input: ProductMatchCandidateExecuteInput): Promise<ProductMatchCandidateRuntimeResult>;
};

export function composeProductMatchCandidateRuntime(
  client: Parameters<typeof createProductMatchCandidatePersistence>[0],
): ProductMatchCandidateRuntime {
  const application = createProductMatchCandidateDiscovery({
    port: createProductMatchCandidatePersistence(client),
  });
  return {
    execute(input) {
      return application.execute({
        actor: input.actor,
        assetId: input.assetId,
        limit: input.limit,
        cursor: input.cursor,
      });
    },
  };
}

export function denyProductMatchCandidateRuntime(): ProductMatchCandidateRuntime {
  return {
    async execute() {
      return { status: 'authority_required' };
    },
  };
}
