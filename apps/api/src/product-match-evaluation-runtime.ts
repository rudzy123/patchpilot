/**
 * API-process composition root for one deliberate Product Match Evidence
 * evaluation. Route modules receive the bound runtime. They do not import
 * the service factory or the persistence adapter.
 * The HTTP correlation id is transport.correlationId. The service mints a
 * separate operation correlation id.
 */

import { createDeliberateProductMatchEvaluationPersistence } from '@patchpilot/database/deliberate-product-match-evaluation-persistence';
import {
  createDeliberateProductMatchEvaluation,
  type DeliberateProductMatchEvaluationResult,
} from '@patchpilot/vulnerability-intelligence/deliberate-product-match-evaluation';

export type { DeliberateProductMatchEvaluationResult as ProductMatchEvaluationRuntimeResult };

export type ProductMatchEvaluationExecuteInput = {
  readonly actor: {
    readonly userId: string;
    readonly sessionId: string;
    readonly organizationId: string;
    readonly membershipId: string;
    readonly role: 'owner' | 'admin' | 'member' | 'viewer';
  };
  readonly assetId: string;
  readonly advisoryRevisionId: string;
  readonly requestId: string;
  readonly correlationId: string;
};

export type ProductMatchEvaluationRuntime = {
  execute(
    input: ProductMatchEvaluationExecuteInput,
  ): Promise<DeliberateProductMatchEvaluationResult>;
};

export function bindProductMatchEvaluationRuntime(
  execute: (input: unknown) => Promise<DeliberateProductMatchEvaluationResult>,
): ProductMatchEvaluationRuntime {
  return {
    execute(input) {
      return execute({
        actor: {
          userId: input.actor.userId,
          sessionId: input.actor.sessionId,
          organizationId: input.actor.organizationId,
          membershipId: input.actor.membershipId,
          role: input.actor.role,
        },
        request: {
          assetId: input.assetId,
          advisoryRevisionId: input.advisoryRevisionId,
        },
        transport: {
          requestId: input.requestId,
          correlationId: input.correlationId,
        },
      });
    },
  };
}

export function composeProductMatchEvaluationRuntime(
  client: Parameters<typeof createDeliberateProductMatchEvaluationPersistence>[0],
): ProductMatchEvaluationRuntime {
  const application = createDeliberateProductMatchEvaluation({
    port: createDeliberateProductMatchEvaluationPersistence(client),
  });
  return bindProductMatchEvaluationRuntime((input) => application.execute(input));
}

export function denyProductMatchEvaluationRuntime(): ProductMatchEvaluationRuntime {
  return {
    async execute() {
      return { status: 'authority_required' };
    },
  };
}
