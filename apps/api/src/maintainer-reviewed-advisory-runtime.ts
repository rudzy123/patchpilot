/**
 * API-process composition root for local advisory submission and independent
 * approval. Route modules receive this boundary. They do not import Prisma,
 * persistence adapters, or the capability issuer.
 */

import { createMaintainerReviewedAdvisoryMutationApplication } from '@patchpilot/database/maintainer-reviewed-advisory-mutation';

export type AdvisoryMutationResult = {
  readonly outcome: string;
  readonly revisionId?: string;
};

export type MaintainerReviewedAdvisorySubmissionExecuteInput = {
  readonly trustedSubmitterUserId: string;
  readonly document: unknown;
};

export type MaintainerReviewedAdvisoryApprovalExecuteInput = {
  readonly trustedReviewerUserId: string;
  readonly advisoryRevisionId: string;
  readonly correlationId: string;
};

export type MaintainerReviewedAdvisoryRuntime = {
  readonly submission: {
    execute(
      input: MaintainerReviewedAdvisorySubmissionExecuteInput,
    ): Promise<AdvisoryMutationResult>;
  };
  readonly approval: {
    execute(input: MaintainerReviewedAdvisoryApprovalExecuteInput): Promise<AdvisoryMutationResult>;
  };
};

export function composeMaintainerReviewedAdvisoryRuntime(
  client: Parameters<typeof createMaintainerReviewedAdvisoryMutationApplication>[0],
): MaintainerReviewedAdvisoryRuntime {
  const application = createMaintainerReviewedAdvisoryMutationApplication(client);
  return {
    submission: {
      execute(input) {
        return application.submit(input);
      },
    },
    approval: {
      execute(input) {
        return application.approve(input);
      },
    },
  };
}

export function denyMaintainerReviewedAdvisoryRuntime(): MaintainerReviewedAdvisoryRuntime {
  return {
    submission: {
      async execute() {
        return { outcome: 'authority_required' };
      },
    },
    approval: {
      async execute() {
        return { outcome: 'authority_required' };
      },
    },
  };
}
