/**
 * API-process application boundary for one local submission and one
 * independent approval. Route handlers do not import this module.
 * The committed parsers and persistence adapters remain the authority.
 * This module does not issue a capability, evaluate a product, contact a
 * provider, or write a Finding.
 */

import type { PrismaClient } from '@prisma/client';
import {
  parseMaintainerReviewedAdvisoryApprovalApplicationCommand,
  prepareMaintainerReviewedAdvisoryApproval,
  toMaintainerReviewedAdvisoryApprovalPersistenceCommand,
  type MaintainerReviewedAdvisoryApprovalResult,
} from '@patchpilot/vulnerability-intelligence/maintainer-reviewed-advisory-approval-application';
import {
  parseMaintainerReviewedAdvisorySubmissionCommand,
  prepareMaintainerReviewedAdvisorySubmission,
  toMaintainerReviewedAdvisorySubmissionPersistenceCommand,
  type MaintainerReviewedAdvisorySubmissionResult,
} from '@patchpilot/vulnerability-intelligence/maintainer-reviewed-advisory-submission';

import { createMaintainerReviewedAdvisoryApprovalApplicationPersistence } from './maintainer-reviewed-advisory-approval-application-persistence.js';
import { createMaintainerReviewedAdvisorySubmissionPersistence } from './maintainer-reviewed-advisory-submission-persistence.js';

export type MaintainerReviewedAdvisorySubmissionExecuteInput = {
  readonly trustedSubmitterUserId: string;
  readonly document: unknown;
};

export type MaintainerReviewedAdvisoryApprovalExecuteInput = {
  readonly trustedReviewerUserId: string;
  readonly advisoryRevisionId: string;
  readonly correlationId: string;
};

export type MaintainerReviewedAdvisoryMutationApplication = {
  readonly submit: (
    input: MaintainerReviewedAdvisorySubmissionExecuteInput,
  ) => Promise<MaintainerReviewedAdvisorySubmissionResult>;
  readonly approve: (
    input: MaintainerReviewedAdvisoryApprovalExecuteInput,
  ) => Promise<MaintainerReviewedAdvisoryApprovalResult>;
};

export function createMaintainerReviewedAdvisoryMutationApplication(
  client: PrismaClient,
): MaintainerReviewedAdvisoryMutationApplication {
  const submission = createMaintainerReviewedAdvisorySubmissionPersistence(client);
  const approval = createMaintainerReviewedAdvisoryApprovalApplicationPersistence(client);
  return {
    async submit(input) {
      const parsed = parseMaintainerReviewedAdvisorySubmissionCommand(input.document);
      if (!parsed.ok) {
        return { outcome: parsed.outcome };
      }
      const prepared = prepareMaintainerReviewedAdvisorySubmission(
        input.trustedSubmitterUserId,
        parsed.command,
      );
      if (!prepared.ok) {
        return { outcome: prepared.outcome };
      }
      return submission.submit(
        toMaintainerReviewedAdvisorySubmissionPersistenceCommand(prepared.prepared),
      );
    },
    async approve(input) {
      const parsed = parseMaintainerReviewedAdvisoryApprovalApplicationCommand({
        advisoryRevisionId: input.advisoryRevisionId,
        correlationId: input.correlationId,
      });
      if (!parsed.ok) {
        return { outcome: parsed.outcome };
      }
      const prepared = prepareMaintainerReviewedAdvisoryApproval(
        input.trustedReviewerUserId,
        parsed.command,
      );
      if (!prepared.ok) {
        return { outcome: prepared.outcome };
      }
      return approval.approve(
        toMaintainerReviewedAdvisoryApprovalPersistenceCommand(prepared.prepared),
      );
    },
  };
}
