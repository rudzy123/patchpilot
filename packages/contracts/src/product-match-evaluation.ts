/**
 * HTTP contract for one owner Product Match Evidence evaluation.
 * The asset id stays on the path and uses the asset route UUID validator.
 * Count relationships are part of the public response. Extra keys are rejected.
 */

import { z } from 'zod';

export const DELIBERATE_PRODUCT_MATCH_EVALUATION_RESPONSE_SCHEMA_VERSION =
  'deliberate_product_match_evaluation_response_v1' as const;

const OCCURRENCE_CAP = 16;

const countSchema = z.number().int().min(0).max(OCCURRENCE_CAP);

const completionStatusSchema = z.enum([
  'evaluated',
  'already_applied',
  'no_relevant_occurrence',
  'no_evaluable_occurrence',
]);

type ConsistentEvaluationResponse = {
  readonly status:
    'evaluated' | 'already_applied' | 'no_relevant_occurrence' | 'no_evaluable_occurrence';
  readonly selectedCount: number;
  readonly evaluatedCount: number;
  readonly insertedCount: number;
  readonly replayedCount: number;
  readonly skippedCount: number;
  readonly skippedByReason: {
    readonly version_not_known: number;
    readonly version_unrepresentable: number;
  };
  readonly outcomeCounts: {
    readonly affected: number;
    readonly unaffected: number;
    readonly unknown: number;
  };
};

export const deliberateProductMatchEvaluationRequestSchema = z.strictObject({
  advisoryRevisionId: z.uuid(),
});

export const deliberateProductMatchEvaluationResponseSchema = z
  .strictObject({
    schemaVersion: z.literal(DELIBERATE_PRODUCT_MATCH_EVALUATION_RESPONSE_SCHEMA_VERSION),
    status: completionStatusSchema,
    assetId: z.uuid(),
    advisoryRevisionId: z.uuid(),
    ingestionId: z.uuid(),
    selectedCount: countSchema,
    evaluatedCount: countSchema,
    insertedCount: countSchema,
    replayedCount: countSchema,
    skippedCount: countSchema,
    skippedByReason: z.strictObject({
      version_not_known: countSchema,
      version_unrepresentable: countSchema,
    }),
    outcomeCounts: z.strictObject({
      affected: countSchema,
      unaffected: countSchema,
      unknown: countSchema,
    }),
    findingCreation: z.literal('unavailable'),
  })
  .superRefine((body, context) => {
    if (!responseIsConsistent(body)) {
      context.addIssue({
        code: 'custom',
        message: 'inconsistent evaluation response',
      });
    }
  });

export type DeliberateProductMatchEvaluationRequest = z.infer<
  typeof deliberateProductMatchEvaluationRequestSchema
>;

export type DeliberateProductMatchEvaluationResponse = z.infer<
  typeof deliberateProductMatchEvaluationResponseSchema
>;

function responseIsConsistent(body: ConsistentEvaluationResponse): boolean {
  const outcomes =
    body.outcomeCounts.affected + body.outcomeCounts.unaffected + body.outcomeCounts.unknown;
  const skips =
    body.skippedByReason.version_not_known + body.skippedByReason.version_unrepresentable;
  if (
    body.selectedCount !== body.evaluatedCount + body.skippedCount ||
    body.evaluatedCount !== body.insertedCount + body.replayedCount ||
    body.evaluatedCount !== outcomes ||
    body.skippedCount !== skips
  ) {
    return false;
  }
  switch (body.status) {
    case 'evaluated':
      return body.insertedCount >= 1;
    case 'already_applied':
      return body.insertedCount === 0 && body.replayedCount >= 1;
    case 'no_relevant_occurrence':
      return (
        body.selectedCount === 0 &&
        body.evaluatedCount === 0 &&
        body.skippedCount === 0 &&
        body.insertedCount === 0 &&
        body.replayedCount === 0
      );
    case 'no_evaluable_occurrence':
      return (
        body.selectedCount >= 1 &&
        body.evaluatedCount === 0 &&
        body.skippedCount === body.selectedCount &&
        body.insertedCount === 0 &&
        body.replayedCount === 0
      );
    default: {
      const exhaustive: never = body.status;
      return exhaustive;
    }
  }
}
