import { describe, expect, it } from 'vitest';

import { assetIdParamSchema } from './assets.js';
import {
  DELIBERATE_PRODUCT_MATCH_EVALUATION_RESPONSE_SCHEMA_VERSION,
  deliberateProductMatchEvaluationRequestSchema,
  deliberateProductMatchEvaluationResponseSchema,
} from './product-match-evaluation.js';

const ASSET = '44444444-4444-4444-8444-444444444444';
const REVISION = '55555555-5555-4555-8555-555555555555';
const INGESTION = '66666666-6666-4666-8666-666666666666';

function response(patch: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schemaVersion: DELIBERATE_PRODUCT_MATCH_EVALUATION_RESPONSE_SCHEMA_VERSION,
    status: 'evaluated',
    assetId: ASSET,
    advisoryRevisionId: REVISION,
    ingestionId: INGESTION,
    selectedCount: 3,
    evaluatedCount: 2,
    insertedCount: 2,
    replayedCount: 0,
    skippedCount: 1,
    skippedByReason: { version_not_known: 1, version_unrepresentable: 0 },
    outcomeCounts: { affected: 1, unaffected: 1, unknown: 0 },
    findingCreation: 'unavailable',
    ...patch,
  };
}

describe('deliberate product match evaluation HTTP contract', () => {
  it('accepts one advisory revision and the same UUID form as an asset id', () => {
    expect(
      deliberateProductMatchEvaluationRequestSchema.parse({ advisoryRevisionId: REVISION }),
    ).toEqual({ advisoryRevisionId: REVISION });
    expect(assetIdParamSchema.safeParse({ assetId: REVISION }).success).toBe(true);
    expect(
      deliberateProductMatchEvaluationRequestSchema.safeParse({ advisoryRevisionId: 'not-a-uuid' })
        .success,
    ).toBe(assetIdParamSchema.safeParse({ assetId: 'not-a-uuid' }).success);
    for (const extra of ['organizationId', 'assetId', 'ingestionId', 'explicitVersions']) {
      expect(
        deliberateProductMatchEvaluationRequestSchema.safeParse({
          advisoryRevisionId: REVISION,
          [extra]: REVISION,
        }).success,
      ).toBe(false);
    }
  });

  it('publishes the count summary and rejects inconsistent or expanded bodies', () => {
    expect(deliberateProductMatchEvaluationResponseSchema.parse(response())).toMatchObject({
      schemaVersion: 'deliberate_product_match_evaluation_response_v1',
      findingCreation: 'unavailable',
    });
    expect(
      deliberateProductMatchEvaluationResponseSchema.safeParse(
        response({
          status: 'already_applied',
          selectedCount: 2,
          evaluatedCount: 2,
          insertedCount: 0,
          replayedCount: 2,
          skippedCount: 0,
          skippedByReason: { version_not_known: 0, version_unrepresentable: 0 },
          outcomeCounts: { affected: 2, unaffected: 0, unknown: 0 },
        }),
      ).success,
    ).toBe(true);
    expect(
      deliberateProductMatchEvaluationResponseSchema.safeParse(
        response({
          status: 'no_relevant_occurrence',
          selectedCount: 0,
          evaluatedCount: 0,
          insertedCount: 0,
          replayedCount: 0,
          skippedCount: 0,
          skippedByReason: { version_not_known: 0, version_unrepresentable: 0 },
          outcomeCounts: { affected: 0, unaffected: 0, unknown: 0 },
        }),
      ).success,
    ).toBe(true);
    expect(
      deliberateProductMatchEvaluationResponseSchema.safeParse(
        response({
          status: 'no_evaluable_occurrence',
          selectedCount: 1,
          evaluatedCount: 0,
          insertedCount: 0,
          replayedCount: 0,
          skippedCount: 1,
          skippedByReason: { version_not_known: 1, version_unrepresentable: 0 },
          outcomeCounts: { affected: 0, unaffected: 0, unknown: 0 },
        }),
      ).success,
    ).toBe(true);
    expect(
      deliberateProductMatchEvaluationResponseSchema.safeParse(
        response({ insertedCount: 0, replayedCount: 2 }),
      ).success,
    ).toBe(false);
    expect(
      deliberateProductMatchEvaluationResponseSchema.safeParse(response({ selectedCount: 17 }))
        .success,
    ).toBe(false);
    expect(
      deliberateProductMatchEvaluationResponseSchema.safeParse(
        response({ findingCreation: 'available' }),
      ).success,
    ).toBe(false);
    expect(
      deliberateProductMatchEvaluationResponseSchema.safeParse(
        response({ matchEvidenceId: INGESTION }),
      ).success,
    ).toBe(false);
  });
});
