import { describe, expect, it } from 'vitest';

import { deliberateProductMatchEvaluationRequestSchema } from './product-match-evaluation.js';
import {
  PRODUCT_MATCH_CANDIDATES_SCHEMA_VERSION,
  productMatchCandidatesResponseSchema,
} from './product-match-candidates.js';

const ASSET = '44444444-4444-4444-8444-444444444444';
const INGESTION = '66666666-6666-4666-8666-666666666666';
const REVISION = '77777777-7777-4777-8777-777777777777';

function page(patch: Record<string, unknown> = {}) {
  return {
    schemaVersion: PRODUCT_MATCH_CANDIDATES_SCHEMA_VERSION,
    assetId: ASSET,
    ingestionId: INGESTION,
    candidates: [
      {
        advisoryRevisionId: REVISION,
        ecosystem: 'npm',
        packageNamespace: null,
        packageName: 'reviewed-npm-widget',
        matchedOccurrenceCount: 2,
        evaluationState: 'not_evaluated',
      },
    ],
    nextCursor: null,
    ...patch,
  };
}

describe('product match candidate contract', () => {
  it('accepts the allowlisted page and rejects a CVE identifier', () => {
    expect(productMatchCandidatesResponseSchema.parse(page())).toMatchObject({
      schemaVersion: PRODUCT_MATCH_CANDIDATES_SCHEMA_VERSION,
      candidates: [{ advisoryRevisionId: REVISION }],
    });
    const candidate = page().candidates[0];
    expect(
      productMatchCandidatesResponseSchema.safeParse(
        page({
          candidates: [{ ...candidate, cveId: 'CVE-2024-9999' }],
        }),
      ).success,
    ).toBe(false);
    expect(
      productMatchCandidatesResponseSchema.safeParse(page({ osvId: 'GHSA-secret' })).success,
    ).toBe(false);
  });

  it('keeps the evaluation request limited to the advisory revision id', () => {
    expect(
      deliberateProductMatchEvaluationRequestSchema.parse({ advisoryRevisionId: REVISION }),
    ).toEqual({ advisoryRevisionId: REVISION });
    expect(
      deliberateProductMatchEvaluationRequestSchema.safeParse({
        advisoryRevisionId: REVISION,
        ingestionId: INGESTION,
      }).success,
    ).toBe(false);
  });
});
