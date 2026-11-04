/**
 * HTTP contract for one owner Product Match candidate page.
 * The asset id stays on the path. Extra keys, including a CVE identifier, are rejected.
 */

import { z } from 'zod';

export const PRODUCT_MATCH_CANDIDATES_SCHEMA_VERSION = 'product_match_candidates_v1' as const;

const packageText = z.string().min(1).max(214);

export const productMatchCandidateSchema = z.strictObject({
  advisoryRevisionId: z.uuid(),
  ecosystem: z.literal('npm'),
  packageNamespace: packageText.nullable(),
  packageName: packageText,
  matchedOccurrenceCount: z.number().int().min(1),
  evaluationState: z.enum(['not_evaluated', 'evaluated']),
});

export const productMatchCandidatesResponseSchema = z.strictObject({
  schemaVersion: z.literal(PRODUCT_MATCH_CANDIDATES_SCHEMA_VERSION),
  assetId: z.uuid(),
  ingestionId: z.uuid().nullable(),
  candidates: z.array(productMatchCandidateSchema).max(20),
  nextCursor: z.string().min(1).max(2048).nullable(),
});

export type ProductMatchCandidate = z.infer<typeof productMatchCandidateSchema>;

export type ProductMatchCandidatesResponse = z.infer<typeof productMatchCandidatesResponseSchema>;
