/**
 * Public HTTP mapping for one deliberate Product Match Evidence evaluation.
 * Internal statuses stay out of the response body. The count summary is the
 * only success payload.
 */

import { PERMISSION_DENIED } from '@patchpilot/auth';
import type { AppError } from '@patchpilot/domain';
import {
  deliberateProductMatchEvaluationResponseSchema,
  type DeliberateProductMatchEvaluationResponse,
} from '@patchpilot/contracts';

import { INVALID_REQUEST, PRODUCT_MATCH_EVALUATION_UNAVAILABLE } from './http-errors.js';

export const PRODUCT_MATCH_EVALUATION_NOT_FOUND: AppError = Object.freeze({
  code: 'not_found',
  message: 'Not found.',
});

export const PRODUCT_MATCH_EVALUATION_ADVISORY_UNPROCESSABLE: AppError = Object.freeze({
  code: 'unprocessable_evidence',
  message: 'The advisory revision cannot be evaluated.',
});

export const PRODUCT_MATCH_EVALUATION_INGESTION_UNPROCESSABLE: AppError = Object.freeze({
  code: 'unprocessable_evidence',
  message: 'The asset has no evaluable ingestion.',
});

export const PRODUCT_MATCH_EVALUATION_CAPACITY_EXCEEDED: AppError = Object.freeze({
  code: 'unprocessable_evidence',
  message: 'The asset exceeds the evaluation occurrence limit.',
});

export const PRODUCT_MATCH_EVALUATION_CONFLICT: AppError = Object.freeze({
  code: 'conflict',
  message: 'The request conflicts with stored evidence.',
});

export const PRODUCT_MATCH_EVALUATION_INTERNAL: AppError = Object.freeze({
  code: 'internal',
  message: 'An internal error occurred.',
});

export const PRODUCT_MATCH_EVALUATION_LOG_OUTCOMES = [
  'evaluated',
  'already_applied',
  'no_relevant_occurrence',
  'no_evaluable_occurrence',
  'invalid_command',
  'unauthenticated',
  'forbidden',
  'authority_required',
  'authority_rejected',
  'not_found',
  'advisory_not_eligible',
  'no_successful_ingestion',
  'ingestion_not_evaluable',
  'capacity_exceeded',
  'immutable_conflict',
  'malformed_persisted_state',
  'transaction_aborted',
  'internal_failure',
  'timeout',
  'database_unavailable',
  'rate_limited',
  'unavailable',
] as const;

export type ProductMatchEvaluationLogOutcome =
  (typeof PRODUCT_MATCH_EVALUATION_LOG_OUTCOMES)[number];

const RESULT_LOG_OUTCOMES: Readonly<Record<string, ProductMatchEvaluationLogOutcome | undefined>> =
  Object.freeze({
    evaluated: 'evaluated',
    already_applied: 'already_applied',
    no_relevant_occurrence: 'no_relevant_occurrence',
    no_evaluable_occurrence: 'no_evaluable_occurrence',
    invalid_command: 'invalid_command',
    authority_required: 'authority_required',
    authority_rejected: 'authority_rejected',
    not_found: 'not_found',
    advisory_not_eligible: 'advisory_not_eligible',
    no_successful_ingestion: 'no_successful_ingestion',
    ingestion_not_evaluable: 'ingestion_not_evaluable',
    capacity_exceeded: 'capacity_exceeded',
    immutable_conflict: 'immutable_conflict',
    malformed_persisted_state: 'malformed_persisted_state',
    transaction_aborted: 'transaction_aborted',
    internal_failure: 'internal_failure',
    timeout: 'timeout',
    database_unavailable: 'database_unavailable',
  });

export function productMatchEvaluationResultLogOutcome(
  status: string,
): ProductMatchEvaluationLogOutcome {
  return RESULT_LOG_OUTCOMES[status] ?? 'internal_failure';
}

export function productMatchEvaluationFailureError(status: string): AppError {
  switch (status) {
    case 'invalid_command':
      return INVALID_REQUEST;
    case 'authority_required':
    case 'authority_rejected':
      return PERMISSION_DENIED;
    case 'not_found':
      return PRODUCT_MATCH_EVALUATION_NOT_FOUND;
    case 'advisory_not_eligible':
      return PRODUCT_MATCH_EVALUATION_ADVISORY_UNPROCESSABLE;
    case 'no_successful_ingestion':
    case 'ingestion_not_evaluable':
      return PRODUCT_MATCH_EVALUATION_INGESTION_UNPROCESSABLE;
    case 'capacity_exceeded':
      return PRODUCT_MATCH_EVALUATION_CAPACITY_EXCEEDED;
    case 'immutable_conflict':
      return PRODUCT_MATCH_EVALUATION_CONFLICT;
    case 'timeout':
    case 'database_unavailable':
      return PRODUCT_MATCH_EVALUATION_UNAVAILABLE;
    default:
      return PRODUCT_MATCH_EVALUATION_INTERNAL;
  }
}

export function publishProductMatchEvaluation(
  result: unknown,
  expected: { readonly assetId: string; readonly advisoryRevisionId: string },
): {
  readonly statusCode: 200 | 201;
  readonly body: DeliberateProductMatchEvaluationResponse;
} | null {
  if (typeof result !== 'object' || result === null) {
    return null;
  }
  const parsed = deliberateProductMatchEvaluationResponseSchema.safeParse({
    schemaVersion: readOwn(result, 'schemaVersion'),
    status: readOwn(result, 'status'),
    assetId: readOwn(result, 'assetId'),
    advisoryRevisionId: readOwn(result, 'advisoryRevisionId'),
    ingestionId: readOwn(result, 'ingestionId'),
    selectedCount: readOwn(result, 'selectedCount'),
    evaluatedCount: readOwn(result, 'evaluatedCount'),
    insertedCount: readOwn(result, 'insertedCount'),
    replayedCount: readOwn(result, 'replayedCount'),
    skippedCount: readOwn(result, 'skippedCount'),
    skippedByReason: readOwn(result, 'skippedByReason'),
    outcomeCounts: readOwn(result, 'outcomeCounts'),
    findingCreation: readOwn(result, 'findingCreation'),
  });
  if (
    !parsed.success ||
    parsed.data.assetId !== expected.assetId ||
    parsed.data.advisoryRevisionId !== expected.advisoryRevisionId
  ) {
    return null;
  }
  return {
    statusCode: parsed.data.status === 'evaluated' ? 201 : 200,
    body: parsed.data,
  };
}

function readOwn(value: object, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(value, key);
  if (descriptor === undefined || descriptor.get !== undefined || descriptor.set !== undefined) {
    return undefined;
  }
  return descriptor.value;
}
