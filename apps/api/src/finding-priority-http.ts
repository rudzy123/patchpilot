/**
 * Maps priority use-case results onto the closed HTTP envelope.
 * `finding_not_eligible` is a 409 conflict. `priority_policy_unavailable`
 * is a 503 internal. Neither code is added to the global error enum.
 */

import { PERMISSION_DENIED } from '@patchpilot/auth';
import {
  findingPriorityResponseSchema,
  findingRiskCalculationResponseSchema,
  type FindingPriorityResponse,
  type FindingRiskCalculationResponse,
} from '@patchpilot/contracts';
import type {
  AppError,
  CalculateFindingRiskResult,
  ReadControlledFindingPriorityResult,
} from '@patchpilot/domain';

import { FINDING_INTERNAL, FINDING_NOT_FOUND } from './finding-http.js';
import {
  INVALID_REQUEST,
  PRIORITY_CALCULATION_UNAVAILABLE,
  PRIORITY_INSPECTION_UNAVAILABLE,
  PRIORITY_POLICY_UNAVAILABLE,
} from './http-errors.js';

export const PRIORITY_CALCULATION_ROUTE = '/findings/:findingId/risk-calculations';
export const PRIORITY_READ_ROUTE = '/findings/:findingId/priority';

export const FINDING_NOT_ELIGIBLE: AppError = Object.freeze({
  code: 'conflict',
  message: 'The Finding is not eligible for priority calculation.',
});

export {
  PRIORITY_CALCULATION_UNAVAILABLE,
  PRIORITY_INSPECTION_UNAVAILABLE,
  PRIORITY_POLICY_UNAVAILABLE,
};

export type PriorityPublicOutcome =
  | 'calculated'
  | 'already_applied'
  | 'not_calculated'
  | 'found'
  | 'validation'
  | 'unauthorized'
  | 'forbidden'
  | 'not_found'
  | 'finding_not_eligible'
  | 'priority_policy_unavailable'
  | 'rate_limited'
  | 'unavailable'
  | 'internal';

export function translatePriorityCalculation(
  result: CalculateFindingRiskResult,
  findingId: string,
):
  | {
      readonly ok: true;
      readonly statusCode: 200 | 201;
      readonly body: FindingRiskCalculationResponse;
    }
  | { readonly ok: false; readonly error: AppError; readonly outcome: PriorityPublicOutcome } {
  if (result.kind === 'calculated' || result.kind === 'replayed') {
    if (result.calculation.findingId !== findingId) {
      return { ok: false, error: FINDING_NOT_FOUND, outcome: 'not_found' };
    }
    const body = findingRiskCalculationResponseSchema.safeParse({
      schemaVersion: 'finding_risk_calculation_v1',
      status: result.kind === 'calculated' ? 'calculated' : 'already_applied',
      findingId: result.calculation.findingId,
      riskCalculationId: result.calculation.id,
      calculationReason: result.calculation.calculationReason,
    });
    if (!body.success) {
      return {
        ok: false,
        error: PRIORITY_CALCULATION_UNAVAILABLE,
        outcome: 'unavailable',
      };
    }
    return {
      ok: true,
      statusCode: result.kind === 'calculated' ? 201 : 200,
      body: body.data,
    };
  }
  return { ok: false, ...calculationFailure(result.kind) };
}

export function translatePriorityRead(
  result: ReadControlledFindingPriorityResult,
  findingId: string,
):
  | { readonly ok: true; readonly body: FindingPriorityResponse }
  | { readonly ok: false; readonly error: AppError; readonly outcome: PriorityPublicOutcome } {
  if (result.kind === 'not_calculated') {
    if (result.findingId !== findingId) {
      return { ok: false, error: FINDING_NOT_FOUND, outcome: 'not_found' };
    }
    const body = findingPriorityResponseSchema.safeParse({
      schemaVersion: 'finding_priority_v1',
      status: 'not_calculated',
      findingId: result.findingId,
    });
    if (!body.success) {
      return { ok: false, error: PRIORITY_INSPECTION_UNAVAILABLE, outcome: 'unavailable' };
    }
    return { ok: true, body: body.data };
  }
  if (result.kind === 'calculated') {
    if (result.view.findingId !== findingId) {
      return { ok: false, error: FINDING_NOT_FOUND, outcome: 'not_found' };
    }
    const calculation = result.view.calculation;
    const body = findingPriorityResponseSchema.safeParse({
      schemaVersion: 'finding_priority_v1',
      status: 'calculated',
      findingId: result.view.findingId,
      calculation: {
        riskCalculationId: calculation.id,
        calculatedAt: calculation.calculatedAt.toISOString(),
        calculationReason: calculation.calculationReason,
        engineVersion: calculation.calculationEngineVersion,
        riskPolicyId: calculation.riskPolicyId,
        policyKey: calculation.policyKey,
        policyVersion: calculation.policyVersion,
        policyDefinitionSha256: calculation.policyDefinitionSha256,
        priority: calculation.result.priority,
        priorityBand: calculation.result.priorityBand,
        escalationRecommendation: calculation.result.escalationRecommendation,
        escalationReasons: calculation.factors.escalationReasons,
        dueDateRecommendationDays: calculation.result.dueDateRecommendationDays,
        factors: calculation.factors.factors,
        rules: calculation.factors.rules,
      },
      comparability: result.view.comparability,
      inputsChanged: result.view.inputsChanged,
      review: result.view.review,
    });
    if (!body.success) {
      return { ok: false, error: PRIORITY_INSPECTION_UNAVAILABLE, outcome: 'unavailable' };
    }
    return { ok: true, body: body.data };
  }
  return { ok: false, ...readFailure(result.kind) };
}

export function priorityOutcomeForError(error: AppError): PriorityPublicOutcome {
  if (error.message === FINDING_NOT_ELIGIBLE.message) {
    return 'finding_not_eligible';
  }
  if (error.message === PRIORITY_POLICY_UNAVAILABLE.message) {
    return 'priority_policy_unavailable';
  }
  if (
    error.message === PRIORITY_CALCULATION_UNAVAILABLE.message ||
    error.message === PRIORITY_INSPECTION_UNAVAILABLE.message
  ) {
    return 'unavailable';
  }
  switch (error.code) {
    case 'validation':
      return 'validation';
    case 'unauthorized':
      return 'unauthorized';
    case 'forbidden':
      return 'forbidden';
    case 'not_found':
      return 'not_found';
    case 'conflict':
      return 'finding_not_eligible';
    case 'rate_limited':
      return 'rate_limited';
    case 'unprocessable_evidence':
      return 'unavailable';
    case 'internal':
      return 'internal';
  }
}

function calculationFailure(
  kind: Exclude<CalculateFindingRiskResult['kind'], 'calculated' | 'replayed'>,
): {
  readonly error: AppError;
  readonly outcome: PriorityPublicOutcome;
} {
  switch (kind) {
    case 'not_found':
      return { error: FINDING_NOT_FOUND, outcome: 'not_found' };
    case 'ineligible':
      return { error: FINDING_NOT_ELIGIBLE, outcome: 'finding_not_eligible' };
    case 'priority_policy_unavailable':
    case 'builtin_unavailable':
      return { error: PRIORITY_POLICY_UNAVAILABLE, outcome: 'priority_policy_unavailable' };
    case 'unauthorized':
      return { error: PERMISSION_DENIED, outcome: 'forbidden' };
    case 'invalid_command':
      return { error: INVALID_REQUEST, outcome: 'validation' };
    case 'canonical_cve_rejected':
    case 'kev_membership_error':
    case 'kev_mapping_rejected':
    case 'kev_source_rejected':
    case 'override_rejected':
    case 'facts_rejected':
    case 'fact_input_rejected':
    case 'canonical_json_rejected':
    case 'engine_rejected':
    case 'immutable_conflict':
    case 'unavailable':
    case 'internal_failure':
      return { error: PRIORITY_CALCULATION_UNAVAILABLE, outcome: 'unavailable' };
    default:
      return { error: FINDING_INTERNAL, outcome: 'internal' };
  }
}

function readFailure(
  kind: Exclude<ReadControlledFindingPriorityResult['kind'], 'not_calculated' | 'calculated'>,
): {
  readonly error: AppError;
  readonly outcome: PriorityPublicOutcome;
} {
  switch (kind) {
    case 'not_found':
      return { error: FINDING_NOT_FOUND, outcome: 'not_found' };
    case 'priority_policy_unavailable':
      return { error: PRIORITY_POLICY_UNAVAILABLE, outcome: 'priority_policy_unavailable' };
    case 'unauthorized':
      return { error: PERMISSION_DENIED, outcome: 'forbidden' };
    case 'invalid_command':
      return { error: INVALID_REQUEST, outcome: 'validation' };
    case 'unavailable':
    case 'internal_failure':
      return { error: PRIORITY_INSPECTION_UNAVAILABLE, outcome: 'unavailable' };
    default:
      return { error: FINDING_INTERNAL, outcome: 'internal' };
  }
}
