import {
  findingPriorityResponseSchema,
  findingRiskCalculationResponseSchema,
  priorityReviewResponseSchema,
  type FindingPriorityResponse,
  type FindingRiskCalculationResponse,
  type PriorityReviewResponse,
} from '@patchpilot/contracts';

export const PRIORITY_HEADING = 'Priority';
export const PRIORITY_NOT_CALCULATED = 'Not calculated';
export const PRIORITY_LOADING = 'Loading priority.';
export const PRIORITY_UNAVAILABLE = 'Priority is temporarily unavailable.';
export const PRIORITY_POLICY_UNAVAILABLE = 'Priority policy is unavailable.';
export const PRIORITY_NOT_FOUND = 'Not found.';
export const PRIORITY_FORBIDDEN = 'Permission denied.';
export const PRIORITY_RATE_LIMITED = 'Too many requests. Try again later.';
export const PRIORITY_CALCULATE = 'Calculate priority';
export const PRIORITY_CALCULATING = 'Calculating priority.';
export const PRIORITY_REFERENCE = 'Comparable with the published built-in policy.';
export const PRIORITY_INCOMPARABLE =
  'Recalculation is required before this result can be compared with the published built-in policy.';
export const PRIORITY_DUE_DATE_LABEL = 'Due-date recommendation days';
export const PRIORITY_DUE_DATE_NOTE = 'This recommendation does not set a Finding due date.';
export const PRIORITY_INPUTS_NONE = 'No stored-identifier change was detected.';
export const PRIORITY_INPUTS_DETECTED =
  'A stored identifier changed after this calculation. A later calculation may still replay.';
export const PRIORITY_REVIEW_NOTE =
  'A review does not change the calculated priority or the queue order.';
export const PRIORITY_REVIEW_HEADING = 'Priority review';
export const PRIORITY_REVIEW_RECORDED = 'Review recorded.';
export const PRIORITY_REVIEW_STALE =
  'The review is no longer current. Reload the priority before trying again.';
export const PRIORITY_REVIEW_UNAVAILABLE = 'Priority review is temporarily unavailable.';

export function readFindingPriority(
  value: unknown,
  findingId: string,
): FindingPriorityResponse | null {
  const parsed = findingPriorityResponseSchema.safeParse(value);
  if (!parsed.success || parsed.data.findingId !== findingId) {
    return null;
  }
  return parsed.data;
}

export function readFindingRiskCalculation(
  value: unknown,
  findingId: string,
): FindingRiskCalculationResponse | null {
  const parsed = findingRiskCalculationResponseSchema.safeParse(value);
  if (!parsed.success || parsed.data.findingId !== findingId) {
    return null;
  }
  return parsed.data;
}

export function readPriorityReview(
  value: unknown,
  findingId: string,
  riskCalculationId: string,
): PriorityReviewResponse | null {
  const parsed = priorityReviewResponseSchema.safeParse(value);
  if (
    !parsed.success ||
    parsed.data.findingId !== findingId ||
    parsed.data.riskCalculationId !== riskCalculationId
  ) {
    return null;
  }
  return parsed.data;
}

export function priorityReviewMarkerLabel(review: {
  readonly status: string;
  readonly correctedBand?: string;
  readonly expiresAt?: string;
}): string {
  if (review.status === 'none') {
    return 'No priority review is recorded.';
  }
  if (review.status === 'none_for_current_calculation') {
    return 'No review is recorded for the current calculation.';
  }
  if (review.status === 'accepted') {
    return 'A review accepted the calculated priority. Queue order is unchanged.';
  }
  if (review.status === 'corrected') {
    return `A review records working band ${review.correctedBand ?? ''} until ${review.expiresAt ?? ''}. The calculated priority and queue order are unchanged.`;
  }
  if (review.status === 'expired') {
    return `A recorded correction expired at ${review.expiresAt ?? ''}. The calculated priority and queue order are unchanged.`;
  }
  if (review.status === 'withdrawn') {
    return 'A review was withdrawn. The calculated priority and queue order are unchanged.';
  }
  return 'No priority review is recorded.';
}
