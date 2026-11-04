import {
  findingPriorityResponseSchema,
  findingRiskCalculationResponseSchema,
  type FindingPriorityResponse,
  type FindingRiskCalculationResponse,
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
