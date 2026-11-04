import {
  remediationQueueResponseSchema,
  type RemediationQueueResponse,
} from '@patchpilot/contracts';

export const QUEUE_HEADING = 'Remediation queue';
export const QUEUE_RANKED_HEADING = 'Ranked';
export const QUEUE_INCOMPARABLE_HEADING = 'Not comparable';
export const QUEUE_NOT_CALCULATED_HEADING = 'Not calculated';
export const QUEUE_LOADING = 'Loading the remediation queue.';
export const QUEUE_UNAVAILABLE = 'Remediation queue is temporarily unavailable.';
export const QUEUE_POLICY_UNAVAILABLE = 'Priority policy is unavailable.';
export const QUEUE_FORBIDDEN = 'Permission denied.';
export const QUEUE_RATE_LIMITED = 'Too many requests. Try again later.';
export const QUEUE_NOT_A_SNAPSHOT =
  'This list is not a snapshot. A later page can change after a new calculation.';
export const QUEUE_NOT_CALCULATED_NOTE =
  'A Finding in this panel has no stored calculation. It is separate from the ranked bands.';
export const QUEUE_INCOMPARABLE_NOTE =
  'These stored results use another policy. They are not on the ranked scale.';
export const QUEUE_COMPARISON_MESSAGE = 'recalculation required for comparison';
export const QUEUE_LOAD_MORE = 'Load more';

export type RemediationQueueSection = RemediationQueueResponse['section'];

export function readRemediationQueue(
  value: unknown,
  section: RemediationQueueSection,
): RemediationQueueResponse | null {
  const parsed = remediationQueueResponseSchema.safeParse(value);
  if (!parsed.success || parsed.data.section !== section) {
    return null;
  }
  return parsed.data;
}
