/**
 * Stored-field order for the ranked remediation section.
 * Priority descending, escalation recommended first, KEV listed first,
 * source-severity percent descending, then Finding first observation
 * ascending and Finding id ascending. Different policy keys are
 * `incomparable`. This module does not call the priority engine.
 * The request path orders in SQL. A contract test requires that SQL and
 * `compareForRemediationQueue`, plus the two caller keys, agree.
 */

import { PRIORITY_KEV_LISTED_TOKENS } from './catalog.js';

export type StoredRemediationRankKey = {
  readonly policyKey: string;
  readonly priority: number;
  readonly escalationRecommended: boolean;
  readonly kevListed: boolean;
  readonly severityPercent: number;
  readonly firstObservedAt: string;
  readonly findingId: string;
};

export function compareStoredRemediationRank(
  left: StoredRemediationRankKey,
  right: StoredRemediationRankKey,
): -1 | 0 | 1 | 'incomparable' {
  if (left.policyKey !== right.policyKey) {
    return 'incomparable';
  }
  const keys = [
    descending(left.priority, right.priority),
    trueFirst(left.escalationRecommended, right.escalationRecommended),
    trueFirst(left.kevListed, right.kevListed),
    descending(left.severityPercent, right.severityPercent),
    ascending(left.firstObservedAt, right.firstObservedAt),
    ascending(left.findingId, right.findingId),
  ];
  return keys.find((comparison) => comparison !== 0) ?? 0;
}

export function storedKevListed(input: {
  readonly inputState: string;
  readonly observedValue: unknown;
}): boolean {
  return (
    input.inputState === 'observed' &&
    typeof input.observedValue === 'string' &&
    (PRIORITY_KEV_LISTED_TOKENS as readonly string[]).includes(input.observedValue)
  );
}

function descending(left: number, right: number): -1 | 0 | 1 {
  if (left === right) {
    return 0;
  }
  return left > right ? -1 : 1;
}

function trueFirst(left: boolean, right: boolean): -1 | 0 | 1 {
  if (left === right) {
    return 0;
  }
  return left ? -1 : 1;
}

function ascending(left: string, right: string): -1 | 0 | 1 {
  if (left === right) {
    return 0;
  }
  return left < right ? -1 : 1;
}
