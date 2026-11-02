import { KEV_LISTED_TOKENS, type FactorId } from './catalog.js';
import type { PriorityEvaluation, PriorityFactorRow } from './evaluate.js';

/** Negative: `a` is worked first. Positive: `b` is worked first. */
export type RemediationQueueComparison = -1 | 0 | 1 | 'incomparable';

function factorRow(
  evaluation: PriorityEvaluation,
  factorId: FactorId,
): PriorityFactorRow | undefined {
  return evaluation.factors.find((row) => row.factorId === factorId);
}

function isKevListed(evaluation: PriorityEvaluation): boolean {
  const row = factorRow(evaluation, 'kev_listed');
  return (
    row?.inputState === 'observed' &&
    (KEV_LISTED_TOKENS as readonly unknown[]).includes(row.observedValue)
  );
}

function severityPercent(evaluation: PriorityEvaluation): number {
  return factorRow(evaluation, 'source_severity')?.normalizedPercent ?? 0;
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

/**
 * Engine keys of the remediation queue order, in precedence: priority
 * descending, escalation recommended first, KEV listed first, then source
 * severity percent descending. Evaluations under different policy keys are
 * `incomparable`. Callers must also require an equal policy definition
 * SHA-256, then break remaining ties by Finding first observation ascending
 * and Finding ID ascending; neither enters the engine.
 */
export function compareForRemediationQueue(
  a: PriorityEvaluation,
  b: PriorityEvaluation,
): RemediationQueueComparison {
  if (a.policyKey !== b.policyKey) {
    return 'incomparable';
  }
  const keys = [
    descending(a.priority, b.priority),
    trueFirst(a.escalation.recommended, b.escalation.recommended),
    trueFirst(isKevListed(a), isKevListed(b)),
    descending(severityPercent(a), severityPercent(b)),
  ];
  return keys.find((comparison) => comparison !== 0) ?? 0;
}

/**
 * Presentation-only view of factor rows by contribution descending, then
 * catalog ordinal ascending. Stored rows stay in catalog order.
 */
export function rankFactorsByContribution(
  factors: readonly PriorityFactorRow[],
): readonly PriorityFactorRow[] {
  return Object.freeze(
    [...factors].sort(
      (left, right) =>
        right.contributionCenti - left.contributionCenti || left.ordinal - right.ordinal,
    ),
  );
}
