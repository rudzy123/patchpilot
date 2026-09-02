import { classifyIntelligenceSafeFailure, type IntelligenceSafeFailureCode } from './failures.js';

export type IntelligenceSyncFailureLayer = 'pre_snapshot' | 'post_snapshot';

export type IntelligenceSyncFailureAction =
  | { kind: 'retry_wait'; code: IntelligenceSafeFailureCode }
  | { kind: 'job_retry'; code: IntelligenceSafeFailureCode }
  | { kind: 'failed'; code: IntelligenceSafeFailureCode }
  | { kind: 'quarantined'; code: IntelligenceSafeFailureCode }
  | { kind: 'rejected'; code: IntelligenceSafeFailureCode };

export function mapIntelligenceSyncFailure(input: {
  code: IntelligenceSafeFailureCode;
  layer: IntelligenceSyncFailureLayer;
  attemptsRemaining: boolean;
}): IntelligenceSyncFailureAction {
  const classification = classifyIntelligenceSafeFailure(input.code);
  if (classification.disposition === 'quarantined') {
    return { kind: 'quarantined', code: input.code };
  }
  if (!classification.retryable) {
    return { kind: 'failed', code: input.code };
  }
  if (!input.attemptsRemaining) {
    return { kind: 'failed', code: input.code };
  }
  if (input.layer === 'pre_snapshot') {
    return { kind: 'retry_wait', code: input.code };
  }
  return { kind: 'job_retry', code: input.code };
}

export function attemptsRemain(attempt: number, maxAttempts: number): boolean {
  return (
    Number.isSafeInteger(attempt) && Number.isSafeInteger(maxAttempts) && attempt < maxAttempts
  );
}
