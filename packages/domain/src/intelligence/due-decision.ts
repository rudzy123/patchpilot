import { isIntelligenceTerminalSyncRunState } from './transitions.js';
import { isPositiveSafeInteger } from './normalize.js';
import type { IntelligenceSyncRunRecord } from './records.js';
import type { IntelligenceSyncRunState } from './constants.js';

export type KevSyncDueDecision =
  | { kind: 'disabled' }
  | { kind: 'shutdown' }
  | { kind: 'due_initial' }
  | { kind: 'due_periodic' }
  | { kind: 'not_due' }
  | { kind: 'inflight' }
  | { kind: 'retry_wait_inflight' };

export type DecideKevSyncDueInput = {
  kevEnabled: boolean;
  shutdown: boolean;
  now: Date;
  syncIntervalSeconds: number;
  latestSyncRun: IntelligenceSyncRunRecord | undefined;
  lastSuccessfulSyncAt: Date | null;
};

function isNonterminal(state: IntelligenceSyncRunState): boolean {
  return !isIntelligenceTerminalSyncRunState(state);
}

/**
 * Periodic due decision. Typed `kevEnabled` is the operator gate. Seeded
 * IntelligenceSource `disabled` is not consulted. Provider timestamps, ETag,
 * catalogVersion, HTTP Date, local time, and the stale threshold are not
 * due triggers. `retry_wait` is inflight and is not redispatched here.
 */
export function decideKevSyncDue(input: DecideKevSyncDueInput): KevSyncDueDecision {
  if (input.shutdown) {
    return { kind: 'shutdown' };
  }
  if (!input.kevEnabled) {
    return { kind: 'disabled' };
  }
  if (!isPositiveSafeInteger(input.syncIntervalSeconds)) {
    return { kind: 'not_due' };
  }
  const latest = input.latestSyncRun;
  if (latest !== undefined && isNonterminal(latest.state)) {
    if (latest.state === 'retry_wait') {
      return { kind: 'retry_wait_inflight' };
    }
    return { kind: 'inflight' };
  }

  if (input.lastSuccessfulSyncAt === null) {
    return { kind: 'due_initial' };
  }

  const elapsedMs = input.now.getTime() - input.lastSuccessfulSyncAt.getTime();
  if (!Number.isSafeInteger(elapsedMs) || elapsedMs < 0) {
    return { kind: 'not_due' };
  }
  const intervalMs = input.syncIntervalSeconds * 1000;
  if (!Number.isSafeInteger(intervalMs)) {
    return { kind: 'not_due' };
  }
  if (elapsedMs < intervalMs) {
    return { kind: 'not_due' };
  }
  return { kind: 'due_periodic' };
}
