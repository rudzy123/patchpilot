import {
  intelligenceRedispatchJobId,
  type IntelligenceRedeliveryCandidate,
} from '@patchpilot/domain';

import type { IntelligenceJobRedispatch } from './intelligence-job-redispatch.js';
import { delayMs } from './outbox-relay-runtime.js';

export type IntelligenceRetryReconciler = {
  start(): void;
  stop(): Promise<void>;
  isRunning(): boolean;
  lastPassAt(): Date | null;
};

export type IntelligenceRetryReconcilerLogger = {
  info(bindings: Record<string, unknown>, message: string): void;
  warn(bindings: Record<string, unknown>, message: string): void;
};

export function createIntelligenceRetryReconciler(options: {
  listDue: (now: Date) => Promise<readonly IntelligenceRedeliveryCandidate[]>;
  redispatch: IntelligenceJobRedispatch;
  logger: IntelligenceRetryReconcilerLogger;
  intervalMs: number;
  now?: () => Date;
  delay?: (ms: number, signal: AbortSignal) => Promise<void>;
}): IntelligenceRetryReconciler {
  const delay = options.delay ?? delayMs;
  const now = options.now ?? (() => new Date());
  const abort = new AbortController();
  let running: Promise<void> | undefined;
  let stopping = false;
  let passInFlight = false;
  let lastPassAt: Date | null = null;

  return {
    start(): void {
      if (running !== undefined || stopping) {
        return;
      }
      running = runLoop();
    },
    async stop(): Promise<void> {
      stopping = true;
      abort.abort();
      if (running !== undefined) {
        await running;
        running = undefined;
      }
    },
    isRunning(): boolean {
      return running !== undefined && !stopping;
    },
    lastPassAt(): Date | null {
      return lastPassAt;
    },
  };

  async function runLoop(): Promise<void> {
    while (!stopping && !abort.signal.aborted) {
      await delay(options.intervalMs, abort.signal);
      if (stopping || abort.signal.aborted) {
        return;
      }
      await runPass();
    }
  }

  async function runPass(): Promise<void> {
    if (passInFlight || stopping || abort.signal.aborted) {
      return;
    }
    passInFlight = true;
    try {
      const candidates = await options.listDue(now());
      let redispatched = 0;
      for (const candidate of candidates) {
        if (stopping || abort.signal.aborted) {
          break;
        }
        try {
          const jobId = intelligenceRedispatchJobId(candidate);
          if (!jobId.ok) {
            options.logger.warn(
              { operation: 'kev_retry_reconcile', outcome: 'invalid_locator' },
              'kev retry candidate skipped',
            );
            continue;
          }
          const published = await options.redispatch.add({
            jobId: jobId.value,
            payload: candidate.locator,
          });
          if (!published.ok) {
            options.logger.warn(
              {
                operation: 'kev_retry_reconcile',
                outcome: 'redis_unavailable',
                syncRunId: candidate.syncRunId,
                backgroundJobId: candidate.backgroundJobId,
              },
              'kev retry redispatch failed',
            );
            continue;
          }
          redispatched += 1;
        } catch {
          options.logger.warn(
            {
              operation: 'kev_retry_reconcile',
              outcome: 'candidate_failed',
              syncRunId: candidate.syncRunId,
            },
            'kev retry candidate failed',
          );
        }
      }
      lastPassAt = now();
      options.logger.info(
        {
          operation: 'kev_retry_reconcile',
          candidateCount: candidates.length,
          redispatched,
        },
        'kev retry reconciliation pass finished',
      );
    } catch {
      lastPassAt = now();
      options.logger.warn(
        { operation: 'kev_retry_reconcile', outcome: 'persistence_failure' },
        'kev retry reconciliation pass failed',
      );
    } finally {
      passInFlight = false;
    }
  }
}
