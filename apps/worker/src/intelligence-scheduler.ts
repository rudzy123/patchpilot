import type { KevSchedulerTickOutcome } from '@patchpilot/domain';

import { delayMs } from './outbox-relay-runtime.js';

export type IntelligenceScheduler = {
  start(): void;
  stop(): Promise<void>;
  isRunning(): boolean;
  lastTickAt(): Date | null;
  lastOutcome(): KevSchedulerTickOutcome['kind'] | null;
};

export type IntelligenceSchedulerLogger = {
  info(bindings: Record<string, unknown>, message: string): void;
  warn(bindings: Record<string, unknown>, message: string): void;
};

export function createIntelligenceScheduler(options: {
  evaluate: (input: { shutdown: boolean }) => Promise<KevSchedulerTickOutcome>;
  logger: IntelligenceSchedulerLogger;
  pollIntervalMs: number;
  startupDelayMs: number;
  delay?: (ms: number, signal: AbortSignal) => Promise<void>;
}): IntelligenceScheduler {
  const delay = options.delay ?? delayMs;
  const abort = new AbortController();
  let running: Promise<void> | undefined;
  let stopping = false;
  let tickInFlight = false;
  let lastTickAt: Date | null = null;
  let lastOutcome: KevSchedulerTickOutcome['kind'] | null = null;

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
    lastTickAt(): Date | null {
      return lastTickAt;
    },
    lastOutcome(): KevSchedulerTickOutcome['kind'] | null {
      return lastOutcome;
    },
  };

  async function runLoop(): Promise<void> {
    if (options.startupDelayMs > 0) {
      await delay(options.startupDelayMs, abort.signal);
    }
    while (!stopping && !abort.signal.aborted) {
      await runTick();
      if (stopping || abort.signal.aborted) {
        return;
      }
      await delay(options.pollIntervalMs, abort.signal);
    }
  }

  async function runTick(): Promise<void> {
    if (tickInFlight || stopping || abort.signal.aborted) {
      return;
    }
    tickInFlight = true;
    try {
      const outcome = await options.evaluate({ shutdown: stopping || abort.signal.aborted });
      lastTickAt = new Date();
      lastOutcome = outcome.kind;
      if (outcome.kind === 'persistence_failure') {
        options.logger.warn(
          { operation: 'kev_scheduler_tick', outcome: outcome.kind },
          'kev scheduler tick failed',
        );
        return;
      }
      if (outcome.kind === 'due_initial' || outcome.kind === 'due_periodic') {
        options.logger.info(
          {
            operation: 'kev_scheduler_tick',
            provider: 'cisa_kev',
            sourceIdentifier: 'cisa_kev_json_catalog',
            outcome: outcome.kind,
            syncRunId: outcome.syncRunId,
          },
          'kev scheduler requested sync',
        );
      }
    } catch {
      lastTickAt = new Date();
      lastOutcome = 'persistence_failure';
      options.logger.warn(
        { operation: 'kev_scheduler_tick', outcome: 'persistence_failure' },
        'kev scheduler tick failed',
      );
    } finally {
      tickInFlight = false;
    }
  }
}
