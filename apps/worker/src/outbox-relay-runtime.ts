import { OUTBOX_RELAY_POLL_INTERVAL_MS } from '@patchpilot/domain';
import type { Logger } from '@patchpilot/logger';

export type OutboxRelayRuntime = {
  start(): void;
  stop(): Promise<void>;
};

export function createOutboxRelayRuntime(options: {
  execute: () => Promise<unknown>;
  logger: Logger;
  delay?: (signal: AbortSignal) => Promise<void>;
  closeQueue?: () => Promise<void>;
  pollIntervalMs?: number;
}): OutboxRelayRuntime {
  const pollIntervalMs = options.pollIntervalMs ?? OUTBOX_RELAY_POLL_INTERVAL_MS;
  const delay = options.delay ?? ((signal) => delayMs(pollIntervalMs, signal));
  let running: Promise<void> | undefined;
  let stopping = false;
  let stopped = false;
  const abort = new AbortController();

  return {
    start(): void {
      if (running !== undefined || stopping) {
        return;
      }
      running = runLoop();
    },
    async stop(): Promise<void> {
      if (stopped) {
        return;
      }
      stopping = true;
      abort.abort();
      if (running !== undefined) {
        await running;
        running = undefined;
      }
      if (options.closeQueue !== undefined) {
        await options.closeQueue();
      }
      stopped = true;
    },
  };

  async function runLoop(): Promise<void> {
    while (!stopping && !abort.signal.aborted) {
      try {
        await options.execute();
      } catch (error: unknown) {
        options.logger.warn(
          {
            err: { type: error instanceof Error ? error.name : 'Error' },
          },
          'outbox relay batch failed',
        );
      }
      if (stopping || abort.signal.aborted) {
        return;
      }
      await delay(abort.signal);
    }
  }
}

export function delayMs(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal.aborted) {
      resolve();
      return;
    }
    const timer = setTimeout(() => {
      resolve();
    }, ms);
    signal.addEventListener(
      'abort',
      () => {
        clearTimeout(timer);
        resolve();
      },
      { once: true },
    );
  });
}
