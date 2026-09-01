import { describe, expect, it } from 'vitest';

import { createIntelligenceScheduler } from './intelligence-scheduler.js';

function createGate() {
  const waiting: Array<() => void> = [];
  return {
    delay(_ms: number, signal: AbortSignal): Promise<void> {
      return new Promise((resolve) => {
        if (signal.aborted) {
          resolve();
          return;
        }
        waiting.push(resolve);
        signal.addEventListener('abort', () => resolve(), { once: true });
      });
    },
    async releaseOne(): Promise<void> {
      const next = waiting.shift();
      next?.();
      await Promise.resolve();
    },
    pending(): number {
      return waiting.length;
    },
  };
}

async function flushUntil(predicate: () => boolean): Promise<void> {
  for (let i = 0; i < 20; i += 1) {
    if (predicate()) {
      return;
    }
    await Promise.resolve();
  }
}

describe('intelligence scheduler runtime', () => {
  it('evaluates one tick at a time after the startup delay and stops overlapping work', async () => {
    const gate = createGate();
    let inFlight = 0;
    let maxInFlight = 0;
    let ticks = 0;
    const settle: Array<() => void> = [];
    const scheduler = createIntelligenceScheduler({
      evaluate: async () => {
        inFlight += 1;
        maxInFlight = Math.max(maxInFlight, inFlight);
        ticks += 1;
        await new Promise<void>((resolve) => {
          settle.push(resolve);
        });
        inFlight -= 1;
        return { kind: 'not_due' };
      },
      logger: {
        info() {
          return;
        },
        warn() {
          return;
        },
      },
      pollIntervalMs: 30_000,
      startupDelayMs: 5_000,
      delay: (ms, signal) => gate.delay(ms, signal),
    });
    scheduler.start();
    expect(ticks).toBe(0);
    await gate.releaseOne();
    await flushUntil(() => ticks === 1);
    expect(ticks).toBe(1);
    expect(maxInFlight).toBe(1);
    settle.shift()?.();
    await flushUntil(() => gate.pending() === 1);
    expect(gate.pending()).toBe(1);
    await scheduler.stop();
    expect(scheduler.isRunning()).toBe(false);
  });

  it('stops during the startup delay without evaluating', async () => {
    const gate = createGate();
    let ticks = 0;
    const scheduler = createIntelligenceScheduler({
      evaluate: async () => {
        ticks += 1;
        return { kind: 'disabled' };
      },
      logger: {
        info() {
          return;
        },
        warn() {
          return;
        },
      },
      pollIntervalMs: 30_000,
      startupDelayMs: 5_000,
      delay: (ms, signal) => gate.delay(ms, signal),
    });
    scheduler.start();
    await scheduler.stop();
    expect(ticks).toBe(0);
  });

  it('logs a persistence failure and continues', async () => {
    const gate = createGate();
    const warnings: string[] = [];
    const scheduler = createIntelligenceScheduler({
      evaluate: async () => ({ kind: 'persistence_failure' }),
      logger: {
        info() {
          return;
        },
        warn(_bindings, message) {
          warnings.push(message);
        },
      },
      pollIntervalMs: 30_000,
      startupDelayMs: 0,
      delay: (ms, signal) => gate.delay(ms, signal),
    });
    scheduler.start();
    await Promise.resolve();
    await Promise.resolve();
    expect(scheduler.lastOutcome()).toBe('persistence_failure');
    expect(warnings).toEqual(['kev scheduler tick failed']);
    await scheduler.stop();
  });
});
