import { createLogger } from '@patchpilot/logger';
import { describe, expect, it } from 'vitest';
import { Writable } from 'node:stream';

import { createOutboxRelayRuntime } from './outbox-relay-runtime.js';

function silentLogger() {
  const destination = new Writable({
    write(_chunk, _encoding, callback) {
      callback();
    },
  });
  return createLogger({
    service: 'worker-test',
    level: 'silent',
    pretty: false,
    destination,
  });
}

describe('outbox relay runtime', () => {
  it('stops leasing new batches and waits for an in-flight publish', async () => {
    let executeCount = 0;
    let releaseInFlight: (() => void) | undefined;
    let startedExecute: () => void = () => undefined;
    const executeStarted = new Promise<void>((resolve) => {
      startedExecute = resolve;
    });
    let queueClosed = 0;

    const runtime = createOutboxRelayRuntime({
      execute: async () => {
        executeCount += 1;
        startedExecute();
        await new Promise<void>((resolve) => {
          releaseInFlight = resolve;
        });
      },
      logger: silentLogger(),
      delay: async (signal) => {
        if (signal.aborted) {
          return;
        }
        await new Promise<void>((resolve) => {
          signal.addEventListener('abort', () => resolve(), { once: true });
        });
      },
      closeQueue: async () => {
        queueClosed += 1;
      },
    });

    runtime.start();
    await executeStarted;
    expect(executeCount).toBe(1);

    const stopping = runtime.stop();
    await Promise.resolve();
    expect(executeCount).toBe(1);
    releaseInFlight?.();
    await stopping;
    expect(executeCount).toBe(1);
    expect(queueClosed).toBe(1);

    await runtime.stop();
    expect(queueClosed).toBe(1);
  });
});
