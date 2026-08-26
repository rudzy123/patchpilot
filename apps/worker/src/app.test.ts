import { createEmptyJobRegistry, type RedisConnectionPort } from '@patchpilot/integrations';
import { createLogger } from '@patchpilot/logger';
import { describe, expect, it } from 'vitest';
import { Writable } from 'node:stream';

import { createWorkerApp } from './app.js';

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

function fakeRedis(options?: { pingOk?: boolean; onQuit?: () => void }): RedisConnectionPort {
  return {
    async ping(): Promise<boolean> {
      return options?.pingOk ?? true;
    },
    async quit(): Promise<void> {
      options?.onQuit?.();
    },
  };
}

describe('worker application', () => {
  it('initializes with fake dependencies', async () => {
    const worker = createWorkerApp({
      logger: silentLogger(),
      telemetry: { shutdown: async () => undefined },
      redis: fakeRedis(),
      checkDatabaseReady: async () => ({ ok: true }),
      jobRegistry: createEmptyJobRegistry(),
      shutdownTimeoutMs: 100,
      readinessTimeoutMs: 50,
    });
    await worker.start();
    expect(worker.isAcceptingWork()).toBe(true);
    await worker.stop();
    expect(worker.isAcceptingWork()).toBe(false);
  });

  it('shuts down cleanly and is idempotent', async () => {
    let quitCount = 0;
    const worker = createWorkerApp({
      logger: silentLogger(),
      telemetry: { shutdown: async () => undefined },
      redis: fakeRedis({
        onQuit: () => {
          quitCount += 1;
        },
      }),
      checkDatabaseReady: async () => ({ ok: true }),
      shutdownTimeoutMs: 100,
      readinessTimeoutMs: 50,
    });
    await worker.start();
    await worker.stop();
    await worker.stop();
    expect(quitCount).toBe(1);
  });

  it('surfaces initialization failure and still allows shutdown to release redis', async () => {
    let quitCount = 0;
    const worker = createWorkerApp({
      logger: silentLogger(),
      telemetry: { shutdown: async () => undefined },
      redis: fakeRedis({
        pingOk: false,
        onQuit: () => {
          quitCount += 1;
        },
      }),
      checkDatabaseReady: async () => ({ ok: true }),
      shutdownTimeoutMs: 100,
      readinessTimeoutMs: 50,
    });
    await expect(worker.start()).rejects.toThrow(/redis is not ready/);
    expect(worker.isAcceptingWork()).toBe(false);
    await worker.stop();
    expect(quitCount).toBe(1);
  });
});
