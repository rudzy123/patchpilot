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

  it('shuts down the ingest processor before the outbox relay and redis', async () => {
    const order: string[] = [];
    const worker = createWorkerApp({
      logger: silentLogger(),
      telemetry: { shutdown: async () => undefined },
      redis: fakeRedis({
        onQuit: () => {
          order.push('redis');
        },
      }),
      checkDatabaseReady: async () => ({ ok: true }),
      ingestionProcessor: {
        async start() {
          return;
        },
        async stop() {
          order.push('processor');
        },
      },
      outboxRelay: {
        start() {
          return;
        },
        async stop() {
          order.push('relay');
        },
      },
      shutdownTimeoutMs: 100,
      readinessTimeoutMs: 50,
    });
    await worker.start();
    await worker.stop();
    expect(order).toEqual(['processor', 'relay', 'redis']);
  });

  it('shuts down intelligence runtime before the queue worker, relay, and redis', async () => {
    const order: string[] = [];
    const worker = createWorkerApp({
      logger: silentLogger(),
      telemetry: { shutdown: async () => undefined },
      redis: fakeRedis({
        onQuit: () => {
          order.push('redis');
        },
      }),
      checkDatabaseReady: async () => ({ ok: true }),
      intelligenceRuntime: {
        async reconcileEnablement() {
          return;
        },
        startLoops() {
          return;
        },
        async stop() {
          order.push('intelligence');
        },
        async closeQueues() {
          order.push('redispatch');
        },
        abortActiveWork() {
          return;
        },
        signal: new AbortController().signal,
        health: () => ({
          schedulerRunning: false,
          schedulerLastTickAt: null,
          schedulerLastOutcome: null,
          retryReconcilerRunning: false,
          retryReconcilerLastPassAt: null,
        }),
      },
      ingestionProcessor: {
        async start() {
          return;
        },
        async stop() {
          order.push('processor');
        },
      },
      outboxRelay: {
        start() {
          return;
        },
        async stop() {
          order.push('relay');
        },
      },
      shutdownTimeoutMs: 100,
      readinessTimeoutMs: 50,
    });
    await worker.start();
    await worker.stop();
    expect(order).toEqual(['intelligence', 'processor', 'relay', 'redispatch', 'redis']);
  });

  it('fails readiness when private object storage is unavailable', async () => {
    const worker = createWorkerApp({
      logger: silentLogger(),
      telemetry: { shutdown: async () => undefined },
      redis: fakeRedis(),
      checkDatabaseReady: async () => ({ ok: true }),
      verifyPrivateStorage: async () => ({ ok: false }),
      shutdownTimeoutMs: 100,
      readinessTimeoutMs: 50,
    });
    await expect(worker.start()).rejects.toThrow(/object storage is not ready/);
    expect(worker.isAcceptingWork()).toBe(false);
  });

  it('does not start intelligence loops until required dependencies succeed', async () => {
    let loops = 0;
    const worker = createWorkerApp({
      logger: silentLogger(),
      telemetry: { shutdown: async () => undefined },
      redis: fakeRedis({ pingOk: false }),
      checkDatabaseReady: async () => ({ ok: true }),
      intelligenceRuntime: {
        async reconcileEnablement() {
          return;
        },
        startLoops() {
          loops += 1;
        },
        async stop() {
          return;
        },
        async closeQueues() {
          return;
        },
        abortActiveWork() {
          return;
        },
        signal: new AbortController().signal,
        health: () => ({
          schedulerRunning: false,
          schedulerLastTickAt: null,
          schedulerLastOutcome: null,
          retryReconcilerRunning: false,
          retryReconcilerLastPassAt: null,
        }),
      },
      shutdownTimeoutMs: 100,
      readinessTimeoutMs: 50,
    });
    await expect(worker.start()).rejects.toThrow(/redis is not ready/);
    expect(loops).toBe(0);
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
