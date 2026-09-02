import { describe, expect, it } from 'vitest';

import { ok } from '@patchpilot/domain';

import { createIntelligenceRuntime } from './intelligence-runtime.js';

describe('intelligence runtime composition', () => {
  it('starts scheduler and reconciler only when KEV is enabled', async () => {
    let listed = 0;
    const enabled = createIntelligenceRuntime({
      kevEnabled: true,
      evaluate: async () => ({ kind: 'not_due' }),
      redelivery: {
        listDueRedeliveries: async () => {
          listed += 1;
          return [];
        },
      },
      redispatch: {
        add: async () => ({ ok: true, duplicate: false }),
        close: async () => undefined,
      },
      freshness: {
        loadCurrentProviderStatus: async () => {
          throw new Error('unused');
        },
        loadCisaKevSourcePointer: async () => undefined,
        reconcileRuntimeEnablement: async () => ok({ outcome: 'unchanged', version: 1 }),
        markAttemptStarted: async () => {
          throw new Error('unused');
        },
        markSuccessfulCompletedGeneration: async () => {
          throw new Error('unused');
        },
        markNotModified: async () => {
          throw new Error('unused');
        },
        markDegradedFailure: async () => {
          throw new Error('unused');
        },
      },
      logger: {
        info() {
          return;
        },
        warn() {
          return;
        },
      },
      schedulerPollIntervalMs: 30_000,
      schedulerStartupDelayMs: 0,
      retryReconcileIntervalMs: 15_000,
      retryReconcileMinAgeMs: 15_000,
      delay: async (_ms, signal) => {
        await new Promise<void>((resolve) => {
          if (signal.aborted) {
            resolve();
            return;
          }
          signal.addEventListener('abort', () => resolve(), { once: true });
        });
      },
    });
    enabled.startLoops();
    expect(enabled.health().schedulerRunning).toBe(true);
    expect(enabled.health().retryReconcilerRunning).toBe(true);
    await enabled.stop();

    const disabled = createIntelligenceRuntime({
      kevEnabled: false,
      evaluate: async () => ({ kind: 'disabled' }),
      redelivery: {
        listDueRedeliveries: async () => {
          listed += 1;
          return [];
        },
      },
      redispatch: {
        add: async () => ({ ok: true, duplicate: false }),
        close: async () => undefined,
      },
      freshness: {
        loadCurrentProviderStatus: async () => {
          throw new Error('unused');
        },
        loadCisaKevSourcePointer: async () => undefined,
        reconcileRuntimeEnablement: async () => ok({ outcome: 'updated', version: 2 }),
        markAttemptStarted: async () => {
          throw new Error('unused');
        },
        markSuccessfulCompletedGeneration: async () => {
          throw new Error('unused');
        },
        markNotModified: async () => {
          throw new Error('unused');
        },
        markDegradedFailure: async () => {
          throw new Error('unused');
        },
      },
      logger: {
        info() {
          return;
        },
        warn() {
          return;
        },
      },
      schedulerPollIntervalMs: 30_000,
      schedulerStartupDelayMs: 0,
      retryReconcileIntervalMs: 15_000,
      retryReconcileMinAgeMs: 15_000,
    });
    await disabled.reconcileEnablement();
    disabled.startLoops();
    expect(disabled.health().schedulerRunning).toBe(false);
    expect(disabled.health().retryReconcilerRunning).toBe(false);
    expect(listed).toBe(0);
    await disabled.stop();
  });
});
