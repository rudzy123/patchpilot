import {
  INTELLIGENCE_RETRY_RECONCILE_BATCH_LIMIT,
  type IntelligenceRedeliveryPersistencePort,
  type IntelligenceSourceFreshnessPort,
  type KevSchedulerTickOutcome,
} from '@patchpilot/domain';

import type { IntelligenceJobRedispatch } from './intelligence-job-redispatch.js';
import {
  createIntelligenceRetryReconciler,
  type IntelligenceRetryReconciler,
} from './intelligence-retry-reconciler.js';
import {
  createIntelligenceScheduler,
  type IntelligenceScheduler,
} from './intelligence-scheduler.js';

export type IntelligenceRuntimeHealth = {
  schedulerRunning: boolean;
  schedulerLastTickAt: string | null;
  schedulerLastOutcome: KevSchedulerTickOutcome['kind'] | null;
  retryReconcilerRunning: boolean;
  retryReconcilerLastPassAt: string | null;
};

export type IntelligenceRuntime = {
  reconcileEnablement(): Promise<void>;
  startLoops(): void;
  stop(): Promise<void>;
  closeQueues(): Promise<void>;
  abortActiveWork(): void;
  signal: AbortSignal;
  health(): IntelligenceRuntimeHealth;
};

export type IntelligenceRuntimeLogger = {
  info(bindings: Record<string, unknown>, message: string): void;
  warn(bindings: Record<string, unknown>, message: string): void;
};

export function createIntelligenceRuntime(options: {
  kevEnabled: boolean;
  evaluate: (input: { shutdown: boolean }) => Promise<KevSchedulerTickOutcome>;
  redelivery: IntelligenceRedeliveryPersistencePort;
  redispatch: IntelligenceJobRedispatch;
  freshness: IntelligenceSourceFreshnessPort;
  logger: IntelligenceRuntimeLogger;
  schedulerPollIntervalMs: number;
  schedulerStartupDelayMs: number;
  retryReconcileIntervalMs: number;
  retryReconcileMinAgeMs: number;
  now?: () => Date;
  delay?: (ms: number, signal: AbortSignal) => Promise<void>;
}): IntelligenceRuntime {
  const abort = new AbortController();
  const scheduler: IntelligenceScheduler = createIntelligenceScheduler({
    evaluate: options.evaluate,
    logger: options.logger,
    pollIntervalMs: options.schedulerPollIntervalMs,
    startupDelayMs: options.schedulerStartupDelayMs,
    ...(options.delay === undefined ? {} : { delay: options.delay }),
  });
  const reconciler: IntelligenceRetryReconciler = createIntelligenceRetryReconciler({
    listDue: (now) =>
      options.redelivery.listDueRedeliveries({
        now,
        minAgeMs: options.retryReconcileMinAgeMs,
        limit: INTELLIGENCE_RETRY_RECONCILE_BATCH_LIMIT,
      }),
    redispatch: options.redispatch,
    logger: options.logger,
    intervalMs: options.retryReconcileIntervalMs,
    ...(options.now === undefined ? {} : { now: options.now }),
    ...(options.delay === undefined ? {} : { delay: options.delay }),
  });
  let loopsStarted = false;

  return {
    async reconcileEnablement(): Promise<void> {
      const result = await options.freshness.reconcileRuntimeEnablement({
        provider: 'cisa_kev',
        enabled: options.kevEnabled,
      });
      if (!result.ok) {
        throw new Error(
          'Worker dependencies failed to initialize: intelligence source is not ready.',
        );
      }
      if (result.value.outcome === 'version_conflict') {
        options.logger.warn(
          { operation: 'kev_enablement_reconcile', outcome: 'version_conflict' },
          'intelligence source enablement version conflict',
        );
      }
    },
    startLoops(): void {
      if (loopsStarted || !options.kevEnabled) {
        return;
      }
      loopsStarted = true;
      reconciler.start();
      scheduler.start();
    },
    async stop(): Promise<void> {
      abort.abort();
      await scheduler.stop();
      await reconciler.stop();
    },
    async closeQueues(): Promise<void> {
      await options.redispatch.close();
    },
    abortActiveWork(): void {
      abort.abort();
    },
    signal: abort.signal,
    health(): IntelligenceRuntimeHealth {
      const lastTick = scheduler.lastTickAt();
      const lastPass = reconciler.lastPassAt();
      return {
        schedulerRunning: scheduler.isRunning(),
        schedulerLastTickAt: lastTick === null ? null : lastTick.toISOString(),
        schedulerLastOutcome: scheduler.lastOutcome(),
        retryReconcilerRunning: reconciler.isRunning(),
        retryReconcilerLastPassAt: lastPass === null ? null : lastPass.toISOString(),
      };
    },
  };
}
