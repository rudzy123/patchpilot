import {
  type JobRegistry,
  type RedisConnectionPort,
  createEmptyJobRegistry,
} from '@patchpilot/integrations';
import { type Logger } from '@patchpilot/logger';
import { type TelemetryHandle } from '@patchpilot/observability';

import type { IntelligenceRuntime } from './intelligence-runtime.js';
import type { OutboxRelayRuntime } from './outbox-relay-runtime.js';
import type { PatchpilotQueueWorker } from './queue-job-router.js';

export type WorkerDependencies = {
  logger: Logger;
  telemetry: TelemetryHandle;
  redis: RedisConnectionPort;
  checkDatabaseReady: (timeoutMs: number) => Promise<{ ok: boolean }>;
  verifyPrivateStorage?: () => Promise<{ ok: boolean }>;
  jobRegistry?: JobRegistry;
  queueWorker?: PatchpilotQueueWorker;
  ingestionProcessor?: { start(): Promise<void>; stop(): Promise<void> };
  intelligenceRuntime?: IntelligenceRuntime;
  outboxRelay?: OutboxRelayRuntime;
  shutdownTimeoutMs: number;
  readinessTimeoutMs: number;
};

export type WorkerApp = {
  start: () => Promise<void>;
  stop: () => Promise<void>;
  isAcceptingWork: () => boolean;
};

export function createWorkerApp(dependencies: WorkerDependencies): WorkerApp {
  let acceptingWork = false;
  let stopped = false;

  return {
    async start(): Promise<void> {
      const database = await dependencies.checkDatabaseReady(dependencies.readinessTimeoutMs);
      if (!database.ok) {
        throw new Error('Worker dependencies failed to initialize: database is not ready.');
      }

      if (dependencies.verifyPrivateStorage !== undefined) {
        const storage = await dependencies.verifyPrivateStorage();
        if (!storage.ok) {
          throw new Error('Worker dependencies failed to initialize: object storage is not ready.');
        }
      }

      if (dependencies.intelligenceRuntime !== undefined) {
        await dependencies.intelligenceRuntime.reconcileEnablement();
      }

      const redisReady = await dependencies.redis.ping(dependencies.readinessTimeoutMs);
      if (!redisReady) {
        throw new Error('Worker dependencies failed to initialize: redis is not ready.');
      }

      const registry = dependencies.jobRegistry ?? createEmptyJobRegistry();
      dependencies.outboxRelay?.start();
      const queueWorker = dependencies.queueWorker ?? dependencies.ingestionProcessor;
      if (queueWorker !== undefined) {
        await queueWorker.start();
      }
      dependencies.intelligenceRuntime?.startLoops();
      dependencies.logger.info(
        {
          jobCount: registry.length,
          ingestJob: 'sbom.ingest',
          intelligenceJob: 'intelligence.sync',
        },
        'worker started',
      );
      acceptingWork = true;
      stopped = false;
    },
    async stop(): Promise<void> {
      if (stopped) {
        return;
      }

      acceptingWork = false;
      const deadline = Date.now() + dependencies.shutdownTimeoutMs;
      const remainingMs = (): number => Math.max(0, deadline - Date.now());

      if (dependencies.intelligenceRuntime !== undefined) {
        await raceWithBudget(dependencies.intelligenceRuntime.stop(), remainingMs());
      }

      const queueWorker = dependencies.queueWorker ?? dependencies.ingestionProcessor;
      if (queueWorker !== undefined) {
        await raceWithBudget(queueWorker.stop(), remainingMs());
      }
      if (dependencies.outboxRelay !== undefined) {
        await raceWithBudget(dependencies.outboxRelay.stop(), remainingMs());
      }
      if (dependencies.intelligenceRuntime !== undefined) {
        await raceWithBudget(dependencies.intelligenceRuntime.closeQueues(), remainingMs());
      }
      await raceWithBudget(dependencies.redis.quit(), remainingMs());
      await raceWithBudget(dependencies.telemetry.shutdown(), remainingMs());
      stopped = true;
    },
    isAcceptingWork(): boolean {
      return acceptingWork;
    },
  };
}

async function raceWithBudget(work: Promise<void>, ms: number): Promise<void> {
  if (ms <= 0) {
    return;
  }
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      work,
      new Promise<void>((resolve) => {
        timer = setTimeout(resolve, ms);
      }),
    ]);
  } finally {
    if (timer !== undefined) {
      clearTimeout(timer);
    }
  }
}
