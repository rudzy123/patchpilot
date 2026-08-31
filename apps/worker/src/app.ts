import {
  type JobRegistry,
  type RedisConnectionPort,
  createEmptyJobRegistry,
} from '@patchpilot/integrations';
import { type Logger } from '@patchpilot/logger';
import { type TelemetryHandle } from '@patchpilot/observability';

import type { OutboxRelayRuntime } from './outbox-relay-runtime.js';
import type { SbomIngestProcessor } from './sbom-ingest-processor.js';

export type WorkerDependencies = {
  logger: Logger;
  telemetry: TelemetryHandle;
  redis: RedisConnectionPort;
  checkDatabaseReady: (timeoutMs: number) => Promise<{ ok: boolean }>;
  jobRegistry?: JobRegistry;
  ingestionProcessor?: SbomIngestProcessor;
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

      const redisReady = await dependencies.redis.ping(dependencies.readinessTimeoutMs);
      if (!redisReady) {
        throw new Error('Worker dependencies failed to initialize: redis is not ready.');
      }

      const registry = dependencies.jobRegistry ?? createEmptyJobRegistry();
      if (dependencies.ingestionProcessor !== undefined) {
        await dependencies.ingestionProcessor.start();
      }
      dependencies.logger.info(
        { jobCount: registry.length, ingestJob: 'sbom.ingest' },
        'worker started',
      );
      acceptingWork = true;
      stopped = false;
      dependencies.outboxRelay?.start();
    },
    async stop(): Promise<void> {
      if (stopped) {
        return;
      }

      acceptingWork = false;
      if (dependencies.ingestionProcessor !== undefined) {
        await dependencies.ingestionProcessor.stop();
      }
      if (dependencies.outboxRelay !== undefined) {
        await dependencies.outboxRelay.stop();
      }
      await dependencies.redis.quit();
      await dependencies.telemetry.shutdown();
      stopped = true;
    },
    isAcceptingWork(): boolean {
      return acceptingWork;
    },
  };
}
