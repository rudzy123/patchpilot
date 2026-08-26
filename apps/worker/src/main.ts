import { loadServerConfig } from '@patchpilot/config';
import { checkDatabaseReady, disconnectPrisma } from '@patchpilot/database';
import { createEmptyJobRegistry } from '@patchpilot/integrations';
import { createLogger } from '@patchpilot/logger';
import { startTelemetry } from '@patchpilot/observability';

import { createWorkerApp } from './app.js';
import { createRedisConnection } from './redis.js';

async function main(): Promise<void> {
  const config = loadServerConfig();
  const logger = createLogger({
    service: 'worker',
    level: config.logLevel,
    pretty: config.prettyLogs && config.deploymentEnvironment !== 'production',
  });
  const telemetry = await startTelemetry({
    serviceName: 'worker',
    enabled: config.openTelemetry.enabled,
    ...(config.openTelemetry.tracesEndpoint === undefined
      ? {}
      : { tracesEndpoint: config.openTelemetry.tracesEndpoint }),
  });
  const redis = createRedisConnection(config.redisUrl);
  const worker = createWorkerApp({
    logger,
    telemetry,
    redis,
    checkDatabaseReady: (timeoutMs) => checkDatabaseReady(timeoutMs),
    jobRegistry: createEmptyJobRegistry(),
    shutdownTimeoutMs: config.shutdownTimeoutMs,
    readinessTimeoutMs: config.readinessTimeoutMs,
  });

  let shuttingDown = false;
  const shutdown = async (signal: string): Promise<void> => {
    if (shuttingDown) {
      return;
    }

    shuttingDown = true;
    logger.info({ signal }, 'worker shutting down');
    const timer = setTimeout(() => {
      logger.error('worker shutdown timed out');
      process.exit(1);
    }, config.shutdownTimeoutMs);
    try {
      await worker.stop();
      await disconnectPrisma();
    } finally {
      clearTimeout(timer);
    }
  };

  process.once('SIGTERM', () => {
    void shutdown('SIGTERM').then(
      () => process.exit(0),
      () => process.exit(1),
    );
  });
  process.once('SIGINT', () => {
    void shutdown('SIGINT').then(
      () => process.exit(0),
      () => process.exit(1),
    );
  });

  try {
    await worker.start();
  } catch (error: unknown) {
    await shutdown('startup-failure');
    throw error;
  }
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : 'Unknown startup error';
  process.stderr.write(`Worker failed to start: ${message}\n`);
  process.exit(1);
});
