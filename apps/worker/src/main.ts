import { loadServerConfig } from '@patchpilot/config';
import { checkDatabaseReady } from '@patchpilot/database';
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

  const shutdown = async (signal: string): Promise<void> => {
    logger.info({ signal }, 'worker shutting down');
    await worker.stop();
  };

  process.once('SIGTERM', () => {
    void shutdown('SIGTERM');
  });
  process.once('SIGINT', () => {
    void shutdown('SIGINT');
  });

  await worker.start();
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : 'Unknown startup error';
  process.stderr.write(`Worker failed to start: ${message}\n`);
  process.exitCode = 1;
});
