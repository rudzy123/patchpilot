import { loadServerConfig } from '@patchpilot/config';
import { checkDatabaseReady } from '@patchpilot/database';
import { createLogger } from '@patchpilot/logger';
import { startTelemetry } from '@patchpilot/observability';

import { buildApi } from './app.js';

async function main(): Promise<void> {
  const config = loadServerConfig();
  if (config.deploymentEnvironment === 'production' && config.prettyLogs) {
    throw new Error('Pretty logs cannot be enabled in production.');
  }

  const logger = createLogger({
    service: 'api',
    level: config.logLevel,
    pretty: config.prettyLogs && config.deploymentEnvironment !== 'production',
  });
  const telemetry = await startTelemetry({
    serviceName: 'api',
    enabled: config.openTelemetry.enabled,
    ...(config.openTelemetry.tracesEndpoint === undefined
      ? {}
      : { tracesEndpoint: config.openTelemetry.tracesEndpoint }),
  });

  const app = await buildApi({
    config,
    logger,
    checkDatabaseReady: (timeoutMs) => checkDatabaseReady(timeoutMs),
  });

  const shutdown = async (signal: string): Promise<void> => {
    logger.info({ signal }, 'shutting down');
    const timer = setTimeout(() => {
      logger.error('shutdown timed out');
    }, config.shutdownTimeoutMs);
    timer.unref();
    await app.close();
    await telemetry.shutdown();
  };

  process.once('SIGTERM', () => {
    void shutdown('SIGTERM');
  });
  process.once('SIGINT', () => {
    void shutdown('SIGINT');
  });

  await app.listen({ host: config.apiHost, port: config.apiPort });
  logger.info({ port: config.apiPort }, 'api listening');
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : 'Unknown startup error';
  process.stderr.write(`API failed to start: ${message}\n`);
  process.exitCode = 1;
});
