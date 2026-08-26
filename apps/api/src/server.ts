import { loadServerConfig } from '@patchpilot/config';
import { checkDatabaseReady, disconnectPrisma } from '@patchpilot/database';
import { createLogger } from '@patchpilot/logger';
import { startTelemetry } from '@patchpilot/observability';

import { buildApi } from './app.js';

async function main(): Promise<void> {
  const config = loadServerConfig();
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

  let shuttingDown = false;
  const shutdown = async (signal: string): Promise<void> => {
    if (shuttingDown) {
      return;
    }

    shuttingDown = true;
    logger.info({ signal }, 'shutting down');
    const timer = setTimeout(() => {
      logger.error('shutdown timed out');
      process.exit(1);
    }, config.shutdownTimeoutMs);
    try {
      await app.close();
      await disconnectPrisma();
      await telemetry.shutdown();
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

  await app.listen({ host: config.apiHost, port: config.apiPort });
  logger.info({ port: config.apiPort }, 'api listening');
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : 'Unknown startup error';
  process.stderr.write(`API failed to start: ${message}\n`);
  process.exit(1);
});
