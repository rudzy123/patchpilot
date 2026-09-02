import { randomUUID } from 'node:crypto';

import {
  createArgon2PasswordHasher,
  createListActiveOrganizationsUseCase,
  createLoginUseCase,
  createLogoutUseCase,
  createNodeRandomTokenGenerator,
  createReadSessionUseCase,
  createResolveSessionUseCase,
  createSelectOrganizationUseCase,
  createSystemClock,
} from '@patchpilot/auth';
import { loadServerConfig } from '@patchpilot/config';
import {
  checkDatabaseReady,
  createPrismaUnitOfWork,
  createRepositories,
  createSbomPersistence,
  createSbomUploadUnitOfWork,
  createIntelligenceStatusReader,
  disconnectPrisma,
  getPrismaClient,
} from '@patchpilot/database';
import { createS3SbomObjectStorage } from '@patchpilot/integrations';
import { createLogger } from '@patchpilot/logger';
import { startTelemetry } from '@patchpilot/observability';

import { buildApi } from './app.js';
import { createAssetRuntime } from './asset-runtime.js';
import { createIntelligenceRuntime } from './intelligence-runtime.js';
import { createRedisLoginRateLimiter } from './redis-login-rate-limiter.js';
import { createSbomRuntime } from './sbom-runtime.js';

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

  const prisma = getPrismaClient({ databaseUrl: config.databaseUrl });
  const repos = createRepositories(prisma);
  const hasher = createArgon2PasswordHasher();
  const tokens = createNodeRandomTokenGenerator();
  const clock = createSystemClock();
  const assets = createAssetRuntime({
    assets: repos.assets,
    environments: repos.environments,
    teams: repos.teams,
    memberships: repos.memberships,
    unitOfWork: createPrismaUnitOfWork({ client: prisma }),
    clock,
  });
  const sbomPersistence = createSbomPersistence(prisma);
  const sboms = createSbomRuntime({
    clock,
    createId: randomUUID,
    assets: repos.assets,
    uploadIdempotency: sbomPersistence.uploadIdempotency,
    sbomMetadata: sbomPersistence.sbomMetadata,
    ingestions: sbomPersistence.ingestions,
    storage: createS3SbomObjectStorage({
      endpoint: config.objectStorage.endpoint,
      region: config.objectStorage.region,
      accessKey: config.objectStorage.accessKey,
      secretKey: config.objectStorage.secretKey,
      bucket: config.objectStorage.bucket,
      useSsl: config.objectStorage.useSsl,
      connectionTimeoutMs: config.objectStorage.connectionTimeoutMs,
      operationTimeoutMs: config.sbom.objectStorageOperationTimeoutMs,
      deploymentEnvironment: config.deploymentEnvironment,
      allowDevelopmentAdapters: config.allowDevelopmentAdapters,
    }),
    unitOfWork: createSbomUploadUnitOfWork(prisma),
    logger: {
      warn(bindings, message) {
        logger.warn(bindings, message);
      },
    },
  });
  const limiter = createRedisLoginRateLimiter({
    redisUrl: config.redisUrl,
    auth: config.auth,
    logger,
  });
  const shared = {
    users: repos.users,
    localCredentials: repos.localCredentials,
    sessions: repos.sessions,
    memberships: repos.memberships,
    clock,
    auth: config.auth,
    logger,
  };

  const app = await buildApi({
    config,
    logger,
    checkDatabaseReady: (timeoutMs) => checkDatabaseReady(timeoutMs),
    auth: {
      login: createLoginUseCase({
        ...shared,
        hasher,
        tokens,
        limiter,
      }),
      logout: createLogoutUseCase({
        sessions: repos.sessions,
        clock,
        logger,
      }),
      resolveSession: createResolveSessionUseCase(shared),
      readSession: createReadSessionUseCase({
        ...shared,
        tokens,
      }),
      selectOrganization: createSelectOrganizationUseCase({
        ...shared,
        tokens,
      }),
      listOrganizations: createListActiveOrganizationsUseCase(shared),
      audit: repos.auditEvents,
    },
    assets,
    sboms,
    intelligence: createIntelligenceRuntime({
      status: createIntelligenceStatusReader(prisma),
      kevEnabled: config.intelligence.kevEnabled,
      staleThresholdSeconds: config.intelligence.kevStaleThresholdSeconds,
      now: () => clock.now(),
    }),
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
      await limiter.close();
      await disconnectPrisma();
      await telemetry.shutdown();
    } finally {
      clearTimeout(timer);
    }
  };

  process.once('SIGTERM', () => {
    void shutdown('SIGTERM').then(
      () => {
        // Intentional successful exit after resources are closed. Remaining
        // handles must not keep the process alive past SIGTERM.
        process.exit(0);
      },
      () => process.exit(1),
    );
  });
  process.once('SIGINT', () => {
    void shutdown('SIGINT').then(
      () => {
        process.exit(0);
      },
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
