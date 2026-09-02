import type { IntelligenceConfig, ServerConfig } from '@patchpilot/config';
import type { CisaKevSynchronizationConfig } from '@patchpilot/domain';
import {
  createCisaKevHttpsTransport,
  createS3IntelligenceSnapshotStorage,
} from '@patchpilot/integrations';
import type { Logger } from '@patchpilot/logger';
import { createKevParserPort } from '@patchpilot/vulnerability-intelligence';

export function cisaKevSynchronizationConfigFrom(
  intelligence: IntelligenceConfig,
): CisaKevSynchronizationConfig {
  return {
    kevEnabled: intelligence.kevEnabled,
    parserVersion: intelligence.parserVersion,
    normalizationVersion: intelligence.normalizationVersion,
    kevResponseMaxBytes: intelligence.kevResponseMaxBytes,
    kevParserTimeoutMs: intelligence.kevParserTimeoutMs,
    kevJobLeaseMs: intelligence.kevJobLeaseMs,
    maxStagedRowsPerTransaction: intelligence.maxStagedRowsPerTransaction,
    syncMaxAttempts: intelligence.syncMaxAttempts,
    syncRetryWaitFloorMs: intelligence.syncRetryWaitFloorMs,
    syncRetryWaitCeilingMs: intelligence.syncRetryWaitCeilingMs,
    jobLeaseRenewalIntervalMs: intelligence.jobLeaseRenewalIntervalMs,
    httpConnectTimeoutMs: intelligence.httpConnectTimeoutMs,
    httpTotalTimeoutMs: intelligence.httpTotalTimeoutMs,
    httpRetryCount: intelligence.httpRetryCount,
    httpBackoffFloorMs: intelligence.httpBackoffFloorMs,
    httpBackoffCeilingMs: intelligence.httpBackoffCeilingMs,
    kevMaxVulnerabilityCount: intelligence.kevMaxVulnerabilityCount,
    kevMaxTextFieldBytes: intelligence.kevMaxTextFieldBytes,
    kevMaxCweCount: intelligence.kevMaxCweCount,
    kevJsonMaxDepth: intelligence.kevJsonMaxDepth,
    kevJsonMaxNodes: intelligence.kevJsonMaxNodes,
    kevJsonMaxStringBytes: intelligence.kevJsonMaxStringBytes,
  };
}

export function createWorkerIntelligenceAdapters(config: ServerConfig, logger: Logger) {
  const log = {
    info(bindings: Record<string, unknown>, message: string) {
      logger.info(bindings, message);
    },
    warn(bindings: Record<string, unknown>, message: string) {
      logger.warn(bindings, message);
    },
  };
  const snapshotStorage = createS3IntelligenceSnapshotStorage({
    endpoint: config.objectStorage.endpoint,
    region: config.objectStorage.region,
    accessKey: config.objectStorage.accessKey,
    secretKey: config.objectStorage.secretKey,
    bucket: config.objectStorage.bucket,
    useSsl: config.objectStorage.useSsl,
    connectionTimeoutMs: config.objectStorage.connectionTimeoutMs,
    operationTimeoutMs: config.intelligence.objectStorageTimeoutMs,
    deploymentEnvironment: config.deploymentEnvironment,
    allowDevelopmentAdapters: config.allowDevelopmentAdapters,
  });
  return {
    snapshotStorage,
    http: createCisaKevHttpsTransport(
      {
        connectTimeoutMs: config.intelligence.httpConnectTimeoutMs,
        totalTimeoutMs: config.intelligence.httpTotalTimeoutMs,
        maxBytes: config.intelligence.kevResponseMaxBytes,
      },
      { logger: log },
    ),
    parser: createKevParserPort(),
  };
}

export async function verifyPrivateIntelligenceStorage(input: {
  storage: {
    verifyPrivateStorageAvailability: () => Promise<{ ok: boolean }>;
    initializeDevelopmentBucket: (init: {
      explicitlyAllowed: true;
      bucket: string;
    }) => Promise<{ ok: boolean }>;
  };
  config: ServerConfig;
}): Promise<{ ok: boolean }> {
  if (
    input.config.deploymentEnvironment !== 'production' &&
    input.config.allowDevelopmentAdapters
  ) {
    const initialized = await input.storage.initializeDevelopmentBucket({
      explicitlyAllowed: true,
      bucket: input.config.objectStorage.bucket,
    });
    if (!initialized.ok) {
      return { ok: false };
    }
  }
  const verified = await input.storage.verifyPrivateStorageAvailability();
  return { ok: verified.ok };
}
