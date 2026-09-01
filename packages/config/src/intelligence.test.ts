import { afterEach, describe, expect, it, vi } from 'vitest';

import { DEVELOPMENT_SESSION_COOKIE_NAME, PRODUCTION_SESSION_COOKIE_NAME } from './auth.js';
import {
  INTELLIGENCE_HTTP_BACKOFF_CEILING_MS_DEFAULT,
  INTELLIGENCE_HTTP_BACKOFF_CEILING_MS_MAX,
  INTELLIGENCE_HTTP_BACKOFF_CEILING_MS_MIN,
  INTELLIGENCE_HTTP_BACKOFF_FLOOR_MS_DEFAULT,
  INTELLIGENCE_HTTP_BACKOFF_FLOOR_MS_MAX,
  INTELLIGENCE_HTTP_BACKOFF_FLOOR_MS_MIN,
  INTELLIGENCE_HTTP_CONNECT_TIMEOUT_MS_DEFAULT,
  INTELLIGENCE_HTTP_CONNECT_TIMEOUT_MS_MAX,
  INTELLIGENCE_HTTP_CONNECT_TIMEOUT_MS_MIN,
  INTELLIGENCE_HTTP_REDIRECT_MAX,
  INTELLIGENCE_HTTP_RETRY_COUNT_DEFAULT,
  INTELLIGENCE_HTTP_RETRY_COUNT_MAX,
  INTELLIGENCE_HTTP_RETRY_COUNT_MIN,
  INTELLIGENCE_HTTP_TOTAL_TIMEOUT_MS_DEFAULT,
  INTELLIGENCE_HTTP_TOTAL_TIMEOUT_MS_MAX,
  INTELLIGENCE_HTTP_TOTAL_TIMEOUT_MS_MIN,
  INTELLIGENCE_KEV_ENABLED_DEFAULT,
  INTELLIGENCE_KEV_HOSTNAME,
  INTELLIGENCE_KEV_JOB_LEASE_MS_DEFAULT,
  INTELLIGENCE_KEV_JOB_LEASE_MS_MAX,
  INTELLIGENCE_KEV_JOB_LEASE_MS_MIN,
  INTELLIGENCE_KEV_JSON_MAX_DEPTH_DEFAULT,
  INTELLIGENCE_KEV_JSON_MAX_DEPTH_MAX,
  INTELLIGENCE_KEV_JSON_MAX_DEPTH_MIN,
  INTELLIGENCE_KEV_JSON_MAX_NODES_DEFAULT,
  INTELLIGENCE_KEV_JSON_MAX_NODES_MAX,
  INTELLIGENCE_KEV_JSON_MAX_NODES_MIN,
  INTELLIGENCE_KEV_JSON_MAX_STRING_BYTES_DEFAULT,
  INTELLIGENCE_KEV_JSON_MAX_STRING_BYTES_MAX,
  INTELLIGENCE_KEV_JSON_MAX_STRING_BYTES_MIN,
  INTELLIGENCE_KEV_MAX_CWE_COUNT_DEFAULT,
  INTELLIGENCE_KEV_MAX_CWE_COUNT_MAX,
  INTELLIGENCE_KEV_MAX_CWE_COUNT_MIN,
  INTELLIGENCE_KEV_MAX_TEXT_FIELD_BYTES_DEFAULT,
  INTELLIGENCE_KEV_MAX_TEXT_FIELD_BYTES_MAX,
  INTELLIGENCE_KEV_MAX_TEXT_FIELD_BYTES_MIN,
  INTELLIGENCE_KEV_MAX_VULNERABILITY_COUNT_DEFAULT,
  INTELLIGENCE_KEV_MAX_VULNERABILITY_COUNT_MAX,
  INTELLIGENCE_KEV_MAX_VULNERABILITY_COUNT_MIN,
  INTELLIGENCE_KEV_ORIGIN,
  INTELLIGENCE_KEV_PARSER_TIMEOUT_MS_DEFAULT,
  INTELLIGENCE_KEV_PARSER_TIMEOUT_MS_MAX,
  INTELLIGENCE_KEV_PARSER_TIMEOUT_MS_MIN,
  INTELLIGENCE_KEV_PATH,
  INTELLIGENCE_KEV_RESPONSE_MAX_BYTES_DEFAULT,
  INTELLIGENCE_KEV_RESPONSE_MAX_BYTES_MAX,
  INTELLIGENCE_KEV_RESPONSE_MAX_BYTES_MIN,
  INTELLIGENCE_KEV_STALE_THRESHOLD_SECONDS_DEFAULT,
  INTELLIGENCE_KEV_STALE_THRESHOLD_SECONDS_MAX,
  INTELLIGENCE_KEV_STALE_THRESHOLD_SECONDS_MIN,
  INTELLIGENCE_KEV_SYNC_INTERVAL_SECONDS_DEFAULT,
  INTELLIGENCE_KEV_SYNC_INTERVAL_SECONDS_MAX,
  INTELLIGENCE_KEV_SYNC_INTERVAL_SECONDS_MIN,
  INTELLIGENCE_MAX_STAGED_ROWS_PER_TRANSACTION_DEFAULT,
  INTELLIGENCE_MAX_STAGED_ROWS_PER_TRANSACTION_MAX,
  INTELLIGENCE_MAX_STAGED_ROWS_PER_TRANSACTION_MIN,
  INTELLIGENCE_SYNC_MAX_ATTEMPTS_DEFAULT,
  INTELLIGENCE_SYNC_MAX_ATTEMPTS_MAX,
  INTELLIGENCE_SYNC_MAX_ATTEMPTS_MIN,
  INTELLIGENCE_SYNC_RETRY_WAIT_FLOOR_MS_DEFAULT,
  INTELLIGENCE_SYNC_RETRY_WAIT_FLOOR_MS_MAX,
  INTELLIGENCE_SYNC_RETRY_WAIT_FLOOR_MS_MIN,
  INTELLIGENCE_SYNC_RETRY_WAIT_CEILING_MS_DEFAULT,
  INTELLIGENCE_SYNC_RETRY_WAIT_CEILING_MS_MAX,
  INTELLIGENCE_SYNC_RETRY_WAIT_CEILING_MS_MIN,
  INTELLIGENCE_JOB_LEASE_RENEWAL_INTERVAL_MS_DEFAULT,
  INTELLIGENCE_JOB_LEASE_RENEWAL_INTERVAL_MS_MAX,
  INTELLIGENCE_JOB_LEASE_RENEWAL_INTERVAL_MS_MIN,
  INTELLIGENCE_STAGING_TRANSACTION_BUDGET_MS,
  INTELLIGENCE_NORMALIZATION_VERSION_DEFAULT,
  INTELLIGENCE_OBJECT_STORAGE_TIMEOUT_MS_DEFAULT,
  INTELLIGENCE_OBJECT_STORAGE_TIMEOUT_MS_MAX,
  INTELLIGENCE_OBJECT_STORAGE_TIMEOUT_MS_MIN,
  INTELLIGENCE_ORPHAN_GRACE_SECONDS_DEFAULT,
  INTELLIGENCE_ORPHAN_GRACE_SECONDS_MAX,
  INTELLIGENCE_ORPHAN_GRACE_SECONDS_MIN,
  INTELLIGENCE_OSV_ENABLED_DEFAULT,
  INTELLIGENCE_OSV_ENABLED_SESSION9_ERROR,
  INTELLIGENCE_OSV_RUNTIME_STATUS,
  INTELLIGENCE_PARSER_VERSION_DEFAULT,
  INTELLIGENCE_SNAPSHOT_RETENTION_COUNT_DEFAULT,
  INTELLIGENCE_SNAPSHOT_RETENTION_COUNT_MAX,
  INTELLIGENCE_SNAPSHOT_RETENTION_COUNT_MIN,
  INTELLIGENCE_STAGING_GENERATION_MAX_AGE_SECONDS_DEFAULT,
  INTELLIGENCE_STAGING_GENERATION_MAX_AGE_SECONDS_MAX,
  INTELLIGENCE_STAGING_GENERATION_MAX_AGE_SECONDS_MIN,
  INTELLIGENCE_VERSION_LABEL_MAX_LENGTH,
  compiledIntelligenceKevSource,
  intelligenceDefaultEnvironmentVariables,
  intelligenceHttpWorstCaseBudgetMs,
  intelligenceRelationshipIssues,
  type IntelligenceConfig,
  type IntelligenceRelationshipIssue,
} from './intelligence.js';
import { ConfigValidationError, loadServerConfigFrom } from './server.js';
import {
  OBJECT_STORAGE_CONNECTION_TIMEOUT_MS_DEFAULT,
  OBJECT_STORAGE_OPERATION_TIMEOUT_MS_DEFAULT,
  SBOM_UPLOAD_MAX_BYTES_DEFAULT,
  sbomDefaultEnvironmentVariables,
} from './sbom.js';

function developmentAuthEnv(): Record<string, string> {
  return {
    AUTH_SESSION_ABSOLUTE_TTL_SECONDS: '604800',
    AUTH_SESSION_IDLE_TTL_SECONDS: '43200',
    AUTH_SESSION_LAST_SEEN_MIN_INTERVAL_SECONDS: '60',
    AUTH_COOKIE_NAME: DEVELOPMENT_SESSION_COOKIE_NAME,
    AUTH_COOKIE_SECURE: 'false',
    AUTH_CSRF_HEADER_NAME: 'x-csrf-token',
    AUTH_PASSWORD_MIN_LENGTH: '12',
    AUTH_PASSWORD_MAX_BYTES: '128',
    AUTH_ARGON2_MEMORY_KIB: '19456',
    AUTH_ARGON2_TIME_COST: '2',
    AUTH_ARGON2_PARALLELISM: '1',
    AUTH_LOGIN_RATE_LIMIT_IP_MAX: '10',
    AUTH_LOGIN_RATE_LIMIT_IP_WINDOW_SECONDS: '900',
    AUTH_LOGIN_RATE_LIMIT_ACCOUNT_MAX: '5',
    AUTH_LOGIN_RATE_LIMIT_ACCOUNT_WINDOW_SECONDS: '900',
    AUTH_RATE_LIMIT_REDIS_TIMEOUT_MS: '200',
  };
}

function validDevelopmentEnv(): Record<string, string> {
  return {
    PATCHPILOT_DEPLOYMENT_ENVIRONMENT: 'development',
    PATCHPILOT_ALLOW_DEVELOPMENT_ADAPTERS: 'true',
    LOG_LEVEL: 'info',
    LOG_PRETTY: 'true',
    API_HOST: '127.0.0.1',
    API_PORT: '3001',
    WEB_PORT: '3000',
    CORS_ALLOWED_ORIGINS: 'http://127.0.0.1:3000',
    DATABASE_URL:
      'postgresql://patchpilot-dev:patchpilot-dev-not-for-production@127.0.0.1:55432/patchpilot',
    REDIS_URL: 'redis://127.0.0.1:16379',
    OBJECT_STORAGE_ENDPOINT: 'http://127.0.0.1:19000',
    OBJECT_STORAGE_ACCESS_KEY: 'patchpilot-dev-access',
    OBJECT_STORAGE_SECRET_KEY: 'patchpilot-dev-secret-not-for-production',
    OBJECT_STORAGE_BUCKET: 'patchpilot-dev',
    OBJECT_STORAGE_USE_SSL: 'false',
    OTEL_ENABLED: 'false',
    READINESS_TIMEOUT_MS: '1000',
    SHUTDOWN_TIMEOUT_MS: '10000',
    REQUEST_BODY_LIMIT_BYTES: '1048576',
    REQUEST_ID_HEADER: 'x-request-id',
    CORRELATION_ID_HEADER: 'x-correlation-id',
    ...sbomDefaultEnvironmentVariables(),
    ...intelligenceDefaultEnvironmentVariables(),
    ...developmentAuthEnv(),
  };
}

function validProductionEnv(): Record<string, string> {
  return {
    ...validDevelopmentEnv(),
    PATCHPILOT_DEPLOYMENT_ENVIRONMENT: 'production',
    PATCHPILOT_ALLOW_DEVELOPMENT_ADAPTERS: 'false',
    LOG_PRETTY: 'false',
    CORS_ALLOWED_ORIGINS: 'https://patchpilot.example',
    DATABASE_URL: 'postgresql://patchpilot:operator-secret@db.internal:5432/patchpilot',
    REDIS_URL: 'redis://:operator-redis-secret@redis.internal:6379',
    OBJECT_STORAGE_ENDPOINT: 'https://objects.internal:9000',
    OBJECT_STORAGE_ACCESS_KEY: 'operator-supplied-access-key',
    OBJECT_STORAGE_SECRET_KEY: 'operator-supplied-secret-key-value',
    OBJECT_STORAGE_BUCKET: 'patchpilot',
    OBJECT_STORAGE_USE_SSL: 'true',
    AUTH_COOKIE_NAME: PRODUCTION_SESSION_COOKIE_NAME,
    AUTH_COOKIE_SECURE: 'true',
  };
}

function validTestEnv(): Record<string, string> {
  return {
    ...validDevelopmentEnv(),
    PATCHPILOT_DEPLOYMENT_ENVIRONMENT: 'test',
    LOG_PRETTY: 'false',
    AUTH_ARGON2_MEMORY_KIB: '8192',
    AUTH_ARGON2_TIME_COST: '1',
  };
}

function expectRejection(env: Record<string, string>, pattern: RegExp): void {
  expect(() => loadServerConfigFrom(env)).toThrow(ConfigValidationError);
  expect(() => loadServerConfigFrom(env)).toThrow(pattern);
}

function relationshipSafeEnv(): Record<string, string> {
  const env = validDevelopmentEnv();
  env['INTELLIGENCE_KEV_JOB_LEASE_MS'] = String(INTELLIGENCE_KEV_JOB_LEASE_MS_MAX);
  env['INTELLIGENCE_KEV_PARSER_TIMEOUT_MS'] = String(INTELLIGENCE_KEV_PARSER_TIMEOUT_MS_MIN);
  env['INTELLIGENCE_OBJECT_STORAGE_TIMEOUT_MS'] = String(
    INTELLIGENCE_OBJECT_STORAGE_TIMEOUT_MS_MIN,
  );
  env['INTELLIGENCE_HTTP_CONNECT_TIMEOUT_MS'] = String(INTELLIGENCE_HTTP_CONNECT_TIMEOUT_MS_MIN);
  env['INTELLIGENCE_HTTP_TOTAL_TIMEOUT_MS'] = String(INTELLIGENCE_HTTP_TOTAL_TIMEOUT_MS_DEFAULT);
  env['INTELLIGENCE_HTTP_RETRY_COUNT'] = String(INTELLIGENCE_HTTP_RETRY_COUNT_MIN);
  env['INTELLIGENCE_HTTP_BACKOFF_FLOOR_MS'] = String(INTELLIGENCE_HTTP_BACKOFF_FLOOR_MS_MIN);
  env['INTELLIGENCE_HTTP_BACKOFF_CEILING_MS'] = String(INTELLIGENCE_HTTP_BACKOFF_CEILING_MS_MAX);
  env['INTELLIGENCE_KEV_SYNC_INTERVAL_SECONDS'] = String(
    INTELLIGENCE_KEV_SYNC_INTERVAL_SECONDS_MIN,
  );
  env['INTELLIGENCE_KEV_STALE_THRESHOLD_SECONDS'] = String(
    INTELLIGENCE_KEV_STALE_THRESHOLD_SECONDS_MAX,
  );
  env['INTELLIGENCE_KEV_MAX_TEXT_FIELD_BYTES'] = String(INTELLIGENCE_KEV_MAX_TEXT_FIELD_BYTES_MIN);
  env['INTELLIGENCE_KEV_JSON_MAX_STRING_BYTES'] = String(
    INTELLIGENCE_KEV_JSON_MAX_STRING_BYTES_MAX,
  );
  env['INTELLIGENCE_ORPHAN_GRACE_SECONDS'] = String(INTELLIGENCE_ORPHAN_GRACE_SECONDS_MAX);
  env['INTELLIGENCE_STAGING_GENERATION_MAX_AGE_SECONDS'] = String(
    INTELLIGENCE_STAGING_GENERATION_MAX_AGE_SECONDS_MAX,
  );
  env['INTELLIGENCE_SYNC_RETRY_WAIT_FLOOR_MS'] = String(INTELLIGENCE_SYNC_RETRY_WAIT_FLOOR_MS_MIN);
  env['INTELLIGENCE_SYNC_RETRY_WAIT_CEILING_MS'] = String(
    INTELLIGENCE_SYNC_RETRY_WAIT_CEILING_MS_MAX,
  );
  env['INTELLIGENCE_JOB_LEASE_RENEWAL_INTERVAL_MS'] = String(
    INTELLIGENCE_JOB_LEASE_RENEWAL_INTERVAL_MS_MIN,
  );
  return env;
}

type IntelligenceNumericKey = keyof Omit<
  IntelligenceConfig,
  | 'kevEnabled'
  | 'osvEnabled'
  | 'kevSource'
  | 'osvRuntime'
  | 'httpRedirectMax'
  | 'parserVersion'
  | 'normalizationVersion'
>;

const boundedNumericLimits: Array<{
  envKey: string;
  configKey: IntelligenceNumericKey;
  min: number;
  max: number;
}> = [
  {
    envKey: 'INTELLIGENCE_KEV_SYNC_INTERVAL_SECONDS',
    configKey: 'kevSyncIntervalSeconds',
    min: INTELLIGENCE_KEV_SYNC_INTERVAL_SECONDS_MIN,
    max: INTELLIGENCE_KEV_SYNC_INTERVAL_SECONDS_MAX,
  },
  {
    envKey: 'INTELLIGENCE_KEV_STALE_THRESHOLD_SECONDS',
    configKey: 'kevStaleThresholdSeconds',
    min: INTELLIGENCE_KEV_STALE_THRESHOLD_SECONDS_MIN,
    max: INTELLIGENCE_KEV_STALE_THRESHOLD_SECONDS_MAX,
  },
  {
    envKey: 'INTELLIGENCE_HTTP_CONNECT_TIMEOUT_MS',
    configKey: 'httpConnectTimeoutMs',
    min: INTELLIGENCE_HTTP_CONNECT_TIMEOUT_MS_MIN,
    max: INTELLIGENCE_HTTP_CONNECT_TIMEOUT_MS_MAX,
  },
  {
    envKey: 'INTELLIGENCE_HTTP_TOTAL_TIMEOUT_MS',
    configKey: 'httpTotalTimeoutMs',
    min: INTELLIGENCE_HTTP_TOTAL_TIMEOUT_MS_MIN,
    max: INTELLIGENCE_HTTP_TOTAL_TIMEOUT_MS_MAX,
  },
  {
    envKey: 'INTELLIGENCE_HTTP_RETRY_COUNT',
    configKey: 'httpRetryCount',
    min: INTELLIGENCE_HTTP_RETRY_COUNT_MIN,
    max: INTELLIGENCE_HTTP_RETRY_COUNT_MAX,
  },
  {
    envKey: 'INTELLIGENCE_HTTP_BACKOFF_FLOOR_MS',
    configKey: 'httpBackoffFloorMs',
    min: INTELLIGENCE_HTTP_BACKOFF_FLOOR_MS_MIN,
    max: INTELLIGENCE_HTTP_BACKOFF_FLOOR_MS_MAX,
  },
  {
    envKey: 'INTELLIGENCE_HTTP_BACKOFF_CEILING_MS',
    configKey: 'httpBackoffCeilingMs',
    min: INTELLIGENCE_HTTP_BACKOFF_CEILING_MS_MIN,
    max: INTELLIGENCE_HTTP_BACKOFF_CEILING_MS_MAX,
  },
  {
    envKey: 'INTELLIGENCE_KEV_RESPONSE_MAX_BYTES',
    configKey: 'kevResponseMaxBytes',
    min: INTELLIGENCE_KEV_RESPONSE_MAX_BYTES_MIN,
    max: INTELLIGENCE_KEV_RESPONSE_MAX_BYTES_MAX,
  },
  {
    envKey: 'INTELLIGENCE_KEV_MAX_VULNERABILITY_COUNT',
    configKey: 'kevMaxVulnerabilityCount',
    min: INTELLIGENCE_KEV_MAX_VULNERABILITY_COUNT_MIN,
    max: INTELLIGENCE_KEV_MAX_VULNERABILITY_COUNT_MAX,
  },
  {
    envKey: 'INTELLIGENCE_KEV_MAX_TEXT_FIELD_BYTES',
    configKey: 'kevMaxTextFieldBytes',
    min: INTELLIGENCE_KEV_MAX_TEXT_FIELD_BYTES_MIN,
    max: INTELLIGENCE_KEV_MAX_TEXT_FIELD_BYTES_MAX,
  },
  {
    envKey: 'INTELLIGENCE_KEV_MAX_CWE_COUNT',
    configKey: 'kevMaxCweCount',
    min: INTELLIGENCE_KEV_MAX_CWE_COUNT_MIN,
    max: INTELLIGENCE_KEV_MAX_CWE_COUNT_MAX,
  },
  {
    envKey: 'INTELLIGENCE_KEV_JSON_MAX_DEPTH',
    configKey: 'kevJsonMaxDepth',
    min: INTELLIGENCE_KEV_JSON_MAX_DEPTH_MIN,
    max: INTELLIGENCE_KEV_JSON_MAX_DEPTH_MAX,
  },
  {
    envKey: 'INTELLIGENCE_KEV_JSON_MAX_NODES',
    configKey: 'kevJsonMaxNodes',
    min: INTELLIGENCE_KEV_JSON_MAX_NODES_MIN,
    max: INTELLIGENCE_KEV_JSON_MAX_NODES_MAX,
  },
  {
    envKey: 'INTELLIGENCE_KEV_JSON_MAX_STRING_BYTES',
    configKey: 'kevJsonMaxStringBytes',
    min: INTELLIGENCE_KEV_JSON_MAX_STRING_BYTES_MIN,
    max: INTELLIGENCE_KEV_JSON_MAX_STRING_BYTES_MAX,
  },
  {
    envKey: 'INTELLIGENCE_KEV_PARSER_TIMEOUT_MS',
    configKey: 'kevParserTimeoutMs',
    min: INTELLIGENCE_KEV_PARSER_TIMEOUT_MS_MIN,
    max: INTELLIGENCE_KEV_PARSER_TIMEOUT_MS_MAX,
  },
  {
    envKey: 'INTELLIGENCE_KEV_JOB_LEASE_MS',
    configKey: 'kevJobLeaseMs',
    min: INTELLIGENCE_KEV_JOB_LEASE_MS_MIN,
    max: INTELLIGENCE_KEV_JOB_LEASE_MS_MAX,
  },
  {
    envKey: 'INTELLIGENCE_OBJECT_STORAGE_TIMEOUT_MS',
    configKey: 'objectStorageTimeoutMs',
    min: INTELLIGENCE_OBJECT_STORAGE_TIMEOUT_MS_MIN,
    max: INTELLIGENCE_OBJECT_STORAGE_TIMEOUT_MS_MAX,
  },
  {
    envKey: 'INTELLIGENCE_ORPHAN_GRACE_SECONDS',
    configKey: 'orphanGraceSeconds',
    min: INTELLIGENCE_ORPHAN_GRACE_SECONDS_MIN,
    max: INTELLIGENCE_ORPHAN_GRACE_SECONDS_MAX,
  },
  {
    envKey: 'INTELLIGENCE_SNAPSHOT_RETENTION_COUNT',
    configKey: 'snapshotRetentionCount',
    min: INTELLIGENCE_SNAPSHOT_RETENTION_COUNT_MIN,
    max: INTELLIGENCE_SNAPSHOT_RETENTION_COUNT_MAX,
  },
  {
    envKey: 'INTELLIGENCE_STAGING_GENERATION_MAX_AGE_SECONDS',
    configKey: 'stagingGenerationMaxAgeSeconds',
    min: INTELLIGENCE_STAGING_GENERATION_MAX_AGE_SECONDS_MIN,
    max: INTELLIGENCE_STAGING_GENERATION_MAX_AGE_SECONDS_MAX,
  },
  {
    envKey: 'INTELLIGENCE_MAX_STAGED_ROWS_PER_TRANSACTION',
    configKey: 'maxStagedRowsPerTransaction',
    min: INTELLIGENCE_MAX_STAGED_ROWS_PER_TRANSACTION_MIN,
    max: INTELLIGENCE_MAX_STAGED_ROWS_PER_TRANSACTION_MAX,
  },
  {
    envKey: 'INTELLIGENCE_SYNC_MAX_ATTEMPTS',
    configKey: 'syncMaxAttempts',
    min: INTELLIGENCE_SYNC_MAX_ATTEMPTS_MIN,
    max: INTELLIGENCE_SYNC_MAX_ATTEMPTS_MAX,
  },
  {
    envKey: 'INTELLIGENCE_SYNC_RETRY_WAIT_FLOOR_MS',
    configKey: 'syncRetryWaitFloorMs',
    min: INTELLIGENCE_SYNC_RETRY_WAIT_FLOOR_MS_MIN,
    max: INTELLIGENCE_SYNC_RETRY_WAIT_FLOOR_MS_MAX,
  },
  {
    envKey: 'INTELLIGENCE_SYNC_RETRY_WAIT_CEILING_MS',
    configKey: 'syncRetryWaitCeilingMs',
    min: INTELLIGENCE_SYNC_RETRY_WAIT_CEILING_MS_MIN,
    max: INTELLIGENCE_SYNC_RETRY_WAIT_CEILING_MS_MAX,
  },
  {
    envKey: 'INTELLIGENCE_JOB_LEASE_RENEWAL_INTERVAL_MS',
    configKey: 'jobLeaseRenewalIntervalMs',
    min: INTELLIGENCE_JOB_LEASE_RENEWAL_INTERVAL_MS_MIN,
    max: INTELLIGENCE_JOB_LEASE_RENEWAL_INTERVAL_MS_MAX,
  },
];

function defaultIntelligenceConfig(): IntelligenceConfig {
  return loadServerConfigFrom(validDevelopmentEnv()).intelligence;
}

function issueOn(
  issues: IntelligenceRelationshipIssue[],
  key: string,
): IntelligenceRelationshipIssue | undefined {
  return issues.find((issue) => issue.path[0] === key);
}

describe('vulnerability intelligence configuration', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('loads complete valid default configuration', () => {
    const config = loadServerConfigFrom(validDevelopmentEnv());
    const source = compiledIntelligenceKevSource();
    expect(config.intelligence).toEqual({
      kevEnabled: INTELLIGENCE_KEV_ENABLED_DEFAULT,
      osvEnabled: INTELLIGENCE_OSV_ENABLED_DEFAULT,
      kevSource: source,
      osvRuntime: INTELLIGENCE_OSV_RUNTIME_STATUS,
      httpRedirectMax: INTELLIGENCE_HTTP_REDIRECT_MAX,
      kevSyncIntervalSeconds: INTELLIGENCE_KEV_SYNC_INTERVAL_SECONDS_DEFAULT,
      kevStaleThresholdSeconds: INTELLIGENCE_KEV_STALE_THRESHOLD_SECONDS_DEFAULT,
      httpConnectTimeoutMs: INTELLIGENCE_HTTP_CONNECT_TIMEOUT_MS_DEFAULT,
      httpTotalTimeoutMs: INTELLIGENCE_HTTP_TOTAL_TIMEOUT_MS_DEFAULT,
      httpRetryCount: INTELLIGENCE_HTTP_RETRY_COUNT_DEFAULT,
      httpBackoffFloorMs: INTELLIGENCE_HTTP_BACKOFF_FLOOR_MS_DEFAULT,
      httpBackoffCeilingMs: INTELLIGENCE_HTTP_BACKOFF_CEILING_MS_DEFAULT,
      kevResponseMaxBytes: INTELLIGENCE_KEV_RESPONSE_MAX_BYTES_DEFAULT,
      kevMaxVulnerabilityCount: INTELLIGENCE_KEV_MAX_VULNERABILITY_COUNT_DEFAULT,
      kevMaxTextFieldBytes: INTELLIGENCE_KEV_MAX_TEXT_FIELD_BYTES_DEFAULT,
      kevMaxCweCount: INTELLIGENCE_KEV_MAX_CWE_COUNT_DEFAULT,
      kevJsonMaxDepth: INTELLIGENCE_KEV_JSON_MAX_DEPTH_DEFAULT,
      kevJsonMaxNodes: INTELLIGENCE_KEV_JSON_MAX_NODES_DEFAULT,
      kevJsonMaxStringBytes: INTELLIGENCE_KEV_JSON_MAX_STRING_BYTES_DEFAULT,
      kevParserTimeoutMs: INTELLIGENCE_KEV_PARSER_TIMEOUT_MS_DEFAULT,
      parserVersion: INTELLIGENCE_PARSER_VERSION_DEFAULT,
      normalizationVersion: INTELLIGENCE_NORMALIZATION_VERSION_DEFAULT,
      kevJobLeaseMs: INTELLIGENCE_KEV_JOB_LEASE_MS_DEFAULT,
      objectStorageTimeoutMs: INTELLIGENCE_OBJECT_STORAGE_TIMEOUT_MS_DEFAULT,
      orphanGraceSeconds: INTELLIGENCE_ORPHAN_GRACE_SECONDS_DEFAULT,
      snapshotRetentionCount: INTELLIGENCE_SNAPSHOT_RETENTION_COUNT_DEFAULT,
      stagingGenerationMaxAgeSeconds: INTELLIGENCE_STAGING_GENERATION_MAX_AGE_SECONDS_DEFAULT,
      maxStagedRowsPerTransaction: INTELLIGENCE_MAX_STAGED_ROWS_PER_TRANSACTION_DEFAULT,
      syncMaxAttempts: INTELLIGENCE_SYNC_MAX_ATTEMPTS_DEFAULT,
      syncRetryWaitFloorMs: INTELLIGENCE_SYNC_RETRY_WAIT_FLOOR_MS_DEFAULT,
      syncRetryWaitCeilingMs: INTELLIGENCE_SYNC_RETRY_WAIT_CEILING_MS_DEFAULT,
      jobLeaseRenewalIntervalMs: INTELLIGENCE_JOB_LEASE_RENEWAL_INTERVAL_MS_DEFAULT,
    });
    expect(config.intelligence.kevEnabled).toBe(true);
    expect(config.intelligence.osvEnabled).toBe(false);
  });

  it('allows KEV to be disabled without enabling OSV', () => {
    const env = validDevelopmentEnv();
    env['INTELLIGENCE_KEV_ENABLED'] = 'false';
    const config = loadServerConfigFrom(env);
    expect(config.intelligence.kevEnabled).toBe(false);
    expect(config.intelligence.osvEnabled).toBe(false);
  });

  it('accepts OSV disabled in development, test, and production', () => {
    expect(loadServerConfigFrom(validDevelopmentEnv()).intelligence.osvEnabled).toBe(false);
    expect(loadServerConfigFrom(validTestEnv()).intelligence.osvEnabled).toBe(false);
    expect(loadServerConfigFrom(validProductionEnv()).intelligence.osvEnabled).toBe(false);
  });

  it('rejects OSV enabled in development', () => {
    const env = validDevelopmentEnv();
    env['INTELLIGENCE_OSV_ENABLED'] = 'true';
    expectRejection(env, new RegExp(INTELLIGENCE_OSV_ENABLED_SESSION9_ERROR));
  });

  it('rejects OSV enabled in test', () => {
    const env = validTestEnv();
    env['INTELLIGENCE_OSV_ENABLED'] = 'true';
    expectRejection(env, new RegExp(INTELLIGENCE_OSV_ENABLED_SESSION9_ERROR));
  });

  it('rejects OSV enabled in production', () => {
    const env = validProductionEnv();
    env['INTELLIGENCE_OSV_ENABLED'] = 'true';
    expectRejection(env, new RegExp(INTELLIGENCE_OSV_ENABLED_SESSION9_ERROR));
  });

  it('rejects mixed-case and malformed boolean forms', () => {
    for (const raw of ['TRUE', 'True', 'yes', '1', 'on', 'FALSE', 'False', '0']) {
      const kevEnv = validDevelopmentEnv();
      kevEnv['INTELLIGENCE_KEV_ENABLED'] = raw;
      expect(() => loadServerConfigFrom(kevEnv)).toThrow(ConfigValidationError);
      expect(() => loadServerConfigFrom(kevEnv)).toThrow(/must be "true" or "false"/);

      const osvEnv = validDevelopmentEnv();
      osvEnv['INTELLIGENCE_OSV_ENABLED'] = raw;
      expect(() => loadServerConfigFrom(osvEnv)).toThrow(ConfigValidationError);
      expect(() => loadServerConfigFrom(osvEnv)).toThrow(/must be "true" or "false"/);
    }
  });

  it('accepts each numeric floor', () => {
    for (const limit of boundedNumericLimits) {
      const env = relationshipSafeEnv();
      env[limit.envKey] = String(limit.min);
      expect(loadServerConfigFrom(env).intelligence[limit.configKey], limit.envKey).toBe(limit.min);
    }
  });

  it('accepts each numeric ceiling', () => {
    for (const limit of boundedNumericLimits) {
      const env = relationshipSafeEnv();
      env[limit.envKey] = String(limit.max);
      expect(loadServerConfigFrom(env).intelligence[limit.configKey], limit.envKey).toBe(limit.max);
    }
  });

  it('rejects each numeric value below its floor', () => {
    for (const limit of boundedNumericLimits) {
      const env = relationshipSafeEnv();
      env[limit.envKey] = String(limit.min - 1);
      expect(() => loadServerConfigFrom(env), limit.envKey).toThrow(ConfigValidationError);
    }
  });

  it('rejects each numeric value above its ceiling', () => {
    for (const limit of boundedNumericLimits) {
      const env = relationshipSafeEnv();
      env[limit.envKey] = String(limit.max + 1);
      expect(() => loadServerConfigFrom(env), limit.envKey).toThrow(ConfigValidationError);
    }
  });

  it('rejects malformed, scientific, decimal, negative, and unsafe integers', () => {
    for (const limit of boundedNumericLimits) {
      for (const raw of ['', '  ', '20.5', '1e7', 'NaN', 'Infinity', '-1', '010', '+8', '0x10']) {
        const env = relationshipSafeEnv();
        env[limit.envKey] = raw;
        expect(() => loadServerConfigFrom(env), `${limit.envKey}=${raw}`).toThrow(
          ConfigValidationError,
        );
      }

      const unsafeEnv = relationshipSafeEnv();
      unsafeEnv[limit.envKey] = '9007199254740993';
      expect(() => loadServerConfigFrom(unsafeEnv), limit.envKey).toThrow(ConfigValidationError);
    }
  });

  it('rejects connect timeout equal to total timeout', () => {
    const env = validDevelopmentEnv();
    env['INTELLIGENCE_HTTP_CONNECT_TIMEOUT_MS'] = '5000';
    env['INTELLIGENCE_HTTP_TOTAL_TIMEOUT_MS'] = '5000';
    expectRejection(
      env,
      /INTELLIGENCE_HTTP_CONNECT_TIMEOUT_MS must be strictly less than INTELLIGENCE_HTTP_TOTAL_TIMEOUT_MS/,
    );
  });

  it('accepts connect timeout less than total timeout', () => {
    const env = validDevelopmentEnv();
    env['INTELLIGENCE_HTTP_CONNECT_TIMEOUT_MS'] = '5000';
    env['INTELLIGENCE_HTTP_TOTAL_TIMEOUT_MS'] = '60000';
    const config = loadServerConfigFrom(env);
    expect(config.intelligence.httpConnectTimeoutMs).toBe(5_000);
    expect(config.intelligence.httpTotalTimeoutMs).toBe(60_000);
  });

  it('rejects backoff floor above ceiling', () => {
    const env = relationshipSafeEnv();
    env['INTELLIGENCE_HTTP_BACKOFF_FLOOR_MS'] = '10000';
    env['INTELLIGENCE_HTTP_BACKOFF_CEILING_MS'] = '1000';
    expectRejection(
      env,
      /INTELLIGENCE_HTTP_BACKOFF_FLOOR_MS must be less than or equal to INTELLIGENCE_HTTP_BACKOFF_CEILING_MS/,
    );
  });

  it('rejects sync retry-wait floor above ceiling', () => {
    const env = relationshipSafeEnv();
    env['INTELLIGENCE_SYNC_RETRY_WAIT_FLOOR_MS'] = '300000';
    env['INTELLIGENCE_SYNC_RETRY_WAIT_CEILING_MS'] = '10000';
    expectRejection(
      env,
      /INTELLIGENCE_SYNC_RETRY_WAIT_FLOOR_MS must be less than or equal to INTELLIGENCE_SYNC_RETRY_WAIT_CEILING_MS/,
    );
  });

  it('rejects a lease-renewal interval that is not less than one-third of the job lease', () => {
    const issues = intelligenceRelationshipIssues({
      ...defaultIntelligenceConfig(),
      kevJobLeaseMs: 600_000,
      jobLeaseRenewalIntervalMs: 200_000,
    });
    expect(issueOn(issues, 'jobLeaseRenewalIntervalMs')?.message).toMatch(
      /INTELLIGENCE_JOB_LEASE_RENEWAL_INTERVAL_MS must be strictly less than one-third of INTELLIGENCE_KEV_JOB_LEASE_MS/,
    );
  });

  it('rejects a lease-renewal interval that is not greater than the staging-transaction budget', () => {
    const issues = intelligenceRelationshipIssues({
      ...defaultIntelligenceConfig(),
      jobLeaseRenewalIntervalMs: INTELLIGENCE_STAGING_TRANSACTION_BUDGET_MS,
    });
    expect(issueOn(issues, 'jobLeaseRenewalIntervalMs')?.message).toMatch(
      /INTELLIGENCE_JOB_LEASE_RENEWAL_INTERVAL_MS must be strictly greater than the PostgreSQL staging-transaction budget/,
    );
  });

  it('accepts default sync-attempt and lease-renewal relationships', () => {
    const issues = intelligenceRelationshipIssues(defaultIntelligenceConfig());
    expect(issueOn(issues, 'syncRetryWaitFloorMs')).toBeUndefined();
    expect(issueOn(issues, 'jobLeaseRenewalIntervalMs')).toBeUndefined();
    expect(defaultIntelligenceConfig().syncMaxAttempts).toBe(
      INTELLIGENCE_SYNC_MAX_ATTEMPTS_DEFAULT,
    );
    expect(defaultIntelligenceConfig().jobLeaseRenewalIntervalMs).toBeLessThan(
      Math.floor(defaultIntelligenceConfig().kevJobLeaseMs / 3),
    );
    expect(defaultIntelligenceConfig().jobLeaseRenewalIntervalMs).toBeGreaterThan(
      INTELLIGENCE_STAGING_TRANSACTION_BUDGET_MS,
    );
  });

  it('rejects stale threshold equal to sync interval', () => {
    const env = validDevelopmentEnv();
    env['INTELLIGENCE_KEV_SYNC_INTERVAL_SECONDS'] = '86400';
    env['INTELLIGENCE_KEV_STALE_THRESHOLD_SECONDS'] = '86400';
    expectRejection(
      env,
      /INTELLIGENCE_KEV_STALE_THRESHOLD_SECONDS must be strictly greater than INTELLIGENCE_KEV_SYNC_INTERVAL_SECONDS/,
    );
  });

  it('accepts stale threshold greater than sync interval', () => {
    const env = validDevelopmentEnv();
    env['INTELLIGENCE_KEV_SYNC_INTERVAL_SECONDS'] = '86400';
    env['INTELLIGENCE_KEV_STALE_THRESHOLD_SECONDS'] = '259200';
    const config = loadServerConfigFrom(env);
    expect(config.intelligence.kevStaleThresholdSeconds).toBe(259_200);
  });

  it('rejects parser timeout equal to the KEV job lease', () => {
    const issues = intelligenceRelationshipIssues({
      ...defaultIntelligenceConfig(),
      kevParserTimeoutMs: 600_000,
      kevJobLeaseMs: 600_000,
    });
    expect(issueOn(issues, 'kevParserTimeoutMs')?.message).toMatch(
      /INTELLIGENCE_KEV_PARSER_TIMEOUT_MS must be strictly less than INTELLIGENCE_KEV_JOB_LEASE_MS/,
    );
  });

  it('rejects object-storage timeout equal to the KEV job lease', () => {
    const env = validDevelopmentEnv();
    env['INTELLIGENCE_HTTP_RETRY_COUNT'] = '0';
    env['INTELLIGENCE_HTTP_CONNECT_TIMEOUT_MS'] = '250';
    env['INTELLIGENCE_HTTP_TOTAL_TIMEOUT_MS'] = '5000';
    env['INTELLIGENCE_KEV_PARSER_TIMEOUT_MS'] = '1000';
    env['INTELLIGENCE_OBJECT_STORAGE_TIMEOUT_MS'] = '120000';
    env['INTELLIGENCE_KEV_JOB_LEASE_MS'] = '120000';
    expectRejection(
      env,
      /INTELLIGENCE_OBJECT_STORAGE_TIMEOUT_MS must be strictly less than INTELLIGENCE_KEV_JOB_LEASE_MS/,
    );
  });

  it('rejects orphan grace equal to or below the KEV job lease', () => {
    const equal = intelligenceRelationshipIssues({
      ...defaultIntelligenceConfig(),
      orphanGraceSeconds: 600,
      kevJobLeaseMs: 600_000,
    });
    expect(issueOn(equal, 'orphanGraceSeconds')?.message).toMatch(
      /INTELLIGENCE_ORPHAN_GRACE_SECONDS in milliseconds must be strictly greater than INTELLIGENCE_KEV_JOB_LEASE_MS/,
    );

    const below = intelligenceRelationshipIssues({
      ...defaultIntelligenceConfig(),
      orphanGraceSeconds: 500,
      kevJobLeaseMs: 600_000,
    });
    expect(issueOn(below, 'orphanGraceSeconds')).toBeDefined();
  });

  it('rejects staging-generation max age equal to or below the KEV job lease', () => {
    const equal = intelligenceRelationshipIssues({
      ...defaultIntelligenceConfig(),
      stagingGenerationMaxAgeSeconds: 600,
      kevJobLeaseMs: 600_000,
    });
    expect(issueOn(equal, 'stagingGenerationMaxAgeSeconds')?.message).toMatch(
      /INTELLIGENCE_STAGING_GENERATION_MAX_AGE_SECONDS in milliseconds must be strictly greater than INTELLIGENCE_KEV_JOB_LEASE_MS/,
    );

    const below = intelligenceRelationshipIssues({
      ...defaultIntelligenceConfig(),
      stagingGenerationMaxAgeSeconds: 500,
      kevJobLeaseMs: 600_000,
    });
    expect(issueOn(below, 'stagingGenerationMaxAgeSeconds')).toBeDefined();
  });

  it('rejects JSON string limit below text-field limit', () => {
    const env = validDevelopmentEnv();
    env['INTELLIGENCE_KEV_JSON_MAX_STRING_BYTES'] = '256';
    env['INTELLIGENCE_KEV_MAX_TEXT_FIELD_BYTES'] = '4096';
    expectRejection(
      env,
      /INTELLIGENCE_KEV_JSON_MAX_STRING_BYTES must be greater than or equal to INTELLIGENCE_KEV_MAX_TEXT_FIELD_BYTES/,
    );
  });

  it('rejects HTTP retry budget equal to the KEV job lease', () => {
    const env = validDevelopmentEnv();
    env['INTELLIGENCE_HTTP_RETRY_COUNT'] = '3';
    env['INTELLIGENCE_HTTP_BACKOFF_CEILING_MS'] = '30000';
    env['INTELLIGENCE_HTTP_TOTAL_TIMEOUT_MS'] = '127500';
    env['INTELLIGENCE_HTTP_CONNECT_TIMEOUT_MS'] = '5000';
    env['INTELLIGENCE_KEV_JOB_LEASE_MS'] = '600000';
    expectRejection(
      env,
      /HTTP worst-case retry budget must be strictly less than INTELLIGENCE_KEV_JOB_LEASE_MS/,
    );
  });

  it('rejects HTTP retry budget plus parser and storage equal to the KEV job lease', () => {
    const env = validDevelopmentEnv();
    env['INTELLIGENCE_HTTP_RETRY_COUNT'] = '3';
    env['INTELLIGENCE_HTTP_BACKOFF_CEILING_MS'] = '30000';
    env['INTELLIGENCE_HTTP_TOTAL_TIMEOUT_MS'] = '117500';
    env['INTELLIGENCE_HTTP_CONNECT_TIMEOUT_MS'] = '5000';
    env['INTELLIGENCE_KEV_PARSER_TIMEOUT_MS'] = '10000';
    env['INTELLIGENCE_OBJECT_STORAGE_TIMEOUT_MS'] = '30000';
    env['INTELLIGENCE_KEV_JOB_LEASE_MS'] = '600000';
    expectRejection(
      env,
      /HTTP worst-case retry budget plus parser timeout and object-storage timeout must be strictly less than INTELLIGENCE_KEV_JOB_LEASE_MS/,
    );
  });

  it('accepts the valid full default retry and lease budget', () => {
    const config = loadServerConfigFrom(validDevelopmentEnv());
    const httpBudget = intelligenceHttpWorstCaseBudgetMs(config.intelligence);
    expect(httpBudget).toBe(330_000);
    expect(httpBudget).toBeLessThan(config.intelligence.kevJobLeaseMs);
    expect(
      (httpBudget ?? Number.NaN) +
        config.intelligence.kevParserTimeoutMs +
        config.intelligence.objectStorageTimeoutMs,
    ).toBe(370_000);
    expect(intelligenceRelationshipIssues(config.intelligence)).toEqual([]);
  });

  it('accepts default version labels', () => {
    const config = loadServerConfigFrom(validDevelopmentEnv());
    expect(config.intelligence.parserVersion).toBe('0.1.0');
    expect(config.intelligence.normalizationVersion).toBe('1');
  });

  it('rejects empty version labels', () => {
    const parserEnv = validDevelopmentEnv();
    parserEnv['INTELLIGENCE_PARSER_VERSION'] = '';
    expect(() => loadServerConfigFrom(parserEnv)).toThrow(/INTELLIGENCE_PARSER_VERSION/);

    const normalizationEnv = validDevelopmentEnv();
    normalizationEnv['INTELLIGENCE_NORMALIZATION_VERSION'] = '';
    expect(() => loadServerConfigFrom(normalizationEnv)).toThrow(
      /INTELLIGENCE_NORMALIZATION_VERSION/,
    );
  });

  it('accepts maximum valid version-label length', () => {
    const env = validDevelopmentEnv();
    const label = `a${'b'.repeat(INTELLIGENCE_VERSION_LABEL_MAX_LENGTH - 1)}`;
    env['INTELLIGENCE_PARSER_VERSION'] = label;
    env['INTELLIGENCE_NORMALIZATION_VERSION'] = label;
    const config = loadServerConfigFrom(env);
    expect(config.intelligence.parserVersion).toBe(label);
    expect(config.intelligence.normalizationVersion).toBe(label);
  });

  it('rejects over-length version labels', () => {
    const env = validDevelopmentEnv();
    env['INTELLIGENCE_PARSER_VERSION'] = `a${'b'.repeat(INTELLIGENCE_VERSION_LABEL_MAX_LENGTH)}`;
    expect(() => loadServerConfigFrom(env)).toThrow(ConfigValidationError);
  });

  it('rejects unsafe slashes in version labels', () => {
    const env = validDevelopmentEnv();
    env['INTELLIGENCE_PARSER_VERSION'] = '../evil';
    expectRejection(env, /Parser version must be a safe database label/);
  });

  it('rejects control characters in version labels', () => {
    const env = validDevelopmentEnv();
    env['INTELLIGENCE_NORMALIZATION_VERSION'] = '1\u0001';
    expectRejection(env, /Normalization version must be a safe database label/);
  });

  it('rejects whitespace-only version labels', () => {
    const env = validDevelopmentEnv();
    env['INTELLIGENCE_PARSER_VERSION'] = '   ';
    expect(() => loadServerConfigFrom(env)).toThrow(/INTELLIGENCE_PARSER_VERSION/);
  });

  it('uses a compiled HTTPS KEV URL with the approved hostname and path', () => {
    const config = loadServerConfigFrom(validDevelopmentEnv());
    const parsed = new URL(config.intelligence.kevSource.href);
    expect(parsed.protocol).toBe('https:');
    expect(parsed.hostname).toBe(INTELLIGENCE_KEV_HOSTNAME);
    expect(parsed.pathname).toBe(INTELLIGENCE_KEV_PATH);
    expect(parsed.username).toBe('');
    expect(parsed.password).toBe('');
    expect(parsed.search).toBe('');
    expect(parsed.hash).toBe('');
    expect(config.intelligence.kevSource.origin).toBe(INTELLIGENCE_KEV_ORIGIN);
    expect(config.intelligence.kevSource.path).toBe(INTELLIGENCE_KEV_PATH);
    expect(config.intelligence.httpRedirectMax).toBe(0);
  });

  it('does not let environment variables override the compiled KEV URL', () => {
    const env = validDevelopmentEnv();
    env['INTELLIGENCE_KEV_URL'] = 'https://evil.example/kev.json';
    env['INTELLIGENCE_KEV_HREF'] = 'https://evil.example/kev.json';
    env['INTELLIGENCE_KEV_ORIGIN'] = 'https://evil.example';
    env['INTELLIGENCE_KEV_PATH'] = '/evil.json';
    env['CISA_KEV_URL'] = 'https://github.com/cisagov/kev-data';
    env['INTELLIGENCE_HTTP_REDIRECT_MAX'] = '5';
    const config = loadServerConfigFrom(env);
    expect(config.intelligence.kevSource).toEqual(compiledIntelligenceKevSource());
    expect(config.intelligence.httpRedirectMax).toBe(0);
  });

  it('does not expose an OSV runtime URL to scheduling code', () => {
    const config = loadServerConfigFrom(validDevelopmentEnv());
    expect(config.intelligence.osvRuntime).toBe('deferred');
    expect(config.intelligence).not.toHaveProperty('osvUrl');
    expect(config.intelligence).not.toHaveProperty('osvSource');
    expect(JSON.stringify(config.intelligence)).not.toMatch(
      /osv-vulnerabilities|api\.osv\.dev|modified_id\.csv|all\.zip/,
    );
  });

  it('leaves ordinary SBOM and object-storage configuration unchanged', () => {
    const config = loadServerConfigFrom(validDevelopmentEnv());
    expect(config.sbom.uploadMaxBytes).toBe(SBOM_UPLOAD_MAX_BYTES_DEFAULT);
    expect(config.sbom.objectStorageOperationTimeoutMs).toBe(
      OBJECT_STORAGE_OPERATION_TIMEOUT_MS_DEFAULT,
    );
    expect(config.objectStorage.connectionTimeoutMs).toBe(
      OBJECT_STORAGE_CONNECTION_TIMEOUT_MS_DEFAULT,
    );
    expect(config.objectStorage.bucket).toBe('patchpilot-dev');
    expect(config.auth.cookieName).toBe(DEVELOPMENT_SESSION_COOKIE_NAME);
  });

  it('does not expose credentials or operator URL fields on intelligence config', () => {
    const config = loadServerConfigFrom(validDevelopmentEnv());
    expect(config.intelligence).not.toHaveProperty('accessKey');
    expect(config.intelligence).not.toHaveProperty('secretKey');
    expect(config.intelligence).not.toHaveProperty('endpoint');
    expect(config.intelligence).not.toHaveProperty('kevUrl');
  });

  it('performs no network requests while loading configuration', () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch');
    loadServerConfigFrom(validDevelopmentEnv());
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});
