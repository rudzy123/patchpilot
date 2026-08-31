import { describe, expect, it } from 'vitest';

import { DEVELOPMENT_SESSION_COOKIE_NAME, PRODUCTION_SESSION_COOKIE_NAME } from './auth.js';
import { ConfigValidationError, loadServerConfigFrom } from './server.js';
import {
  OBJECT_STORAGE_CONNECTION_TIMEOUT_MS_DEFAULT,
  OBJECT_STORAGE_CONNECTION_TIMEOUT_MS_MIN,
  OBJECT_STORAGE_OPERATION_TIMEOUT_MS_DEFAULT,
  OBJECT_STORAGE_OPERATION_TIMEOUT_MS_MAX,
  OBJECT_STORAGE_OPERATION_TIMEOUT_MS_MIN,
  OBJECT_STORAGE_REGION_DEFAULT,
  SBOM_IDEMPOTENCY_KEY_HEADER_NAME,
  SBOM_IDEMPOTENCY_KEY_MAX_LENGTH,
  SBOM_IDEMPOTENCY_KEY_MIN_LENGTH,
  SBOM_IDEMPOTENCY_TTL_SECONDS_DEFAULT,
  SBOM_IDEMPOTENCY_TTL_SECONDS_MAX,
  SBOM_IDEMPOTENCY_TTL_SECONDS_MIN,
  SBOM_JSON_MAX_DEPTH_DEFAULT,
  SBOM_JSON_MAX_DEPTH_MAX,
  SBOM_JSON_MAX_DEPTH_MIN,
  SBOM_JSON_MAX_NODES_DEFAULT,
  SBOM_JSON_MAX_NODES_MAX,
  SBOM_JSON_MAX_NODES_MIN,
  SBOM_JSON_MAX_STRING_BYTES_DEFAULT,
  SBOM_JSON_MAX_STRING_BYTES_MAX,
  SBOM_JSON_MAX_STRING_BYTES_MIN,
  SBOM_MAX_BOM_REF_BYTES_DEFAULT,
  SBOM_MAX_BOM_REF_BYTES_MAX,
  SBOM_MAX_BOM_REF_BYTES_MIN,
  SBOM_MAX_COMPONENTS_DEFAULT,
  SBOM_MAX_COMPONENTS_MAX,
  SBOM_MAX_COMPONENTS_MIN,
  SBOM_MAX_COMPONENT_NAME_CHARS_DEFAULT,
  SBOM_MAX_COMPONENT_NAME_CHARS_MAX,
  SBOM_MAX_COMPONENT_NAME_CHARS_MIN,
  SBOM_MAX_DEPENDENCY_EDGES_DEFAULT,
  SBOM_MAX_DEPENDENCY_EDGES_MAX,
  SBOM_MAX_DEPENDENCY_EDGES_MIN,
  SBOM_MAX_EXTERNAL_REFS_PER_COMPONENT_DEFAULT,
  SBOM_MAX_EXTERNAL_REFS_PER_COMPONENT_MAX,
  SBOM_MAX_EXTERNAL_REFS_PER_COMPONENT_MIN,
  SBOM_MAX_METADATA_TOOLS_DEFAULT,
  SBOM_MAX_METADATA_TOOLS_MAX,
  SBOM_MAX_METADATA_TOOLS_MIN,
  SBOM_MAX_PROPERTIES_PER_COMPONENT_DEFAULT,
  SBOM_MAX_PROPERTIES_PER_COMPONENT_MAX,
  SBOM_MAX_PROPERTIES_PER_COMPONENT_MIN,
  SBOM_MAX_PURL_BYTES_DEFAULT,
  SBOM_MAX_PURL_BYTES_MAX,
  SBOM_MAX_PURL_BYTES_MIN,
  SBOM_MAX_VERSION_CHARS_DEFAULT,
  SBOM_MAX_VERSION_CHARS_MAX,
  SBOM_MAX_VERSION_CHARS_MIN,
  SBOM_NORMALIZATION_VERSION_DEFAULT,
  SBOM_ORPHAN_GRACE_SECONDS_DEFAULT,
  SBOM_ORPHAN_GRACE_SECONDS_MAX,
  SBOM_ORPHAN_GRACE_SECONDS_MIN,
  SBOM_PARSER_TIMEOUT_MS_DEFAULT,
  SBOM_PARSER_TIMEOUT_MS_MAX,
  SBOM_PARSER_TIMEOUT_MS_MIN,
  SBOM_PARSER_VERSION_DEFAULT,
  SBOM_PROCESSING_LEASE_MS_DEFAULT,
  SBOM_PROCESSING_LEASE_MS_MAX,
  SBOM_PROCESSING_LEASE_MS_MIN,
  SBOM_UPLOAD_MAX_BYTES_DEFAULT,
  SBOM_UPLOAD_MAX_BYTES_MAX,
  SBOM_UPLOAD_MAX_BYTES_MIN,
  SBOM_UPLOAD_RATE_LIMIT_MAX_DEFAULT,
  SBOM_UPLOAD_RATE_LIMIT_MAX_MAX,
  SBOM_UPLOAD_RATE_LIMIT_MAX_MIN,
  SBOM_UPLOAD_RATE_LIMIT_WINDOW_SECONDS_DEFAULT,
  SBOM_UPLOAD_RATE_LIMIT_WINDOW_SECONDS_MAX,
  SBOM_UPLOAD_RATE_LIMIT_WINDOW_SECONDS_MIN,
  refineSbomNumericBounds,
  sbomDefaultEnvironmentVariables,
  sbomRelationshipIssues,
  type SbomConfig,
  type SbomRelationshipIssue,
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
  env['SBOM_PARSER_TIMEOUT_MS'] = String(SBOM_PARSER_TIMEOUT_MS_MIN);
  env['OBJECT_STORAGE_OPERATION_TIMEOUT_MS'] = String(OBJECT_STORAGE_OPERATION_TIMEOUT_MS_MIN);
  env['OBJECT_STORAGE_CONNECTION_TIMEOUT_MS'] = String(OBJECT_STORAGE_CONNECTION_TIMEOUT_MS_MIN);
  env['SBOM_PROCESSING_LEASE_MS'] = String(SBOM_PROCESSING_LEASE_MS_MAX);
  env['SBOM_IDEMPOTENCY_TTL_SECONDS'] = String(SBOM_IDEMPOTENCY_TTL_SECONDS_MIN);
  env['SBOM_ORPHAN_GRACE_SECONDS'] = String(SBOM_ORPHAN_GRACE_SECONDS_MAX);
  return env;
}

type SbomNumericKey = keyof Omit<SbomConfig, 'parserVersion' | 'normalizationVersion'>;

const boundedNumericLimits: Array<{
  envKey: string;
  configKey: SbomNumericKey;
  min: number;
  max: number;
}> = [
  {
    envKey: 'SBOM_UPLOAD_MAX_BYTES',
    configKey: 'uploadMaxBytes',
    min: SBOM_UPLOAD_MAX_BYTES_MIN,
    max: SBOM_UPLOAD_MAX_BYTES_MAX,
  },
  {
    envKey: 'SBOM_JSON_MAX_DEPTH',
    configKey: 'jsonMaxDepth',
    min: SBOM_JSON_MAX_DEPTH_MIN,
    max: SBOM_JSON_MAX_DEPTH_MAX,
  },
  {
    envKey: 'SBOM_JSON_MAX_NODES',
    configKey: 'jsonMaxNodes',
    min: SBOM_JSON_MAX_NODES_MIN,
    max: SBOM_JSON_MAX_NODES_MAX,
  },
  {
    envKey: 'SBOM_JSON_MAX_STRING_BYTES',
    configKey: 'jsonMaxStringBytes',
    min: SBOM_JSON_MAX_STRING_BYTES_MIN,
    max: SBOM_JSON_MAX_STRING_BYTES_MAX,
  },
  {
    envKey: 'SBOM_MAX_COMPONENTS',
    configKey: 'maxComponents',
    min: SBOM_MAX_COMPONENTS_MIN,
    max: SBOM_MAX_COMPONENTS_MAX,
  },
  {
    envKey: 'SBOM_MAX_DEPENDENCY_EDGES',
    configKey: 'maxDependencyEdges',
    min: SBOM_MAX_DEPENDENCY_EDGES_MIN,
    max: SBOM_MAX_DEPENDENCY_EDGES_MAX,
  },
  {
    envKey: 'SBOM_MAX_BOM_REF_BYTES',
    configKey: 'maxBomRefBytes',
    min: SBOM_MAX_BOM_REF_BYTES_MIN,
    max: SBOM_MAX_BOM_REF_BYTES_MAX,
  },
  {
    envKey: 'SBOM_MAX_PURL_BYTES',
    configKey: 'maxPurlBytes',
    min: SBOM_MAX_PURL_BYTES_MIN,
    max: SBOM_MAX_PURL_BYTES_MAX,
  },
  {
    envKey: 'SBOM_MAX_COMPONENT_NAME_CHARS',
    configKey: 'maxComponentNameChars',
    min: SBOM_MAX_COMPONENT_NAME_CHARS_MIN,
    max: SBOM_MAX_COMPONENT_NAME_CHARS_MAX,
  },
  {
    envKey: 'SBOM_MAX_VERSION_CHARS',
    configKey: 'maxVersionChars',
    min: SBOM_MAX_VERSION_CHARS_MIN,
    max: SBOM_MAX_VERSION_CHARS_MAX,
  },
  {
    envKey: 'SBOM_MAX_METADATA_TOOLS',
    configKey: 'maxMetadataTools',
    min: SBOM_MAX_METADATA_TOOLS_MIN,
    max: SBOM_MAX_METADATA_TOOLS_MAX,
  },
  {
    envKey: 'SBOM_MAX_EXTERNAL_REFS_PER_COMPONENT',
    configKey: 'maxExternalRefsPerComponent',
    min: SBOM_MAX_EXTERNAL_REFS_PER_COMPONENT_MIN,
    max: SBOM_MAX_EXTERNAL_REFS_PER_COMPONENT_MAX,
  },
  {
    envKey: 'SBOM_MAX_PROPERTIES_PER_COMPONENT',
    configKey: 'maxPropertiesPerComponent',
    min: SBOM_MAX_PROPERTIES_PER_COMPONENT_MIN,
    max: SBOM_MAX_PROPERTIES_PER_COMPONENT_MAX,
  },
  {
    envKey: 'SBOM_PARSER_TIMEOUT_MS',
    configKey: 'parserTimeoutMs',
    min: SBOM_PARSER_TIMEOUT_MS_MIN,
    max: SBOM_PARSER_TIMEOUT_MS_MAX,
  },
  {
    envKey: 'SBOM_PROCESSING_LEASE_MS',
    configKey: 'processingLeaseMs',
    min: SBOM_PROCESSING_LEASE_MS_MIN,
    max: SBOM_PROCESSING_LEASE_MS_MAX,
  },
  {
    envKey: 'SBOM_IDEMPOTENCY_TTL_SECONDS',
    configKey: 'idempotencyTtlSeconds',
    min: SBOM_IDEMPOTENCY_TTL_SECONDS_MIN,
    max: SBOM_IDEMPOTENCY_TTL_SECONDS_MAX,
  },
  {
    envKey: 'SBOM_UPLOAD_RATE_LIMIT_MAX',
    configKey: 'uploadRateLimitMax',
    min: SBOM_UPLOAD_RATE_LIMIT_MAX_MIN,
    max: SBOM_UPLOAD_RATE_LIMIT_MAX_MAX,
  },
  {
    envKey: 'SBOM_UPLOAD_RATE_LIMIT_WINDOW_SECONDS',
    configKey: 'uploadRateLimitWindowSeconds',
    min: SBOM_UPLOAD_RATE_LIMIT_WINDOW_SECONDS_MIN,
    max: SBOM_UPLOAD_RATE_LIMIT_WINDOW_SECONDS_MAX,
  },
  {
    envKey: 'OBJECT_STORAGE_OPERATION_TIMEOUT_MS',
    configKey: 'objectStorageOperationTimeoutMs',
    min: OBJECT_STORAGE_OPERATION_TIMEOUT_MS_MIN,
    max: OBJECT_STORAGE_OPERATION_TIMEOUT_MS_MAX,
  },
  {
    envKey: 'SBOM_ORPHAN_GRACE_SECONDS',
    configKey: 'orphanGraceSeconds',
    min: SBOM_ORPHAN_GRACE_SECONDS_MIN,
    max: SBOM_ORPHAN_GRACE_SECONDS_MAX,
  },
];

function defaultSbomConfig(): SbomConfig {
  return loadServerConfigFrom(validDevelopmentEnv()).sbom;
}

describe('SBOM ingestion configuration', () => {
  it('loads valid development configuration with approved defaults', () => {
    const config = loadServerConfigFrom(validDevelopmentEnv());
    expect(config.deploymentEnvironment).toBe('development');
    expect(config.sbom).toEqual({
      uploadMaxBytes: SBOM_UPLOAD_MAX_BYTES_DEFAULT,
      jsonMaxDepth: SBOM_JSON_MAX_DEPTH_DEFAULT,
      jsonMaxNodes: SBOM_JSON_MAX_NODES_DEFAULT,
      jsonMaxStringBytes: SBOM_JSON_MAX_STRING_BYTES_DEFAULT,
      maxComponents: SBOM_MAX_COMPONENTS_DEFAULT,
      maxDependencyEdges: SBOM_MAX_DEPENDENCY_EDGES_DEFAULT,
      maxBomRefBytes: SBOM_MAX_BOM_REF_BYTES_DEFAULT,
      maxPurlBytes: SBOM_MAX_PURL_BYTES_DEFAULT,
      maxComponentNameChars: SBOM_MAX_COMPONENT_NAME_CHARS_DEFAULT,
      maxVersionChars: SBOM_MAX_VERSION_CHARS_DEFAULT,
      maxMetadataTools: SBOM_MAX_METADATA_TOOLS_DEFAULT,
      maxExternalRefsPerComponent: SBOM_MAX_EXTERNAL_REFS_PER_COMPONENT_DEFAULT,
      maxPropertiesPerComponent: SBOM_MAX_PROPERTIES_PER_COMPONENT_DEFAULT,
      parserTimeoutMs: SBOM_PARSER_TIMEOUT_MS_DEFAULT,
      processingLeaseMs: SBOM_PROCESSING_LEASE_MS_DEFAULT,
      idempotencyTtlSeconds: SBOM_IDEMPOTENCY_TTL_SECONDS_DEFAULT,
      uploadRateLimitMax: SBOM_UPLOAD_RATE_LIMIT_MAX_DEFAULT,
      uploadRateLimitWindowSeconds: SBOM_UPLOAD_RATE_LIMIT_WINDOW_SECONDS_DEFAULT,
      objectStorageOperationTimeoutMs: OBJECT_STORAGE_OPERATION_TIMEOUT_MS_DEFAULT,
      orphanGraceSeconds: SBOM_ORPHAN_GRACE_SECONDS_DEFAULT,
      parserVersion: SBOM_PARSER_VERSION_DEFAULT,
      normalizationVersion: SBOM_NORMALIZATION_VERSION_DEFAULT,
    });
    expect(config.requestBodyLimitBytes).toBe(1_048_576);
    expect(config.objectStorage.region).toBe(OBJECT_STORAGE_REGION_DEFAULT);
    expect(config.objectStorage.connectionTimeoutMs).toBe(
      OBJECT_STORAGE_CONNECTION_TIMEOUT_MS_DEFAULT,
    );
  });

  it('exports the Idempotency-Key header contract used by upload routes', () => {
    expect(SBOM_IDEMPOTENCY_KEY_HEADER_NAME).toBe('Idempotency-Key');
    expect(SBOM_IDEMPOTENCY_KEY_MIN_LENGTH).toBe(1);
    expect(SBOM_IDEMPOTENCY_KEY_MAX_LENGTH).toBe(256);
  });

  it('loads valid test configuration', () => {
    const config = loadServerConfigFrom(validTestEnv());
    expect(config.deploymentEnvironment).toBe('test');
    expect(config.sbom.uploadMaxBytes).toBe(SBOM_UPLOAD_MAX_BYTES_DEFAULT);
  });

  it('loads valid production configuration', () => {
    const config = loadServerConfigFrom(validProductionEnv());
    expect(config.deploymentEnvironment).toBe('production');
    expect(config.objectStorage.bucket).toBe('patchpilot');
    expect(config.sbom.parserVersion).toBe(SBOM_PARSER_VERSION_DEFAULT);
  });

  it('accepts each numeric floor', () => {
    for (const limit of boundedNumericLimits) {
      const boundIssues: SbomRelationshipIssue[] = [];
      refineSbomNumericBounds({ ...defaultSbomConfig(), [limit.configKey]: limit.min }, (issue) =>
        boundIssues.push(issue),
      );
      expect(
        boundIssues.filter((issue) => issue.path[0] === limit.configKey),
        limit.envKey,
      ).toEqual([]);

      const env = relationshipSafeEnv();
      env[limit.envKey] = String(limit.min);
      expect(loadServerConfigFrom(env).sbom[limit.configKey], limit.envKey).toBe(limit.min);
    }
  });

  it('accepts each numeric ceiling', () => {
    for (const limit of boundedNumericLimits) {
      const env = relationshipSafeEnv();
      env[limit.envKey] = String(limit.max);
      expect(loadServerConfigFrom(env).sbom[limit.configKey], limit.envKey).toBe(limit.max);
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

  it('rejects non-integer, NaN, Infinity, and negative numeric values', () => {
    for (const raw of ['20.5', '1e7', 'NaN', 'Infinity', '-1', '010']) {
      const env = validDevelopmentEnv();
      env['SBOM_JSON_MAX_DEPTH'] = raw;
      expect(() => loadServerConfigFrom(env)).toThrow(ConfigValidationError);
    }
  });

  it('rejects parser timeout greater than or equal to the processing lease', () => {
    const env = validDevelopmentEnv();
    env['SBOM_PARSER_TIMEOUT_MS'] = '120000';
    env['SBOM_PROCESSING_LEASE_MS'] = '120000';
    expectRejection(env, /Parser timeout must be less than the processing lease/);
  });

  it('rejects object-storage timeout greater than or equal to the processing lease', () => {
    const env = validDevelopmentEnv();
    env['OBJECT_STORAGE_OPERATION_TIMEOUT_MS'] = '120000';
    env['SBOM_PROCESSING_LEASE_MS'] = '120000';
    expectRejection(env, /Object-storage operation timeout must be less than the processing lease/);
  });

  it('rejects an idempotency TTL that does not outlive put and promote object-storage operations', () => {
    const issues = sbomRelationshipIssues({
      ...defaultSbomConfig(),
      idempotencyTtlSeconds: 1,
      objectStorageOperationTimeoutMs: 2_000,
    });
    expect(issues.some((issue) => issue.path[0] === 'idempotencyTtlSeconds')).toBe(true);
    expect(issues.find((issue) => issue.path[0] === 'idempotencyTtlSeconds')?.message).toMatch(
      /twice the object-storage operation timeout/,
    );
  });

  it('loads the idempotency TTL and orphan-grace floors together', () => {
    const env = validDevelopmentEnv();
    env['SBOM_IDEMPOTENCY_TTL_SECONDS'] = String(SBOM_IDEMPOTENCY_TTL_SECONDS_MIN);
    env['SBOM_ORPHAN_GRACE_SECONDS'] = String(SBOM_ORPHAN_GRACE_SECONDS_MIN);
    const config = loadServerConfigFrom(env);
    expect(config.sbom.idempotencyTtlSeconds).toBe(SBOM_IDEMPOTENCY_TTL_SECONDS_MIN);
    expect(config.sbom.orphanGraceSeconds).toBe(SBOM_ORPHAN_GRACE_SECONDS_MIN);
  });

  it('rejects an orphan grace period that is not greater than the idempotency TTL', () => {
    const env = validDevelopmentEnv();
    env['SBOM_IDEMPOTENCY_TTL_SECONDS'] = String(SBOM_IDEMPOTENCY_TTL_SECONDS_DEFAULT);
    env['SBOM_ORPHAN_GRACE_SECONDS'] = String(SBOM_IDEMPOTENCY_TTL_SECONDS_DEFAULT);
    expectRejection(env, /Orphan grace period must be greater than the idempotency TTL/);
  });

  it('rejects an invalid object-storage bucket name', () => {
    const env = validDevelopmentEnv();
    env['OBJECT_STORAGE_BUCKET'] = 'Bad_Bucket';
    expectRejection(env, /valid S3-compatible bucket name/);
  });

  it('rejects development placeholder buckets in production', () => {
    const env = validProductionEnv();
    env['OBJECT_STORAGE_BUCKET'] = 'patchpilot-dev';
    expectRejection(env, /development placeholders/);
  });

  it('rejects a malformed parser version', () => {
    const env = validDevelopmentEnv();
    env['SBOM_PARSER_VERSION'] = '../evil';
    expectRejection(env, /Parser version must be a safe database label/);
  });

  it('rejects an overlong parser version', () => {
    const env = validDevelopmentEnv();
    env['SBOM_PARSER_VERSION'] = `a${'b'.repeat(64)}`;
    expect(() => loadServerConfigFrom(env)).toThrow(ConfigValidationError);
  });

  it('rejects a malformed normalization version', () => {
    const env = validDevelopmentEnv();
    env['SBOM_NORMALIZATION_VERSION'] = 'version with spaces';
    expectRejection(env, /Normalization version must be a safe database label/);
  });

  it('keeps REQUEST_BODY_LIMIT_BYTES independent from SBOM upload limits', () => {
    const env = validDevelopmentEnv();
    env['REQUEST_BODY_LIMIT_BYTES'] = '4096';
    env['SBOM_UPLOAD_MAX_BYTES'] = String(SBOM_UPLOAD_MAX_BYTES_MIN);
    const config = loadServerConfigFrom(env);
    expect(config.requestBodyLimitBytes).toBe(4096);
    expect(config.sbom.uploadMaxBytes).toBe(SBOM_UPLOAD_MAX_BYTES_MIN);
  });

  it('does not place object-storage credentials on the SBOM config object', () => {
    const config = loadServerConfigFrom(validDevelopmentEnv());
    expect(config.sbom).not.toHaveProperty('accessKey');
    expect(config.sbom).not.toHaveProperty('secretKey');
    expect(config.sbom).not.toHaveProperty('endpoint');
  });
});
