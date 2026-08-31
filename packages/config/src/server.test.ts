import { describe, expect, it } from 'vitest';

import { ConfigValidationError, loadServerConfigFrom } from './server.js';
import { loadPublicConfigFrom } from './public.js';
import { DEVELOPMENT_SESSION_COOKIE_NAME, PRODUCTION_SESSION_COOKIE_NAME } from './auth.js';
import { intelligenceDefaultEnvironmentVariables } from './intelligence.js';
import { sbomDefaultEnvironmentVariables } from './sbom.js';

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

function productionAuthEnv(): Record<string, string> {
  return {
    ...developmentAuthEnv(),
    AUTH_COOKIE_NAME: PRODUCTION_SESSION_COOKIE_NAME,
    AUTH_COOKIE_SECURE: 'true',
  };
}

function testAuthEnv(): Record<string, string> {
  return {
    ...developmentAuthEnv(),
    AUTH_ARGON2_MEMORY_KIB: '8192',
    AUTH_ARGON2_TIME_COST: '1',
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
    PATCHPILOT_DEPLOYMENT_ENVIRONMENT: 'production',
    PATCHPILOT_ALLOW_DEVELOPMENT_ADAPTERS: 'false',
    LOG_LEVEL: 'info',
    LOG_PRETTY: 'false',
    API_HOST: '127.0.0.1',
    API_PORT: '3001',
    WEB_PORT: '3000',
    CORS_ALLOWED_ORIGINS: 'https://patchpilot.example',
    DATABASE_URL: 'postgresql://patchpilot:operator-secret@db.internal:5432/patchpilot',
    REDIS_URL: 'redis://:operator-redis-secret@redis.internal:6379',
    OBJECT_STORAGE_ENDPOINT: 'https://objects.internal:9000',
    OBJECT_STORAGE_ACCESS_KEY: 'operator-supplied-access-key',
    OBJECT_STORAGE_SECRET_KEY: 'operator-supplied-secret-key-value',
    OBJECT_STORAGE_BUCKET: 'patchpilot',
    OBJECT_STORAGE_USE_SSL: 'true',
    OTEL_ENABLED: 'false',
    READINESS_TIMEOUT_MS: '1000',
    SHUTDOWN_TIMEOUT_MS: '10000',
    REQUEST_BODY_LIMIT_BYTES: '1048576',
    REQUEST_ID_HEADER: 'x-request-id',
    CORRELATION_ID_HEADER: 'x-correlation-id',
    ...sbomDefaultEnvironmentVariables(),
    ...intelligenceDefaultEnvironmentVariables(),
    ...productionAuthEnv(),
  };
}

function validTestEnv(): Record<string, string> {
  return {
    ...validDevelopmentEnv(),
    PATCHPILOT_DEPLOYMENT_ENVIRONMENT: 'test',
    LOG_PRETTY: 'false',
    ...testAuthEnv(),
  };
}

describe('loadServerConfigFrom', () => {
  it('loads development configuration from an explicit env record', () => {
    const config = loadServerConfigFrom(validDevelopmentEnv());
    expect(config.deploymentEnvironment).toBe('development');
    expect(config.allowDevelopmentAdapters).toBe(true);
    expect(config.corsAllowedOrigins).toEqual(['http://127.0.0.1:3000']);
    expect(config.intelligence.kevEnabled).toBe(true);
    expect(config.intelligence.osvEnabled).toBe(false);
    expect(config.intelligence.osvRuntime).toBe('deferred');
  });

  it('does not require mutating process.env', () => {
    const before = process.env['PATCHPILOT_DEPLOYMENT_ENVIRONMENT'];
    loadServerConfigFrom(validDevelopmentEnv());
    expect(process.env['PATCHPILOT_DEPLOYMENT_ENVIRONMENT']).toBe(before);
  });

  it('rejects development adapters in production', () => {
    const env = validDevelopmentEnv();
    env['PATCHPILOT_DEPLOYMENT_ENVIRONMENT'] = 'production';
    env['PATCHPILOT_ALLOW_DEVELOPMENT_ADAPTERS'] = 'true';
    env['LOG_PRETTY'] = 'false';
    env['OBJECT_STORAGE_ACCESS_KEY'] = 'operator-supplied-access-key';
    env['OBJECT_STORAGE_SECRET_KEY'] = 'operator-supplied-secret-key-value';
    env['DATABASE_URL'] = 'postgresql://patchpilot:operator-secret@db.internal:5432/patchpilot';

    expect(() => loadServerConfigFrom(env)).toThrow(ConfigValidationError);
    expect(() => loadServerConfigFrom(env)).toThrow(/allowDevelopmentAdapters/);
  });

  it('rejects development placeholder credentials in production', () => {
    const env = validDevelopmentEnv();
    env['PATCHPILOT_DEPLOYMENT_ENVIRONMENT'] = 'production';
    env['PATCHPILOT_ALLOW_DEVELOPMENT_ADAPTERS'] = 'false';
    env['LOG_PRETTY'] = 'false';

    expect(() => loadServerConfigFrom(env)).toThrow(/development-only placeholder credentials/);
  });

  it('rejects wildcard CORS origins', () => {
    const env = validDevelopmentEnv();
    env['CORS_ALLOWED_ORIGINS'] = '*';
    expect(() => loadServerConfigFrom(env)).toThrow(/exact allowlist/);
  });

  it('rejects unauthenticated Redis URLs in production', () => {
    const env = validProductionEnv();
    env['REDIS_URL'] = 'redis://redis.internal:6379';
    expect(() => loadServerConfigFrom(env)).toThrow(/must include a password/);
  });

  it('accepts production configuration with operator secrets and authenticated Redis', () => {
    const config = loadServerConfigFrom(validProductionEnv());
    expect(config.deploymentEnvironment).toBe('production');
    expect(config.allowDevelopmentAdapters).toBe(false);
    expect(config.redisUrl).toContain('operator-redis-secret');
  });

  it('returns an actionable error for a missing variable', () => {
    const env = validDevelopmentEnv();
    delete env['DATABASE_URL'];
    expect(() => loadServerConfigFrom(env)).toThrow(/DATABASE_URL/);
  });

  it('accepts valid production authentication configuration', () => {
    const config = loadServerConfigFrom(validProductionEnv());
    expect(config.auth.cookieName).toBe(PRODUCTION_SESSION_COOKIE_NAME);
    expect(config.auth.cookieSecure).toBe(true);
    expect(config.auth.argon2MemoryKib).toBe(19456);
    expect(config.auth.csrfHeaderName).toBe('x-csrf-token');
    expect(config.corsAllowedOrigins).toEqual(['https://patchpilot.example']);
  });

  it('accepts valid development authentication configuration', () => {
    const config = loadServerConfigFrom(validDevelopmentEnv());
    expect(config.auth.cookieName).toBe(DEVELOPMENT_SESSION_COOKIE_NAME);
    expect(config.auth.cookieSecure).toBe(false);
    expect(config.auth.sessionAbsoluteTtlSeconds).toBe(604800);
    expect(config.auth.sessionIdleTtlSeconds).toBe(43200);
  });

  it('accepts valid test authentication configuration with guarded cheaper Argon2', () => {
    const config = loadServerConfigFrom(validTestEnv());
    expect(config.deploymentEnvironment).toBe('test');
    expect(config.auth.argon2MemoryKib).toBe(8192);
    expect(config.auth.argon2TimeCost).toBe(1);
    expect(config.auth.cookieName).toBe(DEVELOPMENT_SESSION_COOKIE_NAME);
  });

  it('rejects insecure production cookies', () => {
    const env = validProductionEnv();
    env['AUTH_COOKIE_SECURE'] = 'false';
    expect(() => loadServerConfigFrom(env)).toThrow(ConfigValidationError);
    expect(() => loadServerConfigFrom(env)).toThrow(/Secure=true/);
  });

  it('rejects the loopback development cookie name in production', () => {
    const env = validProductionEnv();
    env['AUTH_COOKIE_NAME'] = DEVELOPMENT_SESSION_COOKIE_NAME;
    expect(() => loadServerConfigFrom(env)).toThrow(/loopback development cookie name/);
  });

  it('rejects below-minimum Argon2 production parameters', () => {
    const env = validProductionEnv();
    env['AUTH_ARGON2_MEMORY_KIB'] = '8192';
    env['AUTH_ARGON2_TIME_COST'] = '1';
    expect(() => loadServerConfigFrom(env)).toThrow(/Production Argon2 memory/);
  });

  it('rejects an excessive password UTF-8 byte limit', () => {
    const env = validDevelopmentEnv();
    env['AUTH_PASSWORD_MAX_BYTES'] = '1024';
    expect(() => loadServerConfigFrom(env)).toThrow(ConfigValidationError);
    expect(() => loadServerConfigFrom(env)).toThrow(/passwordMaxBytes|128/);
  });

  it('rejects idle TTL greater than absolute TTL', () => {
    const env = validDevelopmentEnv();
    env['AUTH_SESSION_IDLE_TTL_SECONDS'] = '700000';
    env['AUTH_SESSION_ABSOLUTE_TTL_SECONDS'] = '604800';
    expect(() => loadServerConfigFrom(env)).toThrow(/Idle session TTL/);
  });

  it('rejects invalid production origins', () => {
    const env = validProductionEnv();
    env['CORS_ALLOWED_ORIGINS'] = 'http://patchpilot.example';
    expect(() => loadServerConfigFrom(env)).toThrow(/https URLs/);
  });

  it('rejects unsafe login rate-limit thresholds', () => {
    const env = validDevelopmentEnv();
    env['AUTH_LOGIN_RATE_LIMIT_IP_MAX'] = '0';
    expect(() => loadServerConfigFrom(env)).toThrow(/Login IP rate-limit max attempts/);
  });

  it('loads an explicit object-storage region and connection timeout', () => {
    const config = loadServerConfigFrom(validDevelopmentEnv());
    expect(config.objectStorage.region).toBe('us-east-1');
    expect(config.objectStorage.connectionTimeoutMs).toBe(3000);
    expect(config.objectStorage.useSsl).toBe(false);
    expect(config.sbom.objectStorageOperationTimeoutMs).toBe(30_000);
  });

  it('rejects an object-storage endpoint that includes userinfo', () => {
    const env = validDevelopmentEnv();
    env['OBJECT_STORAGE_ENDPOINT'] = 'http://access:secret@127.0.0.1:19000';
    expect(() => loadServerConfigFrom(env)).toThrow(/must not include credentials or userinfo/);
  });

  it('rejects TLS and endpoint-scheme mismatch', () => {
    const httpsWithSslDisabled = validDevelopmentEnv();
    httpsWithSslDisabled['OBJECT_STORAGE_ENDPOINT'] = 'https://127.0.0.1:19000';
    httpsWithSslDisabled['OBJECT_STORAGE_USE_SSL'] = 'false';
    expect(() => loadServerConfigFrom(httpsWithSslDisabled)).toThrow(/must use http/);

    const httpWithSslEnabled = validProductionEnv();
    httpWithSslEnabled['OBJECT_STORAGE_ENDPOINT'] = 'http://objects.internal:9000';
    httpWithSslEnabled['OBJECT_STORAGE_USE_SSL'] = 'true';
    expect(() => loadServerConfigFrom(httpWithSslEnabled)).toThrow(/must use https/);
  });

  it('rejects an unbounded or missing object-storage region', () => {
    const env = validDevelopmentEnv();
    env['OBJECT_STORAGE_REGION'] = 'US-EAST-1';
    expect(() => loadServerConfigFrom(env)).toThrow(/region/);
    delete env['OBJECT_STORAGE_REGION'];
    expect(() => loadServerConfigFrom(env)).toThrow(/OBJECT_STORAGE_REGION/);
  });

  it('rejects a connection timeout greater than the operation timeout', () => {
    const env = validDevelopmentEnv();
    env['OBJECT_STORAGE_CONNECTION_TIMEOUT_MS'] = '4000';
    env['OBJECT_STORAGE_OPERATION_TIMEOUT_MS'] = '1000';
    expect(() => loadServerConfigFrom(env)).toThrow(
      /connection timeout must be less than or equal to the operation timeout/,
    );
  });

  it('accepts a connection timeout equal to the operation timeout', () => {
    const env = validDevelopmentEnv();
    env['OBJECT_STORAGE_CONNECTION_TIMEOUT_MS'] = '1000';
    env['OBJECT_STORAGE_OPERATION_TIMEOUT_MS'] = '1000';
    const config = loadServerConfigFrom(env);
    expect(config.objectStorage.connectionTimeoutMs).toBe(1000);
    expect(config.sbom.objectStorageOperationTimeoutMs).toBe(1000);
  });
});

describe('loadPublicConfigFrom', () => {
  it('does not expose server secrets', () => {
    const publicConfig = loadPublicConfigFrom({
      NEXT_PUBLIC_PATCHPILOT_ENVIRONMENT: 'development',
      NEXT_PUBLIC_API_BASE_URL: 'http://127.0.0.1:3001',
      DATABASE_URL: 'postgresql://should-not-appear',
    });

    expect(publicConfig.appName).toBe('PatchPilot');
    expect(publicConfig).not.toHaveProperty('databaseUrl');
    expect(JSON.stringify(publicConfig)).not.toContain('postgresql');
  });

  it('does not default the public environment label to development', () => {
    expect(() => loadPublicConfigFrom({})).toThrow(/Public configuration is invalid/);
  });

  it('rejects credentialed or production-http API base URLs', () => {
    expect(() =>
      loadPublicConfigFrom({
        NEXT_PUBLIC_PATCHPILOT_ENVIRONMENT: 'development',
        NEXT_PUBLIC_API_BASE_URL: 'http://user:secret@127.0.0.1:3001',
      }),
    ).toThrow(/must not include credentials/);
    expect(() =>
      loadPublicConfigFrom({
        NEXT_PUBLIC_PATCHPILOT_ENVIRONMENT: 'production',
        NEXT_PUBLIC_API_BASE_URL: 'http://127.0.0.1:3001',
      }),
    ).toThrow(/must use https/);
  });

  it('does not pass the process environment object through as public config input', () => {
    const publicConfig = loadPublicConfigFrom({
      NEXT_PUBLIC_PATCHPILOT_ENVIRONMENT: 'test',
      NEXT_PUBLIC_API_BASE_URL: 'http://127.0.0.1:3001',
      DATABASE_URL: 'postgresql://should-not-appear',
      OBJECT_STORAGE_SECRET_KEY: 'should-not-appear',
    });

    expect(Object.keys(publicConfig).sort()).toEqual([
      'apiBaseUrl',
      'appName',
      'deploymentEnvironment',
    ]);
    expect(publicConfig.apiBaseUrl).toBe('http://127.0.0.1:3001');
  });
});
