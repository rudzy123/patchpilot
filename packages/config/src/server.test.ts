import { describe, expect, it } from 'vitest';

import { ConfigValidationError, loadServerConfigFrom } from './server.js';
import { loadPublicConfigFrom } from './public.js';

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
  };
}

describe('loadServerConfigFrom', () => {
  it('loads development configuration from an explicit env record', () => {
    const config = loadServerConfigFrom(validDevelopmentEnv());
    expect(config.deploymentEnvironment).toBe('development');
    expect(config.allowDevelopmentAdapters).toBe(true);
    expect(config.corsAllowedOrigins).toEqual(['http://127.0.0.1:3000']);
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
});

describe('loadPublicConfigFrom', () => {
  it('does not expose server secrets', () => {
    const publicConfig = loadPublicConfigFrom({
      NEXT_PUBLIC_PATCHPILOT_ENVIRONMENT: 'development',
      DATABASE_URL: 'postgresql://should-not-appear',
    });

    expect(publicConfig.appName).toBe('PatchPilot');
    expect(publicConfig).not.toHaveProperty('databaseUrl');
    expect(JSON.stringify(publicConfig)).not.toContain('postgresql');
  });

  it('does not default the public environment label to development', () => {
    expect(() => loadPublicConfigFrom({})).toThrow(/Public configuration is invalid/);
  });

  it('does not pass the process environment object through as public config input', () => {
    const publicConfig = loadPublicConfigFrom({
      NEXT_PUBLIC_PATCHPILOT_ENVIRONMENT: 'test',
      DATABASE_URL: 'postgresql://should-not-appear',
      OBJECT_STORAGE_SECRET_KEY: 'should-not-appear',
    });

    expect(Object.keys(publicConfig).sort()).toEqual(['appName', 'deploymentEnvironment']);
  });
});
