import { z } from 'zod';

import { parseBoolean, parseInteger, readOptional, readRequired } from './read-env.js';

const deploymentEnvironmentSchema = z.enum(['development', 'test', 'production']);
const logLevelSchema = z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']);

const developmentCredentialFragments = [
  'patchpilot-dev',
  'not-for-production',
  'minioadmin',
  'changeme',
  'password',
] as const;

export const serverConfigSchema = z
  .object({
    deploymentEnvironment: deploymentEnvironmentSchema,
    allowDevelopmentAdapters: z.boolean(),
    logLevel: logLevelSchema,
    prettyLogs: z.boolean(),
    apiHost: z.string().min(1),
    apiPort: z.number().int().positive(),
    webPort: z.number().int().positive(),
    corsAllowedOrigins: z.array(z.string().url()).min(1),
    databaseUrl: z.string().min(1),
    redisUrl: z.string().min(1),
    objectStorage: z.object({
      endpoint: z.string().min(1),
      accessKey: z.string().min(1),
      secretKey: z.string().min(1),
      bucket: z.string().min(1),
      useSsl: z.boolean(),
    }),
    openTelemetry: z.object({
      enabled: z.boolean(),
      tracesEndpoint: z.string().min(1).optional(),
    }),
    readinessTimeoutMs: z.number().int().positive(),
    shutdownTimeoutMs: z.number().int().positive(),
    requestBodyLimitBytes: z.number().int().positive(),
    requestIdHeader: z.string().min(1),
    correlationIdHeader: z.string().min(1),
  })
  .superRefine((value, context) => {
    if (value.deploymentEnvironment === 'production' && value.allowDevelopmentAdapters) {
      context.addIssue({
        code: 'custom',
        path: ['allowDevelopmentAdapters'],
        message:
          'allowDevelopmentAdapters must be false when deploymentEnvironment is production. NODE_ENV=production is not sufficient if this flag is true.',
      });
    }

    if (value.deploymentEnvironment === 'production' && value.prettyLogs) {
      context.addIssue({
        code: 'custom',
        path: ['prettyLogs'],
        message: 'Pretty logs are a development adapter and cannot be enabled in production.',
      });
    }

    if (value.deploymentEnvironment === 'production' && containsDevelopmentCredential(value)) {
      context.addIssue({
        code: 'custom',
        path: ['objectStorage'],
        message:
          'Production configuration rejected development-only placeholder credentials. Supply operator secrets at runtime.',
      });
    }

    if (value.deploymentEnvironment === 'production' && !redisUrlHasPassword(value.redisUrl)) {
      context.addIssue({
        code: 'custom',
        path: ['redisUrl'],
        message:
          'Production Redis URLs must include a password. Unauthenticated Redis is a development adapter.',
      });
    }

    if (value.corsAllowedOrigins.some((origin) => origin === '*')) {
      context.addIssue({
        code: 'custom',
        path: ['corsAllowedOrigins'],
        message: 'CORS origins must be an exact allowlist. Wildcard origins are not permitted.',
      });
    }
  });

export type ServerConfig = z.infer<typeof serverConfigSchema>;
export type DeploymentEnvironment = z.infer<typeof deploymentEnvironmentSchema>;

export class ConfigValidationError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = 'ConfigValidationError';
  }
}

export function loadServerConfigFrom(
  env: Readonly<Record<string, string | undefined>>,
): ServerConfig {
  try {
    const tracesEndpoint = readOptional(env, 'OTEL_EXPORTER_OTLP_TRACES_ENDPOINT');
    const candidate = {
      deploymentEnvironment: readRequired(env, 'PATCHPILOT_DEPLOYMENT_ENVIRONMENT'),
      allowDevelopmentAdapters: parseBoolean(
        readRequired(env, 'PATCHPILOT_ALLOW_DEVELOPMENT_ADAPTERS'),
        'PATCHPILOT_ALLOW_DEVELOPMENT_ADAPTERS',
      ),
      logLevel: readRequired(env, 'LOG_LEVEL'),
      prettyLogs: parseBoolean(readRequired(env, 'LOG_PRETTY'), 'LOG_PRETTY'),
      apiHost: readRequired(env, 'API_HOST'),
      apiPort: parseInteger(readRequired(env, 'API_PORT'), 'API_PORT'),
      webPort: parseInteger(readRequired(env, 'WEB_PORT'), 'WEB_PORT'),
      corsAllowedOrigins: readRequired(env, 'CORS_ALLOWED_ORIGINS')
        .split(',')
        .map((origin) => origin.trim())
        .filter((origin) => origin.length > 0),
      databaseUrl: readRequired(env, 'DATABASE_URL'),
      redisUrl: readRequired(env, 'REDIS_URL'),
      objectStorage: {
        endpoint: readRequired(env, 'OBJECT_STORAGE_ENDPOINT'),
        accessKey: readRequired(env, 'OBJECT_STORAGE_ACCESS_KEY'),
        secretKey: readRequired(env, 'OBJECT_STORAGE_SECRET_KEY'),
        bucket: readRequired(env, 'OBJECT_STORAGE_BUCKET'),
        useSsl: parseBoolean(readRequired(env, 'OBJECT_STORAGE_USE_SSL'), 'OBJECT_STORAGE_USE_SSL'),
      },
      openTelemetry: {
        enabled: parseBoolean(readRequired(env, 'OTEL_ENABLED'), 'OTEL_ENABLED'),
        ...(tracesEndpoint === undefined ? {} : { tracesEndpoint }),
      },
      readinessTimeoutMs: parseInteger(
        readRequired(env, 'READINESS_TIMEOUT_MS'),
        'READINESS_TIMEOUT_MS',
      ),
      shutdownTimeoutMs: parseInteger(
        readRequired(env, 'SHUTDOWN_TIMEOUT_MS'),
        'SHUTDOWN_TIMEOUT_MS',
      ),
      requestBodyLimitBytes: parseInteger(
        readRequired(env, 'REQUEST_BODY_LIMIT_BYTES'),
        'REQUEST_BODY_LIMIT_BYTES',
      ),
      requestIdHeader: readRequired(env, 'REQUEST_ID_HEADER'),
      correlationIdHeader: readRequired(env, 'CORRELATION_ID_HEADER'),
    };

    const parsed = serverConfigSchema.safeParse(candidate);
    if (!parsed.success) {
      const message = parsed.error.issues
        .map((issue) => {
          const path = issue.path.length > 0 ? issue.path.join('.') : 'config';
          return `${path}: ${issue.message}`;
        })
        .join('; ');
      throw new ConfigValidationError(message);
    }

    return parsed.data;
  } catch (error) {
    if (error instanceof ConfigValidationError) {
      throw error;
    }

    if (error instanceof Error) {
      throw new ConfigValidationError(error.message);
    }

    throw new ConfigValidationError('Configuration is invalid.');
  }
}

export function loadServerConfig(): ServerConfig {
  return loadServerConfigFrom(process.env);
}

function redisUrlHasPassword(redisUrl: string): boolean {
  try {
    const parsed = new URL(redisUrl);
    return parsed.password.length > 0;
  } catch {
    return false;
  }
}

function containsDevelopmentCredential(config: ServerConfig): boolean {
  const haystack = [
    config.databaseUrl,
    config.redisUrl,
    config.objectStorage.accessKey,
    config.objectStorage.secretKey,
    config.objectStorage.endpoint,
  ]
    .join(' ')
    .toLowerCase();

  return developmentCredentialFragments.some((fragment) => haystack.includes(fragment));
}
