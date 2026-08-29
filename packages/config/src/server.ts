import { z } from 'zod';

import {
  AUTH_ARGON2_MEMORY_KIB_MAX,
  AUTH_ARGON2_MEMORY_KIB_MIN_DEVELOPMENT,
  AUTH_ARGON2_MEMORY_KIB_MIN_PRODUCTION,
  AUTH_ARGON2_PARALLELISM_MAX,
  AUTH_ARGON2_PARALLELISM_MIN,
  AUTH_ARGON2_TIME_COST_MAX,
  AUTH_ARGON2_TIME_COST_MIN_DEVELOPMENT,
  AUTH_ARGON2_TIME_COST_MIN_PRODUCTION,
  AUTH_LOGIN_RATE_LIMIT_MAX_ATTEMPTS_MAX,
  AUTH_LOGIN_RATE_LIMIT_MAX_ATTEMPTS_MIN,
  AUTH_LOGIN_RATE_LIMIT_WINDOW_SECONDS_MAX,
  AUTH_LOGIN_RATE_LIMIT_WINDOW_SECONDS_MIN,
  AUTH_RATE_LIMIT_REDIS_TIMEOUT_MS_MAX,
  AUTH_RATE_LIMIT_REDIS_TIMEOUT_MS_MIN,
  DEVELOPMENT_SESSION_COOKIE_NAME,
  PRODUCTION_SESSION_COOKIE_NAME,
  authConfigSchema,
} from './auth.js';
import { hydrateProcessEnvFromDevelopmentFiles } from './load-env-files.js';
import { parseBoolean, parseInteger, readOptional, readRequired } from './read-env.js';
import {
  bucketNameLooksLikeDevelopmentPlaceholder,
  isValidObjectStorageBucketName,
  refineSbomNumericBounds,
  sbomConfigSchema,
  sbomRelationshipIssues,
  type SbomConfig,
} from './sbom.js';

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
    sbom: sbomConfigSchema,
    openTelemetry: z.object({
      enabled: z.boolean(),
      tracesEndpoint: z.string().min(1).optional(),
    }),
    readinessTimeoutMs: z.number().int().positive(),
    shutdownTimeoutMs: z.number().int().positive(),
    requestBodyLimitBytes: z.number().int().positive(),
    requestIdHeader: z.string().min(1),
    correlationIdHeader: z.string().min(1),
    auth: authConfigSchema,
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

    if (!isValidObjectStorageBucketName(value.objectStorage.bucket)) {
      context.addIssue({
        code: 'custom',
        path: ['objectStorage', 'bucket'],
        message:
          'Object-storage bucket must be a valid S3-compatible bucket name (3–63 characters, lowercase, no adjacent periods, not an IPv4 address).',
      });
    }

    if (
      value.deploymentEnvironment === 'production' &&
      bucketNameLooksLikeDevelopmentPlaceholder(value.objectStorage.bucket)
    ) {
      context.addIssue({
        code: 'custom',
        path: ['objectStorage', 'bucket'],
        message:
          'Production object-storage bucket names must not use development placeholders such as patchpilot-dev.',
      });
    }

    refineSbomNumericBounds(value.sbom, (issue) => {
      context.addIssue({
        code: 'custom',
        path: ['sbom', ...issue.path],
        message: issue.message,
      });
    });

    for (const issue of sbomRelationshipIssues(value.sbom)) {
      context.addIssue({
        code: 'custom',
        path: ['sbom', ...issue.path],
        message: issue.message,
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

    refineAuthConfig(value, context);
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
      sbom: loadSbomConfigFrom(env),
      auth: {
        sessionAbsoluteTtlSeconds: parseInteger(
          readRequired(env, 'AUTH_SESSION_ABSOLUTE_TTL_SECONDS'),
          'AUTH_SESSION_ABSOLUTE_TTL_SECONDS',
        ),
        sessionIdleTtlSeconds: parseInteger(
          readRequired(env, 'AUTH_SESSION_IDLE_TTL_SECONDS'),
          'AUTH_SESSION_IDLE_TTL_SECONDS',
        ),
        lastSeenMinIntervalSeconds: parseInteger(
          readRequired(env, 'AUTH_SESSION_LAST_SEEN_MIN_INTERVAL_SECONDS'),
          'AUTH_SESSION_LAST_SEEN_MIN_INTERVAL_SECONDS',
        ),
        cookieName: readRequired(env, 'AUTH_COOKIE_NAME'),
        cookieSecure: parseBoolean(readRequired(env, 'AUTH_COOKIE_SECURE'), 'AUTH_COOKIE_SECURE'),
        csrfHeaderName: readRequired(env, 'AUTH_CSRF_HEADER_NAME'),
        passwordMinLength: parseInteger(
          readRequired(env, 'AUTH_PASSWORD_MIN_LENGTH'),
          'AUTH_PASSWORD_MIN_LENGTH',
        ),
        passwordMaxBytes: parseInteger(
          readRequired(env, 'AUTH_PASSWORD_MAX_BYTES'),
          'AUTH_PASSWORD_MAX_BYTES',
        ),
        argon2MemoryKib: parseInteger(
          readRequired(env, 'AUTH_ARGON2_MEMORY_KIB'),
          'AUTH_ARGON2_MEMORY_KIB',
        ),
        argon2TimeCost: parseInteger(
          readRequired(env, 'AUTH_ARGON2_TIME_COST'),
          'AUTH_ARGON2_TIME_COST',
        ),
        argon2Parallelism: parseInteger(
          readRequired(env, 'AUTH_ARGON2_PARALLELISM'),
          'AUTH_ARGON2_PARALLELISM',
        ),
        loginRateLimitIpMaxAttempts: parseInteger(
          readRequired(env, 'AUTH_LOGIN_RATE_LIMIT_IP_MAX'),
          'AUTH_LOGIN_RATE_LIMIT_IP_MAX',
        ),
        loginRateLimitIpWindowSeconds: parseInteger(
          readRequired(env, 'AUTH_LOGIN_RATE_LIMIT_IP_WINDOW_SECONDS'),
          'AUTH_LOGIN_RATE_LIMIT_IP_WINDOW_SECONDS',
        ),
        loginRateLimitAccountMaxAttempts: parseInteger(
          readRequired(env, 'AUTH_LOGIN_RATE_LIMIT_ACCOUNT_MAX'),
          'AUTH_LOGIN_RATE_LIMIT_ACCOUNT_MAX',
        ),
        loginRateLimitAccountWindowSeconds: parseInteger(
          readRequired(env, 'AUTH_LOGIN_RATE_LIMIT_ACCOUNT_WINDOW_SECONDS'),
          'AUTH_LOGIN_RATE_LIMIT_ACCOUNT_WINDOW_SECONDS',
        ),
        rateLimitRedisTimeoutMs: parseInteger(
          readRequired(env, 'AUTH_RATE_LIMIT_REDIS_TIMEOUT_MS'),
          'AUTH_RATE_LIMIT_REDIS_TIMEOUT_MS',
        ),
      },
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
  hydrateProcessEnvFromDevelopmentFiles(process.env, { moduleUrl: import.meta.url });
  return loadServerConfigFrom(process.env);
}

function loadSbomConfigFrom(env: Readonly<Record<string, string | undefined>>): SbomConfig {
  return {
    uploadMaxBytes: parseInteger(
      readRequired(env, 'SBOM_UPLOAD_MAX_BYTES'),
      'SBOM_UPLOAD_MAX_BYTES',
    ),
    jsonMaxDepth: parseInteger(readRequired(env, 'SBOM_JSON_MAX_DEPTH'), 'SBOM_JSON_MAX_DEPTH'),
    jsonMaxNodes: parseInteger(readRequired(env, 'SBOM_JSON_MAX_NODES'), 'SBOM_JSON_MAX_NODES'),
    jsonMaxStringBytes: parseInteger(
      readRequired(env, 'SBOM_JSON_MAX_STRING_BYTES'),
      'SBOM_JSON_MAX_STRING_BYTES',
    ),
    maxComponents: parseInteger(readRequired(env, 'SBOM_MAX_COMPONENTS'), 'SBOM_MAX_COMPONENTS'),
    maxDependencyEdges: parseInteger(
      readRequired(env, 'SBOM_MAX_DEPENDENCY_EDGES'),
      'SBOM_MAX_DEPENDENCY_EDGES',
    ),
    maxBomRefBytes: parseInteger(
      readRequired(env, 'SBOM_MAX_BOM_REF_BYTES'),
      'SBOM_MAX_BOM_REF_BYTES',
    ),
    maxPurlBytes: parseInteger(readRequired(env, 'SBOM_MAX_PURL_BYTES'), 'SBOM_MAX_PURL_BYTES'),
    maxComponentNameChars: parseInteger(
      readRequired(env, 'SBOM_MAX_COMPONENT_NAME_CHARS'),
      'SBOM_MAX_COMPONENT_NAME_CHARS',
    ),
    maxVersionChars: parseInteger(
      readRequired(env, 'SBOM_MAX_VERSION_CHARS'),
      'SBOM_MAX_VERSION_CHARS',
    ),
    maxMetadataTools: parseInteger(
      readRequired(env, 'SBOM_MAX_METADATA_TOOLS'),
      'SBOM_MAX_METADATA_TOOLS',
    ),
    maxExternalRefsPerComponent: parseInteger(
      readRequired(env, 'SBOM_MAX_EXTERNAL_REFS_PER_COMPONENT'),
      'SBOM_MAX_EXTERNAL_REFS_PER_COMPONENT',
    ),
    maxPropertiesPerComponent: parseInteger(
      readRequired(env, 'SBOM_MAX_PROPERTIES_PER_COMPONENT'),
      'SBOM_MAX_PROPERTIES_PER_COMPONENT',
    ),
    parserTimeoutMs: parseInteger(
      readRequired(env, 'SBOM_PARSER_TIMEOUT_MS'),
      'SBOM_PARSER_TIMEOUT_MS',
    ),
    processingLeaseMs: parseInteger(
      readRequired(env, 'SBOM_PROCESSING_LEASE_MS'),
      'SBOM_PROCESSING_LEASE_MS',
    ),
    idempotencyTtlSeconds: parseInteger(
      readRequired(env, 'SBOM_IDEMPOTENCY_TTL_SECONDS'),
      'SBOM_IDEMPOTENCY_TTL_SECONDS',
    ),
    uploadRateLimitMax: parseInteger(
      readRequired(env, 'SBOM_UPLOAD_RATE_LIMIT_MAX'),
      'SBOM_UPLOAD_RATE_LIMIT_MAX',
    ),
    uploadRateLimitWindowSeconds: parseInteger(
      readRequired(env, 'SBOM_UPLOAD_RATE_LIMIT_WINDOW_SECONDS'),
      'SBOM_UPLOAD_RATE_LIMIT_WINDOW_SECONDS',
    ),
    objectStorageOperationTimeoutMs: parseInteger(
      readRequired(env, 'OBJECT_STORAGE_OPERATION_TIMEOUT_MS'),
      'OBJECT_STORAGE_OPERATION_TIMEOUT_MS',
    ),
    orphanGraceSeconds: parseInteger(
      readRequired(env, 'SBOM_ORPHAN_GRACE_SECONDS'),
      'SBOM_ORPHAN_GRACE_SECONDS',
    ),
    parserVersion: readRequired(env, 'SBOM_PARSER_VERSION'),
    normalizationVersion: readRequired(env, 'SBOM_NORMALIZATION_VERSION'),
  };
}

function refineAuthConfig(value: ServerConfig, context: z.RefinementCtx): void {
  const { auth } = value;
  const production = value.deploymentEnvironment === 'production';
  const guardedCheapArgon2 = !production && value.allowDevelopmentAdapters === true;

  if (auth.sessionIdleTtlSeconds > auth.sessionAbsoluteTtlSeconds) {
    context.addIssue({
      code: 'custom',
      path: ['auth', 'sessionIdleTtlSeconds'],
      message: 'Idle session TTL must not exceed absolute session TTL.',
    });
  }

  if (auth.lastSeenMinIntervalSeconds > auth.sessionIdleTtlSeconds) {
    context.addIssue({
      code: 'custom',
      path: ['auth', 'lastSeenMinIntervalSeconds'],
      message: 'lastSeenAt update interval must not exceed idle session TTL.',
    });
  }

  if (auth.passwordMinLength > auth.passwordMaxBytes) {
    context.addIssue({
      code: 'custom',
      path: ['auth', 'passwordMinLength'],
      message: 'Password minimum character length must not exceed the maximum UTF-8 byte length.',
    });
  }

  if (auth.cookieName.startsWith('__Host-') && !auth.cookieSecure) {
    context.addIssue({
      code: 'custom',
      path: ['auth', 'cookieSecure'],
      message: 'Cookies with the __Host- prefix must set Secure=true.',
    });
  }

  if (production) {
    if (!auth.cookieSecure) {
      context.addIssue({
        code: 'custom',
        path: ['auth', 'cookieSecure'],
        message:
          'Production cookies must set Secure=true. Plaintext HTTP session cookies are not permitted.',
      });
    }

    if (auth.cookieName === DEVELOPMENT_SESSION_COOKIE_NAME) {
      context.addIssue({
        code: 'custom',
        path: ['auth', 'cookieName'],
        message:
          'Production must not use the loopback development cookie name. Use the __Host- production cookie name.',
      });
    }

    if (auth.cookieName !== PRODUCTION_SESSION_COOKIE_NAME) {
      context.addIssue({
        code: 'custom',
        path: ['auth', 'cookieName'],
        message: `Production cookie name must be ${PRODUCTION_SESSION_COOKIE_NAME}.`,
      });
    }

    for (const [index, origin] of value.corsAllowedOrigins.entries()) {
      if (!origin.startsWith('https://')) {
        context.addIssue({
          code: 'custom',
          path: ['corsAllowedOrigins', index],
          message:
            'Production approved origins must be https URLs. HTTP and wildcard origins are not permitted.',
        });
      }
    }
  } else if (auth.cookieName !== DEVELOPMENT_SESSION_COOKIE_NAME) {
    context.addIssue({
      code: 'custom',
      path: ['auth', 'cookieName'],
      message: `Development and test cookie name must be ${DEVELOPMENT_SESSION_COOKIE_NAME}.`,
    });
  }

  const argon2MemoryMin = guardedCheapArgon2
    ? AUTH_ARGON2_MEMORY_KIB_MIN_DEVELOPMENT
    : AUTH_ARGON2_MEMORY_KIB_MIN_PRODUCTION;
  const argon2TimeMin = guardedCheapArgon2
    ? AUTH_ARGON2_TIME_COST_MIN_DEVELOPMENT
    : AUTH_ARGON2_TIME_COST_MIN_PRODUCTION;

  if (auth.argon2MemoryKib < argon2MemoryMin) {
    context.addIssue({
      code: 'custom',
      path: ['auth', 'argon2MemoryKib'],
      message: production
        ? `Production Argon2 memory must be at least ${AUTH_ARGON2_MEMORY_KIB_MIN_PRODUCTION} KiB.`
        : `Argon2 memory must be at least ${argon2MemoryMin} KiB.`,
    });
  }

  if (auth.argon2MemoryKib > AUTH_ARGON2_MEMORY_KIB_MAX) {
    context.addIssue({
      code: 'custom',
      path: ['auth', 'argon2MemoryKib'],
      message: `Argon2 memory must not exceed ${AUTH_ARGON2_MEMORY_KIB_MAX} KiB.`,
    });
  }

  if (auth.argon2TimeCost < argon2TimeMin) {
    context.addIssue({
      code: 'custom',
      path: ['auth', 'argon2TimeCost'],
      message: production
        ? `Production Argon2 time cost must be at least ${AUTH_ARGON2_TIME_COST_MIN_PRODUCTION}.`
        : `Argon2 time cost must be at least ${argon2TimeMin}.`,
    });
  }

  if (auth.argon2TimeCost > AUTH_ARGON2_TIME_COST_MAX) {
    context.addIssue({
      code: 'custom',
      path: ['auth', 'argon2TimeCost'],
      message: `Argon2 time cost must not exceed ${AUTH_ARGON2_TIME_COST_MAX}.`,
    });
  }

  if (
    auth.argon2Parallelism < AUTH_ARGON2_PARALLELISM_MIN ||
    auth.argon2Parallelism > AUTH_ARGON2_PARALLELISM_MAX
  ) {
    context.addIssue({
      code: 'custom',
      path: ['auth', 'argon2Parallelism'],
      message: `Argon2 parallelism must be between ${AUTH_ARGON2_PARALLELISM_MIN} and ${AUTH_ARGON2_PARALLELISM_MAX}.`,
    });
  }

  refineRateLimit(
    auth.loginRateLimitIpMaxAttempts,
    ['auth', 'loginRateLimitIpMaxAttempts'],
    AUTH_LOGIN_RATE_LIMIT_MAX_ATTEMPTS_MIN,
    AUTH_LOGIN_RATE_LIMIT_MAX_ATTEMPTS_MAX,
    'Login IP rate-limit max attempts',
    context,
  );
  refineRateLimit(
    auth.loginRateLimitAccountMaxAttempts,
    ['auth', 'loginRateLimitAccountMaxAttempts'],
    AUTH_LOGIN_RATE_LIMIT_MAX_ATTEMPTS_MIN,
    AUTH_LOGIN_RATE_LIMIT_MAX_ATTEMPTS_MAX,
    'Login account rate-limit max attempts',
    context,
  );
  refineRateLimit(
    auth.loginRateLimitIpWindowSeconds,
    ['auth', 'loginRateLimitIpWindowSeconds'],
    AUTH_LOGIN_RATE_LIMIT_WINDOW_SECONDS_MIN,
    AUTH_LOGIN_RATE_LIMIT_WINDOW_SECONDS_MAX,
    'Login IP rate-limit window seconds',
    context,
  );
  refineRateLimit(
    auth.loginRateLimitAccountWindowSeconds,
    ['auth', 'loginRateLimitAccountWindowSeconds'],
    AUTH_LOGIN_RATE_LIMIT_WINDOW_SECONDS_MIN,
    AUTH_LOGIN_RATE_LIMIT_WINDOW_SECONDS_MAX,
    'Login account rate-limit window seconds',
    context,
  );
  refineRateLimit(
    auth.rateLimitRedisTimeoutMs,
    ['auth', 'rateLimitRedisTimeoutMs'],
    AUTH_RATE_LIMIT_REDIS_TIMEOUT_MS_MIN,
    AUTH_RATE_LIMIT_REDIS_TIMEOUT_MS_MAX,
    'Login rate-limit Redis timeout',
    context,
  );
}

function refineRateLimit(
  value: number,
  path: Array<string | number>,
  min: number,
  max: number,
  label: string,
  context: z.RefinementCtx,
): void {
  if (value < min || value > max) {
    context.addIssue({
      code: 'custom',
      path,
      message: `${label} must be between ${min} and ${max}.`,
    });
  }
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
