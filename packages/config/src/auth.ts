import { z } from 'zod';

/** Production cookie name. Requires Secure, Path=/, and no Domain (`__Host-` prefix). */
export const PRODUCTION_SESSION_COOKIE_NAME = '__Host-patchpilot.sid';

/** Loopback HTTP development and test cookie name. Must not be used in production. */
export const DEVELOPMENT_SESSION_COOKIE_NAME = 'patchpilot.sid';

export const DEFAULT_CSRF_HEADER_NAME = 'x-csrf-token';

export const AUTH_PASSWORD_MIN_LENGTH = 12;
export const AUTH_PASSWORD_MAX_BYTES = 128;

/** OWASP minimum memory for interactive Argon2id (KiB). */
export const AUTH_ARGON2_MEMORY_KIB_MIN_PRODUCTION = 19456;
export const AUTH_ARGON2_TIME_COST_MIN_PRODUCTION = 2;
export const AUTH_ARGON2_PARALLELISM_MIN = 1;

/** Guarded test/development floor so dummy hashing cannot be configured as a no-op. */
export const AUTH_ARGON2_MEMORY_KIB_MIN_DEVELOPMENT = 8192;
export const AUTH_ARGON2_TIME_COST_MIN_DEVELOPMENT = 1;

export const AUTH_ARGON2_MEMORY_KIB_MAX = 262144;
export const AUTH_ARGON2_TIME_COST_MAX = 6;
export const AUTH_ARGON2_PARALLELISM_MAX = 4;

export const AUTH_LOGIN_RATE_LIMIT_MAX_ATTEMPTS_MIN = 1;
export const AUTH_LOGIN_RATE_LIMIT_MAX_ATTEMPTS_MAX = 20;
export const AUTH_LOGIN_RATE_LIMIT_WINDOW_SECONDS_MIN = 30;
export const AUTH_LOGIN_RATE_LIMIT_WINDOW_SECONDS_MAX = 3600;
export const AUTH_RATE_LIMIT_REDIS_TIMEOUT_MS_MIN = 50;
export const AUTH_RATE_LIMIT_REDIS_TIMEOUT_MS_MAX = 2000;

const csrfHeaderNamePattern = /^[A-Za-z][A-Za-z0-9-]*$/;

export const authConfigSchema = z.object({
  sessionAbsoluteTtlSeconds: z.number().int().positive(),
  sessionIdleTtlSeconds: z.number().int().positive(),
  lastSeenMinIntervalSeconds: z.number().int().positive(),
  cookieName: z.string().min(1).max(64),
  cookieSecure: z.boolean(),
  csrfHeaderName: z
    .string()
    .min(1)
    .max(64)
    .regex(csrfHeaderNamePattern, 'CSRF header name must be a valid HTTP header token.'),
  passwordMinLength: z.number().int().min(AUTH_PASSWORD_MIN_LENGTH).max(AUTH_PASSWORD_MAX_BYTES),
  passwordMaxBytes: z.number().int().min(AUTH_PASSWORD_MIN_LENGTH).max(AUTH_PASSWORD_MAX_BYTES),
  argon2MemoryKib: z.number().int().positive(),
  argon2TimeCost: z.number().int().positive(),
  argon2Parallelism: z.number().int().positive(),
  loginRateLimitIpMaxAttempts: z.number().int(),
  loginRateLimitIpWindowSeconds: z.number().int(),
  loginRateLimitAccountMaxAttempts: z.number().int(),
  loginRateLimitAccountWindowSeconds: z.number().int(),
  rateLimitRedisTimeoutMs: z.number().int(),
});

export type AuthConfig = z.infer<typeof authConfigSchema>;
