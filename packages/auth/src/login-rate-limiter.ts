import type { AuthConfig } from '@patchpilot/config';
import type { Logger } from '@patchpilot/logger';
import { err, ok, type Result } from '@patchpilot/domain';

import { LOGIN_RATE_LIMITED, LOGIN_UNAVAILABLE } from './errors.js';
import { normalizeDirectPeerIp } from './login-peer-ip.js';
import { isLoginRateLimitTimeoutError } from './login-redis-timeout.js';
import { digestLoginPeerIp } from './token-digests.js';

export const LOGIN_REDIS_IP_KEY_PREFIX = 'pp:login:v1:ip:';
export const LOGIN_REDIS_ACCOUNT_KEY_PREFIX = 'pp:login:v1:acct:';

const ACCOUNT_DIGEST_PATTERN = /^[a-f0-9]{64}$/;

export const loginRateLimitFailureCategories = [
  'ip_threshold',
  'account_threshold',
  'combined_threshold',
  'redis_unavailable',
  'redis_timeout',
  'redis_command_failed',
  'invalid_peer_ip',
  'invalid_account_digest',
] as const;

export type LoginRateLimitFailureCategory = (typeof loginRateLimitFailureCategories)[number];

export type LoginRateLimitConsumeInput = {
  peerIp: string;
  accountDigest: string;
};

export type LoginRateLimiter = {
  consume(input: LoginRateLimitConsumeInput): Promise<Result<void>>;
};

export type LoginRateLimitCounters = {
  increment(key: string, windowSeconds: number): Promise<number>;
};

export type RedisLoginCommands = LoginRateLimitCounters & {
  close(): Promise<void>;
};

export function loginIpRedisKey(normalizedPeerIp: string): string {
  return `${LOGIN_REDIS_IP_KEY_PREFIX}${digestLoginPeerIp(normalizedPeerIp)}`;
}

export function loginAccountRedisKey(accountDigest: string): string {
  return `${LOGIN_REDIS_ACCOUNT_KEY_PREFIX}${accountDigest}`;
}

export function createLoginRateLimiter(dependencies: {
  counters: LoginRateLimitCounters;
  auth: AuthConfig;
  logger: Logger;
}): LoginRateLimiter {
  return {
    consume(input: LoginRateLimitConsumeInput): Promise<Result<void>> {
      return consumeLoginRateLimit(dependencies, input);
    },
  };
}

async function consumeLoginRateLimit(
  dependencies: {
    counters: LoginRateLimitCounters;
    auth: AuthConfig;
    logger: Logger;
  },
  input: LoginRateLimitConsumeInput,
): Promise<Result<void>> {
  const peerIp = normalizeDirectPeerIp(input.peerIp);
  if (peerIp === undefined) {
    return failClosed(dependencies.logger, 'invalid_peer_ip');
  }

  if (!ACCOUNT_DIGEST_PATTERN.test(input.accountDigest)) {
    return failClosed(dependencies.logger, 'invalid_account_digest');
  }

  const ipKey = loginIpRedisKey(peerIp);
  const accountKey = loginAccountRedisKey(input.accountDigest);

  let ipCount: number;
  let accountCount: number;
  try {
    ipCount = await dependencies.counters.increment(
      ipKey,
      dependencies.auth.loginRateLimitIpWindowSeconds,
    );
    accountCount = await dependencies.counters.increment(
      accountKey,
      dependencies.auth.loginRateLimitAccountWindowSeconds,
    );
  } catch (error) {
    if (isLoginRateLimitTimeoutError(error)) {
      return failClosed(dependencies.logger, 'redis_timeout');
    }

    return failClosed(dependencies.logger, classifyCounterFailure(error));
  }

  const ipLimited = ipCount > dependencies.auth.loginRateLimitIpMaxAttempts;
  const accountLimited = accountCount > dependencies.auth.loginRateLimitAccountMaxAttempts;
  if (!ipLimited && !accountLimited) {
    return ok(undefined);
  }

  const category: LoginRateLimitFailureCategory =
    ipLimited && accountLimited
      ? 'combined_threshold'
      : ipLimited
        ? 'ip_threshold'
        : 'account_threshold';
  dependencies.logger.info({ event: 'auth.login_rate_limited', category }, 'login rate limited');
  return err(LOGIN_RATE_LIMITED);
}

function classifyCounterFailure(error: unknown): LoginRateLimitFailureCategory {
  if (error instanceof Error) {
    const message = error.message.toLowerCase();
    if (message.includes('timed out') || message.includes('timeout')) {
      return 'redis_timeout';
    }

    if (
      message.includes('econnrefused') ||
      message.includes('enotfound') ||
      message.includes('connection') ||
      message.includes('unavailable') ||
      message.includes("stream isn't writeable") ||
      message.includes('connect')
    ) {
      return 'redis_unavailable';
    }
  }

  return 'redis_command_failed';
}

function failClosed(logger: Logger, category: LoginRateLimitFailureCategory): Result<void> {
  logger.warn({ event: 'auth.login_limiter_failed', category }, 'login limiter unavailable');
  return err(LOGIN_UNAVAILABLE);
}
