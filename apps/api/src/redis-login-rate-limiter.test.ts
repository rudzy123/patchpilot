import { afterEach, describe, expect, it, vi } from 'vitest';

import { digestLoginAccount, LOGIN_UNAVAILABLE } from '@patchpilot/auth';
import { loadServerConfigFrom } from '@patchpilot/config';
import { createLogger } from '@patchpilot/logger';
import { createFoundationTestEnv } from '@patchpilot/test-utils';

import { createRedisLoginRateLimiter } from './redis-login-rate-limiter.js';

describe('redis login rate limiter adapter', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('times out hung Redis commands without an arbitrary sleep', async () => {
    vi.useFakeTimers();
    const config = loadServerConfigFrom(createFoundationTestEnv());
    const limiter = createRedisLoginRateLimiter({
      redisUrl: 'redis://127.0.0.1:1',
      auth: config.auth,
      logger: createLogger({
        service: 'api-login-limiter-test',
        level: 'silent',
        pretty: false,
      }),
      commands: {
        increment(_key, _windowSeconds) {
          return new Promise<number>(() => {
            /* never settles */
          });
        },
        async close() {
          return;
        },
      },
    });

    const pending = limiter.consume({
      peerIp: '192.0.2.10',
      accountDigest: digestLoginAccount('owner@synthetic.patchpilot.test'),
    });
    await vi.advanceTimersByTimeAsync(config.auth.rateLimitRedisTimeoutMs);
    await expect(pending).resolves.toEqual({ ok: false, error: LOGIN_UNAVAILABLE });
    await limiter.close();
  });
});
