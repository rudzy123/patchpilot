import { afterAll, describe, expect, it } from 'vitest';

import {
  digestLoginAccount,
  LOGIN_RATE_LIMITED,
  loginAccountRedisKey,
  loginIpRedisKey,
} from '@patchpilot/auth';
import { loadServerConfigFrom } from '@patchpilot/config';
import { createLogger } from '@patchpilot/logger';
import { createFoundationTestEnv } from '@patchpilot/test-utils';

import { createRedisLoginRateLimiter } from './redis-login-rate-limiter.js';

describe('redis login rate limiter integration', () => {
  const email = `limiter-${Date.now()}@synthetic.patchpilot.test`;
  const peerIp = `203.0.113.${(Date.now() % 250) + 1}`;
  const accountDigest = digestLoginAccount(email);
  const ipKey = loginIpRedisKey(peerIp);
  const accountKey = loginAccountRedisKey(accountDigest);
  const config = loadServerConfigFrom(createFoundationTestEnv());
  const limiter = createRedisLoginRateLimiter({
    redisUrl: config.redisUrl,
    auth: {
      ...config.auth,
      loginRateLimitIpMaxAttempts: 1,
      loginRateLimitAccountMaxAttempts: 1,
      loginRateLimitIpWindowSeconds: 30,
      loginRateLimitAccountWindowSeconds: 30,
    },
    logger: createLogger({
      service: 'api-login-limiter-test',
      level: 'silent',
      pretty: false,
    }),
  });

  afterAll(async () => {
    await limiter.close();
  });

  it('enforces dual keys against Compose Redis without storing the raw email', async () => {
    const first = await limiter.consume({ peerIp, accountDigest });
    const second = await limiter.consume({ peerIp, accountDigest });
    expect(first).toEqual({ ok: true, value: undefined });
    expect(second).toEqual({ ok: false, error: LOGIN_RATE_LIMITED });
    expect(ipKey.toLowerCase()).not.toContain(email.toLowerCase());
    expect(accountKey.toLowerCase()).not.toContain(email.toLowerCase());
    expect(ipKey).not.toContain(peerIp);
  });
});
