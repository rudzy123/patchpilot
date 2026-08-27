import { afterEach, describe, expect, it, vi } from 'vitest';

import { LOGIN_RATE_LIMITED, LOGIN_UNAVAILABLE } from './errors.js';
import { createFakeLoginRateLimiter } from './fake-login-rate-limiter.js';
import { normalizeDirectPeerIp, selectDirectPeerIp } from './login-peer-ip.js';
import {
  createLoginRateLimiter,
  loginAccountRedisKey,
  loginIpRedisKey,
  LOGIN_REDIS_ACCOUNT_KEY_PREFIX,
  LOGIN_REDIS_IP_KEY_PREFIX,
} from './login-rate-limiter.js';
import {
  createLoginRedisClientOptions,
  loginRedisRetryStrategy,
  MAX_LOGIN_REDIS_RECONNECT_ATTEMPTS,
  withBoundedTimeout,
} from './login-redis-timeout.js';
import {
  createAdjustableClock,
  createCollectingLogger,
  createTestAuthConfig,
  TEST_PEER_IP,
  VALID_PASSWORD,
} from './test-helper.js';
import { digestLoginAccount } from './token-digests.js';

const ACCOUNT_ONE = 'owner@synthetic.patchpilot.test';
const ACCOUNT_TWO = 'viewer@synthetic.patchpilot.test';
const PEER_ONE = '192.0.2.10';
const PEER_TWO = '198.51.100.20';

function limiterHarness(
  overrides: Parameters<typeof createTestAuthConfig>[0] = {},
  unavailable = false,
) {
  const clock = createAdjustableClock();
  const logs = createCollectingLogger();
  const auth = createTestAuthConfig({
    loginRateLimitIpMaxAttempts: 2,
    loginRateLimitAccountMaxAttempts: 2,
    loginRateLimitIpWindowSeconds: 30,
    loginRateLimitAccountWindowSeconds: 30,
    rateLimitRedisTimeoutMs: 50,
    ...overrides,
  });
  const limiter = createFakeLoginRateLimiter({
    auth,
    logger: logs.logger,
    clock,
    ...(unavailable ? { unavailable: true } : {}),
  });
  return { limiter, clock, logs, auth };
}

async function consume(harness: ReturnType<typeof limiterHarness>, peerIp: string, email: string) {
  return harness.limiter.consume({
    peerIp,
    accountDigest: digestLoginAccount(email),
  });
}

describe('login abuse-control boundary', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('enforces the peer-IP threshold across different accounts', async () => {
    const harness = limiterHarness();
    expect(await consume(harness, PEER_ONE, ACCOUNT_ONE)).toEqual({ ok: true, value: undefined });
    expect(await consume(harness, PEER_ONE, ACCOUNT_TWO)).toEqual({ ok: true, value: undefined });
    expect(await consume(harness, PEER_ONE, 'third@synthetic.patchpilot.test')).toEqual({
      ok: false,
      error: LOGIN_RATE_LIMITED,
    });
    expect(harness.logs.text()).toContain('ip_threshold');
  });

  it('enforces the account threshold across different peers', async () => {
    const harness = limiterHarness();
    expect(await consume(harness, PEER_ONE, ACCOUNT_ONE)).toEqual({ ok: true, value: undefined });
    expect(await consume(harness, PEER_TWO, ACCOUNT_ONE)).toEqual({ ok: true, value: undefined });
    expect(await consume(harness, '203.0.113.5', ACCOUNT_ONE)).toEqual({
      ok: false,
      error: LOGIN_RATE_LIMITED,
    });
    expect(harness.logs.text()).toContain('account_threshold');
  });

  it('enforces the combined threshold when both buckets are exhausted', async () => {
    const harness = limiterHarness();
    await consume(harness, PEER_ONE, ACCOUNT_ONE);
    await consume(harness, PEER_ONE, ACCOUNT_TWO);
    await consume(harness, PEER_TWO, ACCOUNT_ONE);
    const result = await consume(harness, PEER_ONE, ACCOUNT_ONE);
    expect(result).toEqual({ ok: false, error: LOGIN_RATE_LIMITED });
    expect(harness.logs.text()).toContain('combined_threshold');
  });

  it('keeps independent peers on separate IP buckets', async () => {
    const harness = limiterHarness();
    await consume(harness, PEER_ONE, ACCOUNT_ONE);
    await consume(harness, PEER_ONE, ACCOUNT_TWO);
    expect(await consume(harness, PEER_ONE, 'third@synthetic.patchpilot.test')).toEqual({
      ok: false,
      error: LOGIN_RATE_LIMITED,
    });
    expect(await consume(harness, PEER_TWO, 'third@synthetic.patchpilot.test')).toEqual({
      ok: true,
      value: undefined,
    });
  });

  it('keeps independent accounts on separate account buckets', async () => {
    const harness = limiterHarness();
    await consume(harness, PEER_ONE, ACCOUNT_ONE);
    await consume(harness, PEER_TWO, ACCOUNT_ONE);
    expect(await consume(harness, '203.0.113.5', ACCOUNT_ONE)).toEqual({
      ok: false,
      error: LOGIN_RATE_LIMITED,
    });
    expect(await consume(harness, '203.0.113.5', ACCOUNT_TWO)).toEqual({
      ok: true,
      value: undefined,
    });
  });

  it('expires windows by advancing the clock instead of sleeping', async () => {
    const harness = limiterHarness();
    await consume(harness, PEER_ONE, ACCOUNT_ONE);
    await consume(harness, PEER_ONE, ACCOUNT_TWO);
    expect(await consume(harness, PEER_ONE, ACCOUNT_ONE)).toEqual({
      ok: false,
      error: LOGIN_RATE_LIMITED,
    });
    harness.clock.advanceMs(30_000);
    expect(await consume(harness, PEER_ONE, ACCOUNT_ONE)).toEqual({ ok: true, value: undefined });
  });

  it('fails closed when Redis counters are unavailable', async () => {
    const harness = limiterHarness({}, true);
    const result = await consume(harness, PEER_ONE, ACCOUNT_ONE);
    expect(result).toEqual({ ok: false, error: LOGIN_UNAVAILABLE });
    expect(harness.logs.text()).toContain('redis_unavailable');
    expect(harness.logs.text()).not.toContain(PEER_ONE);
    expect(harness.logs.text()).not.toContain(ACCOUNT_ONE);
  });

  it('does not put raw email, password, or tokens in limiter keys or consume input', async () => {
    const harness = limiterHarness();
    await consume(harness, PEER_ONE, ACCOUNT_ONE);
    const keys = harness.limiter.incrementKeys.join('\n');
    const calls = JSON.stringify(harness.limiter.consumeCalls);
    expect(keys).toContain(LOGIN_REDIS_IP_KEY_PREFIX);
    expect(keys).toContain(LOGIN_REDIS_ACCOUNT_KEY_PREFIX);
    expect(keys.toLowerCase()).not.toContain(ACCOUNT_ONE);
    expect(keys).not.toContain(PEER_ONE);
    expect(keys).toBe(
      `${loginIpRedisKey(PEER_ONE)}\n${loginAccountRedisKey(digestLoginAccount(ACCOUNT_ONE))}`,
    );
    expect(calls).not.toContain(VALID_PASSWORD);
    expect(calls).not.toContain('RAW_SESSION');
    expect(calls).not.toContain('RAW_CSRF');
    expect(calls).not.toContain(ACCOUNT_ONE);
    expect(Object.keys(harness.limiter.consumeCalls[0] ?? {}).sort()).toEqual([
      'accountDigest',
      'peerIp',
    ]);
  });

  it('selects the direct socket peer IP and ignores X-Forwarded-For', () => {
    expect(
      selectDirectPeerIp({
        socketRemoteAddress: '10.0.0.5',
        xForwardedFor: '203.0.113.9, 192.0.2.1',
      }),
    ).toBe('10.0.0.5');
    expect(
      selectDirectPeerIp({
        socketRemoteAddress: undefined,
        xForwardedFor: '203.0.113.9',
      }),
    ).toBeUndefined();
    expect(normalizeDirectPeerIp('::ffff:192.0.2.10')).toBe('192.0.2.10');
    expect(normalizeDirectPeerIp('203.0.113.9, 192.0.2.1')).toBeUndefined();
  });

  it('fails closed when a comma-separated forwarded chain is supplied as the peer IP', async () => {
    const harness = limiterHarness();
    const result = await consume(harness, '203.0.113.9, 192.0.2.1', ACCOUNT_ONE);
    expect(result).toEqual({ ok: false, error: LOGIN_UNAVAILABLE });
    expect(harness.limiter.incrementKeys).toEqual([]);
  });

  it('bounds Redis reconnect attempts, connection timeout, and disables the offline queue', () => {
    const options = createLoginRedisClientOptions(200);
    expect(options.maxRetriesPerRequest).toBe(1);
    expect(options.enableOfflineQueue).toBe(false);
    expect(options.connectTimeout).toBe(200);
    expect(options.lazyConnect).toBe(true);
    expect(options.retryStrategy(MAX_LOGIN_REDIS_RECONNECT_ATTEMPTS)).toBe(
      50 * MAX_LOGIN_REDIS_RECONNECT_ATTEMPTS,
    );
    expect(loginRedisRetryStrategy(MAX_LOGIN_REDIS_RECONNECT_ATTEMPTS + 1)).toBeNull();
  });

  it('times out a hung Redis operation without an arbitrary sleep', async () => {
    vi.useFakeTimers();
    const logs = createCollectingLogger();
    const auth = createTestAuthConfig({ rateLimitRedisTimeoutMs: 50 });
    const limiter = createLoginRateLimiter({
      auth,
      logger: logs.logger,
      counters: {
        increment(_key, _windowSeconds) {
          return withBoundedTimeout(
            new Promise<number>(() => {
              /* never settles */
            }),
            auth.rateLimitRedisTimeoutMs,
            'login rate-limit Redis operation timed out',
          );
        },
      },
    });

    const pending = limiter.consume({
      peerIp: TEST_PEER_IP,
      accountDigest: digestLoginAccount(ACCOUNT_ONE),
    });
    await vi.advanceTimersByTimeAsync(auth.rateLimitRedisTimeoutMs);
    await expect(pending).resolves.toEqual({ ok: false, error: LOGIN_UNAVAILABLE });
    expect(logs.text()).toContain('redis_timeout');
    expect(logs.text()).not.toContain(TEST_PEER_IP);
    expect(logs.text()).not.toContain(ACCOUNT_ONE);
  });
});
