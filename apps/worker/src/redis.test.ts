import { describe, expect, it } from 'vitest';

import {
  createIoredisOptions,
  createRedisConnection,
  MAX_REDIS_RECONNECT_ATTEMPTS,
  redisRetryStrategy,
} from './redis.js';

describe('redis client options', () => {
  it('bounds reconnect attempts and disables the offline command queue', () => {
    const options = createIoredisOptions();
    expect(options.maxRetriesPerRequest).toBe(1);
    expect(options.enableOfflineQueue).toBe(false);
    expect(options.retryStrategy(MAX_REDIS_RECONNECT_ATTEMPTS)).toBe(
      50 * MAX_REDIS_RECONNECT_ATTEMPTS,
    );
    expect(options.retryStrategy(MAX_REDIS_RECONNECT_ATTEMPTS + 1)).toBeNull();
    expect(redisRetryStrategy(MAX_REDIS_RECONNECT_ATTEMPTS + 1)).toBeNull();
  });

  it('quits cleanly after a failed ping so startup-failure shutdown cannot hang on Redis', async () => {
    const redis = createRedisConnection('redis://127.0.0.1:1');
    expect(await redis.ping(50)).toBe(false);
    await expect(redis.quit()).resolves.toBeUndefined();
  });
});
