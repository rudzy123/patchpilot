import { describe, expect, it } from 'vitest';

import { createIoredisOptions, MAX_REDIS_RECONNECT_ATTEMPTS } from './redis.js';

describe('redis client options', () => {
  it('bounds reconnect attempts and disables the offline command queue', () => {
    const options = createIoredisOptions();
    expect(options.maxRetriesPerRequest).toBe(1);
    expect(options.enableOfflineQueue).toBe(false);
    expect(options.retryStrategy(MAX_REDIS_RECONNECT_ATTEMPTS)).toBe(
      50 * MAX_REDIS_RECONNECT_ATTEMPTS,
    );
    expect(options.retryStrategy(MAX_REDIS_RECONNECT_ATTEMPTS + 1)).toBeNull();
  });
});
