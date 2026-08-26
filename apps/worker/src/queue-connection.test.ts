import { describe, expect, it } from 'vitest';

import { createBullmqConnectionOptions } from './queue-connection.js';
import { MAX_REDIS_RECONNECT_ATTEMPTS, redisRetryStrategy } from './redis.js';

describe('bullmq connection boundary', () => {
  it('prepares connection options without registering product queues', () => {
    const options = createBullmqConnectionOptions('redis://127.0.0.1:6379');
    expect(options).toMatchObject({
      host: '127.0.0.1',
      port: 6379,
      maxRetriesPerRequest: null,
      connectTimeout: 1000,
    });
    expect(options).not.toHaveProperty('password');
    expect(options).not.toHaveProperty('tls');
    expect(Object.hasOwn(options, 'retryStrategy')).toBe(true);
  });

  it('forwards Redis credentials from the URL', () => {
    const options = createBullmqConnectionOptions(
      'redis://operator:operator-redis-secret@redis.internal:6379',
    );
    expect(options).toMatchObject({
      host: 'redis.internal',
      port: 6379,
      username: 'operator',
      password: 'operator-redis-secret',
      maxRetriesPerRequest: null,
    });
  });

  it('enables TLS for rediss URLs without dropping the reconnect bound', () => {
    const options = createBullmqConnectionOptions(
      'rediss://:operator-redis-secret@redis.internal:6379',
    );
    expect(options).toMatchObject({
      host: 'redis.internal',
      port: 6379,
      password: 'operator-redis-secret',
      tls: {},
    });
    expect(Object.hasOwn(options, 'retryStrategy')).toBe(true);
    expect(redisRetryStrategy(MAX_REDIS_RECONNECT_ATTEMPTS + 1)).toBeNull();
  });
});
