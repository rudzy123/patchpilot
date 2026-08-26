import { describe, expect, it } from 'vitest';

import { createBullmqConnectionOptions } from './queue-connection.js';

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
});
