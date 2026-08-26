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
  });
});
