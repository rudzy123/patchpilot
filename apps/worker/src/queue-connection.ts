import type { ConnectionOptions } from 'bullmq';

import { redisRetryStrategy } from './redis.js';

export function createBullmqConnectionOptions(redisUrl: string): ConnectionOptions {
  const parsed = new URL(redisUrl);
  const port = parsed.port === '' ? 6379 : Number(parsed.port);
  const username = parsed.username === '' ? undefined : decodeURIComponent(parsed.username);
  const password = parsed.password === '' ? undefined : decodeURIComponent(parsed.password);
  const useTls = parsed.protocol === 'rediss:';

  return {
    host: parsed.hostname,
    port,
    maxRetriesPerRequest: null,
    connectTimeout: 1000,
    retryStrategy: redisRetryStrategy,
    ...(useTls ? { tls: {} } : {}),
    ...(username === undefined ? {} : { username }),
    ...(password === undefined ? {} : { password }),
  };
}
