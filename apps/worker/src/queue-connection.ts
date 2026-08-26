import type { ConnectionOptions } from 'bullmq';

export function createBullmqConnectionOptions(redisUrl: string): ConnectionOptions {
  const parsed = new URL(redisUrl);
  const port = parsed.port === '' ? 6379 : Number(parsed.port);

  return {
    host: parsed.hostname,
    port,
    maxRetriesPerRequest: null,
    connectTimeout: 1000,
  };
}
