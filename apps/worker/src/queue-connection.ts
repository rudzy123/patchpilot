import type { ConnectionOptions } from 'bullmq';

export function createBullmqConnectionOptions(redisUrl: string): ConnectionOptions {
  const parsed = new URL(redisUrl);
  const port = parsed.port === '' ? 6379 : Number(parsed.port);
  const username = parsed.username === '' ? undefined : decodeURIComponent(parsed.username);
  const password = parsed.password === '' ? undefined : decodeURIComponent(parsed.password);

  return {
    host: parsed.hostname,
    port,
    maxRetriesPerRequest: null,
    connectTimeout: 1000,
    ...(username === undefined ? {} : { username }),
    ...(password === undefined ? {} : { password }),
  };
}
