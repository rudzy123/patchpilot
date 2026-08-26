import { Redis } from 'ioredis';

import { type RedisConnectionPort } from '@patchpilot/integrations';

export const MAX_REDIS_RECONNECT_ATTEMPTS = 3;

export function createIoredisOptions(): {
  maxRetriesPerRequest: number;
  connectTimeout: number;
  lazyConnect: boolean;
  enableOfflineQueue: boolean;
  retryStrategy: (attempt: number) => number | null;
} {
  return {
    maxRetriesPerRequest: 1,
    connectTimeout: 1000,
    lazyConnect: true,
    enableOfflineQueue: false,
    retryStrategy(attempt: number): number | null {
      if (attempt > MAX_REDIS_RECONNECT_ATTEMPTS) {
        return null;
      }

      return Math.min(attempt * 50, 200);
    },
  };
}

export function createRedisConnection(url: string): RedisConnectionPort {
  const client = new Redis(url, createIoredisOptions());

  return {
    async ping(timeoutMs: number): Promise<boolean> {
      try {
        await Promise.race([
          (async () => {
            if (client.status === 'wait') {
              await client.connect();
            }
            await client.ping();
          })(),
          new Promise<never>((_resolve, reject) => {
            setTimeout(() => {
              reject(new Error('redis ping timed out'));
            }, timeoutMs);
          }),
        ]);
        return true;
      } catch {
        return false;
      }
    },
    async quit(): Promise<void> {
      if (client.status === 'wait' || client.status === 'end') {
        client.disconnect();
        return;
      }

      await client.quit();
    },
  };
}
