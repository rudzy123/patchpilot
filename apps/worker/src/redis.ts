import { Redis } from 'ioredis';

import { type RedisConnectionPort } from '@patchpilot/integrations';

export const MAX_REDIS_RECONNECT_ATTEMPTS = 3;

export function redisRetryStrategy(attempt: number): number | null {
  if (attempt > MAX_REDIS_RECONNECT_ATTEMPTS) {
    return null;
  }

  return Math.min(attempt * 50, 200);
}

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
    retryStrategy: redisRetryStrategy,
  };
}

async function withTimeout<T>(
  operation: Promise<T>,
  timeoutMs: number,
  message: string,
): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;

  try {
    return await Promise.race([
      operation,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => {
          reject(new Error(message));
        }, timeoutMs);
      }),
    ]);
  } finally {
    if (timer !== undefined) {
      clearTimeout(timer);
    }
  }
}

export function createRedisConnection(url: string): RedisConnectionPort {
  const client = new Redis(url, createIoredisOptions());

  return {
    async ping(timeoutMs: number): Promise<boolean> {
      try {
        await withTimeout(
          (async () => {
            if (client.status === 'wait') {
              await client.connect();
            }
            await client.ping();
          })(),
          timeoutMs,
          'redis ping timed out',
        );
        return true;
      } catch {
        if (client.status === 'connecting' || client.status === 'connect') {
          client.disconnect();
        }
        return false;
      }
    },
    async quit(): Promise<void> {
      if (
        client.status === 'wait' ||
        client.status === 'end' ||
        client.status === 'close' ||
        client.status === 'reconnecting'
      ) {
        client.disconnect();
        return;
      }

      try {
        await client.quit();
      } catch {
        client.disconnect();
      }
    },
  };
}
