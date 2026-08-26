import { Redis } from 'ioredis';

import { type RedisConnectionPort } from '@patchpilot/integrations';

export function createRedisConnection(url: string): RedisConnectionPort {
  const client = new Redis(url, {
    maxRetriesPerRequest: 1,
    connectTimeout: 1000,
    lazyConnect: true,
  });

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
      if (client.status !== 'end') {
        await client.quit();
      }
    },
  };
}
