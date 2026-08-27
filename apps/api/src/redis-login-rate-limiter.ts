import { Redis } from 'ioredis';

import {
  createLoginRateLimiter,
  createLoginRedisClientOptions,
  withBoundedTimeout,
  type LoginRateLimiter,
  type RedisLoginCommands,
} from '@patchpilot/auth';
import type { AuthConfig } from '@patchpilot/config';
import type { Logger } from '@patchpilot/logger';

const INCREMENT_WITH_TTL_LUA = `
local n = redis.call('INCR', KEYS[1])
if n == 1 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return n
`;

export type RedisLoginRateLimiter = LoginRateLimiter & {
  close(): Promise<void>;
};

export function createRedisLoginRateLimiter(options: {
  redisUrl: string;
  auth: AuthConfig;
  logger: Logger;
  commands?: RedisLoginCommands;
}): RedisLoginRateLimiter {
  const timeoutMs = options.auth.rateLimitRedisTimeoutMs;
  const base = options.commands ?? createIoredisLoginCommands(options.redisUrl, options.auth);
  const commands: RedisLoginCommands = {
    increment(key, windowSeconds) {
      return withBoundedTimeout(
        base.increment(key, windowSeconds),
        timeoutMs,
        'login rate-limit Redis operation timed out',
      );
    },
    close: () => base.close(),
  };
  const limiter = createLoginRateLimiter({
    counters: commands,
    auth: options.auth,
    logger: options.logger,
  });

  return {
    consume: (input) => limiter.consume(input),
    close: () => commands.close(),
  };
}

function createIoredisLoginCommands(redisUrl: string, auth: AuthConfig): RedisLoginCommands {
  const timeoutMs = auth.rateLimitRedisTimeoutMs;
  const client = new Redis(redisUrl, createLoginRedisClientOptions(timeoutMs));

  return {
    async increment(key, windowSeconds) {
      await ensureConnected(client, timeoutMs);
      const result = await withBoundedTimeout(
        client.eval(INCREMENT_WITH_TTL_LUA, 1, key, String(windowSeconds)),
        timeoutMs,
        'login rate-limit Redis operation timed out',
      );
      if (typeof result !== 'number') {
        throw new Error('login rate-limit Redis returned a non-numeric count');
      }

      return result;
    },
    async close() {
      await quitRedis(client);
    },
  };
}

async function ensureConnected(client: Redis, timeoutMs: number): Promise<void> {
  if (client.status === 'wait') {
    await withBoundedTimeout(
      client.connect(),
      timeoutMs,
      'login rate-limit Redis connect timed out',
    );
    return;
  }

  if (client.status === 'ready' || client.status === 'connect') {
    return;
  }

  throw new Error('login rate-limit Redis is unavailable');
}

async function quitRedis(client: Redis): Promise<void> {
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
}
