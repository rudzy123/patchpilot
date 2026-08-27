import type { AuthConfig } from '@patchpilot/config';
import type { Logger } from '@patchpilot/logger';

import type { Clock } from './clock.js';
import {
  createLoginRateLimiter,
  type LoginRateLimitConsumeInput,
  type LoginRateLimiter,
} from './login-rate-limiter.js';

type MemoryCounter = {
  count: number;
  expiresAtMs: number;
};

export type FakeLoginRateLimiter = LoginRateLimiter & {
  consumeCalls: LoginRateLimitConsumeInput[];
  incrementKeys: string[];
};

export function createFakeLoginRateLimiter(options: {
  auth: AuthConfig;
  logger: Logger;
  clock: Clock;
  unavailable?: boolean;
}): FakeLoginRateLimiter {
  const consumeCalls: LoginRateLimitConsumeInput[] = [];
  const incrementKeys: string[] = [];
  const counters = new Map<string, MemoryCounter>();
  const limiter = createLoginRateLimiter({
    auth: options.auth,
    logger: options.logger,
    counters: {
      async increment(key, windowSeconds) {
        incrementKeys.push(key);
        if (options.unavailable === true) {
          throw new Error('redis unavailable');
        }

        const nowMs = options.clock.now().getTime();
        const current = counters.get(key);
        if (current === undefined || nowMs >= current.expiresAtMs) {
          const next: MemoryCounter = {
            count: 1,
            expiresAtMs: nowMs + windowSeconds * 1000,
          };
          counters.set(key, next);
          return next.count;
        }

        current.count += 1;
        counters.set(key, current);
        return current.count;
      },
    },
  });

  return {
    consumeCalls,
    incrementKeys,
    async consume(input) {
      consumeCalls.push({ ...input });
      return limiter.consume(input);
    },
  };
}
