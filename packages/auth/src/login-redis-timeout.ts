export const MAX_LOGIN_REDIS_RECONNECT_ATTEMPTS = 3;

export type LoginRateLimitTimeoutError = {
  category: 'redis_timeout';
};

export function isLoginRateLimitTimeoutError(error: unknown): error is LoginRateLimitTimeoutError {
  return (
    typeof error === 'object' &&
    error !== null &&
    'category' in error &&
    (error as { category: unknown }).category === 'redis_timeout'
  );
}

export function loginRedisRetryStrategy(attempt: number): number | null {
  if (attempt > MAX_LOGIN_REDIS_RECONNECT_ATTEMPTS) {
    return null;
  }

  return Math.min(attempt * 50, 200);
}

export function createLoginRedisClientOptions(connectTimeoutMs: number): {
  maxRetriesPerRequest: number;
  connectTimeout: number;
  lazyConnect: boolean;
  enableOfflineQueue: boolean;
  retryStrategy: (attempt: number) => number | null;
} {
  return {
    maxRetriesPerRequest: 1,
    connectTimeout: connectTimeoutMs,
    lazyConnect: true,
    enableOfflineQueue: false,
    retryStrategy: loginRedisRetryStrategy,
  };
}

export async function withBoundedTimeout<T>(
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
          reject(Object.assign(new Error(message), { category: 'redis_timeout' as const }));
        }, timeoutMs);
      }),
    ]);
  } finally {
    if (timer !== undefined) {
      clearTimeout(timer);
    }
  }
}
