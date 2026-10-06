import { loadServerConfigFrom } from '@patchpilot/config';
import { readDisposableIntegrationDatabaseUrl } from '@patchpilot/config/integration-test';
import { createIntegrationDatabaseTestEnv } from '@patchpilot/test-utils';
import { describe, expect, it } from 'vitest';

import { createRedisConnection } from './redis.js';

describe('redis integration', () => {
  it('pings local Compose Redis', async () => {
    const config = loadServerConfigFrom(
      createIntegrationDatabaseTestEnv(readDisposableIntegrationDatabaseUrl()),
    );
    const redis = createRedisConnection(config.redisUrl);
    try {
      expect(await redis.ping(config.readinessTimeoutMs)).toBe(true);
    } finally {
      await redis.quit();
    }
  });
});
