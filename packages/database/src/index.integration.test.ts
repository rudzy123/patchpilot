import { afterEach, describe, expect, it } from 'vitest';

import { loadServerConfigFrom } from '@patchpilot/config';
import { createFoundationTestEnv } from '@patchpilot/test-utils';

import { checkDatabaseReady, disconnectPrisma, resetPrismaClientForTests } from './index.js';

afterEach(async () => {
  await disconnectPrisma();
});

describe('postgresql integration', () => {
  it('reports ready against local Compose PostgreSQL without leaking the connection string', async () => {
    resetPrismaClientForTests();
    const config = loadServerConfigFrom(createFoundationTestEnv());
    const result = await checkDatabaseReady(config.readinessTimeoutMs, {
      databaseUrl: config.databaseUrl,
    });
    expect(result).toEqual({ ok: true });
    expect(JSON.stringify(result)).not.toContain('postgresql://');
    expect(JSON.stringify(result)).not.toContain('patchpilot-dev-not-for-production');
  });
});
