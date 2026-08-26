import { afterEach, describe, expect, it } from 'vitest';

import {
  checkDatabaseReady,
  disconnectPrisma,
  getPrismaClient,
  resetPrismaClientForTests,
} from './index.js';

afterEach(async () => {
  await disconnectPrisma();
});

describe('prisma client lifecycle', () => {
  it('reuses a single client instance', () => {
    resetPrismaClientForTests();
    const first = getPrismaClient();
    const second = getPrismaClient();
    expect(first).toBe(second);
  });

  it('rejects a second initialization with a different database URL', () => {
    resetPrismaClientForTests();
    getPrismaClient({ databaseUrl: 'postgresql://patchpilot:one@127.0.0.1:1/patchpilot' });
    expect(() =>
      getPrismaClient({ databaseUrl: 'postgresql://patchpilot:two@127.0.0.1:1/patchpilot' }),
    ).toThrow(/different database URL/);
  });

  it('reports not ready when PostgreSQL is unavailable without leaking connection strings', async () => {
    resetPrismaClientForTests();
    const result = await checkDatabaseReady(200, {
      databaseUrl: 'postgresql://patchpilot:invalid@127.0.0.1:1/patchpilot',
    });
    expect(result).toEqual({ ok: false });
    expect(JSON.stringify(result)).not.toContain('postgresql://');
    expect(JSON.stringify(result)).not.toContain('invalid');
  });
});
