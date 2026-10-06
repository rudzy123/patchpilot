import { describe, expect, it } from 'vitest';

import {
  createFoundationProductionTestEnv,
  createFoundationTestEnv,
  createFrozenClock,
  createIntegrationDatabaseTestEnv,
  createSyntheticTenantPair,
  disconnectDatabaseClientAfter,
  getFreePort,
} from './index.js';

describe('test utilities', () => {
  it('freezes time in UTC', () => {
    const clock = createFrozenClock('2026-08-26T16:00:00.000Z');
    expect(clock.nowIso()).toBe('2026-08-26T16:00:00.000Z');
    expect(clock.now().toISOString()).toBe('2026-08-26T16:00:00.000Z');
  });

  it('returns an isolated env record without assigning process.env', () => {
    const before = process.env['DATABASE_URL'];
    const env = createFoundationTestEnv();
    expect(env['PATCHPILOT_DEPLOYMENT_ENVIRONMENT']).toBe('test');
    expect(env['INTELLIGENCE_KEV_ENABLED']).toBe('true');
    expect(env['INTELLIGENCE_OSV_ENABLED']).toBe('false');
    expect(env['INTELLIGENCE_KEV_SCHEDULER_POLL_INTERVAL_MS']).toBe('30000');
    expect(env['INTELLIGENCE_KEV_SCHEDULER_STARTUP_DELAY_MS']).toBe('5000');
    expect(env['INTELLIGENCE_RETRY_RECONCILE_INTERVAL_MS']).toBe('15000');
    expect(env['INTELLIGENCE_RETRY_RECONCILE_MIN_AGE_MS']).toBe('15000');
    expect(env['INTELLIGENCE_KEV_URL']).toBeUndefined();
    expect(env['INTELLIGENCE_OSV_URL']).toBeUndefined();
    expect(process.env['DATABASE_URL']).toBe(before);
  });

  it('disconnects the database client without hiding an earlier cleanup failure', async () => {
    const order: string[] = [];
    const writes: string[] = [];
    const originalWrite = process.stderr.write.bind(process.stderr);
    process.stderr.write = ((chunk: string | Uint8Array) => {
      writes.push(String(chunk));
      return true;
    }) as typeof process.stderr.write;

    try {
      await expect(
        disconnectDatabaseClientAfter(
          async () => {
            order.push('cleanup');
            throw new Error('original cleanup failure');
          },
          async () => {
            order.push('disconnect');
            throw new Error(
              'disconnect postgres://user:secret@127.0.0.1:55432/patchpilot_it_worker_1',
            );
          },
        ),
      ).rejects.toThrow('original cleanup failure');
      expect(order).toEqual(['cleanup', 'disconnect']);
      expect(writes.join('\n')).toContain('postgres://<redacted>');
      expect(writes.join('\n')).not.toContain('secret');
    } finally {
      process.stderr.write = originalWrite;
    }
  });

  it('requires a disposable integration database and refuses the persistent database', () => {
    expect(() =>
      createIntegrationDatabaseTestEnv(
        'postgresql://patchpilot:patchpilot-dev-not-for-production@127.0.0.1:55432/patchpilot',
      ),
    ).toThrow(/refuse the persistent/);
    const env = createIntegrationDatabaseTestEnv(
      'postgresql://patchpilot:patchpilot-dev-not-for-production@127.0.0.1:55432/patchpilot_it_api_1735689600_abcdef012345',
    );
    expect(env['DATABASE_URL']).toContain('patchpilot_it_api_1735689600_abcdef012345');
    expect(env['DATABASE_URL']).not.toBe(createFoundationTestEnv()['DATABASE_URL']);
  });

  it('builds a production env without development credential fragments', () => {
    const env = createFoundationProductionTestEnv();
    expect(env['PATCHPILOT_DEPLOYMENT_ENVIRONMENT']).toBe('production');
    expect(env['REDIS_URL']).toContain('operator-redis-secret');
    expect(JSON.stringify(env).toLowerCase()).not.toMatch(
      /patchpilot-dev|not-for-production|minioadmin|changeme/,
    );
  });

  it('allocates a free port without sleeping', async () => {
    const port = await getFreePort();
    expect(port).toBeGreaterThan(0);
  });

  it('returns two isolated synthetic tenant labels', () => {
    const pair = createSyntheticTenantPair();
    expect(pair.organizationA.slug).not.toBe(pair.organizationB.slug);
    expect(pair.userA.email).toMatch(/synthetic\.patchpilot\.test$/);
    expect(pair.vulnerabilityIdentity).toBe('PATCHPILOT-SYNTH-VULN-1');
  });
});
