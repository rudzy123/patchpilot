import { describe, expect, it } from 'vitest';

import {
  createFoundationProductionTestEnv,
  createFoundationTestEnv,
  createFrozenClock,
  createSyntheticTenantPair,
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
    expect(env['INTELLIGENCE_KEV_URL']).toBeUndefined();
    expect(env['INTELLIGENCE_OSV_URL']).toBeUndefined();
    expect(process.env['DATABASE_URL']).toBe(before);
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
