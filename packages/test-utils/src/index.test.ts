import { describe, expect, it } from 'vitest';

import { createFoundationTestEnv, createFrozenClock, getFreePort } from './index.js';

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
    expect(process.env['DATABASE_URL']).toBe(before);
  });

  it('allocates a free port without sleeping', async () => {
    const port = await getFreePort();
    expect(port).toBeGreaterThan(0);
  });
});
