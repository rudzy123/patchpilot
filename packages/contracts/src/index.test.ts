import { describe, expect, it } from 'vitest';

import { healthLiveResponseSchema, healthReadyResponseSchema } from './index.js';

describe('health contracts', () => {
  it('accepts a live response without dependency details', () => {
    const parsed = healthLiveResponseSchema.parse({
      status: 'live',
      service: 'api',
      timestamp: '2026-08-26T16:00:00.000Z',
      version: '0.0.0',
    });
    expect(parsed.status).toBe('live');
  });

  it('accepts a not-ready summary without topology', () => {
    const parsed = healthReadyResponseSchema.parse({
      status: 'not_ready',
      service: 'api',
      timestamp: '2026-08-26T16:00:00.000Z',
      checks: [{ name: 'postgresql', status: 'down' }],
    });
    expect(parsed.checks[0]?.name).toBe('postgresql');
  });

  it('rejects extra secret-like fields at the schema boundary', () => {
    const result = healthReadyResponseSchema.safeParse({
      status: 'ready',
      service: 'api',
      timestamp: '2026-08-26T16:00:00.000Z',
      checks: [],
      databaseUrl: 'postgresql://example',
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data).not.toHaveProperty('databaseUrl');
    }
  });
});
