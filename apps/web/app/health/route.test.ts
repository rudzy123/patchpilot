import { describe, expect, it } from 'vitest';

import { GET } from './route.js';

describe('web health route', () => {
  it('returns the shared live health contract', async () => {
    const response = GET();
    expect(response.status).toBe(200);
    const body = (await response.json()) as { status: string; service: string };
    expect(body.status).toBe('live');
    expect(body.service).toBe('web');
    expect(JSON.stringify(body)).not.toContain('postgresql://');
  });
});
