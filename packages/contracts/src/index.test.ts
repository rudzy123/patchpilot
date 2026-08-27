import { describe, expect, it } from 'vitest';

import {
  errorEnvelopeSchema,
  healthLiveResponseSchema,
  healthReadyResponseSchema,
  loginRequestSchema,
  organizationsResponseSchema,
  selectOrganizationRequestSchema,
  sessionResponseSchema,
} from './index.js';

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

describe('authentication contracts', () => {
  it('strips client-supplied TrustedActor fields from login bodies', () => {
    const parsed = loginRequestSchema.parse({
      email: 'owner@synthetic.patchpilot.test',
      password: 'correct-horse-battery',
      actorUserId: '11111111-1111-4111-8111-111111111111',
      actorType: 'system',
    });
    expect(parsed).toEqual({
      email: 'owner@synthetic.patchpilot.test',
      password: 'correct-horse-battery',
    });
  });

  it('accepts session and organization payloads without email or hashes', () => {
    const session = sessionResponseSchema.parse({
      user: { id: '11111111-1111-4111-8111-111111111111', displayName: 'Owner' },
      organization: {
        id: '22222222-2222-4222-8222-222222222222',
        slug: 'acme',
        name: 'Acme',
        role: 'owner',
      },
      csrfToken: 'csrf-token',
      expiresAt: '2026-08-28T04:00:00.000Z',
    });
    expect(session.organization?.slug).toBe('acme');
    expect(
      selectOrganizationRequestSchema.parse({
        organizationId: '22222222-2222-4222-8222-222222222222',
      }),
    ).toEqual({ organizationId: '22222222-2222-4222-8222-222222222222' });
    expect(
      organizationsResponseSchema.parse({
        organizations: [
          {
            id: '22222222-2222-4222-8222-222222222222',
            slug: 'acme',
            name: 'Acme',
            role: 'owner',
          },
        ],
      }).organizations,
    ).toHaveLength(1);
  });

  it('requires request and correlation ids on error envelopes', () => {
    const parsed = errorEnvelopeSchema.parse({
      error: {
        code: 'unauthorized',
        message: 'Invalid email or password.',
        requestId: 'req-1',
        correlationId: 'corr-1',
      },
    });
    expect(parsed.error.code).toBe('unauthorized');
  });
});
