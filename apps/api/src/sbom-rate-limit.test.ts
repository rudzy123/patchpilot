import type { FastifyRequest } from 'fastify';
import { describe, expect, it } from 'vitest';

import { createSbomOrganizationRateLimiter, sbomHttpRateLimitKey } from './sbom-rate-limit.js';

function requestStub(overrides: {
  socket: { remoteAddress: string | undefined };
  headers?: Record<string, string>;
}): FastifyRequest {
  return overrides as unknown as FastifyRequest;
}

describe('SBOM HTTP rate-limit keys', () => {
  it('keys by the direct socket peer and ignores X-Forwarded-For', () => {
    const request = requestStub({
      socket: { remoteAddress: '192.0.2.10' },
      headers: { 'x-forwarded-for': '203.0.113.9' },
    });
    expect(sbomHttpRateLimitKey(request)).toBe('192.0.2.10');
  });

  it('groups missing peer addresses onto a shared key', () => {
    const request = requestStub({
      socket: { remoteAddress: undefined },
      headers: {},
    });
    expect(sbomHttpRateLimitKey(request)).toBe('unknown-peer');
  });
});

describe('SBOM organization rate limiter', () => {
  it('limits each organization independently', () => {
    const limiter = createSbomOrganizationRateLimiter({ max: 1, windowMs: 60_000 });
    expect(limiter.consume('org-a', 1_000)).toBe(true);
    expect(limiter.consume('org-a', 1_001)).toBe(false);
    expect(limiter.consume('org-b', 1_001)).toBe(true);
  });
});
