import type { FastifyRequest } from 'fastify';
import { describe, expect, it } from 'vitest';

import { createFindingOrganizationRateLimiter } from './finding-rate-limit.js';
import {
  PRODUCT_MATCH_EVALUATION_BODY_LIMIT_BYTES,
  PRODUCT_MATCH_EVALUATION_ORGANIZATION_LIMIT,
  PRODUCT_MATCH_EVALUATION_PEER_LIMIT,
  productMatchEvaluationDirectPeerRateLimitKey,
} from './product-match-evaluation-rate-limit.js';

describe('product match evaluation rate limits', () => {
  it('caps one process at five requests per minute for the peer and the organization', () => {
    expect(PRODUCT_MATCH_EVALUATION_BODY_LIMIT_BYTES).toBe(1024);
    expect(PRODUCT_MATCH_EVALUATION_PEER_LIMIT).toEqual({ max: 5, windowMs: 60_000 });
    expect(PRODUCT_MATCH_EVALUATION_ORGANIZATION_LIMIT).toEqual({ max: 5, windowMs: 60_000 });
    const limiter = createFindingOrganizationRateLimiter(
      PRODUCT_MATCH_EVALUATION_ORGANIZATION_LIMIT,
    );
    const now = 1_700_000_000_000;
    for (let index = 0; index < 5; index += 1) {
      expect(limiter.consume('org-a', now)).toBe('allowed');
    }
    expect(limiter.consume('org-a', now + 1)).toBe('limited');
    expect(limiter.consume('org-b', now + 1)).toBe('allowed');
    expect(
      limiter.consume('org-a', now + PRODUCT_MATCH_EVALUATION_ORGANIZATION_LIMIT.windowMs),
    ).toBe('allowed');
  });

  it('keys the peer bucket from the direct socket and ignores X-Forwarded-For', () => {
    const peer = (address: string, forwarded?: string) =>
      productMatchEvaluationDirectPeerRateLimitKey({
        socket: { remoteAddress: address },
        headers: forwarded === undefined ? {} : { 'x-forwarded-for': forwarded },
      } as FastifyRequest);
    expect(peer('198.51.100.8', '203.0.113.9')).toBe('198.51.100.8');
    expect(peer('::ffff:198.51.100.8')).toBe('198.51.100.8');
    expect(peer('2001:db8::1')).toBe('2001:db8::1');
    expect(peer('')).toBe('unknown-peer');
  });
});
