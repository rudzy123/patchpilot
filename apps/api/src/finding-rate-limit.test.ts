import type { FastifyRequest } from 'fastify';
import { describe, expect, it } from 'vitest';

import {
  FINDING_CREATION_ORGANIZATION_LIMIT,
  createFindingOrganizationRateLimiter,
  findingDirectPeerRateLimitKey,
} from './finding-rate-limit.js';

describe('finding organization rate limiter', () => {
  it('allows five creations per organization per minute and isolates organizations', () => {
    const limiter = createFindingOrganizationRateLimiter(FINDING_CREATION_ORGANIZATION_LIMIT);
    const now = 1_700_000_000_000;
    for (let index = 0; index < 5; index += 1) {
      expect(limiter.consume('org-a', now)).toBe('allowed');
    }
    expect(limiter.consume('org-a', now + 1)).toBe('limited');
    expect(limiter.consume('org-b', now + 1)).toBe('allowed');
    expect(limiter.consume('org-a', now + FINDING_CREATION_ORGANIZATION_LIMIT.windowMs)).toBe(
      'allowed',
    );
  });

  it('keys the peer bucket from the direct socket and collapses IPv4-mapped IPv6', () => {
    const peer = (address: string, forwarded?: string) =>
      findingDirectPeerRateLimitKey({
        socket: { remoteAddress: address },
        headers: forwarded === undefined ? {} : { 'x-forwarded-for': forwarded },
      } as FastifyRequest);
    expect(peer('198.51.100.8', '203.0.113.9')).toBe('198.51.100.8');
    expect(peer('::ffff:198.51.100.8')).toBe('198.51.100.8');
    expect(peer('::FFFF:198.51.100.8')).toBe('198.51.100.8');
    expect(peer('2001:db8::1')).toBe('2001:db8::1');
    expect(peer('2001:db8::2')).not.toBe(peer('2001:db8::1'));
    expect(peer('')).toBe('unknown-peer');
  });
});
