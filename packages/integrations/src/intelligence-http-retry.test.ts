import { describe, expect, it } from 'vitest';

import {
  clampRetryAfterMs,
  exponentialBackoffMs,
  isIntelligenceHttpRetryable,
  parseRetryAfterMs,
  resolveIntelligenceRetryDelayMs,
} from './intelligence-http-retry.js';

const NOW = new Date('2026-09-01T12:00:00.000Z');

describe('intelligence HTTP retry policy', () => {
  it('retries only the approved idempotent GET failure codes', () => {
    expect(isIntelligenceHttpRetryable('connection_timeout')).toBe(true);
    expect(isIntelligenceHttpRetryable('response_timeout')).toBe(true);
    expect(isIntelligenceHttpRetryable('rate_limited')).toBe(true);
    expect(isIntelligenceHttpRetryable('provider_server_error')).toBe(true);
    expect(isIntelligenceHttpRetryable('dns_rejected')).toBe(false);
    expect(isIntelligenceHttpRetryable('redirect_rejected')).toBe(false);
    expect(isIntelligenceHttpRetryable('provider_client_error')).toBe(false);
    expect(isIntelligenceHttpRetryable('content_type_invalid')).toBe(false);
    expect(isIntelligenceHttpRetryable('response_too_large')).toBe(false);
    expect(isIntelligenceHttpRetryable('response_empty')).toBe(false);
    expect(isIntelligenceHttpRetryable('request_cancelled')).toBe(false);
    expect(isIntelligenceHttpRetryable('snapshot_storage_failed')).toBe(false);
  });

  it('honors Retry-After seconds, HTTP dates, clamps, and malformed fallback', () => {
    expect(parseRetryAfterMs('5', NOW, 1000, 30_000)).toBe(5000);
    expect(parseRetryAfterMs('Mon, 01 Sep 2026 12:00:10 GMT', NOW, 1000, 30_000)).toBe(10_000);
    expect(
      resolveIntelligenceRetryDelayMs({
        retryAfterHeader: '120',
        attempt: 0,
        floorMs: 1000,
        ceilingMs: 30_000,
        now: NOW,
        jitter: (value) => value,
      }),
    ).toBe(30_000);
    expect(
      resolveIntelligenceRetryDelayMs({
        retryAfterHeader: 'Mon, 01 Sep 2026 11:59:00 GMT',
        attempt: 0,
        floorMs: 1000,
        ceilingMs: 30_000,
        now: NOW,
        jitter: (value) => value,
      }),
    ).toBe(1000);
    expect(
      resolveIntelligenceRetryDelayMs({
        retryAfterHeader: 'not-a-date',
        attempt: 1,
        floorMs: 1000,
        ceilingMs: 30_000,
        now: NOW,
        jitter: (value) => value,
      }),
    ).toBe(2000);
    expect(clampRetryAfterMs(50_000, 30_000)).toBe(30_000);
    expect(exponentialBackoffMs(0, 1000, 30_000, (value) => value)).toBe(1000);
  });
});
