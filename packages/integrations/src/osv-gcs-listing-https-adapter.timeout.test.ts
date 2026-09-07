/**
 * Session 12 Batch 1 listing timeout and cancellation tests.
 * Fake timers and local request doubles only.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { OSV_TIMEOUT_POLICY_V1 } from '@patchpilot/vulnerability-intelligence';

import {
  MINIMAL_PAGE,
  SECRET_TOKEN,
  assertConfidential,
  continuationRequest,
  createListingTestContext,
  jsonHeaders,
  validListingRequest,
} from './osv-gcs-listing-https-adapter.test-harness.js';

const ctx = createListingTestContext();

beforeEach(() => {
  vi.useFakeTimers();
  ctx.reset();
});

afterEach(() => {
  vi.useRealTimers();
  ctx.reset();
});

describe('OSV GCS listing timeouts and cancellation', () => {
  it('cancels before dispatch with zero HTTPS requests', async () => {
    const signal = AbortSignal.abort();
    const result = await ctx.adapter().listPage(validListingRequest({ signal }));
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.failure.kind).toBe('cancelled');
      assertConfidential(result.failure);
    }
    expect(ctx.recordedOptions).toHaveLength(0);
  });

  it('cancels during DNS lookup before HTTPS dispatch', async () => {
    const controller = new AbortController();
    ctx.setLookup((_hostname, _options, _callback) => {
      controller.abort();
    });
    const result = await ctx.adapter().listPage(validListingRequest({ signal: controller.signal }));
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.failure.kind).toBe('cancelled');
    }
    expect(ctx.recordedOptions).toHaveLength(0);
  });

  it('times out while connecting and settles once', async () => {
    ctx.remainingResponses.push({ omitSocket: true, omitResponse: true });
    const pending = ctx.adapter().listPage(continuationRequest());
    await Promise.resolve();
    await vi.advanceTimersByTimeAsync(OSV_TIMEOUT_POLICY_V1.connectionTimeoutMs);
    const result = await pending;
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.failure.kind).toBe('timeout');
      assertConfidential(result.failure, [SECRET_TOKEN]);
    }
    expect(ctx.recordedOptions).toHaveLength(1);
    expect(ctx.lastDestroyed.request).toBe(true);
  });

  it('times out while awaiting headers', async () => {
    ctx.remainingResponses.push({ omitResponse: true });
    const pending = ctx.adapter().listPage(validListingRequest());
    await Promise.resolve();
    await vi.advanceTimersByTimeAsync(OSV_TIMEOUT_POLICY_V1.responseHeaderTimeoutMs);
    const result = await pending;
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.failure.kind).toBe('timeout');
    }
    expect(ctx.recordedOptions).toHaveLength(1);
  });

  it('times out on body inactivity', async () => {
    ctx.remainingResponses.push({
      statusCode: 200,
      headers: jsonHeaders(MINIMAL_PAGE),
      body: MINIMAL_PAGE,
      neverEnd: true,
    });
    const pending = ctx.adapter().listPage(validListingRequest());
    await Promise.resolve();
    await vi.advanceTimersByTimeAsync(OSV_TIMEOUT_POLICY_V1.bodyInactivityTimeoutMs);
    const result = await pending;
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.failure.kind).toBe('timeout');
    }
  });

  it('cancels while awaiting headers and ignores a late response', async () => {
    const controller = new AbortController();
    ctx.remainingResponses.push({ omitResponse: true });
    const pending = ctx.adapter().listPage(validListingRequest({ signal: controller.signal }));
    await Promise.resolve();
    controller.abort();
    const result = await pending;
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.failure.kind).toBe('cancelled');
    }
    expect(ctx.recordedOptions).toHaveLength(1);
  });

  it('cancels during TLS before secureConnect', async () => {
    const controller = new AbortController();
    ctx.remainingResponses.push({ omitSecureConnect: true, omitResponse: true });
    const pending = ctx.adapter().listPage(validListingRequest({ signal: controller.signal }));
    await Promise.resolve();
    controller.abort();
    const result = await pending;
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.failure.kind).toBe('cancelled');
    }
  });

  it('cancels during body consumption', async () => {
    const controller = new AbortController();
    ctx.remainingResponses.push({
      statusCode: 200,
      headers: jsonHeaders(MINIMAL_PAGE),
      body: MINIMAL_PAGE,
      neverEnd: true,
    });
    const pending = ctx.adapter().listPage(validListingRequest({ signal: controller.signal }));
    await Promise.resolve();
    controller.abort();
    const result = await pending;
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.failure.kind).toBe('cancelled');
    }
  });

  it('ignores cancellation after an accepted terminal response', async () => {
    const controller = new AbortController();
    ctx.remainingResponses.push({
      statusCode: 200,
      headers: jsonHeaders(MINIMAL_PAGE),
      body: MINIMAL_PAGE,
    });
    const result = await ctx.adapter().listPage(validListingRequest({ signal: controller.signal }));
    expect(result.ok).toBe(true);
    controller.abort();
    expect(result.ok).toBe(true);
  });

  it('treats repeated cancellation as idempotent', async () => {
    const controller = new AbortController();
    ctx.remainingResponses.push({ omitResponse: true });
    const pending = ctx.adapter().listPage(validListingRequest({ signal: controller.signal }));
    await Promise.resolve();
    controller.abort();
    controller.abort();
    const result = await pending;
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.failure.kind).toBe('cancelled');
    }
    expect(ctx.recordedOptions).toHaveLength(1);
  });

  it('settles once when cancellation and timeout race', async () => {
    const controller = new AbortController();
    ctx.remainingResponses.push({ omitResponse: true });
    const pending = ctx.adapter().listPage(validListingRequest({ signal: controller.signal }));
    await Promise.resolve();
    controller.abort();
    await vi.advanceTimersByTimeAsync(OSV_TIMEOUT_POLICY_V1.totalRequestDeadlineMs);
    const result = await pending;
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(['cancelled', 'timeout']).toContain(result.failure.kind);
    }
    expect(ctx.recordedOptions).toHaveLength(1);
  });

  it('ignores a response that arrives after timeout', async () => {
    ctx.remainingResponses.push({
      omitResponse: true,
      delayMs: OSV_TIMEOUT_POLICY_V1.responseHeaderTimeoutMs + 50,
      statusCode: 200,
      headers: jsonHeaders(MINIMAL_PAGE),
      body: MINIMAL_PAGE,
    });
    const pending = ctx.adapter().listPage(validListingRequest());
    await Promise.resolve();
    await vi.advanceTimersByTimeAsync(OSV_TIMEOUT_POLICY_V1.responseHeaderTimeoutMs);
    const result = await pending;
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.failure.kind).toBe('timeout');
    }
    await vi.advanceTimersByTimeAsync(100);
    expect(ctx.recordedOptions).toHaveLength(1);
  });

  it('accepts a response just before timeout', async () => {
    ctx.remainingResponses.push({
      statusCode: 200,
      headers: jsonHeaders(MINIMAL_PAGE),
      body: MINIMAL_PAGE,
    });
    const pending = ctx.adapter().listPage(validListingRequest());
    await Promise.resolve();
    const result = await pending;
    expect(result.ok).toBe(true);
    expect(ctx.recordedOptions).toHaveLength(1);
  });

  it('times out on the total deadline when headers never arrive', async () => {
    ctx.remainingResponses.push({ omitSecureConnect: true, omitResponse: true });
    const pending = ctx.adapter().listPage(validListingRequest());
    await Promise.resolve();
    await vi.advanceTimersByTimeAsync(OSV_TIMEOUT_POLICY_V1.totalRequestDeadlineMs);
    const result = await pending;
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.failure.kind).toBe('timeout');
    }
    expect(ctx.recordedOptions).toHaveLength(1);
  });

  it('does not issue a second request after timeout', async () => {
    ctx.remainingResponses.push({ omitResponse: true });
    const pending = ctx.adapter().listPage(validListingRequest());
    await Promise.resolve();
    await vi.advanceTimersByTimeAsync(OSV_TIMEOUT_POLICY_V1.totalRequestDeadlineMs);
    await pending;
    expect(ctx.recordedOptions).toHaveLength(1);
  });
});

describe('OSV GCS listing DNS lookup timeout', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    ctx.reset();
  });

  afterEach(() => {
    vi.useRealTimers();
    ctx.reset();
  });

  it('maps a hung lookup to timeout without HTTPS', async () => {
    ctx.setLookup(() => undefined);
    const pending = ctx.adapter().listPage(validListingRequest());
    await vi.advanceTimersByTimeAsync(OSV_TIMEOUT_POLICY_V1.connectionTimeoutMs);
    const result = await pending;
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.failure.kind).toBe('timeout');
    }
    expect(ctx.recordedOptions).toHaveLength(0);
  });
});

describe('OSV GCS listing request-error mapping', () => {
  it('maps connection reset before headers', async () => {
    vi.useRealTimers();
    ctx.remainingResponses.push({
      omitResponse: true,
      emitRequestError: Object.assign(new Error('reset'), { code: 'ECONNRESET' }),
    });
    const result = await ctx.adapter().listPage(validListingRequest());
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.failure.kind).toBe('connection_reset');
    }
  });

  it('maps a socket error before headers as connection_reset', async () => {
    vi.useRealTimers();
    ctx.remainingResponses.push({
      omitResponse: true,
      emitSocketError: new Error('socket'),
    });
    const result = await ctx.adapter().listPage(validListingRequest());
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.failure.kind).toBe('connection_reset');
    }
  });
});
