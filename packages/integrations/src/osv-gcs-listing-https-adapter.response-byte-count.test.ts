/**
 * Session 12 Batch 4 listing-page responseByteCount bridge tests.
 * Synthetic local doubles only. Never contacts storage.googleapis.com.
 */

import { inspect } from 'node:util';

import { afterEach, describe, expect, it } from 'vitest';

import { OSV_GCS_LISTING_PAGE_MAX_BYTES } from '@patchpilot/vulnerability-intelligence';

import {
  MINIMAL_PAGE,
  SECRET_TOKEN,
  assertConfidential,
  continuationRequest,
  createListingTestContext,
  jsonHeaders,
  listingInput,
  listingJson,
  validListingRequest,
} from './osv-gcs-listing-https-adapter.test-harness.js';

const ctx = createListingTestContext();

afterEach(() => {
  ctx.reset();
});

describe('Session 12 Batch 4 listing responseByteCount bridge', () => {
  it('returns the exact ASCII transport byte count', async () => {
    ctx.remainingResponses.push({
      statusCode: 200,
      headers: jsonHeaders(MINIMAL_PAGE),
      body: MINIMAL_PAGE,
    });
    const result = await ctx.adapter().listPage(validListingRequest());
    expect(result.ok).toBe(true);
    if (!result.ok) {
      throw new Error(result.failure.kind);
    }
    expect(result.responseByteCount).toBe(MINIMAL_PAGE.byteLength);
    expect(result.responseByteCount).toBeGreaterThan(0);
    expect(result.responseByteCount).toBeLessThanOrEqual(OSV_GCS_LISTING_PAGE_MAX_BYTES);
    expect(Object.isFrozen(result)).toBe(true);
    expect('bytes' in result).toBe(false);
    expect(ctx.recordedOptions).toHaveLength(1);
  });

  it('uses transport byte count for multibyte UTF-8, not JavaScript string length', async () => {
    const body = listingJson({ nextPageToken: 'café' });
    expect(body.byteLength).toBeGreaterThan(body.toString('utf8').length);
    ctx.remainingResponses.push({
      statusCode: 200,
      headers: jsonHeaders(body),
      body,
    });
    const result = await ctx.adapter().listPage(validListingRequest());
    expect(result.ok).toBe(true);
    if (!result.ok) {
      throw new Error(result.failure.kind);
    }
    expect(result.responseByteCount).toBe(body.byteLength);
    expect(result.responseByteCount).not.toBe(body.toString('utf8').length);
    expect(JSON.stringify(result).length).not.toBe(result.responseByteCount);
  });

  it('returns received bytes when Content-Length is missing and agrees when present', async () => {
    ctx.setResponses([
      {
        statusCode: 200,
        headers: { 'content-type': 'application/json' },
        body: MINIMAL_PAGE,
      },
    ]);
    const missing = await ctx.adapter().listPage(validListingRequest());
    expect(missing.ok).toBe(true);
    if (!missing.ok) {
      throw new Error(missing.failure.kind);
    }
    expect(missing.responseByteCount).toBe(MINIMAL_PAGE.byteLength);

    ctx.reset();
    ctx.remainingResponses.push({
      statusCode: 200,
      headers: jsonHeaders(MINIMAL_PAGE),
      body: MINIMAL_PAGE,
    });
    const present = await ctx.adapter().listPage(validListingRequest());
    expect(present.ok).toBe(true);
    if (!present.ok) {
      throw new Error(present.failure.kind);
    }
    expect(present.responseByteCount).toBe(Number(jsonHeaders(MINIMAL_PAGE)['content-length']));
  });

  it('accepts an exact 1048576-byte page and rejects a Content-Length mismatch', async () => {
    const pad = Buffer.alloc(OSV_GCS_LISTING_PAGE_MAX_BYTES - MINIMAL_PAGE.byteLength, 0x20);
    const exact = Buffer.concat([MINIMAL_PAGE, pad]);
    expect(exact.byteLength).toBe(OSV_GCS_LISTING_PAGE_MAX_BYTES);
    ctx.remainingResponses.push({
      statusCode: 200,
      headers: jsonHeaders(exact),
      body: exact,
    });
    const exactResult = await ctx.adapter().listPage(validListingRequest());
    expect(exactResult.ok).toBe(true);
    if (!exactResult.ok) {
      throw new Error(exactResult.failure.kind);
    }
    expect(exactResult.responseByteCount).toBe(OSV_GCS_LISTING_PAGE_MAX_BYTES);

    ctx.reset();
    ctx.setResponses([
      {
        statusCode: 200,
        headers: {
          'content-type': 'application/json',
          'content-length': '10',
        },
        body: MINIMAL_PAGE,
      },
    ]);
    const mismatch = await ctx.adapter().listPage(validListingRequest());
    expect(mismatch.ok).toBe(false);
    expect(mismatch).not.toHaveProperty('responseByteCount');
  });

  it('does not return a successful page result for malformed listing JSON', async () => {
    const body = Buffer.from('{"kind":"not-objects"}', 'utf8');
    ctx.remainingResponses.push({
      statusCode: 200,
      headers: jsonHeaders(body),
      body,
    });
    const result = await ctx.adapter().listPage(validListingRequest());
    expect(result.ok).toBe(false);
    expect(result).not.toHaveProperty('responseByteCount');
    expect(ctx.recordedOptions).toHaveLength(1);
  });

  it('rejects caller-injected responseByteCount on the listing request', async () => {
    const result = await ctx.adapter().listPage(listingInput({ responseByteCount: 12 }) as never);
    expect(result.ok).toBe(false);
    expect(ctx.recordedOptions).toHaveLength(0);
    if (!result.ok) {
      expect(result.failure.kind).toBe('policy_violation');
      expect(result).not.toHaveProperty('responseByteCount');
      assertConfidential(result.failure);
    }
  });

  it('does not return a successful byte count on overflow or malformed UTF-8', async () => {
    const oversize = Buffer.concat([MINIMAL_PAGE, Buffer.alloc(OSV_GCS_LISTING_PAGE_MAX_BYTES)]);
    ctx.setResponses([
      {
        statusCode: 200,
        headers: {
          'content-type': 'application/json',
          'content-length': String(oversize.byteLength),
        },
        body: oversize,
      },
    ]);
    const overflow = await ctx.adapter().listPage(validListingRequest());
    expect(overflow.ok).toBe(false);
    expect(overflow).not.toHaveProperty('responseByteCount');

    ctx.reset();
    ctx.remainingResponses.push({
      statusCode: 200,
      headers: {
        'content-type': 'application/json',
        'content-length': '2',
      },
      body: Buffer.from([0x80, 0x61]),
    });
    const malformed = await ctx.adapter().listPage(validListingRequest());
    expect(malformed.ok).toBe(false);
    expect(malformed).not.toHaveProperty('responseByteCount');
  });

  it('keeps token confidentiality and one-request semantics on success', async () => {
    ctx.remainingResponses.push({
      statusCode: 200,
      headers: jsonHeaders(MINIMAL_PAGE),
      body: MINIMAL_PAGE,
    });
    const result = await ctx.adapter().listPage(continuationRequest(SECRET_TOKEN));
    expect(result.ok).toBe(true);
    if (!result.ok) {
      throw new Error(result.failure.kind);
    }
    expect(ctx.recordedOptions).toHaveLength(1);
    const blob = `${JSON.stringify(result)}\n${inspect(result)}`;
    expect(blob).not.toContain(SECRET_TOKEN);
    expect(result.responseByteCount).toBe(MINIMAL_PAGE.byteLength);
  });
});
