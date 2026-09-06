/**
 * Session 12 Batch 2 endpoint, SSRF, DNS, and TLS attacks against the
 * listing-page HTTPS executor. Synthetic doubles only.
 */

import { afterEach, describe, expect, it } from 'vitest';

import {
  PUBLIC_V4,
  SECRET_TOKEN,
  assertConfidential,
  continuationRequest,
  createListingTestContext,
  jsonHeaders,
  listingInput,
  MINIMAL_PAGE,
  validListingRequest,
} from './osv-gcs-listing-https-adapter.test-harness.js';

const ctx = createListingTestContext();

afterEach(() => {
  ctx.reset();
});

function expectPinnedRequest(): {
  hostname: string;
  port: number;
  servername: string;
  rejectUnauthorized: boolean;
  minVersion: string;
  path: string;
  lookup?: (
    hostname: string,
    options: unknown,
    callback: (error: Error | null, address: string, family?: number) => void,
  ) => void;
  ca?: unknown;
  checkServerIdentity?: unknown;
  agent?: { options?: { proxyEnv?: unknown; autoSelectFamily?: boolean } };
} {
  expect(ctx.recordedOptions).toHaveLength(1);
  return ctx.recordedOptions[0] as ReturnType<typeof expectPinnedRequest>;
}

describe('OSV GCS listing adversarial endpoint and SSRF', () => {
  it('rejects caller-supplied destination fields before HTTPS', async () => {
    const extras = [
      { url: 'https://evil.example/list' },
      { host: 'storage.cloud.google.com' },
      { hostname: 'www.googleapis.com' },
      { scheme: 'http' },
      { port: 80 },
      { bucket: 'other-bucket' },
      { path: '/storage/v1/b/osv-vulnerabilities/o' },
      { query: 'prefix=npm/' },
      { endpoint: 'https://storage.googleapis.com' },
      { href: 'https://storage.googleapis.com/storage/v1/b/osv-vulnerabilities/o' },
      { mediaLink: 'https://storage.googleapis.com/download' },
      { selfLink: 'https://www.googleapis.com/storage/v1' },
      { headers: { Host: 'evil.example' } },
      { proxy: 'http://127.0.0.1:8080' },
    ];
    for (const extra of extras) {
      ctx.recordedOptions.length = 0;
      const result = await ctx.adapter().listPage(listingInput(extra) as never);
      expect(result.ok, JSON.stringify(extra)).toBe(false);
      expect(ctx.recordedOptions, JSON.stringify(extra)).toHaveLength(0);
      if (!result.ok) {
        assertConfidential(result.failure);
        expect(JSON.stringify(result.failure)).not.toContain('evil.example');
        expect(JSON.stringify(result.failure)).not.toContain('127.0.0.1');
      }
    }
  });

  it('always dispatches the compiled GCS listing host, path, and TLS pin', async () => {
    ctx.remainingResponses.push({
      statusCode: 200,
      headers: jsonHeaders(MINIMAL_PAGE),
      body: MINIMAL_PAGE,
    });
    const result = await ctx.adapter().listPage(validListingRequest());
    expect(result.ok).toBe(true);
    const options = expectPinnedRequest();
    expect(options.hostname).toBe('storage.googleapis.com');
    expect(options.port).toBe(443);
    expect(options.servername).toBe('storage.googleapis.com');
    expect(options.rejectUnauthorized).toBe(true);
    expect(options.minVersion).toBe('TLSv1.2');
    expect(options.ca).toBeUndefined();
    expect(options.checkServerIdentity).toBeUndefined();
    expect(options.path.startsWith('/storage/v1/b/osv-vulnerabilities/o?')).toBe(true);
    expect(ctx.lookupHosts).toEqual(['storage.googleapis.com']);
    expect(options.agent?.options?.proxyEnv).toEqual({});
    expect(options.agent?.options?.autoSelectFamily).toBe(false);
  });

  it('pins Node lookup callbacks to the selected public address', async () => {
    ctx.remainingResponses.push({
      statusCode: 200,
      headers: jsonHeaders(MINIMAL_PAGE),
      body: MINIMAL_PAGE,
    });
    await ctx.adapter().listPage(validListingRequest());
    const options = expectPinnedRequest();
    expect(typeof options.lookup).toBe('function');
    const observed: Array<{ address: string; family?: number }> = [];
    options.lookup?.('evil.example', {}, (error, address, family) => {
      expect(error).toBeNull();
      if (family === undefined) {
        observed.push({ address });
        return;
      }
      observed.push({ address, family });
    });
    options.lookup?.('storage.googleapis.com.', { all: true }, (error, address) => {
      expect(error).toBeNull();
      observed.push({ address });
    });
    expect(observed[0]).toEqual({ address: PUBLIC_V4, family: 4 });
  });
});

describe('OSV GCS listing adversarial DNS lookup', () => {
  it('fails closed on prohibited and malformed answers without HTTPS', async () => {
    const blocked: Array<Array<{ address: string; family: number }>> = [
      [{ address: '127.0.0.1', family: 4 }],
      [{ address: '10.0.0.1', family: 4 }],
      [{ address: '169.254.1.1', family: 4 }],
      [{ address: '0.0.0.0', family: 4 }],
      [{ address: '224.0.0.1', family: 4 }],
      [{ address: '192.168.1.1', family: 4 }],
      [{ address: 'fc00::1', family: 6 }],
      [{ address: 'fe80::1', family: 6 }],
      [{ address: '::1', family: 6 }],
      [{ address: '::ffff:10.0.0.1', family: 6 }],
      [{ address: '::ffff:127.0.0.1', family: 6 }],
      [{ address: 'not-an-ip', family: 4 }],
      [{ address: '1.1.1.1', family: 0 }],
      [],
    ];
    for (const answers of blocked) {
      ctx.recordedOptions.length = 0;
      ctx.setLookup((_hostname, _options, callback) => {
        callback(null, answers);
      });
      const result = await ctx.adapter().listPage(validListingRequest());
      expect(result.ok, JSON.stringify(answers)).toBe(false);
      expect(ctx.recordedOptions, JSON.stringify(answers)).toHaveLength(0);
      if (!result.ok) {
        expect(result.failure.kind).toBe('policy_violation');
        assertConfidential(result.failure);
        expect(JSON.stringify(result.failure)).not.toContain('127.0.0.1');
        expect(JSON.stringify(result.failure)).not.toContain('10.0.0.1');
      }
    }
  });

  it('selects the first approved public IPv4 and does not switch on later answers', async () => {
    ctx.setLookup((_hostname, _options, callback) => {
      callback(null, [
        { address: '10.0.0.1', family: 4 },
        { address: PUBLIC_V4, family: 4 },
        { address: '8.8.8.8', family: 4 },
        { address: '2001:4860:4860::8888', family: 6 },
      ]);
    });
    ctx.remainingResponses.push({
      statusCode: 200,
      headers: jsonHeaders(MINIMAL_PAGE),
      body: MINIMAL_PAGE,
      remoteAddress: PUBLIC_V4,
      remoteFamily: 'IPv4',
    });
    const result = await ctx.adapter().listPage(validListingRequest());
    expect(result.ok).toBe(true);
    expect(ctx.recordedOptions).toHaveLength(1);
    expect(ctx.lookupCalls).toBe(1);
  });

  it('ignores a mutated DNS answer array after the lookup callback', async () => {
    ctx.setLookup((_hostname, _options, callback) => {
      const answers = [{ address: PUBLIC_V4, family: 4 }];
      callback(null, answers);
      answers[0] = { address: '127.0.0.1', family: 4 };
    });
    ctx.remainingResponses.push({
      statusCode: 200,
      headers: jsonHeaders(MINIMAL_PAGE),
      body: MINIMAL_PAGE,
      remoteAddress: PUBLIC_V4,
    });
    const result = await ctx.adapter().listPage(validListingRequest());
    expect(result.ok).toBe(true);
    expect(ctx.recordedOptions).toHaveLength(1);
  });

  it('ignores a duplicate lookup callback and does not issue a second request', async () => {
    ctx.setLookup((_hostname, _options, callback) => {
      callback(null, [{ address: PUBLIC_V4, family: 4 }]);
      callback(null, [{ address: '8.8.8.8', family: 4 }]);
    });
    ctx.remainingResponses.push({
      statusCode: 200,
      headers: jsonHeaders(MINIMAL_PAGE),
      body: MINIMAL_PAGE,
      remoteAddress: PUBLIC_V4,
    });
    const result = await ctx.adapter().listPage(validListingRequest());
    expect(result.ok).toBe(true);
    expect(ctx.recordedOptions).toHaveLength(1);
  });

  it('maps lookup errors without raw system detail', async () => {
    ctx.setLookup((_hostname, _options, callback) => {
      callback(
        Object.assign(new Error('ENOTFOUND storage.googleapis.com'), { code: 'ENOTFOUND' }),
        [],
      );
    });
    const result = await ctx.adapter().listPage(continuationRequest());
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.failure.kind).toBe('temporary_dns_failure');
      assertConfidential(result.failure, [SECRET_TOKEN, 'ENOTFOUND', 'storage.googleapis.com']);
    }
    expect(ctx.recordedOptions).toHaveLength(0);
  });

  it('ignores a late lookup result after cancellation', async () => {
    const controller = new AbortController();
    let late:
      | ((
          error: NodeJS.ErrnoException | null,
          addresses: Array<{ address: string; family: number }>,
        ) => void)
      | undefined;
    ctx.setLookup((_hostname, _options, callback) => {
      late = callback;
      controller.abort();
    });
    const result = await ctx.adapter().listPage(validListingRequest({ signal: controller.signal }));
    expect(result.ok).toBe(false);
    late?.(null, [{ address: PUBLIC_V4, family: 4 }]);
    expect(ctx.recordedOptions).toHaveLength(0);
  });
});

describe('OSV GCS listing adversarial TLS and post-connect', () => {
  it('rejects unauthorized, missing, or mismatched peer identity', async () => {
    const peers: Array<{
      remoteAddress?: string;
      remoteFamily?: string;
      omitRemoteAddress?: boolean;
    }> = [
      { remoteAddress: '8.8.8.8', remoteFamily: 'IPv4' },
      { remoteAddress: '127.0.0.1', remoteFamily: 'IPv4' },
      { omitRemoteAddress: true, remoteFamily: 'IPv4' },
      { remoteAddress: 'not-an-ip', remoteFamily: 'IPv4' },
      { remoteAddress: '2001:4860:4860::8888', remoteFamily: 'IPv6' },
    ];
    for (const peer of peers) {
      ctx.setResponses([
        {
          statusCode: 200,
          headers: jsonHeaders(MINIMAL_PAGE),
          body: MINIMAL_PAGE,
          ...peer,
        },
      ]);
      const result = await ctx.adapter().listPage(continuationRequest());
      expect(result.ok, JSON.stringify(peer)).toBe(false);
      if (!result.ok) {
        expect(result.failure.kind).toBe('policy_violation');
        assertConfidential(result.failure, [SECRET_TOKEN, '8.8.8.8', '127.0.0.1']);
      }
      expect(ctx.recordedOptions).toHaveLength(1);
      ctx.recordedOptions.length = 0;
    }
  });

  it('does not accept a response before secureConnect', async () => {
    ctx.remainingResponses.push({
      statusCode: 200,
      headers: jsonHeaders(MINIMAL_PAGE),
      body: MINIMAL_PAGE,
      omitSecureConnect: true,
    });
    const result = await ctx.adapter().listPage(validListingRequest());
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.failure.kind).toBe('policy_violation');
    }
    expect(ctx.recordedOptions).toHaveLength(1);
  });

  it('does not expose a production TLS bypass', async () => {
    ctx.remainingResponses.push({
      statusCode: 200,
      headers: jsonHeaders(MINIMAL_PAGE),
      body: MINIMAL_PAGE,
    });
    await ctx.adapter().listPage(validListingRequest());
    const options = expectPinnedRequest();
    expect(options.rejectUnauthorized).toBe(true);
    expect(options.ca).toBeUndefined();
    expect(JSON.stringify(options)).not.toContain('rejectUnauthorized":false');
  });
});
