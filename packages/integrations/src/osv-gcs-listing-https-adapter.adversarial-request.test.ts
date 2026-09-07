/**
 * Session 12 Batch 2 prefix, continuation-token, header-injection, query,
 * and token-confidentiality attacks. Synthetic tokens only.
 */

import { inspect } from 'node:util';

import { afterEach, describe, expect, it } from 'vitest';

import {
  OSV_GCS_JSON_OBJECTS_LIST_FIELDS,
  OSV_GCS_JSON_OBJECTS_LIST_MAX_RESULTS,
  OSV_INVENTORY_SCOPE_PROVIDER_PREFIXES,
  createOsvListingContinuationToken,
} from '@patchpilot/vulnerability-intelligence';

import {
  MINIMAL_PAGE,
  SECRET_TOKEN,
  assertConfidential,
  continuationRequest,
  createListingTestContext,
  jsonHeaders,
  listingJson,
  listingInput,
  validListingRequest,
} from './osv-gcs-listing-https-adapter.test-harness.js';

const ctx = createListingTestContext();

afterEach(() => {
  ctx.reset();
});

function encodedFields(): string {
  return encodeURIComponent(OSV_GCS_JSON_OBJECTS_LIST_FIELDS);
}

function recordedPath(): string {
  const options = ctx.recordedOptions[0] as { path: string };
  return options.path;
}

describe('OSV GCS listing adversarial prefix encoding', () => {
  it('encodes each approved prefix exactly once without altering query order', async () => {
    for (const prefix of OSV_INVENTORY_SCOPE_PROVIDER_PREFIXES) {
      const page = listingJson({ items: [] });
      ctx.setResponses([
        {
          statusCode: 200,
          headers: jsonHeaders(page),
          body: page,
        },
      ]);
      const result = await ctx.adapter().listPage(validListingRequest({ providerPrefix: prefix }));
      expect(result.ok, prefix).toBe(true);
      expect(ctx.recordedOptions, prefix).toHaveLength(1);
      const path = recordedPath();
      expect(path).toBe(
        `/storage/v1/b/osv-vulnerabilities/o?prefix=${encodeURIComponent(prefix)}&maxResults=${OSV_GCS_JSON_OBJECTS_LIST_MAX_RESULTS}&fields=${encodedFields()}`,
      );
      expect(path).not.toContain('prefix=' + prefix.slice(0, -1) + '&');
      expect(path.indexOf('prefix=')).toBeLessThan(path.indexOf('maxResults='));
      expect(path.indexOf('maxResults=')).toBeLessThan(path.indexOf('fields='));
      ctx.recordedOptions.length = 0;
    }
  });

  it('rejects malformed, unknown, and object-key prefixes with zero HTTPS', async () => {
    const prefixes = [
      '',
      'debian/',
      'NPM/',
      'pypi/',
      '/npm/',
      'npm//',
      'npm\\',
      'npm/../',
      'npm/?x=1',
      'npm/#frag',
      'npm/%2F',
      'npm/%252F',
      'npm/\0',
      'npm/\u0001',
      'npm/\u007f',
      'npm/\u0080',
      'npm/\u2215',
      ' npm/',
      'npm/ ',
      'npm/\t',
      `${'n'.repeat(5000)}/`,
      'npm/GHSA-aaaa-bbbb-cccc.json',
    ];
    for (const providerPrefix of prefixes) {
      ctx.recordedOptions.length = 0;
      const result = await ctx.adapter().listPage(listingInput({ providerPrefix }) as never);
      expect(result.ok, providerPrefix).toBe(false);
      expect(ctx.recordedOptions, providerPrefix).toHaveLength(0);
      if (!result.ok) {
        expect(result.failure.kind).toBe('policy_violation');
        assertConfidential(result.failure);
        if (providerPrefix.length > 0) {
          expect(JSON.stringify(result.failure)).not.toContain(providerPrefix);
        }
      }
    }
  });
});

describe('OSV GCS listing adversarial continuation tokens', () => {
  it('encodes opaque tokens exactly once in pageToken and never as a header', async () => {
    const tokens = [
      SECRET_TOKEN,
      'a'.repeat(8192),
      ' token',
      'token ',
      'a b',
      'plus+slash/equals=',
      'question?and&hash#percent%',
      '%2Falready',
      'こんにちは',
      'token\u00a0wide',
    ];
    for (const raw of tokens) {
      const created = createOsvListingContinuationToken(raw);
      expect(created.ok, raw).toBe(true);
      if (!created.ok) {
        continue;
      }
      ctx.setResponses([
        {
          statusCode: 200,
          headers: jsonHeaders(MINIMAL_PAGE),
          body: MINIMAL_PAGE,
        },
      ]);
      const result = await ctx
        .adapter()
        .listPage(validListingRequest({ continuationToken: created.value }));
      expect(result.ok, raw).toBe(true);
      const options = ctx.recordedOptions[0] as { path: string; headers: Record<string, string> };
      expect(options.path).toContain(`pageToken=${encodeURIComponent(raw)}`);
      expect(options.path.match(/pageToken=/g)).toEqual(['pageToken=']);
      expect(options.path).not.toContain('#' + raw);
      expect(Object.values(options.headers).join('\n')).not.toContain(
        raw === 'a'.repeat(8192) ? 'aaaa' : raw,
      );
      expect(Object.keys(options.headers)).toEqual(
        expect.arrayContaining([
          'Host',
          'User-Agent',
          'Connection',
          'Accept',
          'Accept-Encoding',
          'Cache-Control',
        ]),
      );
      ctx.recordedOptions.length = 0;
    }
  });

  it('rejects empty, oversized, and invalid token wrappers with zero HTTPS', async () => {
    const oversize = createOsvListingContinuationToken('é'.repeat(4097));
    expect(oversize.ok).toBe(true);
    const cases: Array<{ input: unknown; kind: string }> = [
      { input: listingInput({ continuationToken: '' }), kind: 'invalid_page_token' },
      { input: listingInput({ continuationToken: [] }), kind: 'invalid_page_token' },
      {
        input: listingInput({ continuationToken: { token: SECRET_TOKEN } }),
        kind: 'invalid_page_token',
      },
      { input: listingInput({ continuationToken: SECRET_TOKEN }), kind: 'invalid_page_token' },
      {
        input: listingInput({
          continuationToken: oversize.ok ? oversize.value : SECRET_TOKEN,
        }),
        kind: 'invalid_page_token',
      },
      { input: listingInput({ pageToken: SECRET_TOKEN }), kind: 'policy_violation' },
      { input: listingInput({ nextPageToken: SECRET_TOKEN }), kind: 'policy_violation' },
    ];
    for (const item of cases) {
      ctx.recordedOptions.length = 0;
      const result = await ctx.adapter().listPage(item.input as never);
      expect(result.ok, JSON.stringify(item.input)).toBe(false);
      expect(ctx.recordedOptions).toHaveLength(0);
      if (!result.ok) {
        expect(result.failure.kind).toBe(item.kind);
        assertConfidential(result.failure);
      }
    }
  });

  it('does not implement token-cycle detection or a digest store', async () => {
    const source = await import('node:fs').then((fs) =>
      fs.readFileSync(new URL('./osv-gcs-listing-https-adapter.ts', import.meta.url), 'utf8'),
    );
    expect(source).not.toContain('repeated_page_token');
    expect(source).not.toContain('tokenDigestSet');
    expect(source).not.toContain('osv_listing_pagination_policy_v1');
  });
});

describe('OSV GCS listing adversarial query integrity', () => {
  it('cannot add retrieval, auth, callback, or duplicate listing parameters', async () => {
    const extras = [
      { maxResults: 1 },
      { fields: 'items' },
      { delimiter: '/' },
      { alt: 'media' },
      { ifGenerationMatch: '1' },
      { access_token: 'tok' },
      { callback: 'steal' },
      { uploadType: 'media' },
      { pageToken: SECRET_TOKEN },
    ];
    for (const extra of extras) {
      ctx.recordedOptions.length = 0;
      const result = await ctx.adapter().listPage(listingInput(extra) as never);
      expect(result.ok).toBe(false);
      expect(ctx.recordedOptions).toHaveLength(0);
    }
  });

  it('omits pageToken when absent and includes it once when present', async () => {
    ctx.remainingResponses.push({
      statusCode: 200,
      headers: jsonHeaders(MINIMAL_PAGE),
      body: MINIMAL_PAGE,
    });
    await ctx.adapter().listPage(validListingRequest());
    expect(recordedPath()).not.toContain('pageToken=');
    ctx.recordedOptions.length = 0;
    ctx.remainingResponses.push({
      statusCode: 200,
      headers: jsonHeaders(MINIMAL_PAGE),
      body: MINIMAL_PAGE,
    });
    await ctx.adapter().listPage(continuationRequest());
    const path = recordedPath();
    expect(path.match(/pageToken=/g)).toEqual(['pageToken=']);
    expect(path).not.toContain('alt=media');
  });
});

describe('OSV GCS listing adversarial request headers', () => {
  it('uses a closed header set without Authorization, Cookie, Range, or token values', async () => {
    ctx.remainingResponses.push({
      statusCode: 200,
      headers: jsonHeaders(MINIMAL_PAGE),
      body: MINIMAL_PAGE,
    });
    await ctx.adapter().listPage(continuationRequest());
    const options = ctx.recordedOptions[0] as { headers: Record<string, string> };
    expect(Object.keys(options.headers).sort()).toEqual(
      ['Accept', 'Accept-Encoding', 'Cache-Control', 'Connection', 'Host', 'User-Agent'].sort(),
    );
    expect(options.headers['User-Agent']).toBe('PatchPilot-intelligence/0.1');
    expect(options.headers['Accept-Encoding']).toBe('identity');
    expect(options.headers['Authorization']).toBeUndefined();
    expect(options.headers['Cookie']).toBeUndefined();
    expect(options.headers['Range']).toBeUndefined();
    expect(options.headers['X-Forwarded-Host']).toBeUndefined();
    expect(JSON.stringify(options.headers)).not.toContain(SECRET_TOKEN);
    expect(JSON.stringify(options.headers)).not.toContain('\r');
    expect(JSON.stringify(options.headers)).not.toContain('\n');
  });
});

describe('OSV GCS listing adversarial token confidentiality', () => {
  it('omits the raw token marker from every reachable failure phase', async () => {
    const phases: Array<{
      name: string;
      run: () => Promise<unknown>;
    }> = [
      {
        name: 'invalid token wrapper',
        run: () =>
          ctx.adapter().listPage(listingInput({ continuationToken: SECRET_TOKEN }) as never),
      },
      {
        name: 'oversized token',
        run: async () => {
          const token = createOsvListingContinuationToken('x'.repeat(8193));
          expect(token.ok).toBe(true);
          if (!token.ok) {
            return token;
          }
          return ctx.adapter().listPage(listingInput({ continuationToken: token.value }) as never);
        },
      },
      {
        name: 'redirect',
        run: async () => {
          ctx.remainingResponses.push({
            statusCode: 302,
            headers: { location: `https://evil.example/?t=${SECRET_TOKEN}` },
            body: Buffer.from(SECRET_TOKEN),
          });
          return ctx.adapter().listPage(continuationRequest());
        },
      },
      {
        name: 'status 500',
        run: async () => {
          ctx.remainingResponses.push({
            statusCode: 500,
            headers: { 'content-type': 'application/json' },
            body: Buffer.from(SECRET_TOKEN),
          });
          return ctx.adapter().listPage(continuationRequest());
        },
      },
      {
        name: 'content type',
        run: async () => {
          ctx.remainingResponses.push({
            statusCode: 200,
            headers: { 'content-type': 'text/plain' },
            body: Buffer.from(SECRET_TOKEN),
          });
          return ctx.adapter().listPage(continuationRequest());
        },
      },
      {
        name: 'content encoding',
        run: async () => {
          ctx.remainingResponses.push({
            statusCode: 200,
            headers: {
              'content-type': 'application/json',
              'content-encoding': 'gzip',
            },
            body: Buffer.from(SECRET_TOKEN),
          });
          return ctx.adapter().listPage(continuationRequest());
        },
      },
      {
        name: 'overflow',
        run: async () => {
          ctx.remainingResponses.push({
            statusCode: 200,
            headers: { 'content-type': 'application/json' },
            body: Buffer.alloc(1_048_577, 0x61),
          });
          return ctx.adapter().listPage(continuationRequest());
        },
      },
      {
        name: 'invalid utf8',
        run: async () => {
          ctx.remainingResponses.push({
            statusCode: 200,
            headers: jsonHeaders(Buffer.from([0xff, 0xfe])),
            body: Buffer.from([0xff, 0xfe]),
          });
          return ctx.adapter().listPage(continuationRequest());
        },
      },
      {
        name: 'malformed json',
        run: async () => {
          ctx.remainingResponses.push({
            statusCode: 200,
            headers: { 'content-type': 'application/json' },
            body: Buffer.from('{', 'utf8'),
          });
          return ctx.adapter().listPage(continuationRequest());
        },
      },
    ];
    for (const phase of phases) {
      ctx.recordedOptions.length = 0;
      const result = await phase.run();
      const text = `${JSON.stringify(result)}\n${inspect(result)}\n${String(result)}`;
      expect(text, phase.name).not.toContain(SECRET_TOKEN);
      expect(text, phase.name).not.toContain('pageToken=');
    }
  });

  it('does not emit a token digest from listing operational events', async () => {
    const events: Array<Record<string, unknown>> = [];
    ctx.remainingResponses.push({
      statusCode: 200,
      headers: jsonHeaders(MINIMAL_PAGE),
      body: MINIMAL_PAGE,
    });
    await ctx
      .adapter({
        logger: {
          info: (bindings) => {
            events.push(bindings);
          },
          warn: (bindings) => {
            events.push(bindings);
          },
        },
      })
      .listPage(continuationRequest());
    const serialized = JSON.stringify(events);
    expect(serialized).not.toContain(SECRET_TOKEN);
    expect(serialized).not.toContain('digest');
    expect(serialized).not.toContain('pageToken');
  });
});
