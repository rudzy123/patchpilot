/**
 * Session 12 Batch 2 status, redirect, header-ambiguity, bound, UTF-8, and
 * listing-parser handoff attacks. In-memory synthetic pages only.
 */

import { Readable } from 'node:stream';

import { afterEach, describe, expect, it } from 'vitest';

import {
  OSV_GCS_JSON_OBJECTS_LIST_MAX_RESULTS,
  OSV_GCS_LISTING_PAGE_MAX_BYTES,
  parseOsvGcsListingPage,
} from '@patchpilot/vulnerability-intelligence';

import {
  MINIMAL_PAGE,
  SECRET_TOKEN,
  assertConfidential,
  continuationRequest,
  createListingTestContext,
  jsonHeaders,
  listingJson,
  validListingRequest,
} from './osv-gcs-listing-https-adapter.test-harness.js';

const ctx = createListingTestContext();

afterEach(() => {
  ctx.reset();
});

async function listWithHeaders(
  headers: Record<string, string | string[] | undefined>,
  body: Buffer = MINIMAL_PAGE,
): Promise<Awaited<ReturnType<ReturnType<typeof ctx.adapter>['listPage']>>> {
  ctx.setResponses([{ statusCode: 200, headers, body }]);
  return ctx.adapter().listPage(validListingRequest());
}

describe('OSV GCS listing adversarial HTTP status', () => {
  const cases: Array<{ status: number | undefined; kind: string }> = [
    { status: 100, kind: 'malformed_response' },
    { status: 101, kind: 'malformed_response' },
    { status: 102, kind: 'malformed_response' },
    { status: 103, kind: 'malformed_response' },
    { status: 201, kind: 'malformed_response' },
    { status: 202, kind: 'malformed_response' },
    { status: 204, kind: 'malformed_response' },
    { status: 206, kind: 'malformed_response' },
    { status: 299, kind: 'malformed_response' },
    { status: 300, kind: 'redirect_rejected' },
    { status: 301, kind: 'redirect_rejected' },
    { status: 302, kind: 'redirect_rejected' },
    { status: 303, kind: 'redirect_rejected' },
    { status: 304, kind: 'redirect_rejected' },
    { status: 305, kind: 'redirect_rejected' },
    { status: 307, kind: 'redirect_rejected' },
    { status: 308, kind: 'redirect_rejected' },
    { status: 399, kind: 'redirect_rejected' },
    { status: 400, kind: 'malformed_response' },
    { status: 401, kind: 'authentication_required' },
    { status: 403, kind: 'authorization_rejected' },
    { status: 404, kind: 'object_not_found' },
    { status: 408, kind: 'http_408' },
    { status: 409, kind: 'malformed_response' },
    { status: 412, kind: 'malformed_response' },
    { status: 416, kind: 'malformed_response' },
    { status: 418, kind: 'malformed_response' },
    { status: 429, kind: 'http_429' },
    { status: 499, kind: 'malformed_response' },
    { status: 500, kind: 'http_500' },
    { status: 501, kind: 'malformed_response' },
    { status: 502, kind: 'http_502' },
    { status: 503, kind: 'http_503' },
    { status: 504, kind: 'http_504' },
    { status: 505, kind: 'malformed_response' },
    { status: 599, kind: 'malformed_response' },
    { status: undefined, kind: 'malformed_response' },
    { status: -1, kind: 'malformed_response' },
    { status: 600, kind: 'malformed_response' },
  ];

  it.each(cases)(
    'classifies HTTP $status as $kind without a second request',
    async ({ status, kind }) => {
      ctx.setResponses([
        {
          ...(status === undefined ? {} : { statusCode: status }),
          headers: {
            location: `https://evil.example/${SECRET_TOKEN}`,
            'content-type': 'text/html',
          },
          body: Buffer.from('provider error prose'),
        },
      ]);
      const result = await ctx.adapter().listPage(continuationRequest());
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.failure.kind).toBe(kind);
        expect(result.failure.publicCode).toBe(kind === 'http_503' ? 'service_unavailable' : kind);
        assertConfidential(result.failure, [SECRET_TOKEN, 'provider error prose', 'evil.example']);
      }
      expect(ctx.recordedOptions).toHaveLength(1);
    },
  );
});

describe('OSV GCS listing adversarial redirects', () => {
  const locations = [
    undefined,
    'https://storage.googleapis.com/storage/v1/b/osv-vulnerabilities/o',
    'https://evil.example/next',
    'http://storage.googleapis.com/storage/v1/b/osv-vulnerabilities/o',
    'http://127.0.0.1/',
    'http://192.168.0.1/',
    'https://user:pass@evil.example/',
    '/relative',
    '::::',
    ['https://a.example', 'https://b.example'],
    'https://a.example, https://b.example',
    `https://evil.example/?t=${SECRET_TOKEN}`,
    `https://evil.example/${'a'.repeat(4000)}`,
  ];

  it.each([301, 302, 303, 305, 307, 308])(
    'rejects HTTP %s without following Location',
    async (status) => {
      for (const location of locations) {
        ctx.setResponses([
          {
            statusCode: status,
            headers: location === undefined ? {} : { location },
            body: Buffer.from('ignored'),
          },
        ]);
        const result = await ctx.adapter().listPage(continuationRequest());
        expect(result.ok).toBe(false);
        if (!result.ok) {
          expect(result.failure.kind).toBe('redirect_rejected');
          assertConfidential(result.failure, [SECRET_TOKEN, 'evil.example', '127.0.0.1']);
        }
        expect(ctx.recordedOptions).toHaveLength(1);
        ctx.recordedOptions.length = 0;
      }
    },
  );

  it('rejects Location on HTTP 200 including array and empty values', async () => {
    const values: Array<string | string[]> = [
      'https://evil.example/',
      '',
      ['https://evil.example/'],
      ['https://a.example', 'https://b.example'],
      [],
    ];
    for (const location of values) {
      const result = await listWithHeaders({
        'content-type': 'application/json',
        'content-length': String(MINIMAL_PAGE.byteLength),
        location,
      });
      expect(result.ok, JSON.stringify(location)).toBe(false);
      if (!result.ok) {
        expect(result.failure.kind).toBe('malformed_response');
        assertConfidential(result.failure, ['evil.example']);
      }
      expect(ctx.recordedOptions).toHaveLength(1);
      ctx.recordedOptions.length = 0;
    }
  });
});

describe('OSV GCS listing adversarial response headers', () => {
  it('rejects ambiguous or disallowed Content-Type values', async () => {
    const types: Array<string | string[] | undefined> = [
      undefined,
      '',
      '   ',
      'text/json',
      'text/plain',
      'text/html',
      'application/octet-stream',
      'application/zip',
      'multipart/form-data',
      'application/vnd.api+json',
      'application/javascript',
      'application/json; charset=utf-16',
      'application/json; charset=utf-8; charset=utf-8',
      'application/json; foo=bar',
      'application/json, application/json',
      ['application/json', 'application/json'],
      'application/json; charset="utf-8',
    ];
    for (const contentType of types) {
      const result = await listWithHeaders({
        'content-type': contentType,
        'content-length': String(MINIMAL_PAGE.byteLength),
      });
      expect(result.ok, JSON.stringify(contentType)).toBe(false);
      if (!result.ok) {
        expect(result.failure.kind).toBe('invalid_content_type');
      }
      ctx.recordedOptions.length = 0;
    }
  });

  it('accepts only the committed JSON media-type grammar', async () => {
    const accepted = [
      'application/json',
      'APPLICATION/JSON',
      'application/Json',
      'application/json; charset=utf-8',
      'application/json;charset=utf-8',
      'application/json; charset=UTF-8',
    ];
    for (const contentType of accepted) {
      const result = await listWithHeaders({
        'content-type': contentType,
        'content-length': String(MINIMAL_PAGE.byteLength),
      });
      expect(result.ok, contentType).toBe(true);
      ctx.recordedOptions.length = 0;
    }
  });

  it('rejects compressed, stacked, empty, and duplicate Content-Encoding', async () => {
    const encodings: Array<string | string[]> = [
      'gzip',
      'br',
      'deflate',
      'compress',
      'gzip, identity',
      'identity, gzip',
      ['identity', 'gzip'],
      ['identity', 'identity'],
      'identity, identity',
      '',
      '   ',
      'identity\u0000',
    ];
    for (const encoding of encodings) {
      const result = await listWithHeaders({
        'content-type': 'application/json',
        'content-encoding': encoding,
        'content-length': String(MINIMAL_PAGE.byteLength),
      });
      expect(result.ok, JSON.stringify(encoding)).toBe(false);
      if (!result.ok) {
        expect(result.failure.kind).toBe('invalid_content_encoding');
      }
      ctx.recordedOptions.length = 0;
    }
  });

  it('rejects malformed, leading-zero, duplicate, and oversize Content-Length before body read', async () => {
    let consumed = false;
    const unread = new Readable({
      read() {
        consumed = true;
        this.push(MINIMAL_PAGE);
        this.push(null);
      },
    });
    ctx.setResponses([
      {
        statusCode: 200,
        headers: {
          'content-type': 'application/json',
          'content-length': String(OSV_GCS_LISTING_PAGE_MAX_BYTES + 1),
        },
        body: unread,
      },
    ]);
    const oversize = await ctx.adapter().listPage(validListingRequest());
    expect(oversize.ok).toBe(false);
    if (!oversize.ok) {
      expect(oversize.failure.kind).toBe('response_too_large');
    }
    expect(consumed).toBe(false);

    const invalid: Array<string | string[]> = [
      '-1',
      '+12',
      '012',
      '1e3',
      '12.0',
      '0x10',
      '',
      '12 13',
      ['12', '12'],
      ['12', '13'],
      '12,12',
      '9007199254740993',
      `${'9'.repeat(40)}`,
      '0',
    ];
    for (const length of invalid) {
      const result = await listWithHeaders({
        'content-type': 'application/json',
        'content-length': length,
      });
      expect(result.ok, String(length)).toBe(false);
      ctx.recordedOptions.length = 0;
    }
  });

  it('fails closed on Transfer-Encoding gzip and Content-Length plus Transfer-Encoding', async () => {
    const gzip = await listWithHeaders({
      'content-type': 'application/json',
      'transfer-encoding': 'gzip',
    });
    expect(gzip.ok).toBe(false);
    if (!gzip.ok) {
      expect(gzip.failure.kind).toBe('invalid_content_encoding');
    }
    ctx.recordedOptions.length = 0;
    const both = await listWithHeaders({
      'content-type': 'application/json',
      'content-length': String(MINIMAL_PAGE.byteLength),
      'transfer-encoding': 'chunked',
    });
    expect(both.ok).toBe(false);
    if (!both.ok) {
      expect(both.failure.kind).toBe('malformed_response');
    }
  });
});

describe('OSV GCS listing adversarial response size and UTF-8', () => {
  it('fails on the first overflow byte across chunk shapes', async () => {
    const shapes: Array<Buffer | Buffer[]> = [
      Buffer.alloc(OSV_GCS_LISTING_PAGE_MAX_BYTES + 1, 0x61),
      [Buffer.alloc(OSV_GCS_LISTING_PAGE_MAX_BYTES, 0x61), Buffer.from('x')],
      [Buffer.from('a'), Buffer.alloc(OSV_GCS_LISTING_PAGE_MAX_BYTES, 0x61)],
    ];
    for (const body of shapes) {
      let parseCount = 0;
      ctx.setResponses([
        {
          statusCode: 200,
          headers: { 'content-type': 'application/json' },
          body,
        },
      ]);
      const result = await ctx
        .adapter({
          parseListingPage: (input) => {
            parseCount += 1;
            return parseOsvGcsListingPage(input);
          },
        })
        .listPage(validListingRequest());
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.failure.kind).toBe('response_too_large');
      }
      expect(parseCount).toBe(0);
      ctx.recordedOptions.length = 0;
    }
  });

  it('rejects unexpected string chunks without invoking the parser', async () => {
    let parseCount = 0;
    ctx.setResponses([
      {
        statusCode: 200,
        headers: jsonHeaders(MINIMAL_PAGE),
        objectModeChunk: MINIMAL_PAGE.toString('utf8'),
      },
    ]);
    const result = await ctx
      .adapter({
        parseListingPage: (input) => {
          parseCount += 1;
          return parseOsvGcsListingPage(input);
        },
      })
      .listPage(validListingRequest());
    expect(result.ok).toBe(false);
    expect(parseCount).toBe(0);
  });

  it('rejects invalid UTF-8 sequences before the listing parser', async () => {
    const sequences = [
      Buffer.from([0x80]),
      Buffer.from([0xc3]),
      Buffer.from([0xe0, 0x80]),
      Buffer.from([0xf0, 0x80, 0x80]),
      Buffer.from([0xc0, 0x80]),
      Buffer.from([0xed, 0xa0, 0x80]),
      Buffer.from([0xff, 0xfe]),
      Buffer.from([0xf5, 0x80, 0x80, 0x80]),
    ];
    for (const body of sequences) {
      let parseCount = 0;
      ctx.setResponses([
        {
          statusCode: 200,
          headers: {
            'content-type': 'application/json',
            'content-length': String(body.byteLength),
          },
          body,
        },
      ]);
      const result = await ctx
        .adapter({
          parseListingPage: (input) => {
            parseCount += 1;
            return parseOsvGcsListingPage(input);
          },
        })
        .listPage(continuationRequest());
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.failure.kind).toBe('malformed_response');
        assertConfidential(result.failure);
      }
      expect(parseCount).toBe(0);
      ctx.recordedOptions.length = 0;
    }
  });
});

describe('OSV GCS listing adversarial parser handoff', () => {
  it('invokes the listing parser exactly once after transport success and never the advisory parser', async () => {
    let parseCount = 0;
    ctx.remainingResponses.push({
      statusCode: 200,
      headers: jsonHeaders(MINIMAL_PAGE),
      body: MINIMAL_PAGE,
    });
    const result = await ctx
      .adapter({
        parseListingPage: (input) => {
          parseCount += 1;
          return parseOsvGcsListingPage(input);
        },
      })
      .listPage(validListingRequest());
    expect(result.ok).toBe(true);
    expect(parseCount).toBe(1);
  });

  it('returns bounded parser failures for malformed pages and does not paginate', async () => {
    const page = listingJson({ nextPageToken: SECRET_TOKEN });
    ctx.remainingResponses.push({
      statusCode: 200,
      headers: jsonHeaders(page),
      body: page,
    });
    const continued = await ctx.adapter().listPage(validListingRequest());
    expect(continued.ok).toBe(true);
    if (continued.ok) {
      expect(continued.page.complete).toBe(false);
      expect(JSON.stringify(continued.page)).not.toContain(SECRET_TOKEN);
    }
    expect(ctx.recordedOptions).toHaveLength(1);

    const items = Array.from(
      { length: OSV_GCS_JSON_OBJECTS_LIST_MAX_RESULTS + 1 },
      (_value, index) => ({
        name: `npm/GHSA-aaaa-bbbb-${String(index).padStart(4, '0')}.json`,
        generation: '1',
        size: '1',
        contentType: 'application/json',
      }),
    );
    const overflow = listingJson({ items });
    ctx.remainingResponses.push({
      statusCode: 200,
      headers: jsonHeaders(overflow),
      body: overflow,
    });
    const limited = await ctx.adapter().listPage(validListingRequest());
    expect(limited.ok).toBe(false);
    expect(ctx.recordedOptions).toHaveLength(2);
  });
});
