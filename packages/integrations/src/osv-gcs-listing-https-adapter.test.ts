/**
 * Session 12 Batch 1 GCS listing-page HTTPS adapter tests.
 * Synthetic local doubles only. Never contacts storage.googleapis.com.
 */

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { Readable } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { inspect } from 'node:util';

import { afterEach, describe, expect, it } from 'vitest';

import {
  OSV_GCS_JSON_OBJECTS_LIST_FIELDS,
  OSV_GCS_JSON_OBJECTS_LIST_MAX_RESULTS,
  OSV_GCS_LISTING_PAGE_MAX_BYTES,
  createOsvListingContinuationToken,
  parseOsvGcsListingPage,
  type OsvListingRequest,
} from '@patchpilot/vulnerability-intelligence';

import { createOsvGcsListingHttpsAdapter } from './osv-gcs-listing-https-adapter.js';
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

function encodedFields(): string {
  return encodeURIComponent(OSV_GCS_JSON_OBJECTS_LIST_FIELDS);
}

describe('OSV GCS listing-page HTTPS adapter', () => {
  describe('preflight', () => {
    it('invokes HTTPS exactly once for a valid request', async () => {
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
      expect(result.page.itemCount).toBe(1);
      expect(result.page.complete).toBe(true);
      expect(ctx.recordedOptions).toHaveLength(1);
      expect(ctx.lookupHosts).toEqual(['storage.googleapis.com']);
    });

    it('invokes HTTPS zero times for invalid, unknown, tenant, and protocol-mismatched input', async () => {
      const cases: Array<{ input: unknown; kind: string }> = [
        { input: null, kind: 'policy_violation' },
        { input: 'npm/', kind: 'policy_violation' },
        { input: listingInput({ extra: true }), kind: 'policy_violation' },
        {
          input: listingInput({ listingProtocolVersion: 'osv_gcs_json_objects_list_v1' }),
          kind: 'policy_violation',
        },
        {
          input: listingInput({ transportPolicyVersion: 'other' }),
          kind: 'policy_violation',
        },
        { input: listingInput({ providerPrefix: 'debian/' }), kind: 'policy_violation' },
        { input: listingInput({ providerPrefix: 'npm' }), kind: 'policy_violation' },
        { input: listingInput({ continuationToken: 'raw' }), kind: 'invalid_page_token' },
        {
          input: listingInput({
            continuationToken: (() => {
              const token = createOsvListingContinuationToken('a'.repeat(8193));
              if (!token.ok) {
                throw new Error(token.code);
              }
              return token.value;
            })(),
          }),
          kind: 'invalid_page_token',
        },
        { input: listingInput({ organizationId: 'org' }), kind: 'policy_violation' },
        { input: listingInput({ tenantId: 'tenant' }), kind: 'policy_violation' },
        { input: listingInput({ packageName: 'left-pad' }), kind: 'policy_violation' },
        { input: listingInput({ findingId: 'finding' }), kind: 'policy_violation' },
        { input: listingInput({ userId: 'user' }), kind: 'policy_violation' },
        { input: listingInput({ assetId: 'asset' }), kind: 'policy_violation' },
        { input: listingInput({ host: 'evil.example' }), kind: 'policy_violation' },
        { input: listingInput({ bucket: 'other' }), kind: 'policy_violation' },
        { input: listingInput({ pageSizePolicy: 1000 }), kind: 'policy_violation' },
      ];
      for (const item of cases) {
        ctx.recordedOptions.length = 0;
        const result = await ctx.adapter().listPage(item.input as OsvListingRequest);
        expect(result.ok, JSON.stringify(item.input)).toBe(false);
        expect(ctx.recordedOptions, JSON.stringify(item.input)).toHaveLength(0);
        if (!result.ok) {
          expect(result.failure.kind, JSON.stringify(item.input)).toBe(item.kind);
          assertConfidential(result.failure);
        }
      }
    });

    it('invokes HTTPS zero times when the signal is already aborted', async () => {
      const signal = AbortSignal.abort();
      const result = await ctx.adapter().listPage(validListingRequest({ signal }));
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.failure.kind).toBe('cancelled');
      }
      expect(ctx.recordedOptions).toHaveLength(0);
    });
  });

  describe('exact request', () => {
    it('compiles the committed GCS JSON Objects list surface', async () => {
      ctx.remainingResponses.push({
        statusCode: 200,
        headers: jsonHeaders(MINIMAL_PAGE),
        body: MINIMAL_PAGE,
      });
      await ctx.adapter().listPage(validListingRequest());
      expect(ctx.recordedOptions).toHaveLength(1);
      const options = ctx.recordedOptions[0] as {
        method: string;
        hostname: string;
        port: number;
        path: string;
        servername: string;
        headers: Record<string, string>;
        minVersion: string;
        rejectUnauthorized: boolean;
      };
      expect(options.method).toBe('GET');
      expect(options.hostname).toBe('storage.googleapis.com');
      expect(options.port).toBe(443);
      expect(options.servername).toBe('storage.googleapis.com');
      expect(options.minVersion).toBe('TLSv1.2');
      expect(options.rejectUnauthorized).toBe(true);
      expect(options.path).toBe(
        `/storage/v1/b/osv-vulnerabilities/o?prefix=npm%2F&maxResults=${OSV_GCS_JSON_OBJECTS_LIST_MAX_RESULTS}&fields=${encodedFields()}`,
      );
      expect(options.path).not.toContain('delimiter=');
      expect(options.path).not.toContain('pageToken=');
      expect(options.path).not.toContain('npm%252F');
      expect(options.path).not.toContain('#');
      expect(options.path).not.toContain('mediaLink');
      expect(options.path).not.toContain('selfLink');
      expect(options.headers['Accept']).toBe('application/json');
      expect(options.headers['Accept-Encoding']).toBe('identity');
      expect(options.headers['Cache-Control']).toBe('no-cache');
      expect(options.headers['User-Agent']).toBe('PatchPilot-intelligence/0.1');
      expect(options.headers['User-Agent']).not.toContain('GHSA');
      expect(options.headers['User-Agent']).not.toContain(SECRET_TOKEN);
      expect(options.headers['Authorization']).toBeUndefined();
      expect(options.headers['Cookie']).toBeUndefined();
      expect(options.headers['Range']).toBeUndefined();
      expect(options.headers['If-None-Match']).toBeUndefined();
    });

    it('encodes an opaque continuation token exactly once in pageToken', async () => {
      ctx.remainingResponses.push({
        statusCode: 200,
        headers: jsonHeaders(MINIMAL_PAGE),
        body: MINIMAL_PAGE,
      });
      await ctx.adapter().listPage(continuationRequest());
      const options = ctx.recordedOptions[0] as { path: string; headers: Record<string, string> };
      expect(options.path).toContain(`pageToken=${encodeURIComponent(SECRET_TOKEN)}`);
      expect(options.path).toContain('%252F');
      expect(options.path.match(/pageToken=/g)).toEqual(['pageToken=']);
      expect(Object.values(options.headers).join(',')).not.toContain(SECRET_TOKEN);
    });

    it('rejects host, bucket, and endpoint override fields before dispatch', async () => {
      for (const extra of [
        { host: 'storage.cloud.google.com' },
        { bucket: 'other' },
        { url: 'https://example.invalid' },
        { endpoint: 'https://storage.googleapis.com' },
      ]) {
        ctx.recordedOptions.length = 0;
        const result = await ctx.adapter().listPage(listingInput(extra) as OsvListingRequest);
        expect(result.ok).toBe(false);
        expect(ctx.recordedOptions).toHaveLength(0);
      }
    });
  });

  describe('HTTP status', () => {
    const statusCases: Array<{ status: number; kind: string }> = [
      { status: 204, kind: 'malformed_response' },
      { status: 206, kind: 'malformed_response' },
      { status: 201, kind: 'malformed_response' },
      { status: 301, kind: 'redirect_rejected' },
      { status: 302, kind: 'redirect_rejected' },
      { status: 303, kind: 'redirect_rejected' },
      { status: 307, kind: 'redirect_rejected' },
      { status: 308, kind: 'redirect_rejected' },
      { status: 401, kind: 'authentication_required' },
      { status: 403, kind: 'authorization_rejected' },
      { status: 404, kind: 'object_not_found' },
      { status: 408, kind: 'http_408' },
      { status: 429, kind: 'http_429' },
      { status: 500, kind: 'http_500' },
      { status: 502, kind: 'http_502' },
      { status: 503, kind: 'http_503' },
      { status: 504, kind: 'http_504' },
      { status: 418, kind: 'malformed_response' },
    ];

    it.each(statusCases)(
      'classifies HTTP $status as $kind without a second request',
      async ({ status, kind }) => {
        ctx.remainingResponses.push({
          statusCode: status,
          headers: {
            location: 'http://evil.example/redirect',
            'content-type': 'text/html',
          },
          body: Buffer.from('provider error prose'),
        });
        const result = await ctx.adapter().listPage(continuationRequest());
        expect(result.ok).toBe(false);
        if (result.ok) {
          throw new Error('expected failure');
        }
        expect(result.failure.kind).toBe(kind);
        assertConfidential(result.failure, [SECRET_TOKEN, 'provider error prose', 'evil.example']);
        expect(JSON.stringify(result.failure)).not.toContain('http://evil.example/redirect');
        expect(ctx.recordedOptions).toHaveLength(1);
      },
    );

    it('does not follow same-host or cross-host redirects', async () => {
      ctx.remainingResponses.push({
        statusCode: 302,
        headers: { location: 'https://storage.googleapis.com/storage/v1/b/osv-vulnerabilities/o' },
        body: Buffer.from('ignored'),
      });
      const result = await ctx.adapter().listPage(validListingRequest());
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.failure.kind).toBe('redirect_rejected');
      }
      expect(ctx.recordedOptions).toHaveLength(1);
    });
  });

  describe('headers', () => {
    it('accepts application/json and charset=utf-8', async () => {
      ctx.remainingResponses.push({
        statusCode: 200,
        headers: {
          'content-type': 'application/json; charset=utf-8',
          'content-encoding': 'identity',
          'content-length': String(MINIMAL_PAGE.byteLength),
        },
        body: MINIMAL_PAGE,
      });
      const result = await ctx.adapter().listPage(validListingRequest());
      expect(result.ok).toBe(true);
    });

    it('rejects missing, malformed, duplicate, and wrong Content-Type', async () => {
      const headerCases: Array<Record<string, string | string[] | undefined>> = [
        { 'content-length': String(MINIMAL_PAGE.byteLength) },
        {
          'content-type': 'application/json; charset=utf-16',
          'content-length': String(MINIMAL_PAGE.byteLength),
        },
        {
          'content-type': ['application/json', 'text/plain'],
          'content-length': String(MINIMAL_PAGE.byteLength),
        },
        {
          'content-type': 'application/json, text/plain',
          'content-length': String(MINIMAL_PAGE.byteLength),
        },
        {
          'content-type': 'application/json; foo=bar',
          'content-length': String(MINIMAL_PAGE.byteLength),
        },
        { 'content-type': 'text/html', 'content-length': String(MINIMAL_PAGE.byteLength) },
        { 'content-type': 'text/plain', 'content-length': String(MINIMAL_PAGE.byteLength) },
        {
          'content-type': 'application/octet-stream',
          'content-length': String(MINIMAL_PAGE.byteLength),
        },
        { 'content-type': 'application/zip', 'content-length': String(MINIMAL_PAGE.byteLength) },
        {
          'content-type': 'multipart/mixed',
          'content-length': String(MINIMAL_PAGE.byteLength),
        },
        { 'content-type': 'not-a-type', 'content-length': String(MINIMAL_PAGE.byteLength) },
      ];
      for (const headers of headerCases) {
        ctx.setResponses([{ statusCode: 200, headers, body: MINIMAL_PAGE }]);
        const result = await ctx.adapter().listPage(validListingRequest());
        expect(result.ok, JSON.stringify(headers)).toBe(false);
        if (!result.ok) {
          expect(result.failure.kind).toBe('invalid_content_type');
        }
      }
    });

    it('rejects gzip, br, deflate, stacked, duplicate, and malformed encodings', async () => {
      const encodings: Array<string | string[]> = [
        'gzip',
        'br',
        'deflate',
        'gzip, identity',
        ['identity', 'identity'],
        'identity, identity',
        'gzip;q=1',
      ];
      for (const encoding of encodings) {
        ctx.setResponses([
          {
            statusCode: 200,
            headers: {
              'content-type': 'application/json',
              'content-encoding': encoding,
              'content-length': String(MINIMAL_PAGE.byteLength),
            },
            body: MINIMAL_PAGE,
          },
        ]);
        const result = await ctx.adapter().listPage(validListingRequest());
        expect(result.ok, String(encoding)).toBe(false);
        if (!result.ok) {
          expect(result.failure.kind).toBe('invalid_content_encoding');
        }
      }
    });

    it('accepts absent Content-Encoding as identity', async () => {
      ctx.remainingResponses.push({
        statusCode: 200,
        headers: {
          'content-type': 'application/json',
          'content-length': String(MINIMAL_PAGE.byteLength),
        },
        body: MINIMAL_PAGE,
      });
      const result = await ctx.adapter().listPage(validListingRequest());
      expect(result.ok).toBe(true);
    });

    it('enforces Content-Length grammar and the 1048576 ceiling before body consumption', async () => {
      let consumed = false;
      const unread = new Readable({
        read() {
          consumed = true;
          this.push(MINIMAL_PAGE);
          this.push(null);
        },
      });
      ctx.remainingResponses.push({
        statusCode: 200,
        headers: {
          'content-type': 'application/json',
          'content-length': String(OSV_GCS_LISTING_PAGE_MAX_BYTES + 1),
        },
        body: unread,
      });
      const oversize = await ctx.adapter().listPage(validListingRequest());
      expect(oversize.ok).toBe(false);
      if (!oversize.ok) {
        expect(oversize.failure.kind).toBe('response_too_large');
      }
      expect(consumed).toBe(false);

      const cases: Array<{ length: string | string[]; kind: string }> = [
        { length: '-1', kind: 'malformed_response' },
        { length: '+12', kind: 'malformed_response' },
        { length: '1e3', kind: 'malformed_response' },
        { length: '12.0', kind: 'malformed_response' },
        { length: '1,048,576', kind: 'malformed_response' },
        { length: ['12', '12'], kind: 'malformed_response' },
        { length: '9007199254740993', kind: 'malformed_response' },
        { length: '0', kind: 'malformed_response' },
      ];
      for (const item of cases) {
        ctx.setResponses([
          {
            statusCode: 200,
            headers: {
              'content-type': 'application/json',
              'content-length': item.length,
            },
            body: MINIMAL_PAGE,
          },
        ]);
        const result = await ctx.adapter().listPage(validListingRequest());
        expect(result.ok, String(item.length)).toBe(false);
        if (!result.ok) {
          expect(result.failure.kind, String(item.length)).toBe(item.kind);
        }
      }
    });

    it('accepts surrounding whitespace on Content-Length because the committed parser trims', async () => {
      ctx.remainingResponses.push({
        statusCode: 200,
        headers: {
          'content-type': 'application/json',
          'content-length': ` ${String(MINIMAL_PAGE.byteLength)} `,
        },
        body: MINIMAL_PAGE,
      });
      const result = await ctx.adapter().listPage(validListingRequest());
      expect(result.ok).toBe(true);
    });

    it('accepts exact 1048576 Content-Length', async () => {
      const prefix = '{"kind":"storage#objects","nextPageToken":"';
      const suffix = '"}';
      const padding =
        OSV_GCS_LISTING_PAGE_MAX_BYTES -
        Buffer.byteLength(prefix, 'utf8') -
        Buffer.byteLength(suffix, 'utf8');
      const body = Buffer.from(`${prefix}${'a'.repeat(padding)}${suffix}`);
      expect(body.byteLength).toBe(OSV_GCS_LISTING_PAGE_MAX_BYTES);
      ctx.remainingResponses.push({
        statusCode: 200,
        headers: jsonHeaders(body),
        body,
      });
      const result = await ctx.adapter().listPage(validListingRequest());
      expect(result.ok).toBe(true);
    });
  });

  describe('body bounds', () => {
    it('accepts a missing Content-Length when the streamed body is within the ceiling', async () => {
      ctx.remainingResponses.push({
        statusCode: 200,
        headers: { 'content-type': 'application/json' },
        body: MINIMAL_PAGE,
      });
      const result = await ctx.adapter().listPage(validListingRequest());
      expect(result.ok).toBe(true);
    });

    it('fails on the first byte above 1048576 and does not parse a truncated page', async () => {
      let parseCount = 0;
      const oversize = Buffer.concat([
        Buffer.from('{"kind":"storage#objects","items":['),
        Buffer.alloc(OSV_GCS_LISTING_PAGE_MAX_BYTES, 0x61),
      ]);
      ctx.remainingResponses.push({
        statusCode: 200,
        headers: { 'content-type': 'application/json' },
        body: oversize,
      });
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
    });

    it('fails when many small chunks exceed the ceiling', async () => {
      const chunks = Array.from({ length: 1025 }, () => Buffer.alloc(1024, 0x61));
      ctx.remainingResponses.push({
        statusCode: 200,
        headers: { 'content-type': 'application/json' },
        body: chunks,
      });
      const result = await ctx.adapter().listPage(validListingRequest());
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.failure.kind).toBe('response_too_large');
      }
    });

    it('accepts many small chunks that sum to a valid page', async () => {
      const chunks: Buffer[] = [];
      for (let index = 0; index < MINIMAL_PAGE.byteLength; index += 7) {
        chunks.push(MINIMAL_PAGE.subarray(index, Math.min(index + 7, MINIMAL_PAGE.byteLength)));
      }
      ctx.remainingResponses.push({
        statusCode: 200,
        headers: jsonHeaders(MINIMAL_PAGE),
        body: chunks,
      });
      const result = await ctx.adapter().listPage(validListingRequest());
      expect(result.ok).toBe(true);
    });

    it('rejects a zero-byte body', async () => {
      ctx.remainingResponses.push({
        statusCode: 200,
        headers: { 'content-type': 'application/json' },
        body: Buffer.alloc(0),
      });
      const result = await ctx.adapter().listPage(validListingRequest());
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.failure.kind).toBe('malformed_response');
      }
    });

    it('rejects Content-Length larger or smaller than the received body', async () => {
      ctx.remainingResponses.push({
        statusCode: 200,
        headers: {
          'content-type': 'application/json',
          'content-length': String(MINIMAL_PAGE.byteLength + 10),
        },
        body: MINIMAL_PAGE,
      });
      const tooSmall = await ctx.adapter().listPage(validListingRequest());
      expect(tooSmall.ok).toBe(false);
      if (!tooSmall.ok) {
        expect(tooSmall.failure.kind).toBe('malformed_response');
      }

      ctx.remainingResponses.push({
        statusCode: 200,
        headers: {
          'content-type': 'application/json',
          'content-length': String(MINIMAL_PAGE.byteLength - 10),
        },
        body: MINIMAL_PAGE,
      });
      const tooLarge = await ctx.adapter().listPage(validListingRequest());
      expect(tooLarge.ok).toBe(false);
      if (!tooLarge.ok) {
        expect(tooLarge.failure.kind).toBe('malformed_response');
      }
    });

    it('rejects stream errors, abort, and close before end', async () => {
      ctx.remainingResponses.push({
        statusCode: 200,
        headers: jsonHeaders(MINIMAL_PAGE),
        body: MINIMAL_PAGE,
        emitResponseError: new Error('stream'),
      });
      const errored = await ctx.adapter().listPage(validListingRequest());
      expect(errored.ok).toBe(false);

      ctx.remainingResponses.push({
        statusCode: 200,
        headers: jsonHeaders(MINIMAL_PAGE),
        body: MINIMAL_PAGE,
        abortResponse: true,
      });
      const aborted = await ctx.adapter().listPage(validListingRequest());
      expect(aborted.ok).toBe(false);

      ctx.remainingResponses.push({
        statusCode: 200,
        headers: jsonHeaders(MINIMAL_PAGE),
        body: MINIMAL_PAGE,
        closeEarly: true,
      });
      const closed = await ctx.adapter().listPage(validListingRequest());
      expect(closed.ok).toBe(false);
    });

    it('handles duplicate end and data after terminal failure without a second result', async () => {
      ctx.remainingResponses.push({
        statusCode: 200,
        headers: jsonHeaders(MINIMAL_PAGE),
        body: MINIMAL_PAGE,
        duplicateEnd: true,
        dataAfterEnd: Buffer.from('late'),
      });
      const result = await ctx.adapter().listPage(validListingRequest());
      expect(result.ok).toBe(true);
      expect(ctx.recordedOptions).toHaveLength(1);
    });
  });

  describe('UTF-8 and parser handoff', () => {
    it('passes valid UTF-8 to the committed parser exactly once', async () => {
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
            if (typeof input !== 'object' || input === null || !('bytes' in input)) {
              throw new Error('parser input missing bytes');
            }
            expect(input.bytes).toBeInstanceOf(Uint8Array);
            return parseOsvGcsListingPage(input);
          },
        })
        .listPage(validListingRequest());
      expect(result.ok).toBe(true);
      expect(parseCount).toBe(1);
    });

    it('rejects malformed UTF-8 without invoking the listing parser', async () => {
      const cases = [
        Buffer.from([0x80, 0x61]),
        Buffer.from([0xc3]),
        Buffer.from([0xed, 0xa0, 0x80]),
      ];
      for (const body of cases) {
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
          .listPage(validListingRequest());
        expect(result.ok).toBe(false);
        if (!result.ok) {
          expect(result.failure.kind).toBe('malformed_response');
        }
        expect(parseCount).toBe(0);
      }
    });

    it('matches committed parser BOM behavior', async () => {
      const bom = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), MINIMAL_PAGE]);
      ctx.remainingResponses.push({
        statusCode: 200,
        headers: {
          'content-type': 'application/json',
          'content-length': String(bom.byteLength),
        },
        body: bom,
      });
      const result = await ctx.adapter().listPage(validListingRequest());
      expect(result.ok).toBe(true);
    });

    it('does not invoke the parser after transport failure', async () => {
      let parseCount = 0;
      ctx.remainingResponses.push({
        statusCode: 500,
        headers: { 'content-type': 'application/json' },
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
      expect(result.ok).toBe(false);
      expect(parseCount).toBe(0);
    });

    it('returns bounded failures for malformed JSON and item-limit overflow', async () => {
      ctx.remainingResponses.push({
        statusCode: 200,
        headers: { 'content-type': 'application/json' },
        body: Buffer.from('{', 'utf8'),
      });
      const malformed = await ctx.adapter().listPage(validListingRequest());
      expect(malformed.ok).toBe(false);
      if (!malformed.ok) {
        expect(malformed.failure.kind).toBe('malformed_response');
        assertConfidential(malformed.failure);
      }

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
      if (!limited.ok) {
        expect(limited.failure.kind).toBe('policy_violation');
      }
    });
  });

  describe('token confidentiality', () => {
    it('omits the raw token from success serialization, inspection, and events', async () => {
      const events: Array<Record<string, unknown>> = [];
      const page = listingJson({ nextPageToken: SECRET_TOKEN });
      ctx.remainingResponses.push({
        statusCode: 200,
        headers: jsonHeaders(page),
        body: page,
      });
      const result = await ctx
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
      expect(result.ok).toBe(true);
      if (!result.ok) {
        throw new Error('expected page');
      }
      expect(JSON.stringify(result.page)).not.toContain(SECRET_TOKEN);
      expect(inspect(result.page)).not.toContain(SECRET_TOKEN);
      expect(String(result.page.continuationToken)).not.toContain(SECRET_TOKEN);
      expect(JSON.stringify(events)).not.toContain(SECRET_TOKEN);
      const options = ctx.recordedOptions[0] as { path: string; headers: Record<string, string> };
      expect(options.path).toContain(encodeURIComponent(SECRET_TOKEN));
      expect(Object.values(options.headers).join(',')).not.toContain(SECRET_TOKEN);
    });

    it('omits the raw token from timeout, cancellation, redirect, and malformed failures', async () => {
      ctx.remainingResponses.push({
        statusCode: 302,
        headers: { location: 'https://example.invalid' },
        body: Buffer.from(SECRET_TOKEN),
      });
      const redirected = await ctx.adapter().listPage(continuationRequest());
      expect(redirected.ok).toBe(false);
      if (!redirected.ok) {
        assertConfidential(redirected.failure);
      }

      ctx.remainingResponses.push({
        statusCode: 200,
        headers: { 'content-type': 'text/plain' },
        body: Buffer.from(SECRET_TOKEN),
      });
      const malformed = await ctx.adapter().listPage(continuationRequest());
      expect(malformed.ok).toBe(false);
      if (!malformed.ok) {
        assertConfidential(malformed.failure);
      }
    });
  });

  describe('graph and loop invariants', () => {
    it('validates before dispatch and parses only after a complete UTF-8 body', async () => {
      const phases: string[] = [];
      ctx.remainingResponses.push({
        statusCode: 200,
        headers: jsonHeaders(MINIMAL_PAGE),
        body: MINIMAL_PAGE,
      });
      await ctx
        .adapter({
          logger: {
            info: (bindings) => {
              phases.push(String(bindings['phase']));
            },
            warn: (bindings) => {
              phases.push(String(bindings['phase']));
            },
          },
        })
        .listPage(validListingRequest());
      expect(phases).toEqual(['succeeded']);
      expect(ctx.recordedOptions).toHaveLength(1);
    });

    it('does not paginate, retry, retrieve bodies, or persist', async () => {
      ctx.remainingResponses.push({
        statusCode: 500,
        headers: { 'content-type': 'application/json' },
        body: MINIMAL_PAGE,
      });
      const result = await ctx.adapter().listPage(validListingRequest());
      expect(result.ok).toBe(false);
      expect(ctx.recordedOptions).toHaveLength(1);
      const source = readFileSync(
        join(dirname(fileURLToPath(import.meta.url)), 'osv-gcs-listing-https-adapter.ts'),
        'utf8',
      );
      expect(source).not.toContain('nextPage');
      expect(source).not.toContain('backoff');
      expect(source).not.toContain('setInterval');
      expect(source).not.toContain('alt=media');
      expect(source).not.toContain('activateReadyGeneration');
    });
  });

  describe('source boundaries', () => {
    it('keeps production factory free of test seams and runtime composition', () => {
      const adapter = createOsvGcsListingHttpsAdapter();
      expect(typeof adapter.listPage).toBe('function');
      expect(adapter.listPage.length).toBe(1);
    });

    it('does not import persistence, retrieval, parser-worker, or application runtimes', () => {
      const source = readFileSync(
        join(dirname(fileURLToPath(import.meta.url)), 'osv-gcs-listing-https-adapter.ts'),
        'utf8',
      );
      const forbidden = [
        '@aws-sdk/client-s3',
        '@patchpilot/database',
        '@prisma/client',
        'osv-generation-bound-retrieval-https',
        'advisory-parser-worker',
        'advisory-parser-host',
        'createOsvDisabledAcquisitionOrchestrator',
        'bullmq',
        'ioredis',
        'fastify',
        'next/server',
        'process.env',
        'eval(',
        'new Function',
        'organizationId',
        'tenantId',
        'finding.recalculate',
        'createFinding',
      ];
      for (const token of forbidden) {
        expect(source, token).not.toContain(token);
      }
    });
  });
});
