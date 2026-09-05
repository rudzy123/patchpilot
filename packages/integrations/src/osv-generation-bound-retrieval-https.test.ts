/**
 * Session 11 Batch 6A generation-bound OSV retrieval HTTPS adapter tests.
 * Local scripted responses only. Never contacts storage.googleapis.com.
 */

import { createHash } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { inspect } from 'node:util';
import { Readable } from 'node:stream';

import { afterEach, describe, expect, it } from 'vitest';

import { OSV_ELIGIBLE_BODY_SCOPE_IDENTIFIER } from '@patchpilot/vulnerability-intelligence';
import {
  OSV_GENERATION_BOUND_RETRIEVAL_POLICY_IDENTIFIER,
  OSV_INVENTORY_SCOPE_IDENTIFIER,
  OSV_PROVIDER_IDENTIFIER,
  OSV_PROVIDER_OBJECT_RETRIEVAL_MAX_BYTES,
  OSV_SOURCE_LICENSE_REGISTRY_IDENTIFIER,
  OSV_TRANSPORT_POLICY_VERSION,
  copyOsvGenerationBoundRetrievedBytes,
  isOsvGenerationBoundValidatedRetrieval,
} from '@patchpilot/vulnerability-intelligence';

import {
  createOsvGenerationBoundRetrievalHttpsAdapter,
  type OsvRetrievalDnsLookup,
  type OsvRetrievalHttpsRequest,
} from './osv-generation-bound-retrieval-https.js';

const PUBLIC_V4 = '1.1.1.1';
const ELIGIBLE_KEY = 'npm/GHSA-abcd-1234-wxyz.json';
const GENERATION = '1234567890';
const BODY = Buffer.from('{"id":"SYNTH-OSV-1","modified":"2026-01-01T00:00:00Z"}');
const BODY_SHA = createHash('sha256').update(BODY).digest('hex');

type ScriptedResponse = {
  statusCode: number;
  headers?: Record<string, string | string[] | undefined>;
  body?: Buffer | Readable;
  delayMs?: number;
  omitResponse?: boolean;
  remoteAddress?: string;
  remoteFamily?: string;
  closeEarly?: boolean;
  omitSecureConnect?: boolean;
  emitError?: Error;
};

const recordedOptions: unknown[] = [];
const lookupHosts: string[] = [];
let remainingResponses: ScriptedResponse[] = [];
let lookupImpl: OsvRetrievalDnsLookup = (_hostname, _options, callback) => {
  callback(null, [{ address: PUBLIC_V4, family: 4 }]);
};

afterEach(() => {
  recordedOptions.length = 0;
  lookupHosts.length = 0;
  remainingResponses = [];
  lookupImpl = (_hostname, _options, callback) => {
    callback(null, [{ address: PUBLIC_V4, family: 4 }]);
  };
});

const lookup: OsvRetrievalDnsLookup = (hostname, options, callback) => {
  lookupHosts.push(hostname);
  lookupImpl(hostname, options, callback);
};

const request: OsvRetrievalHttpsRequest = (options, callback) => {
  recordedOptions.push(options);
  const req = new EventEmitter() as ReturnType<OsvRetrievalHttpsRequest>;
  let destroyed = false;
  (req as { destroy: () => void }).destroy = () => {
    destroyed = true;
  };
  (req as { end: () => void }).end = () => {
    const script = remainingResponses.shift() ?? {
      statusCode: 200,
      headers: {
        'content-type': 'application/json',
        'content-length': String(BODY.byteLength),
        'x-goog-generation': GENERATION,
      },
      body: BODY,
    };

    const emitSocket = (): void => {
      if (destroyed) {
        return;
      }
      const socket = new EventEmitter();
      Object.defineProperty(socket, 'remoteAddress', {
        value: script.remoteAddress ?? PUBLIC_V4,
      });
      Object.defineProperty(socket, 'remoteFamily', {
        value: script.remoteFamily ?? 'IPv4',
      });
      req.emit('socket', socket);
      if (script.omitSecureConnect !== true) {
        socket.emit('secureConnect');
      }
    };

    const emitResponse = (): void => {
      if (destroyed || callback === undefined) {
        return;
      }
      if (script.emitError !== undefined) {
        req.emit('error', script.emitError);
        return;
      }
      const payload = script.body ?? BODY;
      const response =
        payload instanceof Readable ? payload : Readable.from([payload], { objectMode: false });
      Object.assign(response, {
        statusCode: script.statusCode,
        headers: script.headers ?? {},
      });
      if (script.closeEarly === true) {
        callback(response as never);
        response.destroy();
        return;
      }
      callback(response as never);
    };

    const emit = (): void => {
      emitSocket();
      if (script.omitResponse === true) {
        return;
      }
      emitResponse();
    };

    if (script.delayMs !== undefined && script.delayMs > 0) {
      setTimeout(emit, script.delayMs);
      return;
    }
    queueMicrotask(emit);
  };
  return req;
};

function adapter() {
  return createOsvGenerationBoundRetrievalHttpsAdapter({ lookup, request });
}

function eligibleInput(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    objectKey: ELIGIBLE_KEY,
    generation: GENERATION,
    expectedDeclaredByteCount: BODY.byteLength,
    expectedContentType: 'application/json',
    registryIdentifier: OSV_SOURCE_LICENSE_REGISTRY_IDENTIFIER,
    eligibleBodyScopeIdentifier: OSV_ELIGIBLE_BODY_SCOPE_IDENTIFIER,
    retrievalPolicyIdentifier: OSV_GENERATION_BOUND_RETRIEVAL_POLICY_IDENTIFIER,
    inventoryScopeIdentifier: OSV_INVENTORY_SCOPE_IDENTIFIER,
    providerIdentifier: OSV_PROVIDER_IDENTIFIER,
    transportPolicyVersion: OSV_TRANSPORT_POLICY_VERSION,
    ...overrides,
  };
}

function assertConfidentialFailure(value: unknown): void {
  const text = `${JSON.stringify(value)}\n${inspect(value)}\n${String(value)}`;
  expect(text).not.toContain(ELIGIBLE_KEY);
  expect(text).not.toContain('storage.googleapis.com');
  expect(text).not.toContain('alt=media');
  expect(text).not.toContain('https://');
  expect(text).not.toContain(BODY.toString('utf8'));
  expect(text).not.toContain('Location');
  expect(text).not.toContain('organizationId');
  expect(text).not.toContain('tenantId');
  expect(text).not.toContain('findingId');
  expect(text).not.toContain('stack');
  expect(text).not.toContain('ECONNRESET');
}

describe('OSV generation-bound retrieval HTTPS adapter', () => {
  describe('preflight', () => {
    it('reaches HTTP exactly once for a valid eligible request', async () => {
      remainingResponses = [
        {
          statusCode: 200,
          headers: {
            'content-type': 'application/json',
            'content-length': String(BODY.byteLength),
            'x-goog-generation': GENERATION,
          },
          body: BODY,
        },
      ];
      const result = await adapter().retrieveGenerationBoundObject(eligibleInput());
      expect(result.ok).toBe(true);
      if (!result.ok) {
        throw new Error(result.failure.kind);
      }
      expect(isOsvGenerationBoundValidatedRetrieval(result.value)).toBe(true);
      expect(result.value.sha256).toBe(BODY_SHA);
      expect(result.value.receivedSizeBytes).toBe(BODY.byteLength);
      expect(recordedOptions).toHaveLength(1);
      expect(lookupHosts).toEqual(['storage.googleapis.com']);
    });

    it('does not reach HTTP for over-limit, zero, invalid generation, or wrong policy', async () => {
      const cases: Array<Record<string, unknown>> = [
        { expectedDeclaredByteCount: OSV_PROVIDER_OBJECT_RETRIEVAL_MAX_BYTES + 1 },
        { expectedDeclaredByteCount: 0 },
        { generation: 'latest' },
        { retrievalPolicyIdentifier: 'wrong' },
        { registryIdentifier: 'wrong' },
        { eligibleBodyScopeIdentifier: 'wrong' },
        { objectKey: 'npm/OSV-2024-1.json' },
        { objectKey: 'npm/ECHO-2024-1.json' },
        { objectKey: 'npm/CVE-2024-1234.json' },
        { organizationId: 'org' },
        { sourceUrl: 'https://osv.dev' },
        { providerPrefix: 'npm/' },
        { extraField: true },
        { host: 'evil.example' },
        { findingId: 'finding' },
      ];
      for (const overrides of cases) {
        recordedOptions.length = 0;
        const result = await adapter().retrieveGenerationBoundObject(eligibleInput(overrides));
        expect(result.ok, JSON.stringify(overrides)).toBe(false);
        expect(recordedOptions, JSON.stringify(overrides)).toHaveLength(0);
        if (!result.ok) {
          assertConfidentialFailure(result.failure);
        }
      }
    });
  });

  describe('request construction', () => {
    it('compiles exact HTTPS GCS get-media surface', async () => {
      remainingResponses = [
        {
          statusCode: 200,
          headers: {
            'content-type': 'application/json',
            'content-length': String(BODY.byteLength),
            'x-goog-generation': GENERATION,
          },
          body: BODY,
        },
      ];
      await adapter().retrieveGenerationBoundObject(eligibleInput());
      expect(recordedOptions).toHaveLength(1);
      const options = recordedOptions[0] as {
        method: string;
        hostname: string;
        port: number;
        path: string;
        headers: Record<string, string>;
      };
      expect(options.method).toBe('GET');
      expect(options.hostname).toBe('storage.googleapis.com');
      expect(options.port).toBe(443);
      expect(options.path).toBe(
        `/storage/v1/b/osv-vulnerabilities/o/${encodeURIComponent(ELIGIBLE_KEY)}?alt=media&ifGenerationMatch=${GENERATION}`,
      );
      expect(options.path).not.toContain('%252F');
      expect(options.headers['Accept']).toBe('application/json');
      expect(options.headers['Accept-Encoding']).toBe('identity');
      expect(options.headers['Cache-Control']).toBe('no-cache');
      expect(options.headers['User-Agent']).toBe('PatchPilot-intelligence/0.1');
      expect(options.headers['User-Agent']).not.toContain('GHSA');
      expect(options.headers['Authorization']).toBeUndefined();
      expect(options.headers['Cookie']).toBeUndefined();
      expect(options.headers['Range']).toBeUndefined();
      expect(options.path).not.toContain('mediaLink');
      expect(options.path).not.toContain('selfLink');
    });
  });

  describe('response status', () => {
    const statusCases: Array<{ status: number; kind: string }> = [
      { status: 204, kind: 'unexpected_http_status' },
      { status: 206, kind: 'unexpected_http_status' },
      { status: 201, kind: 'unexpected_http_status' },
      { status: 301, kind: 'redirect_rejected' },
      { status: 302, kind: 'redirect_rejected' },
      { status: 303, kind: 'redirect_rejected' },
      { status: 307, kind: 'redirect_rejected' },
      { status: 308, kind: 'redirect_rejected' },
      { status: 401, kind: 'authentication_required' },
      { status: 403, kind: 'authorization_rejected' },
      { status: 404, kind: 'object_not_found' },
      { status: 408, kind: 'http_408' },
      { status: 412, kind: 'generation_not_found' },
      { status: 429, kind: 'http_429' },
      { status: 500, kind: 'unexpected_http_status' },
      { status: 502, kind: 'unexpected_http_status' },
      { status: 503, kind: 'service_unavailable' },
      { status: 504, kind: 'unexpected_http_status' },
      { status: 418, kind: 'unexpected_http_status' },
    ];

    it.each(statusCases)('classifies HTTP $status as $kind', async ({ status, kind }) => {
      remainingResponses = [
        {
          statusCode: status,
          headers: {
            location: 'https://storage.googleapis.com/redirect',
            'content-type': 'text/html',
          },
          body: Buffer.from('provider error prose'),
        },
      ];
      const result = await adapter().retrieveGenerationBoundObject(eligibleInput());
      expect(result.ok).toBe(false);
      if (result.ok) {
        throw new Error('expected failure');
      }
      expect(result.failure.kind).toBe(kind);
      assertConfidentialFailure(result.failure);
      expect(JSON.stringify(result.failure)).not.toContain('provider error');
      expect(JSON.stringify(result.failure)).not.toContain(
        'https://storage.googleapis.com/redirect',
      );
      expect(recordedOptions).toHaveLength(1);
    });
  });

  describe('headers', () => {
    it('rejects missing, malformed, duplicate, and wrong Content-Type', async () => {
      const headerCases: Array<Record<string, string | string[] | undefined>> = [
        { 'content-length': String(BODY.byteLength), 'x-goog-generation': GENERATION },
        {
          'content-type': 'application/json; charset=utf-16',
          'content-length': String(BODY.byteLength),
          'x-goog-generation': GENERATION,
        },
        {
          'content-type': ['application/json', 'text/plain'],
          'content-length': String(BODY.byteLength),
          'x-goog-generation': GENERATION,
        },
        {
          'content-type': 'text/html',
          'content-length': String(BODY.byteLength),
          'x-goog-generation': GENERATION,
        },
        {
          'content-type': 'application/octet-stream',
          'content-length': String(BODY.byteLength),
          'x-goog-generation': GENERATION,
        },
      ];
      for (const headers of headerCases) {
        remainingResponses = [{ statusCode: 200, headers, body: BODY }];
        const result = await adapter().retrieveGenerationBoundObject(eligibleInput());
        expect(result.ok).toBe(false);
        if (!result.ok) {
          expect(result.failure.kind).toBe('invalid_content_type');
        }
      }
    });

    it('accepts charset=utf-8 and identity encoding, including absent encoding', async () => {
      remainingResponses = [
        {
          statusCode: 200,
          headers: {
            'content-type': 'application/json; charset=utf-8',
            'content-encoding': 'identity',
            'content-length': String(BODY.byteLength),
            'x-goog-generation': GENERATION,
          },
          body: BODY,
        },
      ];
      const result = await adapter().retrieveGenerationBoundObject(eligibleInput());
      expect(result.ok).toBe(true);
    });

    it('rejects gzip, br, deflate, stacked, and malformed encodings', async () => {
      for (const encoding of ['gzip', 'br', 'deflate', 'gzip, identity', 'identity, identity']) {
        remainingResponses = [
          {
            statusCode: 200,
            headers: {
              'content-type': 'application/json',
              'content-encoding': encoding,
              'content-length': String(BODY.byteLength),
              'x-goog-generation': GENERATION,
            },
            body: BODY,
          },
        ];
        const result = await adapter().retrieveGenerationBoundObject(eligibleInput());
        expect(result.ok, encoding).toBe(false);
        if (!result.ok) {
          expect(result.failure.kind).toBe('invalid_content_encoding');
        }
      }
    });

    it('rejects malformed, signed, exponent, oversize, and mismatched Content-Length', async () => {
      const cases: Array<{ headers: Record<string, string>; kind: string }> = [
        {
          headers: {
            'content-type': 'application/json',
            'content-length': '-1',
            'x-goog-generation': GENERATION,
          },
          kind: 'malformed_content_length',
        },
        {
          headers: {
            'content-type': 'application/json',
            'content-length': '+53',
            'x-goog-generation': GENERATION,
          },
          kind: 'malformed_content_length',
        },
        {
          headers: {
            'content-type': 'application/json',
            'content-length': '1e3',
            'x-goog-generation': GENERATION,
          },
          kind: 'malformed_content_length',
        },
        {
          headers: {
            'content-type': 'application/json',
            'content-length': String(OSV_PROVIDER_OBJECT_RETRIEVAL_MAX_BYTES + 1),
            'x-goog-generation': GENERATION,
          },
          kind: 'content_length_exceeds_policy',
        },
        {
          headers: {
            'content-type': 'application/json',
            'content-length': '1',
            'x-goog-generation': GENERATION,
          },
          kind: 'declared_size_mismatch',
        },
      ];
      for (const item of cases) {
        remainingResponses = [{ statusCode: 200, headers: item.headers, body: BODY }];
        const result = await adapter().retrieveGenerationBoundObject(eligibleInput());
        expect(result.ok, item.kind).toBe(false);
        if (!result.ok) {
          expect(result.failure.kind).toBe(item.kind);
        }
      }
    });

    it('rejects a Location header on HTTP 200 without exposing it', async () => {
      remainingResponses = [
        {
          statusCode: 200,
          headers: {
            'content-type': 'application/json',
            'content-length': String(BODY.byteLength),
            'x-goog-generation': GENERATION,
            location: 'https://storage.googleapis.com/other',
          },
          body: BODY,
        },
      ];
      const result = await adapter().retrieveGenerationBoundObject(eligibleInput());
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.failure.kind).toBe('malformed_response_metadata');
        assertConfidentialFailure(result.failure);
      }
      expect(recordedOptions).toHaveLength(1);
    });

    it('rejects signed and malformed generation headers', async () => {
      remainingResponses = [
        {
          statusCode: 200,
          headers: {
            'content-type': 'application/json',
            'content-length': String(BODY.byteLength),
            'x-goog-generation': '+1234567890',
          },
          body: BODY,
        },
      ];
      const signed = await adapter().retrieveGenerationBoundObject(eligibleInput());
      expect(signed.ok).toBe(false);
      if (!signed.ok) {
        expect(signed.failure.kind).toBe('malformed_response_metadata');
      }

      remainingResponses = [
        {
          statusCode: 200,
          headers: {
            'content-type': 'application/json',
            'content-length': String(BODY.byteLength),
            'x-goog-generation': '01234567890',
          },
          body: BODY,
        },
      ];
      const leadingZero = await adapter().retrieveGenerationBoundObject(eligibleInput());
      expect(leadingZero.ok).toBe(false);
      if (!leadingZero.ok) {
        expect(leadingZero.failure.kind).toBe('malformed_response_metadata');
      }
    });

    it('requires exact response generation and ignores metageneration', async () => {
      remainingResponses = [
        {
          statusCode: 200,
          headers: {
            'content-type': 'application/json',
            'content-length': String(BODY.byteLength),
            'x-goog-metageneration': GENERATION,
          },
          body: BODY,
        },
      ];
      const missing = await adapter().retrieveGenerationBoundObject(eligibleInput());
      expect(missing.ok).toBe(false);
      if (!missing.ok) {
        expect(missing.failure.kind).toBe('provider_generation_missing');
      }

      remainingResponses = [
        {
          statusCode: 200,
          headers: {
            'content-type': 'application/json',
            'content-length': String(BODY.byteLength),
            'x-goog-generation': '999',
          },
          body: BODY,
        },
      ];
      const mismatch = await adapter().retrieveGenerationBoundObject(eligibleInput());
      expect(mismatch.ok).toBe(false);
      if (!mismatch.ok) {
        expect(mismatch.failure.kind).toBe('provider_generation_mismatch');
      }
    });
  });

  describe('body', () => {
    it('returns immutable synthetic bytes with exact SHA-256 and omits them from JSON', async () => {
      remainingResponses = [
        {
          statusCode: 200,
          headers: {
            'content-type': 'application/json',
            'content-length': String(BODY.byteLength),
            'x-goog-generation': GENERATION,
            etag: '"not-identity"',
            'x-goog-hash': 'md5=AAAA',
          },
          body: BODY,
        },
      ];
      const result = await adapter().retrieveGenerationBoundObject(eligibleInput());
      expect(result.ok).toBe(true);
      if (!result.ok) {
        throw new Error(result.failure.kind);
      }
      expect(result.value.sha256).toBe(BODY_SHA);
      const copy = copyOsvGenerationBoundRetrievedBytes(result.value);
      expect(copy).toEqual(new Uint8Array(BODY));
      if (copy !== undefined) {
        copy[0] = 0;
      }
      expect(copyOsvGenerationBoundRetrievedBytes(result.value)).toEqual(new Uint8Array(BODY));
      const text = `${JSON.stringify(result.value)}\n${inspect(result.value)}\n${String(result.value)}`;
      expect(text).not.toContain('SYNTH-OSV-1');
      expect(text).not.toContain(ELIGIBLE_KEY);
    });

    it('accepts an exact 1 MiB body and missing Content-Length when the stream matches declared size', async () => {
      const exact = Buffer.alloc(OSV_PROVIDER_OBJECT_RETRIEVAL_MAX_BYTES, 0x7b);
      remainingResponses = [
        {
          statusCode: 200,
          headers: {
            'content-type': 'application/json',
            'x-goog-generation': GENERATION,
          },
          body: exact,
        },
      ];
      const result = await adapter().retrieveGenerationBoundObject(
        eligibleInput({ expectedDeclaredByteCount: exact.byteLength }),
      );
      expect(result.ok).toBe(true);
      if (!result.ok) {
        throw new Error(result.failure.kind);
      }
      expect(result.value.receivedSizeBytes).toBe(OSV_PROVIDER_OBJECT_RETRIEVAL_MAX_BYTES);
      expect(result.value.sha256).toBe(createHash('sha256').update(exact).digest('hex'));
    });

    it('rejects the 1048577th byte immediately', async () => {
      const max = OSV_PROVIDER_OBJECT_RETRIEVAL_MAX_BYTES;
      const oversize = Buffer.alloc(max + 1, 0x61);
      remainingResponses = [
        {
          statusCode: 200,
          headers: {
            'content-type': 'application/json',
            'x-goog-generation': GENERATION,
          },
          body: oversize,
        },
      ];
      const result = await adapter().retrieveGenerationBoundObject(
        eligibleInput({ expectedDeclaredByteCount: max }),
      );
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.failure.kind).toBe('response_too_large');
        assertConfidentialFailure(result.failure);
      }
    });

    it('rejects extra bytes beyond the declared size', async () => {
      remainingResponses = [
        {
          statusCode: 200,
          headers: {
            'content-type': 'application/json',
            'x-goog-generation': GENERATION,
          },
          body: Buffer.concat([BODY, Buffer.from('x')]),
        },
      ];
      const result = await adapter().retrieveGenerationBoundObject(eligibleInput());
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.failure.kind).toBe('declared_size_mismatch');
      }
    });

    it('rejects early EOF', async () => {
      remainingResponses = [
        {
          statusCode: 200,
          headers: {
            'content-type': 'application/json',
            'x-goog-generation': GENERATION,
          },
          body: BODY.subarray(0, 4),
        },
      ];
      const result = await adapter().retrieveGenerationBoundObject(eligibleInput());
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.failure.kind).toBe('declared_size_mismatch');
      }
    });

    it('rejects a stream error after partial receipt', async () => {
      const broken = new Readable({
        read() {
          this.push(BODY.subarray(0, 4));
          this.destroy(new Error('synthetic stream failure'));
        },
      });
      remainingResponses = [
        {
          statusCode: 200,
          headers: {
            'content-type': 'application/json',
            'x-goog-generation': GENERATION,
          },
          body: broken,
        },
      ];
      const result = await adapter().retrieveGenerationBoundObject(eligibleInput());
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(['partial_body', 'declared_size_mismatch']).toContain(result.failure.kind);
        assertConfidentialFailure(result.failure);
      }
      expect(recordedOptions).toHaveLength(1);
    });

    it('rejects an early response close', async () => {
      remainingResponses = [
        {
          statusCode: 200,
          headers: {
            'content-type': 'application/json',
            'x-goog-generation': GENERATION,
          },
          body: BODY,
          closeEarly: true,
        },
      ];
      const result = await adapter().retrieveGenerationBoundObject(eligibleInput());
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(['partial_body', 'declared_size_mismatch']).toContain(result.failure.kind);
      }
    });

    it('rejects a connection reset before headers', async () => {
      remainingResponses = [
        {
          statusCode: 200,
          emitError: Object.assign(new Error('reset'), { code: 'ECONNRESET' }),
        },
      ];
      const result = await adapter().retrieveGenerationBoundObject(eligibleInput());
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.failure.kind).toBe('connection_reset');
        expect(result.failure.retryability).toBe('orchestration_retryable');
        assertConfidentialFailure(result.failure);
      }
      expect(recordedOptions).toHaveLength(1);
    });
  });

  describe('cancellation', () => {
    it('issues zero HTTP requests when already cancelled', async () => {
      const controller = new AbortController();
      controller.abort();
      const result = await adapter().retrieveGenerationBoundObject(
        eligibleInput({ signal: controller.signal }),
      );
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.failure.kind).toBe('cancelled');
        expect(result.failure.retryability).toBe('non_retryable');
      }
      expect(recordedOptions).toHaveLength(0);
    });

    it('cancels during body consumption and does not retry', async () => {
      const controller = new AbortController();
      const idle = new Readable({
        read() {
          return;
        },
      });
      remainingResponses = [
        {
          statusCode: 200,
          headers: {
            'content-type': 'application/json',
            'x-goog-generation': GENERATION,
          },
          body: idle,
        },
      ];
      const pending = adapter().retrieveGenerationBoundObject(
        eligibleInput({ signal: controller.signal }),
      );
      await Promise.resolve();
      controller.abort();
      const result = await pending;
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.failure.kind).toBe('cancelled');
        expect(result.failure.retryability).toBe('non_retryable');
        assertConfidentialFailure(result.failure);
      }
      expect(recordedOptions).toHaveLength(1);
      idle.destroy();
    });
  });
});
