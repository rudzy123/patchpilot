/**
 * Session 11 Batch 6A timeout, cancellation, and settlement tests.
 * Fake timers only. No live provider contact.
 */

import { EventEmitter } from 'node:events';
import { Readable } from 'node:stream';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  OSV_ELIGIBLE_BODY_SCOPE_IDENTIFIER,
  OSV_GENERATION_BOUND_RETRIEVAL_POLICY_IDENTIFIER,
  OSV_INVENTORY_SCOPE_IDENTIFIER,
  OSV_PROVIDER_IDENTIFIER,
  OSV_SOURCE_LICENSE_REGISTRY_IDENTIFIER,
  OSV_TIMEOUT_POLICY_V1,
  OSV_TRANSPORT_POLICY_VERSION,
} from '@patchpilot/vulnerability-intelligence';

import {
  createOsvGenerationBoundRetrievalHttpsAdapter,
  type OsvRetrievalDnsLookup,
  type OsvRetrievalHttpsRequest,
} from './osv-generation-bound-retrieval-https.js';

const PUBLIC_V4 = '1.1.1.1';
const ELIGIBLE_KEY = 'npm/GHSA-abcd-1234-wxyz.json';
const GENERATION = '1234567890';
const BODY = Buffer.from('{"id":"SYNTH-OSV-TIMEOUT"}');

type ScriptedResponse = {
  statusCode: number;
  headers?: Record<string, string | string[] | undefined>;
  body?: Buffer | Readable;
  omitResponse?: boolean;
  omitSecureConnect?: boolean;
};

const recordedOptions: unknown[] = [];
let remainingResponses: ScriptedResponse[] = [];

beforeEach(() => {
  vi.useFakeTimers();
  recordedOptions.length = 0;
  remainingResponses = [];
});

afterEach(() => {
  vi.useRealTimers();
});

const lookup: OsvRetrievalDnsLookup = (_hostname, _options, callback) => {
  callback(null, [{ address: PUBLIC_V4, family: 4 }]);
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
      omitResponse: true,
    };
    queueMicrotask(() => {
      if (destroyed) {
        return;
      }
      const socket = new EventEmitter();
      Object.defineProperty(socket, 'remoteAddress', { value: PUBLIC_V4 });
      Object.defineProperty(socket, 'remoteFamily', { value: 'IPv4' });
      req.emit('socket', socket);
      if (script.omitSecureConnect !== true) {
        socket.emit('secureConnect');
      }
      if (script.omitResponse === true || callback === undefined || destroyed) {
        return;
      }
      const payload = script.body ?? BODY;
      const response =
        payload instanceof Readable ? payload : Readable.from([payload], { objectMode: false });
      Object.assign(response, {
        statusCode: script.statusCode,
        headers: script.headers ?? {},
      });
      callback(response as never);
    });
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

describe('OSV generation-bound retrieval timeouts and races', () => {
  it('times out connection when TLS never completes', async () => {
    remainingResponses = [{ statusCode: 200, omitSecureConnect: true, omitResponse: true }];
    const pending = adapter().retrieveGenerationBoundObject(eligibleInput());
    await Promise.resolve();
    await vi.advanceTimersByTimeAsync(OSV_TIMEOUT_POLICY_V1.connectionTimeoutMs);
    const result = await pending;
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.failure.kind).toBe('connection_timeout');
      expect(result.failure.retryability).toBe('orchestration_retryable');
    }
    expect(recordedOptions).toHaveLength(1);
  });

  it('times out response headers after a successful connection', async () => {
    remainingResponses = [{ statusCode: 200, omitResponse: true }];
    const pending = adapter().retrieveGenerationBoundObject(eligibleInput());
    await Promise.resolve();
    await vi.advanceTimersByTimeAsync(OSV_TIMEOUT_POLICY_V1.responseHeaderTimeoutMs);
    const result = await pending;
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.failure.kind).toBe('response_header_timeout');
    }
  });

  it('times out an idle response body', async () => {
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
    const pending = adapter().retrieveGenerationBoundObject(eligibleInput());
    await Promise.resolve();
    await vi.advanceTimersByTimeAsync(OSV_TIMEOUT_POLICY_V1.bodyInactivityTimeoutMs);
    const result = await pending;
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.failure.kind).toBe('response_body_timeout');
    }
    idle.destroy();
  });

  it('cancels during header wait and does not retry', async () => {
    const controller = new AbortController();
    remainingResponses = [{ statusCode: 200, omitResponse: true }];
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
    }
    expect(recordedOptions).toHaveLength(1);
  });

  it('settles once when cancellation and timeout race', async () => {
    const controller = new AbortController();
    remainingResponses = [{ statusCode: 200, omitResponse: true }];
    const pending = adapter().retrieveGenerationBoundObject(
      eligibleInput({ signal: controller.signal }),
    );
    await Promise.resolve();
    controller.abort();
    await vi.advanceTimersByTimeAsync(OSV_TIMEOUT_POLICY_V1.totalRequestDeadlineMs);
    const result = await pending;
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(['cancelled', 'total_deadline_exceeded', 'response_header_timeout']).toContain(
        result.failure.kind,
      );
    }
    expect(recordedOptions).toHaveLength(1);
  });

  it('does not automatically retry a timed-out attempt', async () => {
    remainingResponses = [{ statusCode: 200, omitResponse: true }];
    const pending = adapter().retrieveGenerationBoundObject(eligibleInput());
    await Promise.resolve();
    await vi.advanceTimersByTimeAsync(OSV_TIMEOUT_POLICY_V1.totalRequestDeadlineMs);
    await pending;
    expect(recordedOptions).toHaveLength(1);
  });

  it('ignores cancellation after accepted success', async () => {
    const controller = new AbortController();
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
    const result = await adapter().retrieveGenerationBoundObject(
      eligibleInput({ signal: controller.signal }),
    );
    expect(result.ok).toBe(true);
    controller.abort();
    expect(result.ok).toBe(true);
    expect(recordedOptions).toHaveLength(1);
  });
});
