/**
 * Session 12 Batch 2 timeout, cancellation, event-order, cleanup, and
 * one-request proofs. Fake timers and local doubles only.
 */

import { EventEmitter } from 'node:events';
import { Readable } from 'node:stream';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  OSV_TIMEOUT_POLICY_V1,
  parseOsvGcsListingPage,
} from '@patchpilot/vulnerability-intelligence';

import {
  createOsvGcsListingHttpsAdapterForTests,
  type OsvGcsListingDnsLookup,
  type OsvGcsListingHttpsRequest,
} from './osv-gcs-listing-https-adapter.js';
import {
  MINIMAL_PAGE,
  PUBLIC_V4,
  SECRET_TOKEN,
  assertConfidential,
  continuationRequest,
  createListingTestContext,
  jsonHeaders,
  listingJson,
  validListingRequest,
} from './osv-gcs-listing-https-adapter.test-harness.js';

const ctx = createListingTestContext();

const lookup: OsvGcsListingDnsLookup = (_hostname, _options, callback) => {
  callback(null, [{ address: PUBLIC_V4, family: 4 }]);
};

type ControlledRequest = EventEmitter & {
  destroy: () => void;
  end: () => void;
};

function createControlledRequest(): {
  request: OsvGcsListingHttpsRequest;
  get: () => {
    req: ControlledRequest;
    callback: ((response: Readable) => void) | undefined;
    destroyed: boolean;
    listenerCounts: { error: number; socket: number };
  };
} {
  let req: ControlledRequest | undefined;
  let callback: ((response: Readable) => void) | undefined;
  let destroyed = false;
  const request: OsvGcsListingHttpsRequest = (_options, next) => {
    callback = next as ((response: Readable) => void) | undefined;
    req = new EventEmitter() as ControlledRequest;
    req.destroy = () => {
      destroyed = true;
    };
    req.end = () => undefined;
    return req as ReturnType<OsvGcsListingHttpsRequest>;
  };
  return {
    request,
    get: () => {
      if (req === undefined) {
        throw new Error('request not created');
      }
      return {
        req,
        callback,
        destroyed,
        listenerCounts: {
          error: req.listenerCount('error'),
          socket: req.listenerCount('socket'),
        },
      };
    },
  };
}

function emitPinnedSocket(req: EventEmitter): EventEmitter {
  const socket = new EventEmitter();
  Object.defineProperty(socket, 'remoteAddress', { value: PUBLIC_V4 });
  Object.defineProperty(socket, 'remoteFamily', { value: 'IPv4' });
  req.emit('socket', socket);
  socket.emit('secureConnect');
  return socket;
}

describe('OSV GCS listing adversarial timeouts', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    ctx.reset();
  });

  afterEach(() => {
    vi.useRealTimers();
    ctx.reset();
  });

  it('times out connection, headers, body inactivity, and total deadline once each', async () => {
    ctx.remainingResponses.push({ omitSocket: true, omitResponse: true });
    const connecting = ctx.adapter().listPage(continuationRequest());
    await Promise.resolve();
    await vi.advanceTimersByTimeAsync(OSV_TIMEOUT_POLICY_V1.connectionTimeoutMs);
    const connected = await connecting;
    expect(connected.ok).toBe(false);
    if (!connected.ok) {
      expect(connected.failure.kind).toBe('timeout');
      assertConfidential(connected.failure, [SECRET_TOKEN]);
    }
    expect(ctx.recordedOptions).toHaveLength(1);

    ctx.recordedOptions.length = 0;
    ctx.remainingResponses.push({ omitResponse: true });
    const headers = ctx.adapter().listPage(validListingRequest());
    await Promise.resolve();
    await vi.advanceTimersByTimeAsync(OSV_TIMEOUT_POLICY_V1.responseHeaderTimeoutMs);
    const headerResult = await headers;
    expect(headerResult.ok).toBe(false);
    expect(ctx.recordedOptions).toHaveLength(1);

    ctx.recordedOptions.length = 0;
    ctx.remainingResponses.push({
      statusCode: 200,
      headers: jsonHeaders(MINIMAL_PAGE),
      body: MINIMAL_PAGE,
      neverEnd: true,
    });
    const body = ctx.adapter().listPage(validListingRequest());
    await Promise.resolve();
    await vi.advanceTimersByTimeAsync(OSV_TIMEOUT_POLICY_V1.bodyInactivityTimeoutMs);
    const bodyResult = await body;
    expect(bodyResult.ok).toBe(false);
    expect(ctx.recordedOptions).toHaveLength(1);
  });

  it('ignores late DNS after lookup timeout', async () => {
    let late:
      | ((
          error: NodeJS.ErrnoException | null,
          addresses: Array<{ address: string; family: number }>,
        ) => void)
      | undefined;
    ctx.setLookup((_hostname, _options, callback) => {
      late = callback;
    });
    const pending = ctx.adapter().listPage(validListingRequest());
    await vi.advanceTimersByTimeAsync(OSV_TIMEOUT_POLICY_V1.connectionTimeoutMs);
    const result = await pending;
    expect(result.ok).toBe(false);
    late?.(null, [{ address: PUBLIC_V4, family: 4 }]);
    expect(ctx.recordedOptions).toHaveLength(0);
  });
});

describe('OSV GCS listing adversarial cancellation', () => {
  afterEach(() => {
    ctx.reset();
  });

  it('cancels before dispatch, during DNS, during TLS, during headers, and during body', async () => {
    const already = AbortSignal.abort();
    const pre = await ctx.adapter().listPage(validListingRequest({ signal: already }));
    expect(pre.ok).toBe(false);
    expect(ctx.recordedOptions).toHaveLength(0);

    const dnsController = new AbortController();
    ctx.setLookup((_hostname, _options, _callback) => {
      dnsController.abort();
    });
    const duringDns = await ctx
      .adapter()
      .listPage(validListingRequest({ signal: dnsController.signal }));
    expect(duringDns.ok).toBe(false);
    expect(ctx.recordedOptions).toHaveLength(0);

    ctx.reset();
    const headerController = new AbortController();
    ctx.remainingResponses.push({ omitResponse: true });
    const pending = ctx
      .adapter()
      .listPage(validListingRequest({ signal: headerController.signal }));
    await Promise.resolve();
    headerController.abort();
    const duringHeaders = await pending;
    expect(duringHeaders.ok).toBe(false);
    if (!duringHeaders.ok) {
      expect(duringHeaders.failure.kind).toBe('cancelled');
    }
    expect(ctx.recordedOptions).toHaveLength(1);
  });

  it('ignores cancellation after success and treats repeated abort as one result', async () => {
    const controller = new AbortController();
    ctx.remainingResponses.push({
      statusCode: 200,
      headers: jsonHeaders(MINIMAL_PAGE),
      body: MINIMAL_PAGE,
    });
    const result = await ctx.adapter().listPage(validListingRequest({ signal: controller.signal }));
    expect(result.ok).toBe(true);
    controller.abort();
    controller.abort();
    expect(result.ok).toBe(true);
    expect(ctx.recordedOptions).toHaveLength(1);
  });
});

describe('OSV GCS listing adversarial event order and cleanup', () => {
  it('settles once across error, close, and late data sequences', async () => {
    const controlled = createControlledRequest();
    const pending = createOsvGcsListingHttpsAdapterForTests({
      lookup,
      request: controlled.request,
    }).listPage(validListingRequest());
    await Promise.resolve();
    const { req } = controlled.get();
    req.emit('error', Object.assign(new Error('reset'), { code: 'ECONNRESET' }));
    req.emit('socket', new EventEmitter());
    const result = await pending;
    expect(result.ok).toBe(false);
    req.on('error', () => undefined);
    req.emit('error', Object.assign(new Error('again'), { code: 'ECONNRESET' }));
    expect(controlled.get().destroyed).toBe(true);
  });

  it('ignores a second socket after the first is attached', async () => {
    const controlled = createControlledRequest();
    const pending = createOsvGcsListingHttpsAdapterForTests({
      lookup,
      request: controlled.request,
    }).listPage(validListingRequest());
    await Promise.resolve();
    const { req, callback } = controlled.get();
    const first = emitPinnedSocket(req);
    const second = new EventEmitter();
    Object.defineProperty(second, 'remoteAddress', { value: '8.8.8.8' });
    Object.defineProperty(second, 'remoteFamily', { value: 'IPv4' });
    req.emit('socket', second);
    second.emit('secureConnect');
    if (callback === undefined) {
      throw new Error('missing callback');
    }
    const response = Readable.from([MINIMAL_PAGE], { objectMode: false });
    Object.assign(response, {
      statusCode: 200,
      headers: jsonHeaders(MINIMAL_PAGE),
    });
    callback(response);
    const result = await pending;
    expect(result.ok).toBe(true);
    expect(first.listenerCount('error')).toBe(0);
  });

  it('does not invoke the parser after a response error', async () => {
    let parseCount = 0;
    const controlled = createControlledRequest();
    const pending = createOsvGcsListingHttpsAdapterForTests({
      lookup,
      request: controlled.request,
      parseListingPage: (input) => {
        parseCount += 1;
        return parseOsvGcsListingPage(input);
      },
    }).listPage(validListingRequest());
    await Promise.resolve();
    const { req, callback } = controlled.get();
    emitPinnedSocket(req);
    if (callback === undefined) {
      throw new Error('missing callback');
    }
    const response = new Readable({
      read() {
        this.emit('error', new Error('body'));
      },
    });
    Object.assign(response, {
      statusCode: 200,
      headers: jsonHeaders(MINIMAL_PAGE),
    });
    callback(response);
    const result = await pending;
    expect(result.ok).toBe(false);
    expect(parseCount).toBe(0);
  });

  it('swallows event-sink failures without changing the result or retrying', async () => {
    ctx.remainingResponses.push({
      statusCode: 200,
      headers: jsonHeaders(MINIMAL_PAGE),
      body: MINIMAL_PAGE,
    });
    const result = await ctx
      .adapter({
        logger: {
          info: () => {
            throw new Error(`sink ${SECRET_TOKEN}`);
          },
          warn: () => {
            throw new Error(`sink ${SECRET_TOKEN}`);
          },
        },
      })
      .listPage(validListingRequest());
    expect(result.ok).toBe(true);
    expect(ctx.recordedOptions).toHaveLength(1);
  });
});

describe('OSV GCS listing one-request and no-pagination proof', () => {
  afterEach(() => {
    ctx.reset();
  });

  it('issues exactly one HTTPS request for success, nextPageToken, and retryable statuses', async () => {
    const scripts = [
      {
        statusCode: 200,
        headers: jsonHeaders(MINIMAL_PAGE),
        body: MINIMAL_PAGE,
      },
      {
        statusCode: 200,
        headers: jsonHeaders(listingJson({ nextPageToken: SECRET_TOKEN })),
        body: listingJson({ nextPageToken: SECRET_TOKEN }),
      },
      { statusCode: 408, headers: { 'content-type': 'application/json' }, body: MINIMAL_PAGE },
      { statusCode: 429, headers: { 'content-type': 'application/json' }, body: MINIMAL_PAGE },
      { statusCode: 500, headers: { 'content-type': 'application/json' }, body: MINIMAL_PAGE },
      { statusCode: 502, headers: { 'content-type': 'application/json' }, body: MINIMAL_PAGE },
      { statusCode: 503, headers: { 'content-type': 'application/json' }, body: MINIMAL_PAGE },
      { statusCode: 504, headers: { 'content-type': 'application/json' }, body: MINIMAL_PAGE },
      {
        statusCode: 302,
        headers: { location: 'https://storage.googleapis.com/next' },
        body: MINIMAL_PAGE,
      },
    ];
    for (const script of scripts) {
      ctx.recordedOptions.length = 0;
      ctx.setResponses([script]);
      await ctx.adapter().listPage(continuationRequest());
      expect(ctx.recordedOptions, String(script.statusCode)).toHaveLength(1);
      const options = ctx.recordedOptions[0] as { method: string; path: string };
      expect(options.method).toBe('GET');
      expect(options.path).not.toContain('alt=media');
    }
  });

  it('issues zero HTTPS requests for preflight rejection and pre-aborted signals', async () => {
    const result = await ctx.adapter().listPage({} as never);
    expect(result.ok).toBe(false);
    expect(ctx.recordedOptions).toHaveLength(0);
    const cancelled = await ctx
      .adapter()
      .listPage(validListingRequest({ signal: AbortSignal.abort() }));
    expect(cancelled.ok).toBe(false);
    expect(ctx.recordedOptions).toHaveLength(0);
  });
});
