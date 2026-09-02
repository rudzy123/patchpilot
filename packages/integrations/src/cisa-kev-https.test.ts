import { createHash } from 'node:crypto';
import { EventEmitter } from 'node:events';
import https from 'node:https';
import { Readable } from 'node:stream';

import { INTELLIGENCE_KEV_HOSTNAME, INTELLIGENCE_KEV_PATH } from '@patchpilot/config';
import { afterEach, describe, expect, it } from 'vitest';

import {
  createCisaKevHttpsTransport,
  type IntelligenceDnsLookup,
  type IntelligenceHttpsRequest,
} from './cisa-kev-https.js';
import { IntelligenceHttpStreamError } from './intelligence-http-stream.js';
import type { IntelligenceProviderHttpRequest } from '@patchpilot/domain';

const PUBLIC_V4 = '1.1.1.1';
const PUBLIC_V6 = '2001:4860:4860::8888';
const BODY = Buffer.from('{"catalogVersion":"2026.09.01","count":1,"vulnerabilities":[]}');
const BODY_SHA = createHash('sha256').update(BODY).digest('hex');
const ETAG = '"raw-cisa-etag-value"';
const ETAG_HASH = createHash('sha256').update(ETAG).digest('hex');

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
};

const recordedOptions: unknown[] = [];
const lookupHosts: string[] = [];
let remainingResponses: ScriptedResponse[] = [];
let lookupImpl: IntelligenceDnsLookup = (_hostname, _options, callback) => {
  callback(null, [{ address: PUBLIC_V4, family: 4 }]);
};

afterEach(() => {
  recordedOptions.length = 0;
  lookupHosts.length = 0;
  remainingResponses = [];
  lookupImpl = (_hostname, _options, callback) => {
    callback(null, [{ address: PUBLIC_V4, family: 4 }]);
  };
  delete process.env['HTTPS_PROXY'];
  delete process.env['HTTP_PROXY'];
  delete process.env['ALL_PROXY'];
  delete process.env['https_proxy'];
  delete process.env['http_proxy'];
  delete process.env['all_proxy'];
});

const lookup: IntelligenceDnsLookup = (hostname, options, callback) => {
  lookupHosts.push(hostname);
  lookupImpl(hostname, options, callback);
};

const request: IntelligenceHttpsRequest = (options, callback) => {
  recordedOptions.push(options);
  const req = new EventEmitter() as ReturnType<IntelligenceHttpsRequest>;
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

function transport() {
  return createCisaKevHttpsTransport(
    { connectTimeoutMs: 200, totalTimeoutMs: 1000, maxBytes: 4096 },
    {
      lookup,
      request,
      clock: { now: () => new Date('2026-09-01T12:00:00.000Z') },
      delay: async () => undefined,
      jitter: (value) => value,
    },
  );
}

function baseRequest(
  overrides: Partial<IntelligenceProviderHttpRequest> = {},
): IntelligenceProviderHttpRequest {
  return {
    provider: 'cisa_kev',
    sourceIdentifier: 'cisa_kev_json_catalog',
    maxBytes: 4096,
    connectTimeoutMs: 200,
    totalTimeoutMs: 1000,
    retryPolicy: { maxRetries: 0, backoffFloorMs: 250, backoffCeilingMs: 1000 },
    correlationId: 'corr-kev-1',
    ...overrides,
  };
}

async function collect(body: AsyncIterable<Uint8Array>): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of body) {
    chunks.push(Buffer.from(chunk));
  }

  return Buffer.concat(chunks);
}

describe('CisaKevHttpsTransport', () => {
  it('accepts only the committed CISA provider and source and never takes a URL', async () => {
    remainingResponses = [
      {
        statusCode: 200,
        headers: {
          'content-type': 'application/json',
          'content-length': String(BODY.byteLength),
        },
        body: BODY,
      },
    ];
    const client = transport();
    const okResult = await client.fetchCatalog(baseRequest());
    expect(okResult.kind).toBe('response');
    expect(await client.fetchCatalog(baseRequest({ provider: 'osv' }))).toMatchObject({
      kind: 'failure',
      code: 'invalid_provider_source',
    });
    expect(
      await client.fetchCatalog(
        baseRequest({ sourceIdentifier: 'cisa_kev_json_catalog', provider: 'osv' }),
      ),
    ).toMatchObject({ code: 'invalid_provider_source' });
    expect(baseRequest()).not.toHaveProperty('url');
  });

  it('constructs GET https://www.cisa.gov:443 with the exact path and controlled headers', async () => {
    remainingResponses = [
      {
        statusCode: 200,
        headers: { 'content-type': 'application/json' },
        body: BODY,
      },
    ];
    const result = await transport().fetchCatalog(baseRequest());
    expect(result.kind).toBe('response');
    const options = recordedOptions[0] as {
      method: string;
      hostname: string;
      port: number;
      path: string;
      servername: string;
      agent: https.Agent;
      rejectUnauthorized: boolean;
      minVersion: string;
      maxHeaderSize: number;
      headers: Record<string, string>;
    };
    expect(options.method).toBe('GET');
    expect(options.hostname).toBe(INTELLIGENCE_KEV_HOSTNAME);
    expect(options.port).toBe(443);
    expect(options.path).toBe(INTELLIGENCE_KEV_PATH);
    expect(options.path).not.toContain('?');
    expect(options.path).not.toContain('#');
    expect(options.servername).toBe(INTELLIGENCE_KEV_HOSTNAME);
    expect(options.agent).toBeInstanceOf(https.Agent);
    const agent = options.agent as https.Agent;
    expect(agent.options.keepAlive).toBe(false);
    expect(agent.options.proxyEnv).toEqual({});
    expect(agent.options.autoSelectFamily).toBe(false);
    expect(options.rejectUnauthorized).toBe(true);
    expect(options.minVersion).toBe('TLSv1.2');
    expect(options.maxHeaderSize).toBe(8192);
    expect(options.headers).toEqual({
      Host: 'www.cisa.gov',
      Accept: 'application/json',
      'Accept-Encoding': 'identity',
      'User-Agent': 'PatchPilot-intelligence/0.1',
      Connection: 'close',
    });
    expect(options.headers).not.toHaveProperty('Authorization');
    expect(options.headers).not.toHaveProperty('Cookie');
    expect(options.headers).not.toHaveProperty('If-None-Match');
    expect(options.headers).not.toHaveProperty('If-Modified-Since');
  });

  it('pins through both Node lookup callback shapes and rejects headers before pin verify', async () => {
    remainingResponses = [
      { statusCode: 200, headers: { 'content-type': 'application/json' }, body: BODY },
    ];
    await transport().fetchCatalog(baseRequest());
    const options = recordedOptions[0] as {
      lookup: (
        hostname: string,
        lookupOptions: { all?: boolean },
        callback: (
          error: NodeJS.ErrnoException | null,
          address: string | Array<{ address: string; family: number }>,
          family?: number,
        ) => void,
      ) => void;
    };

    let allForm: unknown;
    options.lookup('www.cisa.gov', { all: true }, (_error, addresses) => {
      allForm = addresses;
    });
    expect(allForm).toEqual([{ address: PUBLIC_V4, family: 4 }]);

    let singleAddress: unknown;
    let singleFamily: unknown;
    options.lookup('www.cisa.gov', {}, (_error, address, family) => {
      singleAddress = address;
      singleFamily = family;
    });
    expect(singleAddress).toBe(PUBLIC_V4);
    expect(singleFamily).toBe(4);

    remainingResponses = [
      {
        statusCode: 200,
        headers: { 'content-type': 'application/json' },
        body: BODY,
        omitSecureConnect: true,
      },
    ];
    expect(await transport().fetchCatalog(baseRequest())).toMatchObject({ code: 'dns_rejected' });
  });

  it('ignores ambient proxy environment variables', async () => {
    process.env['HTTPS_PROXY'] = 'http://127.0.0.1:8080';
    process.env['HTTP_PROXY'] = 'http://127.0.0.1:8080';
    process.env['ALL_PROXY'] = 'http://127.0.0.1:8080';
    process.env['https_proxy'] = 'http://127.0.0.1:8080';
    remainingResponses = [
      { statusCode: 200, headers: { 'content-type': 'application/json' }, body: BODY },
    ];
    await transport().fetchCatalog(baseRequest());
    const options = recordedOptions[0] as { agent: https.Agent; hostname: string };
    expect(options.agent).toBeInstanceOf(https.Agent);
    expect(options.agent.options.proxyEnv).toEqual({});
    expect(options.hostname).toBe('www.cisa.gov');
  });

  it('pins a public IPv4 address and rejects blocked families', async () => {
    remainingResponses = [
      { statusCode: 200, headers: { 'content-type': 'application/json' }, body: BODY },
    ];
    await transport().fetchCatalog(baseRequest());
    expect(lookupHosts).toEqual(['www.cisa.gov']);

    lookupImpl = (_hostname, _options, callback) => {
      callback(null, [{ address: '10.0.0.1', family: 4 }]);
    };
    expect(await transport().fetchCatalog(baseRequest())).toMatchObject({ code: 'dns_rejected' });

    lookupImpl = (_hostname, _options, callback) => {
      callback(null, [{ address: '127.0.0.1', family: 4 }]);
    };
    expect(await transport().fetchCatalog(baseRequest())).toMatchObject({ code: 'dns_rejected' });

    lookupImpl = (_hostname, _options, callback) => {
      callback(null, [{ address: '169.254.169.254', family: 4 }]);
    };
    expect(await transport().fetchCatalog(baseRequest())).toMatchObject({ code: 'dns_rejected' });

    lookupImpl = (_hostname, _options, callback) => {
      callback(null, [{ address: PUBLIC_V6, family: 6 }]);
    };
    remainingResponses = [
      {
        statusCode: 200,
        headers: { 'content-type': 'application/json' },
        body: BODY,
        remoteAddress: PUBLIC_V6,
        remoteFamily: 'IPv6',
      },
    ];
    expect((await transport().fetchCatalog(baseRequest())).kind).toBe('response');
  });

  it('rejects DNS that returns only IPv4-compatible blocked IPv6 and never starts HTTPS', async () => {
    const logs: string[] = [];
    lookupImpl = (_hostname, _options, callback) => {
      callback(null, [{ address: '::10.0.0.1', family: 6 }]);
    };
    const client = createCisaKevHttpsTransport(
      { connectTimeoutMs: 200, totalTimeoutMs: 1000, maxBytes: 4096 },
      {
        lookup,
        request,
        clock: { now: () => new Date('2026-09-01T12:00:00.000Z') },
        delay: async () => undefined,
        jitter: (value) => value,
        logger: {
          info(bindings, message) {
            logs.push(`${message}:${JSON.stringify(bindings)}`);
          },
          warn(bindings, message) {
            logs.push(`${message}:${JSON.stringify(bindings)}`);
          },
        },
      },
    );
    expect(await client.fetchCatalog(baseRequest())).toMatchObject({
      kind: 'failure',
      code: 'dns_rejected',
    });
    expect(recordedOptions).toHaveLength(0);
    expect(JSON.stringify(logs)).not.toMatch(/::10\.0\.0\.1|10\.0\.0\.1/);
  });

  it('rejects a pin mismatch and repeats DNS on retry', async () => {
    remainingResponses = [
      {
        statusCode: 503,
        headers: {},
        body: Buffer.from('nope'),
      },
      {
        statusCode: 200,
        headers: { 'content-type': 'application/json' },
        body: BODY,
      },
    ];
    const result = await transport().fetchCatalog(
      baseRequest({ retryPolicy: { maxRetries: 1, backoffFloorMs: 250, backoffCeilingMs: 1000 } }),
    );
    expect(result.kind).toBe('response');
    expect(lookupHosts).toEqual(['www.cisa.gov', 'www.cisa.gov']);

    remainingResponses = [
      {
        statusCode: 200,
        headers: { 'content-type': 'application/json' },
        body: BODY,
        remoteAddress: '8.8.8.8',
      },
    ];
    expect(await transport().fetchCatalog(baseRequest())).toMatchObject({ code: 'dns_rejected' });
  });

  it('maps HTTP statuses, rejects unexpected 304 and redirects, and retries 408/429/5xx', async () => {
    remainingResponses = [{ statusCode: 304, headers: {} }];
    expect(await transport().fetchCatalog(baseRequest())).toMatchObject({
      code: 'provider_client_error',
    });
    remainingResponses = [{ statusCode: 302, headers: { location: 'https://evil.example/' } }];
    expect(await transport().fetchCatalog(baseRequest())).toMatchObject({
      code: 'redirect_rejected',
    });
    remainingResponses = [{ statusCode: 404, headers: {} }];
    expect(await transport().fetchCatalog(baseRequest())).toMatchObject({
      code: 'provider_client_error',
    });
    remainingResponses = [
      { statusCode: 429, headers: { 'retry-after': '5' } },
      { statusCode: 200, headers: { 'content-type': 'application/json' }, body: BODY },
    ];
    const limited = await transport().fetchCatalog(
      baseRequest({ retryPolicy: { maxRetries: 1, backoffFloorMs: 250, backoffCeilingMs: 1000 } }),
    );
    expect(limited.kind).toBe('response');
    remainingResponses = [{ statusCode: 503, headers: {} }];
    expect(
      await transport().fetchCatalog(
        baseRequest({
          retryPolicy: { maxRetries: 0, backoffFloorMs: 250, backoffCeilingMs: 1000 },
        }),
      ),
    ).toMatchObject({ code: 'provider_server_error' });
    remainingResponses = [{ statusCode: 408, headers: {} }];
    expect(await transport().fetchCatalog(baseRequest())).toMatchObject({
      code: 'response_timeout',
    });
  });

  it('streams 200 JSON, hashes identity bytes, and returns only etagHash', async () => {
    remainingResponses = [
      {
        statusCode: 200,
        headers: {
          'content-type': 'application/json; charset=utf-8',
          'content-length': String(BODY.byteLength),
          etag: ETAG,
          'last-modified': 'Mon, 31 Aug 2026 16:00:00 GMT',
        },
        body: BODY,
      },
    ];
    const logs: Array<Record<string, unknown>> = [];
    const client = createCisaKevHttpsTransport(
      { connectTimeoutMs: 200, totalTimeoutMs: 1000, maxBytes: 4096 },
      {
        lookup,
        request,
        delay: async () => undefined,
        jitter: (value) => value,
        logger: {
          info: (bindings) => {
            logs.push(bindings);
          },
          warn: (bindings) => {
            logs.push(bindings);
          },
        },
      },
    );
    const result = await client.fetchCatalog(baseRequest());
    expect(result.kind).toBe('response');
    if (result.kind !== 'response') {
      return;
    }

    expect(result.etagHash).toBe(ETAG_HASH);
    expect(result.declaredByteLength).toBe(BODY.byteLength);
    const bytes = await collect(result.body);
    const completion = await result.completion;
    expect(bytes.equals(BODY)).toBe(true);
    expect(completion.observedByteLength).toBe(BODY.byteLength);
    expect(completion.sha256).toBe(BODY_SHA);
    expect(JSON.stringify(logs)).not.toContain(ETAG);
    expect(JSON.stringify(logs)).not.toContain(PUBLIC_V4);
    expect(JSON.stringify(logs)).not.toContain(INTELLIGENCE_KEV_PATH);
  });

  it('rejects invalid length, over-limit streams, empty bodies, and bad encodings', async () => {
    remainingResponses = [
      {
        statusCode: 200,
        headers: { 'content-type': 'application/json', 'content-length': '0' },
        body: Buffer.alloc(0),
      },
    ];
    expect(await transport().fetchCatalog(baseRequest())).toMatchObject({ code: 'response_empty' });
    remainingResponses = [
      {
        statusCode: 200,
        headers: { 'content-type': 'application/json', 'content-length': '99999' },
        body: BODY,
      },
    ];
    expect(await transport().fetchCatalog(baseRequest({ maxBytes: 16 }))).toMatchObject({
      code: 'response_too_large',
    });
    remainingResponses = [
      {
        statusCode: 200,
        headers: { 'content-type': 'text/html' },
        body: BODY,
      },
    ];
    expect(await transport().fetchCatalog(baseRequest())).toMatchObject({
      code: 'content_type_invalid',
    });
    remainingResponses = [
      {
        statusCode: 200,
        headers: { 'content-type': 'application/json', 'content-encoding': 'gzip' },
        body: BODY,
      },
    ];
    expect(await transport().fetchCatalog(baseRequest())).toMatchObject({
      code: 'content_type_invalid',
    });
    remainingResponses = [
      {
        statusCode: 200,
        headers: { 'content-type': 'application/json' },
        body: Buffer.concat([BODY, BODY, BODY, BODY]),
      },
    ];
    const over = await transport().fetchCatalog(baseRequest({ maxBytes: 8 }));
    expect(over.kind).toBe('response');
    if (over.kind === 'response') {
      await expect(collect(over.body)).rejects.toBeInstanceOf(IntelligenceHttpStreamError);
      await expect(over.completion).rejects.toMatchObject({ code: 'response_too_large' });
    }
  });

  it('cancels in-flight streams without leaving an unhandled completion rejection', async () => {
    const hanging = new Readable({
      read() {
        return undefined;
      },
    });
    remainingResponses = [
      {
        statusCode: 200,
        headers: { 'content-type': 'application/json' },
        body: hanging,
      },
    ];
    const result = await transport().fetchCatalog(baseRequest());
    expect(result.kind).toBe('response');
    if (result.kind !== 'response') {
      return;
    }

    await result.cancel();
    await expect(result.completion).rejects.toMatchObject({ code: 'request_cancelled' });
  });

  it('honors caller abort before a retry', async () => {
    const controller = new AbortController();
    remainingResponses = [{ statusCode: 503, headers: {} }];
    controller.abort();
    expect(
      await transport().fetchCatalog(baseRequest({ signal: controller.signal })),
    ).toMatchObject({ code: 'request_cancelled' });
  });

  it('times out a hung TCP/TLS handshake', async () => {
    remainingResponses = [{ statusCode: 200, delayMs: 200 }];
    await expect(
      transport().fetchCatalog(baseRequest({ connectTimeoutMs: 40, totalTimeoutMs: 1000 })),
    ).resolves.toMatchObject({ code: 'connection_timeout' });
  });

  it('times out when headers never arrive after connect', async () => {
    remainingResponses = [{ statusCode: 200, omitResponse: true }];
    await expect(
      transport().fetchCatalog(baseRequest({ connectTimeoutMs: 40, totalTimeoutMs: 1000 })),
    ).resolves.toMatchObject({ code: 'response_timeout' });
  });

  it('times out a hanging identity body after headers', async () => {
    const hanging = new Readable({
      read() {
        return undefined;
      },
    });
    remainingResponses = [
      { statusCode: 200, headers: { 'content-type': 'application/json' }, body: hanging },
    ];
    const timedOut = await transport().fetchCatalog(
      baseRequest({ connectTimeoutMs: 200, totalTimeoutMs: 40 }),
    );
    expect(timedOut.kind).toBe('response');
    if (timedOut.kind === 'response') {
      await expect(timedOut.completion).rejects.toMatchObject({ code: 'response_timeout' });
    }
  });

  it('rejects invalid Content-Length, premature close, and unread error bodies', async () => {
    remainingResponses = [
      {
        statusCode: 200,
        headers: { 'content-type': 'application/json', 'content-length': 'not-a-number' },
        body: BODY,
      },
    ];
    expect(await transport().fetchCatalog(baseRequest())).toMatchObject({
      code: 'processing_failed',
    });

    remainingResponses = [
      {
        statusCode: 200,
        headers: { 'content-type': 'application/json' },
        body: BODY,
        closeEarly: true,
      },
    ];
    const closed = await transport().fetchCatalog(baseRequest());
    expect(closed.kind).toBe('response');
    if (closed.kind === 'response') {
      await expect(collect(closed.body)).rejects.toBeInstanceOf(IntelligenceHttpStreamError);
      await expect(closed.completion).rejects.toMatchObject({ code: 'response_timeout' });
    }

    let readErrorBody = false;
    const errorBody = new Readable({
      read() {
        readErrorBody = true;
        this.push(Buffer.from('provider-error-body'));
        this.push(null);
      },
    });
    remainingResponses = [{ statusCode: 404, headers: {}, body: errorBody }];
    expect(await transport().fetchCatalog(baseRequest())).toMatchObject({
      code: 'provider_client_error',
    });
    expect(readErrorBody).toBe(false);
  });

  it('surfaces bounded Retry-After on 429 and cancels retry delay', async () => {
    remainingResponses = [{ statusCode: 429, headers: { 'retry-after': '5' } }];
    expect(await transport().fetchCatalog(baseRequest())).toMatchObject({
      code: 'rate_limited',
      retryAfterMs: 1000,
    });

    const controller = new AbortController();
    remainingResponses = [
      { statusCode: 503, headers: {} },
      { statusCode: 200, headers: {} },
    ];
    const delayed = createCisaKevHttpsTransport(
      { connectTimeoutMs: 200, totalTimeoutMs: 1000, maxBytes: 4096 },
      {
        lookup,
        request,
        delay: async (_ms, signal) => {
          if (signal?.aborted === true) {
            throw new Error('aborted');
          }

          controller.abort();
          throw new Error('aborted');
        },
        jitter: (value) => value,
      },
    );
    expect(
      await delayed.fetchCatalog(
        baseRequest({
          signal: controller.signal,
          retryPolicy: { maxRetries: 1, backoffFloorMs: 250, backoffCeilingMs: 1000 },
        }),
      ),
    ).toMatchObject({ code: 'request_cancelled' });
  });
});
