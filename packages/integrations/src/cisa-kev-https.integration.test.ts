import { createHash, randomBytes } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import https from 'node:https';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AddressInfo } from 'node:net';

import { INTELLIGENCE_KEV_HOSTNAME, INTELLIGENCE_KEV_PATH } from '@patchpilot/config';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { createCisaKevHttpsTransport, type IntelligenceHttpsRequest } from './cisa-kev-https.js';
import { IntelligenceHttpStreamError } from './intelligence-http-stream.js';

const PUBLIC_V4 = '1.1.1.1';
const BODY = Buffer.from('{"catalogVersion":"2026.09.01","count":0,"vulnerabilities":[]}');
const BODY_SHA = createHash('sha256').update(BODY).digest('hex');
const ETAG = '"integration-etag"';
const ETAG_HASH = createHash('sha256').update(ETAG).digest('hex');

type Handler = (
  request: import('node:http').IncomingMessage,
  response: import('node:http').ServerResponse,
) => void;

describe('CisaKevHttpsTransport local TLS', () => {
  let directory: string;
  let cert: Buffer;
  let key: Buffer;
  let server: https.Server;
  let port: number;
  let handler: Handler = (_request, response) => {
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(BODY);
  };

  beforeAll(async () => {
    directory = mkdtempSync(join(tmpdir(), 'pp-kev-tls-'));
    const keyPath = join(directory, 'key.pem');
    const certPath = join(directory, 'cert.pem');
    execFileSync('openssl', [
      'req',
      '-x509',
      '-newkey',
      'rsa:2048',
      '-keyout',
      keyPath,
      '-out',
      certPath,
      '-days',
      '1',
      '-nodes',
      '-subj',
      '/CN=www.cisa.gov',
      '-addext',
      'subjectAltName=DNS:www.cisa.gov',
    ]);
    key = readFileSync(keyPath);
    cert = readFileSync(certPath);
    server = https.createServer({ key, cert }, (request, response) => {
      handler(request, response);
    });
    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', resolve);
    });
    const address = server.address() as AddressInfo;
    port = address.port;
  });

  afterAll(async () => {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => {
        if (error !== undefined && error !== null) {
          reject(error);
          return;
        }

        resolve();
      });
    });
    rmSync(directory, { recursive: true, force: true });
  });

  function localRequest(): IntelligenceHttpsRequest {
    return (options, callback) => {
      const req = https.request(
        {
          ...options,
          port,
          servername: INTELLIGENCE_KEV_HOSTNAME,
          ca: cert,
          lookup: (_hostname, lookupOptions, lookupCallback) => {
            const all =
              typeof lookupOptions === 'object' &&
              lookupOptions !== null &&
              lookupOptions.all === true;
            if (all) {
              lookupCallback(null, [{ address: '127.0.0.1', family: 4 }]);
              return;
            }

            lookupCallback(null, '127.0.0.1', 4);
          },
        },
        callback,
      );
      req.on('socket', (socket) => {
        Object.defineProperty(socket, 'remoteAddress', {
          configurable: true,
          get: () => PUBLIC_V4,
        });
        Object.defineProperty(socket, 'remoteFamily', {
          configurable: true,
          get: () => 'IPv4',
        });
      });
      return req;
    };
  }

  function client(overrides?: {
    connectTimeoutMs?: number;
    totalTimeoutMs?: number;
    maxBytes?: number;
    logger?: {
      info: (bindings: Record<string, unknown>, message: string) => void;
      warn: (bindings: Record<string, unknown>, message: string) => void;
    };
  }) {
    return createCisaKevHttpsTransport(
      {
        connectTimeoutMs: overrides?.connectTimeoutMs ?? 500,
        totalTimeoutMs: overrides?.totalTimeoutMs ?? 2000,
        maxBytes: overrides?.maxBytes ?? 4096,
      },
      {
        lookup: (_hostname, _options, callback) => {
          callback(null, [{ address: PUBLIC_V4, family: 4 }]);
        },
        request: localRequest(),
        delay: async () => undefined,
        jitter: (value) => value,
        logger: overrides?.logger ?? {
          info: () => undefined,
          warn: () => undefined,
        },
      },
    );
  }

  const catalogRequest = {
    provider: 'cisa_kev' as const,
    sourceIdentifier: 'cisa_kev_json_catalog' as const,
    maxBytes: 4096,
    connectTimeoutMs: 500,
    totalTimeoutMs: 2000,
    retryPolicy: { maxRetries: 1, backoffFloorMs: 250, backoffCeilingMs: 1000 },
    correlationId: 'corr-tls-1',
  };

  async function collect(body: AsyncIterable<Uint8Array>): Promise<Buffer> {
    const chunks: Buffer[] = [];
    for await (const chunk of body) {
      chunks.push(Buffer.from(chunk));
    }

    return Buffer.concat(chunks);
  }

  it('streams a 200 JSON body over local TLS with identity encoding', async () => {
    handler = (_request, response) => {
      expect(_request.url).toBe(INTELLIGENCE_KEV_PATH);
      response.writeHead(200, {
        'content-type': 'application/json',
        etag: ETAG,
      });
      response.end(BODY);
    };
    const result = await client().fetchCatalog(catalogRequest);
    expect(result.kind).toBe('response');
    if (result.kind !== 'response') {
      return;
    }

    expect(result.etagHash).toBe(ETAG_HASH);
    const bytes = await collect(result.body);
    const completion = await result.completion;
    expect(bytes.equals(BODY)).toBe(true);
    expect(completion.sha256).toBe(BODY_SHA);
  });

  it('accepts chunked transfer without Content-Length', async () => {
    handler = (_request, response) => {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.write(BODY.subarray(0, 10));
      response.end(BODY.subarray(10));
    };
    const result = await client().fetchCatalog(catalogRequest);
    expect(result.kind).toBe('response');
    if (result.kind === 'response') {
      expect(result.declaredByteLength).toBeNull();
      expect((await collect(result.body)).equals(BODY)).toBe(true);
      await result.completion;
    }
  });

  it('rejects redirects, invalid content type, and gzip content encoding', async () => {
    handler = (_request, response) => {
      response.writeHead(302, { location: 'https://example.invalid/next' });
      response.end('ignored');
    };
    expect(await client().fetchCatalog(catalogRequest)).toMatchObject({
      code: 'redirect_rejected',
    });

    handler = (_request, response) => {
      response.writeHead(200, { 'content-type': 'text/html' });
      response.end('<html></html>');
    };
    expect(await client().fetchCatalog(catalogRequest)).toMatchObject({
      code: 'content_type_invalid',
    });

    handler = (_request, response) => {
      response.writeHead(200, {
        'content-type': 'application/json',
        'content-encoding': 'gzip',
      });
      response.end(BODY);
    };
    expect(await client().fetchCatalog(catalogRequest)).toMatchObject({
      code: 'content_type_invalid',
    });
  });

  it('retries 429 and 503 against the local server', async () => {
    let attempts = 0;
    handler = (_request, response) => {
      attempts += 1;
      if (attempts === 1) {
        response.writeHead(429, { 'retry-after': '1' });
        response.end();
        return;
      }

      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(BODY);
    };
    const limited = await client().fetchCatalog(catalogRequest);
    expect(limited.kind).toBe('response');

    attempts = 0;
    handler = (_request, response) => {
      attempts += 1;
      if (attempts === 1) {
        response.writeHead(503);
        response.end();
        return;
      }

      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(BODY);
    };
    expect((await client().fetchCatalog(catalogRequest)).kind).toBe('response');
  });

  it('rejects streamed over-limit bodies and caller cancellation', async () => {
    handler = (_request, response) => {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(randomBytes(64));
    };
    const over = await client({ maxBytes: 8 }).fetchCatalog({ ...catalogRequest, maxBytes: 8 });
    expect(over.kind).toBe('response');
    if (over.kind === 'response') {
      await expect(collect(over.body)).rejects.toBeInstanceOf(IntelligenceHttpStreamError);
    }

    handler = (_request, response) => {
      response.writeHead(200, { 'content-type': 'application/json' });
      const timer = setInterval(() => {
        response.write(Buffer.from('x'));
      }, 20);
      response.on('close', () => {
        clearInterval(timer);
      });
    };
    const hanging = await client().fetchCatalog(catalogRequest);
    expect(hanging.kind).toBe('response');
    if (hanging.kind === 'response') {
      await hanging.cancel();
      await expect(hanging.completion).rejects.toMatchObject({ code: 'request_cancelled' });
    }
  });

  it('enforces total timeout, premature close, and does not log the provider body', async () => {
    const logs: string[] = [];
    const capturing = {
      info: (bindings: Record<string, unknown>, message: string) => {
        logs.push(JSON.stringify(bindings) + message);
      },
      warn: (bindings: Record<string, unknown>, message: string) => {
        logs.push(JSON.stringify(bindings) + message);
      },
    };

    handler = (_request, response) => {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(BODY);
    };
    const ok = await client({ logger: capturing }).fetchCatalog(catalogRequest);
    expect(ok.kind).toBe('response');
    if (ok.kind === 'response') {
      await collect(ok.body);
      await ok.completion;
    }

    expect(logs.join('\n')).not.toContain(BODY.toString('utf8'));
    expect(logs.join('\n')).not.toContain(INTELLIGENCE_KEV_PATH);

    handler = (_request, response) => {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.flushHeaders();
    };
    const timedOut = await client({ totalTimeoutMs: 400 }).fetchCatalog({
      ...catalogRequest,
      totalTimeoutMs: 400,
    });
    expect(timedOut.kind).toBe('response');
    if (timedOut.kind === 'response') {
      await expect(timedOut.completion).rejects.toMatchObject({ code: 'response_timeout' });
    }

    handler = (_request, response) => {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.flushHeaders();
      response.destroy();
    };
    const closed = await client().fetchCatalog(catalogRequest);
    expect(closed.kind).toBe('response');
    if (closed.kind === 'response') {
      await expect(collect(closed.body)).rejects.toBeInstanceOf(IntelligenceHttpStreamError);
    }
  });
});
