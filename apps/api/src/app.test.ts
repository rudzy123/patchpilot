import { Writable } from 'node:stream';

import { loadServerConfigFrom } from '@patchpilot/config';
import { createFoundationProductionTestEnv, createFoundationTestEnv } from '@patchpilot/test-utils';
import { createLogger } from '@patchpilot/logger';
import { describe, expect, it } from 'vitest';

import { buildApi } from './app.js';

function testConfig() {
  return loadServerConfigFrom(createFoundationTestEnv());
}

function collectingLogger() {
  const chunks: string[] = [];
  const destination = new Writable({
    write(chunk, _encoding, callback) {
      chunks.push(String(chunk));
      callback();
    },
  });
  return {
    logger: createLogger({
      service: 'api-test',
      level: 'info',
      pretty: false,
      destination,
    }),
    output: () => chunks.join(''),
  };
}

describe('api application factory', () => {
  it('starts in memory and reports live without infrastructure', async () => {
    const logs = collectingLogger();
    const app = await buildApi({
      config: testConfig(),
      logger: logs.logger,
      checkDatabaseReady: async () => ({ ok: false }),
      now: () => '2026-08-26T16:00:00.000Z',
    });

    const response = await app.inject({ method: 'GET', url: '/health/live' });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toMatchObject({
      status: 'live',
      service: 'api',
      timestamp: '2026-08-26T16:00:00.000Z',
    });
    await app.close();
  });

  it('reports ready when the database is healthy and not_ready when it is not', async () => {
    const logs = collectingLogger();
    const readyApp = await buildApi({
      config: testConfig(),
      logger: logs.logger,
      checkDatabaseReady: async () => ({ ok: true }),
      now: () => '2026-08-26T16:00:00.000Z',
    });
    const ready = await readyApp.inject({ method: 'GET', url: '/health/ready' });
    expect(ready.statusCode).toBe(200);
    expect(ready.json()).toMatchObject({
      status: 'ready',
      checks: [{ name: 'database', status: 'up' }],
    });
    expect(JSON.stringify(ready.json())).not.toContain('postgresql://');
    await readyApp.close();

    const downApp = await buildApi({
      config: testConfig(),
      logger: logs.logger,
      checkDatabaseReady: async () => ({ ok: false }),
      now: () => '2026-08-26T16:00:00.000Z',
    });
    const down = await downApp.inject({ method: 'GET', url: '/health/ready' });
    expect(down.statusCode).toBe(503);
    expect(down.json()).toMatchObject({
      status: 'not_ready',
      checks: [{ name: 'database', status: 'down' }],
    });
    await downApp.close();
  });

  it('generates request and correlation ids and replaces unsafe values', async () => {
    const logs = collectingLogger();
    const app = await buildApi({
      config: testConfig(),
      logger: logs.logger,
      checkDatabaseReady: async () => ({ ok: true }),
      generateId: () => 'generated-id',
    });

    const generated = await app.inject({ method: 'GET', url: '/health/live' });
    expect(generated.headers['x-request-id']).toBe('generated-id');
    expect(generated.headers['x-correlation-id']).toBe('generated-id');

    const propagated = await app.inject({
      method: 'GET',
      url: '/health/live',
      headers: {
        'x-request-id': 'req-safe',
        'x-correlation-id': 'corr-safe',
      },
    });
    expect(propagated.headers['x-request-id']).toBe('req-safe');
    expect(propagated.headers['x-correlation-id']).toBe('corr-safe');

    const replaced = await app.inject({
      method: 'GET',
      url: '/health/live',
      headers: {
        'x-request-id': 'not a valid id',
      },
    });
    expect(replaced.headers['x-request-id']).toBe('generated-id');
    await app.close();
  });

  it('returns a stable error envelope without stack traces', async () => {
    const logs = collectingLogger();
    const app = await buildApi({
      config: testConfig(),
      logger: logs.logger,
      checkDatabaseReady: async () => ({ ok: true }),
      generateId: () => 'generated-id',
    });
    const response = await app.inject({ method: 'GET', url: '/missing' });
    expect(response.statusCode).toBe(404);
    const body = response.json() as {
      error?: { code?: string; requestId?: string; stack?: string };
    };
    expect(body.error?.code).toBeDefined();
    expect(body.error?.requestId).toBe('generated-id');
    expect(JSON.stringify(body)).not.toContain('stack');
    await app.close();
  });

  it('does not log configuration values from internal errors in production', async () => {
    const logs = collectingLogger();
    const app = await buildApi({
      config: loadServerConfigFrom(createFoundationProductionTestEnv()),
      logger: logs.logger,
      checkDatabaseReady: async () => {
        throw new Error(
          "Can't reach database server at postgresql://patchpilot:operator-secret@db.internal:5432/patchpilot",
        );
      },
    });
    const response = await app.inject({ method: 'GET', url: '/health/ready' });
    expect(response.statusCode).toBe(500);
    expect(response.json()).toMatchObject({
      error: {
        code: 'internal',
        message: 'An internal error occurred.',
      },
    });
    expect(logs.output()).not.toContain('operator-secret');
    expect(logs.output()).not.toContain('postgresql://');
    expect(JSON.stringify(response.json())).not.toContain('operator-secret');
    await app.close();
  });

  it('redacts sensitive headers from logs', async () => {
    const logs = collectingLogger();
    const app = await buildApi({
      config: testConfig(),
      logger: logs.logger,
      checkDatabaseReady: async () => ({ ok: true }),
    });
    await app.inject({
      method: 'GET',
      url: '/health/live',
      headers: {
        authorization: 'Bearer secret-token',
        cookie: 'session=secret',
        'proxy-authorization': 'Basic proxy-secret',
      },
    });
    expect(logs.output()).not.toContain('secret-token');
    expect(logs.output()).not.toContain('session=secret');
    expect(logs.output()).not.toContain('proxy-secret');
    expect(logs.output()).toContain('[Redacted]');
    await app.close();
  });

  it('rejects disallowed CORS origins', async () => {
    const logs = collectingLogger();
    const app = await buildApi({
      config: testConfig(),
      logger: logs.logger,
      checkDatabaseReady: async () => ({ ok: true }),
    });
    const response = await app.inject({
      method: 'GET',
      url: '/health/live',
      headers: {
        origin: 'https://evil.example',
      },
    });
    expect(response.headers['access-control-allow-origin']).not.toBe('https://evil.example');
    await app.close();
  });

  it('enforces the request body limit', async () => {
    const logs = collectingLogger();
    const config = testConfig();
    const app = await buildApi({
      config,
      logger: logs.logger,
      checkDatabaseReady: async () => ({ ok: true }),
    });
    const response = await app.inject({
      method: 'POST',
      url: '/health/live',
      headers: {
        'content-type': 'application/json',
      },
      payload: 'x'.repeat(config.requestBodyLimitBytes + 16),
    });
    expect(response.statusCode).toBe(413);
    expect(response.json()).toMatchObject({
      error: {
        code: 'validation',
      },
    });
    await app.close();
  });

  it('keeps trustProxy disabled so X-Forwarded-For cannot select the login key', async () => {
    const logs = collectingLogger();
    const app = await buildApi({
      config: testConfig(),
      logger: logs.logger,
      checkDatabaseReady: async () => ({ ok: true }),
    });
    app.get('/__peer-ip', async (request) => ({ ip: request.ip }));
    const response = await app.inject({
      method: 'GET',
      url: '/__peer-ip',
      remoteAddress: '192.0.2.10',
      headers: {
        'x-forwarded-for': '203.0.113.9',
      },
    });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({ ip: '192.0.2.10' });
    await app.close();
  });
});
