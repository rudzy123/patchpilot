import { Writable } from 'node:stream';

import { describe, expect, it } from 'vitest';

import { createChildLogger, createLogger } from './index.js';

function collectLogs(): { stream: Writable; lines: () => string[] } {
  const chunks: Array<Buffer | string> = [];
  const stream = new Writable({
    write(chunk, _encoding, callback) {
      chunks.push(chunk as Buffer | string);
      callback();
    },
  });

  return {
    stream,
    lines: () =>
      chunks
        .join('')
        .split('\n')
        .filter((line) => line.length > 0),
  };
}

describe('logger redaction', () => {
  it('redacts authorization, cookies, tokens, and storage secrets', () => {
    const collected = collectLogs();
    const logger = createLogger({
      service: 'test',
      level: 'info',
      pretty: false,
      destination: collected.stream,
    });

    logger.info(
      {
        req: {
          method: 'GET',
          url: '/health/live',
          headers: {
            authorization: 'Bearer super-secret-access-token',
            cookie: 'session=secret-session-cookie',
            'set-cookie': 'session=secret-session-cookie',
            'proxy-authorization': 'Basic proxy-secret',
            'x-storage-secret': 'header-secret-value',
            'x-amz-signature': 'signed-query-secret',
            'x-request-id': 'req-1',
          },
          body: { shouldNotAppearIfSerialized: true },
        },
        accessToken: 'access-token-value',
        refreshToken: 'refresh-token-value',
        apiKey: 'api-key-value',
        githubToken: 'ghs_exampletoken',
        secretAccessKey: 'minio-secret-key',
        secretKey: 'object-storage-secret',
        signedUrl: 'https://minio.example/object?X-Amz-Signature=abc',
        password: 'plaintext-db-password',
        databaseUrl: 'postgresql://patchpilot:operator-secret@db.internal:5432/patchpilot',
        DATABASE_URL: 'postgresql://patchpilot:operator-secret@db.internal:5432/patchpilot',
        redisUrl: 'redis://:operator-redis-secret@redis.internal:6379',
      },
      'request',
    );

    const output = collected.lines().join('\n');
    expect(output).toContain('[Redacted]');
    expect(output).not.toContain('Bearer super-secret-access-token');
    expect(output).not.toContain('secret-session-cookie');
    expect(output).not.toContain('proxy-secret');
    expect(output).not.toContain('header-secret-value');
    expect(output).not.toContain('signed-query-secret');
    expect(output).not.toContain('access-token-value');
    expect(output).not.toContain('refresh-token-value');
    expect(output).not.toContain('api-key-value');
    expect(output).not.toContain('ghs_exampletoken');
    expect(output).not.toContain('minio-secret-key');
    expect(output).not.toContain('object-storage-secret');
    expect(output).not.toContain('X-Amz-Signature=abc');
    expect(output).not.toContain('plaintext-db-password');
    expect(output).not.toContain('operator-secret');
    expect(output).not.toContain('operator-redis-secret');
    expect(output).not.toContain('postgresql://');
    expect(output).not.toContain('shouldNotAppearIfSerialized');
  });

  it('does not log complete environment objects', () => {
    const collected = collectLogs();
    const logger = createLogger({
      service: 'test',
      level: 'info',
      pretty: false,
      destination: collected.stream,
    });

    logger.info({ env: { DATABASE_URL: 'postgresql://example', SECRET: 'shh' } }, 'env dump');
    const output = collected.lines().join('\n');
    expect(output).toContain('[Redacted]');
    expect(output).not.toContain('postgresql://example');
    expect(output).not.toContain('shh');
  });

  it('creates child loggers with request and correlation ids', () => {
    const collected = collectLogs();
    const logger = createLogger({
      service: 'test',
      level: 'info',
      pretty: false,
      destination: collected.stream,
    });
    const child = createChildLogger(logger, {
      requestId: 'req-123',
      correlationId: 'corr-123',
    });
    child.info('child message');
    const output = collected.lines().join('\n');
    expect(output).toContain('req-123');
    expect(output).toContain('corr-123');
  });
});
