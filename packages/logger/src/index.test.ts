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
            'content-disposition': 'attachment; filename="bom.json"',
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
        accessKey: 'object-storage-access',
        accessKeyId: 'AKIA-not-a-real-key',
        objectKey: 'org/secret-object-key',
        temporaryObjectKey: 'org/secret-temporary-key',
        finalObjectKey: 'org/secret-final-key',
        CopySource: 'bucket/org/secret-copy-source',
        copySource: 'bucket/org/secret-copy-source-alt',
        signedUrl: 'https://minio.example/object?X-Amz-Signature=abc',
        password: 'plaintext-db-password',
        passwordHash: '$argon2id$v=19$m=19456,t=2,p=1$compattesthash',
        phc: '$argon2id$v=19$m=19456,t=2,p=1$compattesthash',
        csrfToken: 'raw-csrf-token-value',
        csrfTokenHash: 'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
        tokenHash: 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
        sessionToken: 'raw-session-token-value',
        idempotencyKey: 'raw-idempotency-header-value',
        rawKey: 'raw-idempotency-secret',
        filename: 'bom.json',
        originalFilename: 'customer-bom.json',
        peerIp: '192.0.2.10',
        accountDigest: 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
        providerUrl:
          'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
        sourceUrl:
          'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
        responseHeaders: { etag: '"raw-provider-etag"', 'retry-after': '120' },
        etag: '"raw-provider-etag"',
        lastModified: 'Mon, 31 Aug 2026 16:00:00 GMT',
        temporarySnapshotKey:
          'intelligence/cisa_kev/cisa_kev_json_catalog/tmp/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
        finalSnapshotKey:
          'intelligence/cisa_kev/cisa_kev_json_catalog/sha256/ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
        conditionalValidator: '"raw-provider-etag"',
        dnsAddresses: ['203.0.113.10', '2001:db8::1'],
        credential: { passwordHash: '$argon2id$v=19$m=19456,p=1,t=2$nestedcredhashvalue' },
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
    expect(output).not.toContain('object-storage-access');
    expect(output).not.toContain('AKIA-not-a-real-key');
    expect(output).not.toContain('secret-object-key');
    expect(output).not.toContain('secret-temporary-key');
    expect(output).not.toContain('secret-final-key');
    expect(output).not.toContain('secret-copy-source');
    expect(output).not.toContain('X-Amz-Signature=abc');
    expect(output).not.toContain('plaintext-db-password');
    expect(output).not.toContain('$argon2id$v=19$m=19456,t=2,p=1$compattesthash');
    expect(output).not.toContain('raw-csrf-token-value');
    expect(output).not.toContain('raw-session-token-value');
    expect(output).not.toContain('raw-idempotency-header-value');
    expect(output).not.toContain('raw-idempotency-secret');
    expect(output).not.toContain('bom.json');
    expect(output).not.toContain('customer-bom.json');
    expect(output).not.toContain('192.0.2.10');
    expect(output).not.toContain('known_exploited_vulnerabilities.json');
    expect(output).not.toContain('raw-provider-etag');
    expect(output).not.toContain('Mon, 31 Aug 2026 16:00:00 GMT');
    expect(output).not.toContain('intelligence/cisa_kev');
    expect(output).not.toContain('203.0.113.10');
    expect(output).not.toContain('2001:db8::1');
    expect(output).not.toContain(
      'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee',
    );
    expect(output).not.toContain(
      'cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc',
    );
    expect(output).not.toContain(
      'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
    );
    expect(output).not.toContain('nestedcredhashvalue');
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
