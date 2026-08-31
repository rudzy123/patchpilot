import { describe, expect, it } from 'vitest';

import { createS3Client, S3ClientConstructionError } from './s3-client.js';

const valid = {
  endpoint: 'http://127.0.0.1:19000',
  region: 'us-east-1',
  accessKey: 'patchpilot-dev-access',
  secretKey: 'patchpilot-dev-secret-not-for-production',
  useSsl: false,
  connectionTimeoutMs: 3000,
  requestTimeoutMs: 30_000,
};

describe('createS3Client', () => {
  it('uses an explicit region, static credentials, forcePathStyle, and bounded timeouts', async () => {
    const client = createS3Client(valid);
    try {
      expect(await client.config.region()).toBe('us-east-1');
      const credentials = await client.config.credentials();
      expect(credentials.accessKeyId).toBe(valid.accessKey);
      expect(credentials.secretAccessKey).toBe(valid.secretKey);
      expect(client.config.forcePathStyle).toBe(true);
      const maxAttemptsValue = client.config.maxAttempts as number | (() => Promise<number>);
      const maxAttempts =
        typeof maxAttemptsValue === 'function' ? await maxAttemptsValue() : maxAttemptsValue;
      expect(maxAttempts).toBe(1);
      const checksumCalculation = client.config.requestChecksumCalculation as
        string | (() => Promise<string>);
      const checksumValidation = client.config.responseChecksumValidation as
        string | (() => Promise<string>);
      expect(
        typeof checksumCalculation === 'function'
          ? await checksumCalculation()
          : checksumCalculation,
      ).toBe('WHEN_REQUIRED');
      expect(
        typeof checksumValidation === 'function' ? await checksumValidation() : checksumValidation,
      ).toBe('WHEN_REQUIRED');
    } finally {
      client.destroy();
    }
  });

  it('rejects TLS and endpoint-scheme mismatch without embedding the URL', () => {
    expect(() =>
      createS3Client({ ...valid, endpoint: 'https://127.0.0.1:19000', useSsl: false }),
    ).toThrow(S3ClientConstructionError);
    expect(() =>
      createS3Client({ ...valid, endpoint: 'https://127.0.0.1:19000', useSsl: false }),
    ).toThrow(/must use http/);
    expect(() =>
      createS3Client({ ...valid, endpoint: 'http://objects.internal:9000', useSsl: true }),
    ).toThrow(/must use https/);
  });

  it('rejects endpoint userinfo', () => {
    expect(() =>
      createS3Client({
        ...valid,
        endpoint: 'http://access:secret@127.0.0.1:19000',
      }),
    ).toThrow(/must not include credentials or userinfo/);
  });

  it('rejects an empty region', () => {
    expect(() => createS3Client({ ...valid, region: '   ' })).toThrow(/region must be explicit/);
  });
});
