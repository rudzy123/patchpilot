import { createHash, randomUUID } from 'node:crypto';
import { Readable } from 'node:stream';

import {
  CopyObjectCommand,
  GetObjectCommand,
  HeadObjectCommand,
  PutObjectCommand,
  S3Client,
} from '@aws-sdk/client-s3';
import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  createS3OsvAdvisoryObjectStorage,
  isCompiledOsvS3ObjectKey,
  type OsvS3Locator,
  type S3OsvAdvisoryObjectStorageConfig,
} from './s3-osv-advisory-object-storage.js';
import type { ObjectStorageLogger } from './s3-sbom-object-storage.js';

const PAYLOAD = new TextEncoder().encode('{"synthetic":"osv-storage"}');
const DIGEST = createHash('sha256').update(PAYLOAD).digest('hex');
const UPLOAD = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';

const send = vi.spyOn(S3Client.prototype, 'send');

afterEach(() => {
  send.mockReset();
});

function testConfig(
  overrides: Partial<S3OsvAdvisoryObjectStorageConfig> = {},
): S3OsvAdvisoryObjectStorageConfig {
  return {
    endpoint: 'http://127.0.0.1:19000',
    region: 'us-east-1',
    accessKey: 'test-access',
    secretKey: 'test-secret',
    bucket: 'patchpilot-dev',
    useSsl: false,
    connectionTimeoutMs: 3000,
    operationTimeoutMs: 30_000,
    deploymentEnvironment: 'test',
    allowDevelopmentAdapters: true,
    ...overrides,
  };
}

function collectingLogger(): {
  logger: ObjectStorageLogger;
  records: Array<Record<string, unknown>>;
} {
  const records: Array<Record<string, unknown>> = [];
  return {
    records,
    logger: {
      info: (bindings) => {
        records.push(bindings);
      },
      warn: (bindings) => {
        records.push(bindings);
      },
      error: (bindings) => {
        records.push(bindings);
      },
    },
  };
}

function notFound(): Error {
  const error = new Error('provider text');
  error.name = 'NotFound';
  Object.assign(error, { $metadata: { httpStatusCode: 404 } });
  return error;
}

function tmpLocator(uploadId = UPLOAD): OsvS3Locator {
  return {
    kind: 'osv_object_storage_locator',
    storageKind: 'advisory_body',
    role: 'temporary',
    objectKey: `intelligence/osv/advisory_body/tmp/${uploadId}`,
    contentSha256: null,
    uploadId,
  };
}

function finalLocator(digest = DIGEST): OsvS3Locator {
  return {
    kind: 'osv_object_storage_locator',
    storageKind: 'advisory_body',
    role: 'final',
    objectKey: `intelligence/osv/advisory_body/sha256/${digest}`,
    contentSha256: digest,
    uploadId: null,
  };
}

function metadata() {
  return {
    'content-sha256': DIGEST,
    'byte-length': String(PAYLOAD.byteLength),
    'artifact-category': 'advisory_body',
    'content-encoding': 'identity',
    'storage-layout-version': 'osv_object_storage_layout_v1',
  };
}

describe('S3OsvAdvisoryObjectStorage identity', () => {
  it('compiles opaque locators and rejects provider keys, URLs, and traversal', () => {
    expect(isCompiledOsvS3ObjectKey(finalLocator().objectKey)).toBe(true);
    expect(isCompiledOsvS3ObjectKey(tmpLocator().objectKey)).toBe(true);
    expect(isCompiledOsvS3ObjectKey('intelligence/osv/advisory_body/tmp/../secret')).toBe(false);
    expect(isCompiledOsvS3ObjectKey('npm/GHSA-aaaa-bbbb-cccc.json')).toBe(false);
    expect(isCompiledOsvS3ObjectKey('https://storage.googleapis.com/osv-vulnerabilities/o')).toBe(
      false,
    );
  });
});

describe('S3OsvAdvisoryObjectStorage write-once', () => {
  it('puts with IfNoneMatch, no ACL, and no signed URL', async () => {
    send.mockImplementation(async (command) => {
      if (command instanceof HeadObjectCommand) {
        throw notFound();
      }
      expect(command).toBeInstanceOf(PutObjectCommand);
      const input = (command as PutObjectCommand).input;
      expect(input.ACL).toBeUndefined();
      expect(input.IfNoneMatch).toBe('*');
      expect(input.GrantRead).toBeUndefined();
      expect(input.ContentType).toBe('application/json');
      expect(input.Metadata?.['content-sha256']).toBe(DIGEST);
      return {};
    });
    const collected = collectingLogger();
    const storage = createS3OsvAdvisoryObjectStorage(testConfig(), {
      logger: collected.logger,
      correlationId: randomUUID(),
    });
    const result = await storage.putExclusive({
      locator: tmpLocator(),
      body: PAYLOAD,
      contentSha256: DIGEST,
      byteCount: PAYLOAD.byteLength,
      contentType: 'application/json',
      contentEncoding: 'identity',
      artifactCategory: 'advisory_body',
    });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.status).toBe('created');
    }
    const serialized = JSON.stringify(collected.records);
    expect(serialized).not.toContain('intelligence/osv');
    expect(serialized).not.toContain('127.0.0.1');
    expect(serialized).not.toContain('test-secret');
    expect(serialized).not.toContain('GHSA');
    storage.destroy();
  });

  it('returns already_applied for identical bytes and immutable_conflict for different bytes', async () => {
    send.mockImplementation(async (command) => {
      if (command instanceof GetObjectCommand) {
        return {
          ContentLength: PAYLOAD.byteLength,
          ContentType: 'application/json',
          Body: Readable.from([PAYLOAD]),
          Metadata: metadata(),
        };
      }
      expect(command).toBeInstanceOf(HeadObjectCommand);
      return {
        ContentLength: PAYLOAD.byteLength,
        ContentType: 'application/json',
        Metadata: metadata(),
      };
    });
    const storage = createS3OsvAdvisoryObjectStorage(testConfig());
    const same = await storage.putExclusive({
      locator: finalLocator(),
      body: PAYLOAD,
      contentSha256: DIGEST,
      byteCount: PAYLOAD.byteLength,
      contentType: 'application/json',
      contentEncoding: 'identity',
      artifactCategory: 'advisory_body',
    });
    expect(same.ok).toBe(true);
    if (same.ok) {
      expect(same.value.status).toBe('already_applied');
    }
    expect(send.mock.calls.some((call) => call[0] instanceof PutObjectCommand)).toBe(false);

    send.mockReset();
    send.mockImplementation(async (command) => {
      expect(command).toBeInstanceOf(HeadObjectCommand);
      return {
        ContentLength: 3,
        ContentType: 'application/json',
        Metadata: {
          ...metadata(),
          'content-sha256': 'b'.repeat(64),
          'byte-length': '3',
        },
      };
    });
    const conflict = await storage.putExclusive({
      locator: finalLocator(),
      body: PAYLOAD,
      contentSha256: DIGEST,
      byteCount: PAYLOAD.byteLength,
      contentType: 'application/json',
      contentEncoding: 'identity',
      artifactCategory: 'advisory_body',
    });
    expect(conflict.ok).toBe(false);
    if (!conflict.ok) {
      expect(conflict.code).toBe('immutable_conflict');
    }
    storage.destroy();
  });

  it('rejects hash mismatch, caller path override, and provider-key locators before write', async () => {
    const storage = createS3OsvAdvisoryObjectStorage(testConfig());
    const mismatch = await storage.putExclusive({
      locator: tmpLocator(),
      body: PAYLOAD,
      contentSha256: 'b'.repeat(64),
      byteCount: PAYLOAD.byteLength,
      contentType: 'application/json',
      contentEncoding: 'identity',
      artifactCategory: 'advisory_body',
    });
    expect(mismatch.ok).toBe(false);
    expect(send).not.toHaveBeenCalled();
    const traversal = await storage.putExclusive({
      locator: {
        ...tmpLocator(),
        objectKey: 'intelligence/osv/advisory_body/tmp/../secret',
      },
      body: PAYLOAD,
      contentSha256: DIGEST,
      byteCount: PAYLOAD.byteLength,
      contentType: 'application/json',
      contentEncoding: 'identity',
      artifactCategory: 'advisory_body',
    });
    expect(traversal.ok).toBe(false);
    const providerKey = await storage.putExclusive({
      locator: {
        kind: 'osv_object_storage_locator',
        storageKind: 'advisory_body',
        role: 'final',
        objectKey: 'npm/GHSA-aaaa-bbbb-cccc.json',
        contentSha256: DIGEST,
        uploadId: null,
      },
      body: PAYLOAD,
      contentSha256: DIGEST,
      byteCount: PAYLOAD.byteLength,
      contentType: 'application/json',
      contentEncoding: 'identity',
      artifactCategory: 'advisory_body',
    });
    expect(providerKey.ok).toBe(false);
    storage.destroy();
  });

  it('copies with IfNoneMatch and verifies destination metadata without treating ETag as SHA-256', async () => {
    send.mockImplementation(async (command) => {
      if (command instanceof HeadObjectCommand) {
        const key = (command as HeadObjectCommand).input.Key;
        if (key === finalLocator().objectKey) {
          const prior = send.mock.calls.filter((call) => call[0] instanceof CopyObjectCommand);
          if (prior.length === 0) {
            throw notFound();
          }
          return {
            ContentLength: PAYLOAD.byteLength,
            ContentType: 'application/json',
            ETag: '"multipart-etag-not-sha256"',
            Metadata: metadata(),
          };
        }
        throw notFound();
      }
      expect(command).toBeInstanceOf(CopyObjectCommand);
      expect((command as CopyObjectCommand).input.IfNoneMatch).toBe('*');
      expect((command as CopyObjectCommand).input.ACL).toBeUndefined();
      return {};
    });
    const storage = createS3OsvAdvisoryObjectStorage(testConfig());
    const copied = await storage.copyExclusive({
      source: tmpLocator(),
      destination: finalLocator(),
      expectedSha256: DIGEST,
      expectedByteCount: PAYLOAD.byteLength,
      contentType: 'application/json',
      contentEncoding: 'identity',
      artifactCategory: 'advisory_body',
    });
    expect(copied.ok).toBe(true);
    storage.destroy();
  });

  it('hashes stored bytes on read-back and rejects oversized declared length', async () => {
    send.mockImplementation(async (command) => {
      expect(command).toBeInstanceOf(GetObjectCommand);
      return {
        ContentLength: PAYLOAD.byteLength,
        ContentType: 'application/json',
        ETag: '"not-a-sha256"',
        Body: Readable.from([PAYLOAD]),
        Metadata: metadata(),
      };
    });
    const storage = createS3OsvAdvisoryObjectStorage(testConfig());
    const verified = await storage.getVerified({
      locator: finalLocator(),
      expectedSha256: DIGEST,
      expectedByteCount: PAYLOAD.byteLength,
      expectedContentType: 'application/json',
      expectedContentEncoding: 'identity',
      maxBytes: 1024,
    });
    expect(verified.ok).toBe(true);
    if (verified.ok) {
      expect(verified.value.sha256).toBe(DIGEST);
      expect(verified.value.byteCount).toBe(PAYLOAD.byteLength);
    }

    send.mockReset();
    send.mockImplementation(async (command) => {
      expect(command).toBeInstanceOf(GetObjectCommand);
      return {
        ContentLength: 9_000_000,
        ContentType: 'application/json',
        Body: Readable.from([PAYLOAD]),
        Metadata: metadata(),
      };
    });
    const oversized = await storage.getVerified({
      locator: finalLocator(),
      expectedSha256: DIGEST,
      expectedByteCount: PAYLOAD.byteLength,
      expectedContentType: 'application/json',
      expectedContentEncoding: 'identity',
      maxBytes: 1024,
    });
    expect(oversized.ok).toBe(false);
    if (!oversized.ok) {
      expect(oversized.code).toBe('response_too_large');
      expect(JSON.stringify(oversized)).not.toContain('intelligence/osv');
    }
    storage.destroy();
  });
});
