/**
 * Session 11 Batch 5F adversarial unit tests for the S3 OSV adapter.
 * Synthetic bytes only. No live provider bodies.
 */

import { createHash } from 'node:crypto';
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

const PAYLOAD = new TextEncoder().encode('{"synthetic":"osv-storage"}');
const DIGEST = createHash('sha256').update(PAYLOAD).digest('hex');
const UPLOAD = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const OTHER = new TextEncoder().encode('{"synthetic":"other"}');
const OTHER_DIGEST = createHash('sha256').update(OTHER).digest('hex');

const send = vi.spyOn(S3Client.prototype, 'send');

afterEach(() => {
  send.mockReset();
});

function testConfig(): S3OsvAdvisoryObjectStorageConfig {
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
  };
}

function precondition(status: 409 | 412): Error {
  const error = new Error('precondition');
  Object.assign(error, { $metadata: { httpStatusCode: status } });
  return error;
}

function notFound(): Error {
  const error = new Error('not found');
  error.name = 'NotFound';
  Object.assign(error, { $metadata: { httpStatusCode: 404 } });
  return error;
}

function tmpLocator(): OsvS3Locator {
  return {
    kind: 'osv_object_storage_locator',
    storageKind: 'advisory_body',
    role: 'temporary',
    objectKey: `intelligence/osv/advisory_body/tmp/${UPLOAD}`,
    contentSha256: null,
    uploadId: UPLOAD,
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

function parsedFinal(digest = DIGEST): OsvS3Locator {
  return {
    kind: 'osv_object_storage_locator',
    storageKind: 'parsed_advisory',
    role: 'final',
    objectKey: `intelligence/osv/parsed_advisory/sha256/${digest}`,
    contentSha256: digest,
    uploadId: null,
  };
}

function metadata(overrides: Record<string, string> = {}) {
  return {
    'content-sha256': DIGEST,
    'byte-length': String(PAYLOAD.byteLength),
    'artifact-category': 'advisory_body',
    'content-encoding': 'identity',
    'storage-layout-version': 'osv_object_storage_layout_v1',
    ...overrides,
  };
}

describe('Session 11 Batch 5F S3 adapter identity and write-once', () => {
  it('rejects percent-encoded traversal and category spoofing before send', async () => {
    const storage = createS3OsvAdvisoryObjectStorage(testConfig());
    expect(isCompiledOsvS3ObjectKey('intelligence/osv/advisory_body/tmp/%2e%2e')).toBe(false);
    const spoofed = await storage.putExclusive({
      locator: tmpLocator(),
      body: PAYLOAD,
      contentSha256: DIGEST,
      byteCount: PAYLOAD.byteLength,
      contentType: 'application/json',
      contentEncoding: 'identity',
      artifactCategory: 'parsed_advisory',
    });
    expect(spoofed.ok).toBe(false);
    expect(send).not.toHaveBeenCalled();
    const oversize = await storage.putExclusive({
      locator: tmpLocator(),
      body: new Uint8Array(1_048_577),
      contentSha256: 'a'.repeat(64),
      byteCount: 1_048_577,
      contentType: 'application/json',
      contentEncoding: 'identity',
      artifactCategory: 'advisory_body',
    });
    expect(oversize.ok).toBe(false);
    expect(send).not.toHaveBeenCalled();
    storage.destroy();
  });

  it('treats 409 and 412 as compare-not-overwrite and verifies bytes', async () => {
    send.mockImplementation(async (command) => {
      if (command instanceof HeadObjectCommand) {
        throw notFound();
      }
      if (command instanceof PutObjectCommand) {
        throw precondition(409);
      }
      expect(command).toBeInstanceOf(GetObjectCommand);
      return {
        ContentLength: PAYLOAD.byteLength,
        ContentType: 'application/json',
        Body: Readable.from([PAYLOAD]),
        Metadata: metadata(),
        ETag: '"multipart-not-sha256"',
      };
    });
    const storage = createS3OsvAdvisoryObjectStorage(testConfig());
    const same = await storage.putExclusive({
      locator: tmpLocator(),
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

    send.mockReset();
    send.mockImplementation(async (command) => {
      if (command instanceof HeadObjectCommand) {
        throw notFound();
      }
      if (command instanceof PutObjectCommand) {
        throw precondition(412);
      }
      return {
        ContentLength: OTHER.byteLength,
        ContentType: 'application/json',
        Body: Readable.from([OTHER]),
        Metadata: metadata({
          'content-sha256': OTHER_DIGEST,
          'byte-length': String(OTHER.byteLength),
        }),
      };
    });
    const conflict = await storage.putExclusive({
      locator: tmpLocator(),
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

  it('does not treat matching HEAD metadata as identity when GET bytes differ', async () => {
    send.mockImplementation(async (command) => {
      if (command instanceof HeadObjectCommand) {
        return {
          ContentLength: PAYLOAD.byteLength,
          ContentType: 'application/json',
          Metadata: metadata(),
        };
      }
      expect(command).toBeInstanceOf(GetObjectCommand);
      return {
        ContentLength: PAYLOAD.byteLength,
        ContentType: 'application/json',
        Body: Readable.from([OTHER]),
        Metadata: metadata(),
      };
    });
    const storage = createS3OsvAdvisoryObjectStorage(testConfig());
    const result = await storage.putExclusive({
      locator: finalLocator(),
      body: PAYLOAD,
      contentSha256: DIGEST,
      byteCount: PAYLOAD.byteLength,
      contentType: 'application/json',
      contentEncoding: 'identity',
      artifactCategory: 'advisory_body',
    });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe('immutable_conflict');
    }
    expect(send.mock.calls.some((call) => call[0] instanceof PutObjectCommand)).toBe(false);
    storage.destroy();
  });

  it('rejects extra stream bytes, missing content type, and unbounded maxBytes', async () => {
    send.mockImplementation(async () => ({
      ContentLength: PAYLOAD.byteLength + 1,
      ContentType: 'application/json',
      Body: Readable.from([PAYLOAD, new Uint8Array([0])]),
      Metadata: metadata(),
    }));
    const storage = createS3OsvAdvisoryObjectStorage(testConfig());
    const extra = await storage.getVerified({
      locator: finalLocator(),
      expectedSha256: DIGEST,
      expectedByteCount: PAYLOAD.byteLength,
      expectedContentType: 'application/json',
      expectedContentEncoding: 'identity',
      maxBytes: 1024,
    });
    expect(extra.ok).toBe(false);

    send.mockReset();
    send.mockImplementation(async () => ({
      ContentLength: PAYLOAD.byteLength,
      Body: Readable.from([PAYLOAD]),
      Metadata: metadata(),
    }));
    const missingType = await storage.getVerified({
      locator: finalLocator(),
      expectedSha256: DIGEST,
      expectedByteCount: PAYLOAD.byteLength,
      expectedContentType: 'application/json',
      expectedContentEncoding: 'identity',
      maxBytes: 1024,
    });
    expect(missingType.ok).toBe(false);
    if (!missingType.ok) {
      expect(missingType.code).toBe('content_type_mismatch');
    }

    const unbounded = await storage.getVerified({
      locator: finalLocator(),
      expectedSha256: DIGEST,
      expectedByteCount: PAYLOAD.byteLength,
      expectedContentType: 'application/json',
      expectedContentEncoding: 'identity',
      maxBytes: 2_000_000,
    });
    expect(unbounded.ok).toBe(false);
    storage.destroy();
  });

  it('refuses to delete attached objects and keeps categories distinct', async () => {
    const storage = createS3OsvAdvisoryObjectStorage(testConfig());
    const deleted = await storage.deleteTemporary({ locator: finalLocator() });
    expect(deleted.ok).toBe(false);
    expect(send).not.toHaveBeenCalled();
    expect(finalLocator().objectKey).not.toBe(parsedFinal().objectKey);
    storage.destroy();
  });

  it('omits locators, buckets, and credentials from public failures', async () => {
    send.mockImplementation(async () => {
      throw Object.assign(new Error('AccessDenied'), { $metadata: { httpStatusCode: 403 } });
    });
    const storage = createS3OsvAdvisoryObjectStorage(testConfig());
    const result = await storage.head({ locator: finalLocator() });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      const serialized = JSON.stringify(result);
      expect(serialized).not.toContain('intelligence/osv');
      expect(serialized).not.toContain('patchpilot-dev');
      expect(serialized).not.toContain('test-secret');
      expect(serialized).not.toContain('127.0.0.1');
      expect(Object.keys(result).sort()).toEqual(['code', 'ok', 'retryability']);
    }
    storage.destroy();
  });

  it('copies with IfNoneMatch and compares on 409 rather than overwriting', async () => {
    send.mockImplementation(async (command) => {
      if (command instanceof HeadObjectCommand) {
        throw notFound();
      }
      if (command instanceof CopyObjectCommand) {
        expect((command as CopyObjectCommand).input.IfNoneMatch).toBe('*');
        throw precondition(409);
      }
      return {
        ContentLength: PAYLOAD.byteLength,
        ContentType: 'application/json',
        Body: Readable.from([PAYLOAD]),
        Metadata: metadata(),
      };
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
    if (copied.ok) {
      expect(copied.value.status).toBe('already_applied');
    }
    storage.destroy();
  });
});

describe('Session 11 Batch 5F S3 client configuration isolation', () => {
  it('does not accept advisory-driven bucket, endpoint, or ACL fields on commands', async () => {
    send.mockImplementation(async (command) => {
      if (command instanceof HeadObjectCommand) {
        throw notFound();
      }
      const input = (command as PutObjectCommand).input;
      expect(input.Bucket).toBe('patchpilot-dev');
      expect(input.ACL).toBeUndefined();
      expect(input.GrantReadACP).toBeUndefined();
      return {};
    });
    const storage = createS3OsvAdvisoryObjectStorage(testConfig());
    await storage.putExclusive({
      locator: tmpLocator(),
      body: PAYLOAD,
      contentSha256: DIGEST,
      byteCount: PAYLOAD.byteLength,
      contentType: 'application/json',
      contentEncoding: 'identity',
      artifactCategory: 'advisory_body',
    });
    storage.destroy();
  });
});
