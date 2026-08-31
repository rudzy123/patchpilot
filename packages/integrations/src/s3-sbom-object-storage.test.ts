import { createHash } from 'node:crypto';
import { Readable } from 'node:stream';
import { finished } from 'node:stream/promises';

import {
  CopyObjectCommand,
  CreateBucketCommand,
  DeleteObjectCommand,
  GetObjectCommand,
  HeadObjectCommand,
  PutObjectCommand,
  S3Client,
} from '@aws-sdk/client-s3';
import { buildFinalSbomObjectKey, buildTemporarySbomObjectKey } from '@patchpilot/domain';
import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  createS3SbomObjectStorage,
  type ObjectStorageLogger,
  type S3SbomObjectStorageConfig,
} from './s3-sbom-object-storage.js';

const ORG = '11111111-1111-4111-8111-111111111111';
const ASSET = '22222222-2222-4222-8222-222222222222';
const UPLOAD = '33333333-3333-4333-8333-333333333333';

const temporaryKey = buildTemporarySbomObjectKey({
  organizationId: ORG,
  assetId: ASSET,
  uploadId: UPLOAD,
});
const finalKey = buildFinalSbomObjectKey({
  organizationId: ORG,
  assetId: ASSET,
  sha256: 'a'.repeat(64),
});

const send = vi.spyOn(S3Client.prototype, 'send');

afterEach(() => {
  send.mockReset();
});

function testConfig(overrides: Partial<S3SbomObjectStorageConfig> = {}): S3SbomObjectStorageConfig {
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

function notFound(name = 'NotFound'): Error {
  const error = new Error('provider text');
  error.name = name;
  Object.assign(error, { $metadata: { httpStatusCode: 404 } });
  return error;
}

async function drainBody(command: { input?: { Body?: unknown } }): Promise<void> {
  const body = command.input?.Body;
  if (body instanceof Readable) {
    body.resume();
    await finished(body);
  }
}

describe('S3SbomObjectStorage', () => {
  it('refuses temporary and final key-shape misuse without sending commands', async () => {
    send.mockResolvedValue({} as never);
    const storage = createS3SbomObjectStorage(testConfig());
    const put = await storage.putTemporaryObject({
      temporaryObjectKey: finalKey,
      body: Readable.from([Buffer.from('{}')]),
      contentType: 'application/json',
      maxBytes: 1024,
    });
    const head = await storage.headFinalObject({ finalObjectKey: temporaryKey });
    const get = await storage.getObject({
      finalObjectKey: temporaryKey,
      maxBytes: 1024,
    });
    const del = await storage.deleteTemporaryObject({ temporaryObjectKey: finalKey });
    expect(put).toEqual({ ok: false, error: { category: 'internal' } });
    expect(head).toEqual({ ok: false, error: { category: 'internal' } });
    expect(get).toEqual({ ok: false, error: { category: 'internal' } });
    expect(del).toEqual({ ok: false, error: { category: 'internal' } });
    expect(send).not.toHaveBeenCalled();
    storage.destroy();
  });

  it('rejects declaredByteLength below one or above maxBytes before PutObject', async () => {
    send.mockResolvedValue({} as never);
    const storage = createS3SbomObjectStorage(testConfig());
    const tooSmall = await storage.putTemporaryObject({
      temporaryObjectKey: temporaryKey,
      body: Readable.from([Buffer.from('{}')]),
      contentType: 'application/json',
      maxBytes: 1024,
      declaredByteLength: 0,
    });
    const tooLarge = await storage.putTemporaryObject({
      temporaryObjectKey: temporaryKey,
      body: Readable.from([Buffer.from('{}')]),
      contentType: 'application/json',
      maxBytes: 8,
      declaredByteLength: 9,
    });
    expect(tooSmall).toEqual({ ok: false, error: { category: 'invalid_content' } });
    expect(tooLarge).toEqual({ ok: false, error: { category: 'size_limit' } });
    expect(send).not.toHaveBeenCalled();
    storage.destroy();
  });

  it('sends one PutObject without ACL and returns the digest after the stream ends', async () => {
    send.mockImplementation(async (command) => {
      expect(command).toBeInstanceOf(PutObjectCommand);
      expect((command as PutObjectCommand).input.ACL).toBeUndefined();
      expect((command as PutObjectCommand).input.ContentLength).toBe(
        Buffer.byteLength('{"bomFormat":"CycloneDX"}'),
      );
      await drainBody(command as PutObjectCommand);
      return {};
    });
    const storage = createS3SbomObjectStorage(testConfig());
    const result = await storage.putTemporaryObject({
      temporaryObjectKey: temporaryKey,
      body: Readable.from([Buffer.from('{"bomFormat":"CycloneDX"}')]),
      contentType: 'application/json',
      maxBytes: 1024,
      declaredByteLength: Buffer.byteLength('{"bomFormat":"CycloneDX"}'),
    });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.observedByteLength).toBe(Buffer.byteLength('{"bomFormat":"CycloneDX"}'));
      expect(result.value.sha256).toMatch(/^[a-f0-9]{64}$/);
    }

    expect(send).toHaveBeenCalledTimes(1);
    storage.destroy();
  });

  it('promotes with CopyObject REPLACE and does not GetObject the temporary body', async () => {
    const digest = 'a'.repeat(64);
    const names: string[] = [];
    send.mockImplementation(async (command) => {
      names.push(command.constructor.name);
      if (command instanceof HeadObjectCommand) {
        if (names.filter((name) => name === 'HeadObjectCommand').length === 1) {
          throw notFound('NoSuchKey');
        }

        return {
          ContentLength: 2,
          ContentType: 'application/json',
          Metadata: { sha256: digest, 'byte-length': '2' },
        };
      }

      if (command instanceof CopyObjectCommand) {
        expect(command.input.ACL).toBeUndefined();
        expect(command.input.MetadataDirective).toBe('REPLACE');
        expect(command.input.ContentType).toBe('application/json');
        expect(command.input.Metadata).toEqual({
          sha256: digest,
          'byte-length': '2',
        });
        expect(command.input.CopySource).toContain(temporaryKey);
        return {};
      }

      if (command instanceof DeleteObjectCommand) {
        return {};
      }

      throw new Error(`unexpected ${command.constructor.name}`);
    });

    const storage = createS3SbomObjectStorage(testConfig());
    const result = await storage.promoteTemporaryObject({
      temporaryObjectKey: temporaryKey,
      finalObjectKey: buildFinalSbomObjectKey({
        organizationId: ORG,
        assetId: ASSET,
        sha256: digest,
      }),
      expectedSha256: digest,
      expectedByteLength: 2,
      contentType: 'application/json',
    });
    expect(result).toEqual({ ok: true, value: undefined });
    expect(names).toEqual([
      'HeadObjectCommand',
      'CopyObjectCommand',
      'HeadObjectCommand',
      'DeleteObjectCommand',
    ]);
    expect(names).not.toContain('GetObjectCommand');
    expect(names).not.toContain('PutObjectCommand');
    storage.destroy();
  });

  it('does not overwrite an inconsistent existing final object', async () => {
    send.mockImplementation(async (command) => {
      if (command instanceof HeadObjectCommand) {
        return { ContentLength: 99, Metadata: { sha256: 'b'.repeat(64) } };
      }

      throw new Error(`unexpected ${command.constructor.name}`);
    });
    const storage = createS3SbomObjectStorage(testConfig());
    const result = await storage.promoteTemporaryObject({
      temporaryObjectKey: temporaryKey,
      finalObjectKey: finalKey,
      expectedSha256: 'a'.repeat(64),
      expectedByteLength: 2,
      contentType: 'application/json',
    });
    expect(result).toEqual({ ok: false, error: { category: 'copy_failed' } });
    expect(send.mock.calls.some((call) => call[0] instanceof CopyObjectCommand)).toBe(false);
    storage.destroy();
  });

  it('does not treat a same-size final object missing sha256 metadata as consistent', async () => {
    send.mockImplementation(async (command) => {
      if (command instanceof HeadObjectCommand) {
        return { ContentLength: 2 };
      }

      throw new Error(`unexpected ${command.constructor.name}`);
    });
    const storage = createS3SbomObjectStorage(testConfig());
    const result = await storage.promoteTemporaryObject({
      temporaryObjectKey: temporaryKey,
      finalObjectKey: finalKey,
      expectedSha256: 'a'.repeat(64),
      expectedByteLength: 2,
      contentType: 'application/json',
    });
    expect(result).toEqual({ ok: false, error: { category: 'copy_failed' } });
    expect(send.mock.calls.some((call) => call[0] instanceof CopyObjectCommand)).toBe(false);
    expect(send.mock.calls.some((call) => call[0] instanceof DeleteObjectCommand)).toBe(false);
    storage.destroy();
  });

  it('is idempotent when an existing final object matches size and sha256 metadata', async () => {
    send.mockImplementation(async (command) => {
      if (command instanceof HeadObjectCommand) {
        return { ContentLength: 2, Metadata: { sha256: 'a'.repeat(64) } };
      }

      if (command instanceof DeleteObjectCommand) {
        return {};
      }

      throw new Error(`unexpected ${command.constructor.name}`);
    });
    const storage = createS3SbomObjectStorage(testConfig());
    const result = await storage.promoteTemporaryObject({
      temporaryObjectKey: temporaryKey,
      finalObjectKey: finalKey,
      expectedSha256: 'a'.repeat(64),
      expectedByteLength: 2,
      contentType: 'application/json',
    });
    expect(result).toEqual({ ok: true, value: undefined });
    expect(send.mock.calls.some((call) => call[0] instanceof CopyObjectCommand)).toBe(false);
    expect(send.mock.calls.some((call) => call[0] instanceof DeleteObjectCommand)).toBe(true);
    storage.destroy();
  });

  it('refuses to promote across organization or asset key prefixes without sending commands', async () => {
    send.mockResolvedValue({} as never);
    const storage = createS3SbomObjectStorage(testConfig());
    const otherOrgFinal = buildFinalSbomObjectKey({
      organizationId: '44444444-4444-4444-8444-444444444444',
      assetId: ASSET,
      sha256: 'a'.repeat(64),
    });
    const otherAssetFinal = buildFinalSbomObjectKey({
      organizationId: ORG,
      assetId: '55555555-5555-4555-8555-555555555555',
      sha256: 'a'.repeat(64),
    });
    const crossOrg = await storage.promoteTemporaryObject({
      temporaryObjectKey: temporaryKey,
      finalObjectKey: otherOrgFinal,
      expectedSha256: 'a'.repeat(64),
      expectedByteLength: 2,
      contentType: 'application/json',
    });
    const crossAsset = await storage.promoteTemporaryObject({
      temporaryObjectKey: temporaryKey,
      finalObjectKey: otherAssetFinal,
      expectedSha256: 'a'.repeat(64),
      expectedByteLength: 2,
      contentType: 'application/json',
    });
    expect(crossOrg).toEqual({ ok: false, error: { category: 'internal' } });
    expect(crossAsset).toEqual({ ok: false, error: { category: 'internal' } });
    expect(send).not.toHaveBeenCalled();
    storage.destroy();
  });

  it('never sends CreateBucket in production', async () => {
    send.mockResolvedValue({} as never);
    const storage = createS3SbomObjectStorage(
      testConfig({
        deploymentEnvironment: 'production',
        allowDevelopmentAdapters: false,
        bucket: 'patchpilot',
      }),
    );
    const result = await storage.initializeDevelopmentBucket({
      explicitlyAllowed: true,
      bucket: 'patchpilot',
    });
    expect(result).toEqual({ ok: false, error: { category: 'internal' } });
    expect(send.mock.calls.some((call) => call[0] instanceof CreateBucketCommand)).toBe(false);
    storage.destroy();
  });

  it('returns a streaming GetObject handle whose completion waits for end-of-stream', async () => {
    const payload = Buffer.from('{"ok":true}');
    const digest = createHash('sha256').update(payload).digest('hex');
    send.mockImplementation(async (command) => {
      expect(command).toBeInstanceOf(GetObjectCommand);
      return {
        ContentLength: payload.byteLength,
        Body: Readable.from([payload]),
      };
    });
    const storage = createS3SbomObjectStorage(testConfig());
    const result = await storage.getObject({
      finalObjectKey: finalKey,
      maxBytes: 1024,
      expectedByteLength: payload.byteLength,
      expectedSha256: digest,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) {
      storage.destroy();
      return;
    }

    expect(result.value.declaredByteLength).toBe(payload.byteLength);
    const chunks: Buffer[] = [];
    for await (const chunk of result.value.body) {
      chunks.push(Buffer.from(chunk));
    }

    await expect(result.value.completion).resolves.toEqual({
      observedByteLength: payload.byteLength,
      sha256: digest,
    });
    expect(Buffer.concat(chunks).equals(payload)).toBe(true);
    storage.destroy();
  });

  it('rejects GetObject completion on a hash mismatch after the stream ends', async () => {
    const payload = Buffer.from('{"ok":true}');
    send.mockImplementation(async (command) => {
      expect(command).toBeInstanceOf(GetObjectCommand);
      return {
        ContentLength: payload.byteLength,
        Body: Readable.from([payload]),
      };
    });
    const storage = createS3SbomObjectStorage(testConfig());
    const result = await storage.getObject({
      finalObjectKey: finalKey,
      maxBytes: 1024,
      expectedSha256: 'a'.repeat(64),
    });
    expect(result.ok).toBe(true);
    if (!result.ok) {
      storage.destroy();
      return;
    }

    const consumption = (async () => {
      const chunks: Buffer[] = [];
      for await (const chunk of result.value.body) {
        chunks.push(Buffer.from(chunk));
      }
      return Buffer.concat(chunks);
    })();
    await expect(result.value.completion).rejects.toEqual({ category: 'invalid_content' });
    await expect(consumption).rejects.toMatchObject({ category: 'invalid_content' });
    storage.destroy();
  });

  it('supports explicit stream cancellation', async () => {
    const hanging = new Readable({
      read() {
        return undefined;
      },
    });
    send.mockResolvedValue({
      ContentLength: 100,
      Body: hanging,
    } as never);
    const storage = createS3SbomObjectStorage(testConfig());
    const result = await storage.getObject({
      finalObjectKey: finalKey,
      maxBytes: 1024,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) {
      storage.destroy();
      return;
    }

    await result.value.cancel();
    await expect(result.value.completion).rejects.toEqual({ category: 'aborted' });
    storage.destroy();
  });

  it('logs only safe fields', async () => {
    send.mockRejectedValue(notFound('NoSuchBucket'));
    const collected = collectingLogger();
    const storage = createS3SbomObjectStorage(testConfig(), {
      logger: collected.logger,
      correlationId: 'corr-1',
    });
    await storage.verifyBucketAvailability();
    expect(collected.records.length).toBeGreaterThan(0);
    for (const record of collected.records) {
      expect(record).toHaveProperty('operation');
      expect(record).not.toHaveProperty('objectKey');
      expect(record).not.toHaveProperty('temporaryObjectKey');
      expect(record).not.toHaveProperty('finalObjectKey');
      expect(record).not.toHaveProperty('CopySource');
      expect(record).not.toHaveProperty('accessKey');
      expect(record).not.toHaveProperty('accessKeyId');
      expect(record).not.toHaveProperty('secretAccessKey');
      expect(JSON.stringify(record)).not.toContain(temporaryKey);
      expect(JSON.stringify(record)).not.toContain('test-secret');
    }

    storage.destroy();
  });
});
