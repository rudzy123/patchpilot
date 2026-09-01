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
import {
  buildFinalIntelligenceSnapshotObjectKey,
  buildTemporaryIntelligenceSnapshotObjectKey,
  buildFinalSbomObjectKey,
} from '@patchpilot/domain';
import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  createS3IntelligenceSnapshotStorage,
  type S3IntelligenceSnapshotStorageConfig,
} from './s3-intelligence-snapshot-storage.js';
import type { ObjectStorageLogger } from './s3-sbom-object-storage.js';

const UPLOAD = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const SHA = 'a'.repeat(64);
const PAYLOAD = Buffer.from('{"catalogVersion":"1","count":0,"vulnerabilities":[]}');

function unwrap<T>(result: { ok: true; value: T } | { ok: false; error: unknown }): T {
  if (!result.ok) {
    throw new Error('expected ok');
  }

  return result.value;
}

const temporaryKey = unwrap(buildTemporaryIntelligenceSnapshotObjectKey(UPLOAD));
const finalKey = unwrap(buildFinalIntelligenceSnapshotObjectKey(SHA));

const send = vi.spyOn(S3Client.prototype, 'send');

afterEach(() => {
  send.mockReset();
});

function testConfig(
  overrides: Partial<S3IntelligenceSnapshotStorageConfig> = {},
): S3IntelligenceSnapshotStorageConfig {
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

describe('S3IntelligenceSnapshotStorage', () => {
  it('keeps static credentials, forcePathStyle, and no ACL, grants, signed URL, or multipart', async () => {
    send.mockImplementation(async (command) => {
      expect(command).toBeInstanceOf(PutObjectCommand);
      expect((command as PutObjectCommand).input.ACL).toBeUndefined();
      expect((command as PutObjectCommand).input.GrantRead).toBeUndefined();
      expect((command as PutObjectCommand).input.ChecksumAlgorithm).toBeUndefined();
      await drainBody(command as PutObjectCommand);
      return {};
    });
    const storage = createS3IntelligenceSnapshotStorage(testConfig());
    const result = await storage.putTemporarySnapshot({
      temporaryObjectKey: temporaryKey,
      body: Readable.from([PAYLOAD]),
      contentType: 'application/json',
      maxBytes: 1024,
      declaredByteLength: PAYLOAD.byteLength,
    });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.observedByteLength).toBe(PAYLOAD.byteLength);
      expect(result.value.sha256).toBe(createHash('sha256').update(PAYLOAD).digest('hex'));
    }

    expect(send).toHaveBeenCalledTimes(1);
    storage.destroy();
  });

  it('rejects SBOM keys, declared-length mismatch, and over-limit writes', async () => {
    send.mockResolvedValue({} as never);
    const storage = createS3IntelligenceSnapshotStorage(testConfig());
    const sbomFinal = buildFinalSbomObjectKey({
      organizationId: UPLOAD,
      assetId: UPLOAD,
      sha256: SHA,
    });
    const wrongKey = await storage.putTemporarySnapshot({
      temporaryObjectKey: sbomFinal as typeof temporaryKey,
      body: Readable.from([PAYLOAD]),
      contentType: 'application/json',
      maxBytes: 1024,
    });
    expect(wrongKey.ok).toBe(false);
    expect(send).not.toHaveBeenCalled();

    const tooLarge = await storage.putTemporarySnapshot({
      temporaryObjectKey: temporaryKey,
      body: Readable.from([PAYLOAD]),
      contentType: 'application/json',
      maxBytes: 8,
      declaredByteLength: 9,
    });
    expect(tooLarge).toEqual({
      ok: false,
      error: { category: 'structural_limit', code: 'response_too_large' },
    });
    storage.destroy();
  });

  it('promotes with CopyObject REPLACE metadata and does not GetObject the body', async () => {
    const digest = createHash('sha256').update(PAYLOAD).digest('hex');
    const names: string[] = [];
    send.mockImplementation(async (command) => {
      names.push(command.constructor.name);
      if (command instanceof HeadObjectCommand) {
        if (names.filter((name) => name === 'HeadObjectCommand').length === 1) {
          throw notFound('NoSuchKey');
        }

        return {
          ContentLength: PAYLOAD.byteLength,
          Metadata: {
            'response-sha256': digest,
            'byte-length': String(PAYLOAD.byteLength),
            provider: 'cisa_kev',
            'source-identifier': 'cisa_kev_json_catalog',
            'declared-content-type': 'application/json',
            'detected-content-type': 'application/json',
          },
        };
      }

      if (command instanceof CopyObjectCommand) {
        expect(command.input.ACL).toBeUndefined();
        expect(command.input.MetadataDirective).toBe('REPLACE');
        expect(command.input.Metadata).toEqual({
          'response-sha256': digest,
          'byte-length': String(PAYLOAD.byteLength),
          'declared-content-type': 'application/json',
          'detected-content-type': 'application/json',
          provider: 'cisa_kev',
          'source-identifier': 'cisa_kev_json_catalog',
        });
        return {};
      }

      if (command instanceof DeleteObjectCommand) {
        return {};
      }

      throw new Error(`unexpected ${command.constructor.name}`);
    });

    const storage = createS3IntelligenceSnapshotStorage(testConfig());
    const promoted = await storage.promoteTemporarySnapshot({
      temporaryObjectKey: temporaryKey,
      finalObjectKey: unwrap(buildFinalIntelligenceSnapshotObjectKey(digest)),
      expectedSha256: digest,
      expectedByteLength: PAYLOAD.byteLength,
      contentType: 'application/json',
    });
    expect(promoted).toEqual({
      ok: true,
      value: { outcome: 'copied', temporaryCleanup: 'deleted' },
    });
    expect(names).toEqual([
      'HeadObjectCommand',
      'CopyObjectCommand',
      'HeadObjectCommand',
      'DeleteObjectCommand',
    ]);
    expect(names).not.toContain('GetObjectCommand');
    storage.destroy();
  });

  it('reuses a matching final, rejects missing hash metadata, and does not overwrite inconsistency', async () => {
    send.mockImplementation(async (command) => {
      if (command instanceof HeadObjectCommand) {
        return { ContentLength: 2, Metadata: { 'byte-length': '2', provider: 'cisa_kev' } };
      }

      throw new Error(`unexpected ${command.constructor.name}`);
    });
    const storage = createS3IntelligenceSnapshotStorage(testConfig());
    const missingHash = await storage.promoteTemporarySnapshot({
      temporaryObjectKey: temporaryKey,
      finalObjectKey: finalKey,
      expectedSha256: SHA,
      expectedByteLength: 2,
      contentType: 'application/json',
    });
    expect(missingHash.ok).toBe(false);
    expect(send.mock.calls.some((call) => call[0] instanceof CopyObjectCommand)).toBe(false);
    expect(send.mock.calls.some((call) => call[0] instanceof DeleteObjectCommand)).toBe(false);
    storage.destroy();

    send.mockReset();
    send.mockImplementation(async (command) => {
      if (command instanceof HeadObjectCommand) {
        return {
          ContentLength: 99,
          Metadata: {
            'response-sha256': 'b'.repeat(64),
            provider: 'cisa_kev',
            'source-identifier': 'cisa_kev_json_catalog',
          },
        };
      }

      throw new Error(`unexpected ${command.constructor.name}`);
    });
    const storage2 = createS3IntelligenceSnapshotStorage(testConfig());
    const wrong = await storage2.promoteTemporarySnapshot({
      temporaryObjectKey: temporaryKey,
      finalObjectKey: finalKey,
      expectedSha256: SHA,
      expectedByteLength: 2,
      contentType: 'application/json',
    });
    expect(wrong.ok).toBe(false);
    expect(send.mock.calls.some((call) => call[0] instanceof CopyObjectCommand)).toBe(false);
    storage2.destroy();

    send.mockReset();
    send.mockImplementation(async (command) => {
      if (command instanceof HeadObjectCommand) {
        return {
          ContentLength: 2,
          Metadata: {
            'response-sha256': SHA,
            provider: 'cisa_kev',
            'source-identifier': 'cisa_kev_json_catalog',
          },
        };
      }

      if (command instanceof DeleteObjectCommand) {
        return {};
      }

      throw new Error(`unexpected ${command.constructor.name}`);
    });
    const storage3 = createS3IntelligenceSnapshotStorage(testConfig());
    const reused = await storage3.promoteTemporarySnapshot({
      temporaryObjectKey: temporaryKey,
      finalObjectKey: finalKey,
      expectedSha256: SHA,
      expectedByteLength: 2,
      contentType: 'application/json',
    });
    expect(reused).toEqual({
      ok: true,
      value: { outcome: 'reused', temporaryCleanup: 'deleted' },
    });
    storage3.destroy();
  });

  it('reports failed temporary cleanup after a successful copy without deleting the final object', async () => {
    send.mockImplementation(async (command) => {
      if (command instanceof HeadObjectCommand) {
        if (send.mock.calls.filter((call) => call[0] instanceof HeadObjectCommand).length === 1) {
          throw notFound();
        }

        return {
          ContentLength: 2,
          Metadata: {
            'response-sha256': SHA,
            provider: 'cisa_kev',
            'source-identifier': 'cisa_kev_json_catalog',
          },
        };
      }

      if (command instanceof CopyObjectCommand) {
        return {};
      }

      if (command instanceof DeleteObjectCommand) {
        throw new Error('cleanup failed');
      }

      throw new Error(`unexpected ${command.constructor.name}`);
    });
    const storage = createS3IntelligenceSnapshotStorage(testConfig());
    const promoted = await storage.promoteTemporarySnapshot({
      temporaryObjectKey: temporaryKey,
      finalObjectKey: finalKey,
      expectedSha256: SHA,
      expectedByteLength: 2,
      contentType: 'application/json',
    });
    expect(promoted).toEqual({
      ok: true,
      value: { outcome: 'copied', temporaryCleanup: 'failed' },
    });
    expect(send.mock.calls.some((call) => call[0] instanceof GetObjectCommand)).toBe(false);
    storage.destroy();
  });

  it('never sends CreateBucket in production and does not expose AWS details', async () => {
    send.mockResolvedValue({} as never);
    const collected = collectingLogger();
    const storage = createS3IntelligenceSnapshotStorage(
      testConfig({
        deploymentEnvironment: 'production',
        allowDevelopmentAdapters: false,
        bucket: 'patchpilot',
      }),
      { logger: collected.logger, correlationId: 'corr-1' },
    );
    const created = await storage.initializeDevelopmentBucket({
      explicitlyAllowed: true,
      bucket: 'patchpilot',
    });
    expect(created.ok).toBe(false);
    expect(send.mock.calls.some((call) => call[0] instanceof CreateBucketCommand)).toBe(false);
    for (const record of collected.records) {
      expect(JSON.stringify(record)).not.toContain(temporaryKey);
      expect(JSON.stringify(record)).not.toContain('test-secret');
      expect(record).not.toHaveProperty('bucket');
    }

    storage.destroy();
  });

  it('streams GetObject, validates hash, and cancels without AWS types', async () => {
    const digest = createHash('sha256').update(PAYLOAD).digest('hex');
    send.mockImplementation(async (command) => {
      expect(command).toBeInstanceOf(GetObjectCommand);
      return { ContentLength: PAYLOAD.byteLength, Body: Readable.from([PAYLOAD]) };
    });
    const storage = createS3IntelligenceSnapshotStorage(testConfig());
    const got = await storage.getFinalSnapshot({
      finalObjectKey: unwrap(buildFinalIntelligenceSnapshotObjectKey(digest)),
      maxBytes: 1024,
      expectedByteLength: PAYLOAD.byteLength,
      expectedSha256: digest,
    });
    expect(got.ok).toBe(true);
    if (!got.ok) {
      storage.destroy();
      return;
    }

    const chunks: Buffer[] = [];
    for await (const chunk of got.value.body) {
      chunks.push(Buffer.from(chunk));
    }

    await expect(got.value.completion).resolves.toEqual({
      observedByteLength: PAYLOAD.byteLength,
      sha256: digest,
    });
    expect(Buffer.concat(chunks).equals(PAYLOAD)).toBe(true);

    const hanging = new Readable({
      read() {
        return undefined;
      },
    });
    send.mockResolvedValue({ ContentLength: 100, Body: hanging } as never);
    const cancellable = await storage.getFinalSnapshot({
      finalObjectKey: unwrap(buildFinalIntelligenceSnapshotObjectKey(digest)),
      maxBytes: 1024,
    });
    expect(cancellable.ok).toBe(true);
    if (cancellable.ok) {
      await cancellable.value.cancel();
      await expect(cancellable.value.completion).rejects.toEqual({
        category: 'timeout',
        code: 'request_cancelled',
      });
    }

    storage.destroy();
  });
});
