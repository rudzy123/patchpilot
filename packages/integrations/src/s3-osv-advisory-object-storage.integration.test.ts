import { createHash, randomUUID } from 'node:crypto';

import { DeleteObjectCommand, HeadObjectCommand, S3Client } from '@aws-sdk/client-s3';
import { loadServerConfigFrom } from '@patchpilot/config';
import { createFoundationTestEnv } from '@patchpilot/test-utils';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { createS3Client } from './s3-client.js';
import {
  createS3OsvAdvisoryObjectStorage,
  type OsvS3Locator,
  type S3OsvAdvisoryObjectStorage,
} from './s3-osv-advisory-object-storage.js';

const CONTENT_TYPE = 'application/json';
const CONTENT_ENCODING = 'identity';

function sha256Hex(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

function payload(label: string): Uint8Array {
  return new TextEncoder().encode(`{"synthetic":"${label}"}`);
}

describe('S3OsvAdvisoryObjectStorage MinIO compatibility', () => {
  const config = loadServerConfigFrom(createFoundationTestEnv());
  const trackedTemporary: string[] = [];
  const trackedFinal: string[] = [];
  let storage: S3OsvAdvisoryObjectStorage;
  let rawClient: S3Client;

  function storageConfig() {
    return {
      endpoint: config.objectStorage.endpoint,
      region: config.objectStorage.region,
      accessKey: config.objectStorage.accessKey,
      secretKey: config.objectStorage.secretKey,
      bucket: config.objectStorage.bucket,
      useSsl: config.objectStorage.useSsl,
      connectionTimeoutMs: config.objectStorage.connectionTimeoutMs,
      operationTimeoutMs: config.intelligence.objectStorageTimeoutMs,
      deploymentEnvironment: config.deploymentEnvironment,
      allowDevelopmentAdapters: config.allowDevelopmentAdapters,
    };
  }

  function bodyLocator(label: string): {
    body: Uint8Array;
    digest: string;
    temporary: OsvS3Locator;
    final: OsvS3Locator;
  } {
    const body = payload(label);
    const digest = sha256Hex(body);
    const uploadId = randomUUID();
    const temporary: OsvS3Locator = {
      kind: 'osv_object_storage_locator',
      storageKind: 'advisory_body',
      role: 'temporary',
      objectKey: `intelligence/osv/advisory_body/tmp/${uploadId}`,
      contentSha256: null,
      uploadId,
    };
    const final: OsvS3Locator = {
      kind: 'osv_object_storage_locator',
      storageKind: 'advisory_body',
      role: 'final',
      objectKey: `intelligence/osv/advisory_body/sha256/${digest}`,
      contentSha256: digest,
      uploadId: null,
    };
    trackedTemporary.push(temporary.objectKey);
    trackedFinal.push(final.objectKey);
    return { body, digest, temporary, final };
  }

  function parsedLocator(label: string): {
    body: Uint8Array;
    digest: string;
    temporary: OsvS3Locator;
    final: OsvS3Locator;
  } {
    const body = payload(label);
    const digest = sha256Hex(body);
    const uploadId = randomUUID();
    const temporary: OsvS3Locator = {
      kind: 'osv_object_storage_locator',
      storageKind: 'parsed_advisory',
      role: 'temporary',
      objectKey: `intelligence/osv/parsed_advisory/tmp/${uploadId}`,
      contentSha256: null,
      uploadId,
    };
    const final: OsvS3Locator = {
      kind: 'osv_object_storage_locator',
      storageKind: 'parsed_advisory',
      role: 'final',
      objectKey: `intelligence/osv/parsed_advisory/sha256/${digest}`,
      contentSha256: digest,
      uploadId: null,
    };
    trackedTemporary.push(temporary.objectKey);
    trackedFinal.push(final.objectKey);
    return { body, digest, temporary, final };
  }

  beforeAll(async () => {
    storage = createS3OsvAdvisoryObjectStorage(storageConfig());
    rawClient = createS3Client({
      endpoint: config.objectStorage.endpoint,
      region: config.objectStorage.region,
      accessKey: config.objectStorage.accessKey,
      secretKey: config.objectStorage.secretKey,
      useSsl: config.objectStorage.useSsl,
      connectionTimeoutMs: config.objectStorage.connectionTimeoutMs,
      requestTimeoutMs: config.intelligence.objectStorageTimeoutMs,
    });
    const initialized = await storage.initializeDevelopmentBucket({
      explicitlyAllowed: true,
      bucket: config.objectStorage.bucket,
    });
    expect(initialized.ok).toBe(true);
  });

  afterAll(async () => {
    try {
      for (const key of trackedTemporary) {
        await rawClient.send(
          new DeleteObjectCommand({
            Bucket: config.objectStorage.bucket,
            Key: key,
          }),
        );
      }
      for (const key of trackedFinal) {
        await rawClient.send(
          new DeleteObjectCommand({
            Bucket: config.objectStorage.bucket,
            Key: key,
          }),
        );
      }
    } finally {
      storage.destroy();
      rawClient.destroy();
    }
  });

  it('writes staged bytes, promotes to sha256 identity, and verifies read-back', async () => {
    const object = bodyLocator('minio-put');
    const put = await storage.putExclusive({
      locator: object.temporary,
      body: object.body,
      contentSha256: object.digest,
      byteCount: object.body.byteLength,
      contentType: CONTENT_TYPE,
      contentEncoding: CONTENT_ENCODING,
      artifactCategory: 'advisory_body',
    });
    expect(put.ok).toBe(true);
    const copied = await storage.copyExclusive({
      source: object.temporary,
      destination: object.final,
      expectedSha256: object.digest,
      expectedByteCount: object.body.byteLength,
      contentType: CONTENT_TYPE,
      contentEncoding: CONTENT_ENCODING,
      artifactCategory: 'advisory_body',
    });
    expect(copied.ok).toBe(true);
    const verified = await storage.getVerified({
      locator: object.final,
      expectedSha256: object.digest,
      expectedByteCount: object.body.byteLength,
      expectedContentType: CONTENT_TYPE,
      expectedContentEncoding: CONTENT_ENCODING,
      maxBytes: 4096,
    });
    expect(verified.ok).toBe(true);
    if (verified.ok) {
      expect(verified.value.sha256).toBe(object.digest);
    }
    const deleted = await storage.deleteTemporary({ locator: object.temporary });
    expect(deleted.ok).toBe(true);
    const missingTmp = await storage.head({ locator: object.temporary });
    expect(missingTmp.ok).toBe(true);
    if (missingTmp.ok) {
      expect(missingTmp.value.exists).toBe(false);
    }
  });

  it('is idempotent for the same attached identity and conflicts on different bytes', async () => {
    const object = bodyLocator('minio-idempotent');
    const first = await storage.putExclusive({
      locator: object.final,
      body: object.body,
      contentSha256: object.digest,
      byteCount: object.body.byteLength,
      contentType: CONTENT_TYPE,
      contentEncoding: CONTENT_ENCODING,
      artifactCategory: 'advisory_body',
    });
    expect(first.ok).toBe(true);
    const repeat = await storage.putExclusive({
      locator: object.final,
      body: object.body,
      contentSha256: object.digest,
      byteCount: object.body.byteLength,
      contentType: CONTENT_TYPE,
      contentEncoding: CONTENT_ENCODING,
      artifactCategory: 'advisory_body',
    });
    expect(repeat.ok).toBe(true);
    if (repeat.ok) {
      expect(repeat.value.status).toBe('already_applied');
    }
    const other = payload('minio-conflict');
    const conflict = await storage.putExclusive({
      locator: object.final,
      body: other,
      contentSha256: sha256Hex(other),
      byteCount: other.byteLength,
      contentType: CONTENT_TYPE,
      contentEncoding: CONTENT_ENCODING,
      artifactCategory: 'advisory_body',
    });
    expect(conflict.ok).toBe(false);
    if (!conflict.ok) {
      expect(conflict.code).toBe('immutable_conflict');
    }
    const head = await rawClient.send(
      new HeadObjectCommand({
        Bucket: config.objectStorage.bucket,
        Key: object.final.objectKey,
      }),
    );
    expect(head.Metadata?.['content-sha256'] ?? head.Metadata?.['Content-Sha256']).toBe(
      object.digest,
    );
  });

  it('keeps parsed-document identity distinct from provider-body identity', async () => {
    const parsed = parsedLocator('parsed-minio');
    const put = await storage.putExclusive({
      locator: parsed.final,
      body: parsed.body,
      contentSha256: parsed.digest,
      byteCount: parsed.body.byteLength,
      contentType: CONTENT_TYPE,
      contentEncoding: CONTENT_ENCODING,
      artifactCategory: 'parsed_advisory',
    });
    expect(put.ok).toBe(true);
    expect(parsed.final.objectKey).toContain('parsed_advisory/sha256/');
    expect(parsed.final.objectKey).not.toContain('advisory_body');
    const verified = await storage.getVerified({
      locator: parsed.final,
      expectedSha256: parsed.digest,
      expectedByteCount: parsed.body.byteLength,
      expectedContentType: CONTENT_TYPE,
      expectedContentEncoding: CONTENT_ENCODING,
      maxBytes: 4096,
    });
    expect(verified.ok).toBe(true);
  });

  it('handles MinIO conditional create, 409 comparison, and category isolation for the same digest', async () => {
    const object = bodyLocator('minio-conditional');
    const first = await storage.putExclusive({
      locator: object.final,
      body: object.body,
      contentSha256: object.digest,
      byteCount: object.body.byteLength,
      contentType: CONTENT_TYPE,
      contentEncoding: CONTENT_ENCODING,
      artifactCategory: 'advisory_body',
    });
    expect(first.ok).toBe(true);
    const [left, right] = await Promise.all([
      storage.putExclusive({
        locator: object.final,
        body: object.body,
        contentSha256: object.digest,
        byteCount: object.body.byteLength,
        contentType: CONTENT_TYPE,
        contentEncoding: CONTENT_ENCODING,
        artifactCategory: 'advisory_body',
      }),
      storage.putExclusive({
        locator: object.final,
        body: object.body,
        contentSha256: object.digest,
        byteCount: object.body.byteLength,
        contentType: CONTENT_TYPE,
        contentEncoding: CONTENT_ENCODING,
        artifactCategory: 'advisory_body',
      }),
    ]);
    expect(left.ok && right.ok).toBe(true);
    if (left.ok) {
      expect(left.value.status).toBe('already_applied');
    }
    const parsedFinalKey = `intelligence/osv/parsed_advisory/sha256/${object.digest}`;
    trackedFinal.push(parsedFinalKey);
    const parsedPut = await storage.putExclusive({
      locator: {
        kind: 'osv_object_storage_locator',
        storageKind: 'parsed_advisory',
        role: 'final',
        objectKey: parsedFinalKey,
        contentSha256: object.digest,
        uploadId: null,
      },
      body: object.body,
      contentSha256: object.digest,
      byteCount: object.body.byteLength,
      contentType: CONTENT_TYPE,
      contentEncoding: CONTENT_ENCODING,
      artifactCategory: 'parsed_advisory',
    });
    expect(parsedPut.ok).toBe(true);
    const deletedFinal = await storage.deleteTemporary({ locator: object.final });
    expect(deletedFinal.ok).toBe(false);
    const stillThere = await storage.head({ locator: object.final });
    expect(stillThere.ok).toBe(true);
    if (stillThere.ok) {
      expect(stillThere.value.exists).toBe(true);
    }
  });
});
