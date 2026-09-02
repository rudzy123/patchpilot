import { createHash, randomUUID } from 'node:crypto';
import { Readable } from 'node:stream';

import {
  CopyObjectCommand,
  DeleteObjectCommand,
  HeadObjectCommand,
  S3Client,
} from '@aws-sdk/client-s3';
import { loadServerConfigFrom } from '@patchpilot/config';
import {
  buildFinalIntelligenceSnapshotObjectKey,
  buildTemporaryIntelligenceSnapshotObjectKey,
  buildTemporarySbomObjectKey,
} from '@patchpilot/domain';
import { createFoundationTestEnv } from '@patchpilot/test-utils';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { createS3Client } from './s3-client.js';
import { encodeS3CopySource } from './s3-copy-source.js';
import {
  createS3IntelligenceSnapshotStorage,
  type S3IntelligenceSnapshotStorage,
} from './s3-intelligence-snapshot-storage.js';

const CONTENT_TYPE = 'application/json';

function sha256Hex(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

function payload(label: string): Buffer {
  return Buffer.from(`{"catalogVersion":"${label}","count":0,"vulnerabilities":[]}`);
}

async function collect(body: AsyncIterable<Uint8Array>): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of body) {
    chunks.push(Buffer.from(chunk));
  }

  return Buffer.concat(chunks);
}

function unwrap<T>(result: { ok: true; value: T } | { ok: false; error: unknown }): T {
  if (!result.ok) {
    throw new Error('expected ok result');
  }

  return result.value;
}

describe('S3IntelligenceSnapshotStorage MinIO compatibility', () => {
  const config = loadServerConfigFrom(createFoundationTestEnv());
  const trackedTemporary: string[] = [];
  const trackedFinal: string[] = [];
  let storage: S3IntelligenceSnapshotStorage;
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

  function keys(label: string) {
    const body = payload(label);
    const digest = sha256Hex(body);
    const temporary = unwrap(buildTemporaryIntelligenceSnapshotObjectKey(randomUUID()));
    const finalKey = unwrap(buildFinalIntelligenceSnapshotObjectKey(digest));
    trackedTemporary.push(temporary);
    trackedFinal.push(finalKey);
    return { temporary, final: finalKey, digest, body };
  }

  beforeAll(async () => {
    storage = createS3IntelligenceSnapshotStorage(storageConfig());
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
        await storage.deleteTemporarySnapshot({ temporaryObjectKey: key });
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

  it('initializes the development bucket idempotently', async () => {
    const second = await storage.initializeDevelopmentBucket({
      explicitlyAllowed: true,
      bucket: config.objectStorage.bucket,
    });
    expect(second.ok).toBe(true);
  });

  it('streams a temporary write, promotes by copy, and gets the exact bytes', async () => {
    const objectKeys = keys('put-get');
    const put = await storage.putTemporarySnapshot({
      temporaryObjectKey: objectKeys.temporary,
      body: Readable.from([objectKeys.body]),
      contentType: CONTENT_TYPE,
      maxBytes: 4096,
      declaredByteLength: objectKeys.body.byteLength,
    });
    expect(put.ok).toBe(true);
    if (!put.ok) {
      return;
    }

    expect(put.value.observedByteLength).toBe(objectKeys.body.byteLength);
    expect(put.value.sha256).toBe(objectKeys.digest);

    const promoted = await storage.promoteTemporarySnapshot({
      temporaryObjectKey: objectKeys.temporary,
      finalObjectKey: objectKeys.final,
      expectedSha256: objectKeys.digest,
      expectedByteLength: objectKeys.body.byteLength,
      contentType: CONTENT_TYPE,
    });
    expect(promoted).toEqual({
      ok: true,
      value: { outcome: 'copied', temporaryCleanup: 'deleted' },
    });

    const head = await storage.headFinalSnapshot({ finalObjectKey: objectKeys.final });
    expect(head.ok).toBe(true);
    if (head.ok && head.value.exists) {
      expect(head.value.sha256).toBe(objectKeys.digest);
      expect(head.value.byteLength).toBe(objectKeys.body.byteLength);
      expect(head.value.provider).toBe('cisa_kev');
    }

    const got = await storage.getFinalSnapshot({
      finalObjectKey: objectKeys.final,
      maxBytes: 4096,
      expectedByteLength: objectKeys.body.byteLength,
      expectedSha256: objectKeys.digest,
    });
    expect(got.ok).toBe(true);
    if (!got.ok) {
      return;
    }

    const bytes = await collect(got.value.body);
    const completion = await got.value.completion;
    expect(bytes.equals(objectKeys.body)).toBe(true);
    expect(completion.sha256).toBe(objectKeys.digest);
  });

  it('replaces metadata on CopyObject and keeps the final object after a skipped temp delete', async () => {
    const objectKeys = keys('copy-meta');
    const put = await storage.putTemporarySnapshot({
      temporaryObjectKey: objectKeys.temporary,
      body: Readable.from([objectKeys.body]),
      contentType: CONTENT_TYPE,
      maxBytes: 4096,
      declaredByteLength: objectKeys.body.byteLength,
    });
    expect(put.ok).toBe(true);

    await rawClient.send(
      new CopyObjectCommand({
        Bucket: config.objectStorage.bucket,
        Key: objectKeys.final,
        CopySource: encodeS3CopySource(config.objectStorage.bucket, objectKeys.temporary),
        MetadataDirective: 'REPLACE',
        ContentType: CONTENT_TYPE,
        Metadata: {
          'response-sha256': objectKeys.digest,
          'byte-length': String(objectKeys.body.byteLength),
          'declared-content-type': CONTENT_TYPE,
          'detected-content-type': CONTENT_TYPE,
          provider: 'cisa_kev',
          'source-identifier': 'cisa_kev_json_catalog',
        },
      }),
    );

    const finalHead = await rawClient.send(
      new HeadObjectCommand({
        Bucket: config.objectStorage.bucket,
        Key: objectKeys.final,
      }),
    );
    expect(finalHead.Metadata?.['response-sha256']).toBe(objectKeys.digest);
    expect(finalHead.ContentLength).toBe(objectKeys.body.byteLength);

    const stillExists = await storage.headFinalSnapshot({ finalObjectKey: objectKeys.final });
    expect(stillExists.ok && stillExists.value.exists).toBe(true);
  });

  it('reuses a matching final and rejects an inconsistent final without overwrite', async () => {
    const matching = keys('reuse');
    const put = await storage.putTemporarySnapshot({
      temporaryObjectKey: matching.temporary,
      body: Readable.from([matching.body]),
      contentType: CONTENT_TYPE,
      maxBytes: 4096,
      declaredByteLength: matching.body.byteLength,
    });
    expect(put.ok).toBe(true);
    const first = await storage.promoteTemporarySnapshot({
      temporaryObjectKey: matching.temporary,
      finalObjectKey: matching.final,
      expectedSha256: matching.digest,
      expectedByteLength: matching.body.byteLength,
      contentType: CONTENT_TYPE,
    });
    expect(first.ok).toBe(true);

    const secondTemp = unwrap(buildTemporaryIntelligenceSnapshotObjectKey(randomUUID()));
    trackedTemporary.push(secondTemp);
    const putAgain = await storage.putTemporarySnapshot({
      temporaryObjectKey: secondTemp,
      body: Readable.from([matching.body]),
      contentType: CONTENT_TYPE,
      maxBytes: 4096,
      declaredByteLength: matching.body.byteLength,
    });
    expect(putAgain.ok).toBe(true);
    const reused = await storage.promoteTemporarySnapshot({
      temporaryObjectKey: secondTemp,
      finalObjectKey: matching.final,
      expectedSha256: matching.digest,
      expectedByteLength: matching.body.byteLength,
      contentType: CONTENT_TYPE,
    });
    expect(reused).toEqual({
      ok: true,
      value: { outcome: 'reused', temporaryCleanup: 'deleted' },
    });

    const inconsistent = keys('inconsistent');
    await rawClient.send(
      new CopyObjectCommand({
        Bucket: config.objectStorage.bucket,
        Key: inconsistent.final,
        CopySource: encodeS3CopySource(config.objectStorage.bucket, matching.final),
        MetadataDirective: 'REPLACE',
        Metadata: {
          'response-sha256': 'c'.repeat(64),
          provider: 'cisa_kev',
          'source-identifier': 'cisa_kev_json_catalog',
        },
      }),
    );
    const rejected = await storage.promoteTemporarySnapshot({
      temporaryObjectKey: matching.temporary,
      finalObjectKey: inconsistent.final,
      expectedSha256: inconsistent.digest,
      expectedByteLength: inconsistent.body.byteLength,
      contentType: CONTENT_TYPE,
    });
    expect(rejected.ok).toBe(false);
  });

  it('does not allow anonymous GET and uses a different namespace than SBOM keys', async () => {
    const objectKeys = keys('anonymous');
    const put = await storage.putTemporarySnapshot({
      temporaryObjectKey: objectKeys.temporary,
      body: Readable.from([objectKeys.body]),
      contentType: CONTENT_TYPE,
      maxBytes: 4096,
      declaredByteLength: objectKeys.body.byteLength,
    });
    expect(put.ok).toBe(true);
    const promoted = await storage.promoteTemporarySnapshot({
      temporaryObjectKey: objectKeys.temporary,
      finalObjectKey: objectKeys.final,
      expectedSha256: objectKeys.digest,
      expectedByteLength: objectKeys.body.byteLength,
      contentType: CONTENT_TYPE,
    });
    expect(promoted.ok).toBe(true);

    const encodedKey = objectKeys.final
      .split('/')
      .map((segment) => encodeURIComponent(segment))
      .join('/');
    const response = await fetch(
      `${config.objectStorage.endpoint}/${config.objectStorage.bucket}/${encodedKey}`,
    );
    expect(response.status).not.toBe(200);
    expect(response.ok).toBe(false);

    const sbomTemporary = buildTemporarySbomObjectKey({
      organizationId: randomUUID(),
      assetId: randomUUID(),
      uploadId: randomUUID(),
    });
    expect(objectKeys.final.startsWith('intelligence/')).toBe(true);
    expect(sbomTemporary.startsWith('org/')).toBe(true);
    expect(objectKeys.final).not.toContain('sboms/');
  });

  it('cancels GetObject and maps a hung put to a timeout', async () => {
    const objectKeys = keys('abort-get');
    const put = await storage.putTemporarySnapshot({
      temporaryObjectKey: objectKeys.temporary,
      body: Readable.from([objectKeys.body]),
      contentType: CONTENT_TYPE,
      maxBytes: 4096,
      declaredByteLength: objectKeys.body.byteLength,
    });
    expect(put.ok).toBe(true);
    const promoted = await storage.promoteTemporarySnapshot({
      temporaryObjectKey: objectKeys.temporary,
      finalObjectKey: objectKeys.final,
      expectedSha256: objectKeys.digest,
      expectedByteLength: objectKeys.body.byteLength,
      contentType: CONTENT_TYPE,
    });
    expect(promoted.ok).toBe(true);

    const controller = new AbortController();
    const got = await storage.getFinalSnapshot({
      finalObjectKey: objectKeys.final,
      maxBytes: 4096,
      signal: controller.signal,
    });
    expect(got.ok).toBe(true);
    if (got.ok) {
      controller.abort();
      await got.value.cancel();
      await expect(got.value.completion).rejects.toMatchObject({ code: 'request_cancelled' });
    }

    const short = createS3IntelligenceSnapshotStorage({
      ...storageConfig(),
      operationTimeoutMs: 1000,
      connectionTimeoutMs: 250,
    });
    const timeoutKeys = keys('timeout-put');
    try {
      const hanging = new Readable({
        read() {
          return undefined;
        },
      });
      const hung = await short.putTemporarySnapshot({
        temporaryObjectKey: timeoutKeys.temporary,
        body: hanging,
        contentType: CONTENT_TYPE,
        maxBytes: 4096,
        declaredByteLength: 32,
      });
      expect(hung.ok).toBe(false);
      if (!hung.ok) {
        expect(hung.error.code).toBe('response_timeout');
      }
    } finally {
      short.destroy();
    }
  });

  it('never creates a missing bucket in production mode', async () => {
    const missingBucket = `ppmiss${randomUUID().replaceAll('-', '')}`;
    const production = createS3IntelligenceSnapshotStorage({
      ...storageConfig(),
      bucket: missingBucket,
      deploymentEnvironment: 'production',
      allowDevelopmentAdapters: false,
    });
    try {
      const created = await production.initializeDevelopmentBucket({
        explicitlyAllowed: true,
        bucket: missingBucket,
      });
      expect(created.ok).toBe(false);
      const verified = await production.verifyPrivateStorageAvailability();
      expect(verified.ok).toBe(false);
    } finally {
      production.destroy();
    }
  });
});
