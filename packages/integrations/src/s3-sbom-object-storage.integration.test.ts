import { createHash, randomUUID } from 'node:crypto';
import { Readable } from 'node:stream';

import {
  CopyObjectCommand,
  DeleteObjectCommand,
  HeadObjectCommand,
  S3Client,
} from '@aws-sdk/client-s3';
import { loadServerConfigFrom } from '@patchpilot/config';
import { buildFinalSbomObjectKey, buildTemporarySbomObjectKey } from '@patchpilot/domain';
import { createFoundationTestEnv } from '@patchpilot/test-utils';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { createS3Client } from './s3-client.js';
import { encodeS3CopySource } from './s3-copy-source.js';
import { createS3SbomObjectStorage, type S3SbomObjectStorage } from './s3-sbom-object-storage.js';

const PAYLOAD = Buffer.from('{"bomFormat":"CycloneDX","specVersion":"1.6"}');
const CONTENT_TYPE = 'application/json';

function sha256Hex(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

async function collect(body: AsyncIterable<Uint8Array>): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of body) {
    chunks.push(Buffer.from(chunk));
  }

  return Buffer.concat(chunks);
}

function putArgs(
  temporaryObjectKey: string,
  body: Buffer = PAYLOAD,
): {
  temporaryObjectKey: string;
  body: Readable;
  contentType: string;
  maxBytes: number;
  declaredByteLength: number;
} {
  return {
    temporaryObjectKey,
    body: Readable.from([body]),
    contentType: CONTENT_TYPE,
    maxBytes: 4096,
    declaredByteLength: body.byteLength,
  };
}

describe('S3SbomObjectStorage MinIO compatibility', () => {
  const config = loadServerConfigFrom(createFoundationTestEnv());
  const trackedTemporary: string[] = [];
  const trackedFinal: string[] = [];
  let storage: S3SbomObjectStorage;
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
      operationTimeoutMs: config.sbom.objectStorageOperationTimeoutMs,
      deploymentEnvironment: config.deploymentEnvironment,
      allowDevelopmentAdapters: config.allowDevelopmentAdapters,
    };
  }

  function keys(label: string): {
    organizationId: string;
    assetId: string;
    temporary: string;
    final: string;
    digest: string;
  } {
    const organizationId = randomUUID();
    const assetId = randomUUID();
    const digest = sha256Hex(PAYLOAD);
    const temporary = buildTemporarySbomObjectKey({
      organizationId,
      assetId,
      uploadId: randomUUID(),
    });
    const finalKey = buildFinalSbomObjectKey({
      organizationId,
      assetId,
      sha256: digest,
    });
    trackedTemporary.push(temporary);
    trackedFinal.push(finalKey);
    expect(label.length).toBeGreaterThan(0);
    return { organizationId, assetId, temporary, final: finalKey, digest };
  }

  beforeAll(async () => {
    storage = createS3SbomObjectStorage(storageConfig());
    rawClient = createS3Client({
      endpoint: config.objectStorage.endpoint,
      region: config.objectStorage.region,
      accessKey: config.objectStorage.accessKey,
      secretKey: config.objectStorage.secretKey,
      useSsl: config.objectStorage.useSsl,
      connectionTimeoutMs: config.objectStorage.connectionTimeoutMs,
      requestTimeoutMs: config.sbom.objectStorageOperationTimeoutMs,
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
        await storage.deleteTemporaryObject({ temporaryObjectKey: key });
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

  it('puts with forcePathStyle, gets a streaming handle, and matches bytes', async () => {
    const objectKeys = keys('put-get');
    const put = await storage.putTemporaryObject(putArgs(objectKeys.temporary));
    expect(put.ok).toBe(true);
    if (!put.ok) {
      return;
    }

    expect(put.value.observedByteLength).toBe(PAYLOAD.byteLength);
    expect(put.value.sha256).toBe(objectKeys.digest);

    const promoted = await storage.promoteTemporaryObject({
      temporaryObjectKey: objectKeys.temporary,
      finalObjectKey: objectKeys.final,
      expectedSha256: objectKeys.digest,
      expectedByteLength: PAYLOAD.byteLength,
      contentType: CONTENT_TYPE,
    });
    expect(promoted.ok).toBe(true);

    const head = await storage.headFinalObject({ finalObjectKey: objectKeys.final });
    expect(head).toEqual({
      ok: true,
      value: { exists: true, byteLength: PAYLOAD.byteLength },
    });

    const got = await storage.getObject({
      finalObjectKey: objectKeys.final,
      maxBytes: 4096,
      expectedByteLength: PAYLOAD.byteLength,
      expectedSha256: objectKeys.digest,
    });
    expect(got.ok).toBe(true);
    if (!got.ok) {
      return;
    }

    expect(got.value.declaredByteLength).toBe(PAYLOAD.byteLength);
    const bytes = await collect(got.value.body);
    const completion = await got.value.completion;
    expect(bytes.equals(PAYLOAD)).toBe(true);
    expect(completion.observedByteLength).toBe(PAYLOAD.byteLength);
    expect(completion.sha256).toBe(objectKeys.digest);
  });

  it('copies with encoded CopySource, REPLACE metadata, and delayed temporary delete', async () => {
    const objectKeys = keys('copy-source');
    const put = await storage.putTemporaryObject(putArgs(objectKeys.temporary));
    expect(put.ok).toBe(true);

    await rawClient.send(
      new CopyObjectCommand({
        Bucket: config.objectStorage.bucket,
        Key: objectKeys.final,
        CopySource: encodeS3CopySource(config.objectStorage.bucket, objectKeys.temporary),
        MetadataDirective: 'REPLACE',
        ContentType: CONTENT_TYPE,
        Metadata: {
          sha256: objectKeys.digest,
          'byte-length': String(PAYLOAD.byteLength),
        },
      }),
    );

    const tmpHead = await rawClient.send(
      new HeadObjectCommand({
        Bucket: config.objectStorage.bucket,
        Key: objectKeys.temporary,
      }),
    );
    expect(tmpHead.ContentLength).toBe(PAYLOAD.byteLength);

    const finalHead = await rawClient.send(
      new HeadObjectCommand({
        Bucket: config.objectStorage.bucket,
        Key: objectKeys.final,
      }),
    );
    expect(finalHead.ContentType).toMatch(/json/);
    expect(finalHead.Metadata?.['sha256']).toBe(objectKeys.digest);
    expect(finalHead.Metadata?.['byte-length']).toBe(String(PAYLOAD.byteLength));
    expect(finalHead.ContentLength).toBe(PAYLOAD.byteLength);

    const deleted = await storage.deleteTemporaryObject({
      temporaryObjectKey: objectKeys.temporary,
    });
    expect(deleted.ok).toBe(true);

    const tmpGone = await storage.headFinalObject({ finalObjectKey: objectKeys.final });
    expect(tmpGone.ok && tmpGone.value.exists).toBe(true);
  });

  it('removes the temporary object after adapter promotion and keeps the final object', async () => {
    const objectKeys = keys('promote-cleanup');
    const put = await storage.putTemporaryObject(putArgs(objectKeys.temporary));
    expect(put.ok).toBe(true);
    const promoted = await storage.promoteTemporaryObject({
      temporaryObjectKey: objectKeys.temporary,
      finalObjectKey: objectKeys.final,
      expectedSha256: objectKeys.digest,
      expectedByteLength: PAYLOAD.byteLength,
      contentType: CONTENT_TYPE,
    });
    expect(promoted.ok).toBe(true);

    await expect(
      rawClient.send(
        new HeadObjectCommand({
          Bucket: config.objectStorage.bucket,
          Key: objectKeys.temporary,
        }),
      ),
    ).rejects.toBeTruthy();

    const finalExists = await storage.headFinalObject({ finalObjectKey: objectKeys.final });
    expect(finalExists).toEqual({
      ok: true,
      value: { exists: true, byteLength: PAYLOAD.byteLength },
    });
  });

  it('does not allow anonymous GET of a stored object', async () => {
    const objectKeys = keys('anonymous');
    const put = await storage.putTemporaryObject(putArgs(objectKeys.temporary));
    expect(put.ok).toBe(true);
    const promoted = await storage.promoteTemporaryObject({
      temporaryObjectKey: objectKeys.temporary,
      finalObjectKey: objectKeys.final,
      expectedSha256: objectKeys.digest,
      expectedByteLength: PAYLOAD.byteLength,
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
  });

  it('scopes the same bytes to different keys across assets and organizations', async () => {
    const first = keys('tenant-a');
    const sameOrgOtherAssetId = randomUUID();
    const sameOrgOtherTemporary = buildTemporarySbomObjectKey({
      organizationId: first.organizationId,
      assetId: sameOrgOtherAssetId,
      uploadId: randomUUID(),
    });
    const sameOrgOtherAsset = buildFinalSbomObjectKey({
      organizationId: first.organizationId,
      assetId: sameOrgOtherAssetId,
      sha256: first.digest,
    });
    expect(sameOrgOtherAsset).not.toBe(first.final);

    const secondOrg = randomUUID();
    const secondAsset = randomUUID();
    const secondTemporary = buildTemporarySbomObjectKey({
      organizationId: secondOrg,
      assetId: secondAsset,
      uploadId: randomUUID(),
    });
    const secondFinal = buildFinalSbomObjectKey({
      organizationId: secondOrg,
      assetId: secondAsset,
      sha256: first.digest,
    });
    trackedTemporary.push(secondTemporary, sameOrgOtherTemporary);
    trackedFinal.push(secondFinal, sameOrgOtherAsset);
    expect(secondFinal).not.toBe(first.final);
    expect(secondFinal).not.toBe(sameOrgOtherAsset);

    for (const pair of [
      { temporary: first.temporary, final: first.final },
      { temporary: sameOrgOtherTemporary, final: sameOrgOtherAsset },
      { temporary: secondTemporary, final: secondFinal },
    ]) {
      const put = await storage.putTemporaryObject(putArgs(pair.temporary));
      expect(put.ok).toBe(true);
      const promoted = await storage.promoteTemporaryObject({
        temporaryObjectKey: pair.temporary,
        finalObjectKey: pair.final,
        expectedSha256: first.digest,
        expectedByteLength: PAYLOAD.byteLength,
        contentType: CONTENT_TYPE,
      });
      expect(promoted.ok).toBe(true);
      const got = await storage.getObject({
        finalObjectKey: pair.final,
        maxBytes: 4096,
      });
      expect(got.ok).toBe(true);
      if (got.ok) {
        expect((await collect(got.value.body)).equals(PAYLOAD)).toBe(true);
        await got.value.completion;
      }
    }
  });

  it('aborts PutObject and leaves no final object', async () => {
    const objectKeys = keys('abort-put');
    const controller = new AbortController();
    const hanging = new Readable({
      read() {
        return undefined;
      },
    });
    const putPromise = storage.putTemporaryObject({
      temporaryObjectKey: objectKeys.temporary,
      body: hanging,
      contentType: CONTENT_TYPE,
      maxBytes: 4096,
      declaredByteLength: 32,
      signal: controller.signal,
    });
    controller.abort();
    const put = await putPromise;
    expect(put.ok).toBe(false);
    if (!put.ok) {
      expect(put.error.category).toBe('aborted');
    }

    const finalExists = await storage.headFinalObject({ finalObjectKey: objectKeys.final });
    expect(finalExists).toEqual({ ok: true, value: { exists: false } });
  });

  it('aborts GetObject stream consumption', async () => {
    const objectKeys = keys('abort-get');
    const put = await storage.putTemporaryObject(putArgs(objectKeys.temporary));
    expect(put.ok).toBe(true);
    const promoted = await storage.promoteTemporaryObject({
      temporaryObjectKey: objectKeys.temporary,
      finalObjectKey: objectKeys.final,
      expectedSha256: objectKeys.digest,
      expectedByteLength: PAYLOAD.byteLength,
      contentType: CONTENT_TYPE,
    });
    expect(promoted.ok).toBe(true);

    const controller = new AbortController();
    const got = await storage.getObject({
      finalObjectKey: objectKeys.final,
      maxBytes: 4096,
      signal: controller.signal,
    });
    expect(got.ok).toBe(true);
    if (!got.ok) {
      return;
    }

    controller.abort();
    await got.value.cancel();
    await expect(got.value.completion).rejects.toEqual({ category: 'aborted' });
  });

  it('maps a hung put to a bounded timeout', async () => {
    const short = createS3SbomObjectStorage({
      ...storageConfig(),
      operationTimeoutMs: 1000,
      connectionTimeoutMs: 250,
    });
    const objectKeys = keys('timeout-put');
    try {
      const hanging = new Readable({
        read() {
          return undefined;
        },
      });
      const put = await short.putTemporaryObject({
        temporaryObjectKey: objectKeys.temporary,
        body: hanging,
        contentType: CONTENT_TYPE,
        maxBytes: 4096,
        declaredByteLength: 32,
      });
      expect(put.ok).toBe(false);
      if (!put.ok) {
        expect(put.error.category).toBe('timeout');
      }

      const finalExists = await storage.headFinalObject({ finalObjectKey: objectKeys.final });
      expect(finalExists).toEqual({ ok: true, value: { exists: false } });
    } finally {
      short.destroy();
    }
  });

  it('does not create a final object after a failed PutObject', async () => {
    const objectKeys = keys('failed-put');
    const invalid = Buffer.from('[]');
    const put = await storage.putTemporaryObject({
      temporaryObjectKey: objectKeys.temporary,
      body: Readable.from([invalid]),
      contentType: CONTENT_TYPE,
      maxBytes: 4096,
      declaredByteLength: invalid.byteLength,
    });
    expect(put.ok).toBe(false);
    if (!put.ok) {
      expect(put.error.category).toBe('invalid_content');
    }

    const finalExists = await storage.headFinalObject({ finalObjectKey: objectKeys.final });
    expect(finalExists).toEqual({ ok: true, value: { exists: false } });
  });

  it('does not create a final object when copy source is missing', async () => {
    const objectKeys = keys('failed-copy');
    const promoted = await storage.promoteTemporaryObject({
      temporaryObjectKey: objectKeys.temporary,
      finalObjectKey: objectKeys.final,
      expectedSha256: objectKeys.digest,
      expectedByteLength: PAYLOAD.byteLength,
      contentType: CONTENT_TYPE,
    });
    expect(promoted.ok).toBe(false);
    const finalExists = await storage.headFinalObject({ finalObjectKey: objectKeys.final });
    expect(finalExists).toEqual({ ok: true, value: { exists: false } });
  });

  it('never creates a missing bucket in production mode', async () => {
    const missingBucket = `ppmiss${randomUUID().replaceAll('-', '')}`;
    const production = createS3SbomObjectStorage({
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
      const verified = await production.verifyBucketAvailability();
      expect(verified.ok).toBe(false);
      if (!verified.ok) {
        expect(['bucket_missing', 'access_denied']).toContain(verified.error.category);
      }
    } finally {
      production.destroy();
    }
  });
});
