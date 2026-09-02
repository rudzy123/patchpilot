import {
  CopyObjectCommand,
  CreateBucketCommand,
  DeleteObjectCommand,
  GetObjectCommand,
  HeadBucketCommand,
  HeadObjectCommand,
  PutObjectCommand,
  type S3Client,
} from '@aws-sdk/client-s3';
import { isValidObjectStorageBucketName } from '@patchpilot/config';
import {
  err,
  intelligenceObjectKeysShareScope,
  isFinalIntelligenceSnapshotObjectKey,
  isTemporaryIntelligenceSnapshotObjectKey,
  ok,
  SHA256_HEX_PATTERN,
  sha256FromFinalIntelligenceSnapshotObjectKey,
  type IntelligenceSnapshotExistence,
  type IntelligenceSnapshotStorageFailure,
  type IntelligenceSnapshotStoragePort,
  type IntelligenceStreamCompletion,
  type Result,
  type StorageFailureCategory,
} from '@patchpilot/domain';

import { createS3Client } from './s3-client.js';
import {
  encodeS3CopySource,
  INTELLIGENCE_BYTE_LENGTH_METADATA_KEY,
  INTELLIGENCE_DECLARED_CONTENT_TYPE_METADATA_KEY,
  INTELLIGENCE_DETECTED_CONTENT_TYPE_METADATA_KEY,
  INTELLIGENCE_PROVIDER_METADATA_KEY,
  INTELLIGENCE_RESPONSE_SHA256_METADATA_KEY,
  INTELLIGENCE_SOURCE_IDENTIFIER_METADATA_KEY,
} from './s3-copy-source.js';
import {
  classifiedStorageFailure,
  isAlreadyOwnedBucketError,
  ObjectStorageStreamError,
  type S3Operation,
} from './s3-errors.js';
import {
  asNodeReadable,
  combineAbortSignals,
  createHashCountTransform,
  destroyStream,
  readableFromByteStream,
} from './s3-stream.js';
import type { ObjectStorageLogger } from './s3-sbom-object-storage.js';

const PRIVACY = {
  bucketPrivate: true,
  publicAccessDisabled: true,
  signedUrlsDisabled: true,
} as const;

export type S3IntelligenceSnapshotStorageConfig = {
  endpoint: string;
  region: string;
  accessKey: string;
  secretKey: string;
  bucket: string;
  useSsl: boolean;
  connectionTimeoutMs: number;
  operationTimeoutMs: number;
  deploymentEnvironment: 'development' | 'test' | 'production';
  allowDevelopmentAdapters: boolean;
};

export type S3IntelligenceSnapshotStorageOptions = {
  logger?: ObjectStorageLogger;
  correlationId?: string;
};

const silentLogger: ObjectStorageLogger = {
  info: () => undefined,
  warn: () => undefined,
  error: () => undefined,
};

function mapStorageFailure(category: StorageFailureCategory): IntelligenceSnapshotStorageFailure {
  if (category === 'size_limit') {
    return { category: 'structural_limit', code: 'response_too_large' };
  }

  if (category === 'aborted') {
    return { category: 'timeout', code: 'request_cancelled' };
  }

  if (category === 'timeout') {
    return { category: 'timeout', code: 'response_timeout' };
  }

  if (category === 'invalid_content') {
    return { category: 'integrity', code: 'hash_mismatch' };
  }

  if (category === 'object_missing') {
    return { category: 'storage', code: 'snapshot_missing' };
  }

  return { category: 'storage', code: 'snapshot_storage_failed' };
}

function metadataValue(
  metadata: Record<string, string> | undefined,
  key: string,
): string | undefined {
  if (metadata === undefined) {
    return undefined;
  }

  const direct = metadata[key];
  if (direct !== undefined) {
    return direct;
  }

  const lower = key.toLowerCase();
  for (const [name, value] of Object.entries(metadata)) {
    if (name.toLowerCase() === lower) {
      return value;
    }
  }

  return undefined;
}

type FinalMetadata = {
  byteLength: number;
  sha256: string;
  declaredContentType: string | null;
  detectedContentType: string | null;
  provider: 'cisa_kev';
  sourceIdentifier: 'cisa_kev_json_catalog';
};

export class S3IntelligenceSnapshotStorage implements IntelligenceSnapshotStoragePort {
  private readonly client: S3Client;
  private readonly bucket: string;
  private readonly operationTimeoutMs: number;
  private readonly deploymentEnvironment: S3IntelligenceSnapshotStorageConfig['deploymentEnvironment'];
  private readonly allowDevelopmentAdapters: boolean;
  private readonly logger: ObjectStorageLogger;
  private readonly correlationId: string | undefined;

  public constructor(
    config: S3IntelligenceSnapshotStorageConfig,
    options: S3IntelligenceSnapshotStorageOptions = {},
  ) {
    this.client = createS3Client({
      endpoint: config.endpoint,
      region: config.region,
      accessKey: config.accessKey,
      secretKey: config.secretKey,
      useSsl: config.useSsl,
      connectionTimeoutMs: config.connectionTimeoutMs,
      requestTimeoutMs: config.operationTimeoutMs,
    });
    this.bucket = config.bucket;
    this.operationTimeoutMs = config.operationTimeoutMs;
    this.deploymentEnvironment = config.deploymentEnvironment;
    this.allowDevelopmentAdapters = config.allowDevelopmentAdapters;
    this.logger = options.logger ?? silentLogger;
    this.correlationId = options.correlationId;
  }

  public destroy(): void {
    this.client.destroy();
  }

  public async verifyPrivateStorageAvailability(input?: {
    signal?: AbortSignal;
  }): Promise<
    Result<
      { bucketPrivate: true; publicAccessDisabled: true; signedUrlsDisabled: true },
      IntelligenceSnapshotStorageFailure
    >
  > {
    const started = Date.now();
    const abort = combineAbortSignals(input?.signal, this.operationTimeoutMs);
    try {
      await this.client.send(new HeadBucketCommand({ Bucket: this.bucket }), {
        abortSignal: abort.signal,
      });
      this.logOk('head_bucket', started);
      return ok(PRIVACY);
    } catch (error) {
      const mapped = mapStorageFailure(this.classify(error, 'head_bucket', abort));
      this.logFailure('head_bucket', mapped.code, started);
      return err(mapped);
    }
  }

  public async initializeDevelopmentBucket(input: {
    explicitlyAllowed: true;
    bucket: string;
  }): Promise<Result<void, IntelligenceSnapshotStorageFailure>> {
    const started = Date.now();
    if (
      this.deploymentEnvironment === 'production' ||
      this.allowDevelopmentAdapters !== true ||
      input.explicitlyAllowed !== true
    ) {
      this.logFailure('create_bucket', 'snapshot_storage_failed', started);
      return err(mapStorageFailure('internal'));
    }

    if (input.bucket !== this.bucket || !isValidObjectStorageBucketName(input.bucket)) {
      this.logFailure('create_bucket', 'snapshot_storage_failed', started);
      return err(mapStorageFailure('internal'));
    }

    const abort = combineAbortSignals(undefined, this.operationTimeoutMs);
    try {
      await this.client.send(new HeadBucketCommand({ Bucket: this.bucket }), {
        abortSignal: abort.signal,
      });
      this.logOk('create_bucket', started);
      return ok(undefined);
    } catch (error) {
      const headCategory = this.classify(error, 'head_bucket', abort);
      if (headCategory !== 'bucket_missing') {
        const mapped = mapStorageFailure(headCategory);
        this.logFailure('create_bucket', mapped.code, started);
        return err(mapped);
      }
    }

    try {
      await this.client.send(new CreateBucketCommand({ Bucket: this.bucket }), {
        abortSignal: abort.signal,
      });
      this.logOk('create_bucket', started);
      return ok(undefined);
    } catch (error) {
      if (isAlreadyOwnedBucketError(error)) {
        this.logOk('create_bucket', started);
        return ok(undefined);
      }

      const mapped = mapStorageFailure(this.classify(error, 'create_bucket', abort));
      this.logFailure('create_bucket', mapped.code, started);
      return err(mapped);
    }
  }

  public async putTemporarySnapshot(input: {
    temporaryObjectKey: string;
    body: AsyncIterable<Uint8Array>;
    contentType: string;
    maxBytes: number;
    declaredByteLength?: number;
    signal?: AbortSignal;
  }): Promise<
    Result<{ sha256: string; observedByteLength: number }, IntelligenceSnapshotStorageFailure>
  > {
    const started = Date.now();
    if (!isTemporaryIntelligenceSnapshotObjectKey(input.temporaryObjectKey)) {
      this.logFailure('put_temporary', 'snapshot_storage_failed', started);
      return err(mapStorageFailure('internal'));
    }

    if (!Number.isInteger(input.maxBytes) || input.maxBytes < 1) {
      this.logFailure('put_temporary', 'snapshot_storage_failed', started);
      return err(mapStorageFailure('internal'));
    }

    if (input.declaredByteLength !== undefined) {
      if (input.declaredByteLength < 1) {
        this.logFailure('put_temporary', 'hash_mismatch', started);
        return err(mapStorageFailure('invalid_content'));
      }

      if (input.declaredByteLength > input.maxBytes) {
        this.logFailure('put_temporary', 'response_too_large', started);
        return err(mapStorageFailure('size_limit'));
      }
    }

    const abort = combineAbortSignals(input.signal, this.operationTimeoutMs);
    const inspect = createHashCountTransform({ maxBytes: input.maxBytes });
    const source = readableFromByteStream(input.body, abort.signal);
    let inspectCategory: StorageFailureCategory | undefined;

    inspect.on('error', (error: unknown) => {
      inspectCategory =
        error instanceof ObjectStorageStreamError ? error.category : inspectCategory;
      source.destroy(error instanceof Error ? error : new ObjectStorageStreamError('internal'));
    });
    source.on('error', (error: unknown) => {
      inspect.destroy(error instanceof Error ? error : new ObjectStorageStreamError('internal'));
    });
    source.pipe(inspect);

    const inspectFailed = new Promise<never>((_resolve, reject) => {
      inspect.once('error', (error: unknown) => {
        reject(error instanceof Error ? error : new ObjectStorageStreamError('internal'));
      });
    });
    void inspectFailed.catch(() => undefined);

    const putInput: ConstructorParameters<typeof PutObjectCommand>[0] = {
      Bucket: this.bucket,
      Key: input.temporaryObjectKey,
      Body: inspect,
      ContentType: input.contentType,
      ...(input.declaredByteLength === undefined
        ? {}
        : { ContentLength: input.declaredByteLength }),
    };

    try {
      const putSent = this.client.send(new PutObjectCommand(putInput), {
        abortSignal: abort.signal,
      });
      void putSent.catch(() => undefined);
      await Promise.race([putSent, inspectFailed]);

      const observedByteLength = inspect.observedByteLength();
      const sha256 = inspect.sha256Hex();
      if (
        input.declaredByteLength !== undefined &&
        input.declaredByteLength !== observedByteLength
      ) {
        await this.bestEffortDeleteTemporary(input.temporaryObjectKey);
        this.logFailure('put_temporary', 'hash_mismatch', started);
        return err(mapStorageFailure('invalid_content'));
      }

      this.logOk('put_temporary', started);
      return ok({ sha256, observedByteLength });
    } catch (error) {
      destroyStream(source);
      destroyStream(inspect);
      await this.bestEffortDeleteTemporary(input.temporaryObjectKey);
      const category = abort.timedOut()
        ? 'timeout'
        : abort.callerAborted()
          ? 'aborted'
          : (inspectCategory ?? this.classify(error, 'put_object', abort));
      const mapped = mapStorageFailure(category);
      this.logFailure('put_temporary', mapped.code, started);
      return err(mapped);
    }
  }

  public async promoteTemporarySnapshot(input: {
    temporaryObjectKey: string;
    finalObjectKey: string;
    expectedSha256: string;
    expectedByteLength: number;
    contentType: string;
    signal?: AbortSignal;
  }): Promise<
    Result<
      { outcome: 'copied' | 'reused'; temporaryCleanup: 'deleted' | 'failed' },
      IntelligenceSnapshotStorageFailure
    >
  > {
    const started = Date.now();
    if (
      !isTemporaryIntelligenceSnapshotObjectKey(input.temporaryObjectKey) ||
      !isFinalIntelligenceSnapshotObjectKey(input.finalObjectKey)
    ) {
      this.logFailure('copy_promote', 'snapshot_storage_failed', started);
      return err(mapStorageFailure('internal'));
    }

    if (!SHA256_HEX_PATTERN.test(input.expectedSha256)) {
      this.logFailure('copy_promote', 'snapshot_storage_failed', started);
      return err(mapStorageFailure('internal'));
    }

    if (
      sha256FromFinalIntelligenceSnapshotObjectKey(input.finalObjectKey) !== input.expectedSha256
    ) {
      this.logFailure('copy_promote', 'hash_mismatch', started);
      return err(mapStorageFailure('invalid_content'));
    }

    if (!intelligenceObjectKeysShareScope(input.temporaryObjectKey, input.finalObjectKey)) {
      this.logFailure('copy_promote', 'snapshot_storage_failed', started);
      return err(mapStorageFailure('internal'));
    }

    const abort = combineAbortSignals(input.signal, this.operationTimeoutMs);
    const existing = await this.headObjectRaw(input.finalObjectKey, abort);
    if (!existing.ok) {
      this.logFailure('copy_promote', existing.error.code, started);
      return existing;
    }

    if (existing.value.exists) {
      if (!this.finalObjectMatches(existing.value, input)) {
        this.logFailure('copy_promote', 'snapshot_storage_failed', started);
        return err(mapStorageFailure('copy_failed'));
      }

      const temporaryCleanup = await this.deleteTemporaryAfterSuccess(input.temporaryObjectKey);
      this.logOk('copy_promote', started);
      return ok({ outcome: 'reused', temporaryCleanup });
    }

    try {
      await this.client.send(
        new CopyObjectCommand({
          Bucket: this.bucket,
          Key: input.finalObjectKey,
          CopySource: encodeS3CopySource(this.bucket, input.temporaryObjectKey),
          MetadataDirective: 'REPLACE',
          ContentType: input.contentType,
          Metadata: {
            [INTELLIGENCE_RESPONSE_SHA256_METADATA_KEY]: input.expectedSha256,
            [INTELLIGENCE_BYTE_LENGTH_METADATA_KEY]: String(input.expectedByteLength),
            [INTELLIGENCE_DECLARED_CONTENT_TYPE_METADATA_KEY]: input.contentType,
            [INTELLIGENCE_DETECTED_CONTENT_TYPE_METADATA_KEY]: input.contentType,
            [INTELLIGENCE_PROVIDER_METADATA_KEY]: 'cisa_kev',
            [INTELLIGENCE_SOURCE_IDENTIFIER_METADATA_KEY]: 'cisa_kev_json_catalog',
          },
        }),
        { abortSignal: abort.signal },
      );
    } catch (error) {
      const mapped = mapStorageFailure(this.classify(error, 'copy_object', abort));
      this.logFailure('copy_promote', mapped.code, started);
      return err(mapped);
    }

    const copied = await this.headObjectRaw(input.finalObjectKey, abort);
    if (!copied.ok) {
      this.logFailure('copy_promote', copied.error.code, started);
      return copied;
    }

    if (!copied.value.exists || !this.finalObjectMatches(copied.value, input)) {
      this.logFailure('copy_promote', 'snapshot_storage_failed', started);
      return err(mapStorageFailure('copy_failed'));
    }

    const temporaryCleanup = await this.deleteTemporaryAfterSuccess(input.temporaryObjectKey);
    this.logOk('copy_promote', started);
    return ok({ outcome: 'copied', temporaryCleanup });
  }

  public async headFinalSnapshot(input: {
    finalObjectKey: string;
    signal?: AbortSignal;
  }): Promise<Result<IntelligenceSnapshotExistence, IntelligenceSnapshotStorageFailure>> {
    const started = Date.now();
    if (!isFinalIntelligenceSnapshotObjectKey(input.finalObjectKey)) {
      this.logFailure('head_final', 'snapshot_storage_failed', started);
      return err(mapStorageFailure('internal'));
    }

    const abort = combineAbortSignals(input.signal, this.operationTimeoutMs);
    const result = await this.headObjectRaw(input.finalObjectKey, abort);
    if (!result.ok) {
      this.logFailure('head_final', result.error.code, started);
      return result;
    }

    this.logOk('head_final', started);
    if (!result.value.exists) {
      return ok({ exists: false });
    }

    return ok({
      exists: true,
      byteLength: result.value.byteLength,
      sha256: result.value.sha256,
      declaredContentType: result.value.declaredContentType,
      detectedContentType: result.value.detectedContentType,
      provider: 'cisa_kev',
      sourceIdentifier: 'cisa_kev_json_catalog',
    });
  }

  public async deleteTemporarySnapshot(input: {
    temporaryObjectKey: string;
    signal?: AbortSignal;
  }): Promise<Result<void, IntelligenceSnapshotStorageFailure>> {
    const started = Date.now();
    if (!isTemporaryIntelligenceSnapshotObjectKey(input.temporaryObjectKey)) {
      this.logFailure('delete_temporary', 'snapshot_storage_failed', started);
      return err(mapStorageFailure('internal'));
    }

    const abort = combineAbortSignals(input.signal, this.operationTimeoutMs);
    try {
      await this.client.send(
        new DeleteObjectCommand({
          Bucket: this.bucket,
          Key: input.temporaryObjectKey,
        }),
        { abortSignal: abort.signal },
      );
      this.logOk('delete_temporary', started);
      return ok(undefined);
    } catch (error) {
      const category = this.classify(error, 'delete_object', abort);
      if (category === 'object_missing') {
        this.logOk('delete_temporary', started);
        return ok(undefined);
      }

      const mapped = mapStorageFailure(category);
      this.logFailure('delete_temporary', mapped.code, started);
      return err(mapped);
    }
  }

  public async getFinalSnapshot(input: {
    finalObjectKey: string;
    maxBytes: number;
    expectedByteLength?: number;
    expectedSha256?: string;
    signal?: AbortSignal;
  }): Promise<
    Result<
      {
        body: AsyncIterable<Uint8Array>;
        declaredByteLength?: number;
        completion: Promise<IntelligenceStreamCompletion>;
        cancel: () => Promise<void>;
      },
      IntelligenceSnapshotStorageFailure
    >
  > {
    const started = Date.now();
    if (!isFinalIntelligenceSnapshotObjectKey(input.finalObjectKey)) {
      this.logFailure('get_object', 'snapshot_storage_failed', started);
      return err(mapStorageFailure('internal'));
    }

    if (!Number.isInteger(input.maxBytes) || input.maxBytes < 1) {
      this.logFailure('get_object', 'snapshot_storage_failed', started);
      return err(mapStorageFailure('internal'));
    }

    const abort = combineAbortSignals(input.signal, this.operationTimeoutMs);
    try {
      const response = await this.client.send(
        new GetObjectCommand({
          Bucket: this.bucket,
          Key: input.finalObjectKey,
        }),
        { abortSignal: abort.signal },
      );

      const declared = response.ContentLength;
      if (declared !== undefined && declared > input.maxBytes) {
        destroyStream(response.Body);
        this.logFailure('get_object', 'response_too_large', started);
        return err(mapStorageFailure('size_limit'));
      }

      if (
        input.expectedByteLength !== undefined &&
        declared !== undefined &&
        declared !== input.expectedByteLength
      ) {
        destroyStream(response.Body);
        this.logFailure('get_object', 'hash_mismatch', started);
        return err(mapStorageFailure('invalid_content'));
      }

      if (response.Body === undefined) {
        this.logFailure('get_object', 'snapshot_storage_failed', started);
        return err(mapStorageFailure('internal'));
      }

      const sdkStream = asNodeReadable(response.Body);
      const inspect = createHashCountTransform({
        maxBytes: input.maxBytes,
        ...(input.expectedByteLength === undefined
          ? {}
          : { expectedByteLength: input.expectedByteLength }),
        ...(input.expectedSha256 === undefined ? {} : { expectedSha256: input.expectedSha256 }),
      });
      const handle = this.createGetHandle({ sdkStream, inspect, declared, abort });
      this.logOk('get_object', started);
      return ok(handle);
    } catch (error) {
      const mapped = mapStorageFailure(this.classify(error, 'get_object', abort));
      this.logFailure('get_object', mapped.code, started);
      return err(mapped);
    }
  }

  private createGetHandle(input: {
    sdkStream: ReturnType<typeof asNodeReadable>;
    inspect: ReturnType<typeof createHashCountTransform>;
    declared: number | undefined;
    abort: ReturnType<typeof combineAbortSignals>;
  }): {
    body: AsyncIterable<Uint8Array>;
    declaredByteLength?: number;
    completion: Promise<IntelligenceStreamCompletion>;
    cancel: () => Promise<void>;
  } {
    const { sdkStream, inspect, declared, abort } = input;
    let settled = false;
    let resolveCompletion!: (value: IntelligenceStreamCompletion) => void;
    let rejectCompletion!: (reason: IntelligenceSnapshotStorageFailure) => void;
    const completion = new Promise<IntelligenceStreamCompletion>((resolve, reject) => {
      resolveCompletion = resolve;
      rejectCompletion = reject;
    });
    void completion.catch(() => undefined);

    const fail = (category: StorageFailureCategory): void => {
      if (settled) {
        return;
      }

      settled = true;
      destroyStream(sdkStream);
      destroyStream(inspect);
      rejectCompletion(mapStorageFailure(category));
    };

    inspect.on('error', (error: unknown) => {
      fail(
        error instanceof ObjectStorageStreamError
          ? error.category
          : this.classify(error, 'get_object', abort),
      );
    });
    sdkStream.on('error', (error: unknown) => {
      fail(this.classify(error, 'get_object', abort));
    });
    inspect.on('end', () => {
      if (settled) {
        return;
      }

      settled = true;
      resolveCompletion({
        observedByteLength: inspect.observedByteLength(),
        sha256: inspect.sha256Hex(),
      });
    });
    abort.signal.addEventListener(
      'abort',
      () => {
        fail(abort.callerAborted() ? 'aborted' : 'timeout');
      },
      { once: true },
    );
    sdkStream.pipe(inspect);

    return {
      body: inspect,
      ...(declared === undefined ? {} : { declaredByteLength: declared }),
      completion,
      cancel: async () => {
        fail('aborted');
      },
    };
  }

  private async headObjectRaw(
    objectKey: string,
    abort: ReturnType<typeof combineAbortSignals>,
  ): Promise<
    Result<
      { exists: false } | ({ exists: true } & FinalMetadata),
      IntelligenceSnapshotStorageFailure
    >
  > {
    try {
      const head = await this.client.send(
        new HeadObjectCommand({
          Bucket: this.bucket,
          Key: objectKey,
        }),
        { abortSignal: abort.signal },
      );
      const byteLength = head.ContentLength;
      if (byteLength === undefined) {
        return err(mapStorageFailure('internal'));
      }

      const sha256 = metadataValue(head.Metadata, INTELLIGENCE_RESPONSE_SHA256_METADATA_KEY);
      const provider = metadataValue(head.Metadata, INTELLIGENCE_PROVIDER_METADATA_KEY);
      const sourceIdentifier = metadataValue(
        head.Metadata,
        INTELLIGENCE_SOURCE_IDENTIFIER_METADATA_KEY,
      );
      if (
        sha256 === undefined ||
        !SHA256_HEX_PATTERN.test(sha256) ||
        provider !== 'cisa_kev' ||
        sourceIdentifier !== 'cisa_kev_json_catalog'
      ) {
        return err(mapStorageFailure('copy_failed'));
      }

      return ok({
        exists: true,
        byteLength,
        sha256,
        declaredContentType:
          metadataValue(head.Metadata, INTELLIGENCE_DECLARED_CONTENT_TYPE_METADATA_KEY) ?? null,
        detectedContentType:
          metadataValue(head.Metadata, INTELLIGENCE_DETECTED_CONTENT_TYPE_METADATA_KEY) ?? null,
        provider: 'cisa_kev',
        sourceIdentifier: 'cisa_kev_json_catalog',
      });
    } catch (error) {
      const category = this.classify(error, 'head_object', abort);
      if (category === 'object_missing') {
        return ok({ exists: false });
      }

      return err(mapStorageFailure(category));
    }
  }

  private finalObjectMatches(
    existing: { exists: true } & FinalMetadata,
    input: { expectedSha256: string; expectedByteLength: number; contentType: string },
  ): boolean {
    return (
      existing.byteLength === input.expectedByteLength &&
      existing.sha256 === input.expectedSha256 &&
      existing.provider === 'cisa_kev' &&
      existing.sourceIdentifier === 'cisa_kev_json_catalog'
    );
  }

  private async deleteTemporaryAfterSuccess(
    temporaryObjectKey: string,
  ): Promise<'deleted' | 'failed'> {
    try {
      await this.client.send(
        new DeleteObjectCommand({
          Bucket: this.bucket,
          Key: temporaryObjectKey,
        }),
      );
      return 'deleted';
    } catch {
      this.logger.warn(this.safeBindings('delete_temporary', Date.now()), 'tmp_cleanup_failed');
      return 'failed';
    }
  }

  private async bestEffortDeleteTemporary(temporaryObjectKey: string): Promise<void> {
    await this.deleteTemporaryAfterSuccess(temporaryObjectKey);
  }

  private classify(
    error: unknown,
    operation: S3Operation,
    abort: ReturnType<typeof combineAbortSignals>,
  ): StorageFailureCategory {
    return classifiedStorageFailure(error, {
      operation,
      callerAborted: abort.callerAborted(),
      timedOut: abort.timedOut(),
    }).category;
  }

  private logOk(operation: string, started: number): void {
    this.logger.info(this.safeBindings(operation, started), 'intelligence snapshot storage ok');
  }

  private logFailure(operation: string, code: string, started: number): void {
    this.logger.warn(
      { ...this.safeBindings(operation, started), code },
      'intelligence snapshot storage failed',
    );
  }

  private safeBindings(operation: string, started: number): Record<string, unknown> {
    return {
      operation,
      provider: 'cisa_kev',
      sourceIdentifier: 'cisa_kev_json_catalog',
      durationMs: Math.max(0, Date.now() - started),
      ...(this.correlationId === undefined ? {} : { correlationId: this.correlationId }),
    };
  }
}

export function createS3IntelligenceSnapshotStorage(
  config: S3IntelligenceSnapshotStorageConfig,
  options?: S3IntelligenceSnapshotStorageOptions,
): S3IntelligenceSnapshotStorage {
  return new S3IntelligenceSnapshotStorage(config, options ?? {});
}
