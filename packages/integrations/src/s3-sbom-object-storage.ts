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
  isFinalSbomObjectKey,
  isTemporarySbomObjectKey,
  ok,
  SHA256_HEX_PATTERN,
  sbomObjectKeysShareScope,
  sha256FromFinalSbomObjectKey,
  type ClassifiedStorageFailure,
  type DeleteTemporaryObjectInput,
  type GetObjectInput,
  type GetObjectResult,
  type HeadObjectInput,
  type InitializeDevelopmentBucketInput,
  type ObjectStorageExistence,
  type ObjectStoragePrivacyAssumptions,
  type PromoteObjectInput,
  type PutTemporaryObjectInput,
  type PutTemporaryObjectResult,
  type Result,
  type SbomObjectStoragePort,
  type StorageFailureCategory,
} from '@patchpilot/domain';

import { createS3Client } from './s3-client.js';
import {
  encodeS3CopySource,
  SBOM_BYTE_LENGTH_METADATA_KEY,
  SBOM_SHA256_METADATA_KEY,
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
  createGetCountTransform,
  createPutInspectTransform,
  destroyStream,
  readableFromByteStream,
} from './s3-stream.js';

const PRIVACY_ASSUMPTIONS: ObjectStoragePrivacyAssumptions = {
  bucketPrivate: true,
  publicAccessDisabled: true,
  signedUrlsDisabled: true,
};

export type S3SbomObjectStorageConfig = {
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

export type ObjectStorageLogger = {
  info: (bindings: Record<string, unknown>, message: string) => void;
  warn: (bindings: Record<string, unknown>, message: string) => void;
  error: (bindings: Record<string, unknown>, message: string) => void;
};

export type S3SbomObjectStorageOptions = {
  logger?: ObjectStorageLogger;
  correlationId?: string;
};

const silentLogger: ObjectStorageLogger = {
  info: () => undefined,
  warn: () => undefined,
  error: () => undefined,
};

export class S3SbomObjectStorage implements SbomObjectStoragePort {
  private readonly client: S3Client;
  private readonly bucket: string;
  private readonly operationTimeoutMs: number;
  private readonly deploymentEnvironment: S3SbomObjectStorageConfig['deploymentEnvironment'];
  private readonly allowDevelopmentAdapters: boolean;
  private readonly logger: ObjectStorageLogger;
  private readonly correlationId: string | undefined;

  public constructor(config: S3SbomObjectStorageConfig, options: S3SbomObjectStorageOptions = {}) {
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

  public async verifyBucketAvailability(input?: {
    signal?: AbortSignal;
  }): Promise<Result<ObjectStoragePrivacyAssumptions, ClassifiedStorageFailure>> {
    const started = Date.now();
    const abort = combineAbortSignals(input?.signal, this.operationTimeoutMs);
    try {
      await this.client.send(new HeadBucketCommand({ Bucket: this.bucket }), {
        abortSignal: abort.signal,
      });
      this.logOk('head_bucket', started);
      return ok(PRIVACY_ASSUMPTIONS);
    } catch (error) {
      const category = this.classify(error, 'head_bucket', abort);
      this.logFailure('head_bucket', category, started);
      return err({ category });
    }
  }

  public async initializeDevelopmentBucket(
    input: InitializeDevelopmentBucketInput,
  ): Promise<Result<void, ClassifiedStorageFailure>> {
    const started = Date.now();
    if (
      this.deploymentEnvironment === 'production' ||
      this.allowDevelopmentAdapters !== true ||
      input.explicitlyAllowed !== true
    ) {
      this.logFailure('create_bucket', 'internal', started);
      return err({ category: 'internal' });
    }

    if (input.bucket !== this.bucket || !isValidObjectStorageBucketName(input.bucket)) {
      this.logFailure('create_bucket', 'internal', started);
      return err({ category: 'internal' });
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
        this.logFailure('create_bucket', headCategory, started);
        return err({ category: headCategory });
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

      const category = this.classify(error, 'create_bucket', abort);
      this.logFailure('create_bucket', category, started);
      return err({ category });
    }
  }

  public async putTemporaryObject(
    input: PutTemporaryObjectInput,
  ): Promise<Result<PutTemporaryObjectResult, ClassifiedStorageFailure>> {
    const started = Date.now();
    if (!isTemporarySbomObjectKey(input.temporaryObjectKey)) {
      this.logFailure('put_temporary', 'internal', started);
      return err({ category: 'internal' });
    }

    if (!Number.isInteger(input.maxBytes) || input.maxBytes < 1) {
      this.logFailure('put_temporary', 'internal', started);
      return err({ category: 'internal' });
    }

    if (input.declaredByteLength !== undefined) {
      if (input.declaredByteLength < 1) {
        this.logFailure('put_temporary', 'invalid_content', started);
        return err({ category: 'invalid_content' });
      }

      if (input.declaredByteLength > input.maxBytes) {
        this.logFailure('put_temporary', 'size_limit', started);
        return err({ category: 'size_limit' });
      }
    }

    const abort = combineAbortSignals(input.signal, this.operationTimeoutMs);
    const inspect = createPutInspectTransform({ maxBytes: input.maxBytes });
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
        this.logFailure('put_temporary', 'invalid_content', started);
        return err({ category: 'invalid_content' });
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
      this.logFailure('put_temporary', category, started);
      return err({ category });
    }
  }

  public async promoteTemporaryObject(
    input: PromoteObjectInput,
  ): Promise<Result<void, ClassifiedStorageFailure>> {
    const started = Date.now();
    if (
      !isTemporarySbomObjectKey(input.temporaryObjectKey) ||
      !isFinalSbomObjectKey(input.finalObjectKey)
    ) {
      this.logFailure('copy_promote', 'internal', started);
      return err({ category: 'internal' });
    }

    if (!SHA256_HEX_PATTERN.test(input.expectedSha256)) {
      this.logFailure('copy_promote', 'internal', started);
      return err({ category: 'internal' });
    }

    const keyDigest = sha256FromFinalSbomObjectKey(input.finalObjectKey);
    if (keyDigest !== input.expectedSha256) {
      this.logFailure('copy_promote', 'internal', started);
      return err({ category: 'internal' });
    }

    if (!sbomObjectKeysShareScope(input.temporaryObjectKey, input.finalObjectKey)) {
      this.logFailure('copy_promote', 'internal', started);
      return err({ category: 'internal' });
    }

    const abort = combineAbortSignals(input.signal, this.operationTimeoutMs);
    const existing = await this.headObjectRaw(input.finalObjectKey, abort);
    if (!existing.ok) {
      this.logFailure('copy_promote', existing.error.category, started);
      return existing;
    }

    if (existing.value.exists) {
      const consistent = this.finalObjectMatches(existing.value, input);
      if (!consistent) {
        this.logFailure('copy_promote', 'copy_failed', started);
        return err({ category: 'copy_failed' });
      }

      await this.bestEffortDeleteTemporary(input.temporaryObjectKey);
      this.logOk('copy_promote', started);
      return ok(undefined);
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
            [SBOM_SHA256_METADATA_KEY]: input.expectedSha256,
            [SBOM_BYTE_LENGTH_METADATA_KEY]: String(input.expectedByteLength),
          },
        }),
        { abortSignal: abort.signal },
      );
    } catch (error) {
      const category = this.classify(error, 'copy_object', abort);
      this.logFailure('copy_promote', category, started);
      return err({ category });
    }

    const copied = await this.headObjectRaw(input.finalObjectKey, abort);
    if (!copied.ok) {
      this.logFailure('copy_promote', copied.error.category, started);
      return copied;
    }

    if (!copied.value.exists || !this.finalObjectMatches(copied.value, input)) {
      this.logFailure('copy_promote', 'copy_failed', started);
      return err({ category: 'copy_failed' });
    }

    await this.bestEffortDeleteTemporary(input.temporaryObjectKey);
    this.logOk('copy_promote', started);
    return ok(undefined);
  }

  public async headFinalObject(
    input: HeadObjectInput,
  ): Promise<Result<ObjectStorageExistence, ClassifiedStorageFailure>> {
    const started = Date.now();
    if (!isFinalSbomObjectKey(input.finalObjectKey)) {
      this.logFailure('head_final', 'internal', started);
      return err({ category: 'internal' });
    }

    const abort = combineAbortSignals(input.signal, this.operationTimeoutMs);
    const result = await this.headObjectRaw(input.finalObjectKey, abort);
    if (!result.ok) {
      this.logFailure('head_final', result.error.category, started);
      return result;
    }

    this.logOk('head_final', started);
    if (!result.value.exists) {
      return ok({ exists: false });
    }

    return ok({ exists: true, byteLength: result.value.byteLength });
  }

  public async deleteTemporaryObject(
    input: DeleteTemporaryObjectInput,
  ): Promise<Result<void, ClassifiedStorageFailure>> {
    const started = Date.now();
    if (!isTemporarySbomObjectKey(input.temporaryObjectKey)) {
      this.logFailure('delete_temporary', 'internal', started);
      return err({ category: 'internal' });
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

      this.logFailure('delete_temporary', category, started);
      return err({ category });
    }
  }

  public async getObject(
    input: GetObjectInput,
  ): Promise<Result<GetObjectResult, ClassifiedStorageFailure>> {
    const started = Date.now();
    if (!isFinalSbomObjectKey(input.finalObjectKey)) {
      this.logFailure('get_object', 'internal', started);
      return err({ category: 'internal' });
    }

    if (!Number.isInteger(input.maxBytes) || input.maxBytes < 1) {
      this.logFailure('get_object', 'internal', started);
      return err({ category: 'internal' });
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
        this.logFailure('get_object', 'size_limit', started);
        return err({ category: 'size_limit' });
      }

      if (
        input.expectedByteLength !== undefined &&
        declared !== undefined &&
        declared !== input.expectedByteLength
      ) {
        destroyStream(response.Body);
        this.logFailure('get_object', 'invalid_content', started);
        return err({ category: 'invalid_content' });
      }

      if (response.Body === undefined) {
        this.logFailure('get_object', 'internal', started);
        return err({ category: 'internal' });
      }

      const sdkStream = asNodeReadable(response.Body);
      const inspect = createGetCountTransform({
        maxBytes: input.maxBytes,
        ...(input.expectedByteLength === undefined
          ? {}
          : { expectedByteLength: input.expectedByteLength }),
        ...(input.expectedSha256 === undefined ? {} : { expectedSha256: input.expectedSha256 }),
      });

      const handle = this.createGetHandle({
        sdkStream,
        inspect,
        declared,
        abort,
        started,
      });
      this.logOk('get_object', started);
      return ok(handle);
    } catch (error) {
      const category = this.classify(error, 'get_object', abort);
      this.logFailure('get_object', category, started);
      return err({ category });
    }
  }

  private createGetHandle(input: {
    sdkStream: ReturnType<typeof asNodeReadable>;
    inspect: ReturnType<typeof createGetCountTransform>;
    declared: number | undefined;
    abort: ReturnType<typeof combineAbortSignals>;
    started: number;
  }): GetObjectResult {
    const { sdkStream, inspect, declared, abort } = input;
    let settled = false;
    let resolveCompletion!: (value: { observedByteLength: number; sha256?: string }) => void;
    let rejectCompletion!: (reason: ClassifiedStorageFailure) => void;
    const completion = new Promise<{ observedByteLength: number; sha256?: string }>(
      (resolve, reject) => {
        resolveCompletion = resolve;
        rejectCompletion = reject;
      },
    );
    void completion.catch(() => undefined);

    const fail = (category: StorageFailureCategory): void => {
      if (settled) {
        return;
      }

      settled = true;
      destroyStream(sdkStream);
      destroyStream(inspect);
      rejectCompletion({ category });
    };

    const succeed = (): void => {
      if (settled) {
        return;
      }

      settled = true;
      const sha256 = inspect.sha256Hex();
      resolveCompletion({
        observedByteLength: inspect.observedByteLength(),
        ...(sha256 === undefined ? {} : { sha256 }),
      });
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
      succeed();
    });
    abort.signal.addEventListener(
      'abort',
      () => {
        fail(abort.callerAborted() ? 'aborted' : 'timeout');
      },
      { once: true },
    );

    sdkStream.pipe(inspect);

    const cancel = async (): Promise<void> => {
      fail('aborted');
    };

    return {
      body: inspect,
      ...(declared === undefined ? {} : { declaredByteLength: declared }),
      completion,
      cancel,
    };
  }

  private async headObjectRaw(
    objectKey: string,
    abort: ReturnType<typeof combineAbortSignals>,
  ): Promise<
    | { ok: true; value: ObjectStorageExistence & { sha256?: string } }
    | { ok: false; error: ClassifiedStorageFailure }
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
        return err({ category: 'internal' });
      }

      const sha256 = metadataValue(head.Metadata, SBOM_SHA256_METADATA_KEY);
      return ok({
        exists: true,
        byteLength,
        ...(sha256 === undefined ? {} : { sha256 }),
      });
    } catch (error) {
      const category = this.classify(error, 'head_object', abort);
      if (category === 'object_missing') {
        return ok({ exists: false });
      }

      return err({ category });
    }
  }

  private finalObjectMatches(
    existing: { exists: true; byteLength: number; sha256?: string },
    input: PromoteObjectInput,
  ): boolean {
    if (existing.byteLength !== input.expectedByteLength) {
      return false;
    }

    return existing.sha256 === input.expectedSha256;
  }

  private async bestEffortDeleteTemporary(temporaryObjectKey: string): Promise<void> {
    try {
      await this.client.send(
        new DeleteObjectCommand({
          Bucket: this.bucket,
          Key: temporaryObjectKey,
        }),
      );
    } catch {
      this.logger.warn(this.safeBindings('delete_temporary', Date.now()), 'tmp_cleanup_failed');
    }
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
    this.logger.info(this.safeBindings(operation, started), 'object storage ok');
  }

  private logFailure(operation: string, category: StorageFailureCategory, started: number): void {
    this.logger.warn(
      { ...this.safeBindings(operation, started), category },
      'object storage failed',
    );
  }

  private safeBindings(operation: string, started: number): Record<string, unknown> {
    return {
      operation,
      durationMs: Math.max(0, Date.now() - started),
      ...(this.correlationId === undefined ? {} : { correlationId: this.correlationId }),
    };
  }
}

export function createS3SbomObjectStorage(
  config: S3SbomObjectStorageConfig,
  options?: S3SbomObjectStorageOptions,
): S3SbomObjectStorage {
  return new S3SbomObjectStorage(config, options ?? {});
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
