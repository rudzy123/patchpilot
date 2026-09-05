/**
 * Session 11 Batch 5E immutable S3-compatible adapter for OSV advisory-body
 * and parsed-document artifacts. Reuses the existing private bucket, client,
 * and copy-source helpers. Provider keys are never storage paths.
 *
 * PostgreSQL is not used. Bytes are synthetic and locally supplied.
 * There is no provider retrieval, signed URL, public ACL, or Finding path.
 */

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
import { SHA256_HEX_PATTERN, UUID_PATTERN } from '@patchpilot/domain';
import { createHash } from 'node:crypto';
import { finished } from 'node:stream/promises';

import { createS3Client } from './s3-client.js';
import { encodeS3CopySource } from './s3-copy-source.js';
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
} from './s3-stream.js';
import type { ObjectStorageLogger } from './s3-sbom-object-storage.js';

const ADVISORY_BODY_TMP = 'intelligence/osv/advisory_body/tmp/';
const ADVISORY_BODY_FINAL = 'intelligence/osv/advisory_body/sha256/';
const PARSED_TMP = 'intelligence/osv/parsed_advisory/tmp/';
const PARSED_FINAL = 'intelligence/osv/parsed_advisory/sha256/';
const LAYOUT_VERSION = 'osv_object_storage_layout_v1';
const CONTENT_TYPE = 'application/json';
const CONTENT_ENCODING = 'identity';
const MIN_BYTES = 1;
const MAX_BYTES = 1_048_576;

const META_SHA256 = 'content-sha256';
const META_BYTES = 'byte-length';
const META_CATEGORY = 'artifact-category';
const META_ENCODING = 'content-encoding';
const META_LAYOUT = 'storage-layout-version';

export type OsvS3Locator = {
  readonly kind: 'osv_object_storage_locator';
  readonly storageKind: 'advisory_body' | 'parsed_advisory';
  readonly role: 'temporary' | 'final';
  readonly objectKey: string;
  readonly contentSha256: string | null;
  readonly uploadId: string | null;
};

export type OsvS3StorageFailure = {
  readonly ok: false;
  readonly code:
    | 'invalid_storage_identity'
    | 'object_not_found'
    | 'immutable_conflict'
    | 'integrity_mismatch'
    | 'byte_count_mismatch'
    | 'content_type_mismatch'
    | 'content_encoding_mismatch'
    | 'response_too_large'
    | 'storage_unavailable'
    | 'storage_timeout'
    | 'access_denied'
    | 'precondition_failed'
    | 'partial_read_rejected';
  readonly retryability: 'non_retryable' | 'orchestration_retryable';
};

type OsvS3Ok<T> = { readonly ok: true; readonly value: T };
type OsvS3Result<T> = OsvS3Ok<T> | OsvS3StorageFailure;

export type S3OsvAdvisoryObjectStorageConfig = {
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

const silentLogger: ObjectStorageLogger = {
  info: () => undefined,
  warn: () => undefined,
  error: () => undefined,
};

function ok<T>(value: T): OsvS3Ok<T> {
  return { ok: true, value };
}

function fail(code: OsvS3StorageFailure['code']): OsvS3StorageFailure {
  const retryability =
    code === 'storage_unavailable' || code === 'storage_timeout'
      ? 'orchestration_retryable'
      : 'non_retryable';
  return Object.freeze({ ok: false, code, retryability });
}

function containsControlOrLineSeparator(objectKey: string): boolean {
  for (let index = 0; index < objectKey.length; index += 1) {
    const code = objectKey.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f || code === 0x2028 || code === 0x2029) {
      return true;
    }
  }
  return false;
}

function containsForbiddenFragment(objectKey: string): boolean {
  return (
    objectKey.includes('..') ||
    objectKey.includes('\\') ||
    objectKey.includes('//') ||
    objectKey.includes('://') ||
    objectKey.includes('org/') ||
    objectKey.includes('.json') ||
    objectKey.includes('npm/') ||
    objectKey.includes('%') ||
    containsControlOrLineSeparator(objectKey)
  );
}

function copyBody(bytes: Uint8Array): Uint8Array {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy;
}

function concatChunks(chunks: readonly Uint8Array[]): Uint8Array {
  let total = 0;
  for (const chunk of chunks) {
    total += chunk.byteLength;
  }
  const copy = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    copy.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return copy;
}

export function isCompiledOsvS3ObjectKey(objectKey: string): boolean {
  if (typeof objectKey !== 'string' || containsForbiddenFragment(objectKey)) {
    return false;
  }
  if (objectKey.startsWith(ADVISORY_BODY_TMP) || objectKey.startsWith(PARSED_TMP)) {
    const token = objectKey.startsWith(ADVISORY_BODY_TMP)
      ? objectKey.slice(ADVISORY_BODY_TMP.length)
      : objectKey.slice(PARSED_TMP.length);
    return UUID_PATTERN.test(token) && token === token.toLowerCase();
  }
  if (objectKey.startsWith(ADVISORY_BODY_FINAL) || objectKey.startsWith(PARSED_FINAL)) {
    const digest = objectKey.startsWith(ADVISORY_BODY_FINAL)
      ? objectKey.slice(ADVISORY_BODY_FINAL.length)
      : objectKey.slice(PARSED_FINAL.length);
    return SHA256_HEX_PATTERN.test(digest);
  }
  return false;
}

function locatorMatchesKey(locator: OsvS3Locator): boolean {
  if (locator.kind !== 'osv_object_storage_locator') {
    return false;
  }
  if (!isCompiledOsvS3ObjectKey(locator.objectKey)) {
    return false;
  }
  if (locator.role === 'temporary') {
    const prefix = locator.storageKind === 'advisory_body' ? ADVISORY_BODY_TMP : PARSED_TMP;
    return (
      locator.objectKey === `${prefix}${locator.uploadId ?? ''}` &&
      locator.uploadId !== null &&
      UUID_PATTERN.test(locator.uploadId)
    );
  }
  const prefix = locator.storageKind === 'advisory_body' ? ADVISORY_BODY_FINAL : PARSED_FINAL;
  return (
    locator.contentSha256 !== null &&
    SHA256_HEX_PATTERN.test(locator.contentSha256) &&
    locator.objectKey === `${prefix}${locator.contentSha256}`
  );
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

function mapCategory(
  error: unknown,
  operation: S3Operation,
  abort: ReturnType<typeof combineAbortSignals>,
): OsvS3StorageFailure['code'] {
  const classified = classifiedStorageFailure(error, {
    operation,
    callerAborted: abort.callerAborted(),
    timedOut: abort.timedOut(),
  }).category;
  if (classified === 'object_missing') {
    return 'object_not_found';
  }
  if (classified === 'timeout' || classified === 'aborted') {
    return 'storage_timeout';
  }
  if (classified === 'access_denied') {
    return 'access_denied';
  }
  if (classified === 'size_limit') {
    return 'response_too_large';
  }
  if (classified === 'invalid_content') {
    return 'integrity_mismatch';
  }
  if (classified === 'storage_unavailable') {
    return 'storage_unavailable';
  }
  const status = httpStatus(error);
  if (status === 412) {
    return 'precondition_failed';
  }
  return 'storage_unavailable';
}

function httpStatus(error: unknown): number | undefined {
  if (typeof error !== 'object' || error === null || !('$metadata' in error)) {
    return undefined;
  }
  const metadata = (error as { $metadata?: { httpStatusCode?: unknown } }).$metadata;
  if (metadata !== undefined && typeof metadata.httpStatusCode === 'number') {
    return metadata.httpStatusCode;
  }
  return undefined;
}

function isWriteOncePrecondition(error: unknown): boolean {
  const status = httpStatus(error);
  return status === 412 || status === 409;
}

export class S3OsvAdvisoryObjectStorage {
  private readonly client: S3Client;
  private readonly bucket: string;
  private readonly operationTimeoutMs: number;
  private readonly deploymentEnvironment: S3OsvAdvisoryObjectStorageConfig['deploymentEnvironment'];
  private readonly allowDevelopmentAdapters: boolean;
  private readonly logger: ObjectStorageLogger;
  private readonly correlationId: string | undefined;

  public constructor(
    config: S3OsvAdvisoryObjectStorageConfig,
    options: { logger?: ObjectStorageLogger; correlationId?: string } = {},
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

  public async initializeDevelopmentBucket(input: {
    explicitlyAllowed: true;
    bucket: string;
  }): Promise<OsvS3Result<void>> {
    if (
      this.deploymentEnvironment === 'production' ||
      this.allowDevelopmentAdapters !== true ||
      input.explicitlyAllowed !== true ||
      input.bucket !== this.bucket ||
      !isValidObjectStorageBucketName(input.bucket)
    ) {
      return fail('access_denied');
    }
    const abort = combineAbortSignals(undefined, this.operationTimeoutMs);
    try {
      await this.client.send(new HeadBucketCommand({ Bucket: this.bucket }), {
        abortSignal: abort.signal,
      });
      return ok(undefined);
    } catch (error) {
      const headCode = mapCategory(error, 'head_bucket', abort);
      if (headCode !== 'object_not_found' && headCode !== 'storage_unavailable') {
        return fail(headCode);
      }
    }
    try {
      await this.client.send(new CreateBucketCommand({ Bucket: this.bucket }), {
        abortSignal: abort.signal,
      });
      return ok(undefined);
    } catch (error) {
      if (isAlreadyOwnedBucketError(error)) {
        return ok(undefined);
      }
      return fail(mapCategory(error, 'create_bucket', abort));
    }
  }

  public async putExclusive(input: {
    readonly locator: OsvS3Locator;
    readonly body: Uint8Array;
    readonly contentSha256: string;
    readonly byteCount: number;
    readonly contentType: string;
    readonly contentEncoding: string;
    readonly artifactCategory: 'advisory_body' | 'parsed_advisory';
  }): Promise<OsvS3Result<{ status: 'created' | 'already_applied' }>> {
    const started = Date.now();
    if (!locatorMatchesKey(input.locator) || input.locator.storageKind !== input.artifactCategory) {
      this.logFailure('put_exclusive', started);
      return fail('invalid_storage_identity');
    }
    if (input.contentType !== CONTENT_TYPE) {
      return fail('content_type_mismatch');
    }
    if (input.contentEncoding !== CONTENT_ENCODING) {
      return fail('content_encoding_mismatch');
    }
    if (
      input.body.byteLength !== input.byteCount ||
      input.byteCount < MIN_BYTES ||
      input.byteCount > MAX_BYTES
    ) {
      return fail(input.byteCount > MAX_BYTES ? 'response_too_large' : 'byte_count_mismatch');
    }
    if (!SHA256_HEX_PATTERN.test(input.contentSha256)) {
      return fail('integrity_mismatch');
    }
    const body = copyBody(input.body);
    const actualSha256 = createHash('sha256').update(body).digest('hex');
    if (actualSha256 !== input.contentSha256) {
      return fail('integrity_mismatch');
    }
    const existing = await this.head({ locator: input.locator });
    if (!existing.ok) {
      return existing;
    }
    if (existing.value.exists) {
      if (!this.existingMatches(existing.value, input)) {
        this.logFailure('put_exclusive', started);
        return fail('immutable_conflict');
      }
      return this.compareVerifiedBytes(input.locator, input, started, 'put_exclusive');
    }
    const abort = combineAbortSignals(undefined, this.operationTimeoutMs);
    try {
      await this.client.send(
        new PutObjectCommand({
          Bucket: this.bucket,
          Key: input.locator.objectKey,
          Body: body,
          ContentLength: input.byteCount,
          ContentType: CONTENT_TYPE,
          IfNoneMatch: '*',
          Metadata: {
            [META_SHA256]: input.contentSha256,
            [META_BYTES]: String(input.byteCount),
            [META_CATEGORY]: input.artifactCategory,
            [META_ENCODING]: CONTENT_ENCODING,
            [META_LAYOUT]: LAYOUT_VERSION,
          },
        }),
        { abortSignal: abort.signal },
      );
      this.logOk('put_exclusive', started);
      return ok({ status: 'created' });
    } catch (error) {
      if (isWriteOncePrecondition(error)) {
        return this.compareVerifiedBytes(input.locator, input, started, 'put_exclusive');
      }
      this.logFailure('put_exclusive', started);
      return fail(mapCategory(error, 'put_object', abort));
    }
  }

  public async head(input: { readonly locator: OsvS3Locator }): Promise<
    OsvS3Result<
      | { exists: false }
      | {
          exists: true;
          byteCount: number;
          sha256: string;
          contentType: string;
          contentEncoding: string;
          artifactCategory: 'advisory_body' | 'parsed_advisory';
          layoutVersion: string;
        }
    >
  > {
    const started = Date.now();
    if (!locatorMatchesKey(input.locator)) {
      return fail('invalid_storage_identity');
    }
    const abort = combineAbortSignals(undefined, this.operationTimeoutMs);
    try {
      const head = await this.client.send(
        new HeadObjectCommand({ Bucket: this.bucket, Key: input.locator.objectKey }),
        { abortSignal: abort.signal },
      );
      const byteCount = head.ContentLength;
      const sha256 = metadataValue(head.Metadata, META_SHA256);
      const declaredBytes = metadataValue(head.Metadata, META_BYTES);
      const category = metadataValue(head.Metadata, META_CATEGORY);
      const encoding = metadataValue(head.Metadata, META_ENCODING);
      const layout = metadataValue(head.Metadata, META_LAYOUT);
      const contentType = head.ContentType;
      if (
        byteCount === undefined ||
        sha256 === undefined ||
        declaredBytes === undefined ||
        encoding === undefined ||
        contentType === undefined ||
        !SHA256_HEX_PATTERN.test(sha256) ||
        Number.parseInt(declaredBytes, 10) !== byteCount ||
        (category !== 'advisory_body' && category !== 'parsed_advisory') ||
        layout !== LAYOUT_VERSION ||
        contentType !== CONTENT_TYPE ||
        encoding !== CONTENT_ENCODING
      ) {
        this.logFailure('head', started);
        return fail('integrity_mismatch');
      }
      this.logOk('head', started);
      return ok({
        exists: true,
        byteCount,
        sha256,
        contentType,
        contentEncoding: encoding,
        artifactCategory: category,
        layoutVersion: layout,
      });
    } catch (error) {
      const code = mapCategory(error, 'head_object', abort);
      if (code === 'object_not_found') {
        return ok({ exists: false });
      }
      this.logFailure('head', started);
      return fail(code);
    }
  }

  public async getVerified(input: {
    readonly locator: OsvS3Locator;
    readonly expectedSha256: string;
    readonly expectedByteCount: number;
    readonly expectedContentType: string;
    readonly expectedContentEncoding: string;
    readonly maxBytes: number;
  }): Promise<
    OsvS3Result<{
      byteCount: number;
      sha256: string;
      contentType: string;
      contentEncoding: string;
    }>
  > {
    const result = await this.verifiedGet(input, false);
    if (!result.ok) {
      return result;
    }
    return ok({
      byteCount: result.value.byteCount,
      sha256: result.value.sha256,
      contentType: result.value.contentType,
      contentEncoding: result.value.contentEncoding,
    });
  }

  /**
   * Batch 6B resume read-back. Returns SHA-256-verified bytes for an already
   * attached advisory body. Does not change write-once getVerified metadata.
   */
  public async readVerifiedBody(input: {
    readonly locator: OsvS3Locator;
    readonly expectedSha256: string;
    readonly expectedByteCount: number;
    readonly expectedContentType: string;
    readonly expectedContentEncoding: string;
    readonly maxBytes: number;
  }): Promise<
    OsvS3Result<{
      byteCount: number;
      sha256: string;
      contentType: string;
      contentEncoding: string;
      bytes: Uint8Array;
    }>
  > {
    const result = await this.verifiedGet(input, true);
    if (!result.ok) {
      return result;
    }
    if (result.value.bytes === undefined) {
      return fail('integrity_mismatch');
    }
    return ok({
      byteCount: result.value.byteCount,
      sha256: result.value.sha256,
      contentType: result.value.contentType,
      contentEncoding: result.value.contentEncoding,
      bytes: result.value.bytes,
    });
  }

  private async verifiedGet(
    input: {
      readonly locator: OsvS3Locator;
      readonly expectedSha256: string;
      readonly expectedByteCount: number;
      readonly expectedContentType: string;
      readonly expectedContentEncoding: string;
      readonly maxBytes: number;
    },
    collectBytes: boolean,
  ): Promise<
    OsvS3Result<{
      byteCount: number;
      sha256: string;
      contentType: string;
      contentEncoding: string;
      bytes?: Uint8Array;
    }>
  > {
    const started = Date.now();
    if (!locatorMatchesKey(input.locator) || !SHA256_HEX_PATTERN.test(input.expectedSha256)) {
      return fail('invalid_storage_identity');
    }
    if (
      !Number.isInteger(input.maxBytes) ||
      input.maxBytes < MIN_BYTES ||
      input.maxBytes > MAX_BYTES
    ) {
      return fail('response_too_large');
    }
    if (input.expectedByteCount > input.maxBytes || input.expectedByteCount > MAX_BYTES) {
      return fail('response_too_large');
    }
    if (input.expectedContentType !== CONTENT_TYPE) {
      return fail('content_type_mismatch');
    }
    if (input.expectedContentEncoding !== CONTENT_ENCODING) {
      return fail('content_encoding_mismatch');
    }
    const abort = combineAbortSignals(undefined, this.operationTimeoutMs);
    try {
      const response = await this.client.send(
        new GetObjectCommand({ Bucket: this.bucket, Key: input.locator.objectKey }),
        { abortSignal: abort.signal },
      );
      const declared = response.ContentLength;
      if (declared !== undefined && declared > input.maxBytes) {
        destroyStream(response.Body);
        this.logFailure('get_verified', started);
        return fail('response_too_large');
      }
      if (declared !== undefined && declared !== input.expectedByteCount) {
        destroyStream(response.Body);
        return fail('byte_count_mismatch');
      }
      if (response.ContentType !== input.expectedContentType) {
        destroyStream(response.Body);
        return fail('content_type_mismatch');
      }
      if (response.Body === undefined) {
        return fail('object_not_found');
      }
      const sdkStream = asNodeReadable(response.Body);
      const inspect = createHashCountTransform({
        maxBytes: input.maxBytes,
        expectedByteLength: input.expectedByteCount,
        expectedSha256: input.expectedSha256,
      });
      const chunks: Buffer[] = [];
      sdkStream.pipe(inspect);
      inspect.on('data', (chunk: Buffer) => {
        if (collectBytes) {
          chunks.push(chunk);
        }
      });
      try {
        await finished(inspect);
      } catch (error) {
        destroyStream(sdkStream);
        destroyStream(inspect);
        if (error instanceof ObjectStorageStreamError && error.category === 'size_limit') {
          return fail('response_too_large');
        }
        if (error instanceof ObjectStorageStreamError && error.category === 'invalid_content') {
          return inspect.observedByteLength() !== input.expectedByteCount
            ? fail('partial_read_rejected')
            : fail('integrity_mismatch');
        }
        return fail(mapCategory(error, 'get_object', abort));
      }
      const sha256 = inspect.sha256Hex();
      const encoding = metadataValue(response.Metadata, META_ENCODING);
      if (encoding !== CONTENT_ENCODING) {
        return fail('content_encoding_mismatch');
      }
      this.logOk('get_verified', started);
      const bytes = collectBytes ? concatChunks(chunks) : undefined;
      return ok({
        byteCount: inspect.observedByteLength(),
        sha256,
        contentType: CONTENT_TYPE,
        contentEncoding: CONTENT_ENCODING,
        ...(bytes === undefined ? {} : { bytes }),
      });
    } catch (error) {
      this.logFailure('get_verified', started);
      return fail(mapCategory(error, 'get_object', abort));
    }
  }

  public async copyExclusive(input: {
    readonly source: OsvS3Locator;
    readonly destination: OsvS3Locator;
    readonly expectedSha256: string;
    readonly expectedByteCount: number;
    readonly contentType: string;
    readonly contentEncoding: string;
    readonly artifactCategory: 'advisory_body' | 'parsed_advisory';
  }): Promise<OsvS3Result<{ status: 'created' | 'already_applied' }>> {
    const started = Date.now();
    if (
      !locatorMatchesKey(input.source) ||
      !locatorMatchesKey(input.destination) ||
      input.source.role !== 'temporary' ||
      input.destination.role !== 'final' ||
      input.source.storageKind !== input.destination.storageKind ||
      input.destination.storageKind !== input.artifactCategory
    ) {
      return fail('invalid_storage_identity');
    }
    if (input.destination.contentSha256 !== input.expectedSha256) {
      return fail('integrity_mismatch');
    }
    if (input.contentType !== CONTENT_TYPE) {
      return fail('content_type_mismatch');
    }
    if (input.contentEncoding !== CONTENT_ENCODING) {
      return fail('content_encoding_mismatch');
    }
    if (
      input.expectedByteCount < MIN_BYTES ||
      input.expectedByteCount > MAX_BYTES ||
      input.source.storageKind !== input.artifactCategory
    ) {
      return fail(
        input.expectedByteCount > MAX_BYTES ? 'response_too_large' : 'invalid_storage_identity',
      );
    }
    const existing = await this.head({ locator: input.destination });
    if (!existing.ok) {
      return existing;
    }
    if (existing.value.exists) {
      if (
        !this.existingMatches(existing.value, {
          contentSha256: input.expectedSha256,
          byteCount: input.expectedByteCount,
          contentType: input.contentType,
          contentEncoding: input.contentEncoding,
          artifactCategory: input.artifactCategory,
        })
      ) {
        return fail('immutable_conflict');
      }
      return this.compareVerifiedBytes(
        input.destination,
        {
          contentSha256: input.expectedSha256,
          byteCount: input.expectedByteCount,
          contentType: input.contentType,
          contentEncoding: input.contentEncoding,
        },
        started,
        'copy_exclusive',
      );
    }
    const abort = combineAbortSignals(undefined, this.operationTimeoutMs);
    try {
      await this.client.send(
        new CopyObjectCommand({
          Bucket: this.bucket,
          Key: input.destination.objectKey,
          CopySource: encodeS3CopySource(this.bucket, input.source.objectKey),
          MetadataDirective: 'REPLACE',
          ContentType: CONTENT_TYPE,
          IfNoneMatch: '*',
          Metadata: {
            [META_SHA256]: input.expectedSha256,
            [META_BYTES]: String(input.expectedByteCount),
            [META_CATEGORY]: input.artifactCategory,
            [META_ENCODING]: CONTENT_ENCODING,
            [META_LAYOUT]: LAYOUT_VERSION,
          },
        }),
        { abortSignal: abort.signal },
      );
    } catch (error) {
      if (isWriteOncePrecondition(error)) {
        return this.compareVerifiedBytes(
          input.destination,
          {
            contentSha256: input.expectedSha256,
            byteCount: input.expectedByteCount,
            contentType: input.contentType,
            contentEncoding: input.contentEncoding,
          },
          started,
          'copy_exclusive',
        );
      }
      this.logFailure('copy_exclusive', started);
      return fail(mapCategory(error, 'copy_object', abort));
    }
    const copied = await this.head({ locator: input.destination });
    if (!copied.ok) {
      return copied;
    }
    if (
      !copied.value.exists ||
      !this.existingMatches(copied.value, {
        contentSha256: input.expectedSha256,
        byteCount: input.expectedByteCount,
        contentType: input.contentType,
        contentEncoding: input.contentEncoding,
        artifactCategory: input.artifactCategory,
      })
    ) {
      return fail('integrity_mismatch');
    }
    this.logOk('copy_exclusive', started);
    return ok({ status: 'created' });
  }

  public async deleteTemporary(input: {
    readonly locator: OsvS3Locator;
  }): Promise<OsvS3Result<void>> {
    const started = Date.now();
    if (!locatorMatchesKey(input.locator) || input.locator.role !== 'temporary') {
      return fail('invalid_storage_identity');
    }
    const abort = combineAbortSignals(undefined, this.operationTimeoutMs);
    try {
      await this.client.send(
        new DeleteObjectCommand({ Bucket: this.bucket, Key: input.locator.objectKey }),
        { abortSignal: abort.signal },
      );
      this.logOk('delete_temporary', started);
      return ok(undefined);
    } catch (error) {
      const code = mapCategory(error, 'delete_object', abort);
      if (code === 'object_not_found') {
        return ok(undefined);
      }
      this.logFailure('delete_temporary', started);
      return fail(code);
    }
  }

  /**
   * Test-infrastructure deletion of rehearsal-owned OSV objects. Disabled in
   * production. Not a catalog cleanup job and not a broad bucket purge.
   */
  public async deleteDevelopmentOwnedObject(input: {
    explicitlyAllowed: true;
    objectKey: string;
  }): Promise<OsvS3Result<void>> {
    if (
      this.deploymentEnvironment === 'production' ||
      this.allowDevelopmentAdapters !== true ||
      input.explicitlyAllowed !== true ||
      !isCompiledOsvS3ObjectKey(input.objectKey)
    ) {
      return fail('access_denied');
    }
    const abort = combineAbortSignals(undefined, this.operationTimeoutMs);
    try {
      await this.client.send(
        new DeleteObjectCommand({ Bucket: this.bucket, Key: input.objectKey }),
        { abortSignal: abort.signal },
      );
      return ok(undefined);
    } catch (error) {
      const code = mapCategory(error, 'delete_object', abort);
      if (code === 'object_not_found') {
        return ok(undefined);
      }
      return fail(code);
    }
  }

  private existingMatches(
    existing: {
      sha256: string;
      byteCount: number;
      contentType: string;
      contentEncoding: string;
      artifactCategory: 'advisory_body' | 'parsed_advisory';
      layoutVersion: string;
    },
    input: {
      contentSha256: string;
      byteCount: number;
      contentType: string;
      contentEncoding: string;
      artifactCategory: 'advisory_body' | 'parsed_advisory';
    },
  ): boolean {
    return (
      existing.sha256 === input.contentSha256 &&
      existing.byteCount === input.byteCount &&
      existing.contentType === input.contentType &&
      existing.contentEncoding === input.contentEncoding &&
      existing.artifactCategory === input.artifactCategory &&
      existing.layoutVersion === LAYOUT_VERSION
    );
  }

  private async compareVerifiedBytes(
    locator: OsvS3Locator,
    input: {
      contentSha256: string;
      byteCount: number;
      contentType: string;
      contentEncoding: string;
    },
    started: number,
    operation: string,
  ): Promise<OsvS3Result<{ status: 'already_applied' }>> {
    const verified = await this.getVerified({
      locator,
      expectedSha256: input.contentSha256,
      expectedByteCount: input.byteCount,
      expectedContentType: input.contentType,
      expectedContentEncoding: input.contentEncoding,
      maxBytes: MAX_BYTES,
    });
    if (!verified.ok) {
      this.logFailure(operation, started);
      if (
        verified.code === 'integrity_mismatch' ||
        verified.code === 'byte_count_mismatch' ||
        verified.code === 'content_type_mismatch' ||
        verified.code === 'content_encoding_mismatch' ||
        verified.code === 'partial_read_rejected' ||
        verified.code === 'response_too_large'
      ) {
        return fail('immutable_conflict');
      }
      return verified;
    }
    this.logOk(operation, started);
    return ok({ status: 'already_applied' });
  }

  private logOk(operation: string, started: number): void {
    this.logger.info(this.safeBindings(operation, started), 'osv object storage ok');
  }

  private logFailure(operation: string, started: number): void {
    this.logger.warn(this.safeBindings(operation, started), 'osv object storage failed');
  }

  private safeBindings(operation: string, started: number): Record<string, unknown> {
    return {
      operation,
      artifact: 'osv_advisory',
      durationMs: Math.max(0, Date.now() - started),
      ...(this.correlationId === undefined ? {} : { correlationId: this.correlationId }),
    };
  }
}

export function createS3OsvAdvisoryObjectStorage(
  config: S3OsvAdvisoryObjectStorageConfig,
  options?: { logger?: ObjectStorageLogger; correlationId?: string },
): S3OsvAdvisoryObjectStorage {
  return new S3OsvAdvisoryObjectStorage(config, options ?? {});
}
