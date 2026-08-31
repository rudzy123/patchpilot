import type { StorageFailureCategory } from '@patchpilot/domain';

export class ObjectStorageStreamError extends Error {
  public readonly category: StorageFailureCategory;

  public constructor(category: StorageFailureCategory) {
    super(category);
    this.name = 'ObjectStorageStreamError';
    this.category = category;
  }
}

export function categoryFromStreamError(error: unknown): StorageFailureCategory {
  if (error instanceof ObjectStorageStreamError) {
    return error.category;
  }

  return 'internal';
}

export type S3Operation =
  | 'head_bucket'
  | 'create_bucket'
  | 'put_object'
  | 'head_object'
  | 'get_object'
  | 'copy_object'
  | 'delete_object';

export type ClassifyS3FailureContext = {
  operation: S3Operation;
  callerAborted: boolean;
  timedOut: boolean;
};

function errorName(error: unknown): string {
  if (error instanceof Error && error.name.length > 0) {
    return error.name;
  }

  if (typeof error === 'object' && error !== null && 'name' in error) {
    const name = (error as { name: unknown }).name;
    if (typeof name === 'string') {
      return name;
    }
  }

  return '';
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

function errnoCode(error: unknown): string | undefined {
  if (typeof error !== 'object' || error === null) {
    return undefined;
  }

  if ('code' in error && typeof (error as { code: unknown }).code === 'string') {
    return (error as { code: string }).code;
  }

  if ('cause' in error) {
    const cause = (error as { cause: unknown }).cause;
    if (typeof cause === 'object' && cause !== null && 'code' in cause) {
      const code = (cause as { code: unknown }).code;
      if (typeof code === 'string') {
        return code;
      }
    }
  }

  return undefined;
}

function isTimeoutName(name: string, code: string | undefined): boolean {
  if (
    name === 'TimeoutError' ||
    name === 'TimeoutErrorException' ||
    name === 'RequestTimeoutError'
  ) {
    return true;
  }

  return (
    code === 'ETIMEDOUT' ||
    code === 'UND_ERR_CONNECT_TIMEOUT' ||
    code === 'UND_ERR_HEADERS_TIMEOUT' ||
    code === 'UND_ERR_BODY_TIMEOUT'
  );
}

function isAbortName(name: string): boolean {
  return name === 'AbortError' || name === 'AbortErrorException';
}

function isUnavailable(code: string | undefined, status: number | undefined): boolean {
  if (status !== undefined && status >= 500) {
    return true;
  }

  return (
    code === 'ECONNREFUSED' ||
    code === 'ENOTFOUND' ||
    code === 'ECONNRESET' ||
    code === 'EPIPE' ||
    code === 'EHOSTUNREACH' ||
    code === 'ENETUNREACH' ||
    code === 'EAI_AGAIN'
  );
}

export function classifyS3Failure(
  error: unknown,
  context: ClassifyS3FailureContext,
): StorageFailureCategory {
  if (error instanceof ObjectStorageStreamError) {
    return error.category;
  }

  if (context.callerAborted) {
    return 'aborted';
  }

  if (context.timedOut) {
    return 'timeout';
  }

  const name = errorName(error);
  const status = httpStatus(error);
  const code = errnoCode(error);

  if (isAbortName(name)) {
    return 'aborted';
  }

  if (isTimeoutName(name, code)) {
    return 'timeout';
  }

  if (name === 'NoSuchBucket' || (name === 'NotFound' && context.operation === 'head_bucket')) {
    return 'bucket_missing';
  }

  if (status === 404 && context.operation === 'head_bucket') {
    return 'bucket_missing';
  }

  if (name === 'NoSuchKey' || name === 'NotFound' || status === 404) {
    return 'object_missing';
  }

  if (name === 'AccessDenied' || name === 'InvalidAccessKeyId' || status === 403) {
    return 'access_denied';
  }

  if (name === 'MissingContentLength' || status === 411) {
    return 'internal';
  }

  if (isUnavailable(code, status)) {
    return 'storage_unavailable';
  }

  if (context.operation === 'copy_object') {
    return 'copy_failed';
  }

  if (name === 'BucketAlreadyOwnedByYou' || name === 'BucketAlreadyExists') {
    return 'internal';
  }

  return 'internal';
}

export function classifiedStorageFailure(
  error: unknown,
  context: ClassifyS3FailureContext,
): { category: StorageFailureCategory } {
  return { category: classifyS3Failure(error, context) };
}

export function isAlreadyOwnedBucketError(error: unknown): boolean {
  const name = errorName(error);
  return name === 'BucketAlreadyOwnedByYou' || name === 'BucketAlreadyExists';
}
