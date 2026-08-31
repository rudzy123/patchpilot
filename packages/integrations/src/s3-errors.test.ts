import { describe, expect, it } from 'vitest';

import { classifiedStorageFailure, classifyS3Failure } from './s3-errors.js';
import { ObjectStorageStreamError } from './s3-errors.js';

function awsError(input: {
  name: string;
  status?: number;
  message?: string;
  extra?: Record<string, unknown>;
}): Error {
  const error = new Error(input.message ?? 'provider text must not leak');
  error.name = input.name;
  Object.assign(error, {
    $metadata: {
      httpStatusCode: input.status,
      requestId: 'req-secret',
      extendedRequestId: 'ext-secret',
    },
    Code: input.name,
    Bucket: 'secret-bucket',
    Key: 'org/secret-key',
    CopySource: 'secret-bucket/org/secret-key',
    stack: 'Error: provider text must not leak\n    at secret',
    ...input.extra,
  });
  return error;
}

describe('classifyS3Failure', () => {
  it('maps provider names and statuses without leaking provider fields', () => {
    const cases = [
      {
        name: 'NoSuchBucket',
        status: 404,
        operation: 'head_bucket' as const,
        expected: 'bucket_missing',
      },
      {
        name: 'NotFound',
        status: 404,
        operation: 'head_bucket' as const,
        expected: 'bucket_missing',
      },
      {
        name: 'NoSuchKey',
        status: 404,
        operation: 'head_object' as const,
        expected: 'object_missing',
      },
      {
        name: 'AccessDenied',
        status: 403,
        operation: 'put_object' as const,
        expected: 'access_denied',
      },
      { name: 'TimeoutError', operation: 'put_object' as const, expected: 'timeout' },
      { name: 'AbortError', operation: 'get_object' as const, expected: 'aborted' },
      {
        name: 'SlowDown',
        status: 503,
        operation: 'put_object' as const,
        expected: 'storage_unavailable',
      },
      { name: 'InvalidRequest', operation: 'copy_object' as const, expected: 'copy_failed' },
      {
        name: 'MissingContentLength',
        status: 411,
        operation: 'put_object' as const,
        expected: 'internal',
      },
    ];

    for (const testCase of cases) {
      const error = awsError({
        name: testCase.name,
        ...(testCase.status === undefined ? {} : { status: testCase.status }),
      });
      const classified = classifiedStorageFailure(error, {
        operation: testCase.operation,
        callerAborted: false,
        timedOut: false,
      });
      expect(classified, testCase.name).toEqual({ category: testCase.expected });
      expect(JSON.stringify(classified)).not.toContain('provider text');
      expect(JSON.stringify(classified)).not.toContain('secret-bucket');
      expect(JSON.stringify(classified)).not.toContain('secret-key');
      expect(JSON.stringify(classified)).not.toContain('req-secret');
      expect(JSON.stringify(classified)).not.toContain('CopySource');
      expect(classified).not.toHaveProperty('message');
      expect(classified).not.toHaveProperty('stack');
      expect(classified).not.toHaveProperty('Code');
      expect(classified).not.toHaveProperty('$metadata');
    }
  });

  it('prefers caller abort over timeout', () => {
    expect(
      classifyS3Failure(awsError({ name: 'TimeoutError' }), {
        operation: 'put_object',
        callerAborted: true,
        timedOut: true,
      }),
    ).toBe('aborted');
  });

  it('maps stream errors to their category', () => {
    expect(
      classifyS3Failure(new ObjectStorageStreamError('size_limit'), {
        operation: 'put_object',
        callerAborted: false,
        timedOut: false,
      }),
    ).toBe('size_limit');
  });

  it('maps connection refused to storage_unavailable', () => {
    const error = Object.assign(new Error('connect'), { code: 'ECONNREFUSED' });
    error.name = 'Error';
    expect(
      classifyS3Failure(error, {
        operation: 'put_object',
        callerAborted: false,
        timedOut: false,
      }),
    ).toBe('storage_unavailable');
  });
});
