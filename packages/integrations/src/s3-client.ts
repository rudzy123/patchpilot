import { Agent as HttpAgent } from 'node:http';
import { Agent as HttpsAgent } from 'node:https';

import { S3Client } from '@aws-sdk/client-s3';
import { NodeHttpHandler } from '@smithy/node-http-handler';

export type S3ClientConstructionInput = {
  endpoint: string;
  region: string;
  accessKey: string;
  secretKey: string;
  useSsl: boolean;
  connectionTimeoutMs: number;
  requestTimeoutMs: number;
};

export class S3ClientConstructionError extends Error {
  public readonly category = 'internal' as const;

  public constructor(message: string) {
    super(message);
    this.name = 'S3ClientConstructionError';
  }
}

export function assertObjectStorageEndpointTls(endpoint: string, useSsl: boolean): URL {
  let parsed: URL;
  try {
    parsed = new URL(endpoint);
  } catch {
    throw new S3ClientConstructionError('Object-storage endpoint must be a valid URL.');
  }

  if (parsed.username !== '' || parsed.password !== '') {
    throw new S3ClientConstructionError(
      'Object-storage endpoint must not include credentials or userinfo.',
    );
  }

  if (useSsl && parsed.protocol !== 'https:') {
    throw new S3ClientConstructionError(
      'Object-storage endpoint must use https when useSsl is true.',
    );
  }

  if (!useSsl && parsed.protocol !== 'http:') {
    throw new S3ClientConstructionError(
      'Object-storage endpoint must use http when useSsl is false.',
    );
  }

  return parsed;
}

/**
 * One S3Client per adapter instance. Static credentials only. No default
 * provider chain, instance/container metadata, SSO, signed URLs, or multipart
 * helpers. forcePathStyle is required for Compose MinIO. maxAttempts is 1 so
 * the operation timeout is not multiplied by retries.
 *
 * Checksum mode is WHEN_REQUIRED: the AWS SDK 3.1120 default (WHEN_SUPPORTED)
 * emits aws-chunked PutObject with `x-amz-decoded-content-length` unset for
 * unknown-length streams. Node 24 then throws
 * `Invalid value "undefined" for header "x-amz-decoded-content-length"`
 * before MinIO receives the body. WHEN_REQUIRED restores identity transfer
 * for PutObject. The pinned MinIO image then requires `ContentLength`
 * (HTTP 411 MissingContentLength); the adapter sets it from declaredByteLength
 * rather than buffering the document or using multipart upload helpers.
 */
export function createS3Client(input: S3ClientConstructionInput): S3Client {
  if (input.region.trim().length === 0) {
    throw new S3ClientConstructionError('Object-storage region must be explicit.');
  }

  assertObjectStorageEndpointTls(input.endpoint, input.useSsl);

  return new S3Client({
    region: input.region,
    endpoint: input.endpoint,
    forcePathStyle: true,
    tls: input.useSsl,
    credentials: {
      accessKeyId: input.accessKey,
      secretAccessKey: input.secretKey,
    },
    maxAttempts: 1,
    requestChecksumCalculation: 'WHEN_REQUIRED',
    responseChecksumValidation: 'WHEN_REQUIRED',
    requestHandler: new NodeHttpHandler({
      connectionTimeout: input.connectionTimeoutMs,
      requestTimeout: input.requestTimeoutMs,
      throwOnRequestTimeout: true,
      httpAgent: new HttpAgent({ keepAlive: true, maxSockets: 64 }),
      httpsAgent: new HttpsAgent({
        keepAlive: true,
        maxSockets: 64,
        rejectUnauthorized: true,
      }),
    }),
  });
}
