export type ObjectStorageHealth = {
  ok: boolean;
};

export type ObjectStoragePort = {
  checkHealth: (timeoutMs: number) => Promise<ObjectStorageHealth>;
  putObject: (input: { key: string; body: Uint8Array; contentType: string }) => Promise<void>;
  getObject: (key: string) => Promise<Uint8Array | undefined>;
  headObject: (key: string) => Promise<{ exists: boolean }>;
  deleteObject: (key: string) => Promise<void>;
};

export type RedisConnectionPort = {
  ping: (timeoutMs: number) => Promise<boolean>;
  quit: () => Promise<void>;
};

export type JobHandler = {
  name: string;
};

export type JobRegistry = ReadonlyArray<JobHandler>;

export function createEmptyJobRegistry(): JobRegistry {
  return [];
}

/**
 * Tenant object-key conventions (org/{organizationId}/assets/{assetId}/sboms/sha256/{sha256})
 * are implemented by S3SbomObjectStorage. The older buffered ObjectStoragePort remains unused.
 *
 * The Session 8 adapter uses @aws-sdk/client-s3@3.1120.0 with static credentials,
 * forcePathStyle, and no public ACLs. Compose MinIO healthchecks are not an SDK
 * compatibility claim; adapter integration tests are.
 */
export const deferredIntegrationNotes = {
  objectKeyConvention: 'org-asset-sha256',
  minioAdapter: 's3-compatible-streaming-adapter',
  s3Client: 'wired-static-credentials',
} as const;

export {
  createS3SbomObjectStorage,
  S3SbomObjectStorage,
  type ObjectStorageLogger,
  type S3SbomObjectStorageConfig,
  type S3SbomObjectStorageOptions,
} from './s3-sbom-object-storage.js';
export { createS3Client, S3ClientConstructionError } from './s3-client.js';
export { encodeS3CopySource } from './s3-copy-source.js';
export { classifyS3Failure, classifiedStorageFailure } from './s3-errors.js';
export {
  createPutInspectTransform,
  readableFromByteStream,
  sniffSbomPrefix,
  SNIFF_PREFIX_MAX_BYTES,
} from './s3-stream.js';
