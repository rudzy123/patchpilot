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
 * are implemented by S3SbomObjectStorage. Intelligence snapshots use
 * intelligence/cisa_kev/cisa_kev_json_catalog/{tmp|sha256}/... and OSV
 * advisory artifacts use intelligence/osv/{advisory_body|parsed_advisory}/{tmp|sha256}/...
 * in the same private bucket. The older buffered ObjectStoragePort remains unused.
 *
 * Both adapters use @aws-sdk/client-s3@3.1120.0 with static credentials,
 * forcePathStyle, and no public ACLs. Compose MinIO healthchecks are not an SDK
 * compatibility claim; adapter integration tests are.
 */
export const deferredIntegrationNotes = {
  objectKeyConvention: 'org-asset-sha256',
  intelligenceObjectKeyConvention: 'intelligence-cisa-kev-sha256',
  osvObjectKeyConvention: 'intelligence-osv-sha256',
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
export {
  createS3IntelligenceSnapshotStorage,
  S3IntelligenceSnapshotStorage,
  type S3IntelligenceSnapshotStorageConfig,
  type S3IntelligenceSnapshotStorageOptions,
} from './s3-intelligence-snapshot-storage.js';
export {
  createS3OsvAdvisoryObjectStorage,
  isCompiledOsvS3ObjectKey,
  S3OsvAdvisoryObjectStorage,
  type S3OsvAdvisoryObjectStorageConfig,
} from './s3-osv-advisory-object-storage.js';
export { createOsvAttachedBodyReadPort } from './osv-attached-body-read.js';
export { createCisaKevHttpsClient, createCisaKevHttpsTransport } from './cisa-kev-https.js';
export { createOsvGenerationBoundRetrievalHttpsClient } from './osv-generation-bound-retrieval-https.js';
export { createS3Client, S3ClientConstructionError } from './s3-client.js';
export { encodeS3CopySource } from './s3-copy-source.js';
export { classifyS3Failure, classifiedStorageFailure } from './s3-errors.js';
export {
  createHashCountTransform,
  createPutInspectTransform,
  readableFromByteStream,
  sniffSbomPrefix,
  SNIFF_PREFIX_MAX_BYTES,
} from './s3-stream.js';
