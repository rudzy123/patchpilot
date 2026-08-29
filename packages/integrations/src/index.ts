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
 * are accepted in ADR 0008 and deferred until SBOM storage exists.
 *
 * @aws-sdk/client-s3 is installed for a later adapter batch. This package does not
 * construct an S3 client, use the default credential-provider chain, or set public ACLs.
 * A MinIO adapter is still deferred; Compose healthchecks are not an SDK compatibility claim.
 */
export const deferredIntegrationNotes = {
  objectKeyConvention: 'deferred-until-sbom-storage',
  minioAdapter: 'deferred-compose-healthcheck-is-sufficient',
  s3Client: 'installed-not-wired',
} as const;
