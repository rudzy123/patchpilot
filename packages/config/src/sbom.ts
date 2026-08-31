import { z } from 'zod';

/**
 * Session 8 typed SBOM ingestion limits. Values are reviewed initial defaults,
 * not production performance guarantees. Runtime ingestion is not implemented
 * in Batch 1.
 */

export const SBOM_UPLOAD_MAX_BYTES_DEFAULT = 20_971_520;
export const SBOM_UPLOAD_MAX_BYTES_MIN = 65_536;
export const SBOM_UPLOAD_MAX_BYTES_MAX = 33_554_432;

export const SBOM_JSON_MAX_DEPTH_DEFAULT = 32;
export const SBOM_JSON_MAX_DEPTH_MIN = 8;
export const SBOM_JSON_MAX_DEPTH_MAX = 64;

export const SBOM_JSON_MAX_NODES_DEFAULT = 200_000;
export const SBOM_JSON_MAX_NODES_MIN = 1_000;
export const SBOM_JSON_MAX_NODES_MAX = 500_000;

export const SBOM_JSON_MAX_STRING_BYTES_DEFAULT = 65_536;
export const SBOM_JSON_MAX_STRING_BYTES_MIN = 1_024;
export const SBOM_JSON_MAX_STRING_BYTES_MAX = 262_144;

export const SBOM_MAX_COMPONENTS_DEFAULT = 10_000;
export const SBOM_MAX_COMPONENTS_MIN = 1;
export const SBOM_MAX_COMPONENTS_MAX = 25_000;

export const SBOM_MAX_DEPENDENCY_EDGES_DEFAULT = 50_000;
export const SBOM_MAX_DEPENDENCY_EDGES_MIN = 0;
export const SBOM_MAX_DEPENDENCY_EDGES_MAX = 100_000;

export const SBOM_MAX_BOM_REF_BYTES_DEFAULT = 2_048;
export const SBOM_MAX_BOM_REF_BYTES_MIN = 64;
export const SBOM_MAX_BOM_REF_BYTES_MAX = 2_048;

export const SBOM_MAX_PURL_BYTES_DEFAULT = 2_048;
export const SBOM_MAX_PURL_BYTES_MIN = 64;
export const SBOM_MAX_PURL_BYTES_MAX = 2_048;

export const SBOM_MAX_COMPONENT_NAME_CHARS_DEFAULT = 512;
export const SBOM_MAX_COMPONENT_NAME_CHARS_MIN = 64;
export const SBOM_MAX_COMPONENT_NAME_CHARS_MAX = 512;

export const SBOM_MAX_VERSION_CHARS_DEFAULT = 256;
export const SBOM_MAX_VERSION_CHARS_MIN = 1;
export const SBOM_MAX_VERSION_CHARS_MAX = 256;

export const SBOM_MAX_METADATA_TOOLS_DEFAULT = 64;
export const SBOM_MAX_METADATA_TOOLS_MIN = 0;
export const SBOM_MAX_METADATA_TOOLS_MAX = 256;

export const SBOM_MAX_EXTERNAL_REFS_PER_COMPONENT_DEFAULT = 32;
export const SBOM_MAX_EXTERNAL_REFS_PER_COMPONENT_MIN = 0;
export const SBOM_MAX_EXTERNAL_REFS_PER_COMPONENT_MAX = 128;

export const SBOM_MAX_PROPERTIES_PER_COMPONENT_DEFAULT = 64;
export const SBOM_MAX_PROPERTIES_PER_COMPONENT_MIN = 0;
export const SBOM_MAX_PROPERTIES_PER_COMPONENT_MAX = 256;

export const SBOM_PARSER_TIMEOUT_MS_DEFAULT = 60_000;
export const SBOM_PARSER_TIMEOUT_MS_MIN = 10_000;
export const SBOM_PARSER_TIMEOUT_MS_MAX = 120_000;

export const SBOM_PROCESSING_LEASE_MS_DEFAULT = 900_000;
export const SBOM_PROCESSING_LEASE_MS_MIN = 120_000;
export const SBOM_PROCESSING_LEASE_MS_MAX = 1_800_000;

export const SBOM_IDEMPOTENCY_TTL_SECONDS_DEFAULT = 86_400;
export const SBOM_IDEMPOTENCY_TTL_SECONDS_MIN = 3_600;
export const SBOM_IDEMPOTENCY_TTL_SECONDS_MAX = 259_200;

export const SBOM_UPLOAD_RATE_LIMIT_MAX_DEFAULT = 10;
export const SBOM_UPLOAD_RATE_LIMIT_MAX_MIN = 1;
export const SBOM_UPLOAD_RATE_LIMIT_MAX_MAX = 60;

export const SBOM_UPLOAD_RATE_LIMIT_WINDOW_SECONDS_DEFAULT = 900;
export const SBOM_UPLOAD_RATE_LIMIT_WINDOW_SECONDS_MIN = 60;
export const SBOM_UPLOAD_RATE_LIMIT_WINDOW_SECONDS_MAX = 3_600;

export const OBJECT_STORAGE_OPERATION_TIMEOUT_MS_DEFAULT = 30_000;
export const OBJECT_STORAGE_OPERATION_TIMEOUT_MS_MIN = 1_000;
export const OBJECT_STORAGE_OPERATION_TIMEOUT_MS_MAX = 120_000;

export const OBJECT_STORAGE_CONNECTION_TIMEOUT_MS_DEFAULT = 3_000;
export const OBJECT_STORAGE_CONNECTION_TIMEOUT_MS_MIN = 250;
export const OBJECT_STORAGE_CONNECTION_TIMEOUT_MS_MAX = 10_000;

export const OBJECT_STORAGE_REGION_DEFAULT = 'us-east-1';
export const OBJECT_STORAGE_REGION_MAX_LENGTH = 32;
export const OBJECT_STORAGE_REGION_PATTERN = /^[a-z0-9][a-z0-9-]{1,31}$/;

export const SBOM_ORPHAN_GRACE_SECONDS_DEFAULT = 604_800;
export const SBOM_ORPHAN_GRACE_SECONDS_MIN = 7_200;
export const SBOM_ORPHAN_GRACE_SECONDS_MAX = 2_592_000;

export const SBOM_PARSER_VERSION_DEFAULT = '0.1.0';
export const SBOM_NORMALIZATION_VERSION_DEFAULT = '1';
export const SBOM_VERSION_LABEL_MAX_LENGTH = 64;

/** Safe labels for VARCHAR(64) parser/normalization versions. No path separators. */
export const sbomVersionLabelPattern = /^[a-zA-Z0-9][a-zA-Z0-9._+-]{0,63}$/;

/**
 * S3-compatible bucket names: 3–63 characters, lowercase, digits, dots, hyphens;
 * start and end alphanumeric; no adjacent periods; not an IPv4 address.
 */
export const objectStorageBucketNamePattern =
  /^(?!^\d{1,3}(?:\.\d{1,3}){3}$)[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/;

const developmentBucketFragments = ['patchpilot-dev', 'not-for-production', 'minioadmin'] as const;

export const sbomConfigSchema = z.object({
  uploadMaxBytes: z.number().int().positive(),
  jsonMaxDepth: z.number().int().positive(),
  jsonMaxNodes: z.number().int().positive(),
  jsonMaxStringBytes: z.number().int().positive(),
  maxComponents: z.number().int().positive(),
  maxDependencyEdges: z.number().int().nonnegative(),
  maxBomRefBytes: z.number().int().positive(),
  maxPurlBytes: z.number().int().positive(),
  maxComponentNameChars: z.number().int().positive(),
  maxVersionChars: z.number().int().positive(),
  maxMetadataTools: z.number().int().nonnegative(),
  maxExternalRefsPerComponent: z.number().int().nonnegative(),
  maxPropertiesPerComponent: z.number().int().nonnegative(),
  parserTimeoutMs: z.number().int().positive(),
  processingLeaseMs: z.number().int().positive(),
  idempotencyTtlSeconds: z.number().int().positive(),
  uploadRateLimitMax: z.number().int().positive(),
  uploadRateLimitWindowSeconds: z.number().int().positive(),
  objectStorageOperationTimeoutMs: z.number().int().positive(),
  orphanGraceSeconds: z.number().int().positive(),
  parserVersion: z
    .string()
    .min(1)
    .max(SBOM_VERSION_LABEL_MAX_LENGTH)
    .regex(sbomVersionLabelPattern, 'Parser version must be a safe database label.'),
  normalizationVersion: z
    .string()
    .min(1)
    .max(SBOM_VERSION_LABEL_MAX_LENGTH)
    .regex(sbomVersionLabelPattern, 'Normalization version must be a safe database label.'),
});

export type SbomConfig = z.infer<typeof sbomConfigSchema>;

export function isValidObjectStorageBucketName(bucket: string): boolean {
  if (!objectStorageBucketNamePattern.test(bucket)) {
    return false;
  }

  return !bucket.includes('..');
}

export function bucketNameLooksLikeDevelopmentPlaceholder(bucket: string): boolean {
  const lowered = bucket.toLowerCase();
  return developmentBucketFragments.some((fragment) => lowered.includes(fragment));
}

export type SbomRelationshipIssue = {
  path: Array<string | number>;
  message: string;
};

/**
 * Cross-field rules. Floors/ceilings currently make the idempotency-versus-storage
 * timeout rule implied; the check remains so a later bound change cannot skip it.
 */
export function sbomRelationshipIssues(sbom: SbomConfig): SbomRelationshipIssue[] {
  const issues: SbomRelationshipIssue[] = [];

  if (sbom.parserTimeoutMs >= sbom.processingLeaseMs) {
    issues.push({
      path: ['parserTimeoutMs'],
      message: 'Parser timeout must be less than the processing lease.',
    });
  }

  if (sbom.objectStorageOperationTimeoutMs >= sbom.processingLeaseMs) {
    issues.push({
      path: ['objectStorageOperationTimeoutMs'],
      message: 'Object-storage operation timeout must be less than the processing lease.',
    });
  }

  if (sbom.idempotencyTtlSeconds * 1000 <= sbom.objectStorageOperationTimeoutMs) {
    issues.push({
      path: ['idempotencyTtlSeconds'],
      message:
        'Idempotency TTL must be greater than the maximum plausible upload object-storage operation.',
    });
  }

  if (sbom.orphanGraceSeconds <= sbom.idempotencyTtlSeconds) {
    issues.push({
      path: ['orphanGraceSeconds'],
      message: 'Orphan grace period must be greater than the idempotency TTL.',
    });
  }

  return issues;
}

export function sbomDefaultEnvironmentVariables(): Record<string, string> {
  return {
    SBOM_UPLOAD_MAX_BYTES: String(SBOM_UPLOAD_MAX_BYTES_DEFAULT),
    SBOM_JSON_MAX_DEPTH: String(SBOM_JSON_MAX_DEPTH_DEFAULT),
    SBOM_JSON_MAX_NODES: String(SBOM_JSON_MAX_NODES_DEFAULT),
    SBOM_JSON_MAX_STRING_BYTES: String(SBOM_JSON_MAX_STRING_BYTES_DEFAULT),
    SBOM_MAX_COMPONENTS: String(SBOM_MAX_COMPONENTS_DEFAULT),
    SBOM_MAX_DEPENDENCY_EDGES: String(SBOM_MAX_DEPENDENCY_EDGES_DEFAULT),
    SBOM_MAX_BOM_REF_BYTES: String(SBOM_MAX_BOM_REF_BYTES_DEFAULT),
    SBOM_MAX_PURL_BYTES: String(SBOM_MAX_PURL_BYTES_DEFAULT),
    SBOM_MAX_COMPONENT_NAME_CHARS: String(SBOM_MAX_COMPONENT_NAME_CHARS_DEFAULT),
    SBOM_MAX_VERSION_CHARS: String(SBOM_MAX_VERSION_CHARS_DEFAULT),
    SBOM_MAX_METADATA_TOOLS: String(SBOM_MAX_METADATA_TOOLS_DEFAULT),
    SBOM_MAX_EXTERNAL_REFS_PER_COMPONENT: String(SBOM_MAX_EXTERNAL_REFS_PER_COMPONENT_DEFAULT),
    SBOM_MAX_PROPERTIES_PER_COMPONENT: String(SBOM_MAX_PROPERTIES_PER_COMPONENT_DEFAULT),
    SBOM_PARSER_TIMEOUT_MS: String(SBOM_PARSER_TIMEOUT_MS_DEFAULT),
    SBOM_PROCESSING_LEASE_MS: String(SBOM_PROCESSING_LEASE_MS_DEFAULT),
    SBOM_IDEMPOTENCY_TTL_SECONDS: String(SBOM_IDEMPOTENCY_TTL_SECONDS_DEFAULT),
    SBOM_UPLOAD_RATE_LIMIT_MAX: String(SBOM_UPLOAD_RATE_LIMIT_MAX_DEFAULT),
    SBOM_UPLOAD_RATE_LIMIT_WINDOW_SECONDS: String(SBOM_UPLOAD_RATE_LIMIT_WINDOW_SECONDS_DEFAULT),
    OBJECT_STORAGE_OPERATION_TIMEOUT_MS: String(OBJECT_STORAGE_OPERATION_TIMEOUT_MS_DEFAULT),
    OBJECT_STORAGE_CONNECTION_TIMEOUT_MS: String(OBJECT_STORAGE_CONNECTION_TIMEOUT_MS_DEFAULT),
    OBJECT_STORAGE_REGION: OBJECT_STORAGE_REGION_DEFAULT,
    SBOM_ORPHAN_GRACE_SECONDS: String(SBOM_ORPHAN_GRACE_SECONDS_DEFAULT),
    SBOM_PARSER_VERSION: SBOM_PARSER_VERSION_DEFAULT,
    SBOM_NORMALIZATION_VERSION: SBOM_NORMALIZATION_VERSION_DEFAULT,
  };
}

export function refineSbomNumericBounds(
  sbom: SbomConfig,
  addIssue: (issue: SbomRelationshipIssue) => void,
): void {
  bound(
    sbom.uploadMaxBytes,
    'uploadMaxBytes',
    SBOM_UPLOAD_MAX_BYTES_MIN,
    SBOM_UPLOAD_MAX_BYTES_MAX,
    addIssue,
  );
  bound(
    sbom.jsonMaxDepth,
    'jsonMaxDepth',
    SBOM_JSON_MAX_DEPTH_MIN,
    SBOM_JSON_MAX_DEPTH_MAX,
    addIssue,
  );
  bound(
    sbom.jsonMaxNodes,
    'jsonMaxNodes',
    SBOM_JSON_MAX_NODES_MIN,
    SBOM_JSON_MAX_NODES_MAX,
    addIssue,
  );
  bound(
    sbom.jsonMaxStringBytes,
    'jsonMaxStringBytes',
    SBOM_JSON_MAX_STRING_BYTES_MIN,
    SBOM_JSON_MAX_STRING_BYTES_MAX,
    addIssue,
  );
  bound(
    sbom.maxComponents,
    'maxComponents',
    SBOM_MAX_COMPONENTS_MIN,
    SBOM_MAX_COMPONENTS_MAX,
    addIssue,
  );
  bound(
    sbom.maxDependencyEdges,
    'maxDependencyEdges',
    SBOM_MAX_DEPENDENCY_EDGES_MIN,
    SBOM_MAX_DEPENDENCY_EDGES_MAX,
    addIssue,
  );
  bound(
    sbom.maxBomRefBytes,
    'maxBomRefBytes',
    SBOM_MAX_BOM_REF_BYTES_MIN,
    SBOM_MAX_BOM_REF_BYTES_MAX,
    addIssue,
  );
  bound(
    sbom.maxPurlBytes,
    'maxPurlBytes',
    SBOM_MAX_PURL_BYTES_MIN,
    SBOM_MAX_PURL_BYTES_MAX,
    addIssue,
  );
  bound(
    sbom.maxComponentNameChars,
    'maxComponentNameChars',
    SBOM_MAX_COMPONENT_NAME_CHARS_MIN,
    SBOM_MAX_COMPONENT_NAME_CHARS_MAX,
    addIssue,
  );
  bound(
    sbom.maxVersionChars,
    'maxVersionChars',
    SBOM_MAX_VERSION_CHARS_MIN,
    SBOM_MAX_VERSION_CHARS_MAX,
    addIssue,
  );
  bound(
    sbom.maxMetadataTools,
    'maxMetadataTools',
    SBOM_MAX_METADATA_TOOLS_MIN,
    SBOM_MAX_METADATA_TOOLS_MAX,
    addIssue,
  );
  bound(
    sbom.maxExternalRefsPerComponent,
    'maxExternalRefsPerComponent',
    SBOM_MAX_EXTERNAL_REFS_PER_COMPONENT_MIN,
    SBOM_MAX_EXTERNAL_REFS_PER_COMPONENT_MAX,
    addIssue,
  );
  bound(
    sbom.maxPropertiesPerComponent,
    'maxPropertiesPerComponent',
    SBOM_MAX_PROPERTIES_PER_COMPONENT_MIN,
    SBOM_MAX_PROPERTIES_PER_COMPONENT_MAX,
    addIssue,
  );
  bound(
    sbom.parserTimeoutMs,
    'parserTimeoutMs',
    SBOM_PARSER_TIMEOUT_MS_MIN,
    SBOM_PARSER_TIMEOUT_MS_MAX,
    addIssue,
  );
  bound(
    sbom.processingLeaseMs,
    'processingLeaseMs',
    SBOM_PROCESSING_LEASE_MS_MIN,
    SBOM_PROCESSING_LEASE_MS_MAX,
    addIssue,
  );
  bound(
    sbom.idempotencyTtlSeconds,
    'idempotencyTtlSeconds',
    SBOM_IDEMPOTENCY_TTL_SECONDS_MIN,
    SBOM_IDEMPOTENCY_TTL_SECONDS_MAX,
    addIssue,
  );
  bound(
    sbom.uploadRateLimitMax,
    'uploadRateLimitMax',
    SBOM_UPLOAD_RATE_LIMIT_MAX_MIN,
    SBOM_UPLOAD_RATE_LIMIT_MAX_MAX,
    addIssue,
  );
  bound(
    sbom.uploadRateLimitWindowSeconds,
    'uploadRateLimitWindowSeconds',
    SBOM_UPLOAD_RATE_LIMIT_WINDOW_SECONDS_MIN,
    SBOM_UPLOAD_RATE_LIMIT_WINDOW_SECONDS_MAX,
    addIssue,
  );
  bound(
    sbom.objectStorageOperationTimeoutMs,
    'objectStorageOperationTimeoutMs',
    OBJECT_STORAGE_OPERATION_TIMEOUT_MS_MIN,
    OBJECT_STORAGE_OPERATION_TIMEOUT_MS_MAX,
    addIssue,
  );
  bound(
    sbom.orphanGraceSeconds,
    'orphanGraceSeconds',
    SBOM_ORPHAN_GRACE_SECONDS_MIN,
    SBOM_ORPHAN_GRACE_SECONDS_MAX,
    addIssue,
  );
}

function bound(
  value: number,
  key: string,
  min: number,
  max: number,
  addIssue: (issue: SbomRelationshipIssue) => void,
): void {
  if (value < min || value > max) {
    addIssue({
      path: [key],
      message: `${key} must be between ${min} and ${max}.`,
    });
  }
}
