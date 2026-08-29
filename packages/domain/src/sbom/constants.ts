export const SHA256_HEX_PATTERN = /^[a-f0-9]{64}$/;
export const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

/** Safe labels for parser/normalization versions. No path separators. */
export const SBOM_VERSION_LABEL_PATTERN = /^[a-zA-Z0-9][a-zA-Z0-9._+-]{0,63}$/;
export const SBOM_VERSION_LABEL_MAX_LENGTH = 64;

export const SBOM_LIST_DEFAULT_LIMIT = 20;
export const SBOM_LIST_MIN_LIMIT = 1;
export const SBOM_LIST_MAX_LIMIT = 100;
export const SBOM_LIST_CURSOR_VERSION = 1;
export const SBOM_RAW_TEXT_MAX_LENGTH = 4096;

export const SBOM_IDENTITY_KEY_MAX_LENGTH = 2048;
export const SBOM_UPLOAD_IDEMPOTENCY_SCOPE = 'sbom.upload' as const;
export const SBOM_INGEST_JOB_TYPE = 'sbom.ingest' as const;
export const SBOM_UPLOAD_IDEMPOTENCY_RESPONSE_SCHEMA_VERSION = 1;

/**
 * Serialized parser-thread success ceiling. Independent of the HTTP upload
 * cap; it bounds structured-clone / JSON size of the normalized graph.
 */
export const SBOM_PARSER_RESULT_MAX_SERIALIZED_BYTES = 16_777_216;

export const SBOM_TEMPORARY_OBJECT_KEY_PATTERN =
  /^org\/[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\/assets\/[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\/sboms\/tmp\/[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export const SBOM_FINAL_OBJECT_KEY_PATTERN =
  /^org\/[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\/assets\/[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\/sboms\/sha256\/[a-f0-9]{64}$/;

export const FORBIDDEN_KNOWN_VERSION_STRINGS = ['*', 'latest', 'unknown'] as const;
