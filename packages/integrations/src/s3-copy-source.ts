/**
 * CopySource for the approved SBOM key alphabet (UUID, `/`, lowercase hex).
 * Path separators stay `/`; each segment is percent-encoded. Unreserved
 * characters in this alphabet are unchanged, so this equals `bucket/key`.
 */
export function encodeS3CopySource(bucket: string, objectKey: string): string {
  const encodedBucket = encodeURIComponent(bucket);
  const encodedKey = objectKey
    .split('/')
    .map((segment) => encodeURIComponent(segment))
    .join('/');
  return `${encodedBucket}/${encodedKey}`;
}

export const SBOM_SHA256_METADATA_KEY = 'sha256';
export const SBOM_BYTE_LENGTH_METADATA_KEY = 'byte-length';

export const INTELLIGENCE_RESPONSE_SHA256_METADATA_KEY = 'response-sha256';
export const INTELLIGENCE_BYTE_LENGTH_METADATA_KEY = 'byte-length';
export const INTELLIGENCE_DECLARED_CONTENT_TYPE_METADATA_KEY = 'declared-content-type';
export const INTELLIGENCE_DETECTED_CONTENT_TYPE_METADATA_KEY = 'detected-content-type';
export const INTELLIGENCE_PROVIDER_METADATA_KEY = 'provider';
export const INTELLIGENCE_SOURCE_IDENTIFIER_METADATA_KEY = 'source-identifier';
