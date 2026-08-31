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
