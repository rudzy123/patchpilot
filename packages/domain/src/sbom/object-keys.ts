import {
  SHA256_HEX_PATTERN,
  SBOM_FINAL_OBJECT_KEY_PATTERN,
  SBOM_TEMPORARY_OBJECT_KEY_PATTERN,
} from './constants.js';

export function isTemporarySbomObjectKey(objectKey: string): boolean {
  return SBOM_TEMPORARY_OBJECT_KEY_PATTERN.test(objectKey);
}

export function isFinalSbomObjectKey(objectKey: string): boolean {
  return (
    SBOM_FINAL_OBJECT_KEY_PATTERN.test(objectKey) && SHA256_HEX_PATTERN.test(objectKey.slice(-64))
  );
}

export function buildTemporarySbomObjectKey(input: {
  organizationId: string;
  assetId: string;
  uploadId: string;
}): string {
  return `org/${input.organizationId}/assets/${input.assetId}/sboms/tmp/${input.uploadId}`;
}

export function buildFinalSbomObjectKey(input: {
  organizationId: string;
  assetId: string;
  sha256: string;
}): string {
  return `org/${input.organizationId}/assets/${input.assetId}/sboms/sha256/${input.sha256}`;
}
