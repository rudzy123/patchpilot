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

export function sha256FromFinalSbomObjectKey(objectKey: string): string | undefined {
  if (!isFinalSbomObjectKey(objectKey)) {
    return undefined;
  }

  return objectKey.slice(-64);
}

export type SbomObjectKeyScope = {
  organizationId: string;
  assetId: string;
};

/**
 * Organization and Asset segments from an approved temporary or final key.
 * Callers must not treat a parsed scope as authorization.
 */
export function sbomObjectKeyScope(objectKey: string): SbomObjectKeyScope | undefined {
  if (!isTemporarySbomObjectKey(objectKey) && !isFinalSbomObjectKey(objectKey)) {
    return undefined;
  }

  const segments = objectKey.split('/');
  const organizationId = segments[1];
  const assetId = segments[3];
  if (organizationId === undefined || assetId === undefined) {
    return undefined;
  }

  return { organizationId, assetId };
}

export function sbomObjectKeysShareScope(left: string, right: string): boolean {
  const first = sbomObjectKeyScope(left);
  const second = sbomObjectKeyScope(right);
  return (
    first !== undefined &&
    second !== undefined &&
    first.organizationId === second.organizationId &&
    first.assetId === second.assetId
  );
}
