import { createHash } from 'node:crypto';

import {
  SBOM_FINAL_FINGERPRINT_PREFIX,
  SBOM_IDEMPOTENCY_KEY_DIGEST_PREFIX,
  SBOM_RESERVATION_FINGERPRINT_PREFIX,
  SBOM_UPLOAD_IDEMPOTENCY_SCOPE,
  SHA256_HEX_PATTERN,
  type SbomApprovedContentType,
} from './constants.js';

export type HashedIdempotencyKey = {
  readonly keyHash: string;
};

export type SecretIdempotencyKey = {
  consume(): HashedIdempotencyKey;
};

export function isSecretIdempotencyKey(
  value: HashedIdempotencyKey | SecretIdempotencyKey,
): value is SecretIdempotencyKey {
  return 'consume' in value && typeof value.consume === 'function';
}

export function hashIdempotencyKey(rawKey: string): HashedIdempotencyKey {
  return { keyHash: sha256Utf8(`${SBOM_IDEMPOTENCY_KEY_DIGEST_PREFIX}${rawKey}`) };
}

/**
 * Secret-safe wrapper. `consume()` hashes immediately and drops the raw key.
 * The wrapper cannot yield the raw value after consume.
 */
export function wrapRawIdempotencyKey(rawKey: string): SecretIdempotencyKey {
  let pending: string | undefined = rawKey;
  return {
    consume(): HashedIdempotencyKey {
      if (pending === undefined) {
        throw new Error('Idempotency key was already consumed.');
      }
      const hashed = hashIdempotencyKey(pending);
      pending = undefined;
      return hashed;
    },
  };
}

export function resolveIdempotencyKeyHash(
  input: HashedIdempotencyKey | SecretIdempotencyKey,
): string {
  const hashed = isSecretIdempotencyKey(input) ? input.consume() : input;
  if (!SHA256_HEX_PATTERN.test(hashed.keyHash)) {
    throw new Error('Idempotency key hash must be 64 lowercase hexadecimal characters.');
  }
  return hashed.keyHash;
}

export function sbomUploadIdempotencyScope(assetId: string): string {
  return `${SBOM_UPLOAD_IDEMPOTENCY_SCOPE}:${assetId}`;
}

export function hashReservationFingerprint(input: {
  assetId: string;
  contentType: SbomApprovedContentType;
}): string {
  return sha256Utf8(
    `${SBOM_RESERVATION_FINGERPRINT_PREFIX}${lengthPrefixed([input.assetId, input.contentType])}`,
  );
}

export function hashFinalFingerprint(input: {
  assetId: string;
  contentType: SbomApprovedContentType;
  sha256: string;
  byteLength: number;
}): string {
  return sha256Utf8(
    `${SBOM_FINAL_FINGERPRINT_PREFIX}${lengthPrefixed([
      input.assetId,
      input.contentType,
      input.sha256,
      String(input.byteLength),
    ])}`,
  );
}

/**
 * Length-prefix each field so concatenation cannot produce ambiguous encodings.
 * `2:ab:1:c` is distinct from `1:a:2:bc`.
 */
export function lengthPrefixed(parts: readonly string[]): string {
  return parts.map((part) => `${part.length}:${part}`).join(':');
}

function sha256Utf8(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}
