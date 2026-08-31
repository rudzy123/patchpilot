import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import {
  hashFinalFingerprint,
  hashIdempotencyKey,
  hashReservationFingerprint,
  lengthPrefixed,
  resolveIdempotencyKeyHash,
  sbomUploadIdempotencyScope,
  wrapRawIdempotencyKey,
} from './idempotency.js';
import {
  SBOM_FINAL_FINGERPRINT_PREFIX,
  SBOM_IDEMPOTENCY_KEY_DIGEST_PREFIX,
  SBOM_RESERVATION_FINGERPRINT_PREFIX,
} from './constants.js';

const ASSET_A = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const ASSET_B = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const SHA = 'ab'.repeat(32);
const JSON_TYPE = 'application/json';
const CDX_TYPE = 'application/vnd.cyclonedx+json';

function sha256(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

describe('SBOM upload idempotency digests', () => {
  it('hashes the raw key with domain separation and forgets the wrapper secret', () => {
    const raw = 'upload-key-one';
    const hashed = hashIdempotencyKey(raw);
    expect(hashed.keyHash).toBe(sha256(`${SBOM_IDEMPOTENCY_KEY_DIGEST_PREFIX}${raw}`));
    expect(hashed.keyHash).not.toContain(raw);

    const wrapper = wrapRawIdempotencyKey(raw);
    expect(resolveIdempotencyKeyHash(wrapper)).toBe(hashed.keyHash);
    expect(() => wrapper.consume()).toThrow(/already consumed/);
  });

  it('keeps reservation fingerprints domain-separated from final fingerprints', () => {
    const reservation = hashReservationFingerprint({ assetId: ASSET_A, contentType: JSON_TYPE });
    const finalFp = hashFinalFingerprint({
      assetId: ASSET_A,
      contentType: JSON_TYPE,
      sha256: SHA,
      byteLength: 12,
    });
    expect(reservation).toBe(
      sha256(`${SBOM_RESERVATION_FINGERPRINT_PREFIX}${lengthPrefixed([ASSET_A, JSON_TYPE])}`),
    );
    expect(finalFp).toBe(
      sha256(`${SBOM_FINAL_FINGERPRINT_PREFIX}${lengthPrefixed([ASSET_A, JSON_TYPE, SHA, '12'])}`),
    );
    expect(reservation).not.toBe(finalFp);
    expect(reservation).not.toBe(hashIdempotencyKey('anything').keyHash);
  });

  it('makes ambiguous concatenation of fingerprint fields impossible', () => {
    expect(lengthPrefixed(['ab', 'c'])).toBe('2:ab:1:c');
    expect(lengthPrefixed(['a', 'bc'])).toBe('1:a:2:bc');
    expect(lengthPrefixed(['ab', 'c'])).not.toBe(lengthPrefixed(['a', 'bc']));
    expect(hashReservationFingerprint({ assetId: ASSET_A, contentType: JSON_TYPE })).not.toBe(
      hashReservationFingerprint({ assetId: ASSET_A, contentType: CDX_TYPE }),
    );
    expect(
      hashFinalFingerprint({
        assetId: ASSET_A,
        contentType: JSON_TYPE,
        sha256: SHA,
        byteLength: 12,
      }),
    ).not.toBe(
      hashFinalFingerprint({
        assetId: ASSET_A,
        contentType: JSON_TYPE,
        sha256: SHA,
        byteLength: 120,
      }),
    );
  });

  it('scopes the same key to an asset so another asset does not collide', () => {
    expect(sbomUploadIdempotencyScope(ASSET_A)).toBe(`sbom.upload:${ASSET_A}`);
    expect(sbomUploadIdempotencyScope(ASSET_A)).not.toBe(sbomUploadIdempotencyScope(ASSET_B));
  });
});
