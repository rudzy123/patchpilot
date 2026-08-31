import { describe, expect, it } from 'vitest';

import {
  buildFinalSbomObjectKey,
  buildTemporarySbomObjectKey,
  isFinalSbomObjectKey,
  isTemporarySbomObjectKey,
  sbomObjectKeyScope,
  sbomObjectKeysShareScope,
  sha256FromFinalSbomObjectKey,
} from './object-keys.js';

const ORG_A = '11111111-1111-4111-8111-111111111111';
const ORG_B = '22222222-2222-4222-8222-222222222222';
const ASSET_A = '33333333-3333-4333-8333-333333333333';
const ASSET_B = '44444444-4444-4444-8444-444444444444';
const UPLOAD = '55555555-5555-4555-8555-555555555555';
const SHA = 'a'.repeat(64);

describe('SBOM object keys', () => {
  it('builds temporary and final keys that match the approved shapes', () => {
    const temporary = buildTemporarySbomObjectKey({
      organizationId: ORG_A,
      assetId: ASSET_A,
      uploadId: UPLOAD,
    });
    const finalKey = buildFinalSbomObjectKey({
      organizationId: ORG_A,
      assetId: ASSET_A,
      sha256: SHA,
    });
    expect(isTemporarySbomObjectKey(temporary)).toBe(true);
    expect(isFinalSbomObjectKey(finalKey)).toBe(true);
    expect(sha256FromFinalSbomObjectKey(finalKey)).toBe(SHA);
    expect(isTemporarySbomObjectKey(finalKey)).toBe(false);
    expect(isFinalSbomObjectKey(temporary)).toBe(false);
  });

  it('scopes the same digest to different keys across assets and organizations', () => {
    const sameAssetDifferentOrg = buildFinalSbomObjectKey({
      organizationId: ORG_B,
      assetId: ASSET_A,
      sha256: SHA,
    });
    const sameOrgDifferentAsset = buildFinalSbomObjectKey({
      organizationId: ORG_A,
      assetId: ASSET_B,
      sha256: SHA,
    });
    const original = buildFinalSbomObjectKey({
      organizationId: ORG_A,
      assetId: ASSET_A,
      sha256: SHA,
    });
    expect(sameAssetDifferentOrg).not.toBe(original);
    expect(sameOrgDifferentAsset).not.toBe(original);
    expect(sha256FromFinalSbomObjectKey(sameAssetDifferentOrg)).toBe(SHA);
    expect(sha256FromFinalSbomObjectKey(sameOrgDifferentAsset)).toBe(SHA);
  });

  it('does not extract a digest from a temporary key', () => {
    expect(
      sha256FromFinalSbomObjectKey(
        buildTemporarySbomObjectKey({
          organizationId: ORG_A,
          assetId: ASSET_A,
          uploadId: UPLOAD,
        }),
      ),
    ).toBeUndefined();
  });

  it('requires temporary and final keys to share organization and asset scope', () => {
    const temporary = buildTemporarySbomObjectKey({
      organizationId: ORG_A,
      assetId: ASSET_A,
      uploadId: UPLOAD,
    });
    const sameScope = buildFinalSbomObjectKey({
      organizationId: ORG_A,
      assetId: ASSET_A,
      sha256: SHA,
    });
    const otherOrg = buildFinalSbomObjectKey({
      organizationId: ORG_B,
      assetId: ASSET_A,
      sha256: SHA,
    });
    const otherAsset = buildFinalSbomObjectKey({
      organizationId: ORG_A,
      assetId: ASSET_B,
      sha256: SHA,
    });
    expect(sbomObjectKeysShareScope(temporary, sameScope)).toBe(true);
    expect(sbomObjectKeysShareScope(temporary, otherOrg)).toBe(false);
    expect(sbomObjectKeysShareScope(temporary, otherAsset)).toBe(false);
    expect(sbomObjectKeyScope('not-a-key')).toBeUndefined();
  });
});
