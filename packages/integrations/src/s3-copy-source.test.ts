import { describe, expect, it } from 'vitest';

import { buildFinalSbomObjectKey, buildTemporarySbomObjectKey } from '@patchpilot/domain';

import { encodeS3CopySource } from './s3-copy-source.js';

const ORG = '11111111-1111-4111-8111-111111111111';
const ASSET = '22222222-2222-4222-8222-222222222222';
const UPLOAD = '33333333-3333-4333-8333-333333333333';
const SHA = 'a'.repeat(64);

describe('encodeS3CopySource', () => {
  it('keeps slashes as separators for approved temporary keys', () => {
    const key = buildTemporarySbomObjectKey({
      organizationId: ORG,
      assetId: ASSET,
      uploadId: UPLOAD,
    });
    expect(encodeS3CopySource('patchpilot-dev', key)).toBe(`patchpilot-dev/${key}`);
    expect(encodeS3CopySource('patchpilot-dev', key)).not.toContain('%2F');
  });

  it('keeps slashes as separators for approved final keys', () => {
    const key = buildFinalSbomObjectKey({
      organizationId: ORG,
      assetId: ASSET,
      sha256: SHA,
    });
    expect(encodeS3CopySource('patchpilot-dev', key)).toBe(`patchpilot-dev/${key}`);
  });

  it('percent-encodes reserved characters in a segment without encoding slashes', () => {
    expect(encodeS3CopySource('bucket name', 'a/b c')).toBe('bucket%20name/a/b%20c');
  });
});
