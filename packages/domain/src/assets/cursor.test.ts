import { describe, expect, it } from 'vitest';

import { ASSET_LIST_CURSOR_VERSION } from './constants.js';
import { decodeAssetListCursor, encodeAssetListCursor } from './cursor.js';

const ASSET_ID = '11111111-1111-4111-8111-111111111111';

describe('asset list cursor', () => {
  it('round-trips a versioned opaque cursor', () => {
    const encoded = encodeAssetListCursor({
      v: ASSET_LIST_CURSOR_VERSION,
      n: 'billing',
      i: ASSET_ID,
    });
    expect(encoded.includes('{')).toBe(false);
    expect(decodeAssetListCursor(encoded)).toEqual({
      ok: true,
      value: { v: 1, n: 'billing', i: ASSET_ID },
    });
  });

  it('rejects unknown versions, extra fields, and non-uuid ids', () => {
    const extra = Buffer.from(
      JSON.stringify({ v: 1, n: 'billing', i: ASSET_ID, sql: 'id > 1' }),
      'utf8',
    ).toString('base64url');
    const wrongVersion = Buffer.from(
      JSON.stringify({ v: 2, n: 'billing', i: ASSET_ID }),
      'utf8',
    ).toString('base64url');
    const invalidId = Buffer.from(
      JSON.stringify({ v: 1, n: 'billing', i: 'not-a-uuid' }),
      'utf8',
    ).toString('base64url');

    expect(decodeAssetListCursor(extra).ok).toBe(false);
    expect(decodeAssetListCursor(wrongVersion).ok).toBe(false);
    expect(decodeAssetListCursor(invalidId).ok).toBe(false);
    expect(decodeAssetListCursor('%%%').ok).toBe(false);
  });
});
