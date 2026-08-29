import { describe, expect, it } from 'vitest';

import { decodeSbomListCursor, encodeSbomListCursor } from './cursor.js';

const SBOM_ID = '11111111-1111-4111-8111-111111111111';
const RECEIVED_AT = '2026-08-29T16:00:00.000Z';

describe('sbom list cursor', () => {
  it('round-trips a versioned opaque cursor', () => {
    const encoded = encodeSbomListCursor({ v: 1, r: RECEIVED_AT, i: SBOM_ID });
    expect(encoded.includes('{')).toBe(false);
    expect(decodeSbomListCursor(encoded)).toEqual({
      ok: true,
      value: { v: 1, r: RECEIVED_AT, i: SBOM_ID },
    });
  });

  it('rejects unknown versions, extra fields, and non-uuid ids', () => {
    const extra = Buffer.from(
      JSON.stringify({ v: 1, r: RECEIVED_AT, i: SBOM_ID, objectKey: 'org/x' }),
      'utf8',
    ).toString('base64url');
    const wrongVersion = Buffer.from(
      JSON.stringify({ v: 2, r: RECEIVED_AT, i: SBOM_ID }),
      'utf8',
    ).toString('base64url');
    const invalidId = Buffer.from(
      JSON.stringify({ v: 1, r: RECEIVED_AT, i: 'not-a-uuid' }),
      'utf8',
    ).toString('base64url');

    expect(decodeSbomListCursor(extra).ok).toBe(false);
    expect(decodeSbomListCursor(wrongVersion).ok).toBe(false);
    expect(decodeSbomListCursor(invalidId).ok).toBe(false);
    expect(decodeSbomListCursor('%%%').ok).toBe(false);
  });
});
