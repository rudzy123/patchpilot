import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { readVerifiedObjectBuffer } from './object-bytes.js';
import type { GetObjectResult } from './ports.js';

const BODY = new TextEncoder().encode('{"bomFormat":"CycloneDX"}');
const SHA = createHash('sha256').update(BODY).digest('hex');

function resultOf(
  chunks: Uint8Array[],
  completion: { observedByteLength: number; sha256?: string },
): GetObjectResult {
  return {
    body: (async function* () {
      for (const chunk of chunks) {
        yield chunk;
      }
    })(),
    completion: Promise.resolve(completion),
    cancel: async () => undefined,
  };
}

describe('readVerifiedObjectBuffer', () => {
  it('returns bytes when size and SHA-256 match', async () => {
    const verified = await readVerifiedObjectBuffer(
      resultOf([BODY], { observedByteLength: BODY.byteLength, sha256: SHA }),
      { sha256: SHA, byteLength: BODY.byteLength, maxBytes: 1024 },
    );
    expect(verified.ok).toBe(true);
    if (!verified.ok) {
      return;
    }
    expect(verified.value.sha256).toBe(SHA);
    expect(verified.value.byteLength).toBe(BODY.byteLength);
  });

  it('quarantines a digest mismatch', async () => {
    const verified = await readVerifiedObjectBuffer(
      resultOf([BODY], { observedByteLength: BODY.byteLength }),
      { sha256: 'a'.repeat(64), byteLength: BODY.byteLength, maxBytes: 1024 },
    );
    expect(verified).toEqual({ ok: false, error: { code: 'hash_mismatch' } });
  });

  it('rejects oversize streams', async () => {
    const verified = await readVerifiedObjectBuffer(resultOf([BODY], { observedByteLength: 1 }), {
      sha256: SHA,
      byteLength: BODY.byteLength,
      maxBytes: 4,
    });
    expect(verified).toEqual({ ok: false, error: { code: 'payload_too_large' } });
  });
});
