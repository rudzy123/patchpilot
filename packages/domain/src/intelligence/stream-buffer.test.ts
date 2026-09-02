import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { collectBoundedKevSnapshotBuffer } from './stream-buffer.js';

async function* chunksOf(bytes: Uint8Array, size: number): AsyncIterable<Uint8Array> {
  for (let offset = 0; offset < bytes.byteLength; offset += size) {
    yield bytes.subarray(offset, Math.min(offset + size, bytes.byteLength));
  }
}

function sha256(bytes: Uint8Array): string {
  return createHash('sha256').update(bytes).digest('hex');
}

describe('collectBoundedKevSnapshotBuffer', () => {
  it('collects declared-length snapshots into one exact ArrayBuffer', async () => {
    const payload = new TextEncoder().encode('{"catalogVersion":"2099.01.01"}');
    const digest = sha256(payload);
    let cancelled = false;
    const collected = await collectBoundedKevSnapshotBuffer({
      result: {
        body: chunksOf(payload, 8),
        declaredByteLength: payload.byteLength,
        completion: Promise.resolve({
          observedByteLength: payload.byteLength,
          sha256: digest,
        }),
        cancel: async () => {
          cancelled = true;
        },
      },
      maxBytes: 4096,
      expectedSha256: digest,
      expectedByteLength: payload.byteLength,
      declaredByteLength: payload.byteLength,
    });
    expect(collected.ok).toBe(true);
    if (!collected.ok) {
      return;
    }
    expect(collected.value.byteLength).toBe(payload.byteLength);
    expect(collected.value.sha256).toBe(digest);
    expect(collected.value.bytes.byteLength).toBe(payload.byteLength);
    expect(cancelled).toBe(false);
  });

  it('grows within maxBytes when length is absent and rejects maxBytes plus one', async () => {
    const payload = new Uint8Array(300);
    payload.fill(7);
    const digest = sha256(payload);
    const okResult = await collectBoundedKevSnapshotBuffer({
      result: {
        body: chunksOf(payload, 50),
        completion: Promise.resolve({
          observedByteLength: payload.byteLength,
          sha256: digest,
        }),
        cancel: async () => undefined,
      },
      maxBytes: 512,
      expectedSha256: digest,
      expectedByteLength: payload.byteLength,
    });
    expect(okResult.ok).toBe(true);

    let cancelled = false;
    const oversize = new Uint8Array(6);
    oversize.fill(1);
    const rejected = await collectBoundedKevSnapshotBuffer({
      result: {
        body: chunksOf(oversize, 2),
        completion: Promise.resolve({ observedByteLength: 6, sha256: sha256(oversize) }),
        cancel: async () => {
          cancelled = true;
        },
      },
      maxBytes: 5,
      expectedSha256: sha256(oversize),
      expectedByteLength: 5,
    });
    expect(rejected.ok).toBe(false);
    if (!rejected.ok) {
      expect(rejected.error.code).toBe('response_too_large');
    }
    expect(cancelled).toBe(true);
  });

  it('rejects empty snapshots and hash mismatches', async () => {
    const empty = await collectBoundedKevSnapshotBuffer({
      result: {
        body: chunksOf(new Uint8Array(), 1),
        completion: Promise.resolve({ observedByteLength: 0, sha256: 'a'.repeat(64) }),
        cancel: async () => undefined,
      },
      maxBytes: 32,
      expectedSha256: 'a'.repeat(64),
      expectedByteLength: 1,
    });
    expect(empty.ok).toBe(false);
    if (!empty.ok) {
      expect(empty.error.code).toBe('response_empty');
    }

    const payload = new TextEncoder().encode('abc');
    const mismatch = await collectBoundedKevSnapshotBuffer({
      result: {
        body: chunksOf(payload, 3),
        completion: Promise.resolve({
          observedByteLength: payload.byteLength,
          sha256: 'b'.repeat(64),
        }),
        cancel: async () => undefined,
      },
      maxBytes: 32,
      expectedSha256: 'a'.repeat(64),
      expectedByteLength: payload.byteLength,
    });
    expect(mismatch.ok).toBe(false);
    if (!mismatch.ok) {
      expect(mismatch.error.code).toBe('hash_mismatch');
    }
  });
});
