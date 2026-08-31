import { describe, expect, it } from 'vitest';

import { fingerprintUploadBody } from './body-fingerprint.js';

function streamOf(text: string): AsyncIterable<Uint8Array> {
  return (async function* () {
    yield new TextEncoder().encode(text);
  })();
}

describe('upload body fingerprinting', () => {
  it('hashes the original bytes without buffering a named body field', async () => {
    const result = await fingerprintUploadBody({
      body: streamOf('{"bomFormat":"CycloneDX"}'),
      maxBytes: 1024,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    expect(result.value.observedByteLength).toBe(25);
    expect(result.value.sha256).toMatch(/^[a-f0-9]{64}$/);
  });

  it('maps abort, size, and empty-body failures without throwing', async () => {
    const aborted = new AbortController();
    aborted.abort();
    expect(
      await fingerprintUploadBody({
        body: streamOf('{"ok":true}'),
        maxBytes: 1024,
        signal: aborted.signal,
      }),
    ).toEqual({ ok: false, error: { category: 'aborted' } });

    expect(
      await fingerprintUploadBody({
        body: streamOf('{"too":"big"}'),
        maxBytes: 4,
      }),
    ).toEqual({ ok: false, error: { category: 'size_limit' } });

    expect(
      await fingerprintUploadBody({
        body: {
          [Symbol.asyncIterator]() {
            return {
              next: async () => ({ done: true as const, value: undefined }),
            };
          },
        },
        maxBytes: 1024,
      }),
    ).toEqual({ ok: false, error: { category: 'invalid_content' } });
  });
});
