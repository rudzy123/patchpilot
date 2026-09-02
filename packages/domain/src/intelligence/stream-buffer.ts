import { createHash } from 'node:crypto';

import { err, ok, type Result } from '../result.js';
import type { IntelligenceSafeFailureCode } from './failures.js';
import type { GetIntelligenceSnapshotResult } from './ports.js';

/**
 * Collect a KEV snapshot GET into one exact-sized ArrayBuffer.
 *
 * Memory behavior:
 * - When `declaredByteLength` is present and within `maxBytes`, allocate that
 *   size once and fill it.
 * - When length is absent, start at 64 KiB and double until `maxBytes`. Peak
 *   temporary overhead is less than 2× the final size plus one chunk.
 * - Completion copies into one exact-sized ArrayBuffer and drops the growable
 *   buffer. Chunk arrays are not retained.
 * - `maxBytes + 1` observed bytes is rejected without assembling a result.
 */
export type BoundedKevSnapshotBuffer = {
  bytes: ArrayBuffer;
  sha256: string;
  byteLength: number;
};

export type BoundedKevSnapshotCollectInput = {
  result: GetIntelligenceSnapshotResult;
  maxBytes: number;
  expectedSha256: string;
  expectedByteLength: number;
  declaredByteLength?: number;
};

const INITIAL_ABSENT_LENGTH_CAPACITY = 65_536;

export async function collectBoundedKevSnapshotBuffer(
  input: BoundedKevSnapshotCollectInput,
): Promise<Result<BoundedKevSnapshotBuffer, { code: IntelligenceSafeFailureCode }>> {
  if (
    !Number.isSafeInteger(input.maxBytes) ||
    input.maxBytes < 1 ||
    !Number.isSafeInteger(input.expectedByteLength) ||
    input.expectedByteLength < 1 ||
    input.expectedByteLength > input.maxBytes
  ) {
    await input.result.cancel();
    return err({ code: 'response_too_large' });
  }

  const declared = input.declaredByteLength;
  if (declared !== undefined) {
    if (!Number.isSafeInteger(declared) || declared < 1 || declared > input.maxBytes) {
      await input.result.cancel();
      return err({ code: 'response_too_large' });
    }
    if (declared !== input.expectedByteLength) {
      await input.result.cancel();
      return err({ code: 'hash_mismatch' });
    }
  }

  const hash = createHash('sha256');
  let observed = 0;
  const capacity =
    declared !== undefined ? declared : Math.min(INITIAL_ABSENT_LENGTH_CAPACITY, input.maxBytes);
  let buffer = new Uint8Array(capacity);

  try {
    for await (const chunk of input.result.body) {
      const next = observed + chunk.byteLength;
      if (next > input.maxBytes) {
        await input.result.cancel();
        return err({ code: 'response_too_large' });
      }
      if (next > buffer.byteLength) {
        let grown = buffer.byteLength;
        while (grown < next) {
          const doubled = grown * 2;
          grown = doubled > input.maxBytes ? input.maxBytes : doubled;
          if (grown < next && grown === input.maxBytes) {
            await input.result.cancel();
            return err({ code: 'response_too_large' });
          }
        }
        const replacement = new Uint8Array(grown);
        replacement.set(buffer.subarray(0, observed));
        buffer = replacement;
      }
      buffer.set(chunk, observed);
      hash.update(chunk);
      observed = next;
    }

    const completion = await input.result.completion;
    if (observed === 0 || completion.observedByteLength === 0) {
      return err({ code: 'response_empty' });
    }
    if (
      observed !== input.expectedByteLength ||
      completion.observedByteLength !== input.expectedByteLength
    ) {
      return err({ code: 'hash_mismatch' });
    }
    const sha256 = hash.digest('hex');
    if (sha256 !== input.expectedSha256 || completion.sha256 !== input.expectedSha256) {
      return err({ code: 'hash_mismatch' });
    }

    const exact = new Uint8Array(observed);
    exact.set(buffer.subarray(0, observed));
    buffer = new Uint8Array(0);
    return ok({
      bytes: exact.buffer,
      sha256,
      byteLength: observed,
    });
  } catch {
    await input.result.cancel();
    return err({ code: 'snapshot_storage_failed' });
  }
}
