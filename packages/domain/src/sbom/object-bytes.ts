import { createHash } from 'node:crypto';

import { err, ok, type Result } from '../result.js';
import type { GetObjectResult } from './ports.js';
import type { SafeFailureCode } from './failures.js';

export type VerifiedObjectBuffer = {
  bytes: ArrayBuffer;
  sha256: string;
  byteLength: number;
};

export async function readVerifiedObjectBuffer(
  result: GetObjectResult,
  expected: { sha256: string; byteLength: number; maxBytes: number },
): Promise<Result<VerifiedObjectBuffer, { code: SafeFailureCode }>> {
  const chunks: Uint8Array[] = [];
  let observed = 0;
  const hash = createHash('sha256');

  try {
    for await (const chunk of result.body) {
      observed += chunk.byteLength;
      if (observed > expected.maxBytes) {
        await result.cancel();
        return err({ code: 'payload_too_large' });
      }
      hash.update(chunk);
      chunks.push(chunk);
    }
    const completion = await result.completion;
    if (completion.observedByteLength !== expected.byteLength || observed !== expected.byteLength) {
      return err({ code: 'hash_mismatch' });
    }
    const sha256 = hash.digest('hex');
    if (sha256 !== expected.sha256) {
      return err({ code: 'hash_mismatch' });
    }
    if (completion.sha256 !== undefined && completion.sha256 !== expected.sha256) {
      return err({ code: 'hash_mismatch' });
    }

    const bytes = new Uint8Array(observed);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return ok({
      bytes: bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
      sha256,
      byteLength: observed,
    });
  } catch {
    await result.cancel();
    return err({ code: 'hash_mismatch' });
  }
}
