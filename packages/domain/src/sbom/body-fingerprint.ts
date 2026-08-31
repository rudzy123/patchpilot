import { createHash } from 'node:crypto';

import { err, ok, type Result } from '../result.js';
import type { ClassifiedStorageFailure, ObjectByteStream } from './ports.js';

export type UploadBodyFingerprint = {
  sha256: string;
  observedByteLength: number;
};

/**
 * Authoritative SHA-256 of original request bytes. Used for completed replay
 * fingerprinting so replay does not write a temporary object.
 */
export async function fingerprintUploadBody(input: {
  body: ObjectByteStream;
  maxBytes: number;
  declaredByteLength?: number;
  signal?: AbortSignal;
}): Promise<Result<UploadBodyFingerprint, ClassifiedStorageFailure>> {
  const declared = input.declaredByteLength;
  if (declared !== undefined && (declared < 1 || declared > input.maxBytes)) {
    return err({ category: 'size_limit' });
  }

  if (isAbortSignalAborted(input.signal)) {
    return err({ category: 'aborted' });
  }

  const hash = createHash('sha256');
  let observedByteLength = 0;
  try {
    for await (const chunk of input.body) {
      if (isAbortSignalAborted(input.signal)) {
        return err({ category: 'aborted' });
      }
      observedByteLength += chunk.byteLength;
      if (observedByteLength > input.maxBytes) {
        return err({ category: 'size_limit' });
      }
      hash.update(chunk);
    }
  } catch (error) {
    if (isAbortSignalAborted(input.signal) || isAbortError(error)) {
      return err({ category: 'aborted' });
    }
    throw error;
  }

  if (observedByteLength < 1) {
    return err({ category: 'invalid_content' });
  }
  if (declared !== undefined && declared !== observedByteLength) {
    return err({ category: 'invalid_content' });
  }

  return ok({
    sha256: hash.digest('hex'),
    observedByteLength,
  });
}

function isAbortSignalAborted(signal: AbortSignal | undefined): boolean {
  return signal !== undefined && signal.aborted;
}

function isAbortError(error: unknown): boolean {
  return (
    typeof error === 'object' && error !== null && 'name' in error && error.name === 'AbortError'
  );
}
