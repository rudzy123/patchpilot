import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import {
  CSRF_TOKEN_DIGEST_PREFIX,
  digestCsrfToken,
  digestSessionToken,
  SESSION_TOKEN_DIGEST_PREFIX,
} from './token-digests.js';

function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

describe('token digests', () => {
  it('domain-separates Session and CSRF SHA-256 digests', () => {
    const rawToken = 'RAW_SESSION_TOKEN_VALUE_NOT_A_DIGEST';
    const sessionDigest = digestSessionToken(rawToken);
    const csrfDigest = digestCsrfToken(rawToken);

    expect(sessionDigest).toBe(sha256Hex(`${SESSION_TOKEN_DIGEST_PREFIX}${rawToken}`));
    expect(csrfDigest).toBe(sha256Hex(`${CSRF_TOKEN_DIGEST_PREFIX}${rawToken}`));
    expect(sessionDigest).not.toBe(csrfDigest);
    expect(sessionDigest).not.toBe(sha256Hex(rawToken));
    expect(csrfDigest).not.toBe(sha256Hex(rawToken));
    expect(sessionDigest).toMatch(/^[a-f0-9]{64}$/);
    expect(csrfDigest).toMatch(/^[a-f0-9]{64}$/);
  });
});
