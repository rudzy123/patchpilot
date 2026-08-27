import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import {
  csrfTokenMatchesDigest,
  CSRF_TOKEN_DIGEST_PREFIX,
  digestCsrfToken,
  digestLoginAccount,
  digestLoginPeerIp,
  digestSessionToken,
  LOGIN_ACCOUNT_DIGEST_PREFIX,
  LOGIN_IP_DIGEST_PREFIX,
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

  it('domain-separates login account and peer-IP digests from raw values', () => {
    const email = 'Owner@Synthetic.PatchPilot.Test';
    const peerIp = '192.0.2.10';
    const account = digestLoginAccount(email);
    const ip = digestLoginPeerIp(peerIp);

    expect(account).toBe(
      sha256Hex(`${LOGIN_ACCOUNT_DIGEST_PREFIX}owner@synthetic.patchpilot.test`),
    );
    expect(ip).toBe(sha256Hex(`${LOGIN_IP_DIGEST_PREFIX}${peerIp}`));
    expect(account).not.toBe(sha256Hex(email));
    expect(account).not.toBe(digestLoginAccount('other@synthetic.patchpilot.test'));
    expect(digestLoginAccount(email)).toBe(
      digestLoginAccount('  owner@synthetic.patchpilot.test  '),
    );
    expect(account).not.toContain('owner@');
  });

  it('compares presented CSRF tokens to stored digests without accepting the raw value as a digest', () => {
    const raw = 'RAW_CSRF_TOKEN_VALUE_NOT_A_DIGEST';
    const stored = digestCsrfToken(raw);
    expect(csrfTokenMatchesDigest(raw, stored)).toBe(true);
    expect(csrfTokenMatchesDigest('other-raw-csrf-token-value', stored)).toBe(false);
    expect(csrfTokenMatchesDigest(undefined, stored)).toBe(false);
    expect(csrfTokenMatchesDigest('', stored)).toBe(false);
    expect(csrfTokenMatchesDigest(stored, stored)).toBe(false);
  });
});
