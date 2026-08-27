import { createHash } from 'node:crypto';

export const SESSION_TOKEN_DIGEST_PREFIX = 'patchpilot-session-v1:';
export const CSRF_TOKEN_DIGEST_PREFIX = 'patchpilot-csrf-v1:';
export const LOGIN_ACCOUNT_DIGEST_PREFIX = 'patchpilot-login-account-v1:';
export const LOGIN_IP_DIGEST_PREFIX = 'patchpilot-login-ip-v1:';

export function digestSessionToken(rawToken: string): string {
  return sha256Hex(`${SESSION_TOKEN_DIGEST_PREFIX}${rawToken}`);
}

export function digestCsrfToken(rawToken: string): string {
  return sha256Hex(`${CSRF_TOKEN_DIGEST_PREFIX}${rawToken}`);
}

/** Trim and lowercase so account limiter keys match User email uniqueness. */
export function normalizeLoginEmail(email: string): string {
  return email.trim().toLowerCase();
}

/** Domain-separated SHA-256 of the normalized email. Never store the raw email. */
export function digestLoginAccount(email: string): string {
  return sha256Hex(`${LOGIN_ACCOUNT_DIGEST_PREFIX}${normalizeLoginEmail(email)}`);
}

/** Domain-separated SHA-256 of a direct socket peer IP. Never log the raw IP. */
export function digestLoginPeerIp(peerIp: string): string {
  return sha256Hex(`${LOGIN_IP_DIGEST_PREFIX}${peerIp}`);
}

function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}
