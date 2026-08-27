import { createHash } from 'node:crypto';

export const SESSION_TOKEN_DIGEST_PREFIX = 'patchpilot-session-v1:';
export const CSRF_TOKEN_DIGEST_PREFIX = 'patchpilot-csrf-v1:';

export function digestSessionToken(rawToken: string): string {
  return sha256Hex(`${SESSION_TOKEN_DIGEST_PREFIX}${rawToken}`);
}

export function digestCsrfToken(rawToken: string): string {
  return sha256Hex(`${CSRF_TOKEN_DIGEST_PREFIX}${rawToken}`);
}

function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}
