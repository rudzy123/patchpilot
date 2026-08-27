import type { AppError } from '@patchpilot/domain';

/** Public login failure for unknown email, wrong password, and disabled User. */
export const PUBLIC_LOGIN_FAILURE: AppError = Object.freeze({
  code: 'unauthorized',
  message: 'Invalid email or password.',
});

export const AUTHENTICATION_REQUIRED: AppError = Object.freeze({
  code: 'unauthorized',
  message: 'Authentication required.',
});

/** Tenant-safe response when Organization selection is unauthorized or missing. */
export const ORGANIZATION_NOT_FOUND: AppError = Object.freeze({
  code: 'not_found',
  message: 'Organization not found.',
});

export const PERMISSION_DENIED: AppError = Object.freeze({
  code: 'forbidden',
  message: 'Permission denied.',
});

/** Public response when either login limiter bucket is exhausted. */
export const LOGIN_RATE_LIMITED: AppError = Object.freeze({
  code: 'rate_limited',
  message: 'Too many login attempts. Try again later.',
});

/**
 * Fail-closed login when the limiter cannot decide. Same public error for every
 * account so Redis outages do not reveal whether an email exists.
 */
export const LOGIN_UNAVAILABLE: AppError = Object.freeze({
  code: 'internal',
  message: 'Login is temporarily unavailable.',
});

export function passwordMinLengthError(minLength: number): AppError {
  return {
    code: 'validation',
    message: `Password must be at least ${minLength} characters.`,
  };
}

export function passwordMaxBytesError(maxBytes: number): AppError {
  return {
    code: 'validation',
    message: `Password must be at most ${maxBytes} UTF-8 bytes.`,
  };
}
