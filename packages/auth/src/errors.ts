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
