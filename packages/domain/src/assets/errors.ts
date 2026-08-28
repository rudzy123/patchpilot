import type { AppError } from '../result.js';

export const ORGANIZATION_CONTEXT_REQUIRED: AppError = Object.freeze({
  code: 'forbidden',
  message: 'Organization context is required.',
});

export const PERMISSION_DENIED: AppError = Object.freeze({
  code: 'forbidden',
  message: 'Permission denied.',
});

export const MEMBERSHIP_NOT_ASSIGNABLE: AppError = Object.freeze({
  code: 'validation',
  message: 'Membership is not an active assignment target.',
});

export const TEAM_NOT_ASSIGNABLE: AppError = Object.freeze({
  code: 'validation',
  message: 'Team is not an active assignment target.',
});

export const ENVIRONMENT_NOT_ASSIGNABLE: AppError = Object.freeze({
  code: 'validation',
  message: 'Environment is not an active assignment target.',
});

export const ASSET_NOT_FOUND: AppError = Object.freeze({
  code: 'not_found',
  message: 'Asset not found.',
});

export const ASSET_NAME_CONFLICT: AppError = Object.freeze({
  code: 'conflict',
  message: 'Asset name already exists.',
});

export const ASSET_VERSION_CONFLICT: AppError = Object.freeze({
  code: 'conflict',
  message: 'Asset version conflict.',
});

export const ASSET_ARCHIVED: AppError = Object.freeze({
  code: 'conflict',
  message: 'Asset is archived.',
});

export const ASSET_UPDATE_EMPTY: AppError = Object.freeze({
  code: 'validation',
  message: 'Asset update must include a mutation.',
});

export const ASSET_INVALID_CURSOR: AppError = Object.freeze({
  code: 'validation',
  message: 'Invalid request.',
});

export function assetValidationError(message: string): AppError {
  return {
    code: 'validation',
    message,
  };
}
