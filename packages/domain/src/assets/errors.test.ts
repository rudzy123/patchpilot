import { describe, expect, it } from 'vitest';

import {
  ASSET_ARCHIVED,
  ASSET_NAME_CONFLICT,
  ASSET_NOT_FOUND,
  ASSET_UPDATE_EMPTY,
  ASSET_VERSION_CONFLICT,
  ENVIRONMENT_NOT_ASSIGNABLE,
  MEMBERSHIP_NOT_ASSIGNABLE,
  ORGANIZATION_CONTEXT_REQUIRED,
  PERMISSION_DENIED,
  TEAM_NOT_ASSIGNABLE,
} from './errors.js';

describe('asset application errors', () => {
  it('uses stable public codes and messages', () => {
    expect(ORGANIZATION_CONTEXT_REQUIRED).toEqual({
      code: 'forbidden',
      message: 'Organization context is required.',
    });
    expect(PERMISSION_DENIED).toEqual({
      code: 'forbidden',
      message: 'Permission denied.',
    });
    expect(MEMBERSHIP_NOT_ASSIGNABLE.code).toBe('validation');
    expect(TEAM_NOT_ASSIGNABLE.code).toBe('validation');
    expect(ENVIRONMENT_NOT_ASSIGNABLE.code).toBe('validation');
    expect(ASSET_NOT_FOUND).toEqual({
      code: 'not_found',
      message: 'Asset not found.',
    });
    expect(ASSET_NAME_CONFLICT).toEqual({
      code: 'conflict',
      message: 'Asset name already exists.',
    });
    expect(ASSET_VERSION_CONFLICT).toEqual({
      code: 'conflict',
      message: 'Asset version conflict.',
    });
    expect(ASSET_ARCHIVED).toEqual({
      code: 'conflict',
      message: 'Asset is archived.',
    });
    expect(ASSET_UPDATE_EMPTY.code).toBe('validation');
  });
});
