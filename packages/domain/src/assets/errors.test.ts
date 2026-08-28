import { describe, expect, it } from 'vitest';

import {
  ASSET_ARCHIVED,
  ASSET_NAME_CONFLICT,
  ASSET_NOT_FOUND,
  ASSET_UPDATE_EMPTY,
  ASSET_VERSION_CONFLICT,
  ORGANIZATION_CONTEXT_REQUIRED,
} from './errors.js';

describe('asset application errors', () => {
  it('uses stable public codes and messages', () => {
    expect(ORGANIZATION_CONTEXT_REQUIRED).toEqual({
      code: 'forbidden',
      message: 'Organization context is required.',
    });
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
