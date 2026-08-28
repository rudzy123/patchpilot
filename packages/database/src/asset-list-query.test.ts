import { describe, expect, it } from 'vitest';

import { Prisma } from '@prisma/client';

import { buildAssetListQuery, sqlContainsRawValue } from './asset-list-query.js';
import { isUuid } from './guards.js';

const ORG_ID = '11111111-1111-4111-8111-111111111111';
const ASSET_ID = '22222222-2222-4222-8222-222222222222';

describe('asset list SQL', () => {
  it('binds cursor name and id as parameters instead of interpolating them', () => {
    const injected = "alpha'); DROP TABLE asset; --";
    const compiled = buildAssetListQuery(ORG_ID, {
      limit: 20,
      lifecycleStatus: 'active',
      cursor: { v: 1, n: injected, i: ASSET_ID },
    });

    expect(compiled.empty).toBe(false);
    expect(sqlContainsRawValue(compiled.sql, injected)).toBe(false);
    expect(compiled.sql.values).toContain(injected);
    expect(compiled.sql.values).toContain(ASSET_ID);
    expect(Prisma.sql`SELECT 1`.values).toEqual([]);
  });

  it('rejects an invalid cursor without using it as SQL', () => {
    const compiled = buildAssetListQuery(ORG_ID, {
      limit: 20,
      lifecycleStatus: 'active',
      cursor: { v: 1, n: 'billing', i: 'not-a-uuid' },
    });

    expect(compiled.empty).toBe(true);
    expect(sqlContainsRawValue(compiled.sql, 'not-a-uuid')).toBe(false);
  });

  it('treats a non-uuid organization as an empty page', () => {
    expect(isUuid('not-an-organization')).toBe(false);
    expect(buildAssetListQuery('not-an-organization').empty).toBe(true);
  });
});
