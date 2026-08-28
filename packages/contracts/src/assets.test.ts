import { encodeAssetListCursor } from '@patchpilot/domain';
import { describe, expect, it } from 'vitest';

import {
  archiveAssetRequestSchema,
  assetListQuerySchema,
  assetOwnerAssignmentSchema,
  createAssetRequestSchema,
  updateAssetRequestSchema,
} from './assets.js';

const MEMBERSHIP_ID = '11111111-1111-4111-8111-111111111111';
const TEAM_ID = '22222222-2222-4222-8222-222222222222';
const ENVIRONMENT_ID = '33333333-3333-4333-8333-333333333333';
const ASSET_ID = '44444444-4444-4444-8444-444444444444';

describe('create asset contract', () => {
  it('requires name and assetType and applies accepted defaults', () => {
    const parsed = createAssetRequestSchema.parse({
      name: '  Payments  ',
      assetType: 'service',
    });
    expect(parsed.name).toBe('Payments');
    expect(parsed.businessCriticality).toBe('unspecified');
    expect(parsed.internetExposure).toBe('unknown');
    expect(parsed.dataClassification).toBe('unspecified');
    expect(parsed.tags).toEqual([]);
  });

  it('rejects unknown fields, TrustedActor, and organizationId', () => {
    const extra = createAssetRequestSchema.safeParse({
      name: 'Payments',
      assetType: 'service',
      organizationId: ENVIRONMENT_ID,
      TrustedActor: { userId: MEMBERSHIP_ID },
      permissions: ['asset:manage'],
    });
    expect(extra.success).toBe(false);

    expect(
      createAssetRequestSchema.safeParse({
        name: 'Payments',
        assetType: 'service',
        requestId: 'req-1',
      }).success,
    ).toBe(false);
  });

  it('accepts optional owners, tags, and identifiers', () => {
    const parsed = createAssetRequestSchema.parse({
      name: 'Payments',
      assetType: 'application',
      environmentId: ENVIRONMENT_ID,
      owners: [{ kind: 'membership', membershipId: MEMBERSHIP_ID, role: 'technical' }],
      tags: ['prod-1', 'prod-1'],
      externalIdentifiers: [{ namespace: 'CMDB', identifier: 'PAY-1' }],
    });
    expect(parsed.tags).toEqual(['prod-1']);
    expect(parsed.externalIdentifiers).toEqual([{ namespace: 'cmdb', identifier: 'PAY-1' }]);
    expect(parsed.owners).toHaveLength(1);
  });
});

describe('update asset contract', () => {
  it('requires expectedVersion and rejects a no-op PATCH', () => {
    expect(updateAssetRequestSchema.safeParse({}).success).toBe(false);
    expect(updateAssetRequestSchema.safeParse({ expectedVersion: 1 }).success).toBe(false);
  });

  it('rejects server-controlled fields and unknown properties', () => {
    expect(
      updateAssetRequestSchema.safeParse({
        expectedVersion: 1,
        name: 'Payments',
        version: 2,
      }).success,
    ).toBe(false);
    expect(
      updateAssetRequestSchema.safeParse({
        expectedVersion: 1,
        lifecycleStatus: 'archived',
      }).success,
    ).toBe(false);
    expect(
      updateAssetRequestSchema.safeParse({
        expectedVersion: 1,
        organizationId: ENVIRONMENT_ID,
      }).success,
    ).toBe(false);
  });

  it('distinguishes omitted fields from explicit null clears', () => {
    const cleared = updateAssetRequestSchema.parse({
      expectedVersion: 4,
      environmentId: null,
      description: null,
    });
    expect(cleared.environmentId).toBeNull();
    expect(cleared.description).toBeNull();
    expect(cleared).not.toHaveProperty('name');

    const renamed = updateAssetRequestSchema.parse({
      expectedVersion: 4,
      name: 'New name',
    });
    expect(renamed.name).toBe('New name');
    expect(renamed).not.toHaveProperty('environmentId');
  });

  it('treats a present empty collection as a replace', () => {
    const parsed = updateAssetRequestSchema.parse({
      expectedVersion: 5,
      tags: [],
      owners: [],
    });
    expect(parsed.tags).toEqual([]);
    expect(parsed.owners).toEqual([]);
  });
});

describe('archive asset contract', () => {
  it('requires expectedVersion and no other fields', () => {
    expect(archiveAssetRequestSchema.parse({ expectedVersion: 2 })).toEqual({
      expectedVersion: 2,
    });
    expect(archiveAssetRequestSchema.safeParse({ expectedVersion: 2, name: 'x' }).success).toBe(
      false,
    );
  });
});

describe('owner XOR contract', () => {
  it('rejects mixed membership and team targets', () => {
    expect(
      assetOwnerAssignmentSchema.safeParse({
        kind: 'membership',
        membershipId: MEMBERSHIP_ID,
        teamId: TEAM_ID,
        role: 'technical',
      }).success,
    ).toBe(false);
    expect(
      assetOwnerAssignmentSchema.safeParse({
        kind: 'team',
        teamId: TEAM_ID,
        role: 'business',
      }).success,
    ).toBe(true);
  });
});

describe('asset list query contract', () => {
  it('defaults limit and lifecycle filter and bounds page size', () => {
    const parsed = assetListQuerySchema.parse({});
    expect(parsed.limit).toBe(20);
    expect(parsed.lifecycleStatus).toBe('active');

    expect(assetListQuerySchema.safeParse({ limit: 0 }).success).toBe(false);
    expect(assetListQuerySchema.safeParse({ limit: 101 }).success).toBe(false);
    expect(assetListQuerySchema.parse({ limit: '37' }).limit).toBe(37);
  });

  it('validates opaque cursors and name-prefix rules', () => {
    const cursor = encodeAssetListCursor({
      v: 1,
      n: 'payments',
      i: ASSET_ID,
    });
    const parsed = assetListQuerySchema.parse({
      cursor,
      namePrefix: ' Pa',
      tag: '  prod-1  ',
    });
    expect(parsed.cursor).toEqual({ v: 1, n: 'payments', i: ASSET_ID });
    expect(parsed.namePrefix).toBe('Pa');
    expect(parsed.tag).toBe('prod-1');

    expect(assetListQuerySchema.safeParse({ namePrefix: 'a' }).success).toBe(false);
    expect(assetListQuerySchema.safeParse({ namePrefix: '%pay' }).success).toBe(false);
    expect(assetListQuerySchema.safeParse({ cursor: 'not-a-cursor' }).success).toBe(false);
  });

  it('rejects unknown filters and organizationId', () => {
    expect(
      assetListQuerySchema.safeParse({
        organizationId: ENVIRONMENT_ID,
      }).success,
    ).toBe(false);
    expect(
      assetListQuerySchema.safeParse({
        orderBy: 'created_at DESC',
      }).success,
    ).toBe(false);
  });
});
