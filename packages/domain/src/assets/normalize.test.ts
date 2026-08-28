import { describe, expect, it } from 'vitest';

import {
  ASSET_DESCRIPTION_MAX_LENGTH,
  ASSET_IDENTIFIER_MAX_COUNT,
  ASSET_NAME_MAX_LENGTH,
  ASSET_OWNER_MAX_COUNT,
  ASSET_REPOSITORY_URL_MAX_LENGTH,
  ASSET_TAG_MAX_COUNT,
  ASSET_UPDATE_EMPTY,
  DEFAULT_BUSINESS_CRITICALITY,
  DEFAULT_DATA_CLASSIFICATION,
  DEFAULT_INTERNET_EXPOSURE,
  hasAssetUpdateMutation,
  normalizeAssetExternalIdentifiers,
  normalizeAssetName,
  normalizeAssetNamePrefix,
  normalizeAssetOwners,
  normalizeAssetRepositoryUrl,
  normalizeAssetTags,
  normalizeCreateAssetCommand,
  normalizeIdentifierNamespace,
  normalizeIdentifierValue,
  normalizeUpdateAssetCommand,
} from './index.js';

const MEMBERSHIP_A = '11111111-1111-4111-8111-111111111111';
const MEMBERSHIP_B = '22222222-2222-4222-8222-222222222222';
const TEAM_A = '33333333-3333-4333-8333-333333333333';
const ENVIRONMENT_A = '44444444-4444-4444-8444-444444444444';

describe('asset name normalization', () => {
  it('trims whitespace, applies Unicode NFC, and preserves display case', () => {
    expect(normalizeAssetName('  Cafe\u0301  ')).toEqual({
      ok: true,
      value: 'Café',
    });
    expect(normalizeAssetName('Billing API')).toEqual({
      ok: true,
      value: 'Billing API',
    });
  });

  it('rejects control characters and empty or oversized names', () => {
    expect(normalizeAssetName('A\u0000B').ok).toBe(false);
    expect(normalizeAssetName('A\nB').ok).toBe(false);
    expect(normalizeAssetName('A\u007FB').ok).toBe(false);
    expect(normalizeAssetName('A\u0080B').ok).toBe(false);
    expect(normalizeAssetName('   ').ok).toBe(false);
    expect(normalizeAssetName('x'.repeat(ASSET_NAME_MAX_LENGTH + 1)).ok).toBe(false);
    expect(normalizeAssetName('x').ok).toBe(true);
    expect(normalizeAssetName('x'.repeat(ASSET_NAME_MAX_LENGTH)).ok).toBe(true);
  });
});

describe('asset name prefix', () => {
  it('requires two normalized characters and rejects leading wildcards', () => {
    expect(normalizeAssetNamePrefix(' a').ok).toBe(false);
    expect(normalizeAssetNamePrefix('Bi')).toEqual({ ok: true, value: 'Bi' });
    expect(normalizeAssetNamePrefix('%bill').ok).toBe(false);
    expect(normalizeAssetNamePrefix('_bill').ok).toBe(false);
  });
});

describe('description, context, and repository URL', () => {
  it('enforces length boundaries without fetching URLs', () => {
    expect(
      normalizeCreateAssetCommand({
        name: 'svc',
        assetType: 'service',
        description: 'x'.repeat(ASSET_DESCRIPTION_MAX_LENGTH + 1),
      }).ok,
    ).toBe(false);
    expect(
      normalizeCreateAssetCommand({
        name: 'svc',
        assetType: 'service',
        deploymentContext: 'x'.repeat(ASSET_DESCRIPTION_MAX_LENGTH + 1),
      }).ok,
    ).toBe(false);

    const url = `https://git.example.test/${'a'.repeat(ASSET_REPOSITORY_URL_MAX_LENGTH)}`;
    expect(normalizeAssetRepositoryUrl(url).ok).toBe(false);
    expect(normalizeAssetRepositoryUrl('git@internal.example.test:org/app.git')).toEqual({
      ok: true,
      value: 'git@internal.example.test:org/app.git',
    });
    expect(normalizeAssetRepositoryUrl('https://example.test/app\u0001').ok).toBe(false);
  });
});

describe('tags', () => {
  it('normalizes, lowercases, collapses duplicates, and sorts alphabetically', () => {
    const tags = normalizeAssetTags(['  Prod-1  ', 'prod-1', 'alpha']);
    expect(tags).toEqual({
      ok: true,
      value: ['alpha', 'prod-1'],
    });
  });

  it('rejects invalid shape, control characters, and more than 20 unique tags', () => {
    expect(normalizeAssetTags(['Prod_1']).ok).toBe(false);
    expect(normalizeAssetTags(['prod\n1']).ok).toBe(false);
    const tooMany = Array.from({ length: ASSET_TAG_MAX_COUNT + 1 }, (_, index) => `tag-${index}`);
    expect(normalizeAssetTags(tooMany).ok).toBe(false);
    const atLimit = Array.from({ length: ASSET_TAG_MAX_COUNT }, (_, index) => `tag-${index}`);
    expect(normalizeAssetTags(atLimit).ok).toBe(true);
  });
});

describe('owners', () => {
  it('accepts membership XOR team assignments and unique role targets', () => {
    const owners = normalizeAssetOwners([
      { kind: 'membership', membershipId: MEMBERSHIP_A, role: 'technical' },
      { kind: 'membership', membershipId: MEMBERSHIP_A, role: 'business' },
      { kind: 'team', teamId: TEAM_A, role: 'security' },
    ]);
    expect(owners.ok).toBe(true);
    if (owners.ok) {
      expect(owners.value).toHaveLength(3);
    }
  });

  it('rejects mixed targets, duplicates, unknown fields, and more than 20 owners', () => {
    expect(
      normalizeAssetOwners([
        {
          kind: 'membership',
          membershipId: MEMBERSHIP_A,
          teamId: TEAM_A,
          role: 'technical',
        },
      ]).ok,
    ).toBe(false);
    expect(
      normalizeAssetOwners([
        { kind: 'membership', membershipId: MEMBERSHIP_A, role: 'technical' },
        { kind: 'membership', membershipId: MEMBERSHIP_A, role: 'technical' },
      ]).ok,
    ).toBe(false);
    expect(
      normalizeAssetOwners([
        {
          kind: 'membership',
          membershipId: MEMBERSHIP_A,
          role: 'technical',
          userId: MEMBERSHIP_B,
        },
      ]).ok,
    ).toBe(false);
    const tooMany = Array.from({ length: ASSET_OWNER_MAX_COUNT + 1 }, (_, index) => ({
      kind: 'membership' as const,
      membershipId: `11111111-1111-4111-8111-${String(index).padStart(12, '0')}`,
      role: 'technical' as const,
    }));
    expect(normalizeAssetOwners(tooMany).ok).toBe(false);
  });
});

describe('external identifiers', () => {
  it('lowercases namespaces, preserves identifier case, and applies NFC', () => {
    const identifiers = normalizeAssetExternalIdentifiers([
      { namespace: '  CMDB  ', identifier: '  Cafe\u0301-1  ' },
    ]);
    expect(identifiers).toEqual({
      ok: true,
      value: [{ namespace: 'cmdb', identifier: 'Café-1' }],
    });
    expect(normalizeIdentifierNamespace('Service-Catalog')).toEqual({
      ok: true,
      value: 'service-catalog',
    });
    expect(normalizeIdentifierValue('Abc')).toEqual({ ok: true, value: 'Abc' });
  });

  it('rejects control characters, duplicate namespaces, and more than 20 identifiers', () => {
    expect(
      normalizeAssetExternalIdentifiers([{ namespace: 'cmdb', identifier: 'id\u0000' }]).ok,
    ).toBe(false);
    expect(normalizeIdentifierValue('id\u0081').ok).toBe(false);
    expect(
      normalizeAssetExternalIdentifiers([
        { namespace: 'cmdb', identifier: 'one' },
        { namespace: 'CMDB', identifier: 'two' },
      ]).ok,
    ).toBe(false);
    const tooMany = Array.from({ length: ASSET_IDENTIFIER_MAX_COUNT + 1 }, (_, index) => ({
      namespace: `ns-${index}`,
      identifier: 'id',
    }));
    expect(normalizeAssetExternalIdentifiers(tooMany).ok).toBe(false);
  });
});

describe('create command', () => {
  it('applies accepted defaults and omits empty optional collections', () => {
    const created = normalizeCreateAssetCommand({
      name: '  Payments  ',
      assetType: 'service',
      environmentId: ENVIRONMENT_A,
    });
    expect(created.ok).toBe(true);
    if (created.ok) {
      expect(created.value.name).toBe('Payments');
      expect(created.value.businessCriticality).toBe(DEFAULT_BUSINESS_CRITICALITY);
      expect(created.value.internetExposure).toBe(DEFAULT_INTERNET_EXPOSURE);
      expect(created.value.dataClassification).toBe(DEFAULT_DATA_CLASSIFICATION);
      expect(created.value.tags).toEqual([]);
      expect(created.value.owners).toEqual([]);
      expect(created.value.externalIdentifiers).toEqual([]);
      expect(created.value.environmentId).toBe(ENVIRONMENT_A);
      expect(created.value).not.toHaveProperty('description');
    }
  });
});

describe('update command', () => {
  it('rejects expectedVersion-only input and treats null as a clear', () => {
    expect(hasAssetUpdateMutation({ expectedVersion: 3 })).toBe(false);
    expect(normalizeUpdateAssetCommand({ expectedVersion: 3 })).toEqual({
      ok: false,
      error: ASSET_UPDATE_EMPTY,
    });
    expect(hasAssetUpdateMutation({ expectedVersion: 3, environmentId: null })).toBe(true);

    const cleared = normalizeUpdateAssetCommand({
      expectedVersion: 3,
      environmentId: null,
      description: null,
    });
    expect(cleared.ok).toBe(true);
    if (cleared.ok) {
      expect(cleared.value.environmentId).toBeNull();
      expect(cleared.value.description).toBeNull();
      expect(cleared.value).not.toHaveProperty('name');
    }
  });

  it('treats empty collections as a replace-to-clear mutation', () => {
    const cleared = normalizeUpdateAssetCommand({
      expectedVersion: 2,
      tags: [],
    });
    expect(cleared).toEqual({
      ok: true,
      value: { expectedVersion: 2, tags: [] },
    });
  });
});
