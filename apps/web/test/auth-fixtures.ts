import { vi, type Mock } from 'vitest';

import type {
  AssetDetail,
  AssetListResponse,
  EnvironmentOption,
  MembershipOption,
  PublicAuthOrganization,
  PublicAuthUser,
  SessionResponse,
  TeamOption,
} from '@patchpilot/contracts';

import type { AuthApi } from '../lib/auth-api';

export const CSRF_TOKEN_FIXTURE = 'csrf-memory-only-token';
export const USER_ID = '11111111-1111-4111-8111-111111111111';
export const ORGANIZATION_ID = '22222222-2222-4222-8222-222222222222';
export const SECOND_ORGANIZATION_ID = '33333333-3333-4333-8333-333333333333';
export const ASSET_ID = '44444444-4444-4444-8444-444444444444';
export const ENVIRONMENT_ID = '55555555-5555-4555-8555-555555555555';
export const TEAM_ID = '66666666-6666-4666-8666-666666666666';
export const MEMBERSHIP_ID = '77777777-7777-4777-8777-777777777777';
export const OWNER_ROW_ID = '88888888-8888-4888-8888-888888888888';

export const publicUserFixture: PublicAuthUser = {
  id: USER_ID,
  displayName: 'Ada Lovelace',
};

export const publicOrganizationFixture: PublicAuthOrganization = {
  id: ORGANIZATION_ID,
  slug: 'ada-org',
  name: 'Ada Org',
  role: 'member',
};

export const adminOrganizationFixture: PublicAuthOrganization = {
  id: ORGANIZATION_ID,
  slug: 'ada-org',
  name: 'Ada Org',
  role: 'admin',
};

export const secondOrganizationFixture: PublicAuthOrganization = {
  id: SECOND_ORGANIZATION_ID,
  slug: 'second-org',
  name: 'Second Org',
  role: 'viewer',
};

export const environmentOptionFixture: EnvironmentOption = {
  id: ENVIRONMENT_ID,
  name: 'production',
  slug: 'production',
  sensitivityClass: 'production',
};

export const teamOptionFixture: TeamOption = {
  id: TEAM_ID,
  name: 'Platform',
  slug: 'platform',
};

export const membershipOptionFixture: MembershipOption = {
  membershipId: MEMBERSHIP_ID,
  displayName: 'Ada Lovelace',
  role: 'admin',
};

export const assetSummaryFixture = {
  id: ASSET_ID,
  name: 'Payments',
  assetType: 'application' as const,
  lifecycleStatus: 'active' as const,
  environment: {
    id: ENVIRONMENT_ID,
    name: 'production',
    sensitivityClass: 'production' as const,
  },
  owningTeam: { id: TEAM_ID, name: 'Platform' },
  businessCriticality: 'high' as const,
  internetExposure: 'internet_facing' as const,
  dataClassification: 'confidential' as const,
  tags: ['core', 'payments'],
  lastObservedAt: null,
  version: 1,
  updatedAt: '2026-08-28T14:00:00.000Z',
};

export const assetDetailFixture: AssetDetail = {
  ...assetSummaryFixture,
  description: 'Primary payments service',
  repositoryUrl: 'https://git.example.invalid/payments',
  deploymentContext: 'us-east-1',
  lastSuccessfulSbomIngestionId: null,
  lastSuccessfulSbomIngestionAt: null,
  archivedAt: null,
  owners: [
    {
      kind: 'membership',
      id: OWNER_ROW_ID,
      membershipId: MEMBERSHIP_ID,
      displayName: 'Ada Lovelace',
      role: 'technical',
    },
  ],
  externalIdentifiers: [{ namespace: 'cmdb', identifier: 'PAY-1' }],
  createdAt: '2026-08-28T13:00:00.000Z',
};

export const assetListFixture: AssetListResponse = {
  items: [assetSummaryFixture],
  nextCursor: null,
};

export function sessionFixture(overrides: Partial<SessionResponse> = {}): SessionResponse {
  return {
    user: publicUserFixture,
    organization: publicOrganizationFixture,
    csrfToken: CSRF_TOKEN_FIXTURE,
    expiresAt: '2026-08-28T00:00:00.000Z',
    ...overrides,
  };
}

export type FakeAuthApi = {
  [K in keyof AuthApi]: Mock<AuthApi[K]>;
};

export function unauthorizedError(): { status: number; code: string; message: string } {
  return { status: 401, code: 'unauthorized', message: 'Unauthorized' };
}

export function createFakeAuthApi(overrides: Partial<FakeAuthApi> = {}): FakeAuthApi {
  return {
    login: vi.fn(async () => sessionFixture()),
    readSession: vi.fn(async () => {
      throw unauthorizedError();
    }),
    listOrganizations: vi.fn(async () => ({
      organizations: [publicOrganizationFixture, secondOrganizationFixture],
    })),
    selectOrganization: vi.fn(async () => sessionFixture()),
    logout: vi.fn(async () => undefined),
    listAssets: vi.fn(async () => assetListFixture),
    getAsset: vi.fn(async () => assetDetailFixture),
    createAsset: vi.fn(async () => assetDetailFixture),
    updateAsset: vi.fn(async () => ({ ...assetDetailFixture, version: 2 })),
    archiveAsset: vi.fn(async () => ({
      ...assetDetailFixture,
      lifecycleStatus: 'archived',
      archivedAt: '2026-08-28T15:00:00.000Z',
      version: 2,
    })),
    listAssetEnvironments: vi.fn(async () => ({
      items: [environmentOptionFixture],
      nextCursor: null,
    })),
    listAssetTeams: vi.fn(async () => ({ items: [teamOptionFixture], nextCursor: null })),
    listAssetMemberships: vi.fn(async () => ({
      items: [membershipOptionFixture],
      nextCursor: null,
    })),
    ...overrides,
  };
}
