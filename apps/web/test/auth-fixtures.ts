import { vi, type Mock } from 'vitest';

import type {
  PublicAuthOrganization,
  PublicAuthUser,
  SessionResponse,
} from '@patchpilot/contracts';

import type { AuthApi } from '../lib/auth-api';

export const CSRF_TOKEN_FIXTURE = 'csrf-memory-only-token';
export const USER_ID = '11111111-1111-4111-8111-111111111111';
export const ORGANIZATION_ID = '22222222-2222-4222-8222-222222222222';
export const SECOND_ORGANIZATION_ID = '33333333-3333-4333-8333-333333333333';

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

export const secondOrganizationFixture: PublicAuthOrganization = {
  id: SECOND_ORGANIZATION_ID,
  slug: 'second-org',
  name: 'Second Org',
  role: 'viewer',
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
    ...overrides,
  };
}
