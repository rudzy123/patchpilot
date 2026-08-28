import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  ASSET_VERSION_CONFLICT,
  ORGANIZATION_CONTEXT_REQUIRED,
  createAuthApi,
  CSRF_HEADER_NAME,
  GENERIC_LOGIN_FAILURE,
  GENERIC_SESSION_EXPIRED,
  GENERIC_UNAVAILABLE,
} from './auth-api';

import {
  ASSET_ID,
  CSRF_TOKEN_FIXTURE,
  assetDetailFixture,
  assetListFixture,
} from '../test/auth-fixtures';

const API_BASE = 'http://127.0.0.1:3001';
const PASSWORD = 'correct-horse-test-password';
const EMAIL = 'operator@example.test';

const sessionBody = {
  user: { id: '11111111-1111-4111-8111-111111111111', displayName: 'Ada Lovelace' },
  organization: {
    id: '22222222-2222-4222-8222-222222222222',
    slug: 'ada-org',
    name: 'Ada Org',
    role: 'member',
  },
  csrfToken: 'csrf-memory-only-token',
  expiresAt: '2026-08-28T00:00:00.000Z',
};

function jsonResponse(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

function errorEnvelope(status: number, code: string, message: string): Response {
  return jsonResponse(status, {
    error: {
      code,
      message,
      requestId: 'req-1',
      correlationId: 'corr-1',
    },
  });
}

function fetchCall(
  fetchMock: ReturnType<typeof vi.fn>,
  index: number,
): { url: string; init: RequestInit } {
  const call = fetchMock.mock.calls[index];
  expect(call).toBeDefined();
  const url = call?.[0];
  const init = call?.[1];
  expect(typeof url).toBe('string');
  expect(init).toEqual(expect.any(Object));
  return { url: String(url), init: init as RequestInit };
}

describe('createAuthApi', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it('sends login with credentials include and never puts the token in the URL', async () => {
    const fetchMock = vi.fn(async (_input: RequestInfo, _init?: RequestInit): Promise<Response> =>
      jsonResponse(200, sessionBody),
    );
    vi.stubGlobal('fetch', fetchMock);
    const api = createAuthApi(`${API_BASE}/`);

    await api.login({ email: EMAIL, password: PASSWORD });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const { url, init } = fetchCall(fetchMock, 0);
    expect(url).toBe(`${API_BASE}/auth/login`);
    expect(url).not.toContain('csrf');
    expect(url).not.toContain(PASSWORD);
    expect(url).not.toContain(EMAIL);
    expect(init.credentials).toBe('include');
    expect(init.cache).toBe('no-store');
    const headers = init.headers as Headers;
    expect(headers.get('content-type')).toBe('application/json');
    expect(headers.get(CSRF_HEADER_NAME)).toBeNull();
    expect(init.body).toBe(JSON.stringify({ email: EMAIL, password: PASSWORD }));
  });

  it('replaces login 401 messages with the generic failure and omits credentials from the error', async () => {
    const fetchMock = vi.fn(async () =>
      errorEnvelope(401, 'unauthorized', `No account for ${EMAIL}`),
    );
    vi.stubGlobal('fetch', fetchMock);
    const api = createAuthApi(API_BASE);

    const error = await api
      .login({ email: EMAIL, password: PASSWORD })
      .catch((caught: unknown) => caught);

    expect(error).toEqual({
      status: 401,
      code: 'unauthorized',
      message: GENERIC_LOGIN_FAILURE,
    });
    expect(JSON.stringify(error)).not.toContain(PASSWORD);
    expect(JSON.stringify(error)).not.toContain(EMAIL);
  });

  it('sends the CSRF header only on authenticated mutations', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo, _init?: RequestInit): Promise<Response> => {
      const url = String(input);
      if (url.endsWith('/auth/session')) {
        return jsonResponse(200, sessionBody);
      }
      if (url.endsWith('/auth/organizations')) {
        return jsonResponse(200, { organizations: [sessionBody.organization] });
      }
      if (url.endsWith('/auth/select-organization')) {
        return jsonResponse(200, sessionBody);
      }
      if (url.endsWith('/auth/logout')) {
        return new Response(null, { status: 204 });
      }
      return jsonResponse(500, {
        error: { code: 'internal', message: 'no', requestId: 'r', correlationId: 'c' },
      });
    });
    vi.stubGlobal('fetch', fetchMock);
    const api = createAuthApi(API_BASE);

    await api.readSession();
    await api.listOrganizations();
    await api.selectOrganization(sessionBody.organization.id, 'csrf-memory-only-token');
    await api.logout('csrf-memory-only-token');

    const session = fetchCall(fetchMock, 0);
    const organizations = fetchCall(fetchMock, 1);
    const select = fetchCall(fetchMock, 2);
    const logout = fetchCall(fetchMock, 3);
    const sessionHeaders = session.init.headers as Headers;
    const organizationsHeaders = organizations.init.headers as Headers;
    const selectHeaders = select.init.headers as Headers;
    const logoutHeaders = logout.init.headers as Headers;

    expect(session.init.credentials).toBe('include');
    expect(sessionHeaders.get(CSRF_HEADER_NAME)).toBeNull();
    expect(organizationsHeaders.get(CSRF_HEADER_NAME)).toBeNull();
    expect(selectHeaders.get(CSRF_HEADER_NAME)).toBe('csrf-memory-only-token');
    expect(logoutHeaders.get(CSRF_HEADER_NAME)).toBe('csrf-memory-only-token');
    expect(select.url).toBe(`${API_BASE}/auth/select-organization`);
    expect(select.url).not.toContain('csrf');
  });

  it('maps unauthenticated session reads to a generic expiry message', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => errorEnvelope(401, 'unauthorized', 'nope')),
    );
    const api = createAuthApi(API_BASE);
    const error = await api.readSession().catch((caught: unknown) => caught);
    expect(error).toMatchObject({ status: 401, message: GENERIC_SESSION_EXPIRED });
  });

  it('maps network failure to a generic unavailable error without the password', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new Error(`connect failed for ${PASSWORD}`);
      }),
    );
    const api = createAuthApi(API_BASE);
    const error = await api
      .login({ email: EMAIL, password: PASSWORD })
      .catch((caught: unknown) => caught);
    expect(error).toEqual({ status: 0, code: 'internal', message: GENERIC_UNAVAILABLE });
    expect(JSON.stringify(error)).not.toContain(PASSWORD);
  });

  it('sends CSRF, credentials, and expectedVersion on asset mutations without putting secrets in the URL', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo, _init?: RequestInit): Promise<Response> => {
      const url = String(input);
      if (url.includes('/archive')) {
        return jsonResponse(200, {
          ...assetDetailFixture,
          lifecycleStatus: 'archived',
          archivedAt: '2026-08-28T15:00:00.000Z',
          version: 2,
        });
      }
      if (url.endsWith(`/assets/${ASSET_ID}`) && (_init?.method === 'PATCH' || _init?.method === 'GET')) {
        return jsonResponse(200, assetDetailFixture);
      }
      if (url.startsWith(`${API_BASE}/assets`)) {
        if (_init?.method === 'POST') {
          return jsonResponse(201, assetDetailFixture);
        }
        return jsonResponse(200, assetListFixture);
      }
      return jsonResponse(500, {
        error: { code: 'internal', message: 'no', requestId: 'r', correlationId: 'c' },
      });
    });
    vi.stubGlobal('fetch', fetchMock);
    const api = createAuthApi(API_BASE);

    await api.listAssets({ lifecycleStatus: 'active' });
    await api.getAsset(ASSET_ID);
    await api.createAsset({ name: 'Billing', assetType: 'service' }, CSRF_TOKEN_FIXTURE);
    await api.updateAsset(
      ASSET_ID,
      { expectedVersion: 1, name: 'Payments renamed' },
      CSRF_TOKEN_FIXTURE,
    );
    await api.archiveAsset(ASSET_ID, { expectedVersion: 1 }, CSRF_TOKEN_FIXTURE);

    const list = fetchCall(fetchMock, 0);
    const get = fetchCall(fetchMock, 1);
    const create = fetchCall(fetchMock, 2);
    const update = fetchCall(fetchMock, 3);
    const archive = fetchCall(fetchMock, 4);

    expect(list.url).toBe(`${API_BASE}/assets?lifecycleStatus=active`);
    expect(list.url).not.toContain('organization');
    expect(list.url).not.toContain('csrf');
    expect(list.init.credentials).toBe('include');
    expect((list.init.headers as Headers).get(CSRF_HEADER_NAME)).toBeNull();

    expect(get.init.credentials).toBe('include');
    expect((get.init.headers as Headers).get(CSRF_HEADER_NAME)).toBeNull();

    expect((create.init.headers as Headers).get(CSRF_HEADER_NAME)).toBe(CSRF_TOKEN_FIXTURE);
    expect(create.url).not.toContain('csrf');
    expect(create.url).not.toContain(sessionBody.organization.id);
    expect(create.init.credentials).toBe('include');

    expect((update.init.headers as Headers).get(CSRF_HEADER_NAME)).toBe(CSRF_TOKEN_FIXTURE);
    expect(update.init.method).toBe('PATCH');
    expect(String(update.init.body)).toContain('"expectedVersion":1');

    expect((archive.init.headers as Headers).get(CSRF_HEADER_NAME)).toBe(CSRF_TOKEN_FIXTURE);
    expect(archive.url).toBe(`${API_BASE}/assets/${ASSET_ID}/archive`);
    expect(String(archive.init.body)).toBe(JSON.stringify({ expectedVersion: 1 }));
  });

  it('preserves organization-context and version-conflict API messages', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo): Promise<Response> => {
      const url = String(input);
      if (url.endsWith('/assets') && url.includes('?') === false) {
        return errorEnvelope(403, 'forbidden', ORGANIZATION_CONTEXT_REQUIRED);
      }
      return errorEnvelope(409, 'conflict', ASSET_VERSION_CONFLICT);
    });
    vi.stubGlobal('fetch', fetchMock);
    const api = createAuthApi(API_BASE);

    const forbidden = await api
      .createAsset({ name: 'Billing', assetType: 'service' }, CSRF_TOKEN_FIXTURE)
      .catch((caught: unknown) => caught);
    const conflict = await api
      .updateAsset(ASSET_ID, { expectedVersion: 1 }, CSRF_TOKEN_FIXTURE)
      .catch((caught: unknown) => caught);

    expect(forbidden).toMatchObject({
      status: 403,
      code: 'forbidden',
      message: ORGANIZATION_CONTEXT_REQUIRED,
    });
    expect(conflict).toMatchObject({
      status: 409,
      code: 'conflict',
      message: ASSET_VERSION_CONFLICT,
    });
  });
});
