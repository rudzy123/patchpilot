import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  createAuthApi,
  CSRF_HEADER_NAME,
  GENERIC_LOGIN_FAILURE,
  GENERIC_SESSION_EXPIRED,
  GENERIC_UNAVAILABLE,
} from './auth-api';

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
});
