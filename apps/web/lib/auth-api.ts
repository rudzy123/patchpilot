import {
  archiveAssetRequestSchema,
  assetDetailSchema,
  assetListResponseSchema,
  environmentOptionsResponseSchema,
  errorEnvelopeSchema,
  membershipOptionsResponseSchema,
  organizationsResponseSchema,
  sessionResponseSchema,
  teamOptionsResponseSchema,
  type ArchiveAssetRequest,
  type AssetDetail,
  type AssetListResponse,
  type EnvironmentOption,
  type MembershipOption,
  type OrganizationsResponse,
  type SessionResponse,
  type TeamOption,
} from '@patchpilot/contracts';

/** Synchronizer token header. Must match `AUTH_CSRF_HEADER_NAME` / ADR 0019. */
export const CSRF_HEADER_NAME = 'x-csrf-token';

export const GENERIC_LOGIN_FAILURE = 'Invalid email or password.';
export const GENERIC_UNAVAILABLE = 'Sign in is temporarily unavailable.';
export const GENERIC_SESSION_EXPIRED = 'Your session has expired. Sign in again.';
export const GENERIC_ACCESS_DENIED = 'You do not have access to that resource.';
export const ORGANIZATION_CONTEXT_REQUIRED = 'Organization context is required.';
export const ASSET_VERSION_CONFLICT = 'Asset version conflict.';
export const ASSET_ARCHIVED = 'Asset is archived.';

export type AuthRequestError = {
  status: number;
  code: string;
  message: string;
};

export function createAuthApi(apiBaseUrl: string) {
  const baseUrl = apiBaseUrl.endsWith('/') ? apiBaseUrl.slice(0, -1) : apiBaseUrl;

  return {
    login(input: { email: string; password: string }): Promise<SessionResponse> {
      return sendJson<SessionResponse>({
        baseUrl,
        path: '/auth/login',
        method: 'POST',
        body: input,
        parse: (value) => sessionResponseSchema.parse(value),
        unauthorizedMessage: GENERIC_LOGIN_FAILURE,
      });
    },

    readSession(): Promise<SessionResponse> {
      return sendJson<SessionResponse>({
        baseUrl,
        path: '/auth/session',
        method: 'GET',
        parse: (value) => sessionResponseSchema.parse(value),
        unauthorizedMessage: GENERIC_SESSION_EXPIRED,
      });
    },

    listOrganizations(): Promise<OrganizationsResponse> {
      return sendJson<OrganizationsResponse>({
        baseUrl,
        path: '/auth/organizations',
        method: 'GET',
        parse: (value) => organizationsResponseSchema.parse(value),
        unauthorizedMessage: GENERIC_SESSION_EXPIRED,
      });
    },

    selectOrganization(organizationId: string, csrfToken: string): Promise<SessionResponse> {
      return sendJson<SessionResponse>({
        baseUrl,
        path: '/auth/select-organization',
        method: 'POST',
        body: { organizationId },
        csrfToken,
        parse: (value) => sessionResponseSchema.parse(value),
        unauthorizedMessage: GENERIC_SESSION_EXPIRED,
      });
    },

    logout(csrfToken: string | null): Promise<void> {
      return sendJson<void>({
        baseUrl,
        path: '/auth/logout',
        method: 'POST',
        body: {},
        ...(csrfToken === null ? {} : { csrfToken }),
        parse: () => undefined,
        acceptNoContent: true,
      });
    },

    listAssets(query?: AssetListClientQuery): Promise<AssetListResponse> {
      return sendJson<AssetListResponse>({
        baseUrl,
        path: '/assets',
        method: 'GET',
        ...(query === undefined ? {} : { query: assetListQuery(query) }),
        parse: (value) => assetListResponseSchema.parse(value),
        unauthorizedMessage: GENERIC_SESSION_EXPIRED,
      });
    },

    getAsset(assetId: string): Promise<AssetDetail> {
      return sendJson<AssetDetail>({
        baseUrl,
        path: `/assets/${assetId}`,
        method: 'GET',
        parse: (value) => assetDetailSchema.parse(value),
        unauthorizedMessage: GENERIC_SESSION_EXPIRED,
      });
    },

    createAsset(body: unknown, csrfToken: string): Promise<AssetDetail> {
      return sendJson<AssetDetail>({
        baseUrl,
        path: '/assets',
        method: 'POST',
        body,
        csrfToken,
        parse: (value) => assetDetailSchema.parse(value),
        unauthorizedMessage: GENERIC_SESSION_EXPIRED,
      });
    },

    updateAsset(assetId: string, body: unknown, csrfToken: string): Promise<AssetDetail> {
      return sendJson<AssetDetail>({
        baseUrl,
        path: `/assets/${assetId}`,
        method: 'PATCH',
        body,
        csrfToken,
        parse: (value) => assetDetailSchema.parse(value),
        unauthorizedMessage: GENERIC_SESSION_EXPIRED,
      });
    },

    archiveAsset(
      assetId: string,
      body: ArchiveAssetRequest,
      csrfToken: string,
    ): Promise<AssetDetail> {
      const parsedBody = archiveAssetRequestSchema.parse(body);
      return sendJson<AssetDetail>({
        baseUrl,
        path: `/assets/${assetId}/archive`,
        method: 'POST',
        body: parsedBody,
        csrfToken,
        parse: (value) => assetDetailSchema.parse(value),
        unauthorizedMessage: GENERIC_SESSION_EXPIRED,
      });
    },

    listAssetEnvironments(): Promise<{ items: EnvironmentOption[]; nextCursor: string | null }> {
      return sendJson({
        baseUrl,
        path: '/asset-options/environments',
        method: 'GET',
        query: { limit: '100' },
        parse: (value) => environmentOptionsResponseSchema.parse(value),
        unauthorizedMessage: GENERIC_SESSION_EXPIRED,
      });
    },

    listAssetTeams(): Promise<{ items: TeamOption[]; nextCursor: string | null }> {
      return sendJson({
        baseUrl,
        path: '/asset-options/teams',
        method: 'GET',
        query: { limit: '100' },
        parse: (value) => teamOptionsResponseSchema.parse(value),
        unauthorizedMessage: GENERIC_SESSION_EXPIRED,
      });
    },

    listAssetMemberships(): Promise<{ items: MembershipOption[]; nextCursor: string | null }> {
      return sendJson({
        baseUrl,
        path: '/asset-options/memberships',
        method: 'GET',
        query: { limit: '100' },
        parse: (value) => membershipOptionsResponseSchema.parse(value),
        unauthorizedMessage: GENERIC_SESSION_EXPIRED,
      });
    },
  };
}

export type AssetListClientQuery = {
  limit?: number;
  cursor?: string;
  lifecycleStatus?: 'active' | 'archived' | 'all';
};

export type AuthApi = ReturnType<typeof createAuthApi>;

async function sendJson<T>(input: {
  baseUrl: string;
  path: string;
  method: 'GET' | 'POST' | 'PATCH';
  body?: unknown;
  query?: Record<string, string>;
  csrfToken?: string;
  parse: (value: unknown) => T;
  acceptNoContent?: boolean;
  unauthorizedMessage?: string;
}): Promise<T> {
  const headers = new Headers();
  if (input.body !== undefined) {
    headers.set('content-type', 'application/json');
  }
  if (input.csrfToken !== undefined && input.csrfToken.length > 0) {
    headers.set(CSRF_HEADER_NAME, input.csrfToken);
  }

  let response: Response;
  try {
    response = await fetch(`${input.baseUrl}${input.path}${queryString(input.query)}`, {
      method: input.method,
      credentials: 'include',
      cache: 'no-store',
      headers,
      ...(input.body === undefined ? {} : { body: JSON.stringify(input.body) }),
    });
  } catch {
    throw createAuthRequestError(0, 'internal', GENERIC_UNAVAILABLE);
  }

  if (input.acceptNoContent === true && response.status === 204) {
    return input.parse(undefined);
  }

  const payload: unknown = await readJson(response);
  if (!response.ok) {
    throw mapErrorEnvelope(payload, response.status, input.unauthorizedMessage);
  }

  return input.parse(payload);
}

async function readJson(response: Response): Promise<unknown> {
  const text = await response.text();
  if (text.length === 0) {
    return null;
  }

  try {
    return JSON.parse(text) as unknown;
  } catch {
    return null;
  }
}

function mapErrorEnvelope(
  payload: unknown,
  status: number,
  unauthorizedMessage: string | undefined,
): AuthRequestError {
  const parsed = errorEnvelopeSchema.safeParse(payload);
  if (!parsed.success) {
    return createAuthRequestError(
      status,
      status === 401 ? 'unauthorized' : 'internal',
      status === 401 ? (unauthorizedMessage ?? GENERIC_SESSION_EXPIRED) : GENERIC_UNAVAILABLE,
    );
  }

  if (parsed.data.error.code === 'unauthorized') {
    return createAuthRequestError(
      status,
      'unauthorized',
      unauthorizedMessage ?? parsed.data.error.message,
    );
  }

  if (parsed.data.error.code === 'forbidden') {
    if (parsed.data.error.message === ORGANIZATION_CONTEXT_REQUIRED) {
      return createAuthRequestError(status, 'forbidden', ORGANIZATION_CONTEXT_REQUIRED);
    }
    return createAuthRequestError(status, 'forbidden', GENERIC_ACCESS_DENIED);
  }

  if (parsed.data.error.code === 'rate_limited' || parsed.data.error.code === 'internal') {
    return createAuthRequestError(status, parsed.data.error.code, parsed.data.error.message);
  }

  return createAuthRequestError(status, parsed.data.error.code, parsed.data.error.message);
}

function createAuthRequestError(status: number, code: string, message: string): AuthRequestError {
  return { status, code, message };
}

export function isAuthRequestError(error: unknown): error is AuthRequestError {
  return (
    typeof error === 'object' &&
    error !== null &&
    'status' in error &&
    'code' in error &&
    'message' in error
  );
}

function queryString(query: Record<string, string> | undefined): string {
  if (query === undefined) {
    return '';
  }

  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value.length > 0) {
      params.set(key, value);
    }
  }
  const encoded = params.toString();
  return encoded.length === 0 ? '' : `?${encoded}`;
}

function assetListQuery(query: AssetListClientQuery): Record<string, string> {
  const params: Record<string, string> = {};
  if (query.limit !== undefined) {
    params['limit'] = String(query.limit);
  }
  if (query.cursor !== undefined) {
    params['cursor'] = query.cursor;
  }
  if (query.lifecycleStatus !== undefined) {
    params['lifecycleStatus'] = query.lifecycleStatus;
  }
  return params;
}
