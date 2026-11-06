import {
  archiveAssetRequestSchema,
  assetDetailSchema,
  assetListResponseSchema,
  controlledFindingCreationResponseSchema,
  controlledFindingDiscoveryResponseSchema,
  controlledFindingInspectionResponseSchema,
  deliberateProductMatchEvaluationResponseSchema,
  productMatchCandidatesResponseSchema,
  environmentOptionsResponseSchema,
  errorEnvelopeSchema,
  membershipOptionsResponseSchema,
  organizationsResponseSchema,
  sessionResponseSchema,
  teamOptionsResponseSchema,
  type ArchiveAssetRequest,
  type AssetDetail,
  type AssetListResponse,
  type ControlledFindingCreationRequest,
  type ControlledFindingCreationResponse,
  type ControlledFindingDiscoveryResponse,
  type ControlledFindingInspectionResponse,
  type DeliberateProductMatchEvaluationResponse,
  type ProductMatchCandidatesResponse,
  type ControlledFindingLatestObservationResponse,
  type FindingPriorityResponse,
  type FindingRiskCalculationResponse,
  type PriorityReviewResponse,
  type RemediationQueueResponse,
  type EnvironmentOption,
  type MembershipOption,
  type OrganizationsResponse,
  type SessionResponse,
  type TeamOption,
} from '@patchpilot/contracts';

import { readLatestObservation } from './finding-latest-observation';
import {
  readFindingPriority,
  readFindingRiskCalculation,
  readPriorityReview,
} from './finding-priority';
import {
  QUEUE_EXPORT_CSV_FILENAME,
  QUEUE_EXPORT_JSON_FILENAME,
  QUEUE_UNAVAILABLE,
  readRemediationQueue,
} from './remediation-queue';
import { isCanonicalUuid } from './resource-id';

/** Synchronizer token header. Must match `AUTH_CSRF_HEADER_NAME` / ADR 0019. */
export const CSRF_HEADER_NAME = 'x-csrf-token';

export const GENERIC_LOGIN_FAILURE = 'Invalid email or password.';
export const GENERIC_UNAVAILABLE = 'Sign in is temporarily unavailable.';
export const GENERIC_SESSION_EXPIRED = 'Your session has expired. Sign in again.';
export const GENERIC_ACCESS_DENIED = 'You do not have access to that resource.';
export const ORGANIZATION_CONTEXT_REQUIRED = 'Organization context is required.';
export const ASSET_VERSION_CONFLICT = 'Asset version conflict.';
export const ASSET_ARCHIVED = 'Asset is archived.';

/** Default discovery page size. Matches the API default of 10. */
export const CONTROLLED_FINDING_TARGET_PAGE_LIMIT = 10;

/** Default product-match candidate page size. Matches the API default of 10. */
export const PRODUCT_MATCH_CANDIDATE_PAGE_LIMIT = 10;

export const FINDING_SERVICE_UNAVAILABLE = 'The service is temporarily unavailable.';

export type AuthRequestError = {
  status: number;
  code: string;
  message: string;
  requestId?: string;
  correlationId?: string;
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

    listProductMatchCandidates(
      assetId: string,
      query?: { cursor: string },
    ): Promise<ProductMatchCandidatesResponse> {
      if (!isCanonicalUuid(assetId)) {
        return Promise.reject(createAuthRequestError(404, 'not_found', 'Not found.'));
      }
      const params: Record<string, string> = {
        limit: String(PRODUCT_MATCH_CANDIDATE_PAGE_LIMIT),
      };
      if (query !== undefined) {
        params['cursor'] = query.cursor;
      }
      return sendJson({
        baseUrl,
        path: `/assets/${assetId}/product-match-candidates`,
        method: 'GET',
        query: params,
        parse: (value) => productMatchCandidatesResponseSchema.parse(value),
        unauthorizedMessage: GENERIC_SESSION_EXPIRED,
        unavailableMessage: FINDING_SERVICE_UNAVAILABLE,
      });
    },

    evaluateProductMatch(
      assetId: string,
      body: { advisoryRevisionId: string },
      csrfToken: string,
    ): Promise<DeliberateProductMatchEvaluationResponse> {
      if (!isCanonicalUuid(assetId)) {
        return Promise.reject(createAuthRequestError(404, 'not_found', 'Not found.'));
      }
      return sendJson({
        baseUrl,
        path: `/assets/${assetId}/product-match-evaluations`,
        method: 'POST',
        body: { advisoryRevisionId: body.advisoryRevisionId },
        csrfToken,
        parse: (value) => deliberateProductMatchEvaluationResponseSchema.parse(value),
        unauthorizedMessage: GENERIC_SESSION_EXPIRED,
        unavailableMessage: FINDING_SERVICE_UNAVAILABLE,
      });
    },

    listControlledFindingTargets(
      assetId: string,
      query?: { cursor: string },
    ): Promise<ControlledFindingDiscoveryResponse> {
      if (!isCanonicalUuid(assetId)) {
        return Promise.reject(createAuthRequestError(404, 'not_found', 'Not found.'));
      }
      const params: Record<string, string> = {
        limit: String(CONTROLLED_FINDING_TARGET_PAGE_LIMIT),
      };
      if (query !== undefined) {
        params['cursor'] = query.cursor;
      }
      return sendJson({
        baseUrl,
        path: `/assets/${assetId}/controlled-finding-targets`,
        method: 'GET',
        query: params,
        parse: (value) => controlledFindingDiscoveryResponseSchema.parse(value),
        unauthorizedMessage: GENERIC_SESSION_EXPIRED,
        unavailableMessage: FINDING_SERVICE_UNAVAILABLE,
      });
    },

    createControlledFinding(
      body: ControlledFindingCreationRequest,
      csrfToken: string,
    ): Promise<ControlledFindingCreationResponse> {
      return sendJson({
        baseUrl,
        path: '/findings',
        method: 'POST',
        body,
        csrfToken,
        parse: (value) => controlledFindingCreationResponseSchema.parse(value),
        unauthorizedMessage: GENERIC_SESSION_EXPIRED,
        unavailableMessage: FINDING_SERVICE_UNAVAILABLE,
      });
    },

    inspectControlledFinding(findingId: string): Promise<ControlledFindingInspectionResponse> {
      if (!isCanonicalUuid(findingId)) {
        return Promise.reject(createAuthRequestError(404, 'not_found', 'Not found.'));
      }
      return sendJson({
        baseUrl,
        path: `/findings/${findingId}`,
        method: 'GET',
        parse: (value) => controlledFindingInspectionResponseSchema.parse(value),
        unauthorizedMessage: GENERIC_SESSION_EXPIRED,
        unavailableMessage: FINDING_SERVICE_UNAVAILABLE,
      });
    },

    inspectControlledFindingLatestObservation(
      findingId: string,
    ): Promise<ControlledFindingLatestObservationResponse> {
      if (!isCanonicalUuid(findingId)) {
        return Promise.reject(createAuthRequestError(404, 'not_found', 'Not found.'));
      }
      return sendJson({
        baseUrl,
        path: `/findings/${findingId}/latest-observation`,
        method: 'GET',
        parse: (value) => {
          const observation = readLatestObservation(value, findingId);
          if (observation === null) {
            throw createAuthRequestError(
              503,
              'internal',
              'Finding operator is temporarily unavailable.',
            );
          }
          return observation;
        },
        unauthorizedMessage: GENERIC_SESSION_EXPIRED,
        unavailableMessage: FINDING_SERVICE_UNAVAILABLE,
      });
    },

    readFindingPriority(findingId: string): Promise<FindingPriorityResponse> {
      if (!isCanonicalUuid(findingId)) {
        return Promise.reject(createAuthRequestError(404, 'not_found', 'Not found.'));
      }
      return sendJson({
        baseUrl,
        path: `/findings/${findingId}/priority`,
        method: 'GET',
        parse: (value) => {
          const priority = readFindingPriority(value, findingId);
          if (priority === null) {
            throw createAuthRequestError(
              503,
              'internal',
              'Priority inspection is temporarily unavailable.',
            );
          }
          return priority;
        },
        unauthorizedMessage: GENERIC_SESSION_EXPIRED,
        unavailableMessage: FINDING_SERVICE_UNAVAILABLE,
      });
    },

    readRemediationQueue(query: {
      section: 'ranked' | 'incomparable' | 'not_calculated';
      limit?: number;
      cursor?: string;
    }): Promise<RemediationQueueResponse> {
      const params: Record<string, string> = { section: query.section };
      if (query.limit !== undefined) {
        params['limit'] = String(query.limit);
      }
      if (query.cursor !== undefined && query.cursor.length > 0) {
        params['cursor'] = query.cursor;
      }
      return sendJson({
        baseUrl,
        path: '/remediation-queue',
        method: 'GET',
        query: params,
        parse: (value) => {
          const page = readRemediationQueue(value, query.section);
          if (page === null) {
            throw createAuthRequestError(503, 'internal', QUEUE_UNAVAILABLE);
          }
          return page;
        },
        unauthorizedMessage: GENERIC_SESSION_EXPIRED,
        unavailableMessage: FINDING_SERVICE_UNAVAILABLE,
      });
    },

    exportRemediationQueue(
      format: 'json' | 'csv',
      csrfToken: string,
    ): Promise<{
      format: 'json' | 'csv';
      mediaType: string;
      filename: string;
      bytes: Uint8Array;
    }> {
      const filename = format === 'json' ? QUEUE_EXPORT_JSON_FILENAME : QUEUE_EXPORT_CSV_FILENAME;
      const mediaType =
        format === 'json' ? 'application/json; charset=utf-8' : 'text/csv; charset=utf-8';
      return sendResponseBody({
        baseUrl,
        path: '/remediation-queue/export',
        method: 'POST',
        body: { format },
        csrfToken,
        unauthorizedMessage: GENERIC_SESSION_EXPIRED,
        unavailableMessage: QUEUE_UNAVAILABLE,
      }).then((response) => {
        if (
          response.mediaType !== mediaType ||
          response.disposition !== `attachment; filename="${filename}"` ||
          response.bytes.byteLength === 0
        ) {
          throw createAuthRequestError(503, 'internal', QUEUE_UNAVAILABLE);
        }
        return { format, mediaType, filename, bytes: response.bytes };
      });
    },

    calculateFindingPriority(
      findingId: string,
      csrfToken: string,
    ): Promise<FindingRiskCalculationResponse> {
      if (!isCanonicalUuid(findingId)) {
        return Promise.reject(createAuthRequestError(404, 'not_found', 'Not found.'));
      }
      return sendJson({
        baseUrl,
        path: `/findings/${findingId}/risk-calculations`,
        method: 'POST',
        body: {},
        csrfToken,
        parse: (value) => {
          const calculation = readFindingRiskCalculation(value, findingId);
          if (calculation === null) {
            throw createAuthRequestError(
              503,
              'internal',
              'Priority calculation is temporarily unavailable.',
            );
          }
          return calculation;
        },
        unauthorizedMessage: GENERIC_SESSION_EXPIRED,
        unavailableMessage: FINDING_SERVICE_UNAVAILABLE,
      });
    },

    recordFindingPriorityReview(
      findingId: string,
      csrfToken: string,
      body: {
        riskCalculationId: string;
        supersedesReviewId: string | null;
        decision: 'accepted' | 'corrected' | 'withdrawn';
        correctedBand?: 'P1' | 'P2' | 'P3' | 'P4';
        expiresAt?: string;
        reason?: string;
      },
    ): Promise<PriorityReviewResponse> {
      if (!isCanonicalUuid(findingId) || !isCanonicalUuid(body.riskCalculationId)) {
        return Promise.reject(createAuthRequestError(404, 'not_found', 'Not found.'));
      }
      return sendJson({
        baseUrl,
        path: `/findings/${findingId}/priority-reviews`,
        method: 'POST',
        body: {
          schemaVersion: 'priority_review_v1',
          riskCalculationId: body.riskCalculationId,
          supersedesReviewId: body.supersedesReviewId,
          decision: body.decision,
          ...(body.correctedBand === undefined ? {} : { correctedBand: body.correctedBand }),
          ...(body.expiresAt === undefined ? {} : { expiresAt: body.expiresAt }),
          ...(body.reason === undefined ? {} : { reason: body.reason }),
        },
        csrfToken,
        parse: (value) => {
          const review = readPriorityReview(value, findingId, body.riskCalculationId);
          if (review === null) {
            throw createAuthRequestError(
              503,
              'internal',
              'Priority review is temporarily unavailable.',
            );
          }
          return review;
        },
        unauthorizedMessage: GENERIC_SESSION_EXPIRED,
        unavailableMessage: FINDING_SERVICE_UNAVAILABLE,
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
  unavailableMessage?: string;
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
    throw mapErrorEnvelope(
      payload,
      response.status,
      input.unauthorizedMessage,
      input.unavailableMessage,
    );
  }

  return input.parse(payload);
}

async function sendResponseBody(input: {
  baseUrl: string;
  path: string;
  method: 'POST';
  body: unknown;
  csrfToken: string;
  unauthorizedMessage?: string;
  unavailableMessage?: string;
}): Promise<{ mediaType: string; disposition: string | null; bytes: Uint8Array }> {
  const headers = new Headers();
  headers.set('content-type', 'application/json');
  if (input.csrfToken.length > 0) {
    headers.set(CSRF_HEADER_NAME, input.csrfToken);
  }
  let response: Response;
  try {
    response = await fetch(`${input.baseUrl}${input.path}`, {
      method: input.method,
      credentials: 'include',
      cache: 'no-store',
      headers,
      body: JSON.stringify(input.body),
    });
  } catch {
    throw createAuthRequestError(0, 'internal', GENERIC_UNAVAILABLE);
  }
  if (!response.ok) {
    throw mapErrorEnvelope(
      await readJson(response),
      response.status,
      input.unauthorizedMessage,
      input.unavailableMessage,
    );
  }
  return {
    mediaType: response.headers.get('content-type') ?? '',
    disposition: response.headers.get('content-disposition'),
    bytes: new Uint8Array(await response.arrayBuffer()),
  };
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
  unavailableMessage: string | undefined,
): AuthRequestError {
  const parsed = errorEnvelopeSchema.safeParse(payload);
  if (!parsed.success) {
    return createAuthRequestError(
      status,
      status === 401 ? 'unauthorized' : 'internal',
      status === 401
        ? (unauthorizedMessage ?? GENERIC_SESSION_EXPIRED)
        : (unavailableMessage ?? GENERIC_UNAVAILABLE),
    );
  }

  const identifiers = {
    requestId: parsed.data.error.requestId,
    correlationId: parsed.data.error.correlationId,
  };

  if (parsed.data.error.code === 'unauthorized') {
    return createAuthRequestError(
      status,
      'unauthorized',
      unauthorizedMessage ?? parsed.data.error.message,
      identifiers,
    );
  }

  if (parsed.data.error.code === 'forbidden') {
    if (parsed.data.error.message === ORGANIZATION_CONTEXT_REQUIRED) {
      return createAuthRequestError(
        status,
        'forbidden',
        ORGANIZATION_CONTEXT_REQUIRED,
        identifiers,
      );
    }
    return createAuthRequestError(status, 'forbidden', GENERIC_ACCESS_DENIED, identifiers);
  }

  if (parsed.data.error.code === 'rate_limited' || parsed.data.error.code === 'internal') {
    return createAuthRequestError(
      status,
      parsed.data.error.code,
      parsed.data.error.message,
      identifiers,
    );
  }

  return createAuthRequestError(
    status,
    parsed.data.error.code,
    parsed.data.error.message,
    identifiers,
  );
}

function createAuthRequestError(
  status: number,
  code: string,
  message: string,
  identifiers?: { requestId: string; correlationId: string },
): AuthRequestError {
  return {
    status,
    code,
    message,
    ...(identifiers === undefined
      ? {}
      : { requestId: identifiers.requestId, correlationId: identifiers.correlationId }),
  };
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
