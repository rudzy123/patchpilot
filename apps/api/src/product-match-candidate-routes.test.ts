import type { SessionResponse } from '@patchpilot/contracts';
import { deliberateProductMatchEvaluationRequestSchema } from '@patchpilot/contracts';
import type { FastifyInstance } from 'fastify';
import { describe, expect, it } from 'vitest';

import {
  TEST_ORIGIN,
  VALID_PASSWORD,
  buildTestApi,
  createAuthTestHarness,
} from './auth-test-harness.js';
import type { FindingOrganizationRateLimiter } from './finding-rate-limit.js';
import {
  PRODUCT_MATCH_CANDIDATE_ORGANIZATION_LIMIT,
  PRODUCT_MATCH_CANDIDATE_PEER_LIMIT,
  PRODUCT_MATCH_CANDIDATE_ROUTE,
} from './product-match-candidate-http.js';
import type {
  ProductMatchCandidateExecuteInput,
  ProductMatchCandidateRuntime,
  ProductMatchCandidateRuntimeResult,
} from './product-match-candidate-runtime.js';

const ASSET = '44444444-4444-4444-8444-444444444444';
const FOREIGN_ASSET = '99999999-9999-4999-8999-999999999999';
const ABSENT_ASSET = '12121212-1212-4212-8212-121212121212';
const INGESTION = '66666666-6666-4666-8666-666666666666';
const REVISION = '77777777-7777-4777-8777-777777777777';
const PACKAGE_NAME = 'reviewed-npm-widget';
const LOGIN_IP = '192.0.2.40';

type RoleName = 'owner' | 'admin' | 'member' | 'viewer';

function pageBody(): Extract<ProductMatchCandidateRuntimeResult, { status: 'page' }> {
  return {
    status: 'page',
    page: {
      schemaVersion: 'product_match_candidates_v1',
      assetId: ASSET,
      ingestionId: INGESTION,
      candidates: [
        {
          advisoryRevisionId: REVISION,
          ecosystem: 'npm',
          packageNamespace: null,
          packageName: PACKAGE_NAME,
          matchedOccurrenceCount: 2,
          evaluationState: 'not_evaluated',
        },
      ],
      nextCursor: null,
    },
  };
}

function scripted(initial: ProductMatchCandidateRuntimeResult = pageBody()): {
  runtime: ProductMatchCandidateRuntime;
  calls: ProductMatchCandidateExecuteInput[];
  set(next: ProductMatchCandidateRuntimeResult): void;
} {
  const calls: ProductMatchCandidateExecuteInput[] = [];
  let next = initial;
  return {
    calls,
    set(value) {
      next = value;
    },
    runtime: {
      async execute(input) {
        calls.push(input);
        return next;
      },
    },
  };
}

describe('product match candidate route', () => {
  it('uses the peer and organization ceilings from the decision', () => {
    expect(PRODUCT_MATCH_CANDIDATE_PEER_LIMIT).toEqual({ max: 30, windowMs: 60_000 });
    expect(PRODUCT_MATCH_CANDIDATE_ORGANIZATION_LIMIT).toEqual({ max: 20, windowMs: 60_000 });
    expect(PRODUCT_MATCH_CANDIDATE_ROUTE).toBe('/assets/:assetId/product-match-candidates');
  });

  it('returns an owner page and stores no cache', async () => {
    const script = scripted();
    const { app, session } = await boot('owner', { productMatchCandidates: script.runtime });
    const response = await get(app, session, ASSET, '198.51.100.20');
    expect(response.statusCode).toBe(200);
    expect(response.headers['cache-control']).toBe('private, no-store');
    const body = response.json();
    expect(Object.keys(body).sort()).toEqual([
      'assetId',
      'candidates',
      'ingestionId',
      'nextCursor',
      'schemaVersion',
    ]);
    expect(Object.keys(body.candidates[0]).sort()).toEqual([
      'advisoryRevisionId',
      'ecosystem',
      'evaluationState',
      'matchedOccurrenceCount',
      'packageName',
      'packageNamespace',
    ]);
    expect(body.candidates[0].packageName).toBe(PACKAGE_NAME);
    expect(script.calls).toHaveLength(1);
    expect(script.calls[0]?.assetId).toBe(ASSET);
    expect(script.calls[0]?.limit).toBe(10);
    expect(script.calls[0]?.cursor).toBeNull();
    await app.close();
  });

  it.each(['admin', 'member', 'viewer'] as const)('denies %s before the runtime', async (role) => {
    const script = scripted();
    const { app, session } = await boot(role, { productMatchCandidates: script.runtime });
    const response = await get(app, session, ASSET, `198.51.100.${role.length + 20}`);
    expect(response.statusCode).toBe(403);
    expectEnvelope(response, 'forbidden', 'Permission denied.');
    expect(script.calls).toHaveLength(0);
    await app.close();
  });

  it('does not consume the organization budget for an unauthenticated request', async () => {
    let consumes = 0;
    const limiter: FindingOrganizationRateLimiter = {
      consume() {
        consumes += 1;
        return 'allowed';
      },
    };
    const script = scripted();
    const { app } = await boot('owner', {
      productMatchCandidates: script.runtime,
      productMatchCandidateOrganizationLimiter: limiter,
    });
    const response = await app.inject({
      method: 'GET',
      url: candidateUrl(ASSET),
      remoteAddress: '198.51.100.30',
    });
    expect(response.statusCode).toBe(401);
    expect(consumes).toBe(0);
    expect(script.calls).toHaveLength(0);
    await app.close();
  });

  it('returns the same not-found body for a foreign asset and an absent asset', async () => {
    const script = scripted();
    script.runtime = {
      async execute(input) {
        script.calls.push(input);
        return { status: 'not_found' };
      },
    };
    const { app, session } = await boot('owner', { productMatchCandidates: script.runtime });
    const foreign = await get(app, session, FOREIGN_ASSET, '198.51.100.31');
    const absent = await get(app, session, ABSENT_ASSET, '198.51.100.32');
    expect(foreign.statusCode).toBe(404);
    expect(absent.statusCode).toBe(404);
    expect(publicError(foreign)).toEqual(publicError(absent));
    expect(publicError(foreign)).toEqual({ code: 'not_found', message: 'Not found.' });
    expect(JSON.stringify(foreign.json())).not.toContain(FOREIGN_ASSET);
    expect(JSON.stringify(absent.json())).not.toContain(ABSENT_ASSET);
    await app.close();
  });

  it('rejects an unknown query, a bad limit, a repeated key, and a GET body', async () => {
    const script = scripted();
    const { app, session } = await boot('owner', { productMatchCandidates: script.runtime });
    const extra = await get(app, session, ASSET, '198.51.100.33', '?organizationId=1');
    const limit = await get(app, session, ASSET, '198.51.100.34', '?limit=21');
    const repeated = await get(app, session, ASSET, '198.51.100.35', '?limit=10&limit=11');
    const body = await app.inject({
      method: 'GET',
      url: candidateUrl(ASSET),
      remoteAddress: '198.51.100.36',
      headers: { cookie: session.cookie, 'content-length': '2' },
      payload: '{}',
    });
    expect(extra.statusCode).toBe(400);
    expect(limit.statusCode).toBe(400);
    expect(repeated.statusCode).toBe(400);
    expect(body.statusCode).toBe(400);
    expect(script.calls).toHaveLength(0);
    await app.close();
  });

  it('returns stale_cursor without calling a second time', async () => {
    const script = scripted({ status: 'stale_cursor' });
    const { app, session } = await boot('owner', { productMatchCandidates: script.runtime });
    const response = await get(app, session, ASSET, '198.51.100.37', '?cursor=abc');
    expect(response.statusCode).toBe(409);
    expectEnvelope(response, 'conflict', 'stale_cursor');
    expect(script.calls).toHaveLength(1);
    await app.close();
  });

  it('hides a CVE identifier that the runtime tries to add', async () => {
    const polluted = pageBody();
    const candidate = {
      ...polluted.page.candidates[0],
      cveId: 'CVE-2024-9999',
    };
    const script = scripted({
      status: 'page',
      page: { ...polluted.page, candidates: [candidate] },
    } as ProductMatchCandidateRuntimeResult);
    const { app, session } = await boot('owner', { productMatchCandidates: script.runtime });
    const response = await get(app, session, ASSET, '198.51.100.38');
    expect(response.statusCode).toBe(500);
    expect(JSON.stringify(response.json())).not.toContain('CVE-2024-9999');
    expect(JSON.stringify(response.json())).not.toContain(PACKAGE_NAME);
    await app.close();
  });

  it('logs the route template and omits the asset, package, and revision', async () => {
    const script = scripted();
    const harness = createAuthTestHarness({ primaryRole: 'owner' });
    const logs: string[] = [];
    const logger = {
      info(bindings: unknown) {
        logs.push(JSON.stringify(bindings));
      },
      warn() {},
      error() {},
      debug() {},
      child() {
        return logger;
      },
    };
    const built = await buildTestApi({
      harness,
      logger: logger as never,
      productMatchCandidates: script.runtime,
    });
    const loggedIn = await built.app.inject({
      method: 'POST',
      url: '/auth/login',
      remoteAddress: LOGIN_IP,
      headers: { origin: TEST_ORIGIN, 'content-type': 'application/json' },
      payload: { email: harness.user.email, password: VALID_PASSWORD },
    });
    const session = sessionFrom(loggedIn, harness.config.auth.cookieName);
    await get(built.app, session, ASSET, '198.51.100.39');
    const lines = logs.filter((line) => line.includes(PRODUCT_MATCH_CANDIDATE_ROUTE));
    expect(lines.length).toBeGreaterThan(0);
    for (const line of lines) {
      expect(line).toContain(PRODUCT_MATCH_CANDIDATE_ROUTE);
      expect(line).not.toContain(ASSET);
      expect(line).not.toContain(REVISION);
      expect(line).not.toContain(PACKAGE_NAME);
      expect(line).not.toContain(INGESTION);
    }
    await built.app.close();
  });

  it('stops at the organization ceiling before the runtime', async () => {
    const limiter: FindingOrganizationRateLimiter = {
      consume() {
        return 'limited';
      },
    };
    const script = scripted();
    const { app, session } = await boot('owner', {
      productMatchCandidates: script.runtime,
      productMatchCandidateOrganizationLimiter: limiter,
    });
    const response = await get(app, session, ASSET, '198.51.100.41');
    expect(response.statusCode).toBe(429);
    expect(script.calls).toHaveLength(0);
    await app.close();
  });

  it('keeps the evaluation body limited to the advisory revision id', () => {
    const revision = '55555555-5555-4555-8555-555555555555';
    expect(
      deliberateProductMatchEvaluationRequestSchema.parse({ advisoryRevisionId: revision }),
    ).toEqual({
      advisoryRevisionId: revision,
    });
    expect(
      deliberateProductMatchEvaluationRequestSchema.safeParse({
        advisoryRevisionId: revision,
        ingestionId: INGESTION,
      }).success,
    ).toBe(false);
  });
});

async function boot(
  role: RoleName,
  options?: {
    productMatchCandidates?: ProductMatchCandidateRuntime;
    productMatchCandidateOrganizationLimiter?: FindingOrganizationRateLimiter;
  },
) {
  const harness = createAuthTestHarness({ primaryRole: role });
  const built = await buildTestApi({
    harness,
    ...(options?.productMatchCandidates === undefined
      ? {}
      : { productMatchCandidates: options.productMatchCandidates }),
    ...(options?.productMatchCandidateOrganizationLimiter === undefined
      ? {}
      : {
          productMatchCandidateOrganizationLimiter:
            options.productMatchCandidateOrganizationLimiter,
        }),
  });
  const loggedIn = await built.app.inject({
    method: 'POST',
    url: '/auth/login',
    remoteAddress: LOGIN_IP,
    headers: { origin: TEST_ORIGIN, 'content-type': 'application/json' },
    payload: { email: harness.user.email, password: VALID_PASSWORD },
  });
  expect(loggedIn.statusCode).toBe(200);
  return {
    app: built.app,
    session: sessionFrom(loggedIn, harness.config.auth.cookieName),
  };
}

function candidateUrl(assetId: string): string {
  return PRODUCT_MATCH_CANDIDATE_ROUTE.replace(':assetId', assetId);
}

async function get(
  app: FastifyInstance,
  session: { cookie: string },
  assetId: string,
  remoteAddress: string,
  query = '',
) {
  return app.inject({
    method: 'GET',
    url: `${candidateUrl(assetId)}${query}`,
    remoteAddress,
    headers: { cookie: session.cookie },
  });
}

function sessionFrom(
  response: { headers: { [key: string]: unknown }; json: () => unknown },
  cookieName: string,
): { cookie: string; csrf: string } {
  const header = response.headers['set-cookie'];
  const setCookie =
    typeof header === 'string' ? header : Array.isArray(header) ? header[0] : undefined;
  if (typeof setCookie !== 'string') {
    throw new Error('expected Set-Cookie');
  }
  const part = setCookie.split(';', 1)[0];
  const prefix = `${cookieName}=`;
  if (part === undefined || !part.startsWith(prefix)) {
    throw new Error('cookie name mismatch');
  }
  return {
    cookie: `${cookieName}=${part.slice(prefix.length)}`,
    csrf: (response.json() as SessionResponse).csrfToken,
  };
}

function expectEnvelope(
  response: { json: () => { error?: { code?: string; message?: string; requestId?: string } } },
  code: string,
  message: string,
): void {
  const body = response.json();
  expect(body.error?.code).toBe(code);
  expect(body.error?.message).toBe(message);
  expect(typeof body.error?.requestId).toBe('string');
}

function publicError(response: { json: () => { error?: { code?: string; message?: string } } }): {
  code: string | undefined;
  message: string | undefined;
} {
  const body = response.json();
  return { code: body.error?.code, message: body.error?.message };
}
