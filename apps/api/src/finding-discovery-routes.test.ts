/**
 * HTTP contract for asset-scoped controlled Finding target discovery.
 */

import type { FastifyInstance } from 'fastify';
import { describe, expect, it } from 'vitest';

import type { SessionResponse } from '@patchpilot/contracts';
import { controlledFindingCreationRequestSchema } from '@patchpilot/contracts';

import {
  TEST_ORIGIN,
  VALID_PASSWORD,
  buildTestApi,
  createAuthTestHarness,
} from './auth-test-harness.js';
import { DISCOVERY_REQUEST_BODY_LIMIT_BYTES } from './finding-discovery-routes.js';
import type { FindingDiscoveryRuntime } from './finding-discovery-runtime.js';
import {
  FINDING_DISCOVERY_ORGANIZATION_LIMIT,
  FINDING_DISCOVERY_PEER_LIMIT,
  createFindingOrganizationRateLimiter,
  type FindingOrganizationRateLimiter,
} from './finding-rate-limit.js';

const ASSET = '44444444-4444-4444-8444-444444444444';
const ABSENT = 'cdcdcdcd-cdcd-4dcd-8dcd-cdcdcdcdcdcd';
const COMPONENT = '55555555-5555-4555-8555-555555555555';
const VULNERABILITY = '66666666-6666-4666-8666-666666666666';
const INGESTION = '77777777-7777-4777-8777-777777777777';
const EVIDENCE = '88888888-8888-4888-8888-888888888888';
const LOGIN_IP = '192.0.2.40';

type RoleName = 'owner' | 'admin' | 'member' | 'viewer';

function page(assetId = ASSET) {
  return {
    candidates: [
      {
        classification: 'eligible_for_creation' as const,
        componentId: COMPONENT,
        vulnerabilityId: VULNERABILITY,
        vulnerabilityPublicId: 'REVIEWED-EXAMPLE',
        affectedVersions: {
          values: ['1.1.0'],
          truncated: false,
          omittedDistinctCount: 0,
          distinctCount: 1,
        },
        affectedOccurrenceCount: 1,
        otherOccurrenceCount: 0,
        explanationCodes: [],
        acknowledgement: {
          assetId,
          componentId: COMPONENT,
          vulnerabilityId: VULNERABILITY,
          expectedSbomIngestionId: INGESTION,
          expectedProductMatchEvidenceIds: [EVIDENCE],
        },
      },
    ],
    oversizedCandidateCount: 0,
    nextCursor: null,
  };
}

function scripted(
  status: 'page' | 'not_found' | 'stale_cursor' | 'malformed_persisted_state' = 'page',
): {
  runtime: FindingDiscoveryRuntime;
  calls: Array<{ organizationId: string | null; assetId: unknown }>;
} {
  const calls: Array<{ organizationId: string | null; assetId: unknown }> = [];
  return {
    calls,
    runtime: {
      async execute(input) {
        calls.push({ organizationId: input.actor.organizationId, assetId: input.assetId });
        if (status === 'page' && input.assetId === ASSET) {
          return { status: 'page', page: page() };
        }
        if (status === 'page') {
          return { status: 'not_found' };
        }
        return { status };
      },
    },
  };
}

describe('controlled finding target discovery route', () => {
  it('lets owner and admin read one page and rejects member and viewer', async () => {
    const ownerScript = scripted();
    const owner = await boot('owner', { discovery: ownerScript.runtime });
    const ownerPage = await get(owner.app, owner.session, ASSET, '198.51.100.10');
    expect(ownerPage.statusCode).toBe(200);
    expect(ownerPage.headers['cache-control']).toBe('private, no-store');
    const ownerBody = ownerPage.json() as { candidates: Array<{ acknowledgement: unknown }> };
    expect(
      controlledFindingCreationRequestSchema.safeParse(ownerBody.candidates[0]?.acknowledgement)
        .success,
    ).toBe(true);
    expect(ownerScript.calls[0]?.organizationId).toBe(owner.harness.organizations[0]?.id);
    await owner.app.close();

    const adminScript = scripted();
    const admin = await boot('admin', { discovery: adminScript.runtime });
    const adminPage = await get(admin.app, admin.session, ASSET, '198.51.100.11');
    expect(adminPage.statusCode).toBe(200);
    await admin.app.close();

    for (const role of ['member', 'viewer'] as const) {
      const script = scripted();
      const denied = await boot(role, { discovery: script.runtime });
      const response = await get(
        denied.app,
        denied.session,
        ASSET,
        `198.51.100.${role === 'member' ? 12 : 13}`,
      );
      expect(response.statusCode, role).toBe(403);
      expect(script.calls, role).toEqual([]);
      await denied.app.close();
    }
  });

  it('rejects a caller organization and keeps foreign and absent assets identical', async () => {
    const script = scripted();
    const { app, session } = await boot('owner', { discovery: script.runtime });
    const injected = await get(
      app,
      session,
      ASSET,
      '198.51.100.14',
      'organizationId=11111111-1111-4111-8111-111111111111',
    );
    const foreign = await get(app, session, ABSENT, '198.51.100.15');
    const absent = await get(app, session, 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', '198.51.100.16');
    expect(injected.statusCode).toBe(400);
    expect(foreign.statusCode).toBe(404);
    expect(absent.statusCode).toBe(404);
    const foreignBody = foreign.json() as { error: { code: string; message: string } };
    const absentBody = absent.json() as { error: { code: string; message: string } };
    expect(foreignBody.error.code).toBe(absentBody.error.code);
    expect(foreignBody.error.message).toBe(absentBody.error.message);
    expect(JSON.stringify(foreignBody)).not.toContain(ABSENT);
    expect(JSON.stringify(absentBody)).not.toContain('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa');
    expect(script.calls.map((call) => call.assetId)).toEqual([
      ABSENT,
      'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    ]);
    await app.close();
  });

  it('rejects a body, a bad limit, and a repeated query field', async () => {
    const script = scripted();
    const { app, session } = await boot('owner', { discovery: script.runtime });
    const body = await app.inject({
      method: 'GET',
      url: `/assets/${ASSET}/controlled-finding-targets`,
      remoteAddress: '198.51.100.17',
      headers: { cookie: session.cookie, 'content-length': '2' },
      payload: {},
    });
    const limit = await get(app, session, ASSET, '198.51.100.18', 'limit=21');
    const repeated = await get(app, session, ASSET, '198.51.100.19', 'limit=10&limit=10');
    expect(body.statusCode).toBe(400);
    expect(limit.statusCode).toBe(400);
    expect(repeated.statusCode).toBe(400);
    expect(script.calls).toEqual([]);
    const oversized = await app.inject({
      method: 'GET',
      url: `/assets/${ASSET}/controlled-finding-targets`,
      remoteAddress: '198.51.100.22',
      headers: { cookie: session.cookie, 'content-type': 'application/json' },
      payload: 'x'.repeat(DISCOVERY_REQUEST_BODY_LIMIT_BYTES + 32),
    });
    expect(oversized.statusCode).toBe(400);
    expect(oversized.headers['cache-control']).toBe('private, no-store');
    const oversizedBody = JSON.stringify(oversized.json());
    expect(oversizedBody).not.toContain(ASSET);
    expect(oversizedBody).not.toContain('FST_');
    expect(oversizedBody).not.toContain('syntax');
    expect(script.calls).toEqual([]);
    await app.close();
  });

  it('returns conflict for a stale cursor and internal failure without a partial page', async () => {
    const stale = scripted('stale_cursor');
    const staleBoot = await boot('owner', { discovery: stale.runtime });
    const conflict = await get(
      staleBoot.app,
      staleBoot.session,
      ASSET,
      '198.51.100.20',
      'cursor=bm90LWEgY3Vyc29y',
    );
    expect(conflict.statusCode).toBe(409);
    expect(JSON.stringify(conflict.json())).not.toContain(INGESTION);
    await staleBoot.app.close();

    const broken = scripted('malformed_persisted_state');
    const brokenBoot = await boot('owner', { discovery: broken.runtime });
    const failed = await get(brokenBoot.app, brokenBoot.session, ASSET, '198.51.100.21');
    expect(failed.statusCode).toBe(500);
    expect(JSON.stringify(failed.json())).not.toContain('candidates');
    expect(JSON.stringify(failed.json())).not.toContain(EVIDENCE);
    await brokenBoot.app.close();
  });

  it('rate limits peers before authentication and organizations after permission', async () => {
    const script = scripted();
    const limiter = createFindingOrganizationRateLimiter(FINDING_DISCOVERY_ORGANIZATION_LIMIT);
    const { app } = await boot('owner', {
      discovery: script.runtime,
      discoveryOrganizationLimiter: limiter,
    });
    const anonymous = await app.inject({
      method: 'GET',
      url: `/assets/${ASSET}/controlled-finding-targets`,
      remoteAddress: '198.51.100.30',
    });
    expect(anonymous.statusCode).toBe(401);
    let last = 0;
    for (let index = 0; index < FINDING_DISCOVERY_PEER_LIMIT.max; index += 1) {
      const response = await app.inject({
        method: 'GET',
        url: `/assets/${ASSET}/controlled-finding-targets`,
        remoteAddress: '198.51.100.31',
      });
      last = response.statusCode;
    }
    expect(last).toBe(401);
    const limited = await app.inject({
      method: 'GET',
      url: `/assets/${ASSET}/controlled-finding-targets`,
      remoteAddress: '198.51.100.31',
    });
    expect(limited.statusCode).toBe(429);
    expect(limited.headers['cache-control']).toBe('private, no-store');
    expect(JSON.stringify(limited.json())).not.toContain(ASSET);
    expect(limited.json()).toMatchObject({
      error: { code: 'rate_limited', message: 'Too many requests. Try again later.' },
    });
    await app.close();

    const memberScript = scripted();
    const shared = createFindingOrganizationRateLimiter(FINDING_DISCOVERY_ORGANIZATION_LIMIT);
    const member = await boot('member', {
      discovery: memberScript.runtime,
      discoveryOrganizationLimiter: shared,
    });
    for (let index = 0; index < 25; index += 1) {
      const response = await get(member.app, member.session, ASSET, `203.0.113.${index + 1}`);
      expect(response.statusCode).toBe(403);
    }
    await member.app.close();
    const ownerScript = scripted();
    const owner = await boot('owner', {
      discovery: ownerScript.runtime,
      discoveryOrganizationLimiter: shared,
    });
    for (let index = 0; index < FINDING_DISCOVERY_ORGANIZATION_LIMIT.max; index += 1) {
      const response = await get(owner.app, owner.session, ASSET, `203.0.113.${40 + index}`);
      expect(response.statusCode).toBe(200);
    }
    const over = await get(owner.app, owner.session, ASSET, '203.0.113.90');
    expect(over.statusCode).toBe(429);
    expect(memberScript.calls).toEqual([]);
    await owner.app.close();
  });

  it('fails closed when the organization limiter throws and does not charge anonymous callers', async () => {
    let consumes = 0;
    const limiter: FindingOrganizationRateLimiter = {
      consume() {
        consumes += 1;
        throw new Error('limiter down');
      },
    };
    const script = scripted();
    const { app, session } = await boot('owner', {
      discovery: script.runtime,
      discoveryOrganizationLimiter: limiter,
    });
    const anonymous = await app.inject({
      method: 'GET',
      url: `/assets/${ASSET}/controlled-finding-targets`,
      remoteAddress: '198.51.100.70',
    });
    expect(anonymous.statusCode).toBe(401);
    expect(consumes).toBe(0);
    const failed = await get(app, session, ASSET, '198.51.100.71');
    expect(failed.statusCode).toBe(503);
    expect(consumes).toBe(1);
    expect(script.calls).toEqual([]);
    const logs = JSON.stringify(failed.json());
    expect(logs).not.toContain(ASSET);
    expect(logs).not.toContain(EVIDENCE);
    await app.close();
  });

  it('omits protected identifiers from the discovery log', async () => {
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
      discovery: script.runtime,
    });
    const loggedIn = await built.app.inject({
      method: 'POST',
      url: '/auth/login',
      remoteAddress: LOGIN_IP,
      headers: { origin: TEST_ORIGIN, 'content-type': 'application/json' },
      payload: { email: harness.user.email, password: VALID_PASSWORD },
    });
    const session = sessionFrom(loggedIn, harness.config.auth.cookieName);
    await get(built.app, session, ASSET, '198.51.100.80');
    const discoveryLogs = logs.filter((line) => line.includes('controlled-finding-targets'));
    expect(discoveryLogs.length).toBeGreaterThan(0);
    for (const line of discoveryLogs) {
      expect(line).not.toContain(ASSET);
      expect(line).not.toContain(COMPONENT);
      expect(line).not.toContain(VULNERABILITY);
      expect(line).not.toContain(EVIDENCE);
      expect(line).not.toContain(INGESTION);
      expect(line).toContain('"/assets/:assetId/controlled-finding-targets"');
    }
    await built.app.close();
  });
});

async function boot(
  role: RoleName,
  options?: {
    discovery?: FindingDiscoveryRuntime;
    discoveryOrganizationLimiter?: FindingOrganizationRateLimiter;
  },
) {
  const harness = createAuthTestHarness({ primaryRole: role });
  const built = await buildTestApi({
    harness,
    ...(options?.discovery === undefined ? {} : { discovery: options.discovery }),
    ...(options?.discoveryOrganizationLimiter === undefined
      ? {}
      : { discoveryOrganizationLimiter: options.discoveryOrganizationLimiter }),
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
    harness,
    session: sessionFrom(loggedIn, harness.config.auth.cookieName),
  };
}

function get(
  app: FastifyInstance,
  session: { cookie: string },
  assetId: string,
  remoteAddress: string,
  query?: string,
) {
  return app.inject({
    method: 'GET',
    url: `/assets/${assetId}/controlled-finding-targets${query === undefined ? '' : `?${query}`}`,
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
