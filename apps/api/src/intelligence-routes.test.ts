import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { ok } from '@patchpilot/domain';
import {
  intelligenceProviderListResponseSchema,
  intelligenceProviderStatusSchema,
  type IntelligenceProviderListResponse,
  type IntelligenceProviderStatus,
  type SessionResponse,
} from '@patchpilot/contracts';
import { describe, expect, it } from 'vitest';

import {
  TEST_ORIGIN,
  VALID_PASSWORD,
  buildTestApi,
  createAuthTestHarness,
} from './auth-test-harness.js';
import { createIntelligenceRuntime } from './intelligence-runtime.js';
import type {
  IntelligenceProviderStatusReadPort,
  IntelligenceStatusReadResult,
} from '@patchpilot/domain';

const SOCKET_IP = '192.0.2.10';
const NOW = new Date('2026-09-02T12:00:00.000Z');
const SUCCESS_AT = new Date('2026-08-31T16:00:00.000Z');
const GENERATION_ID = '11111111-1111-4111-8111-111111111111';
const CSRF_HEADER = 'x-csrf-token';

function foundSnapshot(): IntelligenceStatusReadResult {
  return {
    kind: 'found',
    snapshot: {
      sourceState: 'enabled',
      lastSuccessfulSyncAt: SUCCESS_AT,
      lastAttemptAt: SUCCESS_AT,
      lastFailureAt: null,
      lastFailureCode: null,
      activeGenerationId: GENERATION_ID,
      generation: {
        state: 'active',
        catalogVersion: '2026.08.31',
        catalogReleasedAt: SUCCESS_AT,
        expectedEntryCount: 1687,
      },
    },
  };
}

function statusPort(
  result: IntelligenceStatusReadResult | (() => Promise<IntelligenceStatusReadResult>),
): IntelligenceProviderStatusReadPort & { calls: number } {
  const port = {
    calls: 0,
    async loadCisaKevStatus() {
      port.calls += 1;
      return typeof result === 'function' ? result() : result;
    },
  };
  return port;
}

describe('intelligence provider status routes', () => {
  it('returns the sanitized provider list and CISA/OSV detail', async () => {
    const status = statusPort(foundSnapshot());
    const { app, session } = await boot({ status });
    const listed = await get(app, session, '/intelligence/providers');
    const kev = await get(app, session, '/intelligence/providers/cisa_kev/status');
    const osv = await get(app, session, '/intelligence/providers/osv/status');
    expect(listed.statusCode).toBe(200);
    expect(kev.statusCode).toBe(200);
    expect(osv.statusCode).toBe(200);
    expect(listed.headers['cache-control']).toBe('private, no-store');
    expect(listed.headers['etag']).toBeUndefined();
    expect(listed.headers['last-modified']).toBeUndefined();
    const listBody = intelligenceProviderListResponseSchema.parse(
      listed.json() as IntelligenceProviderListResponse,
    );
    expect(listBody.providers.map((item) => item.provider)).toEqual(['cisa_kev', 'osv']);
    expect(
      intelligenceProviderStatusSchema.parse(kev.json() as IntelligenceProviderStatus).healthStatus,
    ).toBe('current');
    expect(
      intelligenceProviderStatusSchema.parse(osv.json() as IntelligenceProviderStatus),
    ).toMatchObject({
      provider: 'osv',
      healthStatus: 'deferred',
      lastAttemptAt: null,
      lastSafeFailureCode: null,
    });
    expect(JSON.stringify(listBody)).not.toContain(GENERATION_ID);
    expect(JSON.stringify(listBody)).not.toContain('organizationId');
    expect(status.calls).toBe(2);
    await app.close();
  });

  it('returns 404 for unknown, mixed-case, reserved, alias, and extra provider paths', async () => {
    const { app, session } = await boot({ status: statusPort(foundSnapshot()) });
    for (const url of [
      '/intelligence/providers/nvd/status',
      '/intelligence/providers/CISA_KEV/status',
      '/intelligence/providers/reserved/status',
      '/intelligence/providers/cisa/status',
      '/intelligence/providers/kev/status',
      '/intelligence/providers/github/status',
      '/intelligence/providers/cisa_kev/status/extra',
      `/intelligence/providers/${encodeURIComponent('cisa_kév')}/status`,
    ]) {
      const response = await get(app, session, url);
      expect(response.statusCode, url).toBe(404);
      expect(response.headers['cache-control']).toBe('private, no-store');
      expectEnvelope(response, 'not_found', 'Not found.');
    }
    await app.close();
  });

  it('rejects a GET body, does not require Origin or CSRF, and keeps trustProxy disabled', async () => {
    const { app, session } = await boot({ status: statusPort(foundSnapshot()) });
    const withBody = await app.inject({
      method: 'GET',
      url: '/intelligence/providers',
      remoteAddress: SOCKET_IP,
      headers: {
        cookie: session.cookie,
        'content-type': 'application/json',
        'content-length': '2',
      },
      payload: '{}',
    });
    expect(withBody.statusCode).toBe(400);
    expect(withBody.headers['cache-control']).toBe('private, no-store');
    expectEnvelope(withBody, 'validation', 'Invalid request.');

    const withTransfer = await app.inject({
      method: 'GET',
      url: '/intelligence/providers',
      remoteAddress: SOCKET_IP,
      headers: {
        cookie: session.cookie,
        'transfer-encoding': 'chunked',
      },
    });
    expect(withTransfer.statusCode).toBe(400);
    expect(withTransfer.headers['cache-control']).toBe('private, no-store');
    expectEnvelope(withTransfer, 'validation', 'Invalid request.');

    const withoutOrigin = await app.inject({
      method: 'GET',
      url: '/intelligence/providers',
      remoteAddress: SOCKET_IP,
      headers: { cookie: session.cookie },
    });
    expect(withoutOrigin.statusCode).toBe(200);
    await app.close();
  });

  it('requires a session, active Organization, and intelligence:read', async () => {
    const status = statusPort(foundSnapshot());
    const unauthenticated = await boot({ status, membershipCount: 1 });
    const missingSession = await unauthenticated.app.inject({
      method: 'GET',
      url: '/intelligence/providers',
    });
    expect(missingSession.statusCode).toBe(401);
    expect(missingSession.headers['cache-control']).toBe('private, no-store');
    expectEnvelope(missingSession, 'unauthorized', 'Authentication required.');
    const unknownWithoutSession = await unauthenticated.app.inject({
      method: 'GET',
      url: '/intelligence/providers/nvd/status',
    });
    expect(unknownWithoutSession.statusCode).toBe(401);
    expectEnvelope(unknownWithoutSession, 'unauthorized', 'Authentication required.');
    await unauthenticated.app.close();

    const twoOrgs = await boot({ status, membershipCount: 2, selectOrganization: false });
    const missingOrg = await get(twoOrgs.app, twoOrgs.session, '/intelligence/providers');
    expect(missingOrg.statusCode).toBe(403);
    expect(missingOrg.headers['cache-control']).toBe('private, no-store');
    expectEnvelope(missingOrg, 'forbidden', 'Organization context is required.');
    await twoOrgs.app.close();

    const denied = await bootDeniedPermissions(status);
    const forbidden = await get(denied.app, denied.session, '/intelligence/providers');
    expect(forbidden.statusCode).toBe(403);
    expectEnvelope(forbidden, 'forbidden', 'Permission denied.');
    await denied.app.close();
  });

  it('allows viewer, member, admin, and owner and returns the same payload across organizations', async () => {
    const status = statusPort(foundSnapshot());
    for (const role of ['viewer', 'member', 'admin', 'owner'] as const) {
      const { app, session } = await boot({ status, role });
      const response = await get(app, session, '/intelligence/providers/cisa_kev/status');
      expect(response.statusCode, role).toBe(200);
      await app.close();
    }

    const dual = await boot({ status, membershipCount: 2, selectOrganization: true });
    const first = await get(dual.app, dual.session, '/intelligence/providers');
    const secondOrg = dual.harness.organizations[1];
    if (secondOrg === undefined) {
      throw new Error('expected second organization');
    }
    const selected = await dual.app.inject({
      method: 'POST',
      url: '/auth/select-organization',
      remoteAddress: SOCKET_IP,
      headers: {
        origin: TEST_ORIGIN,
        'content-type': 'application/json',
        cookie: dual.session.cookie,
        [CSRF_HEADER]: dual.session.csrf,
      },
      payload: { organizationId: secondOrg.id },
    });
    expect(selected.statusCode).toBe(200);
    const nextSession = sessionFrom(selected, dual.harness.config.auth.cookieName);
    const second = await get(dual.app, nextSession, '/intelligence/providers');
    expect(first.json()).toEqual(second.json());
    expect(JSON.stringify(first.json())).not.toContain(dual.harness.organizations[0]?.id);
    expect(JSON.stringify(second.json())).not.toContain(secondOrg.id);
    await dual.app.close();
  });

  it('maps missing source and database failure to 503 and pointer inconsistency to 500', async () => {
    const missing = await boot({ status: statusPort({ kind: 'missing_source' }) });
    const unavailable = await boot({
      status: statusPort(async () => {
        throw new Error('database down');
      }),
    });
    const inconsistent = await boot({ status: statusPort({ kind: 'inconsistent' }) });
    const missingResponse = await get(missing.app, missing.session, '/intelligence/providers');
    const unavailableResponse = await get(
      unavailable.app,
      unavailable.session,
      '/intelligence/providers/cisa_kev/status',
    );
    const inconsistentResponse = await get(
      inconsistent.app,
      inconsistent.session,
      '/intelligence/providers/cisa_kev/status',
    );
    expect(missingResponse.statusCode).toBe(503);
    expect(missingResponse.headers['cache-control']).toBe('private, no-store');
    expectEnvelope(missingResponse, 'internal', 'Intelligence status is temporarily unavailable.');
    expect(unavailableResponse.statusCode).toBe(503);
    expect(unavailableResponse.headers['cache-control']).toBe('private, no-store');
    expectEnvelope(
      unavailableResponse,
      'internal',
      'Intelligence status is temporarily unavailable.',
    );
    expect(inconsistentResponse.statusCode).toBe(500);
    expect(inconsistentResponse.headers['cache-control']).toBe('private, no-store');
    expectEnvelope(inconsistentResponse, 'internal', 'An internal error occurred.');
    await missing.app.close();
    await unavailable.app.close();
    await inconsistent.app.close();
  });

  it('does not require mutation CSRF, does not write audit, and does not start intelligence runtimes', async () => {
    const status = statusPort(foundSnapshot());
    const { app, session, harness } = await boot({ status });
    const before = harness.audit.events.length;
    const response = await get(app, session, '/intelligence/providers/osv/status');
    expect(response.statusCode).toBe(200);
    expect(harness.audit.events).toHaveLength(before);
    expect(status.calls).toBe(0);
    const sourceDir = path.dirname(fileURLToPath(import.meta.url));
    expect(readFileSync(path.join(sourceDir, 'app.ts'), 'utf8')).toContain('trustProxy: false');
    for (const fileName of [
      'intelligence-routes.ts',
      'intelligence-runtime.ts',
      'intelligence-views.ts',
    ]) {
      const source = readFileSync(path.join(sourceDir, fileName), 'utf8');
      expect(source).not.toMatch(
        /ioredis|bullmq|@aws-sdk|S3Client|undici|\bfetch\s*\(|https\.request/,
      );
      expect(source).not.toContain('createCisaKevSynchronizationService');
      expect(source).not.toContain('FindingRepository');
      expect(source).not.toMatch(/rateLimit|rate-limit/);
    }
    await app.close();
  });

  it('rejects expired sessions and inactive users with unauthorized', async () => {
    const status = statusPort(foundSnapshot());
    const expired = await boot({ status });
    for (const record of expired.harness.sessions.byTokenHash.values()) {
      record.idleExpiresAt = new Date(0);
    }
    const expiredResponse = await get(expired.app, expired.session, '/intelligence/providers');
    expect(expiredResponse.statusCode).toBe(401);
    expect(expiredResponse.headers['cache-control']).toBe('private, no-store');
    await expired.app.close();

    const revoked = await boot({ status });
    for (const record of revoked.harness.sessions.byTokenHash.values()) {
      record.revokedAt = new Date(NOW.getTime() - 1_000);
    }
    const revokedResponse = await get(revoked.app, revoked.session, '/intelligence/providers');
    expect(revokedResponse.statusCode).toBe(401);
    expectEnvelope(revokedResponse, 'unauthorized', 'Authentication required.');
    await revoked.app.close();

    const inactive = await boot({ status });
    const user = inactive.harness.users.users.get(inactive.harness.user.id);
    if (user === undefined) {
      throw new Error('expected user');
    }
    user.status = 'disabled';
    const inactiveResponse = await get(inactive.app, inactive.session, '/intelligence/providers');
    expect(inactiveResponse.statusCode).toBe(401);
    await inactive.app.close();
  });

  it('rejects disabled membership and inactive Organization with organization context required', async () => {
    const status = statusPort(foundSnapshot());
    const disabledMembership = await boot({ status });
    const membershipRow = disabledMembership.harness.memberships.rows[0];
    if (membershipRow === undefined) {
      throw new Error('expected membership');
    }
    membershipRow.membership.status = 'revoked';
    const disabledResponse = await get(
      disabledMembership.app,
      disabledMembership.session,
      '/intelligence/providers',
    );
    expect(disabledResponse.statusCode).toBe(403);
    expectEnvelope(disabledResponse, 'forbidden', 'Organization context is required.');
    await disabledMembership.app.close();

    const inactiveOrg = await boot({ status });
    const orgRow = inactiveOrg.harness.memberships.rows[0];
    if (orgRow === undefined) {
      throw new Error('expected organization');
    }
    orgRow.organization.status = 'archived';
    const archived = await get(inactiveOrg.app, inactiveOrg.session, '/intelligence/providers');
    expect(archived.statusCode).toBe(403);
    await inactiveOrg.app.close();
  });
});

async function boot(options: {
  status: IntelligenceProviderStatusReadPort;
  role?: 'viewer' | 'member' | 'admin' | 'owner';
  membershipCount?: 1 | 2;
  selectOrganization?: boolean;
}) {
  const membershipCount = options.membershipCount ?? 1;
  const harness = createAuthTestHarness({
    membershipCount,
    primaryRole: options.role ?? 'owner',
  });
  const intelligence = createIntelligenceRuntime({
    status: options.status,
    kevEnabled: true,
    staleThresholdSeconds: harness.config.intelligence.kevStaleThresholdSeconds,
    now: () => NOW,
  });
  const { app } = await buildTestApi({ harness, intelligence });
  const loggedIn = await login(app, harness.user.email);
  let session = sessionFrom(loggedIn, harness.config.auth.cookieName);
  if (membershipCount === 2 && options.selectOrganization !== false) {
    const organizationId = harness.organizations[0]?.id;
    if (organizationId === undefined) {
      throw new Error('expected home organization');
    }
    const selected = await app.inject({
      method: 'POST',
      url: '/auth/select-organization',
      remoteAddress: SOCKET_IP,
      headers: {
        origin: TEST_ORIGIN,
        'content-type': 'application/json',
        cookie: session.cookie,
        [CSRF_HEADER]: session.csrf,
      },
      payload: { organizationId },
    });
    session = sessionFrom(selected, harness.config.auth.cookieName);
  }
  return { app, harness, session };
}

async function bootDeniedPermissions(status: IntelligenceProviderStatusReadPort) {
  const harness = createAuthTestHarness({ membershipCount: 1, primaryRole: 'owner' });
  const original = harness.auth.resolveSession;
  harness.auth.resolveSession = {
    execute: async (input) => {
      const resolved = await original.execute(input);
      if (!resolved.ok) {
        return resolved;
      }
      return ok({
        ...resolved.value,
        actor: {
          ...resolved.value.actor,
          permissions: ['finding:read', 'sbom:read', 'integration:read'],
        },
      });
    },
  };
  const intelligence = createIntelligenceRuntime({
    status,
    kevEnabled: true,
    staleThresholdSeconds: harness.config.intelligence.kevStaleThresholdSeconds,
    now: () => NOW,
  });
  const { app } = await buildTestApi({ harness, intelligence });
  const loggedIn = await login(app, harness.user.email);
  return { app, harness, session: sessionFrom(loggedIn, harness.config.auth.cookieName) };
}

async function login(app: Awaited<ReturnType<typeof buildTestApi>>['app'], email: string) {
  return app.inject({
    method: 'POST',
    url: '/auth/login',
    remoteAddress: SOCKET_IP,
    headers: {
      origin: TEST_ORIGIN,
      'content-type': 'application/json',
    },
    payload: { email, password: VALID_PASSWORD },
  });
}

function sessionFrom(
  response: Awaited<ReturnType<typeof login>>,
  cookieName: string,
): { cookie: string; csrf: string } {
  const setCookie = firstSetCookie(response);
  const prefix = `${cookieName}=`;
  const part = setCookie.split(';', 1)[0];
  if (part === undefined || !part.startsWith(prefix)) {
    throw new Error('cookie name mismatch');
  }
  return {
    cookie: `${cookieName}=${part.slice(prefix.length)}`,
    csrf: (response.json() as SessionResponse).csrfToken,
  };
}

function firstSetCookie(response: { headers: { [key: string]: unknown } }): string {
  const header = response.headers['set-cookie'];
  if (typeof header === 'string') {
    return header;
  }
  if (Array.isArray(header) && typeof header[0] === 'string') {
    return header[0];
  }
  throw new Error('expected Set-Cookie');
}

async function get(
  app: Awaited<ReturnType<typeof buildTestApi>>['app'],
  session: { cookie: string },
  url: string,
) {
  return app.inject({
    method: 'GET',
    url,
    remoteAddress: SOCKET_IP,
    headers: { cookie: session.cookie },
  });
}

function expectEnvelope(response: { json: () => unknown }, code: string, message: string): void {
  expect(response.json()).toMatchObject({
    error: { code, message },
  });
}
