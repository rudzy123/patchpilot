import { randomUUID } from 'node:crypto';

import {
  argon2ParametersFromAuthConfig,
  createArgon2PasswordHasher,
  createFakeLoginRateLimiter,
  createListActiveOrganizationsUseCase,
  createLoginUseCase,
  createLogoutUseCase,
  createNodeRandomTokenGenerator,
  createReadSessionUseCase,
  createResolveSessionUseCase,
  createSelectOrganizationUseCase,
  createSystemClock,
} from '@patchpilot/auth';
import { loadServerConfigFrom } from '@patchpilot/config';
import type { SessionResponse } from '@patchpilot/contracts';
import {
  createPrismaUnitOfWork,
  createRepositories,
  disconnectPrisma,
  getPrismaClient,
  resetPrismaClientForTests,
} from '@patchpilot/database';
import { createLogger } from '@patchpilot/logger';
import { createFoundationTestEnv } from '@patchpilot/test-utils';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { buildApi } from './app.js';
import { createAssetRuntime } from './asset-runtime.js';
import { TEST_ORIGIN, VALID_PASSWORD } from './auth-test-harness.js';

const SOCKET_IP = '192.0.2.10';

describe('authentication routes persistence', () => {
  const config = loadServerConfigFrom(createFoundationTestEnv());
  const logger = createLogger({
    service: 'api-auth-integration',
    level: 'silent',
    pretty: false,
  });
  const prisma = getPrismaClient({ databaseUrl: config.databaseUrl });
  const repos = createRepositories(prisma);
  const hasher = createArgon2PasswordHasher();
  const tokens = createNodeRandomTokenGenerator();
  const clock = createSystemClock();
  const assets = createAssetRuntime({
    assets: repos.assets,
    environments: repos.environments,
    teams: repos.teams,
    memberships: repos.memberships,
    unitOfWork: createPrismaUnitOfWork({ client: prisma }),
    clock,
  });
  const limiter = createFakeLoginRateLimiter({
    auth: config.auth,
    logger,
    clock,
  });
  const shared = {
    users: repos.users,
    localCredentials: repos.localCredentials,
    sessions: repos.sessions,
    memberships: repos.memberships,
    clock,
    auth: config.auth,
    logger,
  };

  const email = `auth-it-${randomUUID()}@synthetic.patchpilot.test`;
  const displayName = 'Auth Integration User';
  let userId: string;
  let homeOrgId: string;
  let foreignOrgId: string;

  beforeAll(async () => {
    const passwordHash = await hasher.hash(
      VALID_PASSWORD,
      argon2ParametersFromAuthConfig(config.auth),
    );
    const user = await prisma.user.create({
      data: { email, displayName },
    });
    userId = user.id;
    await prisma.localCredential.create({
      data: { userId: user.id, passwordHash, passwordRevision: 1 },
    });
    const home = await prisma.organization.create({
      data: { slug: `home-${randomUUID().slice(0, 8)}`, name: 'Home Org' },
    });
    const foreign = await prisma.organization.create({
      data: { slug: `foreign-${randomUUID().slice(0, 8)}`, name: 'Foreign Org' },
    });
    homeOrgId = home.id;
    foreignOrgId = foreign.id;
    await prisma.membership.create({
      data: { organizationId: home.id, userId: user.id, role: 'owner', status: 'active' },
    });
  });

  afterAll(async () => {
    await disconnectPrisma();
    resetPrismaClientForTests();
  });

  it('persists login, audit, rotation, tenancy, and CSRF against PostgreSQL', async () => {
    const app = await buildApi({
      config,
      logger,
      checkDatabaseReady: async () => ({ ok: true }),
      auth: {
        login: createLoginUseCase({
          ...shared,
          hasher,
          tokens,
          limiter,
        }),
        logout: createLogoutUseCase({
          sessions: repos.sessions,
          clock,
          logger,
        }),
        resolveSession: createResolveSessionUseCase(shared),
        readSession: createReadSessionUseCase({
          ...shared,
          tokens,
        }),
        selectOrganization: createSelectOrganizationUseCase({
          ...shared,
          tokens,
        }),
        listOrganizations: createListActiveOrganizationsUseCase(shared),
        audit: repos.auditEvents,
      },
      assets,
    });

    const loggedIn = await app.inject({
      method: 'POST',
      url: '/auth/login',
      remoteAddress: SOCKET_IP,
      headers: {
        origin: TEST_ORIGIN,
        'content-type': 'application/json',
      },
      payload: { email, password: VALID_PASSWORD },
    });
    expect(loggedIn.statusCode).toBe(200);
    const loginBody = loggedIn.json() as SessionResponse;
    expect(loginBody.user.id).toBe(userId);
    expect(loginBody.organization?.id).toBe(homeOrgId);
    const cookieName = config.auth.cookieName;
    const setCookie = headerSetCookie(loggedIn);
    expect(setCookie).toMatch(/HttpOnly/i);
    expect(setCookie).toMatch(/Path=\//);
    expect(setCookie).not.toMatch(/Domain=/i);
    const sessionToken = cookiePair(setCookie, cookieName);

    const audits = await prisma.auditEvent.findMany({
      where: { actorUserId: userId, action: 'auth.login_succeeded' },
    });
    expect(audits.length).toBeGreaterThan(0);
    const serialized = JSON.stringify(audits);
    expect(serialized).not.toContain(VALID_PASSWORD);
    expect(serialized).not.toContain(email);
    expect(serialized).not.toContain(loginBody.csrfToken);
    expect(serialized).not.toContain(sessionToken);
    expect(serialized.toLowerCase()).not.toContain('$argon2id$');

    const listed = await app.inject({
      method: 'GET',
      url: '/auth/organizations',
      headers: { cookie: `${cookieName}=${sessionToken}` },
    });
    expect(listed.json()).toMatchObject({
      organizations: [{ id: homeOrgId, role: 'owner' }],
    });
    expect(
      (listed.json() as { organizations: Array<{ id: string }> }).organizations.some(
        (organization) => organization.id === foreignOrgId,
      ),
    ).toBe(false);

    const foreign = await app.inject({
      method: 'POST',
      url: '/auth/select-organization',
      headers: {
        origin: TEST_ORIGIN,
        'content-type': 'application/json',
        cookie: `${cookieName}=${sessionToken}`,
        'x-csrf-token': loginBody.csrfToken,
      },
      payload: { organizationId: foreignOrgId },
    });
    expect(foreign.statusCode).toBe(404);

    const selectedHome = await app.inject({
      method: 'POST',
      url: '/auth/select-organization',
      headers: {
        origin: TEST_ORIGIN,
        'content-type': 'application/json',
        cookie: `${cookieName}=${sessionToken}`,
        'x-csrf-token': loginBody.csrfToken,
      },
      payload: { organizationId: homeOrgId },
    });
    expect(selectedHome.statusCode).toBe(200);
    const rotated = selectedHome.json() as SessionResponse;
    expect(rotated.csrfToken).not.toBe(loginBody.csrfToken);
    const rotatedToken = cookiePair(headerSetCookie(selectedHome), cookieName);
    expect(rotatedToken).not.toBe(sessionToken);

    const stale = await app.inject({
      method: 'GET',
      url: '/auth/session',
      headers: { cookie: `${cookieName}=${sessionToken}` },
    });
    expect(stale.statusCode).toBe(401);

    const session = await app.inject({
      method: 'GET',
      url: '/auth/session',
      headers: { cookie: `${cookieName}=${rotatedToken}` },
    });
    expect(session.statusCode).toBe(200);
    expect(session.headers['cache-control']).toBe('no-store');
    const sessionCsrf = (session.json() as SessionResponse).csrfToken;

    const loggedOut = await app.inject({
      method: 'POST',
      url: '/auth/logout',
      headers: {
        origin: TEST_ORIGIN,
        'content-type': 'application/json',
        cookie: `${cookieName}=${rotatedToken}`,
        'x-csrf-token': sessionCsrf,
      },
      payload: {},
    });
    expect(loggedOut.statusCode).toBe(204);

    const afterLogout = await app.inject({
      method: 'GET',
      url: '/auth/session',
      headers: { cookie: `${cookieName}=${rotatedToken}` },
    });
    expect(afterLogout.statusCode).toBe(401);
    await app.close();
  });

  it('returns the same unavailable envelope when the limiter cannot decide', async () => {
    const closedLimiter = createFakeLoginRateLimiter({
      auth: config.auth,
      logger,
      clock,
      unavailable: true,
    });
    const app = await buildApi({
      config,
      logger,
      checkDatabaseReady: async () => ({ ok: true }),
      auth: {
        login: createLoginUseCase({
          ...shared,
          hasher,
          tokens,
          limiter: closedLimiter,
        }),
        logout: createLogoutUseCase({
          sessions: repos.sessions,
          clock,
          logger,
        }),
        resolveSession: createResolveSessionUseCase(shared),
        readSession: createReadSessionUseCase({
          ...shared,
          tokens,
        }),
        selectOrganization: createSelectOrganizationUseCase({
          ...shared,
          tokens,
        }),
        listOrganizations: createListActiveOrganizationsUseCase(shared),
        audit: repos.auditEvents,
      },
      assets,
    });
    const known = await app.inject({
      method: 'POST',
      url: '/auth/login',
      remoteAddress: SOCKET_IP,
      headers: {
        origin: TEST_ORIGIN,
        'content-type': 'application/json',
      },
      payload: { email, password: VALID_PASSWORD },
    });
    const unknown = await app.inject({
      method: 'POST',
      url: '/auth/login',
      remoteAddress: SOCKET_IP,
      headers: {
        origin: TEST_ORIGIN,
        'content-type': 'application/json',
      },
      payload: {
        email: `missing-${randomUUID()}@synthetic.patchpilot.test`,
        password: VALID_PASSWORD,
      },
    });
    expect(known.statusCode).toBe(503);
    expect(unknown.statusCode).toBe(503);
    expect(known.json().error.message).toBe(unknown.json().error.message);
    await app.close();
  });
});

function headerSetCookie(response: { headers: { [key: string]: unknown } }): string {
  const header = response.headers['set-cookie'];
  if (typeof header === 'string') {
    return header;
  }
  if (Array.isArray(header) && typeof header[0] === 'string') {
    return header[0];
  }
  throw new Error('expected Set-Cookie');
}

function cookiePair(setCookie: string, name: string): string {
  const prefix = `${name}=`;
  const part = setCookie.split(';', 1)[0];
  if (part === undefined || !part.startsWith(prefix)) {
    throw new Error('cookie name mismatch');
  }
  return part.slice(prefix.length);
}
