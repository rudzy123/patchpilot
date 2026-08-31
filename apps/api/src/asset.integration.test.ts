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
import type { AssetDetail, SessionResponse } from '@patchpilot/contracts';
import {
  createPrismaUnitOfWork,
  createRepositories,
  disconnectPrisma,
  getPrismaClient,
  resetPrismaClientForTests,
} from '@patchpilot/database';
import type { PersistenceUnitOfWork } from '@patchpilot/domain';
import { createLogger } from '@patchpilot/logger';
import { createFoundationTestEnv } from '@patchpilot/test-utils';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { buildApi } from './app.js';
import { createAssetRuntime, type AssetRuntime } from './asset-runtime.js';
import { TEST_ORIGIN, VALID_PASSWORD, emptySbomRuntime } from './auth-test-harness.js';

const SOCKET_IP = '192.0.2.10';

describe('asset inventory routes persistence', () => {
  const config = loadServerConfigFrom(createFoundationTestEnv());
  const logger = createLogger({
    service: 'api-asset-integration',
    level: 'silent',
    pretty: false,
  });
  const prisma = getPrismaClient({ databaseUrl: config.databaseUrl });
  const repos = createRepositories(prisma);
  const hasher = createArgon2PasswordHasher();
  const tokens = createNodeRandomTokenGenerator();
  const clock = createSystemClock();
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
  const unitOfWork = createPrismaUnitOfWork({ client: prisma });
  const assets = createAssetRuntime({
    assets: repos.assets,
    environments: repos.environments,
    teams: repos.teams,
    memberships: repos.memberships,
    unitOfWork,
    clock,
  });

  const email = `asset-it-${randomUUID()}@synthetic.patchpilot.test`;
  let homeOrgId: string;
  let foreignOrgId: string;
  let membershipId: string;
  let teamId: string;
  let environmentId: string;

  beforeAll(async () => {
    const passwordHash = await hasher.hash(
      VALID_PASSWORD,
      argon2ParametersFromAuthConfig(config.auth),
    );
    const user = await prisma.user.create({
      data: { email, displayName: 'Asset Integration Admin' },
    });
    await prisma.localCredential.create({
      data: { userId: user.id, passwordHash, passwordRevision: 1 },
    });
    const home = await prisma.organization.create({
      data: { slug: `asset-home-${randomUUID().slice(0, 8)}`, name: 'Asset Home' },
    });
    const foreign = await prisma.organization.create({
      data: { slug: `asset-foreign-${randomUUID().slice(0, 8)}`, name: 'Asset Foreign' },
    });
    homeOrgId = home.id;
    foreignOrgId = foreign.id;
    const membership = await prisma.membership.create({
      data: { organizationId: home.id, userId: user.id, role: 'admin', status: 'active' },
    });
    membershipId = membership.id;
    const team = await prisma.team.create({
      data: {
        organizationId: home.id,
        name: 'Platform',
        slug: `platform-${randomUUID().slice(0, 8)}`,
      },
    });
    teamId = team.id;
    const environment = await prisma.environment.create({
      data: {
        organizationId: home.id,
        name: 'production',
        slug: `production-${randomUUID().slice(0, 8)}`,
        sensitivityClass: 'production',
      },
    });
    environmentId = environment.id;
  });

  afterAll(async () => {
    await disconnectPrisma();
    resetPrismaClientForTests();
  });

  it('creates, updates collections, archives, and isolates tenants against PostgreSQL', async () => {
    const app = await buildApp(assets);
    const session = await login(app);

    const created = await mutate(app, session, 'POST', '/assets', {
      name: `Payments ${randomUUID().slice(0, 8)}`,
      assetType: 'application',
      environmentId,
      owningTeamId: teamId,
      description: 'Primary payments service',
      owners: [{ kind: 'membership', membershipId, role: 'technical' }],
      tags: ['core', 'payments'],
      externalIdentifiers: [{ namespace: 'cmdb', identifier: 'PAY-1' }],
    });
    expect(created.statusCode).toBe(201);
    const createdBody = created.json() as AssetDetail;
    expect(createdBody.owners).toHaveLength(1);
    expect(createdBody.tags).toEqual(['core', 'payments']);
    expect(createdBody.externalIdentifiers).toEqual([{ namespace: 'cmdb', identifier: 'PAY-1' }]);
    expect(createdBody).not.toHaveProperty('organizationId');
    expect(createdBody.owners[0]).not.toHaveProperty('userId');

    const persisted = await prisma.asset.findFirst({
      where: { id: createdBody.id, organizationId: homeOrgId },
    });
    expect(persisted?.name).toBe(createdBody.name);
    const createdAudits = await prisma.auditEvent.findMany({
      where: { organizationId: homeOrgId, subjectId: createdBody.id, action: 'asset.created' },
    });
    expect(createdAudits).toHaveLength(1);
    expect(JSON.stringify(createdAudits)).not.toContain(VALID_PASSWORD);
    expect(JSON.stringify(createdAudits)).not.toContain(session.csrf);

    const replaced = await mutate(app, session, 'PATCH', `/assets/${createdBody.id}`, {
      expectedVersion: createdBody.version,
      tags: ['platform'],
      owners: [{ kind: 'team', teamId, role: 'business' }],
      externalIdentifiers: [{ namespace: 'servicenow', identifier: 'INC-9' }],
    });
    expect(replaced.statusCode).toBe(200);
    const replacedBody = replaced.json() as AssetDetail;
    expect(replacedBody.tags).toEqual(['platform']);
    expect(replacedBody.owners).toEqual([
      {
        kind: 'team',
        id: replacedBody.owners[0]?.id,
        teamId,
        name: 'Platform',
        role: 'business',
      },
    ]);
    expect(replacedBody.externalIdentifiers).toEqual([
      { namespace: 'servicenow', identifier: 'INC-9' },
    ]);

    const cleared = await mutate(app, session, 'PATCH', `/assets/${createdBody.id}`, {
      expectedVersion: replacedBody.version,
      tags: [],
      owners: [],
      externalIdentifiers: [],
    });
    expect(cleared.statusCode).toBe(200);
    const clearedBody = cleared.json() as AssetDetail;
    expect(clearedBody.tags).toEqual([]);
    expect(clearedBody.owners).toEqual([]);
    expect(clearedBody.externalIdentifiers).toEqual([]);

    const archived = await mutate(app, session, 'POST', `/assets/${createdBody.id}/archive`, {
      expectedVersion: clearedBody.version,
    });
    expect(archived.statusCode).toBe(200);
    expect((archived.json() as AssetDetail).lifecycleStatus).toBe('archived');
    const archiveAudits = await prisma.auditEvent.findMany({
      where: { organizationId: homeOrgId, subjectId: createdBody.id, action: 'asset.archived' },
    });
    expect(archiveAudits).toHaveLength(1);

    const foreign = await repos.assets.createAggregate(foreignOrgId, {
      name: `Foreign ${randomUUID().slice(0, 8)}`,
      assetType: 'service',
      businessCriticality: 'unspecified',
      internetExposure: 'unknown',
      dataClassification: 'unspecified',
      owners: [],
      tags: [],
      externalIdentifiers: [],
    });
    expect(foreign.ok).toBe(true);
    if (!foreign.ok) {
      await app.close();
      return;
    }

    const foreignRead = await app.inject({
      method: 'GET',
      url: `/assets/${foreign.value.id}`,
      headers: { cookie: session.cookie },
    });
    const foreignUpdate = await mutate(app, session, 'PATCH', `/assets/${foreign.value.id}`, {
      expectedVersion: 1,
      name: 'Stolen',
    });
    const foreignArchive = await mutate(
      app,
      session,
      'POST',
      `/assets/${foreign.value.id}/archive`,
      { expectedVersion: 1 },
    );
    expect(foreignRead.statusCode).toBe(404);
    expect(foreignUpdate.statusCode).toBe(404);
    expect(foreignArchive.statusCode).toBe(404);
    expect(foreignRead.json().error.message).toBe('Asset not found.');
    const untouched = await prisma.asset.findFirst({
      where: { id: foreign.value.id, organizationId: foreignOrgId },
    });
    expect(untouched?.name).toBe(foreign.value.name);
    await app.close();
  });

  it('rolls back the Asset write when audit append fails', async () => {
    const failingUnitOfWork: PersistenceUnitOfWork = {
      async runInTransaction(work) {
        return unitOfWork.runInTransaction(async (txRepos) =>
          work({
            ...txRepos,
            auditEvents: {
              findById: (organizationId, id) => txRepos.auditEvents.findById(organizationId, id),
              listForOrganization: (organizationId, page) =>
                txRepos.auditEvents.listForOrganization(organizationId, page),
              async append() {
                throw new Error('audit append failed');
              },
            },
          }),
        );
      },
    };
    const app = await buildApp(
      createAssetRuntime({
        assets: repos.assets,
        environments: repos.environments,
        teams: repos.teams,
        memberships: repos.memberships,
        unitOfWork: failingUnitOfWork,
        clock,
      }),
    );
    const session = await login(app);
    const name = `Rollback ${randomUUID().slice(0, 8)}`;
    const created = await mutate(app, session, 'POST', '/assets', {
      name,
      assetType: 'application',
    });
    expect(created.statusCode).toBe(500);
    const leftover = await prisma.asset.findFirst({
      where: { organizationId: homeOrgId, name },
    });
    expect(leftover).toBeNull();
    await app.close();
  });

  async function buildApp(runtime: AssetRuntime) {
    return buildApi({
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
      assets: runtime,
      sboms: emptySbomRuntime(),
    });
  }

  async function login(app: Awaited<ReturnType<typeof buildApp>>) {
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
    const setCookie = headerSetCookie(loggedIn);
    const cookieName = config.auth.cookieName;
    return {
      cookie: `${cookieName}=${cookiePair(setCookie, cookieName)}`,
      csrf: (loggedIn.json() as SessionResponse).csrfToken,
    };
  }

  async function mutate(
    app: Awaited<ReturnType<typeof buildApp>>,
    session: { cookie: string; csrf: string },
    method: 'POST' | 'PATCH',
    url: string,
    payload: Record<string, unknown>,
  ) {
    return app.inject({
      method,
      url,
      remoteAddress: SOCKET_IP,
      headers: {
        origin: TEST_ORIGIN,
        'content-type': 'application/json',
        cookie: session.cookie,
        'x-csrf-token': session.csrf,
      },
      payload,
    });
  }
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
