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
import { readDisposableIntegrationDatabaseUrl } from '@patchpilot/config/integration-test';
import type { SessionResponse } from '@patchpilot/contracts';
import {
  createRepositories,
  disconnectPrisma,
  getPrismaClient,
  resetPrismaClientForTests,
} from '@patchpilot/database';
import { createLogger } from '@patchpilot/logger';
import { createIntegrationDatabaseTestEnv } from '@patchpilot/test-utils';
import type { FastifyInstance } from 'fastify';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { buildApi } from './app.js';
import {
  emptyAssetRuntime,
  emptyIntelligenceRuntime,
  emptySbomRuntime,
  TEST_ORIGIN,
  VALID_PASSWORD,
} from './auth-test-harness.js';
import { composeControlledFindingOperatorRuntime } from './finding-runtime.js';
import { seedControlledFindingEvidence } from '../../../packages/database/src/controlled-finding-operator-seed-fixture.js';

type RoleName = 'owner' | 'admin' | 'member' | 'viewer';
type Session = { cookie: string; csrf: string };

describe('controlled finding operator persistence', () => {
  const config = loadServerConfigFrom(
    createIntegrationDatabaseTestEnv(readDisposableIntegrationDatabaseUrl()),
  );
  const logger = createLogger({
    service: 'api-finding-integration',
    level: 'silent',
    pretty: false,
  });
  const prisma = getPrismaClient({ databaseUrl: config.databaseUrl });
  const repos = createRepositories(prisma);
  const hasher = createArgon2PasswordHasher();
  const tokens = createNodeRandomTokenGenerator();
  const clock = createSystemClock();
  const limiter = createFakeLoginRateLimiter({ auth: config.auth, logger, clock });
  const shared = {
    users: repos.users,
    localCredentials: repos.localCredentials,
    sessions: repos.sessions,
    memberships: repos.memberships,
    clock,
    auth: config.auth,
    logger,
  };
  let app: FastifyInstance;
  let homeOrgId = '';
  let findingId = '';
  let evidenceIds: string[] = [];
  let evidenceCount = 0;
  const sessions = new Map<RoleName | 'foreign' | 'unscoped', Session>();
  let body: Record<string, unknown> = {};

  beforeAll(async () => {
    const passwordHash = await hasher.hash(
      VALID_PASSWORD,
      argon2ParametersFromAuthConfig(config.auth),
    );
    const home = await prisma.organization.create({
      data: { slug: `finding-home-${randomUUID().slice(0, 8)}`, name: 'Finding Home' },
    });
    const foreign = await prisma.organization.create({
      data: { slug: `finding-foreign-${randomUUID().slice(0, 8)}`, name: 'Finding Foreign' },
    });
    const second = await prisma.organization.create({
      data: { slug: `finding-second-${randomUUID().slice(0, 8)}`, name: 'Finding Second' },
    });
    homeOrgId = home.id;
    const seeded = await seedControlledFindingEvidence(prisma, {
      label: `finding-api-${randomUUID().slice(0, 8)}`,
      organizationId: home.id,
      versions: [
        { version: '1.1.0', bomRef: 'component-1' },
        { version: '1.2.0', bomRef: 'component-2' },
      ],
    });
    evidenceIds = seeded.evidence
      .map((row) => row.evidenceId)
      .sort((left, right) => left.localeCompare(right));
    expect(seeded.evidence.every((row) => row.outcome === 'affected')).toBe(true);
    evidenceCount = await prisma.productMatchEvaluationEvidence.count({
      where: { organizationId: home.id },
    });
    body = {
      assetId: seeded.assetId,
      componentId: seeded.componentId,
      vulnerabilityId: seeded.vulnerabilityId,
      expectedSbomIngestionId: seeded.ingestionId,
      expectedProductMatchEvidenceIds: evidenceIds,
    };
    const roles: RoleName[] = ['owner', 'admin', 'member', 'viewer'];
    for (const role of roles) {
      await createUser(passwordHash, home.id, role, `home-${role}`);
    }
    await createUser(passwordHash, foreign.id, 'owner', 'foreign-owner');
    const unscoped = await createUser(passwordHash, home.id, 'owner', 'unscoped');
    await prisma.membership.create({
      data: { organizationId: second.id, userId: unscoped, role: 'member', status: 'active' },
    });
    app = await buildApi({
      config,
      logger,
      checkDatabaseReady: async () => ({ ok: true }),
      auth: {
        login: createLoginUseCase({ ...shared, hasher, tokens, limiter }),
        logout: createLogoutUseCase({ sessions: repos.sessions, clock, logger }),
        resolveSession: createResolveSessionUseCase(shared),
        readSession: createReadSessionUseCase({ ...shared, tokens }),
        selectOrganization: createSelectOrganizationUseCase({ ...shared, tokens }),
        listOrganizations: createListActiveOrganizationsUseCase(shared),
        audit: repos.auditEvents,
      },
      assets: emptyAssetRuntime(),
      sboms: emptySbomRuntime(),
      intelligence: emptyIntelligenceRuntime(config),
      findings: composeControlledFindingOperatorRuntime(prisma),
    });
    for (const [index, role] of roles.entries()) {
      sessions.set(
        role,
        await login(`home-${role}@synthetic.patchpilot.test`, `192.0.2.${20 + index}`),
      );
    }
    sessions.set('foreign', await login('foreign-owner@synthetic.patchpilot.test', '192.0.2.30'));
    sessions.set('unscoped', await login('unscoped@synthetic.patchpilot.test', '192.0.2.31'));
  }, 180_000);

  afterAll(async () => {
    await app?.close();
    await disconnectPrisma();
    resetPrismaClientForTests();
  });

  it('rejects unauthenticated, unscoped, and unauthorized operators before creation', async () => {
    const anonymous = await post(null, body, '198.51.100.80');
    const unscoped = await post(required('unscoped'), body, '198.51.100.81');
    const admin = await post(required('admin'), body, '198.51.100.82');
    const member = await post(required('member'), body, '198.51.100.83');
    const viewer = await post(required('viewer'), body, '198.51.100.84');
    const injected = await post(
      required('owner'),
      { ...body, organizationId: randomUUID() },
      '198.51.100.85',
    );
    expect(anonymous.statusCode).toBe(401);
    expect(unscoped.statusCode).toBe(403);
    expect(admin.statusCode).toBe(403);
    expect(member.statusCode).toBe(403);
    expect(viewer.statusCode).toBe(403);
    expect(injected.statusCode).toBe(400);
    expect(await prisma.finding.count({ where: { organizationId: homeOrgId } })).toBe(0);
  });

  it('creates one Finding for several affected versions, replays it, and rejects stale evidence', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async () => {
      throw new Error('provider contact during finding route');
    };
    try {
      const firstIp = '203.0.113.10';
      const secondIp = '203.0.113.11';
      const [left, right] = await Promise.all([
        post(required('owner'), body, firstIp, randomUUID()),
        post(required('owner'), body, secondIp, randomUUID()),
      ]);
      const statuses = [left.statusCode, right.statusCode].sort((a, b) => a - b);
      expect(statuses).toEqual([200, 201]);
      const createdBody = (left.statusCode === 201 ? left : right).json() as {
        status: string;
        findingId: string;
      };
      const replayedBody = (left.statusCode === 200 ? left : right).json() as {
        status: string;
        findingId: string;
      };
      expect(createdBody).toEqual({ status: 'created', findingId: createdBody.findingId });
      expect(replayedBody).toEqual({
        status: 'already_applied',
        findingId: createdBody.findingId,
      });
      findingId = createdBody.findingId;
      expect(Object.keys(createdBody).sort()).toEqual(['findingId', 'status']);
      const replay = await post(required('owner'), body, '203.0.113.12', randomUUID(), {
        url: `/findings?organizationId=${randomUUID()}`,
      });
      expect(replay.statusCode).toBe(200);
      expect(replay.json()).toEqual({ status: 'already_applied', findingId });
      const absent = await post(
        required('owner'),
        { ...body, assetId: '12121212-1212-4121-8121-121212121212' },
        '203.0.113.13',
        randomUUID(),
      );
      expect(absent.statusCode).toBe(404);
      expect(absent.json().error.message).toBe('Not found.');
      expect(JSON.stringify(absent.json())).not.toContain(evidenceIds[0]);
      const firstEvidence = evidenceIds[0];
      if (firstEvidence === undefined) {
        throw new Error('expected evidence');
      }
      const stale = await post(
        required('owner'),
        { ...body, expectedProductMatchEvidenceIds: [firstEvidence] },
        '203.0.113.14',
        randomUUID(),
      );
      expect(stale.statusCode).toBe(409);
      expect(stale.json().error.message).toBe('The request conflicts with the current evidence.');
      expect(JSON.stringify(stale.json())).not.toContain(firstEvidence);
      expect(JSON.stringify(stale.json())).not.toContain('reviewer');
      const limited = await post(required('owner'), body, '203.0.113.15', randomUUID());
      expect(limited.statusCode).toBe(429);
      const findings = await prisma.finding.findMany({ where: { organizationId: homeOrgId } });
      expect(findings).toHaveLength(1);
      const audits = await prisma.auditEvent.findMany({
        where: { organizationId: homeOrgId, action: 'finding.created' },
      });
      expect(audits).toHaveLength(1);
      expect(audits[0]?.subjectId).toBe(findingId);
      expect(JSON.stringify(audits)).not.toContain(required('owner').csrf);
      expect(
        await prisma.productMatchEvaluationEvidence.count({
          where: { organizationId: homeOrgId },
        }),
      ).toBe(evidenceCount);
    } finally {
      globalThis.fetch = originalFetch;
    }
  }, 120_000);

  it('returns the safe projection to owners and admins and hides foreign and absent findings', async () => {
    const ownerView = await get(required('owner'), findingId, '198.51.100.90');
    const adminView = await app.inject({
      method: 'GET',
      url: `/findings/${findingId}`,
      remoteAddress: '198.51.100.91',
      headers: { cookie: required('admin').cookie },
    });
    const memberView = await get(required('member'), findingId, '198.51.100.92');
    const viewerView = await get(required('viewer'), findingId, '198.51.100.93');
    const absent = await get(
      required('owner'),
      '34343434-3434-4343-8343-343434343434',
      '198.51.100.94',
    );
    const foreign = await get(required('foreign'), findingId, '198.51.100.95');
    expect(ownerView.statusCode).toBe(200);
    expect(adminView.statusCode).toBe(200);
    expect(ownerView.headers['cache-control']).toBe('private, no-store');
    const projection = ownerView.json() as {
      findingId: string;
      state: string;
      affectedOccurrenceCount: number;
      affectedVersions: { values: string[] };
    };
    expect(projection.findingId).toBe(findingId);
    expect(projection.state).toBe('open');
    expect(projection.affectedOccurrenceCount).toBe(2);
    expect(projection.affectedVersions.values).toEqual(['1.1.0', '1.2.0']);
    expect(adminView.json()).toEqual(ownerView.json());
    const serialized = JSON.stringify(ownerView.json());
    expect(serialized).not.toContain(evidenceIds[0]);
    expect(serialized).not.toContain('reviewer.two');
    expect(serialized).not.toContain('author.one');
    expect(serialized).not.toContain('organizationId');
    expect(ownerView.json()).not.toHaveProperty('evidence');
    expect(ownerView.json()).not.toHaveProperty('membershipId');
    expect(memberView.statusCode).toBe(403);
    expect(viewerView.statusCode).toBe(403);
    expect(absent.statusCode).toBe(404);
    expect(foreign.statusCode).toBe(404);
    expect(absent.json().error.code).toBe(foreign.json().error.code);
    expect(absent.json().error.message).toBe(foreign.json().error.message);
    expect(JSON.stringify(foreign.json())).not.toContain(findingId);
    expect(JSON.stringify(absent.json())).not.toContain(findingId);
  });

  async function createUser(
    passwordHash: string,
    organizationId: string,
    role: RoleName,
    label: string,
  ): Promise<string> {
    const user = await prisma.user.create({
      data: {
        email: `${label}@synthetic.patchpilot.test`,
        displayName: label,
      },
    });
    await prisma.localCredential.create({
      data: { userId: user.id, passwordHash, passwordRevision: 1 },
    });
    await prisma.membership.create({
      data: { organizationId, userId: user.id, role, status: 'active' },
    });
    return user.id;
  }

  async function login(email: string, remoteAddress: string): Promise<Session> {
    const response = await app.inject({
      method: 'POST',
      url: '/auth/login',
      remoteAddress,
      headers: { origin: TEST_ORIGIN, 'content-type': 'application/json' },
      payload: { email, password: VALID_PASSWORD },
    });
    expect(response.statusCode, email).toBe(200);
    const header = response.headers['set-cookie'];
    const setCookie =
      typeof header === 'string' ? header : Array.isArray(header) ? header[0] : undefined;
    if (typeof setCookie !== 'string') {
      throw new Error('expected Set-Cookie');
    }
    const part = setCookie.split(';', 1)[0];
    const prefix = `${config.auth.cookieName}=`;
    if (part === undefined || !part.startsWith(prefix)) {
      throw new Error('cookie name mismatch');
    }
    return {
      cookie: `${config.auth.cookieName}=${part.slice(prefix.length)}`,
      csrf: (response.json() as SessionResponse).csrfToken,
    };
  }

  function required(role: RoleName | 'foreign' | 'unscoped'): Session {
    const session = sessions.get(role);
    if (session === undefined) {
      throw new Error(`missing ${role} session`);
    }
    return session;
  }

  async function post(
    session: Session | null,
    payload: Record<string, unknown>,
    remoteAddress: string,
    correlationId?: string,
    options?: { url?: string },
  ) {
    return app.inject({
      method: 'POST',
      url: options?.url ?? '/findings',
      remoteAddress,
      headers: {
        origin: TEST_ORIGIN,
        'content-type': 'application/json',
        ...(session === null ? {} : { cookie: session.cookie, 'x-csrf-token': session.csrf }),
        ...(correlationId === undefined ? {} : { [config.correlationIdHeader]: correlationId }),
      },
      payload,
    });
  }

  async function get(session: Session, id: string, remoteAddress: string) {
    return app.inject({
      method: 'GET',
      url: `/findings/${id}`,
      remoteAddress,
      headers: { cookie: session.cookie },
    });
  }
});
