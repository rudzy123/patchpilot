/**
 * Composed priority routes. Synthetic evidence only.
 * The production allowlist is empty, so this test admits a fixture pair.
 */

import { createHash, randomUUID } from 'node:crypto';

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
import {
  BUILTIN_PRIORITY_POLICY_DEFINITION,
  POLICY_ENGINE_VERSION,
  canonicalJson,
  evaluatePriority,
  parseFactInput,
  validatePolicyDefinition,
  validatePolicyOverride,
} from '@patchpilot/policy-engine';
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
import { composeControlledPriorityRuntime } from './priority-runtime.js';
import { publishBuiltinPriorityPolicy } from '../../../packages/database/src/builtin-priority-policy-publication.js';
import { seedControlledFindingEvidence } from '../../../packages/database/src/controlled-finding-operator-seed-fixture.js';

type RoleName = 'owner' | 'admin' | 'member' | 'viewer';
type Session = { cookie: string; csrf: string };

function admittedPairs() {
  const encoded = canonicalJson(BUILTIN_PRIORITY_POLICY_DEFINITION);
  if (!encoded.ok) {
    throw new Error('builtin canonical json failed');
  }
  return [
    {
      engineVersion: POLICY_ENGINE_VERSION,
      policyDefinitionSha256: createHash('sha256').update(encoded.value, 'utf8').digest('hex'),
      validationEntryId: 'fixture',
    },
  ];
}

describe('controlled finding priority routes', () => {
  const config = loadServerConfigFrom(
    createIntegrationDatabaseTestEnv(readDisposableIntegrationDatabaseUrl()),
  );
  const prisma = getPrismaClient({ databaseUrl: config.databaseUrl });
  const repos = createRepositories(prisma);
  const hasher = createArgon2PasswordHasher();
  const tokens = createNodeRandomTokenGenerator();
  const clock = createSystemClock();
  const logger = createLogger({
    service: 'api-priority-integration',
    level: 'silent',
    pretty: false,
  });
  const limiter = createFakeLoginRateLimiter({
    auth: config.auth,
    logger,
    clock,
  });
  let evaluations = 0;
  const engine = {
    parseFactInput,
    evaluatePriority(
      ...args: Parameters<typeof evaluatePriority>
    ): ReturnType<typeof evaluatePriority> {
      evaluations += 1;
      return evaluatePriority(...args);
    },
    validatePolicyDefinition,
    validatePolicyOverride,
    canonicalJson,
  };
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
  const sessions = new Map<RoleName | 'foreign', Session>();

  beforeAll(async () => {
    const passwordHash = await hasher.hash(
      VALID_PASSWORD,
      argon2ParametersFromAuthConfig(config.auth),
    );
    const label = `priority-${randomUUID().slice(0, 8)}`;
    const home = await prisma.organization.create({
      data: { slug: `${label}-home`, name: 'Priority Home' },
    });
    const foreign = await prisma.organization.create({
      data: { slug: `${label}-foreign`, name: 'Priority Foreign' },
    });
    homeOrgId = home.id;
    const seeded = await seedControlledFindingEvidence(prisma, {
      label,
      organizationId: home.id,
      versions: [{ version: '1.1.0', bomRef: 'component-1' }],
    });
    const published = await publishBuiltinPriorityPolicy(prisma, {
      correlationId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      definition: BUILTIN_PRIORITY_POLICY_DEFINITION,
      canonicalJson,
      admittedPairs: admittedPairs(),
      engineVersion: POLICY_ENGINE_VERSION,
    });
    expect(['inserted', 'already_applied']).toContain(published.outcome);
    for (const role of ['owner', 'admin', 'member', 'viewer'] as const) {
      await createUser(passwordHash, home.id, role, `${label}-${role}`);
    }
    await createUser(passwordHash, foreign.id, 'owner', `${label}-foreign`);
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
      priority: composeControlledPriorityRuntime(prisma, {
        admittedPairs: admittedPairs(),
        kevEnabled: true,
        kevStaleThresholdSeconds: 259_200,
        engine,
      }),
    });
    for (const [index, role] of (['owner', 'admin', 'member', 'viewer'] as const).entries()) {
      sessions.set(
        role,
        await login(`${label}-${role}@synthetic.patchpilot.test`, `192.0.2.${40 + index}`),
      );
    }
    sessions.set(
      'foreign',
      await login(`${label}-foreign@synthetic.patchpilot.test`, '192.0.2.48'),
    );
    const created = await app.inject({
      method: 'POST',
      url: '/findings',
      remoteAddress: '203.0.113.40',
      headers: {
        origin: TEST_ORIGIN,
        'content-type': 'application/json',
        cookie: required('owner').cookie,
        'x-csrf-token': required('owner').csrf,
      },
      payload: {
        assetId: seeded.assetId,
        componentId: seeded.componentId,
        vulnerabilityId: seeded.vulnerabilityId,
        expectedSbomIngestionId: seeded.ingestionId,
        expectedProductMatchEvidenceIds: seeded.evidence.map((row) => row.evidenceId).sort(),
      },
    });
    expect(created.statusCode).toBe(201);
    findingId = (created.json() as { findingId: string }).findingId;
  }, 180_000);

  afterAll(async () => {
    await app?.close();
    await disconnectPrisma();
    resetPrismaClientForTests();
  });

  it('calculates once, replays without a second row, and does not call the engine on read', async () => {
    const beforeRead = await read(required('owner'), findingId, '198.51.100.60');
    expect(beforeRead.statusCode).toBe(200);
    expect(beforeRead.json()).toEqual({
      schemaVersion: 'finding_priority_v1',
      status: 'not_calculated',
      findingId,
    });
    expect(beforeRead.json()).not.toHaveProperty('priorityBand');
    expect(evaluations).toBe(0);
    const first = await calculate(required('owner'), findingId, '198.51.100.61');
    expect(first.statusCode).toBe(201);
    expect(first.json()).toMatchObject({
      schemaVersion: 'finding_risk_calculation_v1',
      status: 'calculated',
      findingId,
    });
    const afterCalculate = evaluations;
    expect(afterCalculate).toBeGreaterThan(0);
    const current = await read(required('owner'), findingId, '198.51.100.62');
    expect(current.statusCode).toBe(200);
    expect(current.json()).toMatchObject({
      schemaVersion: 'finding_priority_v1',
      status: 'calculated',
      findingId,
      comparability: 'reference',
      review: { status: 'none', priorReviewExists: false },
    });
    expect(evaluations).toBe(afterCalculate);
    const replay = await calculate(required('owner'), findingId, '198.51.100.63');
    expect(replay.statusCode).toBe(200);
    expect(replay.json()).toMatchObject({ status: 'already_applied', findingId });
    expect(
      await prisma.riskCalculation.count({ where: { organizationId: homeOrgId, findingId } }),
    ).toBe(1);
    expect(
      await prisma.auditEvent.count({
        where: { organizationId: homeOrgId, action: 'priority.calculated', subjectId: findingId },
      }),
    ).toBe(1);
    const finding = await prisma.finding.findUniqueOrThrow({ where: { id: findingId } });
    expect(finding.currentRiskCalculationId).toBeNull();
    expect(finding.dueAt).toBeNull();
    expect(
      await prisma.outboxEvent.count({
        where: { organizationId: homeOrgId, eventType: 'finding.recalculate' },
      }),
    ).toBe(0);
    expect(
      await prisma.backgroundJob.count({
        where: { organizationId: homeOrgId, jobType: 'finding.recalculate' },
      }),
    ).toBe(0);
  }, 120_000);

  it('hides a foreign Finding and denies member, viewer, and admin calculation', async () => {
    const foreign = await read(required('foreign'), findingId, '198.51.100.70');
    const absent = await read(
      required('owner'),
      '34343434-3434-4343-8343-343434343434',
      '198.51.100.71',
    );
    const member = await read(required('member'), findingId, '198.51.100.72');
    const viewer = await read(required('viewer'), findingId, '198.51.100.73');
    const admin = await calculate(required('admin'), findingId, '198.51.100.74');
    expect(foreign.statusCode).toBe(404);
    expect(absent.statusCode).toBe(404);
    expect(foreign.json().error.code).toBe(absent.json().error.code);
    expect(member.statusCode).toBe(403);
    expect(viewer.statusCode).toBe(403);
    expect(admin.statusCode).toBe(403);
  });

  it('returns 503 when the builtin pair is not admitted', async () => {
    const closed = await buildApi({
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
      priority: composeControlledPriorityRuntime(prisma, {
        admittedPairs: [],
        kevEnabled: true,
        kevStaleThresholdSeconds: 259_200,
      }),
    });
    const response = await closed.inject({
      method: 'POST',
      url: `/findings/${findingId}/risk-calculations`,
      remoteAddress: '198.51.100.80',
      headers: {
        origin: TEST_ORIGIN,
        'content-type': 'application/json',
        cookie: required('owner').cookie,
        'x-csrf-token': required('owner').csrf,
      },
      payload: {},
    });
    expect(response.statusCode).toBe(503);
    expect(response.json().error.message).toBe('Priority policy is unavailable.');
    await closed.close();
  });

  async function createUser(
    passwordHash: string,
    organizationId: string,
    role: RoleName,
    label: string,
  ): Promise<void> {
    const user = await prisma.user.create({
      data: { email: `${label}@synthetic.patchpilot.test`, displayName: label },
    });
    await prisma.localCredential.create({
      data: { userId: user.id, passwordHash, passwordRevision: 1 },
    });
    await prisma.membership.create({
      data: { organizationId, userId: user.id, role, status: 'active' },
    });
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

  function required(role: RoleName | 'foreign'): Session {
    const session = sessions.get(role);
    if (session === undefined) {
      throw new Error(`missing ${role} session`);
    }
    return session;
  }

  function calculate(session: Session, id: string, remoteAddress: string) {
    return app.inject({
      method: 'POST',
      url: `/findings/${id}/risk-calculations`,
      remoteAddress,
      headers: {
        origin: TEST_ORIGIN,
        'content-type': 'application/json',
        cookie: session.cookie,
        'x-csrf-token': session.csrf,
      },
      payload: {},
    });
  }

  function read(session: Session, id: string, remoteAddress: string) {
    return app.inject({
      method: 'GET',
      url: `/findings/${id}/priority`,
      remoteAddress,
      headers: { cookie: session.cookie },
    });
  }
});
