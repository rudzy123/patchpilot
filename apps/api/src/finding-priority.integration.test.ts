/**
 * Composed priority routes. Synthetic evidence only.
 * Publication and calculation use the production admitted pair.
 * A database without the builtin row stays unavailable.
 */

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
import {
  ADMITTED_PRIORITY_POLICY_PAIRS,
  JSON_SCHEMA_VERSION_V1,
  RISK_CALCULATION_FACTORS_SCHEMA_VERSION_V2,
} from '@patchpilot/domain';
import {
  BUILTIN_PRIORITY_POLICY_DEFINITION,
  POLICY_ENGINE_VERSION,
  canonicalJson,
  evaluatePriority,
  parseFactInput,
  validatePolicyDefinition,
  validatePolicyOverride,
  type PriorityEvaluation,
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
import {
  productionPublicationAdmitsCurrentBuiltin,
  publishBuiltinPriorityPolicy,
} from '../../../packages/database/src/builtin-priority-policy-publication.js';
import { seedControlledFindingEvidence } from '../../../packages/database/src/controlled-finding-operator-seed-fixture.js';
import { insertOpenFindingForConstraintTest } from '../../../packages/database/src/finding-constraint-fixture.js';
import {
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
} from '../../../packages/database/src/integration-database.js';
import { createAsset } from '../../../packages/database/src/sbom-test-fixture.js';

const ADMITTED_DEFINITION_SHA256 =
  '7c1815d456ff6dcf9e19c218bcd5eaba73c265abc911027c3f50df41bb8504f7';
const ADMITTED_ENGINE_VERSION = '@patchpilot/policy-engine@1';

type QueueBody = {
  schemaVersion: string;
  section: string;
  reference: {
    policyKey: string;
    policyVersion: number;
    policyDefinitionSha256: string;
    engineVersion: string;
  };
  counts: { ranked: number; incomparable: number; not_calculated: number };
  rows: Array<Record<string, unknown>>;
};

function productionAdmittedPair() {
  const pair = ADMITTED_PRIORITY_POLICY_PAIRS[0];
  if (
    ADMITTED_PRIORITY_POLICY_PAIRS.length !== 1 ||
    pair === undefined ||
    pair.engineVersion !== ADMITTED_ENGINE_VERSION ||
    pair.policyDefinitionSha256 !== ADMITTED_DEFINITION_SHA256 ||
    pair.validationEntryId !== 'V-0001'
  ) {
    throw new Error('production admitted priority pair drifted');
  }
  return pair;
}

type RoleName = 'owner' | 'admin' | 'member' | 'viewer';
type Session = { cookie: string; csrf: string };

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
  let publishedPolicyId = '';
  let seededTarget: Awaited<ReturnType<typeof seedControlledFindingEvidence>> | undefined;
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
    seededTarget = seeded;
    const pair = productionAdmittedPair();
    expect(POLICY_ENGINE_VERSION).toBe(pair.engineVersion);
    const published = await publishBuiltinPriorityPolicy(prisma, {
      correlationId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      definition: BUILTIN_PRIORITY_POLICY_DEFINITION,
      canonicalJson,
      admittedPairs: ADMITTED_PRIORITY_POLICY_PAIRS,
      engineVersion: POLICY_ENGINE_VERSION,
    });
    expect(['inserted', 'already_applied']).toContain(published.outcome);
    if (published.outcome !== 'inserted' && published.outcome !== 'already_applied') {
      throw new Error('builtin publication did not apply');
    }
    publishedPolicyId = published.riskPolicyId;
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
        admittedPairs: ADMITTED_PRIORITY_POLICY_PAIRS,
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
      calculation: {
        policyKey: 'patchpilot.builtin.v0',
        policyVersion: 2,
        policyDefinitionSha256: ADMITTED_DEFINITION_SHA256,
        engineVersion: ADMITTED_ENGINE_VERSION,
      },
    });
    const stored = await prisma.riskCalculation.findFirstOrThrow({
      where: { organizationId: homeOrgId, findingId },
    });
    expect(stored.policyDefinitionSha256).toBe(ADMITTED_DEFINITION_SHA256);
    expect(stored.calculationEngineVersion).toBe(ADMITTED_ENGINE_VERSION);
    expect(stored.policyVersion).toBe(2);
    expect(stored.riskPolicyId).toBe(publishedPolicyId);
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

  it('keeps queue sections and a review from changing the admitted priority', async () => {
    const pair = productionAdmittedPair();
    const calculated = await calculate(required('owner'), findingId, '198.51.100.90');
    expect([200, 201]).toContain(calculated.statusCode);
    const afterCalculate = evaluations;
    const priorityRead = await read(required('owner'), findingId, '198.51.100.91');
    expect(priorityRead.statusCode).toBe(200);
    const priorityBody = priorityRead.json() as {
      status: string;
      calculation: {
        riskCalculationId: string;
        priority: number;
        priorityBand: string;
        policyDefinitionSha256: string;
        engineVersion: string;
      };
    };
    expect(priorityBody.status).toBe('calculated');
    expect(priorityBody.calculation.policyDefinitionSha256).toBe(pair.policyDefinitionSha256);
    expect(priorityBody.calculation.engineVersion).toBe(pair.engineVersion);
    const storedBefore = await prisma.riskCalculation.findUniqueOrThrow({
      where: { id: priorityBody.calculation.riskCalculationId },
    });
    const resultBefore = JSON.stringify(storedBefore.result);
    const factorsBefore = JSON.stringify(storedBefore.factors);
    const evaluation = referenceEvaluation();
    const higherPriority = priorityBody.calculation.priority + 1;
    const higher = await insertQueueFinding('higher');
    await insertStoredCalculation(
      higher.finding,
      evaluation,
      pair.policyDefinitionSha256,
      pair.engineVersion,
      higherPriority,
    );
    const otherHash = await insertQueueFinding('hash');
    await insertStoredCalculation(
      otherHash.finding,
      evaluation,
      'b'.repeat(64),
      pair.engineVersion,
      evaluation.priority,
      new Date('2026-01-01T00:00:00.000Z'),
    );
    const otherEngine = await insertQueueFinding('engine');
    await insertStoredCalculation(
      otherEngine.finding,
      evaluation,
      pair.policyDefinitionSha256,
      '@patchpilot/policy-engine@0',
      evaluation.priority,
      new Date('2026-01-02T00:00:00.000Z'),
    );
    const missing = await insertQueueFinding('missing');

    const ranked = await queue(required('owner'), 'ranked', '198.51.100.92');
    const absent = await queue(required('owner'), 'not_calculated', '198.51.100.93');
    const compared = await queue(required('owner'), 'incomparable', '198.51.100.94');
    expect(ranked.statusCode).toBe(200);
    expect(absent.statusCode).toBe(200);
    expect(compared.statusCode).toBe(200);
    const rankedBody = ranked.json() as QueueBody;
    const absentBody = absent.json() as QueueBody;
    const comparedBody = compared.json() as QueueBody;
    expect(rankedBody).toMatchObject({
      schemaVersion: 'remediation_queue_v1',
      section: 'ranked',
      reference: {
        policyKey: 'patchpilot.builtin.v0',
        policyVersion: 2,
        policyDefinitionSha256: pair.policyDefinitionSha256,
        engineVersion: pair.engineVersion,
      },
    });
    expect(rankedBody.counts).toEqual({ ranked: 2, incomparable: 2, not_calculated: 1 });
    expect(rankedBody.rows.map((row) => row['findingId'])).toEqual([higher.finding.id, findingId]);
    expect(rankedBody.rows[0]?.['priority']).toBe(higherPriority);
    expect(rankedBody.rows[1]?.['priority']).toBe(priorityBody.calculation.priority);
    const rankedOrder = rankedBody.rows.map((row) => ({
      findingId: row['findingId'],
      priority: row['priority'],
    }));
    expect(absentBody.section).toBe('not_calculated');
    expect(absentBody.rows.map((row) => row['findingId'])).toEqual([missing.finding.id]);
    expect(absentBody.rows[0]).not.toHaveProperty('priority');
    expect(absentBody.rows[0]).not.toHaveProperty('priorityBand');
    expect(comparedBody.section).toBe('incomparable');
    expect(comparedBody.rows.map((row) => row['findingId'])).toEqual([
      otherHash.finding.id,
      otherEngine.finding.id,
    ]);
    expect(comparedBody.rows).toEqual([
      expect.objectContaining({ comparisonMessage: 'recalculation required for comparison' }),
      expect.objectContaining({ comparisonMessage: 'recalculation required for comparison' }),
    ]);

    const adminPriority = await read(required('admin'), findingId, '198.51.100.95');
    const adminQueue = await queue(required('admin'), 'ranked', '198.51.100.96');
    const memberQueue = await queue(required('member'), 'ranked', '198.51.100.97');
    const viewerQueue = await queue(required('viewer'), 'ranked', '198.51.100.98');
    const foreignQueue = await queue(required('foreign'), 'ranked', '198.51.100.99');
    expect(adminPriority.statusCode).toBe(200);
    expect(adminPriority.json()).toMatchObject({
      status: 'calculated',
      findingId,
      calculation: {
        priority: priorityBody.calculation.priority,
        priorityBand: priorityBody.calculation.priorityBand,
      },
    });
    expect(adminQueue.statusCode).toBe(200);
    expect((adminQueue.json() as QueueBody).rows.map((row) => row['findingId'])).toEqual([
      higher.finding.id,
      findingId,
    ]);
    expect(memberQueue.statusCode).toBe(403);
    expect(viewerQueue.statusCode).toBe(403);
    expect(foreignQueue.statusCode).toBe(200);
    const foreignBody = foreignQueue.json() as QueueBody;
    expect(foreignBody.rows.map((row) => row['findingId'])).toEqual([]);
    expect(foreignBody.counts).toEqual({ ranked: 0, incomparable: 0, not_calculated: 0 });

    const review = await reviewPriority(
      required('owner'),
      findingId,
      {
        schemaVersion: 'priority_review_v1',
        riskCalculationId: priorityBody.calculation.riskCalculationId,
        supersedesReviewId: null,
        decision: 'accepted',
      },
      '198.51.100.100',
    );
    expect(review.statusCode).toBe(201);
    const storedAfter = await prisma.riskCalculation.findUniqueOrThrow({
      where: { id: priorityBody.calculation.riskCalculationId },
    });
    expect(JSON.stringify(storedAfter.result)).toBe(resultBefore);
    expect(JSON.stringify(storedAfter.factors)).toBe(factorsBefore);
    expect(storedAfter.policyDefinitionSha256).toBe(pair.policyDefinitionSha256);
    expect(storedAfter.calculationEngineVersion).toBe(pair.engineVersion);
    const finding = await prisma.finding.findUniqueOrThrow({ where: { id: findingId } });
    expect(finding.currentRiskCalculationId).toBeNull();
    expect(finding.dueAt).toBeNull();
    expect(finding.state).toBe('open');
    expect(finding.version).toBe(1);
    const rankedAfter = await queue(required('owner'), 'ranked', '198.51.100.101');
    expect(rankedAfter.statusCode).toBe(200);
    expect(
      (rankedAfter.json() as QueueBody).rows.map((row) => ({
        findingId: row['findingId'],
        priority: row['priority'],
      })),
    ).toEqual(rankedOrder);
    expect(
      await prisma.riskCalculation.count({
        where: { organizationId: homeOrgId, findingId },
      }),
    ).toBe(1);
    expect(
      await prisma.auditEvent.count({
        where: { organizationId: homeOrgId, action: 'priority.calculated', subjectId: findingId },
      }),
    ).toBe(1);
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
    expect(evaluations).toBe(afterCalculate);
  }, 180_000);

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

  function queue(
    session: Session,
    section: 'ranked' | 'incomparable' | 'not_calculated',
    remoteAddress: string,
  ) {
    return app.inject({
      method: 'GET',
      url: `/remediation-queue?section=${section}`,
      remoteAddress,
      headers: { cookie: session.cookie },
    });
  }

  function reviewPriority(
    session: Session,
    id: string,
    payload: {
      schemaVersion: 'priority_review_v1';
      riskCalculationId: string;
      supersedesReviewId: null;
      decision: 'accepted';
    },
    remoteAddress: string,
  ) {
    return app.inject({
      method: 'POST',
      url: `/findings/${id}/priority-reviews`,
      remoteAddress,
      headers: {
        origin: TEST_ORIGIN,
        'content-type': 'application/json',
        cookie: session.cookie,
        'x-csrf-token': session.csrf,
      },
      payload,
    });
  }

  async function insertQueueFinding(name: string) {
    if (seededTarget === undefined) {
      throw new Error('controlled finding seed is missing');
    }
    const asset = await createAsset(prisma, homeOrgId, `activation ${name} ${randomUUID()}`);
    return insertOpenFindingForConstraintTest(prisma, {
      organizationId: homeOrgId,
      assetId: asset.id,
      vulnerabilityId: seededTarget.vulnerabilityId,
      componentId: seededTarget.componentId,
    });
  }

  async function insertStoredCalculation(
    finding: { id: string; organizationId: string; lastObservedAt: Date },
    evaluation: PriorityEvaluation,
    policyHash: string,
    engineVersion: string,
    priority: number,
    calculatedAt: Date = finding.lastObservedAt,
  ): Promise<void> {
    await prisma.riskCalculation.create({
      data: {
        organizationId: finding.organizationId,
        findingId: finding.id,
        riskPolicyId: publishedPolicyId,
        policyVersion: 2,
        policyDefinitionSha256: policyHash,
        calculatedAt,
        factors: factorDocument(evaluation) as never,
        result: {
          schemaVersion: JSON_SCHEMA_VERSION_V1,
          priority,
          priorityBand: evaluation.priorityBand,
          dueDateRecommendationDays: evaluation.dueDateRecommendationDays,
          escalationRecommendation: evaluation.escalation.recommended,
        },
        calculationEngineVersion: engineVersion,
        calculationReason: 'initial',
        inputFingerprint: `${finding.id.replaceAll('-', '')}`.padEnd(64, 'a').slice(0, 64),
      },
    });
  }
});

function referenceEvaluation(): PriorityEvaluation {
  const facts = parseFactInput({
    source_severity: { state: 'unavailable' },
    kev_listed: { state: 'unavailable', reason: 'no_active_generation' },
    environment_sensitivity: { state: 'unavailable' },
    internet_exposure: { state: 'unavailable' },
    business_criticality: { state: 'unavailable' },
    asset_data_classification: { state: 'unavailable' },
    direct_dependency: { state: 'unavailable' },
    fix_available: { state: 'unavailable' },
    finding_age_days: { state: 'unavailable' },
    advisory_withdrawn: { state: 'unavailable' },
  });
  const definition = validatePolicyDefinition(structuredClone(BUILTIN_PRIORITY_POLICY_DEFINITION));
  if (!facts.ok || !definition.ok) {
    throw new Error('activation fixture must evaluate');
  }
  const result = evaluatePriority(definition.value, facts.value);
  if (!result.ok) {
    throw new Error('activation fixture evaluation failed');
  }
  return result.value;
}

function factorDocument(evaluation: PriorityEvaluation): Record<string, unknown> {
  return {
    schemaVersion: RISK_CALCULATION_FACTORS_SCHEMA_VERSION_V2,
    factors: evaluation.factors,
    rules: evaluation.rules,
    escalationReasons: evaluation.escalation.reasons,
    evidenceSummary: evaluation.evidenceSummary,
    weightedScoreCenti: evaluation.weightedScoreCenti,
    upliftCenti: evaluation.upliftCenti,
    sources: {
      evidenceIds: [],
      advisoryRevisionIds: [],
      componentOccurrenceIds: [],
      intelligenceSourceRecordIds: [],
      kev: { state: 'unavailable', reason: 'no_active_generation' },
    },
  };
}

describe('admitted priority before publication', () => {
  let ephemeral: Awaited<ReturnType<typeof createEphemeralDatabase>> | undefined;
  let localPrisma: ReturnType<typeof getPrismaClient> | undefined;
  let app: FastifyInstance | undefined;
  let owner: Session | undefined;
  let finding = '';

  beforeAll(async () => {
    expect(
      productionPublicationAdmitsCurrentBuiltin(
        canonicalJson,
        BUILTIN_PRIORITY_POLICY_DEFINITION,
        POLICY_ENGINE_VERSION,
      ),
    ).toBe(true);
    ephemeral = await createEphemeralDatabase('it', { scope: 'unpub' });
    await deployMigrations(ephemeral.databaseUrl);
    const config = loadServerConfigFrom(createIntegrationDatabaseTestEnv(ephemeral.databaseUrl));
    await disconnectPrisma();
    resetPrismaClientForTests();
    localPrisma = getPrismaClient({ databaseUrl: ephemeral.databaseUrl });
    const repos = createRepositories(localPrisma);
    const hasher = createArgon2PasswordHasher();
    const tokens = createNodeRandomTokenGenerator();
    const clock = createSystemClock();
    const logger = createLogger({
      service: 'api-priority-unpublished',
      level: 'silent',
      pretty: false,
    });
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
    const passwordHash = await hasher.hash(
      VALID_PASSWORD,
      argon2ParametersFromAuthConfig(config.auth),
    );
    const label = `unpublished-${randomUUID().slice(0, 8)}`;
    const home = await localPrisma.organization.create({
      data: { slug: `${label}-home`, name: 'Unpublished Home' },
    });
    const user = await localPrisma.user.create({
      data: { email: `${label}-owner@synthetic.patchpilot.test`, displayName: label },
    });
    await localPrisma.localCredential.create({
      data: { userId: user.id, passwordHash, passwordRevision: 1 },
    });
    await localPrisma.membership.create({
      data: { organizationId: home.id, userId: user.id, role: 'owner', status: 'active' },
    });
    const seeded = await seedControlledFindingEvidence(localPrisma, {
      label,
      organizationId: home.id,
      versions: [{ version: '1.1.0', bomRef: 'component-1' }],
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
      findings: composeControlledFindingOperatorRuntime(localPrisma),
      priority: composeControlledPriorityRuntime(localPrisma, {
        admittedPairs: ADMITTED_PRIORITY_POLICY_PAIRS,
        kevEnabled: true,
        kevStaleThresholdSeconds: 259_200,
      }),
    });
    const loggedIn = await app.inject({
      method: 'POST',
      url: '/auth/login',
      remoteAddress: '192.0.2.80',
      headers: { origin: TEST_ORIGIN, 'content-type': 'application/json' },
      payload: { email: `${label}-owner@synthetic.patchpilot.test`, password: VALID_PASSWORD },
    });
    expect(loggedIn.statusCode).toBe(200);
    owner = sessionFrom(loggedIn, config.auth.cookieName);
    const created = await app.inject({
      method: 'POST',
      url: '/findings',
      remoteAddress: '203.0.113.80',
      headers: {
        origin: TEST_ORIGIN,
        'content-type': 'application/json',
        cookie: owner.cookie,
        'x-csrf-token': owner.csrf,
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
    finding = (created.json() as { findingId: string }).findingId;
    expect(await localPrisma.riskPolicy.count()).toBe(0);
  }, 180_000);

  afterAll(async () => {
    await app?.close();
    await disconnectPrisma();
    resetPrismaClientForTests();
    if (ephemeral !== undefined) {
      await dropEphemeralDatabase(ephemeral.admin, ephemeral.databaseName);
    }
  });

  it('returns 503 for calculation, priority read, and the queue', async () => {
    if (app === undefined || owner === undefined || localPrisma === undefined) {
      throw new Error('unpublished priority app is missing');
    }
    const calculation = await app.inject({
      method: 'POST',
      url: `/findings/${finding}/risk-calculations`,
      remoteAddress: '198.51.100.110',
      headers: {
        origin: TEST_ORIGIN,
        'content-type': 'application/json',
        cookie: owner.cookie,
        'x-csrf-token': owner.csrf,
      },
      payload: {},
    });
    const priority = await app.inject({
      method: 'GET',
      url: `/findings/${finding}/priority`,
      remoteAddress: '198.51.100.111',
      headers: { cookie: owner.cookie },
    });
    const ranked = await app.inject({
      method: 'GET',
      url: '/remediation-queue?section=ranked',
      remoteAddress: '198.51.100.112',
      headers: { cookie: owner.cookie },
    });
    expect(calculation.statusCode).toBe(503);
    expect(priority.statusCode).toBe(503);
    expect(ranked.statusCode).toBe(503);
    expect(calculation.json().error.message).toBe('Priority policy is unavailable.');
    expect(priority.json().error.message).toBe('Priority policy is unavailable.');
    expect(ranked.json().error.message).toBe('Priority policy is unavailable.');
    expect(ranked.json()).not.toHaveProperty('rows');
    expect(await localPrisma.riskPolicy.count()).toBe(0);
    expect(await localPrisma.riskCalculation.count()).toBe(0);
    expect(
      await localPrisma.outboxEvent.count({ where: { eventType: 'finding.recalculate' } }),
    ).toBe(0);
    expect(
      await localPrisma.backgroundJob.count({ where: { jobType: 'finding.recalculate' } }),
    ).toBe(0);
  }, 120_000);
});

function sessionFrom(
  response: { headers: { [key: string]: unknown }; json: () => unknown },
  cookieName: string,
): Session {
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
  const body = response.json() as { csrfToken?: string };
  if (typeof body.csrfToken !== 'string') {
    throw new Error('expected csrf');
  }
  return {
    cookie: `${cookieName}=${part.slice(prefix.length)}`,
    csrf: body.csrfToken,
  };
}
