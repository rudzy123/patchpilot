/**
 * Reachable API proof for latest-observation inspection.
 * HTTP uses the composed application service, PostgreSQL adapter, and selector.
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
  FINDING_REPEATED_OBSERVATION_ABSENCE_SUPPORT_SCHEMA_VERSION,
  FINDING_REPEATED_OBSERVATION_AUTHORIZATION_SCHEMA_VERSION,
  FINDING_REPEATED_OBSERVATION_COMMAND_SCHEMA_VERSION,
  FINDING_REPEATED_OBSERVATION_EVIDENCE_SUPPORT_SCHEMA_VERSION,
  FINDING_REPEATED_OBSERVATION_POLICY_ID,
  FINDING_REPEATED_OBSERVATION_POLICY_VERSION,
  FINDING_REPEATED_OBSERVATION_PURPOSE,
  FINDING_REPEATED_OBSERVATION_TRUSTED_CONTEXT_SCHEMA_VERSION,
} from '@patchpilot/domain';
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
import {
  issueFindingRepeatedObservationAuthorization,
  openFindingRepeatedObservationCommand,
} from '../../../packages/domain/dist/findings/controlled-observation/authorization.js';
import { createControlledFindingRepeatedObservationPersistence } from '../../../packages/database/src/controlled-finding-repeated-observation-persistence.js';
import {
  seedControlledFindingEvidence,
  seedLaterControlledFindingIngestion,
  type ControlledFindingSeedTarget,
  type LaterControlledFindingIngestion,
} from '../../../packages/database/src/controlled-finding-operator-seed-fixture.js';

type RoleName = 'owner' | 'admin' | 'member' | 'viewer';
type Session = { cookie: string; csrf: string };
type PreparedActor = {
  readonly organizationId: string;
  readonly actorId: string;
  readonly membershipId: string;
};

describe('controlled finding latest-observation reachability', () => {
  const config = loadServerConfigFrom(
    createIntegrationDatabaseTestEnv(readDisposableIntegrationDatabaseUrl()),
  );
  const logger = createLogger({
    service: 'api-latest-observation-integration',
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
  let seed: ControlledFindingSeedTarget;
  let actor: PreparedActor;
  const sessions = new Map<RoleName | 'foreign', Session>();
  let body: Record<string, unknown> = {};

  beforeAll(async () => {
    const passwordHash = await hasher.hash(
      VALID_PASSWORD,
      argon2ParametersFromAuthConfig(config.auth),
    );
    const home = await prisma.organization.create({
      data: { slug: `latest-home-${randomUUID().slice(0, 8)}`, name: 'Latest Home' },
    });
    const foreign = await prisma.organization.create({
      data: { slug: `latest-foreign-${randomUUID().slice(0, 8)}`, name: 'Latest Foreign' },
    });
    homeOrgId = home.id;
    seed = await seedControlledFindingEvidence(prisma, {
      label: `latest-api-${randomUUID().slice(0, 8)}`,
      organizationId: home.id,
      versions: [{ version: '1.1.0', bomRef: 'component-1' }],
    });
    const evidenceIds = seed.evidence
      .map((row) => row.evidenceId)
      .sort((left, right) => (left < right ? -1 : 1));
    body = {
      assetId: seed.assetId,
      componentId: seed.componentId,
      vulnerabilityId: seed.vulnerabilityId,
      expectedSbomIngestionId: seed.ingestionId,
      expectedProductMatchEvidenceIds: evidenceIds,
    };
    const owner = await createUser(passwordHash, home.id, 'owner', 'latest-owner');
    actor = { organizationId: home.id, actorId: owner.userId, membershipId: owner.membershipId };
    for (const role of ['admin', 'member', 'viewer'] as const) {
      await createUser(passwordHash, home.id, role, `latest-${role}`);
    }
    await createUser(passwordHash, foreign.id, 'owner', 'latest-foreign');
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
    sessions.set('owner', await login('latest-owner@synthetic.patchpilot.test', '192.0.2.60'));
    sessions.set('admin', await login('latest-admin@synthetic.patchpilot.test', '192.0.2.61'));
    sessions.set('member', await login('latest-member@synthetic.patchpilot.test', '192.0.2.62'));
    sessions.set('viewer', await login('latest-viewer@synthetic.patchpilot.test', '192.0.2.63'));
    sessions.set('foreign', await login('latest-foreign@synthetic.patchpilot.test', '192.0.2.64'));
    const created = await post(required('owner'), body, '203.0.113.80');
    expect(created.statusCode).toBe(201);
    findingId = (created.json() as { findingId: string }).findingId;
  }, 180_000);

  afterAll(async () => {
    await app?.close();
    await disconnectPrisma();
    resetPrismaClientForTests();
  });

  it('returns creation fallback through PostgreSQL and writes nothing', async () => {
    const before = await footprint(homeOrgId);
    const response = await read(required('owner'), findingId, '198.51.100.110');
    expect(response.statusCode).toBe(200);
    expect(response.headers['cache-control']).toBe('private, no-store');
    expect(response.json()).toMatchObject({
      schemaVersion: 'finding_latest_observation_transport_v1',
      findingId,
      observationSource: 'creation',
      aggregate: 'affected',
      evidence: {
        kind: 'occurrence_support',
        affectedSupportCount: 1,
        unaffectedSupportCount: 0,
        unknownSupportCount: 0,
        unknownVersionSupportCount: 0,
      },
    });
    expect(response.json()).not.toHaveProperty('mappedResult');
    expect(await footprint(homeOrgId)).toEqual(before);
    const inspected = await inspect(required('owner'), findingId, '198.51.100.111');
    expect(inspected.statusCode).toBe(200);
    expect(inspected.json()).toMatchObject({ findingId, state: 'open' });
    expect(inspected.json()).not.toHaveProperty('observationSource');
  }, 60_000);

  it('allows admin, denies member and viewer, and hides foreign and absent findings', async () => {
    const adminView = await read(required('admin'), findingId, '198.51.100.112');
    const memberView = await read(required('member'), findingId, '198.51.100.113');
    const viewerView = await read(required('viewer'), findingId, '198.51.100.114');
    const absent = await read(
      required('owner'),
      '34343434-3434-4343-8343-343434343434',
      '198.51.100.115',
    );
    const foreign = await read(required('foreign'), findingId, '198.51.100.116');
    expect(adminView.statusCode).toBe(200);
    expect(adminView.json()).toMatchObject({
      observationSource: 'creation',
      aggregate: 'affected',
    });
    expect(memberView.statusCode).toBe(403);
    expect(viewerView.statusCode).toBe(403);
    expect(absent.statusCode).toBe(404);
    expect(foreign.statusCode).toBe(404);
    expect(absent.json().error.code).toBe(foreign.json().error.code);
    expect(absent.json().error.message).toBe(foreign.json().error.message);
    expect(JSON.stringify(absent.json())).not.toContain(findingId);
    expect(JSON.stringify(foreign.json())).not.toContain(findingId);
  });

  it('publishes the latest legal aggregate and keeps creation inspection independent', async () => {
    const affected = await later('affected', {
      receivedAt: new Date('2026-10-08T12:00:00.000Z'),
      versions: [{ version: '1.2.0', bomRef: 'component-affected' }],
    });
    expect(affected.evidence.map((row) => row.outcome)).toEqual(['affected']);
    await observe(affected);
    const affectedView = await read(required('owner'), findingId, '198.51.100.120');
    expect(affectedView.statusCode).toBe(200);
    expect(affectedView.json()).toMatchObject({
      observationSource: 'latest_repeated',
      aggregate: 'affected',
      evidence: { kind: 'occurrence_support', affectedSupportCount: 1 },
    });
    expect(JSON.stringify(affectedView.json())).not.toContain('mappedResult');

    const unaffected = await later('unaffected', {
      receivedAt: new Date('2026-10-09T12:00:00.000Z'),
      versions: [{ version: '3.0.0', bomRef: 'component-unaffected' }],
    });
    expect(unaffected.evidence.map((row) => row.outcome)).toEqual(['unaffected']);
    await observe(unaffected);
    const unaffectedView = await read(required('owner'), findingId, '198.51.100.121');
    expect(unaffectedView.json()).toMatchObject({
      observationSource: 'latest_repeated',
      aggregate: 'unaffected',
      evidence: { kind: 'occurrence_support' },
    });
    expect(JSON.stringify(unaffectedView.json())).not.toMatch(/"(present|absent|inconclusive)"/);

    const unknown = await later('unknown', {
      receivedAt: new Date('2026-10-10T12:00:00.000Z'),
      versions: [{ version: 'not-a-version', bomRef: 'component-unknown' }],
    });
    expect(unknown.evidence.map((row) => row.outcome)).toEqual(['unknown']);
    await observe(unknown);
    const unknownView = await read(required('owner'), findingId, '198.51.100.122');
    expect(unknownView.json()).toMatchObject({
      observationSource: 'latest_repeated',
      aggregate: 'unknown',
      evidence: { kind: 'occurrence_support' },
    });

    const absent = await later('absent', {
      receivedAt: new Date('2026-10-11T12:00:00.000Z'),
      otherComponent: { name: 'other-widget', version: '1.0.0', bomRef: 'other-1' },
    });
    await observe(absent);
    const before = await footprint(homeOrgId);
    const absentView = await read(required('owner'), findingId, '198.51.100.123');
    expect(absentView.statusCode).toBe(200);
    expect(absentView.json()).toMatchObject({
      observationSource: 'latest_repeated',
      aggregate: 'component_absent',
      evidence: { kind: 'component_absence', graphCompleteness: 'no_dependencies' },
    });
    expect(JSON.stringify(absentView.json())).not.toContain('componentCount');
    expect(JSON.stringify(absentView.json())).not.toContain('dependencyEdgeCount');
    expect(await footprint(homeOrgId)).toEqual(before);

    const hostileEvidenceId = affected.evidence[0]?.evidenceId;
    if (hostileEvidenceId === undefined) {
      throw new Error('missing later evidence');
    }
    await withUserTriggersDisabled('advisory_revision', async () => {
      await prisma.$executeRaw`
        UPDATE "advisory_revision" AS revision
        SET "withdrawal_classification" = 'withdrawn',
            "revision_disposition" = 'withdrawn'
        FROM "product_match_evaluation_evidence" AS evidence
        WHERE evidence."organization_id" = ${homeOrgId}::uuid
          AND evidence."id" = ${hostileEvidenceId}::uuid
          AND revision."id" = evidence."advisory_revision_id"
      `;
    });
    const beforeBrokenRead = await footprint(homeOrgId);
    const broken = await read(required('owner'), findingId, '198.51.100.124');
    expect(broken.statusCode).toBe(503);
    expect(broken.json().error).toMatchObject({
      code: 'internal',
      message: 'Finding operator is temporarily unavailable.',
    });
    expect(JSON.stringify(broken.json())).not.toContain('malformed');
    expect(JSON.stringify(broken.json())).not.toContain('normalization');
    expect(JSON.stringify(broken.json())).not.toContain(findingId);
    const inspected = await inspect(required('owner'), findingId, '198.51.100.125');
    expect(inspected.statusCode).toBe(200);
    expect(inspected.json()).toMatchObject({
      findingId,
      state: 'open',
      creationEvidenceApplicability: expect.any(String),
    });
    expect(inspected.json()).not.toHaveProperty('observationSource');
    expect(await footprint(homeOrgId)).toEqual(beforeBrokenRead);
  }, 180_000);

  async function createUser(
    passwordHash: string,
    organizationId: string,
    role: RoleName,
    label: string,
  ): Promise<{ userId: string; membershipId: string }> {
    const user = await prisma.user.create({
      data: { email: `${label}@synthetic.patchpilot.test`, displayName: label },
    });
    await prisma.localCredential.create({
      data: { userId: user.id, passwordHash, passwordRevision: 1 },
    });
    const membership = await prisma.membership.create({
      data: { organizationId, userId: user.id, role, status: 'active' },
    });
    return { userId: user.id, membershipId: membership.id };
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

  async function post(session: Session, payload: Record<string, unknown>, remoteAddress: string) {
    return app.inject({
      method: 'POST',
      url: '/findings',
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

  async function read(session: Session, id: string, remoteAddress: string) {
    return app.inject({
      method: 'GET',
      url: `/findings/${id}/latest-observation`,
      remoteAddress,
      headers: { cookie: session.cookie },
    });
  }

  async function inspect(session: Session, id: string, remoteAddress: string) {
    return app.inject({
      method: 'GET',
      url: `/findings/${id}`,
      remoteAddress,
      headers: { cookie: session.cookie },
    });
  }

  async function later(
    label: string,
    input: Omit<
      Parameters<typeof seedLaterControlledFindingIngestion>[1],
      'label' | 'organizationId' | 'target'
    >,
  ): Promise<LaterControlledFindingIngestion> {
    return seedLaterControlledFindingIngestion(prisma, {
      label: `latest-${label}-${randomUUID().slice(0, 8)}`,
      organizationId: homeOrgId,
      target: seed,
      ...input,
    });
  }

  async function observe(ingestion: LaterControlledFindingIngestion): Promise<void> {
    const support =
      ingestion.evidence.length === 0
        ? {
            schemaVersion: FINDING_REPEATED_OBSERVATION_ABSENCE_SUPPORT_SCHEMA_VERSION,
            kind: 'component_absence' as const,
            sbomIngestionId: ingestion.ingestionId,
            graphCompleteness: 'no_dependencies' as const,
            componentCount: ingestion.componentCount,
            occurrenceCardinality: ingestion.occurrenceCardinality,
            dependencyEdgeCount: ingestion.dependencyEdgeCount,
            expectedFindingComponentOccurrenceCount: 0 as const,
            normalizationVersion: 2 as const,
          }
        : {
            schemaVersion: FINDING_REPEATED_OBSERVATION_EVIDENCE_SUPPORT_SCHEMA_VERSION,
            kind: 'evidence_set' as const,
            productMatchEvidenceIds: ingestion.evidence
              .map((row) => row.evidenceId)
              .sort((left, right) => (left < right ? -1 : 1)),
            unknownVersionOccurrenceIds: [] as string[],
          };
    const correlationId = randomUUID();
    const trustedContext = {
      schemaVersion: FINDING_REPEATED_OBSERVATION_TRUSTED_CONTEXT_SCHEMA_VERSION,
      organizationId: actor.organizationId,
      actorId: actor.actorId,
      membershipId: actor.membershipId,
      membershipStatus: 'active' as const,
    };
    const issued = issueFindingRepeatedObservationAuthorization({
      schemaVersion: FINDING_REPEATED_OBSERVATION_AUTHORIZATION_SCHEMA_VERSION,
      trustedContext,
      purpose: FINDING_REPEATED_OBSERVATION_PURPOSE,
      policyId: FINDING_REPEATED_OBSERVATION_POLICY_ID,
      policyVersion: FINDING_REPEATED_OBSERVATION_POLICY_VERSION,
      findingId,
      assetId: seed.assetId,
      componentId: seed.componentId,
      vulnerabilityId: seed.vulnerabilityId,
      sbomIngestionId: ingestion.ingestionId,
      support,
      correlationId,
    });
    if (issued.status !== 'authorized') {
      throw new Error(`observation authorization was ${issued.status}`);
    }
    const opened = openFindingRepeatedObservationCommand({
      schemaVersion: FINDING_REPEATED_OBSERVATION_COMMAND_SCHEMA_VERSION,
      purpose: FINDING_REPEATED_OBSERVATION_PURPOSE,
      policyId: FINDING_REPEATED_OBSERVATION_POLICY_ID,
      policyVersion: FINDING_REPEATED_OBSERVATION_POLICY_VERSION,
      expectedFindingId: findingId,
      expectedAssetId: seed.assetId,
      expectedComponentId: seed.componentId,
      expectedVulnerabilityId: seed.vulnerabilityId,
      expectedSbomIngestionId: ingestion.ingestionId,
      support,
      correlationId,
      authorization: issued.authorization,
    });
    if (opened.status !== 'authorized') {
      throw new Error(`observation command was ${opened.status}`);
    }
    const applied = await createControlledFindingRepeatedObservationPersistence(prisma).apply({
      trustedContext,
      command: opened.command,
    });
    if (applied.status !== 'observed') {
      throw new Error(`observation was ${applied.status}`);
    }
  }

  async function withUserTriggersDisabled(
    table: 'advisory_revision',
    body: () => Promise<void>,
  ): Promise<void> {
    try {
      await prisma.$executeRawUnsafe(`ALTER TABLE "${table}" DISABLE TRIGGER USER`);
      await body();
    } finally {
      await prisma.$executeRawUnsafe(`ALTER TABLE "${table}" ENABLE TRIGGER USER`);
    }
  }

  async function footprint(organizationId: string): Promise<string> {
    const rows = await prisma.$queryRaw<Array<{ line: string }>>`
      SELECT line
      FROM (
        SELECT 'finding|' || "id"::text || '|' || "state"::text || '|' || "version"::text || '|' ||
               "updated_at"::text || '|' || "last_observed_at"::text || '|' ||
               COALESCE("resolved_at"::text, '') || '|' || COALESCE("reopened_at"::text, '') || '|' ||
               COALESCE("assigned_membership_id"::text, '') || '|' ||
               COALESCE("due_at"::text, '') || '|' ||
               COALESCE("current_risk_calculation_id"::text, '') AS line
        FROM "finding"
        WHERE "organization_id" = ${organizationId}::uuid
        UNION ALL
        SELECT 'observation|' || "id"::text || '|' || "method" || '|' || "observed_at"::text
        FROM "finding_observation"
        WHERE "organization_id" = ${organizationId}::uuid
        UNION ALL
        SELECT 'creation-link|' || "id"::text || '|' || "created_at"::text
        FROM "finding_creation_evidence_link"
        WHERE "organization_id" = ${organizationId}::uuid
        UNION ALL
        SELECT 'repeated-link|' || "id"::text || '|' || "created_at"::text
        FROM "finding_repeated_observation_evidence_link"
        WHERE "organization_id" = ${organizationId}::uuid
        UNION ALL
        SELECT 'evidence|' || "id"::text || '|' || "created_at"::text || '|' || "outcome"::text
        FROM "product_match_evaluation_evidence"
        WHERE "organization_id" = ${organizationId}::uuid
        UNION ALL
        SELECT 'occurrence|' || "id"::text || '|' || "created_at"::text
        FROM "component_occurrence"
        WHERE "organization_id" = ${organizationId}::uuid
        UNION ALL
        SELECT 'ingestion|' || "id"::text || '|' || "state"::text || '|' || "updated_at"::text
        FROM "sbom_ingestion"
        WHERE "organization_id" = ${organizationId}::uuid
        UNION ALL
        SELECT 'asset|' || "id"::text || '|' || "lifecycle_status"::text || '|' || "updated_at"::text
        FROM "asset"
        WHERE "organization_id" = ${organizationId}::uuid
        UNION ALL
        SELECT 'membership|' || "id"::text || '|' || "status"::text || '|' || "version"::text || '|' ||
               "updated_at"::text
        FROM "membership"
        WHERE "organization_id" = ${organizationId}::uuid
        UNION ALL
        SELECT 'audit|' || "id"::text || '|' || "action"
        FROM "audit_event"
        WHERE "organization_id" = ${organizationId}::uuid
        UNION ALL
        SELECT 'session|' || "id"::text || '|' || COALESCE("active_organization_id"::text, '') || '|' ||
               COALESCE("revoked_at"::text, '') || '|' || "absolute_expires_at"::text
        FROM "session"
        WHERE "active_organization_id" = ${organizationId}::uuid
      ) AS rows
      ORDER BY line
    `;
    return rows.map((row) => row.line).join('\n');
  }
});
