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
  INSTANCE_ADVISORY_AUTHORITY_COMMAND_SCHEMA_VERSION,
  parseInstanceAdvisoryAuthorityCommand,
  type InstanceAdvisoryAuthority,
  type InstanceAdvisoryAuthorityCommand,
} from '@patchpilot/domain/instance-advisory-authority';
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
  TEST_ORIGIN,
  VALID_PASSWORD,
  emptyAssetRuntime,
  emptyIntelligenceRuntime,
  emptySbomRuntime,
} from './auth-test-harness.js';
import { composeMaintainerReviewedAdvisoryRuntime } from './maintainer-reviewed-advisory-runtime.js';
import { createInstanceAdvisoryAuthorityPersistence } from '../../../packages/database/src/instance-advisory-authority-persistence.js';

type Session = { cookie: string; csrf: string };

describe('maintainer-reviewed advisory API persistence', () => {
  const config = loadServerConfigFrom(
    createIntegrationDatabaseTestEnv(readDisposableIntegrationDatabaseUrl()),
  );
  const logger = createLogger({
    service: 'api-advisory-integration',
    level: 'silent',
    pretty: false,
  });
  const prisma = getPrismaClient({ databaseUrl: config.databaseUrl });
  const repos = createRepositories(prisma);
  const hasher = createArgon2PasswordHasher();
  const tokens = createNodeRandomTokenGenerator();
  const clock = createSystemClock();
  const limiter = createFakeLoginRateLimiter({ auth: config.auth, logger, clock });
  const authority = createInstanceAdvisoryAuthorityPersistence(prisma);
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
  let sequence = 0;
  const sessions = new Map<string, Session>();
  const users = new Map<string, string>();
  const grants = new Map<string, string>();

  beforeAll(async () => {
    const passwordHash = await hasher.hash(
      VALID_PASSWORD,
      argon2ParametersFromAuthConfig(config.auth),
    );
    for (const label of [
      'submitter',
      'author-b',
      'reviewer-a',
      'reviewer-b',
      'stranger',
      'disabled',
    ]) {
      users.set(label, await createUser(passwordHash, label));
    }
    grants.set('submitter', await grant(requiredUser('submitter'), 'advisory_submit_local'));
    await grant(requiredUser('author-b'), 'advisory_submit_local');
    await grant(requiredUser('reviewer-a'), 'advisory_approve_for_product_evaluation');
    await grant(requiredUser('reviewer-b'), 'advisory_approve_for_product_evaluation');
    await grant(requiredUser('disabled'), 'advisory_submit_local');
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
      findings: {
        creation: {
          async execute() {
            return { status: 'authority_required' };
          },
        },
        inspection: {
          async execute() {
            return { status: 'authority_required' };
          },
        },
        latestObservation: {
          async execute() {
            return { status: 'authority_required' };
          },
        },
      },
      advisories: composeMaintainerReviewedAdvisoryRuntime(prisma),
    });
    let address = 20;
    for (const label of users.keys()) {
      sessions.set(label, await login(`${label}@synthetic.patchpilot.test`, `192.0.2.${address}`));
      address += 1;
    }
  }, 180_000);

  afterAll(async () => {
    await app?.close();
    await disconnectPrisma();
    resetPrismaClientForTests();
  });

  it('submits, replays, conflicts, approves, and writes no downstream product rows', async () => {
    const originalFetch = globalThis.fetch;
    let providerCalls = 0;
    globalThis.fetch = async () => {
      providerCalls += 1;
      throw new Error('provider contact during advisory route');
    };
    const before = await downstreamCounts();
    try {
      const stranger = await submit(
        session('stranger'),
        document(requiredUser('stranger')),
        '198.51.100.1',
      );
      expect(stranger.statusCode).toBe(403);
      expect(stranger.json().error.message).toBe('Advisory authority was not granted.');
      expect(stranger.headers['cache-control']).toBe('private, no-store');

      const body = document(requiredUser('submitter'));
      const created = await submit(session('submitter'), body, '198.51.100.2');
      expect(created.statusCode).toBe(201);
      expect(created.headers['cache-control']).toBe('private, no-store');
      const createdBody = created.json() as {
        schemaVersion: string;
        result: string;
        advisoryRevisionId: string;
      };
      expect(Object.keys(createdBody).sort()).toEqual([
        'advisoryRevisionId',
        'result',
        'schemaVersion',
      ]);
      expect(createdBody.result).toBe('submitted');
      const revisionId = createdBody.advisoryRevisionId;
      expect(JSON.stringify(createdBody)).not.toContain('left-pad');
      expect(JSON.stringify(createdBody)).not.toContain('fingerprint');

      const replay = await submit(session('submitter'), body, '198.51.100.3');
      expect(replay.statusCode).toBe(200);
      expect(replay.json()).toEqual({ ...createdBody, result: 'already_applied' });
      expect(await auditsFor(revisionId)).toBe(1);

      const conflict = await submit(
        session('author-b'),
        document(requiredUser('author-b'), {
          family: body.advisoryFamilyId as string,
          packageName: 'changed-pad',
        }),
        '198.51.100.4',
      );
      expect(conflict.statusCode).toBe(409);
      expect(conflict.json().error.message).toBe('The request conflicts with the stored advisory.');
      expect(JSON.stringify(conflict.json())).not.toContain('changed-pad');
      expect(await auditsFor(revisionId)).toBe(1);

      const submitterApproval = await approve(session('submitter'), revisionId, '198.51.100.5');
      expect(submitterApproval.statusCode).toBe(403);
      expect(submitterApproval.json().error.message).toBe('Advisory authority was not granted.');

      const approved = await approve(session('reviewer-a'), revisionId, '198.51.100.6');
      expect(approved.statusCode).toBe(201);
      expect(approved.json()).toEqual({
        schemaVersion: 'maintainer_reviewed_advisory_approval_transport_v1',
        result: 'approved',
        advisoryRevisionId: revisionId,
      });
      expect(JSON.stringify(approved.json())).not.toMatch(/capability|seal|issuer|fingerprint/i);
      const approvedAudits = await auditsFor(revisionId);
      expect(approvedAudits).toBe(2);

      const approvalReplay = await approve(session('reviewer-a'), revisionId, '198.51.100.7');
      expect(approvalReplay.statusCode).toBe(200);
      expect(approvalReplay.json()).toMatchObject({
        result: 'already_applied',
        advisoryRevisionId: revisionId,
      });
      expect(await auditsFor(revisionId)).toBe(approvedAudits);

      const otherReviewer = await approve(session('reviewer-b'), revisionId, '198.51.100.8');
      expect(otherReviewer.statusCode).toBe(409);
      expect(otherReviewer.json().error.message).toBe(
        'The request conflicts with the stored advisory.',
      );
      expect(await auditsFor(revisionId)).toBe(approvedAudits);
      expect(
        await prisma.maintainerReviewedAdvisoryApproval.count({
          where: { advisoryRevisionId: revisionId },
        }),
      ).toBe(1);

      const own = document(requiredUser('submitter'));
      const ownCreated = await submit(session('submitter'), own, '198.51.100.9');
      expect(ownCreated.statusCode).toBe(201);
      const ownRevision = (ownCreated.json() as { advisoryRevisionId: string }).advisoryRevisionId;
      await revoke(requiredUser('submitter'), requiredGrant('submitter'), 'advisory_submit_local');
      await grant(requiredUser('submitter'), 'advisory_approve_for_product_evaluation');
      const capabilitiesBefore = await prisma.reviewerCapabilityIssuance.count();
      const selfApproval = await approve(session('submitter'), ownRevision, '198.51.100.10');
      expect(selfApproval.statusCode).toBe(403);
      expect(selfApproval.json().error.message).toBe('The approval was not recorded.');
      expect(JSON.stringify(selfApproval.json())).not.toMatch(/capability|seal|separation|author/i);
      expect(await prisma.reviewerCapabilityIssuance.count()).toBe(capabilitiesBefore);
      expect(
        await prisma.maintainerReviewedAdvisoryApproval.count({
          where: { advisoryRevisionId: ownRevision },
        }),
      ).toBe(0);

      const malformedBody = document(requiredUser('author-b'));
      const malformedCreated = await submit(session('author-b'), malformedBody, '198.51.100.11');
      expect(malformedCreated.statusCode).toBe(201);
      const malformedRevision = (malformedCreated.json() as { advisoryRevisionId: string })
        .advisoryRevisionId;
      const storedAudit = await prisma.auditEvent.findFirstOrThrow({
        where: { subjectId: malformedRevision },
      });
      await prisma.auditEvent.create({
        data: {
          actorUserId: storedAudit.actorUserId,
          actorType: storedAudit.actorType,
          action: storedAudit.action,
          subjectType: storedAudit.subjectType,
          subjectId: storedAudit.subjectId,
          correlationId: randomUUID(),
          payload: storedAudit.payload as object,
          schemaVersion: storedAudit.schemaVersion,
          retentionCategory: storedAudit.retentionCategory,
        },
      });
      const malformed = await submit(session('author-b'), malformedBody, '198.51.100.12');
      expect(malformed.statusCode).toBe(503);
      expect(malformed.headers['cache-control']).toBe('private, no-store');
      expect(malformed.json().error.message).toBe(
        'Maintainer-reviewed advisory storage is temporarily unavailable.',
      );
      const malformedJson = JSON.stringify(malformed.json());
      expect(malformedJson).not.toContain('left-pad');
      expect(malformedJson).not.toMatch(/select|prisma|constraint|fingerprint/i);
      expect(await auditsFor(malformedRevision)).toBe(2);

      const disabled = await submit(
        session('disabled'),
        document(requiredUser('disabled')),
        '198.51.100.13',
      );
      await authority.execute(disableCommand(requiredUser('disabled')));
      const disabledAfter = await submit(
        session('disabled'),
        document(requiredUser('disabled')),
        '198.51.100.14',
      );
      expect(disabled.statusCode).toBe(201);
      expect(disabledAfter.statusCode).toBe(401);
      expect(disabledAfter.json().error.message).toBe('Authentication required.');

      expect(providerCalls).toBe(0);
      expect(await downstreamCounts()).toEqual(before);
    } finally {
      globalThis.fetch = originalFetch;
    }
  }, 120_000);

  it('returns a confidential 503 when the composed adapter cannot reach the database', async () => {
    const dead = await buildApi({
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
      findings: {
        creation: {
          async execute() {
            return { status: 'authority_required' };
          },
        },
        inspection: {
          async execute() {
            return { status: 'authority_required' };
          },
        },
        latestObservation: {
          async execute() {
            return { status: 'authority_required' };
          },
        },
      },
      advisories: composeMaintainerReviewedAdvisoryRuntime({
        async $transaction() {
          throw new Error("Can't reach database server at 127.0.0.1:1");
        },
      } as unknown as Parameters<typeof composeMaintainerReviewedAdvisoryRuntime>[0]),
    });
    try {
      const response = await dead.inject({
        method: 'POST',
        url: '/intelligence/maintainer-reviewed-advisories',
        remoteAddress: '198.51.100.200',
        headers: {
          origin: TEST_ORIGIN,
          'content-type': 'application/json',
          cookie: session('submitter').cookie,
          'x-csrf-token': session('submitter').csrf,
        },
        payload: document(requiredUser('submitter')),
      });
      expect(response.statusCode).toBe(503);
      expect(response.headers['cache-control']).toBe('private, no-store');
      expect(response.json().error.message).toBe(
        'Maintainer-reviewed advisory storage is temporarily unavailable.',
      );
      expect(JSON.stringify(response.json())).not.toMatch(/database server|127\.0\.0\.1|prisma/i);
    } finally {
      await dead.close();
    }
  });

  async function createUser(passwordHash: string, label: string): Promise<string> {
    const user = await prisma.user.create({
      data: {
        email: `${label}@synthetic.patchpilot.test`,
        displayName: label,
      },
    });
    await prisma.localCredential.create({
      data: { userId: user.id, passwordHash, passwordRevision: 1 },
    });
    return user.id;
  }

  async function grant(userId: string, authorityName: InstanceAdvisoryAuthority): Promise<string> {
    const granted = await authority.execute(
      authorityCommand({
        schemaVersion: INSTANCE_ADVISORY_AUTHORITY_COMMAND_SCHEMA_VERSION,
        operation: 'grant',
        targetUserId: userId,
        authority: authorityName,
        issuanceClassification: 'deployment_local_command',
        correlationId: randomUUID(),
      }),
    );
    if (granted.outcome !== 'granted') {
      throw new Error(`grant failed: ${granted.outcome}`);
    }
    return granted.grantId;
  }

  async function revoke(
    userId: string,
    expectedGrantId: string,
    expectedAuthority: InstanceAdvisoryAuthority,
  ): Promise<void> {
    const revoked = await authority.execute(
      authorityCommand({
        schemaVersion: INSTANCE_ADVISORY_AUTHORITY_COMMAND_SCHEMA_VERSION,
        operation: 'revoke',
        targetUserId: userId,
        expectedGrantId,
        expectedAuthority,
        correlationId: randomUUID(),
      }),
    );
    if (revoked.outcome !== 'revoked') {
      throw new Error(`revoke failed: ${revoked.outcome}`);
    }
  }

  function document(userId: string, overrides: { family?: string; packageName?: string } = {}) {
    sequence += 1;
    return {
      schemaVersion: 'maintainer_reviewed_advisory_document_v1',
      advisoryFamilyId:
        overrides.family ??
        `FAMILYAPI${String(sequence).padStart(4, '0')}${randomUUID().replaceAll('-', '').slice(0, 8).toUpperCase()}`,
      revisionNumber: 1,
      vulnerabilityId: randomUUID(),
      aliases: [`CVE-2026-${String(20000 + sequence)}`],
      packageEcosystem: 'npm',
      packageName: overrides.packageName ?? 'left-pad',
      packageUrl: null,
      affectedRanges: [{ type: 'SEMVER', events: [{ introduced: '1.0.0' }, { fixed: '1.2.0' }] }],
      withdrawal: 'not_withdrawn',
      supersedesRevisionId: null,
      sourceLicenseDecision: {
        policyId: 'maintainer_reviewed_source_license_policy_v1',
        policyVersion: 1,
        spdxLicenseId: 'CC-BY-4.0',
        productUse: 'permitted_for_internal_matching',
        modification: 'permitted',
        redistribution: 'permitted',
        notice: 'required',
        contentProvenance: 'maintainer_original',
        decision: 'accepted',
      },
      authorIdentity: userId,
      submissionCorrelationId: randomUUID(),
    };
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

  async function submit(current: Session, payload: Record<string, unknown>, remoteAddress: string) {
    return app.inject({
      method: 'POST',
      url: '/intelligence/maintainer-reviewed-advisories',
      remoteAddress,
      headers: {
        origin: TEST_ORIGIN,
        'content-type': 'application/json',
        cookie: current.cookie,
        'x-csrf-token': current.csrf,
      },
      payload,
    });
  }

  async function approve(current: Session, revisionId: string, remoteAddress: string) {
    return app.inject({
      method: 'POST',
      url: `/intelligence/maintainer-reviewed-advisories/${revisionId}/approval`,
      remoteAddress,
      headers: {
        origin: TEST_ORIGIN,
        'content-type': 'application/json',
        cookie: current.cookie,
        'x-csrf-token': current.csrf,
      },
      payload: {},
    });
  }

  async function auditsFor(revisionId: string): Promise<number> {
    return prisma.auditEvent.count({ where: { subjectId: revisionId } });
  }

  async function downstreamCounts() {
    const [productMatch, findings, observations] = await Promise.all([
      prisma.productMatchEvaluationEvidence.count(),
      prisma.finding.count(),
      prisma.findingObservation.count(),
    ]);
    return { productMatch, findings, observations };
  }

  function session(label: string): Session {
    const current = sessions.get(label);
    if (current === undefined) {
      throw new Error(`missing session ${label}`);
    }
    return current;
  }

  function requiredUser(label: string): string {
    const userId = users.get(label);
    if (userId === undefined) {
      throw new Error(`missing user ${label}`);
    }
    return userId;
  }

  function requiredGrant(label: string): string {
    const grantId = grants.get(label);
    if (grantId === undefined) {
      throw new Error(`missing grant ${label}`);
    }
    return grantId;
  }
});

function authorityCommand(input: unknown): InstanceAdvisoryAuthorityCommand {
  const parsed = parseInstanceAdvisoryAuthorityCommand(input);
  if (!parsed.ok) {
    throw new Error('authority command was rejected');
  }
  return parsed.command;
}

function disableCommand(userId: string): InstanceAdvisoryAuthorityCommand {
  return authorityCommand({
    schemaVersion: INSTANCE_ADVISORY_AUTHORITY_COMMAND_SCHEMA_VERSION,
    operation: 'disable_user',
    targetUserId: userId,
    correlationId: randomUUID(),
  });
}
