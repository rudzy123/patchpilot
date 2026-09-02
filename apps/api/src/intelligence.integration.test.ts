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
import {
  intelligenceProviderListResponseSchema,
  intelligenceProviderStatusSchema,
  type IntelligenceProviderListResponse,
  type IntelligenceProviderStatus,
  type SessionResponse,
} from '@patchpilot/contracts';
import {
  createIntelligenceStatusReader,
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
import { TEST_ORIGIN, VALID_PASSWORD, emptySbomRuntime } from './auth-test-harness.js';
import { createIntelligenceRuntime } from './intelligence-runtime.js';

const SOCKET_IP = '192.0.2.10';
const EMAIL = `intel-it-${randomUUID()}@synthetic.patchpilot.test`;

describe('intelligence provider status routes persistence', () => {
  const config = loadServerConfigFrom(createFoundationTestEnv());
  const prisma = getPrismaClient({ databaseUrl: config.databaseUrl });
  const hasher = createArgon2PasswordHasher();
  let homeOrganizationId: string;
  let secondOrganizationId: string;

  beforeAll(async () => {
    const passwordHash = await hasher.hash(
      VALID_PASSWORD,
      argon2ParametersFromAuthConfig(config.auth),
    );
    const user = await prisma.user.create({
      data: { email: EMAIL, displayName: 'Intelligence Integration Viewer' },
    });
    await prisma.localCredential.create({
      data: { userId: user.id, passwordHash, passwordRevision: 1 },
    });
    const home = await prisma.organization.create({
      data: { slug: `intel-home-${randomUUID().slice(0, 8)}`, name: 'Intel Home' },
    });
    const foreign = await prisma.organization.create({
      data: { slug: `intel-foreign-${randomUUID().slice(0, 8)}`, name: 'Intel Foreign' },
    });
    homeOrganizationId = home.id;
    secondOrganizationId = foreign.id;
    await prisma.membership.create({
      data: { organizationId: home.id, userId: user.id, role: 'viewer', status: 'active' },
    });
    await prisma.membership.create({
      data: { organizationId: foreign.id, userId: user.id, role: 'member', status: 'active' },
    });
  });

  afterAll(async () => {
    await disconnectPrisma();
    resetPrismaClientForTests();
  });

  it('reads sanitized global provider status without Findings, writes, or provider I/O', async () => {
    const app = await buildApp();
    const loggedIn = await login(app);
    const selectedHome = await app.inject({
      method: 'POST',
      url: '/auth/select-organization',
      remoteAddress: SOCKET_IP,
      headers: {
        origin: TEST_ORIGIN,
        'content-type': 'application/json',
        cookie: loggedIn.cookie,
        'x-csrf-token': loggedIn.csrf,
      },
      payload: { organizationId: homeOrganizationId },
    });
    expect(selectedHome.statusCode).toBe(200);
    const session = sessionFrom(selectedHome, config.auth.cookieName);
    const before = await snapshotCounts();
    const sourceBefore = await prisma.intelligenceSource.findUnique({
      where: { providerKey: 'cisa_kev' },
    });
    const representativeFinding = await prisma.finding.findFirst();
    const representativeVulnerability = await prisma.vulnerability.findFirst();

    const listed = await app.inject({
      method: 'GET',
      url: '/intelligence/providers',
      remoteAddress: SOCKET_IP,
      headers: { cookie: session.cookie },
    });
    const kev = await app.inject({
      method: 'GET',
      url: '/intelligence/providers/cisa_kev/status',
      remoteAddress: SOCKET_IP,
      headers: { cookie: session.cookie },
    });
    const osv = await app.inject({
      method: 'GET',
      url: '/intelligence/providers/osv/status',
      remoteAddress: SOCKET_IP,
      headers: { cookie: session.cookie },
    });

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
    const kevBody = intelligenceProviderStatusSchema.parse(
      kev.json() as IntelligenceProviderStatus,
    );
    const osvBody = intelligenceProviderStatusSchema.parse(
      osv.json() as IntelligenceProviderStatus,
    );
    expect(osvBody.healthStatus).toBe('deferred');
    expect(osvBody.runtimeEnabled).toBe(false);
    expect(osvBody.lastAttemptAt).toBeNull();
    expect(osvBody.lastSafeFailureCode).toBeNull();
    expect(kevBody.provider).toBe('cisa_kev');
    expect(['never_synchronized', 'current', 'stale', 'degraded', 'disabled']).toContain(
      kevBody.healthStatus,
    );
    expect(JSON.stringify(listBody)).not.toContain('objectKey');
    expect(JSON.stringify(listBody)).not.toContain('organizationId');
    expect(JSON.stringify(listBody)).not.toContain(secondOrganizationId);

    const selected = await app.inject({
      method: 'POST',
      url: '/auth/select-organization',
      remoteAddress: SOCKET_IP,
      headers: {
        origin: TEST_ORIGIN,
        'content-type': 'application/json',
        cookie: session.cookie,
        'x-csrf-token': session.csrf,
      },
      payload: { organizationId: secondOrganizationId },
    });
    expect(selected.statusCode).toBe(200);
    const nextSession = sessionFrom(selected, config.auth.cookieName);
    const listedAgain = await app.inject({
      method: 'GET',
      url: '/intelligence/providers',
      remoteAddress: SOCKET_IP,
      headers: { cookie: nextSession.cookie },
    });
    expect(listedAgain.statusCode).toBe(200);
    expect(listedAgain.json()).toEqual(listed.json());

    const after = await snapshotCounts();
    expect(after).toEqual(before);
    const sourceAfter = await prisma.intelligenceSource.findUnique({
      where: { providerKey: 'cisa_kev' },
    });
    expect(sourceAfter).toEqual(sourceBefore);
    if (representativeFinding !== null) {
      expect(
        await prisma.finding.findUnique({ where: { id: representativeFinding.id } }),
      ).toMatchObject({ id: representativeFinding.id, state: representativeFinding.state });
    }
    if (representativeVulnerability !== null) {
      expect(
        await prisma.vulnerability.findUnique({ where: { id: representativeVulnerability.id } }),
      ).toMatchObject({
        id: representativeVulnerability.id,
        osvId: representativeVulnerability.osvId,
      });
    }
    await app.close();
  });
});

async function snapshotCounts() {
  const prisma = getPrismaClient();
  return {
    findings: await prisma.finding.count(),
    observations: await prisma.findingObservation.count(),
    vulnerabilities: await prisma.vulnerability.count(),
    aliases: await prisma.vulnerabilityAlias.count(),
    sourceRecords: await prisma.vulnerabilitySourceRecord.count(),
    components: await prisma.component.count(),
    occurrences: await prisma.componentOccurrence.count(),
    syncOutbox: await prisma.outboxEvent.count({
      where: { eventType: 'intelligence.sync.requested.v1' },
    }),
    recalculateOutbox: await prisma.outboxEvent.count({
      where: { eventType: 'finding.recalculate' },
    }),
    jobs: await prisma.backgroundJob.count(),
    intelligenceAudits: await prisma.auditEvent.count({
      where: { action: { startsWith: 'intelligence.status' } },
    }),
    intelligenceSourceWrites: await prisma.intelligenceSource.count(),
  };
}

async function buildApp() {
  const config = loadServerConfigFrom(createFoundationTestEnv());
  const logger = createLogger({
    service: 'api-intelligence-integration',
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
    assets: createAssetRuntime({
      assets: repos.assets,
      environments: repos.environments,
      teams: repos.teams,
      memberships: repos.memberships,
      unitOfWork: createPrismaUnitOfWork({ client: prisma }),
      clock,
    }),
    sboms: emptySbomRuntime(),
    intelligence: createIntelligenceRuntime({
      status: createIntelligenceStatusReader(prisma),
      kevEnabled: config.intelligence.kevEnabled,
      staleThresholdSeconds: config.intelligence.kevStaleThresholdSeconds,
      now: () => clock.now(),
    }),
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
    payload: { email: EMAIL, password: VALID_PASSWORD },
  });
  expect(loggedIn.statusCode).toBe(200);
  const config = loadServerConfigFrom(createFoundationTestEnv());
  return sessionFrom(loggedIn, config.auth.cookieName);
}

function sessionFrom(
  response: { headers: { [key: string]: unknown }; json: () => unknown },
  cookieName: string,
): { cookie: string; csrf: string } {
  const header = response.headers['set-cookie'];
  const setCookie =
    typeof header === 'string'
      ? header
      : Array.isArray(header) && typeof header[0] === 'string'
        ? header[0]
        : undefined;
  if (setCookie === undefined) {
    throw new Error('expected Set-Cookie');
  }
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
