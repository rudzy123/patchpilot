import { randomUUID } from 'node:crypto';
import { Writable } from 'node:stream';

import {
  createFakeLoginRateLimiter,
  createListActiveOrganizationsUseCase,
  createLoginUseCase,
  createLogoutUseCase,
  createNodeRandomTokenGenerator,
  createReadSessionUseCase,
  createResolveSessionUseCase,
  createSelectOrganizationUseCase,
  createSystemClock,
  type Clock,
  type FakeLoginRateLimiter,
  type PasswordHasher,
} from '@patchpilot/auth';
import { loadServerConfigFrom, type ServerConfig } from '@patchpilot/config';
import type {
  ActiveMembershipWithOrganization,
  AppendAuditEventInput,
  AuditEventRecord,
  CreateSessionInput,
  LocalCredentialRecord,
  LocalCredentialRepository,
  MembershipRecord,
  MembershipRepository,
  OrganizationRecord,
  ReplaceCsrfTokenInput,
  RotateSessionInput,
  SessionRecord,
  SessionRepository,
  UserRecord,
  UserRepository,
} from '@patchpilot/domain';
import {
  ASSET_NOT_FOUND,
  JSON_SCHEMA_VERSION_V1,
  ORGANIZATION_CONTEXT_REQUIRED,
  SBOM_NOT_FOUND,
  SBOM_UPLOAD_INTERNAL,
} from '@patchpilot/domain';
import { createLogger, type Logger } from '@patchpilot/logger';
import { createFoundationTestEnv } from '@patchpilot/test-utils';

import { buildApi } from './app.js';
import type { AssetRuntime } from './asset-runtime.js';
import type { AuthRuntime } from './auth-runtime.js';
import type { DatabaseReadyCheck } from './app.js';
import { createIntelligenceRuntime, type IntelligenceRuntime } from './intelligence-runtime.js';
import type { SbomRuntime } from './sbom-runtime.js';

export const VALID_PASSWORD = 'correct-horse-battery';
export const TEST_ORIGIN = 'http://127.0.0.1:3000';
const STORED_PASSWORD_HASH = '$argon2id$v=19$m=8192,p=1,t=1$stored-local-credential-hash';

export type MemoryAuditAppend = {
  events: AppendAuditEventInput[];
  append: AuthRuntime['audit']['append'];
};

export type AuthTestHarness = {
  config: ServerConfig;
  logger: Logger;
  logs: () => string;
  users: MemoryUserRepository;
  credentials: MemoryCredentialRepository;
  sessions: MemorySessionRepository;
  memberships: MemoryMembershipRepository;
  limiter: FakeLoginRateLimiter;
  audit: MemoryAuditAppend;
  user: UserRecord;
  organizations: OrganizationRecord[];
  auth: AuthRuntime;
};

export async function buildTestApi(options?: {
  config?: ServerConfig;
  logger?: Logger;
  membershipCount?: 0 | 1 | 2;
  primaryRole?: 'viewer' | 'member' | 'admin' | 'owner';
  limiterUnavailable?: boolean;
  now?: () => string;
  generateId?: () => string;
  checkDatabaseReady?: DatabaseReadyCheck;
  harness?: AuthTestHarness;
  assets?: AssetRuntime;
  sboms?: SbomRuntime;
  intelligence?: IntelligenceRuntime;
}) {
  const harness = options?.harness ?? createAuthTestHarness(options);
  const app = await buildApi({
    config: options?.config ?? harness.config,
    logger: options?.logger ?? harness.logger,
    checkDatabaseReady: options?.checkDatabaseReady ?? (async () => ({ ok: true })),
    auth: harness.auth,
    assets: options?.assets ?? emptyAssetRuntime(),
    sboms: options?.sboms ?? emptySbomRuntime(),
    intelligence:
      options?.intelligence ?? emptyIntelligenceRuntime(options?.config ?? harness.config),
    ...(options?.now === undefined ? {} : { now: options.now }),
    ...(options?.generateId === undefined ? {} : { generateId: options.generateId }),
  });
  return { app, harness };
}

export function createAuthTestHarness(options?: {
  membershipCount?: 0 | 1 | 2;
  primaryRole?: 'viewer' | 'member' | 'admin' | 'owner';
  limiterUnavailable?: boolean;
  config?: ServerConfig;
}): AuthTestHarness {
  const config = options?.config ?? loadServerConfigFrom(createFoundationTestEnv());
  const logs = collectingLogger();
  const clock: Clock = createSystemClock();
  const user = createUserRecord();
  const organizations = [
    createOrganizationRecord({ slug: 'org-one', name: 'One' }),
    createOrganizationRecord({ slug: 'org-two', name: 'Two' }),
  ];
  const membershipCount = options?.membershipCount ?? 1;
  const membershipRows = organizations.slice(0, membershipCount).map((organization, index) => ({
    organization,
    membership: createMembershipRecord(organization, user, {
      role: index === 0 ? (options?.primaryRole ?? 'owner') : 'member',
    }),
  }));
  const users = createMemoryUserRepository([user]);
  const credentials = createMemoryCredentialRepository([createCredentialRecord(user)]);
  const sessions = createMemorySessionRepository();
  const memberships = createMemoryMembershipRepository(membershipRows);
  const limiter = createFakeLoginRateLimiter({
    auth: config.auth,
    logger: logs.logger,
    clock,
    ...(options?.limiterUnavailable === true ? { unavailable: true } : {}),
  });
  const audit = createMemoryAuditAppend();
  const hasher = createFakePasswordHasher();
  const tokens = createNodeRandomTokenGenerator();
  const shared = {
    users,
    localCredentials: credentials,
    sessions,
    memberships,
    clock,
    auth: config.auth,
    logger: logs.logger,
  };
  const auth: AuthRuntime = {
    login: createLoginUseCase({
      ...shared,
      hasher,
      tokens,
      limiter,
    }),
    logout: createLogoutUseCase({
      sessions,
      clock,
      logger: logs.logger,
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
    audit,
  };

  return {
    config,
    logger: logs.logger,
    logs: logs.output,
    users,
    credentials,
    sessions,
    memberships,
    limiter,
    audit,
    user,
    organizations,
    auth,
  };
}

function emptyAssetRuntime(): AssetRuntime {
  const denied = {
    async execute() {
      return { ok: false as const, error: ORGANIZATION_CONTEXT_REQUIRED };
    },
  };
  return {
    list: {
      async execute() {
        return { ok: true as const, value: { items: [], nextCursor: undefined } };
      },
    },
    get: {
      async execute() {
        return { ok: false as const, error: ASSET_NOT_FOUND };
      },
    },
    create: denied,
    update: denied,
    archive: denied,
    listEnvironments: {
      async execute() {
        return { ok: true as const, value: { items: [], nextCursor: undefined } };
      },
    },
    listTeams: {
      async execute() {
        return { ok: true as const, value: { items: [], nextCursor: undefined } };
      },
    },
    listMemberships: {
      async execute() {
        return { ok: true as const, value: { items: [], nextCursor: undefined } };
      },
    },
  };
}

export function emptySbomRuntime(): SbomRuntime {
  return {
    upload: {
      async execute() {
        return { ok: false as const, error: SBOM_UPLOAD_INTERNAL };
      },
    },
    list: {
      async execute() {
        return { ok: false as const, error: ORGANIZATION_CONTEXT_REQUIRED };
      },
    },
    get: {
      async execute() {
        return { ok: false as const, error: SBOM_NOT_FOUND };
      },
    },
    getIngestion: {
      async execute() {
        return { ok: false as const, error: SBOM_NOT_FOUND };
      },
    },
  };
}

export function emptyIntelligenceRuntime(config: ServerConfig): IntelligenceRuntime {
  return createIntelligenceRuntime({
    status: {
      async loadCisaKevStatus() {
        return {
          kind: 'found' as const,
          snapshot: {
            sourceState: 'disabled',
            lastSuccessfulSyncAt: null,
            lastAttemptAt: null,
            lastFailureAt: null,
            lastFailureCode: null,
            activeGenerationId: null,
            generation: null,
          },
        };
      },
    },
    kevEnabled: config.intelligence.kevEnabled,
    staleThresholdSeconds: config.intelligence.kevStaleThresholdSeconds,
    now: () => new Date('2026-09-02T12:00:00.000Z'),
  });
}

function collectingLogger() {
  const chunks: string[] = [];
  const destination = new Writable({
    write(chunk, _encoding, callback) {
      chunks.push(String(chunk));
      callback();
    },
  });
  return {
    logger: createLogger({
      service: 'api-auth-test',
      level: 'info',
      pretty: false,
      destination,
    }),
    output: () => chunks.join(''),
  };
}

function createFakePasswordHasher(): PasswordHasher {
  const secrets = new Map<string, string>([[STORED_PASSWORD_HASH, VALID_PASSWORD]]);
  return {
    async hash(password) {
      const next = `$argon2id$v=19$m=8192,p=1,t=1$rehashed-${secrets.size}`;
      secrets.set(next, password);
      return next;
    },
    async verify(passwordHash, password) {
      return secrets.get(passwordHash) === password;
    },
    needsRehash() {
      return false;
    },
  };
}

function createMemoryAuditAppend(): MemoryAuditAppend {
  const events: AppendAuditEventInput[] = [];
  return {
    events,
    async append(input) {
      events.push(input);
      const record: AuditEventRecord = {
        id: randomUUID(),
        organizationId: input.organizationId ?? null,
        actorUserId: input.actorUserId ?? null,
        actorMembershipId: input.actorMembershipId ?? null,
        actorType: input.actorType,
        action: input.action,
        subjectType: input.subjectType,
        subjectId: input.subjectId,
        occurredAt: input.occurredAt ?? new Date(),
        requestId: input.requestId ?? null,
        correlationId: input.correlationId,
        sourceIp: input.sourceIp ?? null,
        userAgent: input.userAgent ?? null,
        payload: input.payload,
        schemaVersion: input.schemaVersion ?? JSON_SCHEMA_VERSION_V1,
        retentionCategory: input.retentionCategory ?? 'security',
      };
      return record;
    },
  };
}

type MemoryUserRepository = UserRepository & { users: Map<string, UserRecord> };

function createMemoryUserRepository(users: UserRecord[]): MemoryUserRepository {
  const byId = new Map(users.map((user) => [user.id, user]));
  return {
    users: byId,
    async findById(userId) {
      return byId.get(userId);
    },
    async findByNormalizedEmail(email) {
      const normalized = email.trim().toLowerCase();
      return [...byId.values()].find((user) => user.email === normalized);
    },
  };
}

type MemoryCredentialRepository = LocalCredentialRepository;

function createMemoryCredentialRepository(
  records: LocalCredentialRecord[],
): MemoryCredentialRepository {
  const credentials = new Map(records.map((record) => [record.userId, record]));
  return {
    async findByUserId(userId) {
      return credentials.get(userId);
    },
    async updatePasswordHash(input) {
      const current = credentials.get(input.userId);
      if (current === undefined) {
        return undefined;
      }
      const updated = {
        ...current,
        passwordHash: input.passwordHash,
        passwordRevision: input.passwordRevision,
      };
      credentials.set(input.userId, updated);
      return updated;
    },
  };
}

type MemorySessionRepository = SessionRepository & {
  byTokenHash: Map<string, SessionRecord>;
  createCalls: CreateSessionInput[];
  rotateCalls: RotateSessionInput[];
  replaceCsrfCalls: ReplaceCsrfTokenInput[];
};

function createMemorySessionRepository(records: SessionRecord[] = []): MemorySessionRepository {
  const byTokenHash = new Map(records.map((record) => [record.tokenHash, record]));
  const createCalls: CreateSessionInput[] = [];
  const rotateCalls: RotateSessionInput[] = [];
  const replaceCsrfCalls: ReplaceCsrfTokenInput[] = [];

  function find(tokenHash: string): SessionRecord | undefined {
    const found = byTokenHash.get(tokenHash);
    return found === undefined ? undefined : { ...found };
  }

  return {
    byTokenHash,
    createCalls,
    rotateCalls,
    replaceCsrfCalls,
    async create(input) {
      createCalls.push(input);
      const record: SessionRecord = {
        id: randomUUID(),
        userId: input.userId,
        tokenHash: input.tokenHash,
        csrfTokenHash: input.csrfTokenHash,
        activeOrganizationId: input.activeOrganizationId ?? null,
        authenticationMethod: input.authenticationMethod ?? 'password',
        passwordRevision: input.passwordRevision,
        createdAt: input.lastSeenAt,
        lastSeenAt: input.lastSeenAt,
        idleExpiresAt: input.idleExpiresAt,
        absoluteExpiresAt: input.absoluteExpiresAt,
        revokedAt: null,
        revokeReason: null,
        userAgent: input.userAgent ?? null,
      };
      byTokenHash.set(record.tokenHash, record);
      return { ...record };
    },
    async findByTokenHash(tokenHash) {
      return find(tokenHash);
    },
    async updateThrottledLastSeen(input) {
      const current = byTokenHash.get(input.tokenHash);
      if (current === undefined || current.revokedAt !== null) {
        return undefined;
      }
      if (current.lastSeenAt.getTime() > input.minLastSeenAt.getTime()) {
        return undefined;
      }
      const updated = {
        ...current,
        lastSeenAt: input.lastSeenAt,
        idleExpiresAt: input.idleExpiresAt,
      };
      byTokenHash.set(input.tokenHash, updated);
      return { ...updated };
    },
    async rotate(input) {
      rotateCalls.push(input);
      const current = byTokenHash.get(input.currentTokenHash);
      if (current === undefined || current.revokedAt !== null) {
        return undefined;
      }
      byTokenHash.delete(input.currentTokenHash);
      const updated: SessionRecord = {
        ...current,
        tokenHash: input.nextTokenHash,
        csrfTokenHash: input.nextCsrfTokenHash,
        lastSeenAt: input.lastSeenAt,
        idleExpiresAt: input.idleExpiresAt,
        activeOrganizationId:
          input.activeOrganizationId === undefined
            ? current.activeOrganizationId
            : input.activeOrganizationId,
      };
      byTokenHash.set(updated.tokenHash, updated);
      return { ...updated };
    },
    async replaceCsrfToken(input) {
      replaceCsrfCalls.push(input);
      const current = byTokenHash.get(input.tokenHash);
      if (current === undefined || current.revokedAt !== null) {
        return undefined;
      }
      const updated = { ...current, csrfTokenHash: input.nextCsrfTokenHash };
      byTokenHash.set(input.tokenHash, updated);
      return { ...updated };
    },
    async revokeCurrent(input) {
      const current = byTokenHash.get(input.tokenHash);
      if (current === undefined || current.revokedAt !== null) {
        return undefined;
      }
      const updated = {
        ...current,
        revokedAt: input.revokedAt,
        revokeReason: input.revokeReason,
      };
      byTokenHash.set(input.tokenHash, updated);
      return { ...updated };
    },
    async revokeAllForUser(input) {
      let count = 0;
      for (const [hash, record] of byTokenHash) {
        if (record.userId !== input.userId || record.revokedAt !== null) {
          continue;
        }
        byTokenHash.set(hash, {
          ...record,
          revokedAt: input.revokedAt,
          revokeReason: input.revokeReason,
        });
        count += 1;
      }
      return count;
    },
    async clearActiveOrganization(input) {
      let count = 0;
      for (const [hash, record] of byTokenHash) {
        if (
          record.userId !== input.userId ||
          record.activeOrganizationId !== input.organizationId
        ) {
          continue;
        }
        byTokenHash.set(hash, { ...record, activeOrganizationId: null });
        count += 1;
      }
      return count;
    },
  };
}

type MemoryMembershipRepository = MembershipRepository & {
  rows: ActiveMembershipWithOrganization[];
};

function createMemoryMembershipRepository(
  rows: ActiveMembershipWithOrganization[],
): MemoryMembershipRepository {
  return {
    rows,
    async create() {
      throw new Error('Membership create is not used by auth routes.');
    },
    async findById() {
      return undefined;
    },
    async findByUser() {
      return undefined;
    },
    async listForOrganization() {
      return { items: [], nextCursor: undefined };
    },
    async listActiveOptions() {
      return { items: [], nextCursor: undefined };
    },
    async listActiveInActiveOrganizationsForUser(userId) {
      return rows.filter(
        (row) =>
          row.membership.userId === userId &&
          row.membership.status === 'active' &&
          row.organization.status === 'active',
      );
    },
    async findActiveInActiveOrganization(userId, organizationId) {
      return rows.find(
        (row) =>
          row.membership.userId === userId &&
          row.membership.organizationId === organizationId &&
          row.membership.status === 'active' &&
          row.organization.status === 'active',
      );
    },
  };
}

function createUserRecord(): UserRecord {
  const now = new Date('2026-08-27T16:00:00.000Z');
  return {
    id: randomUUID(),
    email: 'owner@synthetic.patchpilot.test',
    displayName: 'Synthetic User',
    status: 'active',
    version: 1,
    disabledAt: null,
    createdAt: now,
    updatedAt: now,
  };
}

function createOrganizationRecord(overrides: { slug: string; name: string }): OrganizationRecord {
  const now = new Date('2026-08-27T16:00:00.000Z');
  return {
    id: randomUUID(),
    slug: overrides.slug,
    name: overrides.name,
    status: 'active',
    version: 1,
    archivedAt: null,
    createdAt: now,
    updatedAt: now,
  };
}

function createMembershipRecord(
  organization: OrganizationRecord,
  user: UserRecord,
  overrides: { role: MembershipRecord['role'] },
): MembershipRecord {
  const now = new Date('2026-08-27T16:00:00.000Z');
  return {
    id: randomUUID(),
    organizationId: organization.id,
    userId: user.id,
    role: overrides.role,
    status: 'active',
    invitedAt: null,
    joinedAt: now,
    revokedAt: null,
    version: 1,
    createdAt: now,
    updatedAt: now,
  };
}

function createCredentialRecord(user: UserRecord): LocalCredentialRecord {
  const now = new Date('2026-08-27T16:00:00.000Z');
  return {
    id: randomUUID(),
    userId: user.id,
    passwordHash: STORED_PASSWORD_HASH,
    passwordRevision: 1,
    algorithm: 'argon2id',
    createdAt: now,
    updatedAt: now,
  };
}
