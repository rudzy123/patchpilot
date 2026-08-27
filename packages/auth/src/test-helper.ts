import { randomUUID } from 'node:crypto';
import { Writable } from 'node:stream';

import type { AuthConfig } from '@patchpilot/config';
import { createLogger, type Logger } from '@patchpilot/logger';
import type {
  ActiveMembershipWithOrganization,
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

import type { Clock } from './clock.js';
import type { PasswordHasher } from './password-hasher.js';
import type { RandomTokenGenerator } from './random-token-generator.js';

export const TEST_NOW_ISO = '2026-08-27T16:00:00.000Z';
export const VALID_PASSWORD = 'correct-horse-battery';
export const TEST_PEER_IP = '192.0.2.10';
export const STORED_PASSWORD_HASH = '$argon2id$v=19$m=8192,p=1,t=1$stored-local-credential-hash';
export const RAW_SESSION_TOKEN = 'RAW_SESSION_TOKEN_VALUE_NOT_A_DIGEST';
export const RAW_CSRF_TOKEN = 'RAW_CSRF_TOKEN_VALUE_NOT_A_DIGEST';
export const ROTATED_SESSION_TOKEN = 'RAW_ROTATED_SESSION_TOKEN_NOT_DIGEST';
export const ROTATED_CSRF_TOKEN = 'RAW_ROTATED_CSRF_TOKEN_NOT_A_DIGEST';

export function createTestAuthConfig(overrides: Partial<AuthConfig> = {}): AuthConfig {
  return {
    sessionAbsoluteTtlSeconds: 604_800,
    sessionIdleTtlSeconds: 43_200,
    lastSeenMinIntervalSeconds: 60,
    cookieName: 'patchpilot.sid',
    cookieSecure: false,
    csrfHeaderName: 'x-csrf-token',
    passwordMinLength: 12,
    passwordMaxBytes: 128,
    argon2MemoryKib: 8_192,
    argon2TimeCost: 1,
    argon2Parallelism: 1,
    loginRateLimitIpMaxAttempts: 10,
    loginRateLimitIpWindowSeconds: 900,
    loginRateLimitAccountMaxAttempts: 5,
    loginRateLimitAccountWindowSeconds: 900,
    rateLimitRedisTimeoutMs: 200,
    ...overrides,
  };
}

export function createAdjustableClock(isoUtc: string = TEST_NOW_ISO): Clock & {
  set(isoUtc: string): void;
  advanceMs(milliseconds: number): void;
} {
  let current = new Date(isoUtc);
  return {
    now(): Date {
      return new Date(current.getTime());
    },
    set(nextIsoUtc: string): void {
      current = new Date(nextIsoUtc);
    },
    advanceMs(milliseconds: number): void {
      current = new Date(current.getTime() + milliseconds);
    },
  };
}

export function createCollectingLogger(): { logger: Logger; text: () => string } {
  const chunks: Array<Buffer | string> = [];
  const stream = new Writable({
    write(chunk, _encoding, callback) {
      chunks.push(chunk as Buffer | string);
      callback();
    },
  });
  return {
    logger: createLogger({
      service: 'auth-test',
      level: 'info',
      pretty: false,
      destination: stream,
    }),
    text: () => chunks.join(''),
  };
}

export type FakePasswordHasher = PasswordHasher & {
  verifyCalls: Array<{ passwordHash: string; password: string }>;
  hashCalls: string[];
  needsRehashCalls: string[];
  needsRehashResult: boolean;
};

export function createFakePasswordHasher(options?: {
  needsRehashResult?: boolean;
}): FakePasswordHasher {
  const secrets = new Map<string, string>([[STORED_PASSWORD_HASH, VALID_PASSWORD]]);
  const hasher: FakePasswordHasher = {
    verifyCalls: [],
    hashCalls: [],
    needsRehashCalls: [],
    needsRehashResult: options?.needsRehashResult ?? false,
    async hash(password) {
      hasher.hashCalls.push(password);
      const next = `$argon2id$v=19$m=8192,p=1,t=1$rehashed-${hasher.hashCalls.length}`;
      secrets.set(next, password);
      return next;
    },
    async verify(passwordHash, password) {
      hasher.verifyCalls.push({ passwordHash, password });
      return secrets.get(passwordHash) === password;
    },
    needsRehash(passwordHash) {
      hasher.needsRehashCalls.push(passwordHash);
      return hasher.needsRehashResult;
    },
  };
  return hasher;
}

export function createQueuedTokenGenerator(tokens: string[]): RandomTokenGenerator & {
  generated: string[];
} {
  const generated: string[] = [];
  return {
    generated,
    generate(byteLength: number): string {
      if (byteLength !== 32) {
        throw new Error(`Unexpected token byte length: ${byteLength}`);
      }
      const next = tokens[generated.length];
      if (next === undefined) {
        throw new Error('Token generator queue exhausted.');
      }
      generated.push(next);
      return next;
    },
  };
}

export type MemoryUserRepository = UserRepository & {
  users: Map<string, UserRecord>;
};

export function createMemoryUserRepository(users: UserRecord[] = []): MemoryUserRepository {
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

export type MemoryCredentialRepository = LocalCredentialRepository & {
  credentials: Map<string, LocalCredentialRecord>;
  updateCalls: Array<{ userId: string; passwordHash: string; passwordRevision: number }>;
};

export function createMemoryCredentialRepository(
  records: LocalCredentialRecord[] = [],
): MemoryCredentialRepository {
  const credentials = new Map(records.map((record) => [record.userId, record]));
  const updateCalls: MemoryCredentialRepository['updateCalls'] = [];
  return {
    credentials,
    updateCalls,
    async findByUserId(userId) {
      return credentials.get(userId);
    },
    async updatePasswordHash(input) {
      updateCalls.push(input);
      const current = credentials.get(input.userId);
      if (current === undefined) {
        return undefined;
      }
      const updated: LocalCredentialRecord = {
        ...current,
        passwordHash: input.passwordHash,
        passwordRevision: input.passwordRevision,
        updatedAt: new Date(current.updatedAt.getTime()),
      };
      credentials.set(input.userId, updated);
      return updated;
    },
  };
}

export type MemorySessionRepository = SessionRepository & {
  byTokenHash: Map<string, SessionRecord>;
  createCalls: CreateSessionInput[];
  rotateCalls: RotateSessionInput[];
  replaceCsrfCalls: ReplaceCsrfTokenInput[];
};

export function createMemorySessionRepository(
  records: SessionRecord[] = [],
): MemorySessionRepository {
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
      const updated: SessionRecord = {
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
      const updated: SessionRecord = {
        ...current,
        csrfTokenHash: input.nextCsrfTokenHash,
      };
      byTokenHash.set(input.tokenHash, updated);
      return { ...updated };
    },
    async revokeCurrent(input) {
      const current = byTokenHash.get(input.tokenHash);
      if (current === undefined || current.revokedAt !== null) {
        return undefined;
      }
      const updated: SessionRecord = {
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

export type MemoryMembershipRepository = MembershipRepository & {
  rows: ActiveMembershipWithOrganization[];
};

export function createMemoryMembershipRepository(
  rows: ActiveMembershipWithOrganization[] = [],
): MemoryMembershipRepository {
  return {
    rows,
    async create() {
      throw new Error('Membership create is not used by auth use cases.');
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

export function createUserRecord(overrides: {
  id?: string;
  email?: string;
  status?: UserRecord['status'];
  disabledAt?: Date | null;
}): UserRecord {
  const now = new Date(TEST_NOW_ISO);
  const status = overrides.status ?? 'active';
  return {
    id: overrides.id ?? randomUUID(),
    email: overrides.email ?? 'owner@synthetic.patchpilot.test',
    displayName: 'Synthetic User',
    status,
    version: 1,
    disabledAt: overrides.disabledAt ?? (status === 'disabled' ? now : null),
    createdAt: now,
    updatedAt: now,
  };
}

export function createOrganizationRecord(overrides: {
  id?: string;
  slug?: string;
  name?: string;
  status?: OrganizationRecord['status'];
  archivedAt?: Date | null;
}): OrganizationRecord {
  const now = new Date(TEST_NOW_ISO);
  const status = overrides.status ?? 'active';
  return {
    id: overrides.id ?? randomUUID(),
    slug: overrides.slug ?? `org-${randomUUID().slice(0, 8)}`,
    name: overrides.name ?? 'Synthetic Organization',
    status,
    version: 1,
    archivedAt: overrides.archivedAt ?? (status === 'archived' ? now : null),
    createdAt: now,
    updatedAt: now,
  };
}

export function createMembershipRecord(
  organization: OrganizationRecord,
  user: UserRecord,
  overrides: {
    id?: string;
    role?: MembershipRecord['role'];
    status?: MembershipRecord['status'];
    revokedAt?: Date | null;
  } = {},
): MembershipRecord {
  const now = new Date(TEST_NOW_ISO);
  const status = overrides.status ?? 'active';
  return {
    id: overrides.id ?? randomUUID(),
    organizationId: organization.id,
    userId: user.id,
    role: overrides.role ?? 'owner',
    status,
    invitedAt: null,
    joinedAt: now,
    revokedAt: overrides.revokedAt ?? (status === 'revoked' ? now : null),
    version: 1,
    createdAt: now,
    updatedAt: now,
  };
}

export function createCredentialRecord(
  user: UserRecord,
  overrides: { passwordRevision?: number; passwordHash?: string } = {},
): LocalCredentialRecord {
  const now = new Date(TEST_NOW_ISO);
  return {
    id: randomUUID(),
    userId: user.id,
    passwordHash: overrides.passwordHash ?? STORED_PASSWORD_HASH,
    passwordRevision: overrides.passwordRevision ?? 1,
    algorithm: 'argon2id',
    createdAt: now,
    updatedAt: now,
  };
}

export function createSessionRecord(
  user: UserRecord,
  overrides: {
    tokenHash: string;
    csrfTokenHash: string;
    activeOrganizationId?: string | null;
    passwordRevision?: number;
    lastSeenAt?: Date;
    idleExpiresAt?: Date;
    absoluteExpiresAt?: Date;
    revokedAt?: Date | null;
    revokeReason?: string | null;
  },
): SessionRecord {
  const now = new Date(TEST_NOW_ISO);
  return {
    id: randomUUID(),
    userId: user.id,
    tokenHash: overrides.tokenHash,
    csrfTokenHash: overrides.csrfTokenHash,
    activeOrganizationId: overrides.activeOrganizationId ?? null,
    authenticationMethod: 'password',
    passwordRevision: overrides.passwordRevision ?? 1,
    createdAt: now,
    lastSeenAt: overrides.lastSeenAt ?? now,
    idleExpiresAt: overrides.idleExpiresAt ?? new Date('2026-08-28T04:00:00.000Z'),
    absoluteExpiresAt: overrides.absoluteExpiresAt ?? new Date('2026-09-03T16:00:00.000Z'),
    revokedAt: overrides.revokedAt ?? null,
    revokeReason: overrides.revokeReason ?? null,
    userAgent: null,
  };
}
