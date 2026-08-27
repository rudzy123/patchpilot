import type { AuthConfig } from '@patchpilot/config';
import type { Logger } from '@patchpilot/logger';
import { err, ok, type Result, type UserRecord } from '@patchpilot/domain';
import type {
  LocalCredentialRepository,
  MembershipRepository,
  SessionRepository,
  UserRepository,
} from '@patchpilot/domain';

import { argon2ParametersFromAuthConfig, type PasswordHasher } from './password-hasher.js';
import { addSeconds, type Clock } from './clock.js';
import { DUMMY_ARGON2ID_PHC } from './dummy-phc.js';
import { PUBLIC_LOGIN_FAILURE, passwordMaxBytesError, passwordMinLengthError } from './errors.js';
import type { LoginRateLimiter } from './login-rate-limiter.js';
import { SESSION_TOKEN_BYTES, type RandomTokenGenerator } from './random-token-generator.js';
import {
  publicAuthOrganization,
  sessionExpiresAt,
  type PublicAuthOrganization,
  type PublicAuthUser,
} from './session-view.js';
import { digestCsrfToken, digestLoginAccount, digestSessionToken } from './token-digests.js';
import { createTrustedActor, type TrustedActor } from './trusted-actor.js';

export type LoginInput = {
  email: string;
  password: string;
  /** Direct socket peer IP. Do not pass X-Forwarded-For. */
  peerIp: string;
  userAgent?: string;
};

export type IssuedSessionTokens = {
  sessionToken: string;
  csrfToken: string;
};

export type LoginResult = {
  actor: TrustedActor;
  sessionId: string;
  tokens: IssuedSessionTokens;
  user: PublicAuthUser;
  organization: PublicAuthOrganization | null;
  expiresAt: Date;
};

export type LoginDependencies = {
  users: UserRepository;
  localCredentials: LocalCredentialRepository;
  sessions: SessionRepository;
  memberships: MembershipRepository;
  hasher: PasswordHasher;
  tokens: RandomTokenGenerator;
  clock: Clock;
  auth: AuthConfig;
  logger: Logger;
  limiter: LoginRateLimiter;
};

export function createLoginUseCase(dependencies: LoginDependencies) {
  return {
    execute(input: LoginInput): Promise<Result<LoginResult>> {
      return executeLogin(dependencies, input);
    },
  };
}

async function executeLogin(
  dependencies: LoginDependencies,
  input: LoginInput,
): Promise<Result<LoginResult>> {
  const lengthError = validatePasswordLength(input.password, dependencies.auth);
  if (lengthError !== undefined) {
    return err(lengthError);
  }

  const limitResult = await dependencies.limiter.consume({
    peerIp: input.peerIp,
    accountDigest: digestLoginAccount(input.email),
  });
  if (!limitResult.ok) {
    return limitResult;
  }

  const user = await dependencies.users.findByNormalizedEmail(input.email);
  if (user === undefined) {
    await verifyDummy(dependencies, input.password);
    return publicLoginFailure(dependencies);
  }

  const credential = await dependencies.localCredentials.findByUserId(user.id);
  if (credential === undefined) {
    await verifyDummy(dependencies, input.password);
    return publicLoginFailure(dependencies);
  }

  const verified = await dependencies.hasher.verify(credential.passwordHash, input.password);
  if (verified !== true) {
    return publicLoginFailure(dependencies);
  }

  if (user.status !== 'active') {
    return publicLoginFailure(dependencies);
  }

  const parameters = argon2ParametersFromAuthConfig(dependencies.auth);
  let passwordRevision = credential.passwordRevision;
  if (dependencies.hasher.needsRehash(credential.passwordHash, parameters)) {
    const nextHash = await dependencies.hasher.hash(input.password, parameters);
    const updated = await dependencies.localCredentials.updatePasswordHash({
      userId: user.id,
      passwordHash: nextHash,
      passwordRevision: credential.passwordRevision + 1,
    });
    if (updated !== undefined) {
      passwordRevision = updated.passwordRevision;
    }
  }

  return issueSession(dependencies, user, passwordRevision, input.userAgent);
}

async function issueSession(
  dependencies: LoginDependencies,
  user: UserRecord,
  passwordRevision: number,
  userAgent: string | undefined,
): Promise<Result<LoginResult>> {
  const now = dependencies.clock.now();
  const memberships = await dependencies.memberships.listActiveInActiveOrganizationsForUser(
    user.id,
  );
  const selected = memberships.length === 1 ? memberships[0] : undefined;
  const sessionToken = dependencies.tokens.generate(SESSION_TOKEN_BYTES);
  const csrfToken = dependencies.tokens.generate(SESSION_TOKEN_BYTES);
  const session = await dependencies.sessions.create({
    userId: user.id,
    tokenHash: digestSessionToken(sessionToken),
    csrfTokenHash: digestCsrfToken(csrfToken),
    passwordRevision,
    lastSeenAt: now,
    idleExpiresAt: addSeconds(now, dependencies.auth.sessionIdleTtlSeconds),
    absoluteExpiresAt: addSeconds(now, dependencies.auth.sessionAbsoluteTtlSeconds),
    authenticationMethod: 'password',
    ...(selected === undefined ? {} : { activeOrganizationId: selected.organization.id }),
    ...(userAgent === undefined ? {} : { userAgent }),
  });

  const actor = createTrustedActor({
    userId: user.id,
    sessionId: session.id,
    ...(selected === undefined
      ? {}
      : { organization: selected.organization, membership: selected.membership }),
  });

  dependencies.logger.info(
    { event: 'auth.login_succeeded', userId: user.id, sessionId: session.id },
    'login succeeded',
  );

  return ok({
    actor,
    sessionId: session.id,
    tokens: { sessionToken, csrfToken },
    user: { id: user.id, displayName: user.displayName },
    organization:
      selected === undefined
        ? null
        : publicAuthOrganization({
            organization: selected.organization,
            role: selected.membership.role,
          }),
    expiresAt: sessionExpiresAt(session),
  });
}

async function verifyDummy(dependencies: LoginDependencies, password: string): Promise<void> {
  await dependencies.hasher.verify(DUMMY_ARGON2ID_PHC, password);
}

function publicLoginFailure(dependencies: LoginDependencies): Result<LoginResult> {
  dependencies.logger.info({ event: 'auth.login_failed' }, 'login failed');
  return err(PUBLIC_LOGIN_FAILURE);
}

export function validatePasswordLength(
  password: string,
  auth: Pick<AuthConfig, 'passwordMinLength' | 'passwordMaxBytes'>,
):
  ReturnType<typeof passwordMinLengthError> | ReturnType<typeof passwordMaxBytesError> | undefined {
  const characterCount = Array.from(password).length;
  if (characterCount < auth.passwordMinLength) {
    return passwordMinLengthError(auth.passwordMinLength);
  }

  const byteCount = Buffer.byteLength(password, 'utf8');
  if (byteCount > auth.passwordMaxBytes) {
    return passwordMaxBytesError(auth.passwordMaxBytes);
  }

  return undefined;
}
