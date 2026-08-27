/**
 * Authentication and organization-authorization application logic.
 * HTTP cookies, CSRF middleware, and web UI live in later adapters.
 */
export const packageBoundary = '@patchpilot/auth' as const;
export const passwordHashingLibrary = 'argon2' as const;

export { addSeconds, createSystemClock, type Clock } from './clock.js';
export {
  AUTHENTICATION_REQUIRED,
  LOGIN_RATE_LIMITED,
  LOGIN_UNAVAILABLE,
  ORGANIZATION_NOT_FOUND,
  PERMISSION_DENIED,
  PUBLIC_LOGIN_FAILURE,
  passwordMaxBytesError,
  passwordMinLengthError,
} from './errors.js';
export { createArgon2PasswordHasher } from './argon2-password-hasher.js';
export {
  argon2ParametersFromAuthConfig,
  type Argon2Parameters,
  type PasswordHasher,
} from './password-hasher.js';
export { SESSION_TOKEN_BYTES, type RandomTokenGenerator } from './random-token-generator.js';
export { createNodeRandomTokenGenerator } from './node-random-token-generator.js';
export {
  CSRF_TOKEN_DIGEST_PREFIX,
  digestCsrfToken,
  digestLoginAccount,
  digestLoginPeerIp,
  digestSessionToken,
  LOGIN_ACCOUNT_DIGEST_PREFIX,
  LOGIN_IP_DIGEST_PREFIX,
  normalizeLoginEmail,
  SESSION_TOKEN_DIGEST_PREFIX,
} from './token-digests.js';
export {
  actorHasPermission,
  canAdministerMembershipRole,
  hasPermission,
  PERMISSIONS,
  permissionCatalog,
  permissionsForRole,
  requirePermission,
  type Permission,
} from './permissions.js';
export {
  anonymousAuditActorFields,
  auditActorFields,
  createTrustedActor,
  type AuditActorFields,
  type TrustedActor,
} from './trusted-actor.js';
export {
  createLoginUseCase,
  type LoginDependencies,
  type LoginInput,
  type LoginResult,
  type IssuedSessionTokens,
} from './login.js';
export {
  createResolveSessionUseCase,
  type ResolveSessionDependencies,
  type ResolveSessionInput,
  type ResolveSessionResult,
} from './resolve-session.js';
export { createLogoutUseCase, type LogoutDependencies, type LogoutInput } from './logout.js';
export {
  createSelectOrganizationUseCase,
  type SelectOrganizationDependencies,
  type SelectOrganizationInput,
  type SelectOrganizationResult,
} from './select-organization.js';
export {
  createListActiveOrganizationsUseCase,
  type ActiveOrganizationSummary,
  type ListActiveOrganizationsDependencies,
  type ListActiveOrganizationsInput,
} from './list-active-organizations.js';
export {
  createLoginRateLimiter,
  loginAccountRedisKey,
  loginIpRedisKey,
  LOGIN_REDIS_ACCOUNT_KEY_PREFIX,
  LOGIN_REDIS_IP_KEY_PREFIX,
  loginRateLimitFailureCategories,
  type LoginRateLimitConsumeInput,
  type LoginRateLimitCounters,
  type LoginRateLimiter,
  type LoginRateLimitFailureCategory,
  type RedisLoginCommands,
} from './login-rate-limiter.js';
export {
  createFakeLoginRateLimiter,
  type FakeLoginRateLimiter,
} from './fake-login-rate-limiter.js';
export {
  createLoginRedisClientOptions,
  loginRedisRetryStrategy,
  MAX_LOGIN_REDIS_RECONNECT_ATTEMPTS,
  withBoundedTimeout,
} from './login-redis-timeout.js';
export {
  normalizeDirectPeerIp,
  selectDirectPeerIp,
  type DirectPeerIpInput,
} from './login-peer-ip.js';
