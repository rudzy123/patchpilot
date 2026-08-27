/**
 * Authentication and organization-authorization application logic.
 * HTTP cookies, CSRF middleware, Redis limits, and web UI live in later adapters.
 */
export const packageBoundary = '@patchpilot/auth' as const;
export const passwordHashingLibrary = 'argon2' as const;

export { addSeconds, createSystemClock, type Clock } from './clock.js';
export {
  AUTHENTICATION_REQUIRED,
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
  digestSessionToken,
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
