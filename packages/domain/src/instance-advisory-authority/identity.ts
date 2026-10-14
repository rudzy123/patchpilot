/**
 * Canonical User.id is the only instance advisory principal.
 * Email, membership, session, and correlation do not identify the principal.
 * One human with two User accounts is an operational residual, not a matcher.
 */

const CANONICAL_USER_ID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export const INSTANCE_ADVISORY_PRINCIPAL_EXCLUDED_FIELDS = [
  'organizationId',
  'membershipId',
  'role',
  'permission',
  'sessionId',
  'email',
  'displayName',
  'username',
  'advisoryRevisionId',
  'capabilityId',
  'correlationId',
  'instanceOperatorAttestation',
] as const;

export const INSTANCE_ADVISORY_SEPARATION_RESIDUAL = {
  case: 'one_human_controlling_two_user_accounts',
  detectableByCanonicalUserIdComparison: false,
  speculativeIdentityMatchingAuthorized: false,
  enrollmentOrPasswordResetAdded: false,
  operatorMustNotKnowinglyGrantBothAuthoritiesToAccountsOfOnePerson: true,
  comparisonRemainsCanonicalUserId: true,
} as const;

export type InstanceAdvisoryPrincipalComparison =
  | {
      readonly classification: 'distinct';
      readonly submitterUserId: string;
      readonly reviewerUserId: string;
    }
  | {
      readonly classification: 'self_approval_forbidden';
      readonly userId: string;
    }
  | { readonly classification: 'malformed_principal' };

/**
 * Canonical lowercase UUID text. Command fields must already be in this form.
 * Comparison lowercases first so a mixed-case User.id is the same principal.
 */
export function canonicalLowercaseUuid(value: unknown): string | null {
  if (typeof value !== 'string' || value.length !== 36) {
    return null;
  }
  const canonical = value.toLowerCase();
  if (!CANONICAL_USER_ID_PATTERN.test(canonical)) {
    return null;
  }
  return canonical;
}

export function isCanonicalLowercaseUuid(value: unknown): value is string {
  return typeof value === 'string' && canonicalLowercaseUuid(value) === value;
}

/** Lowercase a User.id for comparison. Returns null when the value is not a UUID. */
export function canonicalInstanceAdvisoryPrincipalId(value: unknown): string | null {
  return canonicalLowercaseUuid(value);
}

export function isCanonicalInstanceAdvisoryPrincipalId(value: unknown): value is string {
  return isCanonicalLowercaseUuid(value);
}

/**
 * Submitter and reviewer are the same principal when canonical User.id matches.
 * Sessions, memberships, organizations, email, display name, and correlation
 * are not arguments. Malformed input fails closed and is not treated as distinct.
 */
export function compareInstanceAdvisoryPrincipals(
  submitterUserId: unknown,
  reviewerUserId: unknown,
): InstanceAdvisoryPrincipalComparison {
  const submitter = canonicalInstanceAdvisoryPrincipalId(submitterUserId);
  const reviewer = canonicalInstanceAdvisoryPrincipalId(reviewerUserId);
  if (submitter === null || reviewer === null) {
    return { classification: 'malformed_principal' };
  }
  if (submitter === reviewer) {
    return { classification: 'self_approval_forbidden', userId: submitter };
  }
  return {
    classification: 'distinct',
    submitterUserId: submitter,
    reviewerUserId: reviewer,
  };
}
