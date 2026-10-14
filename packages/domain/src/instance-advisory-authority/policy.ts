/**
 * Instance advisory authority contracts. ADR 0043 and ADR 0042.
 * Session 1 defines classifications, lifecycle, and nonauthority.
 * It does not persist a grant, migrate, submit, approve, or compose production.
 */

export const INSTANCE_ADVISORY_AUTHORITY_CONTRACT_SCHEMA_VERSION =
  'instance_advisory_authority_contracts_v1' as const;

export const INSTANCE_ADVISORY_AUTHORITIES = [
  'advisory_submit_local',
  'advisory_approve_for_product_evaluation',
] as const;

export type InstanceAdvisoryAuthority = (typeof INSTANCE_ADVISORY_AUTHORITIES)[number];

export const INSTANCE_ADVISORY_REJECTED_AUTHORITIES = [
  'instance_administrator',
  'instance_operator',
  'advisory_administrator',
  'advisory_admin',
  'owner',
  'admin',
  'capability_issuer',
  'product_match_evidence_evaluator',
  'provider_manager',
  'finding_authority',
  'lifecycle_authority',
  'status_inspection',
  '*',
] as const;

export function isInstanceAdvisoryAuthority(value: unknown): value is InstanceAdvisoryAuthority {
  return value === 'advisory_submit_local' || value === 'advisory_approve_for_product_evaluation';
}

/**
 * Future meaning names the later command these classifications will authorize.
 * Every boolean is false in this session. Naming a future consumer grants nothing.
 */
export const INSTANCE_ADVISORY_AUTHORITY_POWERS = {
  advisory_submit_local: {
    grantsAuthorityInThisSession: false,
    futureMeaning: 'submit_one_local_maintainer_reviewed_advisory_document',
    approve: false,
    issueApprovalCapability: false,
    evaluateVersions: false,
    generateProductMatchEvidence: false,
    inspectTenantFindings: false,
    createFindings: false,
    recordRepeatedObservations: false,
  },
  advisory_approve_for_product_evaluation: {
    grantsAuthorityInThisSession: false,
    futureMeaning: 'approve_one_exact_submitted_advisory_revision_after_service_validation',
    submit: false,
    directlyMintCapabilities: false,
    accessGenericIssuer: false,
    performProductEvaluation: false,
    generateProductMatchEvidence: false,
    createFindings: false,
    recordObservations: false,
  },
} as const;

export const INSTANCE_ADVISORY_ISSUANCE_CLASSIFICATIONS = ['deployment_local_command'] as const;

export type InstanceAdvisoryIssuanceClassification =
  (typeof INSTANCE_ADVISORY_ISSUANCE_CLASSIFICATIONS)[number];

export const INSTANCE_ADVISORY_REJECTED_ISSUANCE_CLASSIFICATIONS = [
  'organization_admin',
  'tenant_operator',
  'instance_operator',
  'owner',
  'admin',
  'api',
  'web',
  'worker',
  'seed',
  'automatic',
  'provider',
  'evaluator',
] as const;

export function isInstanceAdvisoryIssuanceClassification(
  value: unknown,
): value is InstanceAdvisoryIssuanceClassification {
  return value === 'deployment_local_command';
}

export const INSTANCE_ADVISORY_GRANT_LIFECYCLE_STATES = ['active', 'revoked'] as const;

export type InstanceAdvisoryGrantLifecycle =
  (typeof INSTANCE_ADVISORY_GRANT_LIFECYCLE_STATES)[number];

export const INSTANCE_ADVISORY_REJECTED_GRANT_LIFECYCLE_STATES = [
  'suspended',
  'pending',
  'expired',
  'deleted',
  'reactivated',
  'inherited',
  'organization_scoped',
] as const;

/**
 * A grant row is active when revocation has not been committed.
 * A non-empty revocation time is revoked history. Blank text is malformed.
 */
export function instanceAdvisoryGrantLifecycle(
  revokedAt: string | null,
): InstanceAdvisoryGrantLifecycle | 'malformed_persisted_state' {
  if (revokedAt === null) {
    return 'active';
  }
  if (revokedAt.length > 0 && revokedAt === revokedAt.trim()) {
    return 'revoked';
  }
  return 'malformed_persisted_state';
}

/** Conceptual columns from ADR 0043. Not a database client type and not a writable row. */
export const INSTANCE_ADVISORY_GRANT_IDENTITY_FIELDS = [
  'id',
  'user_id',
  'authority',
  'issued_at',
  'revoked_at',
  'issuance_classification',
  'command_correlation_id',
] as const;

export const INSTANCE_ADVISORY_GRANT_EXCLUDED_IDENTITY_FIELDS = [
  'organization_id',
  'membership_id',
  'role',
  'permission',
  'advisory_revision_id',
  'capability_id',
  'provider',
  'evaluator',
  'asset_id',
  'finding_id',
  'component_id',
  'vulnerability_id',
] as const;

export const INSTANCE_ADVISORY_ACTIVE_GRANT_INVARIANTS = {
  maxActiveGrantsPerUser: 1,
  oneActiveAuthorityPerUser: true,
  submissionAndApprovalMutuallyExclusive: true,
  enforcement: 'persistence_invariant',
  applicationCheckAloneSufficient: false,
  silentRevokeOrReplace: false,
  conflictingGrantOutcome: 'active_grant_conflict',
  activeUserRequiredForAuthorityUse: true,
  activeGrantRequiredForAuthorityUse: true,
  organizationMembershipRelevant: false,
  organizationRoleRelevant: false,
  tenantPermissionRelevant: false,
} as const;

export const INSTANCE_ADVISORY_TENANT_NONAUTHORITY = {
  inspectTenantAssets: false,
  inspectTenantFindings: false,
  createTenantFindings: false,
  modifyOrganizationMembership: false,
  changeOrganizationRoles: false,
  selectActiveOrganization: false,
  administerAnotherTenant: false,
  runProductMatchEvidenceEvaluation: false,
  approveOrganizationSpecificActions: false,
  organizationMembershipGrantsAdvisoryAuthority: false,
  organizationRoleGrantsAdvisoryAuthority: false,
  tenantPermissionGrantsAdvisoryAuthority: false,
} as const satisfies Record<string, false>;

export const INSTANCE_ADVISORY_PRODUCT_NONAUTHORITY = {
  advisorySubmission: false,
  advisoryApproval: false,
  capabilityIssuance: false,
  productMatchEvidenceGeneration: false,
  providerAccess: false,
  evaluatorExecution: false,
  targetDiscovery: false,
  findingCreation: false,
  repeatedObservation: false,
  observationHistory: false,
  lifecycle: false,
  findingClosure: false,
  findingReopening: false,
  risk: false,
  priority: false,
  assignment: false,
  dueDates: false,
  suppression: false,
  acceptedRisk: false,
  falsePositiveDecision: false,
  remediation: false,
  verification: false,
  notifications: false,
  dashboards: false,
  exports: false,
  ticketing: false,
  aiAuthority: false,
} as const satisfies Record<string, false>;

export const INSTANCE_ADVISORY_AUTHORITY_INVARIANTS = {
  contractSchemaVersion: INSTANCE_ADVISORY_AUTHORITY_CONTRACT_SCHEMA_VERSION,
  persistenceImplemented: true,
  migration26Implemented: true,
  deploymentLocalCommandImplemented: false,
  grantsCanBeCreated: false,
  grantsCanBeRevoked: false,
  advisorySubmissionAvailable: false,
  advisoryApprovalAvailable: false,
  productMatchEvidenceProductionAvailable: false,
  organizationRolesGrantAdvisoryAuthority: false,
  productionComposition: 'absent',
  nextSession: 'instance_advisory_authority_foundation_session_3',
  frozenMigrationCount: 26,
  authorityFoundationComplete: false,
  genericInstanceRbac: false,
  capabilityIssuerExposed: false,
  userStatusMutationImplemented: true,
  findingWrites: 0,
  providerContact: false,
  evaluatorInvocations: 0,
} as const;
