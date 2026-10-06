/**
 * Controlled Finding creation contracts.
 * ADR 0035 and the ADR 0026 exception
 * `controlled_maintainer_reviewed_finding_creation_v1`.
 * These constants do not persist a Finding and do not compose production.
 */

export const FINDING_CREATION_EXCEPTION_ID =
  'controlled_maintainer_reviewed_finding_creation_v1' as const;

export const FINDING_CREATION_PURPOSE = 'create_finding_from_product_match_evidence' as const;

export const FINDING_CREATION_POLICY_ID = 'finding_creation_policy_v1' as const;

export const FINDING_CREATION_POLICY_VERSION = 1 as const;

export const FINDING_CREATION_COMMAND_SCHEMA_VERSION = 'finding_creation_command_v1' as const;

export const FINDING_CREATION_AUTHORIZATION_SCHEMA_VERSION =
  'finding_creation_authorization_v1' as const;

export const FINDING_CREATION_TRUSTED_CONTEXT_SCHEMA_VERSION =
  'finding_creation_trusted_context_v1' as const;

export const FINDING_CREATION_EVIDENCE_SET_SCHEMA_VERSION =
  'finding_creation_evidence_set_v1' as const;

export const FINDING_CREATION_REPLAY_COMPARISON_SCHEMA_VERSION =
  'finding_creation_replay_comparison_v1' as const;

export const FINDING_CREATION_ELIGIBILITY_SCHEMA_VERSION =
  'finding_creation_evidence_eligibility_v1' as const;

export const FINDING_CREATION_PRODUCTION_REGISTRATION = 'absent' as const;

/**
 * Implementation policy limit for `finding_creation_policy_v1` version 1.
 * ADR 0035 does not fix a numeric maximum and does not put this number in
 * Finding identity. Sixteen qualifying Product Match Evidence identities is
 * the conservative ceiling for the first controlled slice: one organization,
 * one asset, one versionless component, one Vulnerability, and one ingestion.
 * A larger set is rejected. This constant is not a schema constraint and not
 * a permanent domain maximum. A later policy version may raise it.
 */
export const FINDING_CREATION_MAX_EVIDENCE_SET_SIZE = 16 as const;

export const FINDING_CREATION_EVIDENCE_SET_LIMIT = Object.freeze({
  policyId: FINDING_CREATION_POLICY_ID,
  policyVersion: FINDING_CREATION_POLICY_VERSION,
  maxSize: FINDING_CREATION_MAX_EVIDENCE_SET_SIZE,
  classification: 'implementation_policy_limit',
  findingProductIdentity: false,
  permanentDomainMaximum: false,
  schemaConstraint: false,
  firstSliceSufficient: true,
  oversizedReason: 'evidence_set_oversized',
} as const);

export const FINDING_CREATION_NORMALIZATION_VERSION = 2 as const;

export const FINDING_CREATION_TARGET_FIELDS = [
  'organizationId',
  'assetId',
  'componentId',
  'vulnerabilityId',
] as const;

export const FINDING_CREATION_NON_IDENTITY_FIELDS = [
  'componentOccurrenceId',
  'productMatchEvidenceId',
  'advisoryRevisionId',
  'evaluatorVersion',
  'matchingPolicyVersion',
  'sbomIngestionId',
  'dependencyPath',
  'observedComponentVersion',
] as const;

export const FINDING_CREATION_COMMAND_FIELDS = [
  'schemaVersion',
  'purpose',
  'policyId',
  'policyVersion',
  'expectedAssetId',
  'expectedComponentId',
  'expectedVulnerabilityId',
  'expectedSbomIngestionId',
  'expectedProductMatchEvidenceIds',
  'correlationId',
  'authorization',
] as const;

export const FINDING_CREATION_PROHIBITED_COMMAND_FIELDS = [
  'organizationId',
  'findingId',
  'state',
  'findingState',
  'componentOccurrenceId',
  'occurrenceId',
  'assetOwnership',
  'componentAuthority',
  'vulnerabilityAuthority',
  'risk',
  'priority',
  'assignee',
  'assignedMembershipId',
  'assignedTeamId',
  'teamId',
  'dueAt',
  'dueDate',
  'suppression',
  'acceptedRisk',
  'falsePositive',
  'remediationState',
  'verificationState',
  'observationResult',
  'observationMethod',
  'explanation',
  'timestamp',
  'createdAt',
  'replayFingerprint',
  'transaction',
  'prisma',
] as const;

export const FINDING_CREATION_AMBIENT_CLAIMS = [
  'administrator',
  'admin',
  'owner',
  'maintainer',
  'role',
  'permission',
  'permissions',
  'membershipRole',
  'isAdmin',
  'authorized',
  'canCreateFinding',
] as const;

export const FINDING_CREATION_GENERIC_PURPOSES = [
  'create_finding',
  'finding_create',
  'ensure_finding',
] as const;

export const FINDING_CREATION_OUTCOMES = [
  'authorized',
  'created',
  'already_applied',
  'invalid_command',
  'authority_required',
  'authority_rejected',
  'not_found',
  'evidence_unavailable',
  'evidence_not_affected',
  'evidence_not_current',
  'evidence_not_eligible',
  'target_mismatch',
  'evidence_set_mismatch',
  'finding_already_exists',
  'immutable_conflict',
  'malformed_persisted_state',
  'transaction_aborted',
  'database_unavailable',
  'internal_failure',
] as const;

export type FindingCreationOutcome = (typeof FINDING_CREATION_OUTCOMES)[number];

/** Outcomes this session can return. Persistence outcomes stay in the closed taxonomy. */
export const FINDING_CREATION_AUTHORIZATION_OUTCOMES = [
  'authorized',
  'invalid_command',
  'authority_required',
  'authority_rejected',
  'target_mismatch',
  'evidence_set_mismatch',
  'internal_failure',
] as const;

export type FindingCreationAuthorizationOutcome =
  (typeof FINDING_CREATION_AUTHORIZATION_OUTCOMES)[number];

export const FINDING_CREATION_REASONS = [
  'exact_binding',
  'authorization_missing',
  'authorization_unrecognized',
  'purpose_mismatch',
  'policy_mismatch',
  'correlation_mismatch',
  'membership_mismatch',
  'actor_mismatch',
  'organization_mismatch',
  'asset_mismatch',
  'component_mismatch',
  'vulnerability_mismatch',
  'ingestion_mismatch',
  'evidence_set_mismatch',
  'evidence_set_empty',
  'evidence_set_duplicate',
  'evidence_set_unsorted',
  'evidence_set_malformed',
  'evidence_set_oversized',
  'evidence_set_hostile',
  'command_rejected',
  'trusted_context_rejected',
  'membership_inactive',
  'ambient_authority_rejected',
  'schema_mismatch',
  'internal',
] as const;

export type FindingCreationReason = (typeof FINDING_CREATION_REASONS)[number];

const OUTCOME_EXPLANATIONS: Record<FindingCreationOutcome, string> = {
  authorized: 'creation authorization matches the bound request',
  created: 'finding creation is not performed by this contract',
  already_applied: 'matching creation records already exist',
  invalid_command: 'creation command was rejected',
  authority_required: 'creation authorization is required',
  authority_rejected: 'creation authorization was rejected',
  not_found: 'creation target is not available',
  evidence_unavailable: 'qualifying evidence set is not available',
  evidence_not_affected: 'qualifying evidence is not affected',
  evidence_not_current: 'qualifying evidence is not current',
  evidence_not_eligible: 'qualifying evidence is not eligible',
  target_mismatch: 'creation target does not match the authorization',
  evidence_set_mismatch: 'evidence set does not match the authorization',
  finding_already_exists: 'finding identity exists without an exact creation replay',
  immutable_conflict: 'finding identity conflicts with the requested evidence set',
  malformed_persisted_state: 'persisted creation state is malformed',
  transaction_aborted: 'creation transaction aborted',
  database_unavailable: 'creation store is unavailable',
  internal_failure: 'creation authorization failed closed',
};

export function findingCreationOutcomeExplanation(outcome: FindingCreationOutcome): string {
  return OUTCOME_EXPLANATIONS[outcome];
}

export function isFindingCreationOutcome(value: unknown): value is FindingCreationOutcome {
  return (
    typeof value === 'string' && (FINDING_CREATION_OUTCOMES as readonly string[]).includes(value)
  );
}

export function findingCreationOutcomeForReason(
  reason: FindingCreationReason,
): FindingCreationAuthorizationOutcome {
  switch (reason) {
    case 'exact_binding':
      return 'authorized';
    case 'authorization_missing':
      return 'authority_required';
    case 'organization_mismatch':
    case 'asset_mismatch':
    case 'component_mismatch':
    case 'vulnerability_mismatch':
      return 'target_mismatch';
    case 'evidence_set_mismatch':
    case 'ingestion_mismatch':
      return 'evidence_set_mismatch';
    case 'evidence_set_empty':
    case 'evidence_set_duplicate':
    case 'evidence_set_unsorted':
    case 'evidence_set_malformed':
    case 'evidence_set_oversized':
    case 'evidence_set_hostile':
    case 'command_rejected':
    case 'trusted_context_rejected':
    case 'schema_mismatch':
      return 'invalid_command';
    case 'internal':
      return 'internal_failure';
    case 'authorization_unrecognized':
    case 'purpose_mismatch':
    case 'policy_mismatch':
    case 'correlation_mismatch':
    case 'membership_mismatch':
    case 'actor_mismatch':
    case 'membership_inactive':
    case 'ambient_authority_rejected':
      return 'authority_rejected';
    default:
      return 'internal_failure';
  }
}

export const FINDING_CREATION_ZERO_EFFECTS = Object.freeze({
  findingWrites: 0,
  findingObservationWrites: 0,
  evidenceLinkWrites: 0,
  auditWrites: 0,
  evaluatorCalls: 0,
  productMatchEvidenceWrites: 0,
  providerCalls: 0,
  persistenceWrites: 0,
  automaticMatchingOperations: 0,
  bulkFindingCreations: 0,
  repeatedObservationWrites: 0,
  riskCalculations: 0,
  priorityCalculations: 0,
  assignmentOperations: 0,
  dueDateOperations: 0,
  suppressionOperations: 0,
  acceptedRiskOperations: 0,
  falsePositiveOperations: 0,
  remediationOperations: 0,
  verificationOperations: 0,
  notificationOperations: 0,
  dashboardOperations: 0,
  exportOperations: 0,
  ticketingOperations: 0,
  automaticClosureOperations: 0,
  automaticReopeningOperations: 0,
  aiAuthorityOperations: 0,
});

export const FINDING_CREATION_WITHHELD_POWERS = Object.freeze({
  evaluatorExecution: 'unavailable',
  productMatchEvidenceCreation: 'unavailable',
  providerContact: 'unavailable',
  automaticMatching: 'unavailable',
  bulkFindingCreation: 'unavailable',
  repeatedFindingObservations: 'unavailable',
  findingStateTransitions: 'unavailable',
  riskCalculation: 'unavailable',
  priority: 'unavailable',
  assignment: 'unavailable',
  dueDates: 'unavailable',
  suppression: 'unavailable',
  acceptedRisk: 'unavailable',
  falsePositiveDecisions: 'unavailable',
  remediation: 'unavailable',
  verification: 'unavailable',
  notifications: 'unavailable',
  dashboards: 'unavailable',
  exports: 'unavailable',
  ticketing: 'unavailable',
  automaticClosure: 'unavailable',
  automaticReopening: 'unavailable',
  aiAuthority: 'unavailable',
});

export const FINDING_CREATION_INVARIANTS = Object.freeze({
  structuralCommandIsAuthority: false,
  plainObjectIsAuthority: false,
  jsonValueIsAuthority: false,
  clonedHandleIsAuthority: false,
  roleIsAuthority: false,
  membershipAloneIsAuthority: false,
  trustedContextIsFindingAuthority: false,
  clientOrganizationIdIsAuthorization: false,
  fingerprintEqualityReplacesSemanticValidation: false,
  evidenceSetFingerprintIsAuthority: false,
  correlationIsReplayIdentity: false,
  correlationIsAuthorizationBinding: true,
  sbomIngestionIsFindingIdentity: false,
  componentOccurrenceIsFindingIdentity: false,
  productMatchEvidenceIdIsFindingIdentity: false,
  unaffectedOccurrenceVetoesAffected: false,
  representativeOccurrenceIsFindingIdentity: false,
  subsetFailsClosed: true,
  supersetFailsClosed: true,
  emptyEvidenceSetFailsClosed: true,
  authorizationIsDurable: false,
  authorizationIsConsumed: false,
  authorizationExpires: false,
  durableCreationAuthorityTable: false,
  issuerPackageExport: 'absent',
  issuerDeepImportSupported: false,
  internalIssuerTrustBoundary: 'same_package_relative_import',
  productionRegistration: FINDING_CREATION_PRODUCTION_REGISTRATION,
  persistenceImplemented: true,
  evidenceLinkMigrationImplemented: true,
  findingCanBeCreated: true,
  session: 'controlled_finding_session_2',
  sessionReview: 'controlled_finding_session_2r',
  nextSession: 'controlled_finding_session_3',
});

export const FINDING_CREATION_EVIDENCE_REQUIREMENTS = [
  'loaded_under_trusted_organization',
  'internally_valid',
  'outcome_affected',
  'non_synthetic',
  'maintainer_reviewed_advisory_authority',
  'immutable_reviewed_approval',
  'currently_applicable',
  'associated_with_target_asset',
  'associated_with_versionless_component',
  'associated_with_target_vulnerability',
  'associated_with_latest_successful_sbom_ingestion',
  'normalization_version_2_completed_graph',
  'accepted_evaluator_and_policies',
] as const;

export type FindingCreationEvidenceRequirement =
  (typeof FINDING_CREATION_EVIDENCE_REQUIREMENTS)[number];

export const FINDING_CREATION_PERSISTENCE_BOUNDARY = Object.freeze({
  implemented: true,
  migrationImplemented: true,
  evidenceLinkMigrationImplemented: true,
  productionComposition: 'absent',
  issuerPackageExport: 'absent',
  reloadsOrganizationAndMembership: true,
  clientOrganizationIdIsAuthorization: false,
  durableCreationAuthorityTable: false,
  databaseTimeDefinesCreationTimestamps: true,
  networkIoInsideTransaction: false,
  queueIoInsideTransaction: false,
  objectStorageIoInsideTransaction: false,
  parserIoInsideTransaction: false,
  evaluatorIoInsideTransaction: false,
  providerIoInsideTransaction: false,
  futureWrites: Object.freeze([
    'one_finding',
    'one_creation_observation',
    'one_evidence_link_per_qualifying_row',
    'one_audit_event',
  ] as const),
});

export const FINDING_CREATION_CALLER_SUPPLIED_FIELDS = Object.freeze([
  'purpose',
  'policyId',
  'policyVersion',
  'expectedAssetId',
  'expectedComponentId',
  'expectedVulnerabilityId',
  'expectedSbomIngestionId',
  'expectedProductMatchEvidenceIds',
  'correlationId',
] as const);

export const FINDING_CREATION_DERIVED_FIELDS = Object.freeze([
  'organizationId',
  'actorId',
  'membershipId',
  'evidenceSetFingerprint',
  'authorizationHandle',
  'replayClassification',
] as const);
