/**
 * Controlled Finding repeated-observation contracts.
 * ADR 0039. Purpose `record_finding_repeated_observation` under
 * `finding_observation_policy_v1` version 1.
 * These constants do not persist an observation, update a Finding,
 * write `finding.observed`, or compose production.
 */

import type { FindingObservationResult } from '../../lifecycle.js';

export const FINDING_REPEATED_OBSERVATION_PURPOSE = 'record_finding_repeated_observation' as const;

export const FINDING_REPEATED_OBSERVATION_POLICY_ID = 'finding_observation_policy_v1' as const;

export const FINDING_REPEATED_OBSERVATION_POLICY_VERSION = 1 as const;

export const FINDING_REPEATED_OBSERVATION_COMMAND_SCHEMA_VERSION =
  'finding_repeated_observation_command_v1' as const;

export const FINDING_REPEATED_OBSERVATION_AUTHORIZATION_SCHEMA_VERSION =
  'finding_repeated_observation_authorization_v1' as const;

export const FINDING_REPEATED_OBSERVATION_TRUSTED_CONTEXT_SCHEMA_VERSION =
  'finding_repeated_observation_trusted_context_v1' as const;

export const FINDING_REPEATED_OBSERVATION_EVIDENCE_SUPPORT_SCHEMA_VERSION =
  'finding_repeated_observation_evidence_support_v1' as const;

export const FINDING_REPEATED_OBSERVATION_ABSENCE_SUPPORT_SCHEMA_VERSION =
  'finding_repeated_observation_absence_support_v1' as const;

export const FINDING_REPEATED_OBSERVATION_REPLAY_COMPARISON_SCHEMA_VERSION =
  'finding_repeated_observation_replay_comparison_v1' as const;

export const FINDING_REPEATED_OBSERVATION_OCCURRENCE_SET_SCHEMA_VERSION =
  'finding_repeated_observation_occurrence_set_v1' as const;

export const FINDING_REPEATED_OBSERVATION_ABSENCE_FACTS_SCHEMA_VERSION =
  'finding_repeated_observation_absence_facts_v1' as const;

export const FINDING_REPEATED_OBSERVATION_TRANSACTION_SCHEMA_VERSION =
  'finding_repeated_observation_transaction_v1' as const;

export const FINDING_REPEATED_OBSERVATION_EVIDENCE_SCHEMA_VERSION =
  'finding_repeated_observation_v1' as const;

export const FINDING_REPEATED_OBSERVATION_INSPECTION_COMPATIBILITY_SCHEMA_VERSION =
  'finding_repeated_observation_inspection_compatibility_v1' as const;

export const FINDING_REPEATED_OBSERVATION_METHOD =
  'controlled_finding_repeated_observation' as const;

export const FINDING_REPEATED_OBSERVATION_TRANSITION = 'evidence_observation' as const;

export const FINDING_REPEATED_OBSERVATION_AUDIT_ACTION = 'finding.observed' as const;

export const FINDING_REPEATED_OBSERVATION_NORMALIZATION_VERSION = 2 as const;

export const FINDING_REPEATED_OBSERVATION_PRODUCTION_REGISTRATION = 'absent' as const;

/**
 * Versioned policy limit for `finding_observation_policy_v1` version 1.
 * Sixteen is the combined count of Product Match Evidence rows and
 * unknown-version occurrence proofs. It is not Finding identity, observation
 * identity, a permanent domain maximum, or a schema maximum.
 */
export const FINDING_REPEATED_OBSERVATION_MAX_SUPPORT_FACTS = 16 as const;

export const FINDING_REPEATED_OBSERVATION_SUPPORT_LIMIT = Object.freeze({
  policyId: FINDING_REPEATED_OBSERVATION_POLICY_ID,
  policyVersion: FINDING_REPEATED_OBSERVATION_POLICY_VERSION,
  maxSupportFacts: FINDING_REPEATED_OBSERVATION_MAX_SUPPORT_FACTS,
  countsProductMatchEvidenceRows: true,
  countsUnknownVersionOccurrenceProofs: true,
  classification: 'versioned_policy_limit',
  findingIdentity: false,
  observationIdentity: false,
  permanentDomainMaximum: false,
  schemaMaximum: false,
  oversizedReason: 'evidence_set_oversized',
} as const);

export const FINDING_REPEATED_OBSERVATION_AGGREGATES = [
  'affected',
  'unaffected',
  'unknown',
  'component_absent',
] as const;

export type FindingRepeatedObservationAggregate =
  (typeof FINDING_REPEATED_OBSERVATION_AGGREGATES)[number];

export const FINDING_REPEATED_OBSERVATION_AGGREGATE_RESULT = Object.freeze({
  affected: 'present',
  unaffected: 'absent',
  unknown: 'inconclusive',
  component_absent: 'absent',
} as const satisfies Readonly<
  Record<FindingRepeatedObservationAggregate, FindingObservationResult>
>);

export const FINDING_REPEATED_OBSERVATION_NON_AGGREGATE_FAILURES = [
  'evidence_unavailable',
  'ingestion_not_completed',
  'ingestion_not_latest',
  'ingestion_not_later',
  'unsupported_normalization_version',
  'evidence_set_oversized',
  'malformed_persisted_state',
] as const;

export type FindingRepeatedObservationNonAggregateFailure =
  (typeof FINDING_REPEATED_OBSERVATION_NON_AGGREGATE_FAILURES)[number];

export const FINDING_REPEATED_OBSERVATION_OUTCOMES = [
  'observed',
  'already_applied',
  'invalid_command',
  'authority_required',
  'authority_rejected',
  'not_found',
  'ingestion_not_completed',
  'ingestion_not_latest',
  'ingestion_not_later',
  'unsupported_normalization_version',
  'evidence_unavailable',
  'evidence_set_oversized',
  'evidence_set_mismatch',
  'evidence_not_current',
  'immutable_conflict',
  'malformed_persisted_state',
  'concurrency_conflict',
  'transaction_aborted',
  'database_unavailable',
  'internal_failure',
] as const;

export type FindingRepeatedObservationOutcome =
  (typeof FINDING_REPEATED_OBSERVATION_OUTCOMES)[number];

/** Outcomes this session can return. Persistence outcomes stay in the closed taxonomy. */
export const FINDING_REPEATED_OBSERVATION_AUTHORIZATION_OUTCOMES = [
  'authorized',
  'invalid_command',
  'authority_required',
  'authority_rejected',
  'evidence_set_mismatch',
  'evidence_set_oversized',
  'unsupported_normalization_version',
  'internal_failure',
] as const;

export type FindingRepeatedObservationAuthorizationOutcome =
  (typeof FINDING_REPEATED_OBSERVATION_AUTHORIZATION_OUTCOMES)[number];

export const FINDING_REPEATED_OBSERVATION_REASONS = [
  'exact_binding',
  'authorization_missing',
  'authorization_unrecognized',
  'purpose_mismatch',
  'policy_mismatch',
  'correlation_mismatch',
  'membership_mismatch',
  'actor_mismatch',
  'organization_mismatch',
  'finding_mismatch',
  'asset_mismatch',
  'component_mismatch',
  'vulnerability_mismatch',
  'ingestion_mismatch',
  'evidence_set_mismatch',
  'unknown_version_set_mismatch',
  'absence_proof_mismatch',
  'evidence_set_empty',
  'evidence_set_duplicate',
  'evidence_set_unsorted',
  'evidence_set_malformed',
  'evidence_set_oversized',
  'evidence_set_hostile',
  'unknown_version_duplicate',
  'unknown_version_unsorted',
  'unknown_version_malformed',
  'unknown_version_hostile',
  'support_mutually_exclusive',
  'absence_graph_rejected',
  'absence_count_rejected',
  'unsupported_normalization_version',
  'command_rejected',
  'trusted_context_rejected',
  'membership_inactive',
  'ambient_authority_rejected',
  'schema_mismatch',
  'caller_selected_aggregate',
  'caller_selected_result',
  'internal',
] as const;

export type FindingRepeatedObservationReason =
  (typeof FINDING_REPEATED_OBSERVATION_REASONS)[number];

export const FINDING_REPEATED_OBSERVATION_FINDING_IDENTITY_FIELDS = [
  'organizationId',
  'assetId',
  'componentId',
  'vulnerabilityId',
] as const;

export const FINDING_REPEATED_OBSERVATION_NATURAL_IDENTITY_FIELDS = [
  'organizationId',
  'findingId',
  'sbomIngestionId',
] as const;

export const FINDING_REPEATED_OBSERVATION_NON_FINDING_IDENTITY_FIELDS = [
  'sbomIngestionId',
  'componentOccurrenceId',
  'componentVersion',
  'productMatchEvidenceId',
  'observationResult',
  'aggregate',
  'policyVersion',
  'evidenceFingerprint',
  'actorId',
  'correlationId',
] as const;

export const FINDING_REPEATED_OBSERVATION_SEMANTIC_COMPARISON_FIELDS = [
  'organizationId',
  'findingId',
  'findingTarget',
  'sbomIngestionId',
  'purpose',
  'policyId',
  'policyVersion',
  'aggregate',
  'mappedResult',
  'evidenceOrAbsenceFingerprint',
  'evidenceLinkSet',
  'replayFingerprint',
] as const;

export const FINDING_REPEATED_OBSERVATION_REPLAY_EXCLUDED_FIELDS = [
  'correlationId',
  'actorId',
  'membershipId',
] as const;

export const FINDING_REPEATED_OBSERVATION_COMMAND_FIELDS = [
  'schemaVersion',
  'purpose',
  'policyId',
  'policyVersion',
  'expectedFindingId',
  'expectedAssetId',
  'expectedComponentId',
  'expectedVulnerabilityId',
  'expectedSbomIngestionId',
  'support',
  'correlationId',
  'authorization',
] as const;

export const FINDING_REPEATED_OBSERVATION_PROHIBITED_COMMAND_FIELDS = [
  'organizationId',
  'findingNaturalIdentity',
  'aggregate',
  'observationAggregate',
  'observationResult',
  'mappedResult',
  'result',
  'state',
  'findingState',
  'timestamp',
  'createdAt',
  'updatedAt',
  'lastObservedAt',
  'firstObservedAt',
  'resolvedAt',
  'reopenedAt',
  'observedAt',
  'version',
  'findingVersion',
  'componentOccurrenceId',
  'representativeOccurrenceId',
  'occurrenceId',
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
  'remediation',
  'remediationState',
  'verification',
  'verificationState',
  'explanation',
  'auditAction',
  'prisma',
  'transaction',
  'absenceAuthority',
  'callerAssertsAbsent',
  'fingerprint',
  'replayFingerprint',
  'supportFingerprint',
] as const;

export const FINDING_REPEATED_OBSERVATION_AMBIENT_CLAIMS = [
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
  'assetManagement',
  'canCreateFinding',
  'canInspectFinding',
  'canDiscoverFinding',
  'canTriageFinding',
  'canObserveFinding',
] as const;

export const FINDING_REPEATED_OBSERVATION_REJECTED_GENERIC_PURPOSES = [
  'observe_finding',
  'finding_observe',
  'record_finding_observation',
  'update_finding',
] as const;

export const FINDING_REPEATED_OBSERVATION_CALLER_SUPPLIED_FIELDS = Object.freeze([
  'purpose',
  'policyId',
  'policyVersion',
  'expectedFindingId',
  'expectedAssetId',
  'expectedComponentId',
  'expectedVulnerabilityId',
  'expectedSbomIngestionId',
  'support',
  'correlationId',
] as const);

export const FINDING_REPEATED_OBSERVATION_DERIVED_FIELDS = Object.freeze([
  'organizationId',
  'actorId',
  'membershipId',
  'aggregate',
  'mappedResult',
  'supportCount',
  'supportFingerprint',
  'replayFingerprint',
  'lastObservedAt',
  'updatedAt',
  'auditAction',
] as const);

export const FINDING_REPEATED_OBSERVATION_FINDING_MUTATION = Object.freeze({
  directMutationAuthority: false,
  futureTransactionDerivesTimestamps: true,
  databaseTime: true,
  permittedSummaryFields: Object.freeze(['last_observed_at', 'updated_at'] as const),
  deniedFields: Object.freeze([
    'organization_id',
    'asset_id',
    'component_id',
    'vulnerability_id',
    'state',
    'version',
    'first_observed_at',
    'component_occurrence_id',
    'resolved_at',
    'reopened_at',
    'assigned_membership_id',
    'assigned_team_id',
    'due_at',
    'current_risk_calculation_id',
    'created_at',
  ] as const),
  stateAfterEveryAggregate: 'open',
  versionRemains: 1,
} as const);

export const FINDING_REPEATED_OBSERVATION_WITHHELD_POWERS = Object.freeze({
  findingCreation: 'unavailable',
  findingClosure: 'unavailable',
  findingReopening: 'unavailable',
  remediationVerification: 'unavailable',
  automaticObservation: 'unavailable',
  bulkObservation: 'unavailable',
  riskCalculation: 'unavailable',
  priority: 'unavailable',
  assignment: 'unavailable',
  dueDates: 'unavailable',
  suppression: 'unavailable',
  acceptedRisk: 'unavailable',
  falsePositiveDecisions: 'unavailable',
  remediationWorkflow: 'unavailable',
  verificationWorkflow: 'unavailable',
  notifications: 'unavailable',
  dashboards: 'unavailable',
  exports: 'unavailable',
  ticketing: 'unavailable',
  aiAuthority: 'unavailable',
  historicalBackfill: 'unavailable',
  providerAcquisition: 'unavailable',
  evaluatorExecution: 'unavailable',
} as const);

export const FINDING_REPEATED_OBSERVATION_ZERO_EFFECTS = Object.freeze({
  findingWrites: 0,
  findingObservationWrites: 0,
  evidenceLinkWrites: 0,
  findingTimestampUpdates: 0,
  auditWrites: 0,
  findingObservedAuditWrites: 0,
  evaluatorCalls: 0,
  providerCalls: 0,
  persistenceWrites: 0,
  automaticObservationOperations: 0,
  bulkObservationOperations: 0,
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
  findingClosureOperations: 0,
  findingReopeningOperations: 0,
  aiAuthorityOperations: 0,
  historicalBackfillOperations: 0,
});

export const FINDING_REPEATED_OBSERVATION_ABSENCE_NONAUTHORITY = Object.freeze({
  callerEstablishesAbsence: false,
  meansRemediated: false,
  meansVerified: false,
  meansResolved: false,
  meansSafe: false,
  meansClosed: false,
  emptyGraphIsProof: false,
  partialGraphIsProof: false,
  missingEvidenceIsAbsence: false,
  unknownVersionIsAbsence: false,
} as const);

export const FINDING_REPEATED_OBSERVATION_INVARIANTS = Object.freeze({
  structuralCommandIsAuthority: false,
  plainObjectIsAuthority: false,
  jsonValueIsAuthority: false,
  clonedHandleIsAuthority: false,
  spreadObjectIsAuthority: false,
  prototypeCopyIsAuthority: false,
  proxyIsAuthority: false,
  typeAssertionIsAuthority: false,
  roleIsAuthority: false,
  permissionIsAuthority: false,
  administratorIsAuthority: false,
  membershipAloneIsAuthority: false,
  findingCreationPermissionIsAuthority: false,
  findingInspectionPermissionIsAuthority: false,
  findingDiscoveryPermissionIsAuthority: false,
  findingTriagePermissionIsAuthority: false,
  assetManagementIsAuthority: false,
  trustedContextIsObservationAuthority: false,
  clientOrganizationIdIsAuthorization: false,
  callerSelectsAggregate: false,
  callerSelectsObservationResult: false,
  callerSelectsAbsenceAuthority: false,
  storedAbsentAloneIsProductAggregate: false,
  unaffectedEqualsComponentAbsent: false,
  fingerprintEqualityReplacesSemanticValidation: false,
  supportFingerprintIsAuthority: false,
  correlationIsReplayIdentity: false,
  correlationIsAuthorizationBinding: true,
  ingestionIsFindingIdentity: false,
  ingestionIsObservationNaturalIdentity: true,
  componentOccurrenceIsFindingIdentity: false,
  componentVersionIsFindingIdentity: false,
  productMatchEvidenceIdIsFindingIdentity: false,
  observationResultIsFindingIdentity: false,
  aggregateIsFindingIdentity: false,
  policyVersionIsFindingIdentity: false,
  evidenceFingerprintIsFindingIdentity: false,
  actorIsFindingIdentity: false,
  actorIsObservationNaturalIdentity: false,
  unaffectedOccurrenceVetoesAffected: false,
  unknownDominatesUnaffectedWhenNothingAffected: true,
  directAndTransitiveOccurrencesAreRelevant: true,
  authorizationIsDurable: false,
  authorizationIsConsumed: false,
  authorizationExpires: false,
  durableObservationAuthorityTable: false,
  reviewerCapabilityPersistenceCopied: false,
  exactPresentationContinuesToPersistedFactValidation: true,
  exactReuseAfterCommitResolvedByPersistedReplay: true,
  staleEvidenceRejectedAtTransactionTime: true,
  genericSuccessBoolean: false,
  issuerPackageExport: 'absent',
  issuerDeepImportSupported: false,
  internalIssuerTrustBoundary: 'same_package_relative_import',
  issuerProductionCaller: 'absent',
  productionRegistration: FINDING_REPEATED_OBSERVATION_PRODUCTION_REGISTRATION,
  persistenceImplemented: true,
  migrationImplemented: true,
  observationCanBeWritten: true,
  findingTimestampCanBeUpdated: true,
  findingObservedAuditCanBeWritten: true,
  sliceComplete: false,
  session: 'controlled_finding_repeated_observation_session_2',
  authorityReview: 'controlled_finding_repeated_observation_session_1r',
  nextSession: 'controlled_finding_repeated_observation_session_2r',
} as const);

export const FINDING_REPEATED_OBSERVATION_PERSISTENCE_BOUNDARY = Object.freeze({
  implemented: true,
  migrationImplemented: true,
  adapterImplemented: true,
  productionComposition: 'absent',
  canWriteObservation: true,
  canCreateEvidenceLink: true,
  canUpdateFinding: false,
  canUpdateFindingTimestamp: true,
  canWriteFindingObservedAudit: true,
  issuerPackageExport: 'absent',
  reloadsOrganizationAndActiveMembership: true,
  clientOrganizationIdIsAuthorization: false,
  durableObservationAuthorityTable: false,
  databaseTimeDefinesObservationTimestamps: true,
  networkIoInsideTransaction: false,
  queueIoInsideTransaction: false,
  objectStorageIoInsideTransaction: false,
  parserIoInsideTransaction: false,
  evaluatorIoInsideTransaction: false,
  providerIoInsideTransaction: false,
  sliceComplete: false,
  frozenMigrationCount: 25,
} as const);

const OUTCOME_EXPLANATIONS: Record<
  FindingRepeatedObservationOutcome | FindingRepeatedObservationAuthorizationOutcome,
  string
> = {
  authorized: 'repeated-observation authorization matches the bound request',
  observed: 'one repeated observation was recorded and the Finding stayed open',
  already_applied: 'matching repeated-observation records already exist',
  invalid_command: 'repeated-observation command was rejected',
  authority_required: 'repeated-observation authorization is required',
  authority_rejected: 'repeated-observation authorization was rejected',
  not_found: 'repeated-observation target is not available',
  ingestion_not_completed: 'target ingestion is not a completed ingestion',
  ingestion_not_latest: 'target ingestion is not the latest successful ingestion',
  ingestion_not_later: 'target ingestion is not strictly later than creation',
  unsupported_normalization_version: 'target ingestion normalization version is not supported',
  evidence_unavailable: 'complete current evidence or absence proof is not available',
  evidence_set_oversized: 'combined support set exceeds the observation policy limit',
  evidence_set_mismatch: 'support set does not match the authorization',
  evidence_not_current: 'support evidence is not current',
  immutable_conflict: 'repeated observation conflicts with stored immutable facts',
  malformed_persisted_state: 'persisted observation state is malformed',
  concurrency_conflict: 'repeated observation did not converge',
  transaction_aborted: 'repeated-observation transaction aborted',
  database_unavailable: 'repeated-observation store is unavailable',
  internal_failure: 'repeated-observation authorization failed closed',
};

export function findingRepeatedObservationOutcomeExplanation(
  outcome: FindingRepeatedObservationOutcome | FindingRepeatedObservationAuthorizationOutcome,
): string {
  return OUTCOME_EXPLANATIONS[outcome];
}

export function isFindingRepeatedObservationOutcome(
  value: unknown,
): value is FindingRepeatedObservationOutcome {
  return (
    typeof value === 'string' &&
    (FINDING_REPEATED_OBSERVATION_OUTCOMES as readonly string[]).includes(value)
  );
}

export function isFindingRepeatedObservationAggregate(
  value: unknown,
): value is FindingRepeatedObservationAggregate {
  return (
    typeof value === 'string' &&
    (FINDING_REPEATED_OBSERVATION_AGGREGATES as readonly string[]).includes(value)
  );
}

export function mapRepeatedObservationAggregate(
  aggregate: FindingRepeatedObservationAggregate,
): FindingObservationResult {
  return FINDING_REPEATED_OBSERVATION_AGGREGATE_RESULT[aggregate];
}

export function findingRepeatedObservationOutcomeForReason(
  reason: FindingRepeatedObservationReason,
): FindingRepeatedObservationAuthorizationOutcome {
  switch (reason) {
    case 'exact_binding':
      return 'authorized';
    case 'authorization_missing':
      return 'authority_required';
    case 'evidence_set_mismatch':
    case 'unknown_version_set_mismatch':
    case 'absence_proof_mismatch':
      return 'evidence_set_mismatch';
    case 'evidence_set_oversized':
      return 'evidence_set_oversized';
    case 'unsupported_normalization_version':
      return 'unsupported_normalization_version';
    case 'evidence_set_empty':
    case 'evidence_set_duplicate':
    case 'evidence_set_unsorted':
    case 'evidence_set_malformed':
    case 'evidence_set_hostile':
    case 'unknown_version_duplicate':
    case 'unknown_version_unsorted':
    case 'unknown_version_malformed':
    case 'unknown_version_hostile':
    case 'support_mutually_exclusive':
    case 'absence_graph_rejected':
    case 'absence_count_rejected':
    case 'command_rejected':
    case 'trusted_context_rejected':
    case 'schema_mismatch':
    case 'caller_selected_aggregate':
    case 'caller_selected_result':
      return 'invalid_command';
    case 'internal':
      return 'internal_failure';
    case 'authorization_unrecognized':
    case 'purpose_mismatch':
    case 'policy_mismatch':
    case 'correlation_mismatch':
    case 'membership_mismatch':
    case 'actor_mismatch':
    case 'organization_mismatch':
    case 'finding_mismatch':
    case 'asset_mismatch':
    case 'component_mismatch':
    case 'vulnerability_mismatch':
    case 'ingestion_mismatch':
    case 'membership_inactive':
    case 'ambient_authority_rejected':
      return 'authority_rejected';
    default:
      return 'internal_failure';
  }
}
