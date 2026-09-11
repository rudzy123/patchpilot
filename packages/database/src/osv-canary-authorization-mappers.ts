/**
 * Session 13 Batch 2C mapping from Prisma OSV canary authorization rows to
 * Batch 2A/2C contracts. Mappers reconstruct records through committed
 * constructors. They never include credentials, holder tokens, page tokens,
 * provider bodies, tenant fields, or Findings.
 */

import type {
  OsvCanaryAuthorizationPurpose,
  OsvCanaryAuthorizationState,
  OsvCanaryLegalPermittedOperation,
  OsvCanaryListingReviewVerdict,
  OsvCanaryOperatorIdentityStatus,
  OsvCanaryPhase,
  OsvRuntimeSynchronizationReason,
  OsvRuntimeWorkScope,
} from '@prisma/client';
import {
  createOsvCanaryActivationProhibitionAcknowledgement,
  createOsvCanaryAuthorizationSnapshot,
  createOsvCanaryAutomaticRetryProhibitionAcknowledgement,
  createOsvCanaryHaltControlAcknowledgement,
  createOsvCanaryInstanceOperatorIdentity,
  createOsvCanaryLegalDecisionReference,
  createOsvCanaryListingReviewEvidence,
  createOsvCanaryRunbookAcknowledgement,
  evaluateOsvCanaryOperatorIdentityRevoke,
  getOsvCanaryBudgetProfile,
  markOsvCanaryAuthorizationConstructed,
  type OsvCanaryAuthorizationRecord,
  type OsvCanaryPersistedAuthorization,
  type OsvCanaryPersistedOperatorIdentity,
} from '@patchpilot/vulnerability-intelligence';

const AUTHORIZATION_SCHEMA_VERSION = 'osv_canary_execution_authorization_record_v1';
const CANARY_ARCHITECTURE = 'osv_first_real_provider_canary_authorization_v1';
const RUNTIME_ARCHITECTURE = 'osv_runtime_enablement_architecture_v1';
const LISTING_PROTOCOL = 'osv_gcs_json_objects_list_v1';
const SELECTED_PREFIX = 'crates.io/';
const SOURCE_IDENTIFIER = 'rustsec_advisory_database';
const FAMILY = 'RUSTSEC';
const POLICY_IDENTIFIER = 'osv_disabled_first_provider_canary_policy_v1';
const WORK_SCOPE = 'osv_runtime_canary_scope_crates_io_rustsec_v1';
const LEASE_SCOPE = 'osv_runtime_lease_scope_osv_gcs_public_export_v1';
const LISTING_BUDGET = 'osv_canary_listing_only_budget_v1';
const BODY_BUDGET = 'osv_canary_bounded_body_budget_v1';
const UNUSED_TTL_SECONDS = 3600;
const AUTHORIZATION_STATES = [
  'issued',
  'consumed',
  'completed',
  'failed',
  'cancelled',
  'revoked',
  'expired',
] as const;

export class OsvCanaryAuthorizationMappingError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = 'OsvCanaryAuthorizationMappingError';
  }
}

export function toIsoUtc(value: Date): string {
  return value.toISOString().replace(/\.000Z$/, 'Z');
}

function readField(row: Record<string, unknown>, camel: string, snake: string): unknown {
  if (Object.hasOwn(row, camel)) {
    return row[camel];
  }
  return row[snake];
}

function readString(row: Record<string, unknown>, camel: string, snake: string): string {
  const value = readField(row, camel, snake);
  if (typeof value !== 'string' || value.length === 0) {
    throw new OsvCanaryAuthorizationMappingError('string mapping failed.');
  }
  return value;
}

function readOptionalString(
  row: Record<string, unknown>,
  camel: string,
  snake: string,
): string | null {
  const value = readField(row, camel, snake);
  if (value === null || value === undefined) {
    return null;
  }
  if (typeof value !== 'string' || value.length === 0) {
    throw new OsvCanaryAuthorizationMappingError('optional string mapping failed.');
  }
  return value;
}

function readDate(row: Record<string, unknown>, camel: string, snake: string): Date {
  const value = readField(row, camel, snake);
  if (!(value instanceof Date) || Number.isNaN(value.getTime())) {
    throw new OsvCanaryAuthorizationMappingError('timestamp mapping failed.');
  }
  return value;
}

function readOptionalDate(row: Record<string, unknown>, camel: string, snake: string): Date | null {
  const value = readField(row, camel, snake);
  if (value === null || value === undefined) {
    return null;
  }
  if (!(value instanceof Date) || Number.isNaN(value.getTime())) {
    throw new OsvCanaryAuthorizationMappingError('optional timestamp mapping failed.');
  }
  return value;
}

function requireExact(actual: string, expected: string): string {
  if (actual !== expected) {
    throw new OsvCanaryAuthorizationMappingError('persisted constant mismatch.');
  }
  return actual;
}

function readExactInteger(row: Record<string, unknown>, camel: string, snake: string): number {
  const value = readField(row, camel, snake);
  if (typeof value === 'number' && Number.isInteger(value)) {
    return value;
  }
  if (
    typeof value === 'bigint' &&
    value >= BigInt(Number.MIN_SAFE_INTEGER) &&
    value <= BigInt(Number.MAX_SAFE_INTEGER)
  ) {
    return Number(value);
  }
  if (typeof value === 'string' && /^-?\d+$/.test(value)) {
    const parsed = Number(value);
    if (Number.isInteger(parsed)) {
      return parsed;
    }
  }
  throw new OsvCanaryAuthorizationMappingError('integer mapping failed.');
}

function readOperatorStatus(row: Record<string, unknown>): OsvCanaryOperatorIdentityStatus {
  const value = readString(row, 'status', 'status');
  if (value === 'active' || value === 'revoked') {
    return value;
  }
  throw new OsvCanaryAuthorizationMappingError('operator status mapping failed.');
}

function readAuthorizationState(row: Record<string, unknown>): OsvCanaryAuthorizationState {
  const value = readString(row, 'state', 'state');
  if ((AUTHORIZATION_STATES as readonly string[]).includes(value)) {
    return value as OsvCanaryAuthorizationState;
  }
  throw new OsvCanaryAuthorizationMappingError('authorization state mapping failed.');
}

export type OperatorRow = {
  readonly id: string;
  readonly identitySchemaVersion: string;
  readonly identityType: string;
  readonly authenticationSource: string;
  readonly provenanceIdentifier: string;
  readonly displayLabel: string;
  readonly establishedAt: Date;
  readonly status: OsvCanaryOperatorIdentityStatus;
  readonly revokedAt: Date | null;
  readonly createdAt: Date;
};

export type AuthorizationRow = {
  readonly id: string;
  readonly operatorIdentityId: string;
  readonly authorizationSchemaVersion: string;
  readonly canaryArchitectureIdentifier: string;
  readonly runtimeArchitectureIdentifier: string;
  readonly listingProtocolIdentifier: string;
  readonly actorKind: string;
  readonly phase: OsvCanaryPhase;
  readonly synchronizationReason: OsvRuntimeSynchronizationReason;
  readonly authorizationPurpose: OsvCanaryAuthorizationPurpose;
  readonly providerPrefix: string;
  readonly sourceIdentifier: string;
  readonly family: string;
  readonly canaryPolicyIdentifier: string;
  readonly workScope: OsvRuntimeWorkScope;
  readonly leaseScope: string;
  readonly runtimeVersionSetFingerprint: string;
  readonly budgetProfileIdentifier: string;
  readonly unusedTtlSeconds: number;
  readonly singleUsePolicy: string;
  readonly catalogActivationAuthorization: string;
  readonly matchingAuthorization: string;
  readonly findingAuthorization: string;
  readonly postcanaryReviewRequirement: string;
  readonly legalDecisionReferenceIdentifier: string;
  readonly legalDecisionId: string;
  readonly legalDecisionSourceRegistryVersion: string;
  readonly legalDecisionPhase: OsvCanaryPhase;
  readonly legalDecisionPermittedOperation: OsvCanaryLegalPermittedOperation;
  readonly legalDecisionState: string;
  readonly legalDecisionIssuance: string;
  readonly legalDecisionIssuedAt: Date;
  readonly legalDecisionRevalidationBoundaryAt: Date;
  readonly legalDecisionResponsibleRole: string;
  readonly legalDecisionEvidenceSetId: string;
  readonly bodyLegalDecisionId: string | null;
  readonly bodyLegalDecisionPhase: OsvCanaryPhase | null;
  readonly bodyLegalDecisionPermittedOperation: OsvCanaryLegalPermittedOperation | null;
  readonly bodyLegalDecisionIssuedAt: Date | null;
  readonly bodyLegalDecisionRevalidationBoundaryAt: Date | null;
  readonly bodyLegalDecisionEvidenceSetId: string | null;
  readonly bodyRetrieveDisposition: string | null;
  readonly bodyTransientInspectionDisposition: string | null;
  readonly bodyPrivateRetentionDisposition: string | null;
  readonly bodyParseDisposition: string | null;
  readonly bodyExternalExposureDisposition: string | null;
  readonly bodyMatchingDisposition: string | null;
  readonly listingReviewEvidenceIdentifier: string | null;
  readonly listingReviewId: string | null;
  readonly listingAuthorizationId: string | null;
  readonly listingRequestId: string | null;
  readonly listingRunId: string | null;
  readonly listingCanonicalInventoryEvidenceId: string | null;
  readonly listingReviewVerdict: OsvCanaryListingReviewVerdict | null;
  readonly listingReviewedAt: Date | null;
  readonly listingReviewerRole: string | null;
  readonly bodySelectionAlgorithmIdentifier: string | null;
  readonly runbookSetIdentifier: string;
  readonly runbookVersion: string;
  readonly runbookAcknowledgedAt: Date;
  readonly runbookEmergencyHaltProcedure: string;
  readonly haltAcknowledgementIdentifier: string;
  readonly haltAcknowledgedAt: Date;
  readonly activationProhibitionIdentifier: string;
  readonly retryProhibitionIdentifier: string;
  readonly issuedAt: Date;
  readonly expiresAt: Date;
  readonly state: OsvCanaryAuthorizationState;
  readonly consumedAt: Date | null;
  readonly consumedBySynchronizationRequestId: string | null;
  readonly consumedBySynchronizationRunId: string | null;
  readonly terminalAt: Date | null;
  readonly terminalDisposition: OsvCanaryAuthorizationState | null;
  readonly terminalReasonCode: string | null;
  readonly revokedAt: Date | null;
  readonly revokedByOperatorIdentityId: string | null;
  readonly createdAt: Date;
};

export function coerceOperatorRow(raw: Record<string, unknown>): OperatorRow {
  return {
    id: readString(raw, 'id', 'id'),
    identitySchemaVersion: readString(raw, 'identitySchemaVersion', 'identity_schema_version'),
    identityType: readString(raw, 'identityType', 'identity_type'),
    authenticationSource: readString(raw, 'authenticationSource', 'authentication_source'),
    provenanceIdentifier: readString(raw, 'provenanceIdentifier', 'provenance_identifier'),
    displayLabel: readString(raw, 'displayLabel', 'display_label'),
    establishedAt: readDate(raw, 'establishedAt', 'established_at'),
    status: readOperatorStatus(raw),
    revokedAt: readOptionalDate(raw, 'revokedAt', 'revoked_at'),
    createdAt: readDate(raw, 'createdAt', 'created_at'),
  };
}

export function coerceAuthorizationRow(raw: Record<string, unknown>): AuthorizationRow {
  return {
    id: readString(raw, 'id', 'id'),
    operatorIdentityId: readString(raw, 'operatorIdentityId', 'operator_identity_id'),
    authorizationSchemaVersion: readString(
      raw,
      'authorizationSchemaVersion',
      'authorization_schema_version',
    ),
    canaryArchitectureIdentifier: readString(
      raw,
      'canaryArchitectureIdentifier',
      'canary_architecture_identifier',
    ),
    runtimeArchitectureIdentifier: readString(
      raw,
      'runtimeArchitectureIdentifier',
      'runtime_architecture_identifier',
    ),
    listingProtocolIdentifier: readString(
      raw,
      'listingProtocolIdentifier',
      'listing_protocol_identifier',
    ),
    actorKind: readString(raw, 'actorKind', 'actor_kind'),
    phase: readString(raw, 'phase', 'phase') as OsvCanaryPhase,
    synchronizationReason: readString(
      raw,
      'synchronizationReason',
      'synchronization_reason',
    ) as OsvRuntimeSynchronizationReason,
    authorizationPurpose: readString(
      raw,
      'authorizationPurpose',
      'authorization_purpose',
    ) as OsvCanaryAuthorizationPurpose,
    providerPrefix: readString(raw, 'providerPrefix', 'provider_prefix'),
    sourceIdentifier: readString(raw, 'sourceIdentifier', 'source_identifier'),
    family: readString(raw, 'family', 'family'),
    canaryPolicyIdentifier: readString(raw, 'canaryPolicyIdentifier', 'canary_policy_identifier'),
    workScope: readString(raw, 'workScope', 'work_scope') as OsvRuntimeWorkScope,
    leaseScope: readString(raw, 'leaseScope', 'lease_scope'),
    runtimeVersionSetFingerprint: readString(
      raw,
      'runtimeVersionSetFingerprint',
      'runtime_version_set_fingerprint',
    ),
    budgetProfileIdentifier: readString(
      raw,
      'budgetProfileIdentifier',
      'budget_profile_identifier',
    ),
    unusedTtlSeconds: readExactInteger(raw, 'unusedTtlSeconds', 'unused_ttl_seconds'),
    singleUsePolicy: readString(raw, 'singleUsePolicy', 'single_use_policy'),
    catalogActivationAuthorization: readString(
      raw,
      'catalogActivationAuthorization',
      'catalog_activation_authorization',
    ),
    matchingAuthorization: readString(raw, 'matchingAuthorization', 'matching_authorization'),
    findingAuthorization: readString(raw, 'findingAuthorization', 'finding_authorization'),
    postcanaryReviewRequirement: readString(
      raw,
      'postcanaryReviewRequirement',
      'postcanary_review_requirement',
    ),
    legalDecisionReferenceIdentifier: readString(
      raw,
      'legalDecisionReferenceIdentifier',
      'legal_decision_reference_identifier',
    ),
    legalDecisionId: readString(raw, 'legalDecisionId', 'legal_decision_id'),
    legalDecisionSourceRegistryVersion: readString(
      raw,
      'legalDecisionSourceRegistryVersion',
      'legal_decision_source_registry_version',
    ),
    legalDecisionPhase: readString(
      raw,
      'legalDecisionPhase',
      'legal_decision_phase',
    ) as OsvCanaryPhase,
    legalDecisionPermittedOperation: readString(
      raw,
      'legalDecisionPermittedOperation',
      'legal_decision_permitted_operation',
    ) as OsvCanaryLegalPermittedOperation,
    legalDecisionState: readString(raw, 'legalDecisionState', 'legal_decision_state'),
    legalDecisionIssuance: readString(raw, 'legalDecisionIssuance', 'legal_decision_issuance'),
    legalDecisionIssuedAt: readDate(raw, 'legalDecisionIssuedAt', 'legal_decision_issued_at'),
    legalDecisionRevalidationBoundaryAt: readDate(
      raw,
      'legalDecisionRevalidationBoundaryAt',
      'legal_decision_revalidation_boundary_at',
    ),
    legalDecisionResponsibleRole: readString(
      raw,
      'legalDecisionResponsibleRole',
      'legal_decision_responsible_role',
    ),
    legalDecisionEvidenceSetId: readString(
      raw,
      'legalDecisionEvidenceSetId',
      'legal_decision_evidence_set_id',
    ),
    bodyLegalDecisionId: readOptionalString(raw, 'bodyLegalDecisionId', 'body_legal_decision_id'),
    bodyLegalDecisionPhase: readOptionalString(
      raw,
      'bodyLegalDecisionPhase',
      'body_legal_decision_phase',
    ) as OsvCanaryPhase | null,
    bodyLegalDecisionPermittedOperation: readOptionalString(
      raw,
      'bodyLegalDecisionPermittedOperation',
      'body_legal_decision_permitted_operation',
    ) as OsvCanaryLegalPermittedOperation | null,
    bodyLegalDecisionIssuedAt: readOptionalDate(
      raw,
      'bodyLegalDecisionIssuedAt',
      'body_legal_decision_issued_at',
    ),
    bodyLegalDecisionRevalidationBoundaryAt: readOptionalDate(
      raw,
      'bodyLegalDecisionRevalidationBoundaryAt',
      'body_legal_decision_revalidation_boundary_at',
    ),
    bodyLegalDecisionEvidenceSetId: readOptionalString(
      raw,
      'bodyLegalDecisionEvidenceSetId',
      'body_legal_decision_evidence_set_id',
    ),
    bodyRetrieveDisposition: readOptionalString(
      raw,
      'bodyRetrieveDisposition',
      'body_retrieve_disposition',
    ),
    bodyTransientInspectionDisposition: readOptionalString(
      raw,
      'bodyTransientInspectionDisposition',
      'body_transient_inspection_disposition',
    ),
    bodyPrivateRetentionDisposition: readOptionalString(
      raw,
      'bodyPrivateRetentionDisposition',
      'body_private_retention_disposition',
    ),
    bodyParseDisposition: readOptionalString(raw, 'bodyParseDisposition', 'body_parse_disposition'),
    bodyExternalExposureDisposition: readOptionalString(
      raw,
      'bodyExternalExposureDisposition',
      'body_external_exposure_disposition',
    ),
    bodyMatchingDisposition: readOptionalString(
      raw,
      'bodyMatchingDisposition',
      'body_matching_disposition',
    ),
    listingReviewEvidenceIdentifier: readOptionalString(
      raw,
      'listingReviewEvidenceIdentifier',
      'listing_review_evidence_identifier',
    ),
    listingReviewId: readOptionalString(raw, 'listingReviewId', 'listing_review_id'),
    listingAuthorizationId: readOptionalString(
      raw,
      'listingAuthorizationId',
      'listing_authorization_id',
    ),
    listingRequestId: readOptionalString(raw, 'listingRequestId', 'listing_request_id'),
    listingRunId: readOptionalString(raw, 'listingRunId', 'listing_run_id'),
    listingCanonicalInventoryEvidenceId: readOptionalString(
      raw,
      'listingCanonicalInventoryEvidenceId',
      'listing_canonical_inventory_evidence_id',
    ),
    listingReviewVerdict: readOptionalString(
      raw,
      'listingReviewVerdict',
      'listing_review_verdict',
    ) as OsvCanaryListingReviewVerdict | null,
    listingReviewedAt: readOptionalDate(raw, 'listingReviewedAt', 'listing_reviewed_at'),
    listingReviewerRole: readOptionalString(raw, 'listingReviewerRole', 'listing_reviewer_role'),
    bodySelectionAlgorithmIdentifier: readOptionalString(
      raw,
      'bodySelectionAlgorithmIdentifier',
      'body_selection_algorithm_identifier',
    ),
    runbookSetIdentifier: readString(raw, 'runbookSetIdentifier', 'runbook_set_identifier'),
    runbookVersion: readString(raw, 'runbookVersion', 'runbook_version'),
    runbookAcknowledgedAt: readDate(raw, 'runbookAcknowledgedAt', 'runbook_acknowledged_at'),
    runbookEmergencyHaltProcedure: readString(
      raw,
      'runbookEmergencyHaltProcedure',
      'runbook_emergency_halt_procedure',
    ),
    haltAcknowledgementIdentifier: readString(
      raw,
      'haltAcknowledgementIdentifier',
      'halt_acknowledgement_identifier',
    ),
    haltAcknowledgedAt: readDate(raw, 'haltAcknowledgedAt', 'halt_acknowledged_at'),
    activationProhibitionIdentifier: readString(
      raw,
      'activationProhibitionIdentifier',
      'activation_prohibition_identifier',
    ),
    retryProhibitionIdentifier: readString(
      raw,
      'retryProhibitionIdentifier',
      'retry_prohibition_identifier',
    ),
    issuedAt: readDate(raw, 'issuedAt', 'issued_at'),
    expiresAt: readDate(raw, 'expiresAt', 'expires_at'),
    state: readAuthorizationState(raw),
    consumedAt: readOptionalDate(raw, 'consumedAt', 'consumed_at'),
    consumedBySynchronizationRequestId: readOptionalString(
      raw,
      'consumedBySynchronizationRequestId',
      'consumed_by_synchronization_request_id',
    ),
    consumedBySynchronizationRunId: readOptionalString(
      raw,
      'consumedBySynchronizationRunId',
      'consumed_by_synchronization_run_id',
    ),
    terminalAt: readOptionalDate(raw, 'terminalAt', 'terminal_at'),
    terminalDisposition: readOptionalString(
      raw,
      'terminalDisposition',
      'terminal_disposition',
    ) as OsvCanaryAuthorizationState | null,
    terminalReasonCode: readOptionalString(raw, 'terminalReasonCode', 'terminal_reason_code'),
    revokedAt: readOptionalDate(raw, 'revokedAt', 'revoked_at'),
    revokedByOperatorIdentityId: readOptionalString(
      raw,
      'revokedByOperatorIdentityId',
      'revoked_by_operator_identity_id',
    ),
    createdAt: readDate(raw, 'createdAt', 'created_at'),
  };
}

export function mapOperator(row: OperatorRow): OsvCanaryPersistedOperatorIdentity {
  if (row.status === 'revoked' && row.revokedAt === null) {
    throw new OsvCanaryAuthorizationMappingError('revoked operator missing revokedAt.');
  }
  if (row.status === 'active' && row.revokedAt !== null) {
    throw new OsvCanaryAuthorizationMappingError('active operator has revokedAt.');
  }
  const created = createOsvCanaryInstanceOperatorIdentity({
    operatorAttestationId: row.id,
    identityType: row.identityType,
    authenticationSource: row.authenticationSource,
    displayLabel: row.displayLabel,
    provenanceIdentifier: row.provenanceIdentifier,
    establishedAt: toIsoUtc(row.establishedAt),
  });
  if (!created.ok) {
    throw new OsvCanaryAuthorizationMappingError('operator reconstruction failed.');
  }
  let identity = created.value;
  if (row.status === 'revoked') {
    const revoked = evaluateOsvCanaryOperatorIdentityRevoke({ identity });
    if (!revoked.ok) {
      throw new OsvCanaryAuthorizationMappingError('operator revocation mapping failed.');
    }
    identity = revoked.value;
  }
  return {
    identity,
    revokedAt: row.revokedAt === null ? null : toIsoUtc(row.revokedAt),
  };
}

export function mapAuthorization(
  row: AuthorizationRow,
  operator: OsvCanaryPersistedOperatorIdentity,
): OsvCanaryPersistedAuthorization {
  if (operator.identity.operatorAttestationId !== row.operatorIdentityId) {
    throw new OsvCanaryAuthorizationMappingError('operator identity mismatch.');
  }
  requireExact(row.authorizationSchemaVersion, AUTHORIZATION_SCHEMA_VERSION);
  requireExact(row.canaryArchitectureIdentifier, CANARY_ARCHITECTURE);
  requireExact(row.runtimeArchitectureIdentifier, RUNTIME_ARCHITECTURE);
  requireExact(row.listingProtocolIdentifier, LISTING_PROTOCOL);
  requireExact(row.actorKind, 'instance_operator');
  requireExact(row.synchronizationReason, 'operator_canary');
  requireExact(row.providerPrefix, SELECTED_PREFIX);
  requireExact(row.sourceIdentifier, SOURCE_IDENTIFIER);
  requireExact(row.family, FAMILY);
  requireExact(row.canaryPolicyIdentifier, POLICY_IDENTIFIER);
  requireExact(row.workScope, WORK_SCOPE);
  requireExact(row.leaseScope, LEASE_SCOPE);
  requireExact(
    row.budgetProfileIdentifier,
    row.phase === 'listing_only' ? LISTING_BUDGET : BODY_BUDGET,
  );
  if (row.unusedTtlSeconds !== UNUSED_TTL_SECONDS) {
    throw new OsvCanaryAuthorizationMappingError('unused ttl mismatch.');
  }
  if (Math.abs(row.expiresAt.getTime() - row.issuedAt.getTime() - UNUSED_TTL_SECONDS * 1000) > 1) {
    throw new OsvCanaryAuthorizationMappingError('expiration interval mismatch.');
  }
  requireExact(row.singleUsePolicy, 'single_use');
  requireExact(row.catalogActivationAuthorization, 'prohibited');
  requireExact(row.matchingAuthorization, 'prohibited');
  requireExact(row.findingAuthorization, 'prohibited');
  requireExact(row.postcanaryReviewRequirement, 'required');
  requireExact(row.activationProhibitionIdentifier, 'osv_canary_activation_prohibition_v1');
  requireExact(row.retryProhibitionIdentifier, 'osv_canary_automatic_retry_prohibition_v1');
  if (row.phase === 'listing_only') {
    if (
      row.bodyLegalDecisionId !== null ||
      row.bodyLegalDecisionPhase !== null ||
      row.bodyLegalDecisionPermittedOperation !== null ||
      row.bodyLegalDecisionIssuedAt !== null ||
      row.bodyLegalDecisionRevalidationBoundaryAt !== null ||
      row.bodyLegalDecisionEvidenceSetId !== null ||
      row.bodyRetrieveDisposition !== null ||
      row.bodyTransientInspectionDisposition !== null ||
      row.bodyPrivateRetentionDisposition !== null ||
      row.bodyParseDisposition !== null ||
      row.bodyExternalExposureDisposition !== null ||
      row.bodyMatchingDisposition !== null ||
      row.listingReviewEvidenceIdentifier !== null ||
      row.listingReviewId !== null ||
      row.listingAuthorizationId !== null ||
      row.listingRequestId !== null ||
      row.listingRunId !== null ||
      row.listingCanonicalInventoryEvidenceId !== null ||
      row.listingReviewVerdict !== null ||
      row.listingReviewedAt !== null ||
      row.listingReviewerRole !== null ||
      row.bodySelectionAlgorithmIdentifier !== null
    ) {
      throw new OsvCanaryAuthorizationMappingError('listing-only body fields present.');
    }
  }
  const legal = createOsvCanaryLegalDecisionReference({
    decisionId: row.legalDecisionId,
    sourceRegistryVersion: row.legalDecisionSourceRegistryVersion,
    sourceIdentifier: row.sourceIdentifier,
    family: row.family,
    phase: row.legalDecisionPhase,
    permittedOperation: row.legalDecisionPermittedOperation,
    issuedAt: toIsoUtc(row.legalDecisionIssuedAt),
    revalidationBoundaryAt: toIsoUtc(row.legalDecisionRevalidationBoundaryAt),
    responsibleRole: row.legalDecisionResponsibleRole,
    evidenceSetId: row.legalDecisionEvidenceSetId,
  });
  if (!legal.ok) {
    throw new OsvCanaryAuthorizationMappingError('legal decision reconstruction failed.');
  }
  let bodyLegal = null;
  let listingReview = null;
  if (row.phase === 'bounded_body') {
    if (
      row.bodyLegalDecisionId === null ||
      row.bodyLegalDecisionPhase === null ||
      row.bodyLegalDecisionPermittedOperation === null ||
      row.bodyLegalDecisionIssuedAt === null ||
      row.bodyLegalDecisionRevalidationBoundaryAt === null ||
      row.bodyLegalDecisionEvidenceSetId === null ||
      row.listingAuthorizationId === null ||
      row.listingRunId === null ||
      row.listingReviewId === null ||
      row.listingCanonicalInventoryEvidenceId === null ||
      row.listingReviewVerdict === null ||
      row.listingReviewedAt === null ||
      row.listingReviewerRole === null
    ) {
      throw new OsvCanaryAuthorizationMappingError('bounded-body evidence missing.');
    }
    const body = createOsvCanaryLegalDecisionReference({
      decisionId: row.bodyLegalDecisionId,
      sourceRegistryVersion: row.legalDecisionSourceRegistryVersion,
      sourceIdentifier: row.sourceIdentifier,
      family: row.family,
      phase: row.bodyLegalDecisionPhase,
      permittedOperation: row.bodyLegalDecisionPermittedOperation,
      issuedAt: toIsoUtc(row.bodyLegalDecisionIssuedAt),
      revalidationBoundaryAt: toIsoUtc(row.bodyLegalDecisionRevalidationBoundaryAt),
      responsibleRole: row.legalDecisionResponsibleRole,
      evidenceSetId: row.bodyLegalDecisionEvidenceSetId,
    });
    if (!body.ok) {
      throw new OsvCanaryAuthorizationMappingError('body legal decision reconstruction failed.');
    }
    bodyLegal = body.value;
    const review = createOsvCanaryListingReviewEvidence({
      listingAuthorizationId: row.listingAuthorizationId,
      listingRunId: row.listingRunId,
      reviewId: row.listingReviewId,
      providerPrefix: row.providerPrefix,
      sourceIdentifier: row.sourceIdentifier,
      canonicalInventoryEvidenceId: row.listingCanonicalInventoryEvidenceId,
      canaryPolicyIdentifier: row.canaryPolicyIdentifier,
      workScope: row.workScope,
      runtimeVersionSetFingerprint: row.runtimeVersionSetFingerprint,
      verdict: row.listingReviewVerdict,
      reviewedAt: toIsoUtc(row.listingReviewedAt),
      reviewerRole: row.listingReviewerRole,
    });
    if (!review.ok) {
      throw new OsvCanaryAuthorizationMappingError('listing review reconstruction failed.');
    }
    listingReview = review.value;
  }
  const runbook = createOsvCanaryRunbookAcknowledgement({
    runbookSetIdentifier: row.runbookSetIdentifier,
    runbookVersion: row.runbookVersion,
    acknowledgedAt: toIsoUtc(row.runbookAcknowledgedAt),
    phase: row.phase,
  });
  if (!runbook.ok) {
    throw new OsvCanaryAuthorizationMappingError('runbook reconstruction failed.');
  }
  const halt = createOsvCanaryHaltControlAcknowledgement({
    acknowledgedAt: toIsoUtc(row.haltAcknowledgedAt),
  });
  if (!halt.ok) {
    throw new OsvCanaryAuthorizationMappingError('halt acknowledgement reconstruction failed.');
  }
  const activation = createOsvCanaryActivationProhibitionAcknowledgement();
  if (!activation.ok) {
    throw new OsvCanaryAuthorizationMappingError(
      'activation acknowledgement reconstruction failed.',
    );
  }
  const retry = createOsvCanaryAutomaticRetryProhibitionAcknowledgement();
  if (!retry.ok) {
    throw new OsvCanaryAuthorizationMappingError('retry acknowledgement reconstruction failed.');
  }
  const record = markOsvCanaryAuthorizationConstructed({
    authorizationSchemaVersion: AUTHORIZATION_SCHEMA_VERSION,
    canaryArchitectureIdentifier: CANARY_ARCHITECTURE,
    runtimeArchitectureIdentifier: RUNTIME_ARCHITECTURE,
    listingProtocolIdentifier: LISTING_PROTOCOL,
    authorizationId: row.id,
    operatorAttestationId: row.operatorIdentityId,
    actorKind: 'instance_operator',
    phase: row.phase,
    synchronizationReason: 'operator_canary',
    authorizationPurpose: row.authorizationPurpose,
    providerPrefix: SELECTED_PREFIX,
    sourceIdentifier: SOURCE_IDENTIFIER,
    family: FAMILY,
    canaryPolicyIdentifier: POLICY_IDENTIFIER,
    workScope: WORK_SCOPE,
    leaseScope: LEASE_SCOPE,
    runtimeVersionSetFingerprint: row.runtimeVersionSetFingerprint,
    budgetProfile: getOsvCanaryBudgetProfile(row.phase),
    issuedAt: toIsoUtc(row.issuedAt),
    expiresAt: toIsoUtc(row.expiresAt),
    unusedTtlSeconds: UNUSED_TTL_SECONDS,
    singleUse: true,
    state: 'issued',
    consumedAt: null,
    terminalDisposition: null,
    postcanaryReviewRequired: true,
    catalogActivationAuthorization: 'prohibited',
    matchingAuthorization: 'prohibited',
    findingAuthorization: 'prohibited',
    operatorIdentity: operator.identity,
    legalDecisionReference: legal.value,
    bodyLegalDecisionReference: bodyLegal,
    listingReviewEvidence: listingReview,
    runbookAcknowledgement: runbook.value,
    haltControlAcknowledgement: halt.value,
    activationProhibitionAcknowledgement: activation.value,
    automaticRetryProhibitionAcknowledgement: retry.value,
  } as OsvCanaryAuthorizationRecord);
  const consumption =
    row.consumedAt === null ||
    row.consumedBySynchronizationRequestId === null ||
    row.consumedBySynchronizationRunId === null
      ? null
      : {
          requestId: row.consumedBySynchronizationRequestId,
          runId: row.consumedBySynchronizationRunId,
          consumedAt: toIsoUtc(row.consumedAt),
        };
  const snapshot = createOsvCanaryAuthorizationSnapshot({
    record,
    state: row.state,
    consumption,
    terminalDisposition:
      row.terminalDisposition === 'completed' ||
      row.terminalDisposition === 'failed' ||
      row.terminalDisposition === 'cancelled' ||
      row.terminalDisposition === 'revoked' ||
      row.terminalDisposition === 'expired'
        ? row.terminalDisposition
        : null,
  });
  if (!snapshot.ok) {
    throw new OsvCanaryAuthorizationMappingError('authorization snapshot reconstruction failed.');
  }
  return {
    snapshot: snapshot.value,
    revokedAt: row.revokedAt === null ? null : toIsoUtc(row.revokedAt),
    terminalAt: row.terminalAt === null ? null : toIsoUtc(row.terminalAt),
    terminalReasonCode: row.terminalReasonCode,
    revokedByOperatorAttestationId: row.revokedByOperatorIdentityId,
  };
}

export function firstRow<T>(
  rows: readonly unknown[],
  coerce: (raw: Record<string, unknown>) => T,
): T | undefined {
  const raw = rows[0];
  if (raw === undefined || raw === null || typeof raw !== 'object') {
    return undefined;
  }
  return coerce(raw as Record<string, unknown>);
}
