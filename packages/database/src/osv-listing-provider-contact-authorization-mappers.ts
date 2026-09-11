/**
 * Session 13 Batch 3B-A mapping from Prisma listing-only provider-contact
 * authorization rows to Batch 3B-A contracts. Mappers never include
 * credentials, holder tokens, page tokens, provider bodies, tenant fields,
 * legal prose, or Findings. They do not reconstruct full egress evidence.
 */

import type {
  OsvListingProviderContactAuthorizationState,
  OsvRuntimeSynchronizationReason,
  OsvRuntimeWorkScope,
} from '@prisma/client';
import {
  createOsvListingProviderContactPersistedAuthorization,
  isOsvListingProviderContactAuthorizationState,
  type OsvListingProviderContactPersistedAuthorization,
} from '@patchpilot/vulnerability-intelligence';

const AUTHORIZATION_SCHEMA_VERSION = 'osv_listing_only_provider_contact_authorization_v1';
const PHASE = 'listing_only';
const PROVIDER = 'rustsec_advisory_database';
const BUCKET = 'osv-vulnerabilities';
const LISTING_PATH = '/storage/v1/b/osv-vulnerabilities/o';
const LISTING_PROTOCOL = 'osv_gcs_json_objects_list_v1';
const PREFIX = 'crates.io/';
const FAMILY = 'RUSTSEC';
const POLICY = 'osv_disabled_first_provider_canary_policy_v1';
const BUDGET = 'osv_canary_listing_only_budget_v1';
const WORK_SCOPE = 'osv_runtime_canary_scope_crates_io_rustsec_v1';
const LEASE_SCOPE = 'osv_runtime_lease_scope_osv_gcs_public_export_v1';
const RUNTIME_ARCHITECTURE = 'osv_runtime_enablement_architecture_v1';
const QUERY_GRAMMAR = 'committed';
const TRANSPORT = 'osv_transport_policy_v1';
const CONTENT_ENCODING = 'identity';
const REDIRECT = 'error';
const UNUSED_TTL_SECONDS = 3600;
const SINGLE_USE = 'single_use';
const PROHIBITED = 'prohibited';
const LEGAL_APPROVAL = 'osv_listing_provider_contact_legal_approval_v1';
const LEGAL_REGISTRY = 'osv_source_license_registry_v1';
const LEGAL_ROLE = 'instance_legal_and_provenance_reviewer_countersigned_by_instance_operator';
const EGRESS_IDENTIFIER = 'osv_listing_provider_contact_egress_evidence_v1';
const EGRESS_VERSION = 'osv_listing_provider_contact_egress_evidence_v1';
const EGRESS_ROLE = 'instance_operator_deployment_reviewer';
const DEPLOYMENT_IDENTIFIER = 'osv_listing_provider_contact_deployment_approval_v1';
const ENVIRONMENT = 'dedicated_instance_operator_process';
const OBSERVABILITY = 'osv_listing_provider_contact_observability_policy_v1';
const DEPLOYMENT_ROLE = 'instance_operator_deployment_reviewer';
const HEARTBEAT = 'osv_canary_runtime_controls_v1';
const DEADLINE = 'osv_canary_runtime_controls_v1';
const RUNBOOK_SET = 'osv_listing_provider_contact_runbook_set_v1';
const RUNBOOK_VERSION = 'osv_listing_provider_contact_runbook_v1';
const HALT_PROCEDURE = 'osv_listing_provider_contact_halt_procedure_v1';
const CONTAINMENT = 'osv_listing_provider_contact_emergency_containment_v1';
const REVIEW_POLICY = 'osv_listing_provider_contact_postcanary_review_v1';
const REVIEW_ROLE = 'instance_canary_evidence_reviewer';
const RETENTION = 'osv_listing_provider_contact_retention_disposition_v1';
const SHA256 = /^[a-f0-9]{64}$/;

export class OsvListingProviderContactAuthorizationMappingError extends Error {
  public constructor(message: string) {
    super(message);
    this.name = 'OsvListingProviderContactAuthorizationMappingError';
  }
}

export function toIsoUtc(value: Date): string {
  return value.toISOString().replace(/\.000Z$/, 'Z');
}

function readField(row: Record<string, unknown>, camel: string, snake: string): unknown {
  try {
    if (Object.hasOwn(row, camel)) {
      return row[camel];
    }
    return row[snake];
  } catch {
    throw new OsvListingProviderContactAuthorizationMappingError('field mapping failed.');
  }
}

function readString(row: Record<string, unknown>, camel: string, snake: string): string {
  const value = readField(row, camel, snake);
  if (typeof value !== 'string' || value.length === 0) {
    throw new OsvListingProviderContactAuthorizationMappingError('string mapping failed.');
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
    throw new OsvListingProviderContactAuthorizationMappingError('optional string mapping failed.');
  }
  return value;
}

function readDate(row: Record<string, unknown>, camel: string, snake: string): Date {
  const value = readField(row, camel, snake);
  if (!(value instanceof Date) || Number.isNaN(value.getTime())) {
    throw new OsvListingProviderContactAuthorizationMappingError('timestamp mapping failed.');
  }
  return value;
}

function readOptionalDate(row: Record<string, unknown>, camel: string, snake: string): Date | null {
  const value = readField(row, camel, snake);
  if (value === null || value === undefined) {
    return null;
  }
  if (!(value instanceof Date) || Number.isNaN(value.getTime())) {
    throw new OsvListingProviderContactAuthorizationMappingError(
      'optional timestamp mapping failed.',
    );
  }
  return value;
}

function readBoolean(row: Record<string, unknown>, camel: string, snake: string): boolean {
  const value = readField(row, camel, snake);
  if (typeof value !== 'boolean') {
    throw new OsvListingProviderContactAuthorizationMappingError('boolean mapping failed.');
  }
  return value;
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
  throw new OsvListingProviderContactAuthorizationMappingError('integer mapping failed.');
}

function requireExact(actual: string, expected: string): string {
  if (actual !== expected) {
    throw new OsvListingProviderContactAuthorizationMappingError('persisted constant mismatch.');
  }
  return actual;
}

function requireFalse(actual: boolean): void {
  if (actual !== false) {
    throw new OsvListingProviderContactAuthorizationMappingError('persisted prohibition mismatch.');
  }
}

function requireTrue(actual: boolean): void {
  if (actual !== true) {
    throw new OsvListingProviderContactAuthorizationMappingError('persisted flag mismatch.');
  }
}

function readFingerprint(row: Record<string, unknown>, camel: string, snake: string): string {
  const value = readString(row, camel, snake);
  if (!SHA256.test(value)) {
    throw new OsvListingProviderContactAuthorizationMappingError('fingerprint mapping failed.');
  }
  return value;
}

function rejectTenantOrFinding(row: Record<string, unknown>): void {
  const forbidden = [
    'organizationId',
    'organization_id',
    'tenantId',
    'tenant_id',
    'userId',
    'user_id',
    'assetId',
    'asset_id',
    'componentId',
    'component_id',
    'findingId',
    'finding_id',
    'findingObservationId',
    'holderToken',
    'pageToken',
    'providerObjectKey',
  ];
  try {
    for (const key of forbidden) {
      if (Object.hasOwn(row, key)) {
        throw new OsvListingProviderContactAuthorizationMappingError(
          'unexpected tenant or Finding data.',
        );
      }
    }
  } catch (error) {
    if (error instanceof OsvListingProviderContactAuthorizationMappingError) {
      throw error;
    }
    throw new OsvListingProviderContactAuthorizationMappingError(
      'unexpected tenant or Finding data.',
    );
  }
}

export type ProviderContactAuthorizationRow = {
  readonly id: string;
  readonly authorizationSchemaVersion: string;
  readonly sourceCanaryAuthorizationId: string;
  readonly operatorIdentityId: string;
  readonly synchronizationRequestId: string;
  readonly synchronizationRunId: string;
  readonly preflightEvidenceId: string;
  readonly phase: string;
  readonly providerIdentity: string;
  readonly bucketIdentity: string;
  readonly listingApiPathPolicy: string;
  readonly listingProtocol: string;
  readonly approvedPrefix: string;
  readonly family: string;
  readonly canaryPolicyIdentifier: string;
  readonly listingBudgetProfile: string;
  readonly workScope: OsvRuntimeWorkScope;
  readonly leaseScope: string;
  readonly synchronizationReason: OsvRuntimeSynchronizationReason;
  readonly runtimeArchitectureIdentifier: string;
  readonly runtimeVersionSetFingerprint: string;
  readonly queryGrammarPolicy: string;
  readonly transportPolicy: string;
  readonly contentEncodingPolicy: string;
  readonly redirectPolicy: string;
  readonly unusedTtlSeconds: number;
  readonly singleUsePolicy: string;
  readonly providerRetryAuthorization: string;
  readonly providerBodyAuthorization: string;
  readonly parserAuthorization: string;
  readonly catalogActivationAuthorization: string;
  readonly matchingAuthorization: string;
  readonly findingAuthorization: string;
  readonly legalApprovalIdentifier: string;
  readonly legalDecisionId: string;
  readonly sourceCanaryLegalDecisionId: string;
  readonly legalDecisionSourceRegistryVersion: string;
  readonly legalListingMetadataPermission: string;
  readonly legalBodyRetrievalPermission: string;
  readonly legalParsingPermission: string;
  readonly legalMatchingPermission: string;
  readonly legalIssuedAt: Date;
  readonly legalRevalidationBoundaryAt: Date;
  readonly legalEvidenceSetId: string;
  readonly legalApprovalRole: string;
  readonly legalSupersessionStatus: string;
  readonly egressEvidenceIdentifier: string;
  readonly egressEvidenceId: string;
  readonly egressEvidenceVersion: string;
  readonly egressReviewerRole: string;
  readonly egressReviewedAt: Date;
  readonly providerConnectivityExercised: boolean;
  readonly deploymentApprovalIdentifier: string;
  readonly deploymentId: string;
  readonly environmentClass: string;
  readonly runtimeArtifactVersion: string;
  readonly configurationFingerprint: string;
  readonly observabilityPolicy: string;
  readonly deploymentApprovalRole: string;
  readonly deploymentApprovedAt: Date;
  readonly invalidatesOnDeploymentChange: boolean;
  readonly heartbeatPolicyIdentifier: string;
  readonly deadlinePolicyIdentifier: string;
  readonly runbookSetIdentifier: string;
  readonly runbookVersion: string;
  readonly runbookAcknowledgedAt: Date;
  readonly haltProcedureIdentifier: string;
  readonly haltAcknowledgedAt: Date;
  readonly containmentCatalogIdentifier: string;
  readonly containmentAcknowledgedAt: Date;
  readonly postcanaryReviewPolicyIdentifier: string;
  readonly requiredReviewRole: string;
  readonly reviewerAssignedAt: Date;
  readonly issuingOperatorMayReview: boolean;
  readonly automaticProgression: boolean;
  readonly evidenceRetentionPolicyIdentifier: string;
  readonly retentionAcknowledgedAt: Date;
  readonly activePointerBaselineIdentity: string;
  readonly zeroFindingBaselineIdentity: string;
  readonly issuedAt: Date;
  readonly expiresAt: Date;
  readonly state: OsvListingProviderContactAuthorizationState;
  readonly consumedAt: Date | null;
  readonly consumedBySynchronizationRequestId: string | null;
  readonly consumedBySynchronizationRunId: string | null;
  readonly terminalAt: Date | null;
  readonly terminalDisposition: OsvListingProviderContactAuthorizationState | null;
  readonly terminalReasonCode: string | null;
  readonly revokedAt: Date | null;
  readonly revokedByOperatorIdentityId: string | null;
  readonly createdAt: Date;
};

export function coerceProviderContactAuthorizationRow(
  raw: Record<string, unknown>,
): ProviderContactAuthorizationRow {
  rejectTenantOrFinding(raw);
  const stateValue = readString(raw, 'state', 'state');
  if (!isOsvListingProviderContactAuthorizationState(stateValue)) {
    throw new OsvListingProviderContactAuthorizationMappingError('unknown state.');
  }
  const terminalDispositionValue = readOptionalString(
    raw,
    'terminalDisposition',
    'terminal_disposition',
  );
  if (
    terminalDispositionValue !== null &&
    !isOsvListingProviderContactAuthorizationState(terminalDispositionValue)
  ) {
    throw new OsvListingProviderContactAuthorizationMappingError('unknown terminal disposition.');
  }
  const unusedTtlSeconds = readExactInteger(raw, 'unusedTtlSeconds', 'unused_ttl_seconds');
  if (unusedTtlSeconds !== UNUSED_TTL_SECONDS) {
    throw new OsvListingProviderContactAuthorizationMappingError('ttl mapping failed.');
  }
  return {
    id: readString(raw, 'id', 'id'),
    authorizationSchemaVersion: requireExact(
      readString(raw, 'authorizationSchemaVersion', 'authorization_schema_version'),
      AUTHORIZATION_SCHEMA_VERSION,
    ),
    sourceCanaryAuthorizationId: readString(
      raw,
      'sourceCanaryAuthorizationId',
      'source_canary_authorization_id',
    ),
    operatorIdentityId: readString(raw, 'operatorIdentityId', 'operator_identity_id'),
    synchronizationRequestId: readString(
      raw,
      'synchronizationRequestId',
      'synchronization_request_id',
    ),
    synchronizationRunId: readString(raw, 'synchronizationRunId', 'synchronization_run_id'),
    preflightEvidenceId: readString(raw, 'preflightEvidenceId', 'preflight_evidence_id'),
    phase: requireExact(readString(raw, 'phase', 'phase'), PHASE),
    providerIdentity: requireExact(
      readString(raw, 'providerIdentity', 'provider_identity'),
      PROVIDER,
    ),
    bucketIdentity: requireExact(readString(raw, 'bucketIdentity', 'bucket_identity'), BUCKET),
    listingApiPathPolicy: requireExact(
      readString(raw, 'listingApiPathPolicy', 'listing_api_path_policy'),
      LISTING_PATH,
    ),
    listingProtocol: requireExact(
      readString(raw, 'listingProtocol', 'listing_protocol'),
      LISTING_PROTOCOL,
    ),
    approvedPrefix: requireExact(readString(raw, 'approvedPrefix', 'approved_prefix'), PREFIX),
    family: requireExact(readString(raw, 'family', 'family'), FAMILY),
    canaryPolicyIdentifier: requireExact(
      readString(raw, 'canaryPolicyIdentifier', 'canary_policy_identifier'),
      POLICY,
    ),
    listingBudgetProfile: requireExact(
      readString(raw, 'listingBudgetProfile', 'listing_budget_profile'),
      BUDGET,
    ),
    workScope: requireExact(
      readString(raw, 'workScope', 'work_scope'),
      WORK_SCOPE,
    ) as OsvRuntimeWorkScope,
    leaseScope: requireExact(readString(raw, 'leaseScope', 'lease_scope'), LEASE_SCOPE),
    synchronizationReason: requireExact(
      readString(raw, 'synchronizationReason', 'synchronization_reason'),
      'operator_canary',
    ) as OsvRuntimeSynchronizationReason,
    runtimeArchitectureIdentifier: requireExact(
      readString(raw, 'runtimeArchitectureIdentifier', 'runtime_architecture_identifier'),
      RUNTIME_ARCHITECTURE,
    ),
    runtimeVersionSetFingerprint: readFingerprint(
      raw,
      'runtimeVersionSetFingerprint',
      'runtime_version_set_fingerprint',
    ),
    queryGrammarPolicy: requireExact(
      readString(raw, 'queryGrammarPolicy', 'query_grammar_policy'),
      QUERY_GRAMMAR,
    ),
    transportPolicy: requireExact(
      readString(raw, 'transportPolicy', 'transport_policy'),
      TRANSPORT,
    ),
    contentEncodingPolicy: requireExact(
      readString(raw, 'contentEncodingPolicy', 'content_encoding_policy'),
      CONTENT_ENCODING,
    ),
    redirectPolicy: requireExact(readString(raw, 'redirectPolicy', 'redirect_policy'), REDIRECT),
    unusedTtlSeconds,
    singleUsePolicy: requireExact(
      readString(raw, 'singleUsePolicy', 'single_use_policy'),
      SINGLE_USE,
    ),
    providerRetryAuthorization: requireExact(
      readString(raw, 'providerRetryAuthorization', 'provider_retry_authorization'),
      PROHIBITED,
    ),
    providerBodyAuthorization: requireExact(
      readString(raw, 'providerBodyAuthorization', 'provider_body_authorization'),
      PROHIBITED,
    ),
    parserAuthorization: requireExact(
      readString(raw, 'parserAuthorization', 'parser_authorization'),
      PROHIBITED,
    ),
    catalogActivationAuthorization: requireExact(
      readString(raw, 'catalogActivationAuthorization', 'catalog_activation_authorization'),
      PROHIBITED,
    ),
    matchingAuthorization: requireExact(
      readString(raw, 'matchingAuthorization', 'matching_authorization'),
      PROHIBITED,
    ),
    findingAuthorization: requireExact(
      readString(raw, 'findingAuthorization', 'finding_authorization'),
      PROHIBITED,
    ),
    legalApprovalIdentifier: requireExact(
      readString(raw, 'legalApprovalIdentifier', 'legal_approval_identifier'),
      LEGAL_APPROVAL,
    ),
    legalDecisionId: readString(raw, 'legalDecisionId', 'legal_decision_id'),
    sourceCanaryLegalDecisionId: readString(
      raw,
      'sourceCanaryLegalDecisionId',
      'source_canary_legal_decision_id',
    ),
    legalDecisionSourceRegistryVersion: requireExact(
      readString(
        raw,
        'legalDecisionSourceRegistryVersion',
        'legal_decision_source_registry_version',
      ),
      LEGAL_REGISTRY,
    ),
    legalListingMetadataPermission: requireExact(
      readString(raw, 'legalListingMetadataPermission', 'legal_listing_metadata_permission'),
      'approved',
    ),
    legalBodyRetrievalPermission: requireExact(
      readString(raw, 'legalBodyRetrievalPermission', 'legal_body_retrieval_permission'),
      PROHIBITED,
    ),
    legalParsingPermission: requireExact(
      readString(raw, 'legalParsingPermission', 'legal_parsing_permission'),
      PROHIBITED,
    ),
    legalMatchingPermission: requireExact(
      readString(raw, 'legalMatchingPermission', 'legal_matching_permission'),
      PROHIBITED,
    ),
    legalIssuedAt: readDate(raw, 'legalIssuedAt', 'legal_issued_at'),
    legalRevalidationBoundaryAt: readDate(
      raw,
      'legalRevalidationBoundaryAt',
      'legal_revalidation_boundary_at',
    ),
    legalEvidenceSetId: readString(raw, 'legalEvidenceSetId', 'legal_evidence_set_id'),
    legalApprovalRole: requireExact(
      readString(raw, 'legalApprovalRole', 'legal_approval_role'),
      LEGAL_ROLE,
    ),
    legalSupersessionStatus: requireExact(
      readString(raw, 'legalSupersessionStatus', 'legal_supersession_status'),
      'current',
    ),
    egressEvidenceIdentifier: requireExact(
      readString(raw, 'egressEvidenceIdentifier', 'egress_evidence_identifier'),
      EGRESS_IDENTIFIER,
    ),
    egressEvidenceId: readString(raw, 'egressEvidenceId', 'egress_evidence_id'),
    egressEvidenceVersion: requireExact(
      readString(raw, 'egressEvidenceVersion', 'egress_evidence_version'),
      EGRESS_VERSION,
    ),
    egressReviewerRole: requireExact(
      readString(raw, 'egressReviewerRole', 'egress_reviewer_role'),
      EGRESS_ROLE,
    ),
    egressReviewedAt: readDate(raw, 'egressReviewedAt', 'egress_reviewed_at'),
    providerConnectivityExercised: readBoolean(
      raw,
      'providerConnectivityExercised',
      'provider_connectivity_exercised',
    ),
    deploymentApprovalIdentifier: requireExact(
      readString(raw, 'deploymentApprovalIdentifier', 'deployment_approval_identifier'),
      DEPLOYMENT_IDENTIFIER,
    ),
    deploymentId: readString(raw, 'deploymentId', 'deployment_id'),
    environmentClass: requireExact(
      readString(raw, 'environmentClass', 'environment_class'),
      ENVIRONMENT,
    ),
    runtimeArtifactVersion: readString(raw, 'runtimeArtifactVersion', 'runtime_artifact_version'),
    configurationFingerprint: readFingerprint(
      raw,
      'configurationFingerprint',
      'configuration_fingerprint',
    ),
    observabilityPolicy: requireExact(
      readString(raw, 'observabilityPolicy', 'observability_policy'),
      OBSERVABILITY,
    ),
    deploymentApprovalRole: requireExact(
      readString(raw, 'deploymentApprovalRole', 'deployment_approval_role'),
      DEPLOYMENT_ROLE,
    ),
    deploymentApprovedAt: readDate(raw, 'deploymentApprovedAt', 'deployment_approved_at'),
    invalidatesOnDeploymentChange: readBoolean(
      raw,
      'invalidatesOnDeploymentChange',
      'invalidates_on_deployment_change',
    ),
    heartbeatPolicyIdentifier: requireExact(
      readString(raw, 'heartbeatPolicyIdentifier', 'heartbeat_policy_identifier'),
      HEARTBEAT,
    ),
    deadlinePolicyIdentifier: requireExact(
      readString(raw, 'deadlinePolicyIdentifier', 'deadline_policy_identifier'),
      DEADLINE,
    ),
    runbookSetIdentifier: requireExact(
      readString(raw, 'runbookSetIdentifier', 'runbook_set_identifier'),
      RUNBOOK_SET,
    ),
    runbookVersion: requireExact(
      readString(raw, 'runbookVersion', 'runbook_version'),
      RUNBOOK_VERSION,
    ),
    runbookAcknowledgedAt: readDate(raw, 'runbookAcknowledgedAt', 'runbook_acknowledged_at'),
    haltProcedureIdentifier: requireExact(
      readString(raw, 'haltProcedureIdentifier', 'halt_procedure_identifier'),
      HALT_PROCEDURE,
    ),
    haltAcknowledgedAt: readDate(raw, 'haltAcknowledgedAt', 'halt_acknowledged_at'),
    containmentCatalogIdentifier: requireExact(
      readString(raw, 'containmentCatalogIdentifier', 'containment_catalog_identifier'),
      CONTAINMENT,
    ),
    containmentAcknowledgedAt: readDate(
      raw,
      'containmentAcknowledgedAt',
      'containment_acknowledged_at',
    ),
    postcanaryReviewPolicyIdentifier: requireExact(
      readString(raw, 'postcanaryReviewPolicyIdentifier', 'postcanary_review_policy_identifier'),
      REVIEW_POLICY,
    ),
    requiredReviewRole: requireExact(
      readString(raw, 'requiredReviewRole', 'required_review_role'),
      REVIEW_ROLE,
    ),
    reviewerAssignedAt: readDate(raw, 'reviewerAssignedAt', 'reviewer_assigned_at'),
    issuingOperatorMayReview: readBoolean(
      raw,
      'issuingOperatorMayReview',
      'issuing_operator_may_review',
    ),
    automaticProgression: readBoolean(raw, 'automaticProgression', 'automatic_progression'),
    evidenceRetentionPolicyIdentifier: requireExact(
      readString(raw, 'evidenceRetentionPolicyIdentifier', 'evidence_retention_policy_identifier'),
      RETENTION,
    ),
    retentionAcknowledgedAt: readDate(raw, 'retentionAcknowledgedAt', 'retention_acknowledged_at'),
    activePointerBaselineIdentity: readString(
      raw,
      'activePointerBaselineIdentity',
      'active_pointer_baseline_identity',
    ),
    zeroFindingBaselineIdentity: readString(
      raw,
      'zeroFindingBaselineIdentity',
      'zero_finding_baseline_identity',
    ),
    issuedAt: readDate(raw, 'issuedAt', 'issued_at'),
    expiresAt: readDate(raw, 'expiresAt', 'expires_at'),
    state: stateValue,
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
    terminalDisposition: terminalDispositionValue === null ? null : terminalDispositionValue,
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

export function mapProviderContactAuthorization(
  row: ProviderContactAuthorizationRow,
): OsvListingProviderContactPersistedAuthorization {
  requireFalse(row.providerConnectivityExercised);
  requireFalse(row.issuingOperatorMayReview);
  requireFalse(row.automaticProgression);
  requireTrue(row.invalidatesOnDeploymentChange);
  if (row.issuedAt.getTime() >= row.expiresAt.getTime()) {
    throw new OsvListingProviderContactAuthorizationMappingError('invalid issuance expiry order.');
  }
  if (row.state === 'issued') {
    if (
      row.consumedAt !== null ||
      row.consumedBySynchronizationRequestId !== null ||
      row.consumedBySynchronizationRunId !== null ||
      row.revokedAt !== null ||
      row.terminalAt !== null
    ) {
      throw new OsvListingProviderContactAuthorizationMappingError(
        'issued row has terminal metadata.',
      );
    }
  }
  if (row.state === 'consumed_for_listing_execution') {
    if (
      row.consumedAt === null ||
      row.consumedBySynchronizationRequestId !== row.synchronizationRequestId ||
      row.consumedBySynchronizationRunId !== row.synchronizationRunId
    ) {
      throw new OsvListingProviderContactAuthorizationMappingError(
        'consumed row missing consume binding.',
      );
    }
  }
  if (
    row.state === 'revoked' &&
    (row.revokedAt === null || row.revokedByOperatorIdentityId === null)
  ) {
    throw new OsvListingProviderContactAuthorizationMappingError(
      'revoked row missing revocation metadata.',
    );
  }
  return createOsvListingProviderContactPersistedAuthorization({
    providerContactAuthorizationId: row.id,
    sourceCanaryAuthorizationId: row.sourceCanaryAuthorizationId,
    operatorAttestationId: row.operatorIdentityId,
    synchronizationRequestId: row.synchronizationRequestId,
    synchronizationRunId: row.synchronizationRunId,
    preflightEvidenceId: row.preflightEvidenceId,
    runtimeVersionSetFingerprint: row.runtimeVersionSetFingerprint,
    legalDecisionId: row.legalDecisionId,
    sourceCanaryLegalDecisionId: row.sourceCanaryLegalDecisionId,
    legalEvidenceSetId: row.legalEvidenceSetId,
    legalIssuedAt: toIsoUtc(row.legalIssuedAt),
    legalRevalidationBoundaryAt: toIsoUtc(row.legalRevalidationBoundaryAt),
    egressEvidenceId: row.egressEvidenceId,
    egressEvidenceVersion: row.egressEvidenceVersion,
    deploymentId: row.deploymentId,
    runtimeArtifactVersion: row.runtimeArtifactVersion,
    configurationFingerprint: row.configurationFingerprint,
    activePointerBaselineIdentity: row.activePointerBaselineIdentity,
    zeroFindingBaselineIdentity: row.zeroFindingBaselineIdentity,
    issuedAt: toIsoUtc(row.issuedAt),
    expiresAt: toIsoUtc(row.expiresAt),
    state: row.state,
    consumedAt: row.consumedAt === null ? null : toIsoUtc(row.consumedAt),
    revokedAt: row.revokedAt === null ? null : toIsoUtc(row.revokedAt),
    terminalAt: row.terminalAt === null ? null : toIsoUtc(row.terminalAt),
    terminalDisposition: row.terminalDisposition,
  });
}

export function firstProviderContactRow<T>(
  rows: readonly unknown[],
  coerce: (raw: Record<string, unknown>) => T,
): T | undefined {
  if (!Array.isArray(rows)) {
    throw new OsvListingProviderContactAuthorizationMappingError('array mapping failed.');
  }
  const raw = rows[0];
  if (raw === undefined || raw === null) {
    return undefined;
  }
  if (typeof raw !== 'object') {
    throw new OsvListingProviderContactAuthorizationMappingError('row mapping failed.');
  }
  return coerce(raw as Record<string, unknown>);
}
