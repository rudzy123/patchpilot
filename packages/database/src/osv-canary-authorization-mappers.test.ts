import { describe, expect, it } from 'vitest';

import {
  coerceAuthorizationRow,
  coerceOperatorRow,
  mapAuthorization,
  mapOperator,
  OsvCanaryAuthorizationMappingError,
  toIsoUtc,
} from './osv-canary-authorization-mappers.js';

const OPERATOR_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const AUTHORIZATION_ID = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const ISSUED = new Date('2026-09-08T12:00:00.000Z');
const EXPIRES = new Date('2026-09-08T13:00:00.000Z');
const ACK = new Date('2026-09-08T11:00:00.000Z');
const FINGERPRINT = 'a'.repeat(64);

function operatorRaw(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: OPERATOR_ID,
    identitySchemaVersion: 'osv_canary_instance_operator_identity_v1',
    identityType: 'instance_operator',
    authenticationSource: 'local_host_control_of_one_shot_administrative_command',
    provenanceIdentifier: 'configured_instance_operator_attestation_v1',
    displayLabel: 'canary-operator-1',
    establishedAt: ISSUED,
    status: 'active',
    revokedAt: null,
    createdAt: ISSUED,
    ...overrides,
  };
}

function listingRaw(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: AUTHORIZATION_ID,
    operatorIdentityId: OPERATOR_ID,
    authorizationSchemaVersion: 'osv_canary_execution_authorization_record_v1',
    canaryArchitectureIdentifier: 'osv_first_real_provider_canary_authorization_v1',
    runtimeArchitectureIdentifier: 'osv_runtime_enablement_architecture_v1',
    listingProtocolIdentifier: 'osv_gcs_json_objects_list_v1',
    actorKind: 'instance_operator',
    phase: 'listing_only',
    synchronizationReason: 'operator_canary',
    authorizationPurpose: 'initial_listing_compatibility',
    providerPrefix: 'crates.io/',
    sourceIdentifier: 'rustsec_advisory_database',
    family: 'RUSTSEC',
    canaryPolicyIdentifier: 'osv_disabled_first_provider_canary_policy_v1',
    workScope: 'osv_runtime_canary_scope_crates_io_rustsec_v1',
    leaseScope: 'osv_runtime_lease_scope_osv_gcs_public_export_v1',
    runtimeVersionSetFingerprint: FINGERPRINT,
    budgetProfileIdentifier: 'osv_canary_listing_only_budget_v1',
    unusedTtlSeconds: 3600,
    singleUsePolicy: 'single_use',
    catalogActivationAuthorization: 'prohibited',
    matchingAuthorization: 'prohibited',
    findingAuthorization: 'prohibited',
    postcanaryReviewRequirement: 'required',
    legalDecisionReferenceIdentifier: 'osv_canary_legal_decision_reference_v1',
    legalDecisionId: 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
    legalDecisionSourceRegistryVersion: 'osv_source_license_registry_v1',
    legalDecisionPhase: 'listing_only',
    legalDecisionPermittedOperation: 'list_object_metadata',
    legalDecisionState: 'recorded_reference_not_execution_authority',
    legalDecisionIssuance: 'blocking_preexecution_dependency_not_issued_in_batch_2a',
    legalDecisionIssuedAt: ACK,
    legalDecisionRevalidationBoundaryAt: new Date('2099-01-01T00:00:00.000Z'),
    legalDecisionResponsibleRole:
      'instance_legal_and_provenance_reviewer_countersigned_by_instance_operator',
    legalDecisionEvidenceSetId: 'dddddddd-dddd-4ddd-8ddd-dddddddddddd',
    bodyLegalDecisionId: null,
    bodyLegalDecisionPhase: null,
    bodyLegalDecisionPermittedOperation: null,
    bodyLegalDecisionIssuedAt: null,
    bodyLegalDecisionRevalidationBoundaryAt: null,
    bodyLegalDecisionEvidenceSetId: null,
    bodyRetrieveDisposition: null,
    bodyTransientInspectionDisposition: null,
    bodyPrivateRetentionDisposition: null,
    bodyParseDisposition: null,
    bodyExternalExposureDisposition: null,
    bodyMatchingDisposition: null,
    listingReviewEvidenceIdentifier: null,
    listingReviewId: null,
    listingAuthorizationId: null,
    listingRequestId: null,
    listingRunId: null,
    listingCanonicalInventoryEvidenceId: null,
    listingReviewVerdict: null,
    listingReviewedAt: null,
    listingReviewerRole: null,
    bodySelectionAlgorithmIdentifier: null,
    runbookSetIdentifier: 'osv_canary_runbook_set_v1',
    runbookVersion: 'osv_canary_runbook_outlines_v1',
    runbookAcknowledgedAt: ACK,
    runbookEmergencyHaltProcedure: 'stop_next_protected_stage_production_remains_halted',
    haltAcknowledgementIdentifier: 'osv_canary_halt_control_acknowledgement_v1',
    haltAcknowledgedAt: ACK,
    activationProhibitionIdentifier: 'osv_canary_activation_prohibition_v1',
    retryProhibitionIdentifier: 'osv_canary_automatic_retry_prohibition_v1',
    issuedAt: ISSUED,
    expiresAt: EXPIRES,
    state: 'issued',
    consumedAt: null,
    consumedBySynchronizationRequestId: null,
    consumedBySynchronizationRunId: null,
    terminalAt: null,
    terminalDisposition: null,
    terminalReasonCode: null,
    revokedAt: null,
    revokedByOperatorIdentityId: null,
    createdAt: ISSUED,
    ...overrides,
  };
}

describe('OSV canary authorization timestamp mapping', () => {
  it('emits UTC ISO timestamps without leaking SQL', () => {
    expect(toIsoUtc(new Date('2026-09-08T12:00:00.000Z'))).toBe('2026-09-08T12:00:00Z');
    expect(toIsoUtc(new Date('2026-09-08T12:00:00.123Z'))).toBe('2026-09-08T12:00:00.123Z');
    expect(toIsoUtc(new Date('2026-09-08T12:00:00.000Z'))).not.toContain('SELECT');
  });
});

describe('OSV canary authorization persisted-row mapping', () => {
  it('maps a valid listing-only row', () => {
    const operator = mapOperator(coerceOperatorRow(operatorRaw()));
    const authorization = mapAuthorization(coerceAuthorizationRow(listingRaw()), operator);
    expect(authorization.snapshot.record.providerPrefix).toBe('crates.io/');
    expect(authorization.snapshot.state).toBe('issued');
  });

  it('fails closed on unknown operator status', () => {
    expect(() => coerceOperatorRow(operatorRaw({ status: 'suspended' }))).toThrow(
      OsvCanaryAuthorizationMappingError,
    );
  });

  it('fails closed on revoked operator without revokedAt', () => {
    expect(() => mapOperator(coerceOperatorRow(operatorRaw({ status: 'revoked' })))).toThrow(
      OsvCanaryAuthorizationMappingError,
    );
  });

  it('fails closed on a foreign provider prefix', () => {
    const operator = mapOperator(coerceOperatorRow(operatorRaw()));
    expect(() =>
      mapAuthorization(coerceAuthorizationRow(listingRaw({ providerPrefix: 'npm/' })), operator),
    ).toThrow(OsvCanaryAuthorizationMappingError);
  });

  it('fails closed on listing-only rows that carry body fields', () => {
    const operator = mapOperator(coerceOperatorRow(operatorRaw()));
    expect(() =>
      mapAuthorization(
        coerceAuthorizationRow(
          listingRaw({
            listingReviewEvidenceIdentifier: 'osv_canary_listing_review_evidence_v1',
            listingAuthorizationId: AUTHORIZATION_ID,
          }),
        ),
        operator,
      ),
    ).toThrow(OsvCanaryAuthorizationMappingError);
    expect(() =>
      mapAuthorization(
        coerceAuthorizationRow(
          listingRaw({
            bodyRetrieveDisposition: 'required_current_before_bounded_body',
          }),
        ),
        operator,
      ),
    ).toThrow(OsvCanaryAuthorizationMappingError);
  });

  it('fails closed on unused TTL other than 3600', () => {
    const operator = mapOperator(coerceOperatorRow(operatorRaw()));
    expect(() =>
      mapAuthorization(coerceAuthorizationRow(listingRaw({ unusedTtlSeconds: 1800 })), operator),
    ).toThrow(OsvCanaryAuthorizationMappingError);
  });

  it('fails closed on unknown authorization state', () => {
    expect(() => coerceAuthorizationRow(listingRaw({ state: 'retried' }))).toThrow(
      OsvCanaryAuthorizationMappingError,
    );
  });

  it('fails closed on NaN unused TTL', () => {
    expect(() => coerceAuthorizationRow(listingRaw({ unusedTtlSeconds: Number.NaN }))).toThrow(
      OsvCanaryAuthorizationMappingError,
    );
  });
});
