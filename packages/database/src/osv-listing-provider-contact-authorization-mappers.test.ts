import { describe, expect, it } from 'vitest';

import {
  coerceProviderContactAuthorizationRow,
  mapProviderContactAuthorization,
  OsvListingProviderContactAuthorizationMappingError,
  toIsoUtc,
} from './osv-listing-provider-contact-authorization-mappers.js';

const AUTHORIZATION_ID = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const SOURCE_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const OPERATOR_ID = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const REQUEST_ID = 'dddddddd-dddd-4ddd-8ddd-dddddddddddd';
const RUN_ID = 'eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee';
const PREFLIGHT_ID = 'ffffffff-ffff-4fff-8fff-ffffffffffff';
const ISSUED = new Date('2026-09-08T12:00:00.000Z');
const EXPIRES = new Date('2026-09-08T13:00:00.000Z');
const ACK = new Date('2026-09-08T11:00:00.000Z');
const FINGERPRINT = 'a'.repeat(64);

function issuedRaw(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: AUTHORIZATION_ID,
    authorizationSchemaVersion: 'osv_listing_only_provider_contact_authorization_v1',
    sourceCanaryAuthorizationId: SOURCE_ID,
    operatorIdentityId: OPERATOR_ID,
    synchronizationRequestId: REQUEST_ID,
    synchronizationRunId: RUN_ID,
    preflightEvidenceId: PREFLIGHT_ID,
    phase: 'listing_only',
    providerIdentity: 'rustsec_advisory_database',
    bucketIdentity: 'osv-vulnerabilities',
    listingApiPathPolicy: '/storage/v1/b/osv-vulnerabilities/o',
    listingProtocol: 'osv_gcs_json_objects_list_v1',
    approvedPrefix: 'crates.io/',
    family: 'RUSTSEC',
    canaryPolicyIdentifier: 'osv_disabled_first_provider_canary_policy_v1',
    listingBudgetProfile: 'osv_canary_listing_only_budget_v1',
    workScope: 'osv_runtime_canary_scope_crates_io_rustsec_v1',
    leaseScope: 'osv_runtime_lease_scope_osv_gcs_public_export_v1',
    synchronizationReason: 'operator_canary',
    runtimeArchitectureIdentifier: 'osv_runtime_enablement_architecture_v1',
    runtimeVersionSetFingerprint: FINGERPRINT,
    queryGrammarPolicy: 'committed',
    transportPolicy: 'osv_transport_policy_v1',
    contentEncodingPolicy: 'identity',
    redirectPolicy: 'error',
    unusedTtlSeconds: 3600,
    singleUsePolicy: 'single_use',
    providerRetryAuthorization: 'prohibited',
    providerBodyAuthorization: 'prohibited',
    parserAuthorization: 'prohibited',
    catalogActivationAuthorization: 'prohibited',
    matchingAuthorization: 'prohibited',
    findingAuthorization: 'prohibited',
    legalApprovalIdentifier: 'osv_listing_provider_contact_legal_approval_v1',
    legalDecisionId: '11111111-1111-4111-8111-111111111111',
    sourceCanaryLegalDecisionId: '22222222-2222-4222-8222-222222222222',
    legalDecisionSourceRegistryVersion: 'osv_source_license_registry_v1',
    legalListingMetadataPermission: 'approved',
    legalBodyRetrievalPermission: 'prohibited',
    legalParsingPermission: 'prohibited',
    legalMatchingPermission: 'prohibited',
    legalIssuedAt: ACK,
    legalRevalidationBoundaryAt: new Date('2099-09-09T11:00:00.000Z'),
    legalEvidenceSetId: '33333333-3333-4333-8333-333333333333',
    legalApprovalRole: 'instance_legal_and_provenance_reviewer_countersigned_by_instance_operator',
    legalSupersessionStatus: 'current',
    egressEvidenceIdentifier: 'osv_listing_provider_contact_egress_evidence_v1',
    egressEvidenceId: '44444444-4444-4444-8444-444444444444',
    egressEvidenceVersion: 'osv_listing_provider_contact_egress_evidence_v1',
    egressReviewerRole: 'instance_operator_deployment_reviewer',
    egressReviewedAt: ACK,
    providerConnectivityExercised: false,
    deploymentApprovalIdentifier: 'osv_listing_provider_contact_deployment_approval_v1',
    deploymentId: '55555555-5555-4555-8555-555555555555',
    environmentClass: 'dedicated_instance_operator_process',
    runtimeArtifactVersion: 'patchpilot.canary.artifact.1',
    configurationFingerprint: FINGERPRINT,
    observabilityPolicy: 'osv_listing_provider_contact_observability_policy_v1',
    deploymentApprovalRole: 'instance_operator_deployment_reviewer',
    deploymentApprovedAt: ACK,
    invalidatesOnDeploymentChange: true,
    heartbeatPolicyIdentifier: 'osv_canary_runtime_controls_v1',
    deadlinePolicyIdentifier: 'osv_canary_runtime_controls_v1',
    runbookSetIdentifier: 'osv_listing_provider_contact_runbook_set_v1',
    runbookVersion: 'osv_listing_provider_contact_runbook_v1',
    runbookAcknowledgedAt: ACK,
    haltProcedureIdentifier: 'osv_listing_provider_contact_halt_procedure_v1',
    haltAcknowledgedAt: ACK,
    containmentCatalogIdentifier: 'osv_listing_provider_contact_emergency_containment_v1',
    containmentAcknowledgedAt: ACK,
    postcanaryReviewPolicyIdentifier: 'osv_listing_provider_contact_postcanary_review_v1',
    requiredReviewRole: 'instance_canary_evidence_reviewer',
    reviewerAssignedAt: ACK,
    issuingOperatorMayReview: false,
    automaticProgression: false,
    evidenceRetentionPolicyIdentifier: 'osv_listing_provider_contact_retention_disposition_v1',
    retentionAcknowledgedAt: ACK,
    activePointerBaselineIdentity: '66666666-6666-4666-8666-666666666666',
    zeroFindingBaselineIdentity: '77777777-7777-4777-8777-777777777777',
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

describe('OSV listing provider-contact authorization mapping', () => {
  it('emits UTC ISO timestamps without leaking SQL', () => {
    expect(toIsoUtc(new Date('2026-09-08T12:00:00.000Z'))).toBe('2026-09-08T12:00:00Z');
    expect(toIsoUtc(new Date('2026-09-08T12:00:00.000Z'))).not.toContain('SELECT');
  });

  it('maps a valid issued listing-only row', () => {
    const mapped = mapProviderContactAuthorization(
      coerceProviderContactAuthorizationRow(issuedRaw()),
    );
    expect(mapped.approvedPrefix).toBe('crates.io/');
    expect(mapped.state).toBe('issued');
    expect(mapped.providerBodyProhibited).toBe(true);
    expect(mapped.findingProhibited).toBe(true);
  });

  it('fails closed on unknown state, wrong prefix, tenant fields, and issued+consumed timestamps', () => {
    expect(() => coerceProviderContactAuthorizationRow(issuedRaw({ state: 'granted' }))).toThrow(
      OsvListingProviderContactAuthorizationMappingError,
    );
    expect(() =>
      coerceProviderContactAuthorizationRow(issuedRaw({ approvedPrefix: 'npm/' })),
    ).toThrow(OsvListingProviderContactAuthorizationMappingError);
    expect(() =>
      coerceProviderContactAuthorizationRow(issuedRaw({ organizationId: 'org' })),
    ).toThrow(OsvListingProviderContactAuthorizationMappingError);
    expect(() =>
      mapProviderContactAuthorization(
        coerceProviderContactAuthorizationRow(
          issuedRaw({ consumedAt: new Date('2026-09-08T12:30:00.000Z') }),
        ),
      ),
    ).toThrow(OsvListingProviderContactAuthorizationMappingError);
    expect(() =>
      coerceProviderContactAuthorizationRow(issuedRaw({ phase: 'bounded_body' })),
    ).toThrow(OsvListingProviderContactAuthorizationMappingError);
    expect(() =>
      coerceProviderContactAuthorizationRow(issuedRaw({ providerBodyAuthorization: 'permitted' })),
    ).toThrow(OsvListingProviderContactAuthorizationMappingError);
    const hostile = issuedRaw();
    Object.defineProperty(hostile, 'state', {
      get() {
        throw new Error('SELECT password FROM secret');
      },
    });
    expect(() => coerceProviderContactAuthorizationRow(hostile)).toThrow(
      OsvListingProviderContactAuthorizationMappingError,
    );
  });

  it('requires consume bindings for consumed_for_listing_execution', () => {
    expect(() =>
      mapProviderContactAuthorization(
        coerceProviderContactAuthorizationRow(
          issuedRaw({
            state: 'consumed_for_listing_execution',
            consumedAt: new Date('2026-09-08T12:30:00.000Z'),
            consumedBySynchronizationRequestId: REQUEST_ID,
            consumedBySynchronizationRunId: RUN_ID,
          }),
        ),
      ),
    ).not.toThrow();
    expect(() =>
      mapProviderContactAuthorization(
        coerceProviderContactAuthorizationRow(
          issuedRaw({
            state: 'consumed_for_listing_execution',
            consumedAt: new Date('2026-09-08T12:30:00.000Z'),
          }),
        ),
      ),
    ).toThrow(OsvListingProviderContactAuthorizationMappingError);
  });
});
