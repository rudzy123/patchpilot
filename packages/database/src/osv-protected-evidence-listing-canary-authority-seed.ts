/**
 * Session 13 Batch 3D nonpublic protected-evidence listing-canary authority
 * seed. Uses closed canary purpose approved_listing_repetition. Not a public
 * package export. Does not contact a provider. Batch 3C authority is not reused.
 */

import { randomUUID } from 'node:crypto';

import { PrismaClient } from '@prisma/client';
import {
  createClosedOsvRuntimeSyncJobInput,
  createOsvCanaryActivationProhibitionAcknowledgement,
  createOsvCanaryAuthorizationConsumePersistenceCommand,
  createOsvCanaryAuthorizationEnsureCommand,
  createOsvCanaryAutomaticRetryProhibitionAcknowledgement,
  createOsvCanaryHaltControlAcknowledgement,
  createOsvCanaryInstanceOperatorIdentity,
  createOsvCanaryLegalDecisionReference,
  createOsvCanaryOperatorEnsureCommand,
  createOsvCanaryRunbookAcknowledgement,
  createOsvEvidenceRetainingListingAuthorizationInput,
  createOsvEvidenceRetainingListingConfirmation,
  createOsvListingProviderContactAuthorizationIssueCommand,
  createOsvListingProviderContactContainmentAcknowledgement,
  createOsvListingProviderContactDeploymentApproval,
  createOsvListingProviderContactEgressEvidence,
  createOsvListingProviderContactHaltProcedureAcknowledgement,
  createOsvListingProviderContactLegalApproval,
  createOsvListingProviderContactRetentionDisposition,
  createOsvListingProviderContactReviewerAssignment,
  createOsvListingProviderContactRunbookAcknowledgement,
  createOsvRuntimeJobIdempotencyIdentity,
  createOsvRuntimeSynchronizationRequestEnsureCommand,
  createOsvRuntimeSynchronizationRunEnsureCommand,
  createOsvRuntimeSyncJobPayload,
  OSV_EVIDENCE_RETAINING_LISTING_ASSOCIATED_DATA_POLICY_ID,
  OSV_EVIDENCE_RETAINING_LISTING_AUTHORIZATION_EGRESS_POLICY_ID,
  OSV_EVIDENCE_RETAINING_LISTING_AUTHORIZATION_EXPECTED_BUDGET,
  OSV_EVIDENCE_RETAINING_LISTING_AUTHORIZATION_EXPECTED_POLICY,
  OSV_EVIDENCE_RETAINING_LISTING_AUTHORIZATION_EXPECTED_PREFIX,
  OSV_EVIDENCE_RETAINING_LISTING_AUTHORIZATION_EXPECTED_PROVIDER,
  OSV_EVIDENCE_RETAINING_LISTING_AUTHORIZATION_KIND,
  OSV_EVIDENCE_RETAINING_LISTING_AUTHORIZATION_LEASE_SCOPE,
  OSV_EVIDENCE_RETAINING_LISTING_AUTHORIZATION_PHASE,
  OSV_EVIDENCE_RETAINING_LISTING_AUTHORIZATION_PURPOSE,
  OSV_EVIDENCE_RETAINING_LISTING_AUTHORIZATION_SCHEMA_VERSION,
  OSV_EVIDENCE_RETAINING_LISTING_CANARY_PURPOSE,
  OSV_EVIDENCE_RETAINING_LISTING_ENCRYPTION_POLICY_ID,
  OSV_EVIDENCE_RETAINING_LISTING_ENVELOPE_SCHEMA_VERSION,
  OSV_EVIDENCE_RETAINING_LISTING_EVIDENCE_POLICY_ID,
  OSV_EVIDENCE_RETAINING_LISTING_EVIDENCE_PURPOSE_ID,
  OSV_EVIDENCE_RETAINING_LISTING_EVIDENCE_SCHEMA_VERSION,
  OSV_EVIDENCE_RETAINING_LISTING_MAX_EVIDENCE_METADATA_BYTES,
  OSV_EVIDENCE_RETAINING_LISTING_MAX_OBSERVATIONS,
  OSV_EVIDENCE_RETAINING_LISTING_MAX_PROTECTED_KEY_BYTES,
  OSV_EVIDENCE_RETAINING_LISTING_PAGE_ORDINAL,
  OSV_EVIDENCE_RETAINING_LISTING_PERSISTENCE_ADAPTER_POLICY_ID,
  OSV_EVIDENCE_RETAINING_LISTING_RETENTION_POLICY_ID,
  OSV_GCS_JSON_OBJECTS_LIST_HOST,
  OSV_GCS_JSON_OBJECTS_LIST_PATH,
  OSV_GCS_JSON_OBJECTS_LIST_REDIRECT_POLICY,
  OSV_GCS_JSON_OBJECTS_LIST_SCHEME,
  osvCanaryRuntimeVersionSetFingerprint,
  type OsvCanaryAuthorizationResult,
  type OsvCanaryInstanceOperatorIdentity,
  type OsvCanaryPhase,
  type OsvEvidenceRetainingListingAuthorizationInput,
} from '@patchpilot/vulnerability-intelligence';

import { createOsvCanaryAuthorizationPersistence } from './osv-canary-authorization-persistence.js';
import { createOsvListingProviderContactAuthorizationPersistence } from './osv-listing-provider-contact-authorization-persistence.js';
import { createOsvRuntimeCoordinationPersistence } from './osv-runtime-coordination-persistence.js';

const ACK = '2026-09-08T11:00:00Z';
const LEGAL_ISSUED = '2026-09-08T10:00:00Z';
const LEGAL_REVALIDATE = '2099-09-09T10:00:00Z';
const FINGERPRINT = osvCanaryRuntimeVersionSetFingerprint();
const ARTIFACT = 'patchpilot.canary.artifact.1';
const CANARY_SCOPE = 'osv_runtime_canary_scope_crates_io_rustsec_v1';
const APPLICATION_TESTED = 'application_control_implemented_and_tested';
const DEPLOYMENT_CONFIGURED = 'deployment_control_configured';
const CONFIRMATION_PROOF = 'protected-evidence-listing-one-shot-confirmation-proof';

function expectOk<T>(
  result: OsvCanaryAuthorizationResult<T> | { ok: true; value: T } | { ok: false; code: string },
  label: string,
): T {
  if (!result.ok) {
    throw new Error(`${label}: ${'code' in result ? result.code : 'failed'}`);
  }
  return result.value;
}

function uuid(): string {
  return randomUUID();
}

export type OsvProtectedEvidenceListingCanaryAuthoritySeed = {
  readonly operatorAttestationId: string;
  readonly sourceId: string;
  readonly requestId: string;
  readonly runId: string;
  readonly preflightId: string;
  readonly providerContactAuthorizationId: string;
  readonly identity: OsvCanaryInstanceOperatorIdentity;
};

export function createListingCanaryRehearsalEgressPort() {
  return {
    inspect(input: { readonly phase: OsvCanaryPhase }) {
      return Promise.resolve({
        ready: true as const,
        dnsLookupCount: 0 as const,
        providerCallCount: 0 as const,
        tlsConnectionCount: 0 as const,
        host: OSV_GCS_JSON_OBJECTS_LIST_HOST,
        scheme: OSV_GCS_JSON_OBJECTS_LIST_SCHEME,
        port: 443 as const,
        listingPath: OSV_GCS_JSON_OBJECTS_LIST_PATH,
        bucket: 'osv-vulnerabilities',
        redirectPolicy: OSV_GCS_JSON_OBJECTS_LIST_REDIRECT_POLICY,
        dnsPinning: 'application_control_verified' as const,
        prohibitedAddresses: 'application_control_verified' as const,
        tlsVerification: 'application_control_verified' as const,
        postConnectPeerVerification: 'application_control_verified' as const,
        cloudMetadataDenial: 'deployment_control_declared_but_not_externally_proven' as const,
        callerSelectedProxy: false as const,
        bodyEndpoint:
          input.phase === 'listing_only'
            ? ('prohibited' as const)
            : ('generation_bound_get_media' as const),
        queryGrammar: 'committed' as const,
      });
    },
  };
}

export function createProtectedEvidenceListingCryptographicReadinessPort() {
  return {
    async inspect() {
      return {
        cryptographicPolicyId: OSV_EVIDENCE_RETAINING_LISTING_ENCRYPTION_POLICY_ID,
        envelopeSchemaVersion: OSV_EVIDENCE_RETAINING_LISTING_ENVELOPE_SCHEMA_VERSION,
        algorithmId: 'aes-256-gcm',
        associatedDataPolicyId: OSV_EVIDENCE_RETAINING_LISTING_ASSOCIATED_DATA_POLICY_ID,
        currentKeyState: 'current',
        currentKeyStatePermitsEncryption: true,
        historicalCapabilityAvailability: 'not_required',
        nonceCapabilityAvailable: true,
        algorithmAvailable: true,
        associatedDataPolicyExact: true,
        plaintextFallbackConfigured: false,
        encryptionExecutionAvailable: true,
        decryptionExecutionAvailable: true,
        persistenceAvailable: false,
        providerContactAuthorized: false,
        encryptionPermitted: true,
        decryptionPermitted: true,
        rotationClassification: 'current',
        multiInstanceClassification: 'independent_csprng_no_distributed_lock',
        physicalMemoryErasure: 'javascript_cannot_guarantee_physical_memory_erasure',
        genericReady: false,
      };
    },
  };
}

export function createProtectedEvidenceListingPersistenceReadinessPort() {
  return {
    async inspect() {
      return {
        persistenceAdapterPolicyId: OSV_EVIDENCE_RETAINING_LISTING_PERSISTENCE_ADAPTER_POLICY_ID,
        evidenceSchemaVersion: OSV_EVIDENCE_RETAINING_LISTING_EVIDENCE_SCHEMA_VERSION,
        publicInspectionOmitsEnvelopeBytea: true,
        publicInspectionOmitsOpaqueKeyAlias: true,
        observationCapacitySupported: OSV_EVIDENCE_RETAINING_LISTING_MAX_OBSERVATIONS,
        databaseTransactionReadiness: 'atomic_insert_once_available',
        encryptionBeforePrisma: true,
        plaintextFallbackConfigured: false,
        providerDataCurrentlyRetained: false,
        productionCompositionActive: false,
        bodyAuthority: false,
        activationAuthority: false,
        matchingAuthority: false,
        findingAuthority: false,
        genericReady: false,
        persistenceReady: true,
      };
    },
  };
}

export function identityOf(operatorAttestationId: string): OsvCanaryInstanceOperatorIdentity {
  return expectOk(
    createOsvCanaryInstanceOperatorIdentity({
      operatorAttestationId,
      identityType: 'instance_operator',
      authenticationSource: 'local_host_control_of_one_shot_administrative_command',
      displayLabel: `canary-op-${operatorAttestationId.slice(0, 8)}`,
      provenanceIdentifier: 'configured_instance_operator_attestation_v1',
      establishedAt: '2026-09-08T12:00:00Z',
    }),
    'identity',
  );
}

export async function seedOsvProtectedEvidenceListingCanaryAuthority(
  prisma: PrismaClient,
): Promise<OsvProtectedEvidenceListingCanaryAuthoritySeed> {
  const canary = createOsvCanaryAuthorizationPersistence(prisma);
  const coordination = createOsvRuntimeCoordinationPersistence(prisma);
  const providerContact = createOsvListingProviderContactAuthorizationPersistence(prisma);
  const operatorAttestationId = uuid();
  expectOk(
    await canary.operators.ensure(
      expectOk(
        createOsvCanaryOperatorEnsureCommand({
          operatorAttestationId,
          identityType: 'instance_operator',
          authenticationSource: 'local_host_control_of_one_shot_administrative_command',
          displayLabel: `canary-op-${operatorAttestationId.slice(0, 8)}`,
          provenanceIdentifier: 'configured_instance_operator_attestation_v1',
        }),
        'operator command',
      ),
    ),
    'operator ensure',
  );
  const listing = expectOk(
    await canary.authorizations.ensure(
      expectOk(
        createOsvCanaryAuthorizationEnsureCommand({
          authorizationId: uuid(),
          operatorAttestationId,
          phase: 'listing_only',
          authorizationPurpose: 'approved_listing_repetition',
          legalDecisionReference: expectOk(
            createOsvCanaryLegalDecisionReference({
              decisionId: uuid(),
              sourceRegistryVersion: 'osv_source_license_registry_v1',
              sourceIdentifier: 'rustsec_advisory_database',
              family: 'RUSTSEC',
              phase: 'listing_only',
              permittedOperation: 'list_object_metadata',
              issuedAt: LEGAL_ISSUED,
              revalidationBoundaryAt: LEGAL_REVALIDATE,
              responsibleRole:
                'instance_legal_and_provenance_reviewer_countersigned_by_instance_operator',
              evidenceSetId: uuid(),
            }),
            'listing legal',
          ),
          runbookAcknowledgement: expectOk(
            createOsvCanaryRunbookAcknowledgement({
              runbookSetIdentifier: 'osv_canary_runbook_set_v1',
              runbookVersion: 'osv_canary_runbook_outlines_v1',
              acknowledgedAt: ACK,
              phase: 'listing_only',
            }),
            'runbook',
          ),
          haltControlAcknowledgement: expectOk(
            createOsvCanaryHaltControlAcknowledgement({ acknowledgedAt: ACK }),
            'halt',
          ),
          activationProhibitionAcknowledgement: expectOk(
            createOsvCanaryActivationProhibitionAcknowledgement(),
            'activation',
          ),
          automaticRetryProhibitionAcknowledgement: expectOk(
            createOsvCanaryAutomaticRetryProhibitionAcknowledgement(),
            'retry',
          ),
        }),
        'listing command',
      ),
    ),
    'listing ensure',
  );
  const sourceId = listing.authorization.snapshot.record.authorizationId;
  const sourceLegalDecisionId =
    listing.authorization.snapshot.record.legalDecisionReference.decisionId;
  const payload = expectOk(
    createOsvRuntimeSyncJobPayload(
      createClosedOsvRuntimeSyncJobInput({
        synchronizationReason: 'operator_canary',
        requestedAt: '2026-09-08T12:00:00Z',
        correlationId: uuid(),
      }),
    ),
    'payload',
  );
  const request = expectOk(
    await coordination.requests.ensure(
      expectOk(
        createOsvRuntimeSynchronizationRequestEnsureCommand({
          payload,
          idempotency: expectOk(
            createOsvRuntimeJobIdempotencyIdentity({
              workScope: payload.workScope,
              reason: payload.synchronizationReason,
              versionSetFingerprint: payload.versionSetFingerprint,
              requestKind: 'operator_request',
              schedulerWindowId: null,
              operatorRequestId: uuid(),
            }),
            'idempotency',
          ),
          requestState: 'accepted',
        }),
        'request command',
      ),
    ),
    'request',
  );
  const run = expectOk(
    await coordination.runs.ensure(
      expectOk(
        createOsvRuntimeSynchronizationRunEnsureCommand({ requestId: request.request.id }),
        'run command',
      ),
    ),
    'run',
  );
  expectOk(
    await canary.authorizations.consume(
      expectOk(
        createOsvCanaryAuthorizationConsumePersistenceCommand({
          authorizationId: sourceId,
          operatorAttestationId,
          phase: 'listing_only',
          providerPrefix: 'crates.io/',
          canaryPolicyIdentifier: 'osv_disabled_first_provider_canary_policy_v1',
          runtimeVersionSetFingerprint: FINGERPRINT,
          requestId: request.request.id,
          runId: run.run.id,
        }),
        'canary consume command',
      ),
    ),
    'canary consume',
  );
  const activePointer = uuid();
  const zeroFinding = uuid();
  const capturedAt = new Date('2026-09-08T11:30:00.000Z');
  const preflight = await prisma.osvCanaryProviderFreePreflightAttestation.create({
    data: {
      id: uuid(),
      evidenceSchemaVersion: 'osv_canary_provider_free_preflight_attestation_v1',
      sourceCanaryAuthorizationId: sourceId,
      operatorIdentityId: operatorAttestationId,
      synchronizationRequestId: request.request.id,
      synchronizationRunId: run.run.id,
      phase: 'listing_only',
      providerIdentity: 'rustsec_advisory_database',
      approvedPrefix: 'crates.io/',
      canaryPolicyIdentifier: 'osv_disabled_first_provider_canary_policy_v1',
      listingBudgetProfile: 'osv_canary_listing_only_budget_v1',
      workScope: CANARY_SCOPE,
      leaseScope: OSV_EVIDENCE_RETAINING_LISTING_AUTHORIZATION_LEASE_SCOPE,
      synchronizationReason: 'operator_canary',
      runtimeVersionSetFingerprint: FINGERPRINT,
      legalDecisionVersion: 'osv_listing_provider_contact_legal_approval_v1',
      egressEvidenceVersion: 'osv_listing_provider_contact_egress_evidence_v1',
      heartbeatPolicyIdentifier: 'osv_canary_runtime_controls_v1',
      deadlinePolicyIdentifier: 'osv_canary_runtime_controls_v1',
      activePointerBaselineIdentity: activePointer,
      zeroFindingBaselineIdentity: zeroFinding,
      outcome: 'canary_execution_preflight_passed_provider_contact_not_authorized',
      providerContactAuthorized: false,
      executionPermitted: false,
      acceptedForProviderContactAuth: true,
      capturedAt,
      createdAt: capturedAt,
    },
  });
  const issued = expectOk(
    await providerContact.issue(
      expectOk(
        createOsvListingProviderContactAuthorizationIssueCommand({
          providerContactAuthorizationId: uuid(),
          sourceCanaryAuthorizationId: sourceId,
          operatorAttestationId,
          synchronizationRequestId: request.request.id,
          synchronizationRunId: run.run.id,
          preflightEvidenceId: preflight.id,
          activePointerBaselineIdentity: activePointer,
          zeroFindingBaselineIdentity: zeroFinding,
          legalApproval: expectOk(
            createOsvListingProviderContactLegalApproval({
              decisionId: uuid(),
              sourceCanaryLegalDecisionId: sourceLegalDecisionId,
              issuedAt: LEGAL_ISSUED,
              revalidationBoundaryAt: LEGAL_REVALIDATE,
              evidenceSetId: uuid(),
              approvalRole:
                'instance_legal_and_provenance_reviewer_countersigned_by_instance_operator',
              supersessionStatus: 'current',
            }),
            'legal',
          ),
          egressEvidence: expectOk(
            createOsvListingProviderContactEgressEvidence({
              egressEvidenceId: uuid(),
              reviewedAt: ACK,
              reviewerRole: 'instance_operator_deployment_reviewer',
              fixedHttpsHost: APPLICATION_TESTED,
              defaultTlsPort: APPLICATION_TESTED,
              fixedGcsApiPath: APPLICATION_TESTED,
              fixedBucket: APPLICATION_TESTED,
              fixedQueryGrammar: APPLICATION_TESTED,
              redirectsRejected: APPLICATION_TESTED,
              providerControlledCustomCaProhibited: APPLICATION_TESTED,
              listingOnlyBodyRoutesProhibited: APPLICATION_TESTED,
              callerSelectedProxyProhibited: DEPLOYMENT_CONFIGURED,
              dnsPinningPolicy: DEPLOYMENT_CONFIGURED,
              prohibitedAddressFiltering: DEPLOYMENT_CONFIGURED,
              privateLoopbackLinkLocalMetadataDenied: DEPLOYMENT_CONFIGURED,
              postConnectPeerVerification: DEPLOYMENT_CONFIGURED,
              tlsCertificateVerification: DEPLOYMENT_CONFIGURED,
              cloudMetadataAccessDenied: DEPLOYMENT_CONFIGURED,
              providerConnectivityExercised: false,
              dnsLookupCount: 0,
              tlsConnectionCount: 0,
              httpCount: 0,
            }),
            'egress',
          ),
          deploymentApproval: expectOk(
            createOsvListingProviderContactDeploymentApproval({
              deploymentId: uuid(),
              environmentClass: 'dedicated_instance_operator_process',
              egressPolicyVersion: 'osv_listing_provider_contact_egress_evidence_v1',
              runtimeArtifactVersion: ARTIFACT,
              configurationFingerprint: FINGERPRINT,
              providerTransportPolicy: 'osv_transport_policy_v1',
              observabilityPolicy: 'osv_listing_provider_contact_observability_policy_v1',
              runbookVersion: 'osv_listing_provider_contact_runbook_v1',
              approvalRole: 'instance_operator_deployment_reviewer',
              approvedAt: ACK,
              invalidatesOnDeploymentChange: true,
            }),
            'deployment',
          ),
          haltProcedureAcknowledgement: expectOk(
            createOsvListingProviderContactHaltProcedureAcknowledgement({
              acknowledgedAt: ACK,
            }),
            'halt procedure',
          ),
          runbookAcknowledgement: expectOk(
            createOsvListingProviderContactRunbookAcknowledgement({
              runbookSetIdentifier: 'osv_listing_provider_contact_runbook_set_v1',
              runbookVersion: 'osv_listing_provider_contact_runbook_v1',
              acknowledgedAt: ACK,
            }),
            'provider runbook',
          ),
          containmentAcknowledgement: expectOk(
            createOsvListingProviderContactContainmentAcknowledgement({ acknowledgedAt: ACK }),
            'containment',
          ),
          reviewerAssignment: expectOk(
            createOsvListingProviderContactReviewerAssignment({
              assignedAt: ACK,
              requiredReviewRole: 'instance_canary_evidence_reviewer',
            }),
            'reviewer',
          ),
          retentionDisposition: expectOk(
            createOsvListingProviderContactRetentionDisposition({ acknowledgedAt: ACK }),
            'retention',
          ),
        }),
        'issue command',
      ),
    ),
    'issue',
  );
  return {
    operatorAttestationId,
    sourceId,
    requestId: request.request.id,
    runId: run.run.id,
    preflightId: preflight.id,
    providerContactAuthorizationId: issued.record.providerContactAuthorizationId,
    identity: identityOf(operatorAttestationId),
  };
}

function confirmationPolicyPins() {
  return {
    authorizationKind: OSV_EVIDENCE_RETAINING_LISTING_AUTHORIZATION_KIND,
    purposeId: OSV_EVIDENCE_RETAINING_LISTING_AUTHORIZATION_PURPOSE,
    pageOrdinal: OSV_EVIDENCE_RETAINING_LISTING_PAGE_ORDINAL,
    evidencePolicyId: OSV_EVIDENCE_RETAINING_LISTING_EVIDENCE_POLICY_ID,
    retentionPolicyId: OSV_EVIDENCE_RETAINING_LISTING_RETENTION_POLICY_ID,
    encryptionPolicyId: OSV_EVIDENCE_RETAINING_LISTING_ENCRYPTION_POLICY_ID,
    associatedDataPolicyId: OSV_EVIDENCE_RETAINING_LISTING_ASSOCIATED_DATA_POLICY_ID,
    envelopeSchemaVersion: OSV_EVIDENCE_RETAINING_LISTING_ENVELOPE_SCHEMA_VERSION,
    persistenceAdapterPolicyId: OSV_EVIDENCE_RETAINING_LISTING_PERSISTENCE_ADAPTER_POLICY_ID,
    maximumObservationCount: OSV_EVIDENCE_RETAINING_LISTING_MAX_OBSERVATIONS,
  };
}

function inputPolicyPins() {
  return {
    authorizationKind: OSV_EVIDENCE_RETAINING_LISTING_AUTHORIZATION_KIND,
    purposeId: OSV_EVIDENCE_RETAINING_LISTING_AUTHORIZATION_PURPOSE,
    canaryPurpose: OSV_EVIDENCE_RETAINING_LISTING_CANARY_PURPOSE,
    pageOrdinal: OSV_EVIDENCE_RETAINING_LISTING_PAGE_ORDINAL,
    evidenceSchemaVersion: OSV_EVIDENCE_RETAINING_LISTING_EVIDENCE_SCHEMA_VERSION,
    evidencePolicyId: OSV_EVIDENCE_RETAINING_LISTING_EVIDENCE_POLICY_ID,
    evidencePurposeId: OSV_EVIDENCE_RETAINING_LISTING_EVIDENCE_PURPOSE_ID,
    retentionPolicyId: OSV_EVIDENCE_RETAINING_LISTING_RETENTION_POLICY_ID,
    encryptionPolicyId: OSV_EVIDENCE_RETAINING_LISTING_ENCRYPTION_POLICY_ID,
    envelopeSchemaVersion: OSV_EVIDENCE_RETAINING_LISTING_ENVELOPE_SCHEMA_VERSION,
    associatedDataPolicyId: OSV_EVIDENCE_RETAINING_LISTING_ASSOCIATED_DATA_POLICY_ID,
    persistenceAdapterPolicyId: OSV_EVIDENCE_RETAINING_LISTING_PERSISTENCE_ADAPTER_POLICY_ID,
    maximumObservationCount: OSV_EVIDENCE_RETAINING_LISTING_MAX_OBSERVATIONS,
    maxTotalProtectedKeyBytes: OSV_EVIDENCE_RETAINING_LISTING_MAX_PROTECTED_KEY_BYTES,
    maxTotalEvidenceMetadataBytes: OSV_EVIDENCE_RETAINING_LISTING_MAX_EVIDENCE_METADATA_BYTES,
  };
}

export function createProtectedEvidenceListingCanaryExecutionInput(
  seed: OsvProtectedEvidenceListingCanaryAuthoritySeed,
): OsvEvidenceRetainingListingAuthorizationInput {
  const confirmationId = uuid();
  const confirmation = expectOk(
    createOsvEvidenceRetainingListingConfirmation({
      confirmationId,
      providerContactAuthorizationId: seed.providerContactAuthorizationId,
      sourceCanaryAuthorizationId: seed.sourceId,
      synchronizationRequestId: seed.requestId,
      synchronizationRunId: seed.runId,
      phase: OSV_EVIDENCE_RETAINING_LISTING_AUTHORIZATION_PHASE,
      approvedPrefix: OSV_EVIDENCE_RETAINING_LISTING_AUTHORIZATION_EXPECTED_PREFIX,
      canaryPolicyIdentifier: OSV_EVIDENCE_RETAINING_LISTING_AUTHORIZATION_EXPECTED_POLICY,
      runtimeVersionSetFingerprint: FINGERPRINT,
      ...confirmationPolicyPins(),
      proofMaterial: CONFIRMATION_PROOF,
    }),
    'confirmation',
  );
  return expectOk(
    createOsvEvidenceRetainingListingAuthorizationInput({
      executionAuthorizationSchemaVersion:
        OSV_EVIDENCE_RETAINING_LISTING_AUTHORIZATION_SCHEMA_VERSION,
      operatorExecutionConfirmationId: confirmationId,
      providerContactAuthorizationId: seed.providerContactAuthorizationId,
      sourceCanaryAuthorizationId: seed.sourceId,
      synchronizationRequestId: seed.requestId,
      synchronizationRunId: seed.runId,
      preflightEvidenceId: seed.preflightId,
      phase: OSV_EVIDENCE_RETAINING_LISTING_AUTHORIZATION_PHASE,
      expectedProvider: OSV_EVIDENCE_RETAINING_LISTING_AUTHORIZATION_EXPECTED_PROVIDER,
      expectedPrefix: OSV_EVIDENCE_RETAINING_LISTING_AUTHORIZATION_EXPECTED_PREFIX,
      expectedCanaryPolicy: OSV_EVIDENCE_RETAINING_LISTING_AUTHORIZATION_EXPECTED_POLICY,
      expectedBudgetProfile: OSV_EVIDENCE_RETAINING_LISTING_AUTHORIZATION_EXPECTED_BUDGET,
      expectedRuntimeVersionSetFingerprint: FINGERPRINT,
      expectedEgressPolicyId: OSV_EVIDENCE_RETAINING_LISTING_AUTHORIZATION_EGRESS_POLICY_ID,
      expectedLeaseScope: OSV_EVIDENCE_RETAINING_LISTING_AUTHORIZATION_LEASE_SCOPE,
      ...inputPolicyPins(),
      correlationId: uuid(),
      executionConfirmation: confirmation,
    }),
    'input',
  );
}
