/**
 * Session 13 Batch 3D-S protected listing-observation evidence schema
 * constraints. Direct SQL against disposable PostgreSQL. Schema only:
 * no persistence adapters, encryption, keys, provider contact, DNS,
 * TLS, HTTP, listing canary, body retrieval, parser, activation,
 * matching, or Finding writes. Synthetic envelope bytes are fixtures,
 * not cryptographically secure ciphertext.
 */

import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { Prisma, PrismaClient } from '@prisma/client';

import {
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
} from './integration-database.js';

const FINGERPRINT = 'a'.repeat(64);
const CANARY_SCOPE = 'osv_runtime_canary_scope_crates_io_rustsec_v1';
const LEASE_SCOPE = 'osv_runtime_lease_scope_osv_gcs_public_export_v1';
const ARTIFACT = 'patchpilot.canary.artifact.1';
const srcDir = path.dirname(fileURLToPath(import.meta.url));

function liveWindow(issuedAgoMs = 5_000): {
  issuedAt: Date;
  expiresAt: Date;
  createdAt: Date;
  acknowledgedAt: Date;
} {
  const issuedAt = new Date(Date.now() - issuedAgoMs);
  return {
    issuedAt,
    expiresAt: new Date(issuedAt.getTime() + 3_600_000),
    createdAt: issuedAt,
    acknowledgedAt: new Date(issuedAt.getTime() - 1_000),
  };
}

function operator(
  overrides: Partial<Prisma.OsvCanaryInstanceOperatorIdentityUncheckedCreateInput> = {},
): Prisma.OsvCanaryInstanceOperatorIdentityUncheckedCreateInput {
  const establishedAt = overrides.establishedAt ?? liveWindow().issuedAt;
  return {
    id: randomUUID(),
    identitySchemaVersion: 'osv_canary_instance_operator_identity_v1',
    identityType: 'instance_operator',
    authenticationSource: 'local_host_control_of_one_shot_administrative_command',
    provenanceIdentifier: 'configured_instance_operator_attestation_v1',
    displayLabel: `canary-operator-${randomUUID().slice(0, 8)}`,
    establishedAt,
    createdAt: establishedAt,
    status: 'active',
    ...overrides,
  };
}

function canaryRequest(
  overrides: Partial<Prisma.OsvRuntimeSynchronizationRequestUncheckedCreateInput> = {},
): Prisma.OsvRuntimeSynchronizationRequestUncheckedCreateInput {
  const requestedAt = overrides.requestedAt ?? liveWindow().issuedAt;
  return {
    jobType: 'intelligence.osv.sync',
    jobSchemaVersion: 'osv_runtime_sync_job_schema_v1',
    synchronizationReason: 'operator_canary',
    workScope: CANARY_SCOPE,
    leaseScope: LEASE_SCOPE,
    catalogScope: 'osv_gcs_six_prefix_public_export_v1',
    versionSetFingerprint: FINGERPRINT,
    requestedAt,
    createdAt: requestedAt,
    correlationId: randomUUID(),
    canaryPolicyIdentifier: 'osv_disabled_first_provider_canary_policy_v1',
    requestKind: 'operator_request',
    operatorRequestId: randomUUID(),
    requestState: 'accepted',
    ...overrides,
  };
}

function canaryRun(
  request: { id: string },
  overrides: Partial<Prisma.OsvRuntimeSynchronizationRunUncheckedCreateInput> = {},
): Prisma.OsvRuntimeSynchronizationRunUncheckedCreateInput {
  const createdAt = overrides.createdAt ?? liveWindow().issuedAt;
  return {
    requestId: request.id,
    workScope: CANARY_SCOPE,
    leaseScope: LEASE_SCOPE,
    synchronizationReason: 'operator_canary',
    paginationPolicyIdentifier: 'osv_disabled_first_provider_canary_policy_v1',
    versionSetFingerprint: FINGERPRINT,
    runtimeArchitectureIdentifier: 'osv_runtime_enablement_architecture_v1',
    synchronizationAlgorithmIdentifier: 'osv_catalog_sync_algorithm_v1',
    retryPolicyIdentifier: 'osv_runtime_retry_policy_v1',
    state: 'planned',
    createdAt,
    updatedAt: createdAt,
    ...overrides,
  };
}

function listingAuthorization(
  operatorId: string,
  window: ReturnType<typeof liveWindow>,
  overrides: Partial<Prisma.OsvCanaryAuthorizationUncheckedCreateInput> = {},
): Prisma.OsvCanaryAuthorizationUncheckedCreateInput {
  return {
    id: randomUUID(),
    operatorIdentityId: operatorId,
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
    workScope: CANARY_SCOPE,
    leaseScope: LEASE_SCOPE,
    runtimeVersionSetFingerprint: FINGERPRINT,
    budgetProfileIdentifier: 'osv_canary_listing_only_budget_v1',
    unusedTtlSeconds: 3600,
    singleUsePolicy: 'single_use',
    catalogActivationAuthorization: 'prohibited',
    matchingAuthorization: 'prohibited',
    findingAuthorization: 'prohibited',
    postcanaryReviewRequirement: 'required',
    legalDecisionReferenceIdentifier: 'osv_canary_legal_decision_reference_v1',
    legalDecisionId: randomUUID(),
    legalDecisionSourceRegistryVersion: 'osv_source_license_registry_v1',
    legalDecisionPhase: 'listing_only',
    legalDecisionPermittedOperation: 'list_object_metadata',
    legalDecisionState: 'recorded_reference_not_execution_authority',
    legalDecisionIssuance: 'blocking_preexecution_dependency_not_issued_in_batch_2a',
    legalDecisionIssuedAt: window.acknowledgedAt,
    legalDecisionRevalidationBoundaryAt: new Date('2099-09-09T11:00:00.000Z'),
    legalDecisionResponsibleRole:
      'instance_legal_and_provenance_reviewer_countersigned_by_instance_operator',
    legalDecisionEvidenceSetId: randomUUID(),
    runbookSetIdentifier: 'osv_canary_runbook_set_v1',
    runbookVersion: 'osv_canary_runbook_outlines_v1',
    runbookAcknowledgedAt: window.acknowledgedAt,
    runbookEmergencyHaltProcedure: 'stop_next_protected_stage_production_remains_halted',
    haltAcknowledgementIdentifier: 'osv_canary_halt_control_acknowledgement_v1',
    haltAcknowledgedAt: window.acknowledgedAt,
    activationProhibitionIdentifier: 'osv_canary_activation_prohibition_v1',
    retryProhibitionIdentifier: 'osv_canary_automatic_retry_prohibition_v1',
    issuedAt: window.issuedAt,
    expiresAt: window.expiresAt,
    state: 'issued',
    createdAt: window.createdAt,
    ...overrides,
  };
}

function preflightAttestation(
  input: {
    operatorId: string;
    sourceId: string;
    requestId: string;
    runId: string;
    capturedAt: Date;
  },
  overrides: Partial<Prisma.OsvCanaryProviderFreePreflightAttestationUncheckedCreateInput> = {},
): Prisma.OsvCanaryProviderFreePreflightAttestationUncheckedCreateInput {
  return {
    id: randomUUID(),
    evidenceSchemaVersion: 'osv_canary_provider_free_preflight_attestation_v1',
    sourceCanaryAuthorizationId: input.sourceId,
    operatorIdentityId: input.operatorId,
    synchronizationRequestId: input.requestId,
    synchronizationRunId: input.runId,
    phase: 'listing_only',
    providerIdentity: 'rustsec_advisory_database',
    approvedPrefix: 'crates.io/',
    canaryPolicyIdentifier: 'osv_disabled_first_provider_canary_policy_v1',
    listingBudgetProfile: 'osv_canary_listing_only_budget_v1',
    workScope: CANARY_SCOPE,
    leaseScope: LEASE_SCOPE,
    synchronizationReason: 'operator_canary',
    runtimeVersionSetFingerprint: FINGERPRINT,
    legalDecisionVersion: 'osv_listing_provider_contact_legal_approval_v1',
    egressEvidenceVersion: 'osv_listing_provider_contact_egress_evidence_v1',
    heartbeatPolicyIdentifier: 'osv_canary_runtime_controls_v1',
    deadlinePolicyIdentifier: 'osv_canary_runtime_controls_v1',
    activePointerBaselineIdentity: randomUUID(),
    zeroFindingBaselineIdentity: randomUUID(),
    outcome: 'canary_execution_preflight_passed_provider_contact_not_authorized',
    providerContactAuthorized: false,
    executionPermitted: false,
    acceptedForProviderContactAuth: true,
    capturedAt: input.capturedAt,
    createdAt: input.capturedAt,
    ...overrides,
  };
}

function providerContactAuthorization(
  input: {
    operatorId: string;
    sourceId: string;
    requestId: string;
    runId: string;
    preflightId: string;
    sourceLegalDecisionId: string;
    activePointerBaselineIdentity: string;
    zeroFindingBaselineIdentity: string;
    window: ReturnType<typeof liveWindow>;
  },
  overrides: Partial<Prisma.OsvListingProviderContactAuthorizationUncheckedCreateInput> = {},
): Prisma.OsvListingProviderContactAuthorizationUncheckedCreateInput {
  return {
    id: randomUUID(),
    authorizationSchemaVersion: 'osv_listing_only_provider_contact_authorization_v1',
    sourceCanaryAuthorizationId: input.sourceId,
    operatorIdentityId: input.operatorId,
    synchronizationRequestId: input.requestId,
    synchronizationRunId: input.runId,
    preflightEvidenceId: input.preflightId,
    phase: 'listing_only',
    providerIdentity: 'rustsec_advisory_database',
    bucketIdentity: 'osv-vulnerabilities',
    listingApiPathPolicy: '/storage/v1/b/osv-vulnerabilities/o',
    listingProtocol: 'osv_gcs_json_objects_list_v1',
    approvedPrefix: 'crates.io/',
    family: 'RUSTSEC',
    canaryPolicyIdentifier: 'osv_disabled_first_provider_canary_policy_v1',
    listingBudgetProfile: 'osv_canary_listing_only_budget_v1',
    workScope: CANARY_SCOPE,
    leaseScope: LEASE_SCOPE,
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
    legalDecisionId: randomUUID(),
    sourceCanaryLegalDecisionId: input.sourceLegalDecisionId,
    legalDecisionSourceRegistryVersion: 'osv_source_license_registry_v1',
    legalListingMetadataPermission: 'approved',
    legalBodyRetrievalPermission: 'prohibited',
    legalParsingPermission: 'prohibited',
    legalMatchingPermission: 'prohibited',
    legalIssuedAt: input.window.acknowledgedAt,
    legalRevalidationBoundaryAt: new Date('2099-09-09T11:00:00.000Z'),
    legalEvidenceSetId: randomUUID(),
    legalApprovalRole: 'instance_legal_and_provenance_reviewer_countersigned_by_instance_operator',
    legalSupersessionStatus: 'current',
    egressEvidenceIdentifier: 'osv_listing_provider_contact_egress_evidence_v1',
    egressEvidenceId: randomUUID(),
    egressEvidenceVersion: 'osv_listing_provider_contact_egress_evidence_v1',
    egressReviewerRole: 'instance_operator_deployment_reviewer',
    egressReviewedAt: input.window.acknowledgedAt,
    providerConnectivityExercised: false,
    deploymentApprovalIdentifier: 'osv_listing_provider_contact_deployment_approval_v1',
    deploymentId: randomUUID(),
    environmentClass: 'dedicated_instance_operator_process',
    runtimeArtifactVersion: ARTIFACT,
    configurationFingerprint: FINGERPRINT,
    observabilityPolicy: 'osv_listing_provider_contact_observability_policy_v1',
    deploymentApprovalRole: 'instance_operator_deployment_reviewer',
    deploymentApprovedAt: input.window.acknowledgedAt,
    invalidatesOnDeploymentChange: true,
    heartbeatPolicyIdentifier: 'osv_canary_runtime_controls_v1',
    deadlinePolicyIdentifier: 'osv_canary_runtime_controls_v1',
    runbookSetIdentifier: 'osv_listing_provider_contact_runbook_set_v1',
    runbookVersion: 'osv_listing_provider_contact_runbook_v1',
    runbookAcknowledgedAt: input.window.acknowledgedAt,
    haltProcedureIdentifier: 'osv_listing_provider_contact_halt_procedure_v1',
    haltAcknowledgedAt: input.window.acknowledgedAt,
    containmentCatalogIdentifier: 'osv_listing_provider_contact_emergency_containment_v1',
    containmentAcknowledgedAt: input.window.acknowledgedAt,
    postcanaryReviewPolicyIdentifier: 'osv_listing_provider_contact_postcanary_review_v1',
    requiredReviewRole: 'instance_canary_evidence_reviewer',
    reviewerAssignedAt: input.window.acknowledgedAt,
    issuingOperatorMayReview: false,
    automaticProgression: false,
    evidenceRetentionPolicyIdentifier: 'osv_listing_provider_contact_retention_disposition_v1',
    retentionAcknowledgedAt: input.window.acknowledgedAt,
    activePointerBaselineIdentity: input.activePointerBaselineIdentity,
    zeroFindingBaselineIdentity: input.zeroFindingBaselineIdentity,
    issuedAt: input.window.issuedAt,
    expiresAt: input.window.expiresAt,
    state: 'issued',
    createdAt: input.window.createdAt,
    ...overrides,
  };
}

const DIGEST = 'c'.repeat(64);
const KEY_ALIAS = 'osv.listing.evidence.kcanary1';
const MIGRATION_SQL = path.join(
  srcDir,
  '../prisma/migrations/20260910120000_osv_listing_observation_evidence_persistence/migration.sql',
);

function syntheticEnvelopeBytes(plaintextLength: number): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(12 + plaintextLength + 16);
  bytes.fill(0x01, 0, 12);
  bytes.fill(0xa5, 12, 12 + plaintextLength);
  bytes.fill(0x02, 12 + plaintextLength);
  return bytes;
}

function evidenceSetData(
  authorization: { id: string; synchronizationRequestId: string; synchronizationRunId: string },
  overrides: Partial<Prisma.OsvListingObservationEvidenceSetUncheckedCreateInput> = {},
): Prisma.OsvListingObservationEvidenceSetUncheckedCreateInput {
  return {
    id: randomUUID(),
    evidenceSchemaVersion: 'osv_protected_listing_observation_evidence_v1',
    evidencePolicyId: 'osv_protected_listing_observation_evidence_policy_v1',
    purposeId: 'osv_protected_listing_observation_evidence_purpose_v1',
    ownership: 'instance_owned_non_tenant',
    listingExecutionId: randomUUID(),
    providerContactAuthorizationId: authorization.id,
    synchronizationRequestId: authorization.synchronizationRequestId,
    synchronizationRunId: authorization.synchronizationRunId,
    provider: 'osv',
    approvedPrefix: 'crates.io/',
    listingProtocolId: 'osv_gcs_json_objects_list_v1',
    listingPolicyId: 'osv_disabled_first_provider_canary_policy_v1',
    budgetProfileId: 'osv_canary_listing_only_budget_v1',
    workScope: CANARY_SCOPE,
    leaseScope: LEASE_SCOPE,
    synchronizationReason: 'operator_canary',
    runtimeVersionSetFingerprint: FINGERPRINT,
    sourceLicenseRegistryVersion: 'osv_source_license_registry_v1',
    classificationPolicyId: 'osv_metadata_policy_v1',
    canonicalEvidenceSetAlgorithmId: 'osv_protected_listing_observation_evidence_set_canonical_v1',
    encryptionPolicyId: 'osv_protected_listing_evidence_encryption_policy_v1',
    associatedDataPolicyId: 'osv_protected_listing_evidence_associated_data_v1',
    associatedDataAlgorithmId: 'osv_protected_listing_evidence_associated_data_canonical_v1',
    envelopeSchemaVersion: 'osv_protected_listing_evidence_ciphertext_envelope_v1',
    algorithmId: 'aes-256-gcm',
    retentionPolicyId: 'osv_protected_listing_observation_evidence_retention_v1',
    pageOrdinal: 1,
    canonicalEvidenceSetDigest: DIGEST,
    translatorObservationCount: 0,
    acceptedObservationCount: 0,
    protectedObservationCount: 0,
    rejectedObservationCount: 0,
    exactDuplicateCount: 0,
    duplicateAmbiguityCount: 0,
    immutableConflictCount: 0,
    totalProtectedKeyPlaintextBytes: 0n,
    totalEnvelopeBytes: 0n,
    totalCanonicalBytes: 0n,
    totalMetadataBytes: 0n,
    eventCount: 0,
    evidenceState: 'constructed',
    candidateSelectionReadiness: 'empty_page_not_candidate_ready',
    retentionOverdueClassification: 'not_overdue',
    legalHoldActive: false,
    legalHoldClassification: 'hold_absent',
    dependentAuthorizationsTerminal: false,
    candidateSelectionAuthorized: false,
    bodyRetrievalAuthorized: false,
    batch4pPermitted: false,
    paginationAuthorized: false,
    activationAuthorized: false,
    matchingAuthorized: false,
    findingWritesAuthorized: false,
    providerContactAuthorized: false,
    rowRevision: 1n,
    ...overrides,
  };
}

describe(
  'session 13 Batch 3D-S protected listing-observation evidence SQL constraints',
  { timeout: 360_000 },
  () => {
    let databaseName: string;
    let admin: PrismaClient;
    let prisma: PrismaClient;

    beforeAll(async () => {
      const ephemeral = await createEphemeralDatabase('it');
      databaseName = ephemeral.databaseName;
      admin = ephemeral.admin;
      await deployMigrations(ephemeral.databaseUrl);
      prisma = new PrismaClient({
        datasources: { db: { url: ephemeral.databaseUrl } },
      });
    });

    afterAll(async () => {
      if (prisma !== undefined) {
        await prisma.$disconnect();
      }
      if (admin !== undefined && databaseName !== undefined) {
        await dropEphemeralDatabase(admin, databaseName);
      }
    });

    async function consumeCanary(
      authorizationId: string,
      requestId: string,
      runId: string,
    ): Promise<number> {
      return prisma.$executeRaw`
        UPDATE "osv_canary_authorization"
        SET "state" = 'consumed',
            "consumed_at" = CURRENT_TIMESTAMP,
            "consumed_by_synchronization_request_id" = ${requestId}::uuid,
            "consumed_by_synchronization_run_id" = ${runId}::uuid
        WHERE "id" = ${authorizationId}::uuid
          AND "state" = 'issued'
          AND CURRENT_TIMESTAMP < "expires_at"
      `;
    }

    async function seedIssuedProviderContact(window = liveWindow()) {
      const createdOperator = await prisma.osvCanaryInstanceOperatorIdentity.create({
        data: operator({ establishedAt: window.issuedAt, createdAt: window.issuedAt }),
      });
      const request = await prisma.osvRuntimeSynchronizationRequest.create({
        data: canaryRequest({ requestedAt: window.issuedAt, createdAt: window.issuedAt }),
      });
      const run = await prisma.osvRuntimeSynchronizationRun.create({
        data: canaryRun(request, { createdAt: window.issuedAt, updatedAt: window.issuedAt }),
      });
      const source = await prisma.osvCanaryAuthorization.create({
        data: listingAuthorization(createdOperator.id, window),
      });
      const consumed = await consumeCanary(source.id, request.id, run.id);
      expect(consumed).toBe(1);
      const preflight = await prisma.osvCanaryProviderFreePreflightAttestation.create({
        data: preflightAttestation({
          operatorId: createdOperator.id,
          sourceId: source.id,
          requestId: request.id,
          runId: run.id,
          capturedAt: window.acknowledgedAt,
        }),
      });
      const authorization = await prisma.osvListingProviderContactAuthorization.create({
        data: providerContactAuthorization({
          operatorId: createdOperator.id,
          sourceId: source.id,
          requestId: request.id,
          runId: run.id,
          preflightId: preflight.id,
          sourceLegalDecisionId: source.legalDecisionId,
          activePointerBaselineIdentity: preflight.activePointerBaselineIdentity,
          zeroFindingBaselineIdentity: preflight.zeroFindingBaselineIdentity,
          window,
        }),
      });
      return { operatorId: createdOperator.id, request, run, source, preflight, authorization };
    }

    async function persistProtectedObservation(input: {
      authorization: { id: string; synchronizationRequestId: string; synchronizationRunId: string };
      generation?: string;
      declaredListingByteCount?: bigint;
      plaintextLength?: number;
      sourceFamilyClassification?: string;
      classificationStatus?: Prisma.OsvListingObservationEvidenceUncheckedCreateInput['classificationStatus'];
      setOverrides?: Partial<Prisma.OsvListingObservationEvidenceSetUncheckedCreateInput>;
    }) {
      const plaintextLength = input.plaintextLength ?? 8;
      const envelopeBytes = syntheticEnvelopeBytes(plaintextLength);
      const setData = evidenceSetData(input.authorization, {
        translatorObservationCount: 1,
        acceptedObservationCount: 1,
        protectedObservationCount: 1,
        totalProtectedKeyPlaintextBytes: BigInt(plaintextLength),
        totalEnvelopeBytes: BigInt(envelopeBytes.byteLength),
        totalCanonicalBytes: 64n,
        totalMetadataBytes: 256n,
        candidateSelectionReadiness: 'metadata_complete_selection_not_authorized',
        ...input.setOverrides,
      });
      const observationId = randomUUID();
      const envelopeId = randomUUID();
      await prisma.$transaction(async (tx) => {
        await tx.osvListingObservationEvidenceSet.create({ data: setData });
        await tx.osvListingObservationEvidence.create({
          data: {
            id: observationId,
            evidenceSetId: setData.id,
            listingExecutionId: setData.listingExecutionId,
            providerContactAuthorizationId: setData.providerContactAuthorizationId,
            synchronizationRequestId: setData.synchronizationRequestId,
            synchronizationRunId: setData.synchronizationRunId,
            provider: 'osv',
            approvedPrefix: 'crates.io/',
            listingProtocolId: 'osv_gcs_json_objects_list_v1',
            sourceLicenseRegistryVersion: 'osv_source_license_registry_v1',
            runtimeVersionSetFingerprint: FINGERPRINT,
            evidenceSchemaVersion: 'osv_protected_listing_observation_evidence_v1',
            classificationPolicyId: 'osv_metadata_policy_v1',
            observationCanonicalAlgorithmId: 'osv_protected_listing_observation_canonical_v1',
            encryptionPolicyId: 'osv_protected_listing_evidence_encryption_policy_v1',
            associatedDataPolicyId: 'osv_protected_listing_evidence_associated_data_v1',
            associatedDataAlgorithmId:
              'osv_protected_listing_evidence_associated_data_canonical_v1',
            envelopeSchemaVersion: 'osv_protected_listing_evidence_ciphertext_envelope_v1',
            observationOrdinal: 1,
            listingObservationIdentity: DIGEST,
            providerGeneration: input.generation ?? '1',
            declaredListingByteCount: input.declaredListingByteCount ?? 128n,
            sourceFamilyClassification: input.sourceFamilyClassification ?? 'known:RUSTSEC',
            classificationStatus: input.classificationStatus ?? 'eligible',
            duplicateClassification: 'none',
            immutableConflictClassification: 'none',
            candidateSelectionEligibility: 'eligible_for_later_selection_evaluation',
            evidenceState: 'constructed',
            candidateSelectionAuthorized: false,
            bodyRetrievalAuthorized: false,
            batch4pPermitted: false,
            plaintextLengthAccounting: plaintextLength,
            rowRevision: 1n,
          },
        });
        await tx.osvListingObservationEvidenceEnvelope.create({
          data: {
            id: envelopeId,
            observationId,
            evidenceSetId: setData.id,
            providerGeneration: input.generation ?? '1',
            declaredListingByteCount: input.declaredListingByteCount ?? 128n,
            sourceFamilyClassification: input.sourceFamilyClassification ?? 'known:RUSTSEC',
            classificationStatus: input.classificationStatus ?? 'eligible',
            envelopeOrdinal: 1,
            envelopeSchemaVersion: 'osv_protected_listing_evidence_ciphertext_envelope_v1',
            cryptographicPolicyId: 'osv_protected_listing_evidence_encryption_policy_v1',
            algorithmId: 'aes-256-gcm',
            associatedDataPolicyId: 'osv_protected_listing_evidence_associated_data_v1',
            opaqueKeyAlias: KEY_ALIAS,
            keyVersionClassification: 'current',
            envelopeState: 'current',
            rotationState: 'current',
            erasureState: 'not_erased',
            plaintextLengthAccounting: plaintextLength,
            ciphertextLengthAccounting: plaintextLength,
            protectedIdentityEnvelope: envelopeBytes,
            rowRevision: 1n,
          },
        });
      });
      return {
        setId: setData.id,
        observationId,
        envelopeId,
        listingExecutionId: setData.listingExecutionId,
        generation: input.generation ?? '1',
        declaredListingByteCount: input.declaredListingByteCount ?? 128n,
        plaintextLength,
        sourceFamilyClassification: input.sourceFamilyClassification ?? 'known:RUSTSEC',
        classificationStatus: input.classificationStatus ?? 'eligible',
      };
    }

    async function insertRotationPending(input: {
      observationId: string;
      evidenceSetId: string;
      generation: string;
      declaredListingByteCount: bigint;
      plaintextLength: number;
      sourceFamilyClassification: string;
      classificationStatus: Prisma.OsvListingObservationEvidenceEnvelopeUncheckedCreateInput['classificationStatus'];
    }) {
      const envelopeBytes = syntheticEnvelopeBytes(input.plaintextLength);
      envelopeBytes.fill(0xa6, 12, 12 + input.plaintextLength);
      return prisma.osvListingObservationEvidenceEnvelope.create({
        data: {
          id: randomUUID(),
          observationId: input.observationId,
          evidenceSetId: input.evidenceSetId,
          providerGeneration: input.generation,
          declaredListingByteCount: input.declaredListingByteCount,
          sourceFamilyClassification: input.sourceFamilyClassification,
          classificationStatus: input.classificationStatus,
          envelopeOrdinal: 2,
          envelopeSchemaVersion: 'osv_protected_listing_evidence_ciphertext_envelope_v1',
          cryptographicPolicyId: 'osv_protected_listing_evidence_encryption_policy_v1',
          algorithmId: 'aes-256-gcm',
          associatedDataPolicyId: 'osv_protected_listing_evidence_associated_data_v1',
          opaqueKeyAlias: KEY_ALIAS,
          keyVersionClassification: 'current',
          envelopeState: 'rotation_pending',
          rotationState: 'current',
          erasureState: 'not_erased',
          plaintextLengthAccounting: input.plaintextLength,
          ciphertextLengthAccounting: input.plaintextLength,
          protectedIdentityEnvelope: envelopeBytes,
          rowRevision: 1n,
        },
      });
    }

    it('inserts an empty constructed evidence set without envelopes', async () => {
      const seeded = await seedIssuedProviderContact();
      const created = await prisma.osvListingObservationEvidenceSet.create({
        data: evidenceSetData(seeded.authorization),
      });
      expect(created.evidenceState).toBe('constructed');
      expect(created.protectedObservationCount).toBe(0);
      expect(created.rowRevision).toBe(1n);
      expect(created.candidateSelectionAuthorized).toBe(false);
      expect(created.bodyRetrievalAuthorized).toBe(false);
      expect(created.batch4pPermitted).toBe(false);
      expect(created.provider).toBe('osv');
    });

    it('inserts one synthetic protected observation with a bounded envelope', async () => {
      const seeded = await seedIssuedProviderContact();
      const persisted = await persistProtectedObservation({ authorization: seeded.authorization });
      const observation = await prisma.osvListingObservationEvidence.findUniqueOrThrow({
        where: { id: persisted.observationId },
      });
      expect(observation.providerGeneration).toBe('1');
      expect(observation.declaredListingByteCount).toBe(128n);
      expect(observation.sourceFamilyClassification).toBe('known:RUSTSEC');
      const envelope = await prisma.osvListingObservationEvidenceEnvelope.findUniqueOrThrow({
        where: { id: persisted.envelopeId },
      });
      expect(envelope.protectedIdentityEnvelope?.byteLength).toBe(36);
      expect(envelope.algorithmId).toBe('aes-256-gcm');
    });

    it('accepts generation above Number.MAX_SAFE_INTEGER as exact text', async () => {
      const seeded = await seedIssuedProviderContact();
      const persisted = await persistProtectedObservation({
        authorization: seeded.authorization,
        generation: '9007199254740993',
      });
      const observation = await prisma.osvListingObservationEvidence.findUniqueOrThrow({
        where: { id: persisted.observationId },
      });
      expect(observation.providerGeneration).toBe('9007199254740993');
    });

    it('accepts exactly 1000 synthetic observations in one transaction', async () => {
      const seeded = await seedIssuedProviderContact();
      const setData = evidenceSetData(seeded.authorization, {
        translatorObservationCount: 1000,
        acceptedObservationCount: 1000,
        protectedObservationCount: 1000,
        totalProtectedKeyPlaintextBytes: 8000n,
        totalEnvelopeBytes: 36000n,
        totalCanonicalBytes: 64000n,
        totalMetadataBytes: 256000n,
        candidateSelectionReadiness: 'metadata_complete_selection_not_authorized',
      });
      await prisma.$transaction(
        async (tx) => {
          await tx.osvListingObservationEvidenceSet.create({ data: setData });
          await tx.$executeRaw`
          INSERT INTO "osv_listing_observation_evidence" (
            "id", "evidence_set_id", "listing_execution_id", "provider_contact_authorization_id",
            "synchronization_request_id", "synchronization_run_id", "provider", "approved_prefix",
            "listing_protocol_id", "source_license_registry_version", "runtime_version_set_fingerprint",
            "evidence_schema_version", "classification_policy_id", "observation_canonical_algorithm_id",
            "encryption_policy_id", "associated_data_policy_id", "associated_data_algorithm_id",
            "envelope_schema_version", "observation_ordinal", "listing_observation_identity",
            "provider_generation", "declared_listing_byte_count", "source_family_classification",
            "classification_status", "duplicate_classification", "immutable_conflict_classification",
            "candidate_selection_eligibility", "evidence_state", "candidate_selection_authorized",
            "body_retrieval_authorized", "batch_4p_permitted", "plaintext_length_accounting", "row_revision"
          )
          SELECT
            gen_random_uuid(),
            ${setData.id}::uuid,
            ${setData.listingExecutionId}::uuid,
            ${setData.providerContactAuthorizationId}::uuid,
            ${setData.synchronizationRequestId}::uuid,
            ${setData.synchronizationRunId}::uuid,
            'osv',
            'crates.io/',
            'osv_gcs_json_objects_list_v1',
            'osv_source_license_registry_v1',
            ${FINGERPRINT},
            'osv_protected_listing_observation_evidence_v1',
            'osv_metadata_policy_v1',
            'osv_protected_listing_observation_canonical_v1',
            'osv_protected_listing_evidence_encryption_policy_v1',
            'osv_protected_listing_evidence_associated_data_v1',
            'osv_protected_listing_evidence_associated_data_canonical_v1',
            'osv_protected_listing_evidence_ciphertext_envelope_v1',
            ordinal,
            md5(ordinal::text) || md5((ordinal + 1000)::text),
            '1',
            128,
            'known:RUSTSEC',
            'eligible',
            'none',
            'none',
            'eligible_for_later_selection_evaluation',
            'constructed',
            FALSE,
            FALSE,
            FALSE,
            8,
            1
          FROM generate_series(1, 1000) AS ordinal
        `;
          await tx.$executeRaw`
          INSERT INTO "osv_listing_observation_evidence_envelope" (
            "id", "observation_id", "evidence_set_id", "provider_generation",
            "declared_listing_byte_count", "source_family_classification", "classification_status",
            "envelope_ordinal", "envelope_schema_version", "cryptographic_policy_id", "algorithm_id",
            "associated_data_policy_id", "opaque_key_alias", "key_version_classification",
            "envelope_state", "rotation_state", "erasure_state", "plaintext_length_accounting",
            "ciphertext_length_accounting", "protected_identity_envelope", "row_revision"
          )
          SELECT
            gen_random_uuid(),
            evidence.id,
            ${setData.id}::uuid,
            '1',
            128,
            'known:RUSTSEC',
            'eligible',
            1,
            'osv_protected_listing_evidence_ciphertext_envelope_v1',
            'osv_protected_listing_evidence_encryption_policy_v1',
            'aes-256-gcm',
            'osv_protected_listing_evidence_associated_data_v1',
            ${KEY_ALIAS},
            'current',
            'current',
            'current',
            'not_erased',
            8,
            8,
            decode(repeat('01', 12), 'hex') || decode(repeat('a5', 8), 'hex') || decode(repeat('02', 16), 'hex'),
            1
          FROM "osv_listing_observation_evidence" AS evidence
          WHERE evidence.evidence_set_id = ${setData.id}::uuid
        `;
        },
        { timeout: 120_000, maxWait: 15_000 },
      );
      const count = await prisma.osvListingObservationEvidence.count({
        where: { evidenceSetId: setData.id },
      });
      expect(count).toBe(1000);
    });

    it('rejects malformed, zero, leading-zero, and 21-digit generations', async () => {
      const seeded = await seedIssuedProviderContact();
      for (const generation of ['0', '01', '1'.repeat(21), '1.5', 'latest', '']) {
        await expect(
          persistProtectedObservation({ authorization: seeded.authorization, generation }),
        ).rejects.toThrow();
      }
    });

    it('rejects negative declared size and counts above 1000', async () => {
      const seeded = await seedIssuedProviderContact();
      await expect(
        persistProtectedObservation({
          authorization: seeded.authorization,
          declaredListingByteCount: -1n,
        }),
      ).rejects.toThrow();
      await expect(
        prisma.osvListingObservationEvidenceSet.create({
          data: evidenceSetData(seeded.authorization, { acceptedObservationCount: 1001 }),
        }),
      ).rejects.toThrow();
      await expect(
        prisma.osvListingObservationEvidenceSet.create({
          data: evidenceSetData(seeded.authorization, {
            translatorObservationCount: 0,
            acceptedObservationCount: 1,
          }),
        }),
      ).rejects.toThrow();
      await expect(
        prisma.osvListingObservationEvidenceSet.create({
          data: evidenceSetData(seeded.authorization, {
            translatorObservationCount: 1,
            acceptedObservationCount: 0,
            rejectedObservationCount: 2,
            candidateSelectionReadiness: 'empty_page_not_candidate_ready',
          }),
        }),
      ).rejects.toThrow();
    });

    it('rejects an all-zero nonce on envelope insert', async () => {
      const seeded = await seedIssuedProviderContact();
      const setData = evidenceSetData(seeded.authorization, {
        translatorObservationCount: 1,
        acceptedObservationCount: 1,
        protectedObservationCount: 1,
        totalProtectedKeyPlaintextBytes: 8n,
        totalEnvelopeBytes: 36n,
        candidateSelectionReadiness: 'metadata_complete_selection_not_authorized',
      });
      const observationId = randomUUID();
      const zeroNonceEnvelope = syntheticEnvelopeBytes(8);
      zeroNonceEnvelope.fill(0x00, 0, 12);
      await expect(
        prisma.$transaction(async (tx) => {
          await tx.osvListingObservationEvidenceSet.create({ data: setData });
          await tx.osvListingObservationEvidence.create({
            data: {
              id: observationId,
              evidenceSetId: setData.id,
              listingExecutionId: setData.listingExecutionId,
              providerContactAuthorizationId: setData.providerContactAuthorizationId,
              synchronizationRequestId: setData.synchronizationRequestId,
              synchronizationRunId: setData.synchronizationRunId,
              provider: 'osv',
              approvedPrefix: 'crates.io/',
              listingProtocolId: 'osv_gcs_json_objects_list_v1',
              sourceLicenseRegistryVersion: 'osv_source_license_registry_v1',
              runtimeVersionSetFingerprint: FINGERPRINT,
              evidenceSchemaVersion: 'osv_protected_listing_observation_evidence_v1',
              classificationPolicyId: 'osv_metadata_policy_v1',
              observationCanonicalAlgorithmId: 'osv_protected_listing_observation_canonical_v1',
              encryptionPolicyId: 'osv_protected_listing_evidence_encryption_policy_v1',
              associatedDataPolicyId: 'osv_protected_listing_evidence_associated_data_v1',
              associatedDataAlgorithmId:
                'osv_protected_listing_evidence_associated_data_canonical_v1',
              envelopeSchemaVersion: 'osv_protected_listing_evidence_ciphertext_envelope_v1',
              observationOrdinal: 1,
              listingObservationIdentity: DIGEST,
              providerGeneration: '1',
              declaredListingByteCount: 128n,
              sourceFamilyClassification: 'known:RUSTSEC',
              classificationStatus: 'eligible',
              duplicateClassification: 'none',
              immutableConflictClassification: 'none',
              candidateSelectionEligibility: 'eligible_for_later_selection_evaluation',
              evidenceState: 'constructed',
              candidateSelectionAuthorized: false,
              bodyRetrievalAuthorized: false,
              batch4pPermitted: false,
              plaintextLengthAccounting: 8,
              rowRevision: 1n,
            },
          });
          await tx.osvListingObservationEvidenceEnvelope.create({
            data: {
              id: randomUUID(),
              observationId,
              evidenceSetId: setData.id,
              providerGeneration: '1',
              declaredListingByteCount: 128n,
              sourceFamilyClassification: 'known:RUSTSEC',
              classificationStatus: 'eligible',
              envelopeOrdinal: 1,
              envelopeSchemaVersion: 'osv_protected_listing_evidence_ciphertext_envelope_v1',
              cryptographicPolicyId: 'osv_protected_listing_evidence_encryption_policy_v1',
              algorithmId: 'aes-256-gcm',
              associatedDataPolicyId: 'osv_protected_listing_evidence_associated_data_v1',
              opaqueKeyAlias: KEY_ALIAS,
              keyVersionClassification: 'current',
              envelopeState: 'current',
              rotationState: 'current',
              erasureState: 'not_erased',
              plaintextLengthAccounting: 8,
              ciphertextLengthAccounting: 8,
              protectedIdentityEnvelope: zeroNonceEnvelope,
              rowRevision: 1n,
            },
          });
        }),
      ).rejects.toThrow();
    });

    it('rejects unsupported envelope versions, algorithms, and all-zero nonces', async () => {
      const seeded = await seedIssuedProviderContact();
      await expect(
        prisma.osvListingObservationEvidenceSet.create({
          data: evidenceSetData(seeded.authorization, {
            envelopeSchemaVersion: 'osv_protected_listing_evidence_ciphertext_envelope_v2',
          }),
        }),
      ).rejects.toThrow();
      const persisted = await persistProtectedObservation({ authorization: seeded.authorization });
      await expect(
        prisma.$executeRaw`
          UPDATE "osv_listing_observation_evidence_envelope"
          SET "algorithm_id" = 'chacha20-poly1305', "row_revision" = 2
          WHERE "id" = ${persisted.envelopeId}::uuid
        `,
      ).rejects.toThrow();
      await expect(
        persistProtectedObservation({
          authorization: seeded.authorization,
          plaintextLength: 8,
          setOverrides: { canonicalEvidenceSetDigest: 'd'.repeat(64) },
        }).then(async (created) => {
          await prisma.$executeRaw`
            UPDATE "osv_listing_observation_evidence_envelope"
            SET "protected_identity_envelope" = decode('000000000000000000000000', 'hex') || substring("protected_identity_envelope" from 13),
                "row_revision" = "row_revision" + 1
            WHERE "id" = ${created.envelopeId}::uuid
          `;
        }),
      ).rejects.toThrow();
    });

    it('rejects evidence-set substitution of another version-set fingerprint', async () => {
      const seeded = await seedIssuedProviderContact();
      await expect(
        prisma.osvListingObservationEvidenceSet.create({
          data: evidenceSetData(seeded.authorization, {
            runtimeVersionSetFingerprint: 'b'.repeat(64),
          }),
        }),
      ).rejects.toThrow();
    });

    it('forbids DELETE, cascade delete, and immutable identity updates', async () => {
      const seeded = await seedIssuedProviderContact();
      const persisted = await persistProtectedObservation({ authorization: seeded.authorization });
      await expect(
        prisma.$executeRaw`
          DELETE FROM "osv_listing_observation_evidence" WHERE "id" = ${persisted.observationId}::uuid
        `,
      ).rejects.toThrow(/append-only|forbid|restrict/i);
      await expect(
        prisma.$executeRaw`
          DELETE FROM "osv_listing_provider_contact_authorization" WHERE "id" = ${seeded.authorization.id}::uuid
        `,
      ).rejects.toThrow();
      await expect(
        prisma.$executeRaw`
          UPDATE "osv_listing_observation_evidence_set"
          SET "listing_execution_id" = ${randomUUID()}::uuid, "row_revision" = 2
          WHERE "id" = ${persisted.setId}::uuid
        `,
      ).rejects.toThrow(/immutable/i);
    });

    it('rejects duplicate ordinals and canonical identities', async () => {
      const seeded = await seedIssuedProviderContact();
      const persisted = await persistProtectedObservation({ authorization: seeded.authorization });
      await expect(
        prisma.osvListingObservationEvidence.create({
          data: {
            id: randomUUID(),
            evidenceSetId: persisted.setId,
            listingExecutionId: persisted.listingExecutionId,
            providerContactAuthorizationId: seeded.authorization.id,
            synchronizationRequestId: seeded.authorization.synchronizationRequestId,
            synchronizationRunId: seeded.authorization.synchronizationRunId,
            provider: 'osv',
            approvedPrefix: 'crates.io/',
            listingProtocolId: 'osv_gcs_json_objects_list_v1',
            sourceLicenseRegistryVersion: 'osv_source_license_registry_v1',
            runtimeVersionSetFingerprint: FINGERPRINT,
            evidenceSchemaVersion: 'osv_protected_listing_observation_evidence_v1',
            classificationPolicyId: 'osv_metadata_policy_v1',
            observationCanonicalAlgorithmId: 'osv_protected_listing_observation_canonical_v1',
            encryptionPolicyId: 'osv_protected_listing_evidence_encryption_policy_v1',
            associatedDataPolicyId: 'osv_protected_listing_evidence_associated_data_v1',
            associatedDataAlgorithmId:
              'osv_protected_listing_evidence_associated_data_canonical_v1',
            envelopeSchemaVersion: 'osv_protected_listing_evidence_ciphertext_envelope_v1',
            observationOrdinal: 1,
            listingObservationIdentity: 'e'.repeat(64),
            providerGeneration: '2',
            declaredListingByteCount: 1n,
            sourceFamilyClassification: 'known:RUSTSEC',
            classificationStatus: 'eligible',
            duplicateClassification: 'none',
            immutableConflictClassification: 'none',
            candidateSelectionEligibility: 'eligible_for_later_selection_evaluation',
            evidenceState: 'constructed',
            candidateSelectionAuthorized: false,
            bodyRetrievalAuthorized: false,
            batch4pPermitted: false,
            plaintextLengthAccounting: 8,
            rowRevision: 1n,
          },
        }),
      ).rejects.toThrow();
    });

    it('rejects constructed-to-accepted, purged reopen, and purge under legal hold', async () => {
      const seeded = await seedIssuedProviderContact();
      const persisted = await persistProtectedObservation({ authorization: seeded.authorization });
      await expect(
        prisma.$executeRaw`
          UPDATE "osv_listing_observation_evidence_set"
          SET "evidence_state" = 'review_accepted',
              "candidate_selection_readiness" = 'metadata_complete_selection_not_authorized',
              "row_revision" = 2
          WHERE "id" = ${persisted.setId}::uuid
        `,
      ).rejects.toThrow();
      const illegalFromConstructed = [
        'incomplete',
        'overflow_rejected',
        'conflict_quarantine_required',
        'duplicate_ambiguous',
        'malformed_rejected',
        'review_accepted',
        'review_rejected',
        'failed',
        'purged',
      ] as const;
      for (const nextState of illegalFromConstructed) {
        await expect(
          prisma.$executeRaw`
            UPDATE "osv_listing_observation_evidence_set"
            SET "evidence_state" = ${nextState}::osv_listing_observation_evidence_set_state,
                "row_revision" = 2
            WHERE "id" = ${persisted.setId}::uuid
          `,
        ).rejects.toThrow();
      }
      await prisma.$executeRaw`
        UPDATE "osv_listing_observation_evidence_set"
        SET "legal_hold_active" = TRUE,
            "legal_hold_classification" = 'legal_hold_active',
            "row_revision" = 2
        WHERE "id" = ${persisted.setId}::uuid
      `;
      await expect(
        prisma.$executeRaw`
          UPDATE "osv_listing_observation_evidence_envelope"
          SET "envelope_state" = 'erased', "row_revision" = 2
          WHERE "id" = ${persisted.envelopeId}::uuid
        `,
      ).rejects.toThrow(/legal hold/i);
      await prisma.$executeRaw`
        UPDATE "osv_listing_observation_evidence_set"
        SET "evidence_state" = 'review_pending',
            "candidate_selection_readiness" = 'review_not_accepted',
            "row_revision" = 3
        WHERE "id" = ${persisted.setId}::uuid
      `;
      await prisma.$executeRaw`
        UPDATE "osv_listing_observation_evidence_set"
        SET "evidence_state" = 'review_accepted',
            "candidate_selection_readiness" = 'metadata_complete_selection_not_authorized',
            "row_revision" = 4
        WHERE "id" = ${persisted.setId}::uuid
      `;
      await expect(
        prisma.$executeRaw`
          UPDATE "osv_listing_observation_evidence_set"
          SET "evidence_state" = 'purged', "row_revision" = 5
          WHERE "id" = ${persisted.setId}::uuid
        `,
      ).rejects.toThrow(/legal hold|envelopes remain recoverable/i);
      const held = await prisma.osvListingObservationEvidenceEnvelope.findUniqueOrThrow({
        where: { id: persisted.envelopeId },
      });
      expect(held.protectedIdentityEnvelope?.byteLength).toBe(36);
      expect(held.envelopeState).toBe('current');
    });

    it('records append-only purge evidence after envelope redaction and set purge', async () => {
      const seeded = await seedIssuedProviderContact();
      const persisted = await persistProtectedObservation({ authorization: seeded.authorization });
      await prisma.$executeRaw`
        UPDATE "osv_listing_observation_evidence_envelope"
        SET "envelope_state" = 'erased', "row_revision" = 2
        WHERE "id" = ${persisted.envelopeId}::uuid
      `;
      await prisma.$executeRaw`
        UPDATE "osv_listing_observation_evidence_set"
        SET "evidence_state" = 'review_pending',
            "candidate_selection_readiness" = 'review_not_accepted',
            "row_revision" = 2
        WHERE "id" = ${persisted.setId}::uuid
      `;
      await prisma.$executeRaw`
        UPDATE "osv_listing_observation_evidence_set"
        SET "evidence_state" = 'review_accepted',
            "candidate_selection_readiness" = 'metadata_complete_selection_not_authorized',
            "row_revision" = 3
        WHERE "id" = ${persisted.setId}::uuid
      `;
      await prisma.$executeRaw`
        UPDATE "osv_listing_observation_evidence_set"
        SET "evidence_state" = 'purged', "row_revision" = 4
        WHERE "id" = ${persisted.setId}::uuid
      `;
      const purge = await prisma.osvListingObservationEvidencePurge.create({
        data: {
          id: randomUUID(),
          evidenceSetId: persisted.setId,
          purgeAuthorizationClassification:
            'distinct_instance_operator_cleanup_grant_not_listing_authorization',
          purgeReasonCode: 'independent_review_complete',
          legalHoldDecision: 'hold_absent_verified',
          dependentAuthorityTerminalDecision: 'terminal_verified',
          erasureMechanismClassification:
            'authorized_envelope_redaction_not_instance_key_destruction',
          erasureOutcome: 'envelopes_redacted_metadata_retained',
        },
      });
      expect(purge.completedAt).not.toBeNull();
      await expect(
        prisma.$executeRaw`
          DELETE FROM "osv_listing_observation_evidence_purge" WHERE "id" = ${purge.id}::uuid
        `,
      ).rejects.toThrow();
      await expect(
        prisma.$executeRaw`
          UPDATE "osv_listing_observation_evidence_set"
          SET "evidence_state" = 'constructed', "row_revision" = 5
          WHERE "id" = ${persisted.setId}::uuid
        `,
      ).rejects.toThrow(/purged|reopen/i);
    });

    it('omits plaintext identity columns and tenant or Finding relationships', async () => {
      const columns = await prisma.$queryRaw<Array<{ column_name: string }>>`
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name IN (
            'osv_listing_observation_evidence_set',
            'osv_listing_observation_evidence',
            'osv_listing_observation_evidence_envelope',
            'osv_listing_observation_evidence_purge'
          )
      `;
      const names = columns.map((column) => column.column_name);
      for (const forbidden of [
        'provider_object_key',
        'object_key',
        'plaintext_identity',
        'organization_id',
        'tenant_id',
        'user_id',
        'asset_id',
        'component_id',
        'finding_id',
        'page_token',
        'etag',
        'md5',
        'media_link',
      ]) {
        expect(names, forbidden).not.toContain(forbidden);
      }
      const sql = readFileSync(MIGRATION_SQL, 'utf8');
      expect(sql).not.toMatch(/storage\.googleapis\.com/i);
      expect(sql).not.toMatch(/osv\.dev/i);
      expect(sql).not.toContain('CREATE TABLE "finding"');
      expect(sql).toContain('substring("protected_identity_envelope" from 1 for 12)');
      expect(sql).toContain('octet_length("protected_identity_envelope") BETWEEN 29 AND 540');
    });

    it('requires a protected envelope in the same transaction as an observation', async () => {
      const seeded = await seedIssuedProviderContact();
      const setData = evidenceSetData(seeded.authorization, {
        translatorObservationCount: 1,
        acceptedObservationCount: 1,
        protectedObservationCount: 1,
        totalProtectedKeyPlaintextBytes: 8n,
        totalEnvelopeBytes: 36n,
        candidateSelectionReadiness: 'metadata_complete_selection_not_authorized',
      });
      await expect(
        prisma.$transaction(async (tx) => {
          await tx.osvListingObservationEvidenceSet.create({ data: setData });
          await tx.osvListingObservationEvidence.create({
            data: {
              id: randomUUID(),
              evidenceSetId: setData.id,
              listingExecutionId: setData.listingExecutionId,
              providerContactAuthorizationId: setData.providerContactAuthorizationId,
              synchronizationRequestId: setData.synchronizationRequestId,
              synchronizationRunId: setData.synchronizationRunId,
              provider: 'osv',
              approvedPrefix: 'crates.io/',
              listingProtocolId: 'osv_gcs_json_objects_list_v1',
              sourceLicenseRegistryVersion: 'osv_source_license_registry_v1',
              runtimeVersionSetFingerprint: FINGERPRINT,
              evidenceSchemaVersion: 'osv_protected_listing_observation_evidence_v1',
              classificationPolicyId: 'osv_metadata_policy_v1',
              observationCanonicalAlgorithmId: 'osv_protected_listing_observation_canonical_v1',
              encryptionPolicyId: 'osv_protected_listing_evidence_encryption_policy_v1',
              associatedDataPolicyId: 'osv_protected_listing_evidence_associated_data_v1',
              associatedDataAlgorithmId:
                'osv_protected_listing_evidence_associated_data_canonical_v1',
              envelopeSchemaVersion: 'osv_protected_listing_evidence_ciphertext_envelope_v1',
              observationOrdinal: 1,
              listingObservationIdentity: DIGEST,
              providerGeneration: '1',
              declaredListingByteCount: 1n,
              sourceFamilyClassification: 'known:RUSTSEC',
              classificationStatus: 'eligible',
              duplicateClassification: 'none',
              immutableConflictClassification: 'none',
              candidateSelectionEligibility: 'eligible_for_later_selection_evaluation',
              evidenceState: 'constructed',
              candidateSelectionAuthorized: false,
              bodyRetrievalAuthorized: false,
              batch4pPermitted: false,
              plaintextLengthAccounting: 8,
              rowRevision: 1n,
            },
          });
        }),
      ).rejects.toThrow(/envelope/i);
    });

    it('rejects successor-only failed evidence-set insert', async () => {
      const seeded = await seedIssuedProviderContact();
      await expect(
        prisma.osvListingObservationEvidenceSet.create({
          data: evidenceSetData(seeded.authorization, {
            evidenceState: 'failed',
            candidateSelectionReadiness: 'empty_page_not_candidate_ready',
          }),
        }),
      ).rejects.toThrow(/successor-only/i);
    });

    it('rejects unicode, signed, exponential, and padded generations', async () => {
      const seeded = await seedIssuedProviderContact();
      for (const generation of ['١', '+1', ' 1', '1 ', '1e2', '1\u0000', '-1']) {
        await expect(
          persistProtectedObservation({ authorization: seeded.authorization, generation }),
        ).rejects.toThrow();
      }
      const persisted = await persistProtectedObservation({
        authorization: seeded.authorization,
        generation: '9'.repeat(20),
      });
      const observation = await prisma.osvListingObservationEvidence.findUniqueOrThrow({
        where: { id: persisted.observationId },
      });
      expect(observation.providerGeneration).toBe('9'.repeat(20));
    });

    it('rejects envelope bytes above 540 and hostname-shaped key aliases', async () => {
      const seeded = await seedIssuedProviderContact();
      const exact = await persistProtectedObservation({
        authorization: seeded.authorization,
        plaintextLength: 512,
      });
      const exactEnvelope = await prisma.osvListingObservationEvidenceEnvelope.findUniqueOrThrow({
        where: { id: exact.envelopeId },
      });
      expect(exactEnvelope.protectedIdentityEnvelope?.byteLength).toBe(540);
      await expect(
        persistProtectedObservation({
          authorization: (await seedIssuedProviderContact()).authorization,
          plaintextLength: 513,
        }),
      ).rejects.toThrow();
      await expect(
        persistProtectedObservation({
          authorization: (await seedIssuedProviderContact()).authorization,
        }).then(async (created) => {
          await prisma.$executeRaw`
            UPDATE "osv_listing_observation_evidence_envelope"
            SET "opaque_key_alias" = 'osv.listing.evidence.kexample.com',
                "row_revision" = 2
            WHERE "id" = ${created.envelopeId}::uuid
          `;
        }),
      ).rejects.toThrow(/immutable|opaque_key_alias|check/i);
    });

    it('rejects stale, skipped, and zero row revisions', async () => {
      const seeded = await seedIssuedProviderContact();
      const persisted = await persistProtectedObservation({ authorization: seeded.authorization });
      await expect(
        prisma.$executeRaw`
          UPDATE "osv_listing_observation_evidence_set"
          SET "legal_hold_active" = TRUE,
              "legal_hold_classification" = 'legal_hold_active',
              "row_revision" = 1
          WHERE "id" = ${persisted.setId}::uuid
        `,
      ).rejects.toThrow(/row revision/i);
      await expect(
        prisma.$executeRaw`
          UPDATE "osv_listing_observation_evidence_set"
          SET "legal_hold_active" = TRUE,
              "legal_hold_classification" = 'legal_hold_active',
              "row_revision" = 3
          WHERE "id" = ${persisted.setId}::uuid
        `,
      ).rejects.toThrow(/row revision/i);
      await expect(
        prisma.$executeRaw`
          UPDATE "osv_listing_observation_evidence_envelope"
          SET "envelope_state" = 'current', "row_revision" = 0
          WHERE "id" = ${persisted.envelopeId}::uuid
        `,
      ).rejects.toThrow();
    });

    it('keeps exactly one current envelope unless the observation is fully erased', async () => {
      const seeded = await seedIssuedProviderContact();
      const persisted = await persistProtectedObservation({ authorization: seeded.authorization });
      await expect(
        prisma.$executeRaw`
          UPDATE "osv_listing_observation_evidence_envelope"
          SET "envelope_state" = 'retired',
              "rotation_state" = 'rotated',
              "key_version_classification" = 'historical',
              "row_revision" = 2
          WHERE "id" = ${persisted.envelopeId}::uuid
        `,
      ).rejects.toThrow(/exactly one current envelope/i);
      const pending = await insertRotationPending({
        observationId: persisted.observationId,
        evidenceSetId: persisted.setId,
        generation: persisted.generation,
        declaredListingByteCount: persisted.declaredListingByteCount,
        plaintextLength: persisted.plaintextLength,
        sourceFamilyClassification: persisted.sourceFamilyClassification,
        classificationStatus: persisted.classificationStatus,
      });
      await expect(
        prisma.$executeRaw`
          UPDATE "osv_listing_observation_evidence_envelope"
          SET "envelope_state" = 'current', "row_revision" = 2
          WHERE "id" = ${pending.id}::uuid
        `,
      ).rejects.toThrow();
      await prisma.$transaction(async (tx) => {
        await tx.$executeRaw`
          UPDATE "osv_listing_observation_evidence_envelope"
          SET "envelope_state" = 'decrypt_only',
              "rotation_state" = 'rotated',
              "key_version_classification" = 'historical',
              "row_revision" = 2
          WHERE "id" = ${persisted.envelopeId}::uuid
        `;
        await tx.$executeRaw`
          UPDATE "osv_listing_observation_evidence_envelope"
          SET "envelope_state" = 'current',
              "rotation_state" = 'current',
              "key_version_classification" = 'current',
              "row_revision" = 2
          WHERE "id" = ${pending.id}::uuid
        `;
      });
      const afterSwap = await prisma.osvListingObservationEvidenceEnvelope.findMany({
        where: { observationId: persisted.observationId },
        orderBy: { envelopeOrdinal: 'asc' },
      });
      expect(afterSwap).toHaveLength(2);
      expect(afterSwap[0]?.envelopeState).toBe('decrypt_only');
      expect(afterSwap[0]?.protectedIdentityEnvelope?.byteLength).toBe(36);
      expect(afterSwap[1]?.envelopeState).toBe('current');
      expect(afterSwap[1]?.protectedIdentityEnvelope?.byteLength).toBe(36);
    });

    it('isolates envelope erasure to one evidence set', async () => {
      const first = await persistProtectedObservation({
        authorization: (await seedIssuedProviderContact()).authorization,
      });
      const second = await persistProtectedObservation({
        authorization: (await seedIssuedProviderContact()).authorization,
      });
      await prisma.$executeRaw`
        UPDATE "osv_listing_observation_evidence_envelope"
        SET "envelope_state" = 'erased', "row_revision" = 2
        WHERE "id" = ${first.envelopeId}::uuid
      `;
      const erased = await prisma.osvListingObservationEvidenceEnvelope.findUniqueOrThrow({
        where: { id: first.envelopeId },
      });
      const retained = await prisma.osvListingObservationEvidenceEnvelope.findUniqueOrThrow({
        where: { id: second.envelopeId },
      });
      expect(erased.protectedIdentityEnvelope).toBeNull();
      expect(erased.envelopeState).toBe('erased');
      expect(retained.envelopeState).toBe('current');
      expect(retained.protectedIdentityEnvelope?.byteLength).toBe(36);
    });

    it('rejects envelope reparenting and ciphertext replacement', async () => {
      const first = await persistProtectedObservation({
        authorization: (await seedIssuedProviderContact()).authorization,
      });
      const second = await persistProtectedObservation({
        authorization: (await seedIssuedProviderContact()).authorization,
      });
      await expect(
        prisma.$executeRaw`
          UPDATE "osv_listing_observation_evidence_envelope"
          SET "observation_id" = ${second.observationId}::uuid, "row_revision" = 2
          WHERE "id" = ${first.envelopeId}::uuid
        `,
      ).rejects.toThrow(/immutable/i);
      await expect(
        prisma.$executeRaw`
          UPDATE "osv_listing_observation_evidence_envelope"
          SET "evidence_set_id" = ${second.setId}::uuid, "row_revision" = 2
          WHERE "id" = ${first.envelopeId}::uuid
        `,
      ).rejects.toThrow(/immutable/i);
      await expect(
        prisma.$executeRaw`
          UPDATE "osv_listing_observation_evidence"
          SET "evidence_set_id" = ${second.setId}::uuid, "row_revision" = 2
          WHERE "id" = ${first.observationId}::uuid
        `,
      ).rejects.toThrow(/append-only|forbid|restrict/i);
      await expect(
        prisma.$executeRaw`
          UPDATE "osv_listing_observation_evidence_envelope"
          SET "protected_identity_envelope" = decode(repeat('ab', 36), 'hex'),
              "row_revision" = 2
          WHERE "id" = ${first.envelopeId}::uuid
        `,
      ).rejects.toThrow(/cannot be replaced/i);
    });

    it('rejects purge before review and does not treat overdue as purge authority', async () => {
      const seeded = await seedIssuedProviderContact();
      const persisted = await persistProtectedObservation({ authorization: seeded.authorization });
      await prisma.$executeRaw`
        UPDATE "osv_listing_observation_evidence_envelope"
        SET "envelope_state" = 'erased', "row_revision" = 2
        WHERE "id" = ${persisted.envelopeId}::uuid
      `;
      await prisma.$executeRaw`
        UPDATE "osv_listing_observation_evidence_set"
        SET "evidence_state" = 'review_pending',
            "candidate_selection_readiness" = 'review_not_accepted',
            "row_revision" = 2
        WHERE "id" = ${persisted.setId}::uuid
      `;
      await expect(
        prisma.$executeRaw`
          UPDATE "osv_listing_observation_evidence_set"
          SET "evidence_state" = 'purged', "row_revision" = 3
          WHERE "id" = ${persisted.setId}::uuid
        `,
      ).rejects.toThrow(/review transition/i);
      await prisma.$executeRaw`
        UPDATE "osv_listing_observation_evidence_set"
        SET "evidence_state" = 'review_accepted',
            "candidate_selection_readiness" = 'metadata_complete_selection_not_authorized',
            "row_revision" = 3
        WHERE "id" = ${persisted.setId}::uuid
      `;
      await prisma.$executeRaw`
        UPDATE "osv_listing_observation_evidence_set"
        SET "retention_overdue_classification" = 'retention_overdue_review_required_no_automatic_delete',
            "row_revision" = 4
        WHERE "id" = ${persisted.setId}::uuid
      `;
      const overdue = await prisma.osvListingObservationEvidenceSet.findUniqueOrThrow({
        where: { id: persisted.setId },
      });
      expect(overdue.evidenceState).toBe('review_accepted');
      expect(overdue.retentionOverdueClassification).toBe(
        'retention_overdue_review_required_no_automatic_delete',
      );
      await expect(
        prisma.osvListingObservationEvidencePurge.create({
          data: {
            id: randomUUID(),
            evidenceSetId: persisted.setId,
            purgeAuthorizationClassification:
              'distinct_instance_operator_cleanup_grant_not_listing_authorization',
            purgeReasonCode: 'independent_review_complete',
            legalHoldDecision: 'hold_absent_verified',
            dependentAuthorityTerminalDecision: 'terminal_verified',
            erasureMechanismClassification:
              'authorized_envelope_redaction_not_instance_key_destruction',
            erasureOutcome: 'envelopes_redacted_metadata_retained',
          },
        }),
      ).rejects.toThrow(/purged set state/i);
    });

    it('rejects concurrent duplicate evidence-set identity and duplicate ordinals', async () => {
      const seeded = await seedIssuedProviderContact();
      const first = evidenceSetData(seeded.authorization);
      const second = evidenceSetData(seeded.authorization, {
        id: randomUUID(),
        listingExecutionId: randomUUID(),
      });
      const results = await Promise.allSettled([
        prisma.osvListingObservationEvidenceSet.create({ data: first }),
        prisma.osvListingObservationEvidenceSet.create({ data: second }),
      ]);
      const fulfilled = results.filter((result) => result.status === 'fulfilled');
      const rejected = results.filter((result) => result.status === 'rejected');
      expect(fulfilled).toHaveLength(1);
      expect(rejected).toHaveLength(1);
    });

    it('reconstructs associated-data context from immutable columns and has no JSON fallback', async () => {
      const rows = await prisma.$queryRaw<Array<{ column_name: string; udt_name: string }>>`
        SELECT column_name, udt_name
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name IN (
            'osv_listing_observation_evidence_set',
            'osv_listing_observation_evidence',
            'osv_listing_observation_evidence_envelope',
            'osv_listing_observation_evidence_purge'
          )
      `;
      const names = rows.map((row) => row.column_name);
      expect(rows.every((row) => row.udt_name !== 'json' && row.udt_name !== 'jsonb')).toBe(true);
      for (const required of [
        'encryption_policy_id',
        'envelope_schema_version',
        'evidence_schema_version',
        'associated_data_policy_id',
        'listing_execution_id',
        'provider_contact_authorization_id',
        'synchronization_request_id',
        'synchronization_run_id',
        'provider',
        'approved_prefix',
        'provider_generation',
        'listing_protocol_id',
        'source_license_registry_version',
        'runtime_version_set_fingerprint',
        'declared_listing_byte_count',
        'source_family_classification',
        'classification_status',
      ]) {
        expect(names, required).toContain(required);
      }
      const first = await persistProtectedObservation({
        authorization: (await seedIssuedProviderContact()).authorization,
        generation: '2',
      });
      const second = await persistProtectedObservation({
        authorization: (await seedIssuedProviderContact()).authorization,
        generation: '3',
      });
      const left = await prisma.osvListingObservationEvidence.findUniqueOrThrow({
        where: { id: first.observationId },
      });
      const right = await prisma.osvListingObservationEvidence.findUniqueOrThrow({
        where: { id: second.observationId },
      });
      expect(left.providerGeneration).not.toBe(right.providerGeneration);
      expect(left.evidenceSetId).not.toBe(right.evidenceSetId);
      expect(left.listingExecutionId).not.toBe(right.listingExecutionId);
    });

    it('enumerates evidence-set lifecycle pairs and rejects illegal reopen', async () => {
      const setStates = [
        'constructed',
        'incomplete',
        'overflow_rejected',
        'conflict_quarantine_required',
        'duplicate_ambiguous',
        'malformed_rejected',
        'review_pending',
        'review_accepted',
        'review_rejected',
        'failed',
        'purged',
      ] as const;
      const allowed = (
        from: (typeof setStates)[number],
        to: (typeof setStates)[number],
      ): boolean => {
        if (from === to) {
          return true;
        }
        if (from === 'constructed') {
          return to === 'review_pending';
        }
        if (from === 'review_pending') {
          return to === 'review_accepted' || to === 'review_rejected';
        }
        if (from === 'review_accepted' || from === 'review_rejected' || from === 'failed') {
          return to === 'purged';
        }
        if (
          from === 'incomplete' ||
          from === 'overflow_rejected' ||
          from === 'conflict_quarantine_required' ||
          from === 'duplicate_ambiguous' ||
          from === 'malformed_rejected'
        ) {
          return to === 'failed' || to === 'purged';
        }
        return false;
      };

      async function seedFrom(
        state: (typeof setStates)[number],
      ): Promise<{ setId: string; envelopeId?: string }> {
        const seeded = await seedIssuedProviderContact();
        if (state === 'review_accepted' || state === 'review_rejected') {
          const persisted = await persistProtectedObservation({
            authorization: seeded.authorization,
          });
          await prisma.$executeRaw`
            UPDATE "osv_listing_observation_evidence_set"
            SET "evidence_state" = 'review_pending',
                "candidate_selection_readiness" = 'review_not_accepted',
                "row_revision" = 2
            WHERE "id" = ${persisted.setId}::uuid
          `;
          if (state === 'review_accepted') {
            await prisma.$executeRaw`
              UPDATE "osv_listing_observation_evidence_set"
              SET "evidence_state" = 'review_accepted',
                  "candidate_selection_readiness" = 'metadata_complete_selection_not_authorized',
                  "row_revision" = 3
              WHERE "id" = ${persisted.setId}::uuid
            `;
          } else {
            await prisma.$executeRaw`
              UPDATE "osv_listing_observation_evidence_set"
              SET "evidence_state" = 'review_rejected',
                  "candidate_selection_readiness" = 'review_not_accepted',
                  "row_revision" = 3
              WHERE "id" = ${persisted.setId}::uuid
            `;
          }
          return { setId: persisted.setId, envelopeId: persisted.envelopeId };
        }
        if (state === 'failed' || state === 'purged') {
          const created = await prisma.osvListingObservationEvidenceSet.create({
            data: evidenceSetData(seeded.authorization, {
              evidenceState: 'incomplete',
              candidateSelectionReadiness: 'ineligible_incomplete',
            }),
          });
          await prisma.$executeRaw`
            UPDATE "osv_listing_observation_evidence_set"
            SET "evidence_state" = ${state}::osv_listing_observation_evidence_set_state,
                "row_revision" = 2
            WHERE "id" = ${created.id}::uuid
          `;
          return { setId: created.id };
        }
        const overrides: Partial<Prisma.OsvListingObservationEvidenceSetUncheckedCreateInput> = {
          evidenceState: state,
        };
        if (state === 'incomplete') {
          overrides.candidateSelectionReadiness = 'ineligible_incomplete';
        }
        if (state === 'overflow_rejected') {
          overrides.candidateSelectionReadiness = 'ineligible_overflow';
        }
        if (state === 'conflict_quarantine_required') {
          overrides.acceptedObservationCount = 1;
          overrides.translatorObservationCount = 1;
          overrides.immutableConflictCount = 1;
          overrides.candidateSelectionReadiness = 'ineligible_conflict';
        }
        if (state === 'duplicate_ambiguous') {
          overrides.acceptedObservationCount = 1;
          overrides.translatorObservationCount = 1;
          overrides.duplicateAmbiguityCount = 1;
          overrides.candidateSelectionReadiness = 'ineligible_duplicate_ambiguity';
        }
        if (state === 'malformed_rejected') {
          overrides.candidateSelectionReadiness = 'ineligible_binding_mismatch';
        }
        if (state === 'review_pending') {
          overrides.acceptedObservationCount = 1;
          overrides.translatorObservationCount = 1;
          overrides.candidateSelectionReadiness = 'review_not_accepted';
        }
        const created = await prisma.osvListingObservationEvidenceSet.create({
          data: evidenceSetData(seeded.authorization, overrides),
        });
        return { setId: created.id };
      }

      function targetReadiness(
        from: (typeof setStates)[number],
        to: (typeof setStates)[number],
      ): string | undefined {
        if (from === to) {
          return undefined;
        }
        if (to === 'review_pending' || to === 'review_rejected') {
          return 'review_not_accepted';
        }
        if (to === 'review_accepted') {
          return 'metadata_complete_selection_not_authorized';
        }
        return undefined;
      }

      for (const from of setStates) {
        for (const to of setStates) {
          const seeded = await seedFrom(from);
          if (to === 'purged' && allowed(from, to) && seeded.envelopeId !== undefined) {
            await prisma.$executeRaw`
              UPDATE "osv_listing_observation_evidence_envelope"
              SET "envelope_state" = 'erased', "row_revision" = 2
              WHERE "id" = ${seeded.envelopeId}::uuid
            `;
          }
          const current = await prisma.osvListingObservationEvidenceSet.findUniqueOrThrow({
            where: { id: seeded.setId },
          });
          const readiness = targetReadiness(from, to) ?? null;
          const update = prisma.$executeRaw`
            UPDATE "osv_listing_observation_evidence_set"
            SET "evidence_state" = ${to}::osv_listing_observation_evidence_set_state,
                "candidate_selection_readiness" = COALESCE(
                  ${readiness}::osv_listing_observation_set_candidate_readiness,
                  "candidate_selection_readiness"
                ),
                "row_revision" = ${current.rowRevision + 1n}
            WHERE "id" = ${seeded.setId}::uuid
          `;
          if (allowed(from, to)) {
            await expect(update).resolves.toBe(1);
          } else {
            await expect(update).rejects.toThrow();
          }
        }
      }
    });
  },
);
