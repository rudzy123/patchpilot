/**
 * Session 13 Batch 3B-P listing-only provider-contact authorization schema
 * constraints. Direct SQL against disposable PostgreSQL. No issuance or
 * consumption adapters, no provider contact, DNS, TLS, HTTP, lease, timer,
 * body retrieval, parser, activation, matching, or Finding writes.
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
const OTHER_FINGERPRINT = 'b'.repeat(64);
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

describe(
  'session 13 Batch 3B-P / 3B-P-R OSV listing provider-contact authorization SQL constraints',
  { timeout: 180_000 },
  () => {
    let databaseName: string;
    let databaseUrl: string;
    let admin: PrismaClient;
    let prisma: PrismaClient;

    beforeAll(async () => {
      const ephemeral = await createEphemeralDatabase('it');
      databaseName = ephemeral.databaseName;
      databaseUrl = ephemeral.databaseUrl;
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

    async function seedConsumedListing(window = liveWindow()): Promise<{
      operatorId: string;
      source: Prisma.OsvCanaryAuthorizationGetPayload<object>;
      requestId: string;
      runId: string;
      window: ReturnType<typeof liveWindow>;
    }> {
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
      return {
        operatorId: createdOperator.id,
        source: await prisma.osvCanaryAuthorization.findUniqueOrThrow({ where: { id: source.id } }),
        requestId: request.id,
        runId: run.id,
        window,
      };
    }

    async function seedIssuedProviderContact(window = liveWindow()) {
      const listing = await seedConsumedListing(window);
      const preflight = await prisma.osvCanaryProviderFreePreflightAttestation.create({
        data: preflightAttestation({
          operatorId: listing.operatorId,
          sourceId: listing.source.id,
          requestId: listing.requestId,
          runId: listing.runId,
          capturedAt: window.acknowledgedAt,
        }),
      });
      const authorization = await prisma.osvListingProviderContactAuthorization.create({
        data: providerContactAuthorization({
          operatorId: listing.operatorId,
          sourceId: listing.source.id,
          requestId: listing.requestId,
          runId: listing.runId,
          preflightId: preflight.id,
          sourceLegalDecisionId: listing.source.legalDecisionId,
          activePointerBaselineIdentity: preflight.activePointerBaselineIdentity,
          zeroFindingBaselineIdentity: preflight.zeroFindingBaselineIdentity,
          window,
        }),
      });
      return { ...listing, preflight, authorization };
    }

    it('inserts one distinct listing-only provider-contact authorization against consumed source authority', async () => {
      const seeded = await seedIssuedProviderContact();
      expect(seeded.authorization.state).toBe('issued');
      expect(seeded.authorization.phase).toBe('listing_only');
      expect(seeded.authorization.sourceCanaryAuthorizationId).toBe(seeded.source.id);
      expect(seeded.authorization.consumedAt).toBeNull();
      expect(seeded.source.state).toBe('consumed');
      expect(seeded.source.consumedAt).not.toBeNull();
      expect(seeded.preflight.providerContactAuthorized).toBe(false);
    });

    it('rejects bounded_body, combined, and unknown provider-contact phases', async () => {
      const seeded = await seedIssuedProviderContact();
      for (const phase of ['bounded_body', 'combined', 'activation', 'matching']) {
        await expect(
          prisma.osvListingProviderContactAuthorization.create({
            data: providerContactAuthorization(
              {
                operatorId: seeded.operatorId,
                sourceId: seeded.source.id,
                requestId: seeded.requestId,
                runId: seeded.runId,
                preflightId: seeded.preflight.id,
                sourceLegalDecisionId: seeded.source.legalDecisionId,
                activePointerBaselineIdentity: seeded.preflight.activePointerBaselineIdentity,
                zeroFindingBaselineIdentity: seeded.preflight.zeroFindingBaselineIdentity,
                window: seeded.window,
              },
              { id: randomUUID(), phase },
            ),
          }),
        ).rejects.toThrow();
      }
    });

    it('rejects wrong provider, bucket, path, prefix, budget, and fingerprint', async () => {
      const listing = await seedConsumedListing();
      const preflight = await prisma.osvCanaryProviderFreePreflightAttestation.create({
        data: preflightAttestation({
          operatorId: listing.operatorId,
          sourceId: listing.source.id,
          requestId: listing.requestId,
          runId: listing.runId,
          capturedAt: listing.window.acknowledgedAt,
        }),
      });
      const base = () =>
        providerContactAuthorization({
          operatorId: listing.operatorId,
          sourceId: listing.source.id,
          requestId: listing.requestId,
          runId: listing.runId,
          preflightId: preflight.id,
          sourceLegalDecisionId: listing.source.legalDecisionId,
          activePointerBaselineIdentity: preflight.activePointerBaselineIdentity,
          zeroFindingBaselineIdentity: preflight.zeroFindingBaselineIdentity,
          window: listing.window,
        });
      await expect(
        prisma.osvListingProviderContactAuthorization.create({
          data: base(),
        }),
      ).resolves.toMatchObject({ state: 'issued' });
      const listing2 = await seedConsumedListing();
      const preflight2 = await prisma.osvCanaryProviderFreePreflightAttestation.create({
        data: preflightAttestation({
          operatorId: listing2.operatorId,
          sourceId: listing2.source.id,
          requestId: listing2.requestId,
          runId: listing2.runId,
          capturedAt: listing2.window.acknowledgedAt,
        }),
      });
      const attempts: Array<
        Partial<Prisma.OsvListingProviderContactAuthorizationUncheckedCreateInput>
      > = [
        { providerIdentity: 'github_advisory_database' },
        { bucketIdentity: 'other-bucket' },
        { listingApiPathPolicy: '/storage/v1/b/other/o' },
        { approvedPrefix: 'npm/' },
        { listingBudgetProfile: 'osv_canary_bounded_body_budget_v1' },
        { runtimeVersionSetFingerprint: OTHER_FINGERPRINT },
        { providerBodyAuthorization: 'permitted' },
        { parserAuthorization: 'permitted' },
        { providerRetryAuthorization: 'permitted' },
        { catalogActivationAuthorization: 'permitted' },
        { matchingAuthorization: 'permitted' },
        { findingAuthorization: 'permitted' },
        { requiredReviewRole: 'review_optional' },
        { automaticProgression: true },
        { issuingOperatorMayReview: true },
        { legalBodyRetrievalPermission: 'approved' },
      ];
      for (const override of attempts) {
        await expect(
          prisma.osvListingProviderContactAuthorization.create({
            data: providerContactAuthorization(
              {
                operatorId: listing2.operatorId,
                sourceId: listing2.source.id,
                requestId: listing2.requestId,
                runId: listing2.runId,
                preflightId: preflight2.id,
                sourceLegalDecisionId: listing2.source.legalDecisionId,
                activePointerBaselineIdentity: preflight2.activePointerBaselineIdentity,
                zeroFindingBaselineIdentity: preflight2.zeroFindingBaselineIdentity,
                window: listing2.window,
              },
              override,
            ),
          }),
        ).rejects.toThrow();
      }
    });

    it('rejects missing source, unconsumed source, and mismatched request or run', async () => {
      const window = liveWindow();
      const createdOperator = await prisma.osvCanaryInstanceOperatorIdentity.create({
        data: operator({ establishedAt: window.issuedAt, createdAt: window.issuedAt }),
      });
      const request = await prisma.osvRuntimeSynchronizationRequest.create({
        data: canaryRequest({ requestedAt: window.issuedAt, createdAt: window.issuedAt }),
      });
      const run = await prisma.osvRuntimeSynchronizationRun.create({
        data: canaryRun(request, { createdAt: window.issuedAt, updatedAt: window.issuedAt }),
      });
      const issued = await prisma.osvCanaryAuthorization.create({
        data: listingAuthorization(createdOperator.id, window),
      });
      await expect(
        prisma.osvCanaryProviderFreePreflightAttestation.create({
          data: preflightAttestation({
            operatorId: createdOperator.id,
            sourceId: issued.id,
            requestId: request.id,
            runId: run.id,
            capturedAt: window.acknowledgedAt,
          }),
        }),
      ).rejects.toThrow();

      const missingId = randomUUID();
      await expect(
        prisma.osvCanaryProviderFreePreflightAttestation.create({
          data: preflightAttestation({
            operatorId: createdOperator.id,
            sourceId: missingId,
            requestId: request.id,
            runId: run.id,
            capturedAt: window.acknowledgedAt,
          }),
        }),
      ).rejects.toThrow();

      expect(await consumeCanary(issued.id, request.id, run.id)).toBe(1);
      const otherRequest = await prisma.osvRuntimeSynchronizationRequest.create({
        data: canaryRequest({ requestedAt: window.issuedAt, createdAt: window.issuedAt }),
      });
      const otherRun = await prisma.osvRuntimeSynchronizationRun.create({
        data: canaryRun(otherRequest, { createdAt: window.issuedAt, updatedAt: window.issuedAt }),
      });
      await expect(
        prisma.osvCanaryProviderFreePreflightAttestation.create({
          data: preflightAttestation({
            operatorId: createdOperator.id,
            sourceId: issued.id,
            requestId: otherRequest.id,
            runId: otherRun.id,
            capturedAt: window.acknowledgedAt,
          }),
        }),
      ).rejects.toThrow();
    });

    it('rejects issued rows with consumed fields and consumed rows without execution binding', async () => {
      const seeded = await seedIssuedProviderContact();
      await expect(
        prisma.$executeRaw`
          UPDATE "osv_listing_provider_contact_authorization"
          SET "consumed_at" = CURRENT_TIMESTAMP
          WHERE "id" = ${seeded.authorization.id}::uuid
        `,
      ).rejects.toThrow();
      await expect(
        prisma.$executeRaw`
          UPDATE "osv_listing_provider_contact_authorization"
          SET "state" = 'consumed_for_listing_execution',
              "consumed_at" = CURRENT_TIMESTAMP
          WHERE "id" = ${seeded.authorization.id}::uuid
            AND "state" = 'issued'
        `,
      ).rejects.toThrow();
    });

    it('consumes once against the exact issuance request and run', async () => {
      const seeded = await seedIssuedProviderContact();
      const updated = await prisma.$executeRaw`
        UPDATE "osv_listing_provider_contact_authorization"
        SET "state" = 'consumed_for_listing_execution',
            "consumed_at" = CURRENT_TIMESTAMP,
            "consumed_by_synchronization_request_id" = ${seeded.requestId}::uuid,
            "consumed_by_synchronization_run_id" = ${seeded.runId}::uuid
        WHERE "id" = ${seeded.authorization.id}::uuid
          AND "state" = 'issued'
          AND CURRENT_TIMESTAMP < "expires_at"
      `;
      expect(updated).toBe(1);
      const consumed = await prisma.osvListingProviderContactAuthorization.findUniqueOrThrow({
        where: { id: seeded.authorization.id },
      });
      expect(consumed.state).toBe('consumed_for_listing_execution');
      expect(consumed.consumedBySynchronizationRunId).toBe(seeded.runId);
      const source = await prisma.osvCanaryAuthorization.findUniqueOrThrow({
        where: { id: seeded.source.id },
      });
      expect(source.state).toBe('consumed');
      expect(source.consumedAt?.toISOString()).toBe(seeded.source.consumedAt?.toISOString());
    });

    it('rejects different-run consumption and distinguishes same-run replay', async () => {
      const seeded = await seedIssuedProviderContact();
      const other = await seedConsumedListing();
      await expect(
        prisma.$executeRaw`
          UPDATE "osv_listing_provider_contact_authorization"
          SET "state" = 'consumed_for_listing_execution',
              "consumed_at" = CURRENT_TIMESTAMP,
              "consumed_by_synchronization_request_id" = ${other.requestId}::uuid,
              "consumed_by_synchronization_run_id" = ${other.runId}::uuid
          WHERE "id" = ${seeded.authorization.id}::uuid
            AND "state" = 'issued'
            AND CURRENT_TIMESTAMP < "expires_at"
        `,
      ).rejects.toThrow();
      expect(
        await prisma.$executeRaw`
          UPDATE "osv_listing_provider_contact_authorization"
          SET "state" = 'consumed_for_listing_execution',
              "consumed_at" = CURRENT_TIMESTAMP,
              "consumed_by_synchronization_request_id" = ${seeded.requestId}::uuid,
              "consumed_by_synchronization_run_id" = ${seeded.runId}::uuid
          WHERE "id" = ${seeded.authorization.id}::uuid
            AND "state" = 'issued'
            AND CURRENT_TIMESTAMP < "expires_at"
        `,
      ).toBe(1);
      const replay = await prisma.$executeRaw`
        UPDATE "osv_listing_provider_contact_authorization"
        SET "state" = 'consumed_for_listing_execution',
            "consumed_at" = CURRENT_TIMESTAMP,
            "consumed_by_synchronization_request_id" = ${seeded.requestId}::uuid,
            "consumed_by_synchronization_run_id" = ${seeded.runId}::uuid
        WHERE "id" = ${seeded.authorization.id}::uuid
          AND "state" = 'issued'
          AND CURRENT_TIMESTAMP < "expires_at"
      `;
      expect(replay).toBe(0);
      const sameRun = await prisma.osvListingProviderContactAuthorization.findUniqueOrThrow({
        where: { id: seeded.authorization.id },
      });
      expect(sameRun.state).toBe('consumed_for_listing_execution');
      await expect(
        prisma.$executeRaw`
          UPDATE "osv_listing_provider_contact_authorization"
          SET "consumed_at" = CURRENT_TIMESTAMP + INTERVAL '1 second'
          WHERE "id" = ${seeded.authorization.id}::uuid
            AND "state" = 'consumed_for_listing_execution'
        `,
      ).rejects.toThrow();
    });

    it('forbids mutation back to issued, completed without terminal time, and failed without reason', async () => {
      const seeded = await seedIssuedProviderContact();
      expect(
        await prisma.$executeRaw`
          UPDATE "osv_listing_provider_contact_authorization"
          SET "state" = 'consumed_for_listing_execution',
              "consumed_at" = CURRENT_TIMESTAMP,
              "consumed_by_synchronization_request_id" = ${seeded.requestId}::uuid,
              "consumed_by_synchronization_run_id" = ${seeded.runId}::uuid
          WHERE "id" = ${seeded.authorization.id}::uuid
            AND "state" = 'issued'
            AND CURRENT_TIMESTAMP < "expires_at"
        `,
      ).toBe(1);
      await expect(
        prisma.$executeRaw`
          UPDATE "osv_listing_provider_contact_authorization"
          SET "state" = 'issued',
              "consumed_at" = NULL,
              "consumed_by_synchronization_request_id" = NULL,
              "consumed_by_synchronization_run_id" = NULL
          WHERE "id" = ${seeded.authorization.id}::uuid
        `,
      ).rejects.toThrow();
      await expect(
        prisma.$executeRaw`
          UPDATE "osv_listing_provider_contact_authorization"
          SET "state" = 'completed',
              "terminal_disposition" = 'completed'
          WHERE "id" = ${seeded.authorization.id}::uuid
        `,
      ).rejects.toThrow();
      await expect(
        prisma.$executeRaw`
          UPDATE "osv_listing_provider_contact_authorization"
          SET "state" = 'failed',
              "terminal_at" = CURRENT_TIMESTAMP,
              "terminal_disposition" = 'failed'
          WHERE "id" = ${seeded.authorization.id}::uuid
        `,
      ).rejects.toThrow();
      expect(
        await prisma.$executeRaw`
          UPDATE "osv_listing_provider_contact_authorization"
          SET "state" = 'failed',
              "terminal_at" = CURRENT_TIMESTAMP,
              "terminal_disposition" = 'failed',
              "terminal_reason_code" = 'timeout'
          WHERE "id" = ${seeded.authorization.id}::uuid
            AND "state" = 'consumed_for_listing_execution'
        `,
      ).toBe(1);
      await expect(
        prisma.$executeRaw`
          UPDATE "osv_listing_provider_contact_authorization"
          SET "state" = 'issued'
          WHERE "id" = ${seeded.authorization.id}::uuid
        `,
      ).rejects.toThrow();
    });

    it('requires revocation evidence and rejects optional review or missing retention', async () => {
      const seeded = await seedIssuedProviderContact();
      await expect(
        prisma.$executeRaw`
          UPDATE "osv_listing_provider_contact_authorization"
          SET "state" = 'revoked',
              "terminal_at" = CURRENT_TIMESTAMP,
              "terminal_disposition" = 'revoked'
          WHERE "id" = ${seeded.authorization.id}::uuid
            AND "state" = 'issued'
        `,
      ).rejects.toThrow();
      expect(
        await prisma.$executeRaw`
          UPDATE "osv_listing_provider_contact_authorization"
          SET "state" = 'revoked',
              "terminal_at" = CURRENT_TIMESTAMP,
              "terminal_disposition" = 'revoked',
              "revoked_at" = CURRENT_TIMESTAMP,
              "revoked_by_operator_identity_id" = ${seeded.operatorId}::uuid
          WHERE "id" = ${seeded.authorization.id}::uuid
            AND "state" = 'issued'
            AND CURRENT_TIMESTAMP < "expires_at"
        `,
      ).toBe(1);
    });

    it('lets exactly one concurrent consumer win and rejects a second source authorization', async () => {
      const seeded = await seedIssuedProviderContact();
      const clientA = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
      const clientB = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
      try {
        const results = await Promise.allSettled([
          clientA.$executeRaw`
            UPDATE "osv_listing_provider_contact_authorization"
            SET "state" = 'consumed_for_listing_execution',
                "consumed_at" = CURRENT_TIMESTAMP,
                "consumed_by_synchronization_request_id" = ${seeded.requestId}::uuid,
                "consumed_by_synchronization_run_id" = ${seeded.runId}::uuid
            WHERE "id" = ${seeded.authorization.id}::uuid
              AND "state" = 'issued'
              AND CURRENT_TIMESTAMP < "expires_at"
          `,
          clientB.$executeRaw`
            UPDATE "osv_listing_provider_contact_authorization"
            SET "state" = 'consumed_for_listing_execution',
                "consumed_at" = CURRENT_TIMESTAMP,
                "consumed_by_synchronization_request_id" = ${seeded.requestId}::uuid,
                "consumed_by_synchronization_run_id" = ${seeded.runId}::uuid
            WHERE "id" = ${seeded.authorization.id}::uuid
              AND "state" = 'issued'
              AND CURRENT_TIMESTAMP < "expires_at"
          `,
        ]);
        const updates = results.map((result) => (result.status === 'fulfilled' ? result.value : 0));
        expect(updates.filter((value) => value === 1)).toHaveLength(1);
        expect(updates.filter((value) => value === 0)).toHaveLength(1);
      } finally {
        await clientA.$disconnect();
        await clientB.$disconnect();
      }
      await expect(
        prisma.osvListingProviderContactAuthorization.create({
          data: providerContactAuthorization({
            operatorId: seeded.operatorId,
            sourceId: seeded.source.id,
            requestId: seeded.requestId,
            runId: seeded.runId,
            preflightId: seeded.preflight.id,
            sourceLegalDecisionId: seeded.source.legalDecisionId,
            activePointerBaselineIdentity: seeded.preflight.activePointerBaselineIdentity,
            zeroFindingBaselineIdentity: seeded.preflight.zeroFindingBaselineIdentity,
            window: seeded.window,
          }),
        }),
      ).rejects.toThrow();
    });

    it('lets consumption and revocation race to one winner', async () => {
      const seeded = await seedIssuedProviderContact();
      const clientA = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
      const clientB = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
      try {
        const results = await Promise.allSettled([
          clientA.$executeRaw`
            UPDATE "osv_listing_provider_contact_authorization"
            SET "state" = 'consumed_for_listing_execution',
                "consumed_at" = CURRENT_TIMESTAMP,
                "consumed_by_synchronization_request_id" = ${seeded.requestId}::uuid,
                "consumed_by_synchronization_run_id" = ${seeded.runId}::uuid
            WHERE "id" = ${seeded.authorization.id}::uuid
              AND "state" = 'issued'
              AND CURRENT_TIMESTAMP < "expires_at"
          `,
          clientB.$executeRaw`
            UPDATE "osv_listing_provider_contact_authorization"
            SET "state" = 'revoked',
                "terminal_at" = CURRENT_TIMESTAMP,
                "terminal_disposition" = 'revoked',
                "revoked_at" = CURRENT_TIMESTAMP,
                "revoked_by_operator_identity_id" = ${seeded.operatorId}::uuid
            WHERE "id" = ${seeded.authorization.id}::uuid
              AND "state" = 'issued'
              AND CURRENT_TIMESTAMP < "expires_at"
          `,
        ]);
        const updates = results.map((result) => (result.status === 'fulfilled' ? result.value : 0));
        expect(updates.filter((value) => value === 1)).toHaveLength(1);
        expect(updates.filter((value) => value === 0)).toHaveLength(1);
      } finally {
        await clientA.$disconnect();
        await clientB.$disconnect();
      }
      const winner = await prisma.osvListingProviderContactAuthorization.findUniqueOrThrow({
        where: { id: seeded.authorization.id },
      });
      expect(['consumed_for_listing_execution', 'revoked']).toContain(winner.state);
    });

    it('lets cancellation and completion race after consumption', async () => {
      const seeded = await seedIssuedProviderContact();
      expect(
        await prisma.$executeRaw`
          UPDATE "osv_listing_provider_contact_authorization"
          SET "state" = 'consumed_for_listing_execution',
              "consumed_at" = CURRENT_TIMESTAMP,
              "consumed_by_synchronization_request_id" = ${seeded.requestId}::uuid,
              "consumed_by_synchronization_run_id" = ${seeded.runId}::uuid
          WHERE "id" = ${seeded.authorization.id}::uuid
            AND "state" = 'issued'
            AND CURRENT_TIMESTAMP < "expires_at"
        `,
      ).toBe(1);
      const clientA = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
      const clientB = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
      try {
        const results = await Promise.allSettled([
          clientA.$executeRaw`
            UPDATE "osv_listing_provider_contact_authorization"
            SET "state" = 'completed',
                "terminal_at" = CURRENT_TIMESTAMP,
                "terminal_disposition" = 'completed'
            WHERE "id" = ${seeded.authorization.id}::uuid
              AND "state" = 'consumed_for_listing_execution'
          `,
          clientB.$executeRaw`
            UPDATE "osv_listing_provider_contact_authorization"
            SET "state" = 'cancelled',
                "terminal_at" = CURRENT_TIMESTAMP,
                "terminal_disposition" = 'cancelled'
            WHERE "id" = ${seeded.authorization.id}::uuid
              AND "state" = 'consumed_for_listing_execution'
          `,
        ]);
        const updates = results.map((result) => (result.status === 'fulfilled' ? result.value : 0));
        expect(updates.filter((value) => value === 1)).toHaveLength(1);
        expect(updates.filter((value) => value === 0)).toHaveLength(1);
      } finally {
        await clientA.$disconnect();
        await clientB.$disconnect();
      }
    });

    it('forbids deletion of provider-contact, preflight, source, request, run, and operator rows', async () => {
      const seeded = await seedIssuedProviderContact();
      await expect(
        prisma.osvListingProviderContactAuthorization.delete({
          where: { id: seeded.authorization.id },
        }),
      ).rejects.toThrow();
      await expect(
        prisma.osvCanaryProviderFreePreflightAttestation.delete({
          where: { id: seeded.preflight.id },
        }),
      ).rejects.toThrow();
      await expect(
        prisma.osvCanaryAuthorization.delete({ where: { id: seeded.source.id } }),
      ).rejects.toThrow();
      await expect(
        prisma.osvRuntimeSynchronizationRun.delete({ where: { id: seeded.runId } }),
      ).rejects.toThrow();
      await expect(
        prisma.osvRuntimeSynchronizationRequest.delete({ where: { id: seeded.requestId } }),
      ).rejects.toThrow();
      await expect(
        prisma.osvCanaryInstanceOperatorIdentity.delete({ where: { id: seeded.operatorId } }),
      ).rejects.toThrow();
      expect(
        await prisma.osvListingProviderContactAuthorization.count({
          where: { id: seeded.authorization.id },
        }),
      ).toBe(1);
    });

    it('lets exactly one of two identical identity inserts succeed', async () => {
      const listing = await seedConsumedListing();
      const preflight = await prisma.osvCanaryProviderFreePreflightAttestation.create({
        data: preflightAttestation({
          operatorId: listing.operatorId,
          sourceId: listing.source.id,
          requestId: listing.requestId,
          runId: listing.runId,
          capturedAt: listing.window.acknowledgedAt,
        }),
      });
      const sharedId = randomUUID();
      const payload = providerContactAuthorization(
        {
          operatorId: listing.operatorId,
          sourceId: listing.source.id,
          requestId: listing.requestId,
          runId: listing.runId,
          preflightId: preflight.id,
          sourceLegalDecisionId: listing.source.legalDecisionId,
          activePointerBaselineIdentity: preflight.activePointerBaselineIdentity,
          zeroFindingBaselineIdentity: preflight.zeroFindingBaselineIdentity,
          window: listing.window,
        },
        { id: sharedId },
      );
      const clientA = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
      const clientB = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
      try {
        const results = await Promise.allSettled([
          clientA.osvListingProviderContactAuthorization.create({ data: payload }),
          clientB.osvListingProviderContactAuthorization.create({ data: { ...payload } }),
        ]);
        expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
        expect(results.filter((result) => result.status === 'rejected')).toHaveLength(1);
      } finally {
        await clientA.$disconnect();
        await clientB.$disconnect();
      }
    });

    it('rejects conflicting issuance against the same source authorization', async () => {
      const seeded = await seedIssuedProviderContact();
      await expect(
        prisma.osvListingProviderContactAuthorization.create({
          data: providerContactAuthorization({
            operatorId: seeded.operatorId,
            sourceId: seeded.source.id,
            requestId: seeded.requestId,
            runId: seeded.runId,
            preflightId: seeded.preflight.id,
            sourceLegalDecisionId: seeded.source.legalDecisionId,
            activePointerBaselineIdentity: seeded.preflight.activePointerBaselineIdentity,
            zeroFindingBaselineIdentity: seeded.preflight.zeroFindingBaselineIdentity,
            window: seeded.window,
          }),
        }),
      ).rejects.toThrow();
    });

    it('rejects consumption after unused TTL expiry and expires issued rows with database time', async () => {
      const listing = await seedConsumedListing();
      const expiredWindow = liveWindow(3_601_000);
      const preflight = await prisma.osvCanaryProviderFreePreflightAttestation.create({
        data: preflightAttestation({
          operatorId: listing.operatorId,
          sourceId: listing.source.id,
          requestId: listing.requestId,
          runId: listing.runId,
          capturedAt: expiredWindow.acknowledgedAt,
        }),
      });
      const authorization = await prisma.osvListingProviderContactAuthorization.create({
        data: providerContactAuthorization({
          operatorId: listing.operatorId,
          sourceId: listing.source.id,
          requestId: listing.requestId,
          runId: listing.runId,
          preflightId: preflight.id,
          sourceLegalDecisionId: listing.source.legalDecisionId,
          activePointerBaselineIdentity: preflight.activePointerBaselineIdentity,
          zeroFindingBaselineIdentity: preflight.zeroFindingBaselineIdentity,
          window: expiredWindow,
        }),
      });
      const consume = await prisma.$executeRaw`
        UPDATE "osv_listing_provider_contact_authorization"
        SET "state" = 'consumed_for_listing_execution',
            "consumed_at" = CURRENT_TIMESTAMP,
            "consumed_by_synchronization_request_id" = ${listing.requestId}::uuid,
            "consumed_by_synchronization_run_id" = ${listing.runId}::uuid
        WHERE "id" = ${authorization.id}::uuid
          AND "state" = 'issued'
          AND CURRENT_TIMESTAMP < "expires_at"
      `;
      expect(consume).toBe(0);
      expect(
        await prisma.$executeRaw`
          UPDATE "osv_listing_provider_contact_authorization"
          SET "state" = 'expired',
              "terminal_at" = CURRENT_TIMESTAMP,
              "terminal_disposition" = 'expired'
          WHERE "id" = ${authorization.id}::uuid
            AND "state" = 'issued'
            AND CURRENT_TIMESTAMP >= "expires_at"
        `,
      ).toBe(1);
    });

    it('has no tenant, Finding, credential, token, body, or JSON columns', async () => {
      const columns = await prisma.$queryRaw<Array<{ column_name: string; data_type: string }>>`
        SELECT column_name, data_type
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name IN (
            'osv_listing_provider_contact_authorization',
            'osv_canary_provider_free_preflight_attestation'
          )
      `;
      const names = columns.map((column) => column.column_name);
      for (const forbidden of [
        'organization_id',
        'tenant_id',
        'tenant_user_id',
        'asset_id',
        'component_id',
        'finding_id',
        'password',
        'api_key',
        'bearer_token',
        'page_token',
        'token_digest',
        'holder_token',
        'holder_digest',
        'provider_object_key',
        'legal_prose',
        'hostname',
        'ip_address',
        'proxy',
        'certificate',
      ]) {
        expect(names, forbidden).not.toContain(forbidden);
      }
      expect(
        columns.some((column) => column.data_type === 'json' || column.data_type === 'jsonb'),
      ).toBe(false);
      const sql = readFileSync(
        path.join(
          srcDir,
          '../prisma/migrations/20260909120000_osv_listing_provider_contact_authorization_persistence/migration.sql',
        ),
        'utf8',
      );
      expect(sql).not.toMatch(/storage\.googleapis\.com/i);
      expect(sql).not.toMatch(/osv\.dev/i);
      expect(sql).not.toContain('CREATE TABLE "finding"');
    });

    it('rejects consumption of a not-yet-valid authorization using database time', async () => {
      const listing = await seedConsumedListing();
      const preflight = await prisma.osvCanaryProviderFreePreflightAttestation.create({
        data: preflightAttestation({
          operatorId: listing.operatorId,
          sourceId: listing.source.id,
          requestId: listing.requestId,
          runId: listing.runId,
          capturedAt: listing.window.acknowledgedAt,
        }),
      });
      const clock = await prisma.$queryRaw<Array<{ issued: Date; expires: Date }>>`
        SELECT
          (CURRENT_TIMESTAMP + INTERVAL '3600 seconds') AS issued,
          (CURRENT_TIMESTAMP + INTERVAL '7200 seconds') AS expires
      `;
      const issuedAt = clock[0]?.issued;
      const expiresAt = clock[0]?.expires;
      if (!(issuedAt instanceof Date) || !(expiresAt instanceof Date)) {
        throw new Error('database clock unavailable');
      }
      await prisma.$executeRaw`
        ALTER TABLE "osv_listing_provider_contact_authorization"
        DISABLE TRIGGER osv_listing_provider_contact_insert_issued
      `;
      try {
        const authorization = await prisma.osvListingProviderContactAuthorization.create({
          data: providerContactAuthorization({
            operatorId: listing.operatorId,
            sourceId: listing.source.id,
            requestId: listing.requestId,
            runId: listing.runId,
            preflightId: preflight.id,
            sourceLegalDecisionId: listing.source.legalDecisionId,
            activePointerBaselineIdentity: preflight.activePointerBaselineIdentity,
            zeroFindingBaselineIdentity: preflight.zeroFindingBaselineIdentity,
            window: {
              issuedAt,
              expiresAt,
              createdAt: issuedAt,
              acknowledgedAt: new Date(issuedAt.getTime() - 1_000),
            },
          }),
        });
        await expect(
          prisma.$executeRaw`
            UPDATE "osv_listing_provider_contact_authorization"
            SET "state" = 'consumed_for_listing_execution',
                "consumed_at" = CURRENT_TIMESTAMP,
                "consumed_by_synchronization_request_id" = ${listing.requestId}::uuid,
                "consumed_by_synchronization_run_id" = ${listing.runId}::uuid
            WHERE "id" = ${authorization.id}::uuid
              AND "state" = 'issued'
              AND CURRENT_TIMESTAMP < "expires_at"
          `,
        ).rejects.toThrow(/not yet valid|restrict_violation/);
        const stillIssued = await prisma.osvListingProviderContactAuthorization.findUniqueOrThrow({
          where: { id: authorization.id },
        });
        expect(stillIssued.state).toBe('issued');
        expect(stillIssued.consumedAt).toBeNull();
      } finally {
        await prisma.$executeRaw`
          ALTER TABLE "osv_listing_provider_contact_authorization"
          ENABLE TRIGGER osv_listing_provider_contact_insert_issued
        `;
      }
    });

    it('rejects future issued_at so unused TTL cannot be extended past database now', async () => {
      const listing = await seedConsumedListing();
      const preflight = await prisma.osvCanaryProviderFreePreflightAttestation.create({
        data: preflightAttestation({
          operatorId: listing.operatorId,
          sourceId: listing.source.id,
          requestId: listing.requestId,
          runId: listing.runId,
          capturedAt: listing.window.acknowledgedAt,
        }),
      });
      const issuedAt = new Date(Date.now() + 86_400_000);
      await expect(
        prisma.osvListingProviderContactAuthorization.create({
          data: providerContactAuthorization({
            operatorId: listing.operatorId,
            sourceId: listing.source.id,
            requestId: listing.requestId,
            runId: listing.runId,
            preflightId: preflight.id,
            sourceLegalDecisionId: listing.source.legalDecisionId,
            activePointerBaselineIdentity: preflight.activePointerBaselineIdentity,
            zeroFindingBaselineIdentity: preflight.zeroFindingBaselineIdentity,
            window: {
              issuedAt,
              expiresAt: new Date(issuedAt.getTime() + 3_600_000),
              createdAt: issuedAt,
              acknowledgedAt: listing.window.acknowledgedAt,
            },
          }),
        }),
      ).rejects.toThrow(/issued_at|restrict_violation/);
    });

    it('rejects unknown schema version, UUID v1, case-folded prefix, and mutation-shaped fields', async () => {
      const listing = await seedConsumedListing();
      const preflight = await prisma.osvCanaryProviderFreePreflightAttestation.create({
        data: preflightAttestation({
          operatorId: listing.operatorId,
          sourceId: listing.source.id,
          requestId: listing.requestId,
          runId: listing.runId,
          capturedAt: listing.window.acknowledgedAt,
        }),
      });
      const base = () =>
        providerContactAuthorization({
          operatorId: listing.operatorId,
          sourceId: listing.source.id,
          requestId: listing.requestId,
          runId: listing.runId,
          preflightId: preflight.id,
          sourceLegalDecisionId: listing.source.legalDecisionId,
          activePointerBaselineIdentity: preflight.activePointerBaselineIdentity,
          zeroFindingBaselineIdentity: preflight.zeroFindingBaselineIdentity,
          window: listing.window,
        });
      await expect(
        prisma.osvListingProviderContactAuthorization.create({
          data: {
            ...base(),
            authorizationSchemaVersion: 'osv_listing_only_provider_contact_authorization_v2',
          },
        }),
      ).rejects.toThrow();
      await expect(
        prisma.$executeRaw`
          INSERT INTO "osv_listing_provider_contact_authorization" (
            "id"
          ) VALUES ('11111111-1111-1111-8111-111111111111'::uuid)
        `,
      ).rejects.toThrow();
      for (const override of [
        { approvedPrefix: 'CRATES.IO/' },
        { approvedPrefix: ' crates.io/' },
        { approvedPrefix: 'crates.io/\u200b' },
        { providerIdentity: 'Rustsec_Advisory_Database' },
        { listingProtocol: 'osv_gcs_object_compose_v1' },
        { queryGrammarPolicy: 'caller_supplied' },
        { legalListingMetadataPermission: 'write' },
        { unusedTtlSeconds: 7200 },
      ] as Array<Partial<Prisma.OsvListingProviderContactAuthorizationUncheckedCreateInput>>) {
        await expect(
          prisma.osvListingProviderContactAuthorization.create({
            data: { ...base(), id: randomUUID(), ...override },
          }),
        ).rejects.toThrow();
      }
    });

    it('rejects consumption after operator revocation and after legal revalidation expiry', async () => {
      const seeded = await seedIssuedProviderContact();
      expect(
        await prisma.$executeRaw`
          UPDATE "osv_canary_instance_operator_identity"
          SET "status" = 'revoked',
              "revoked_at" = CURRENT_TIMESTAMP
          WHERE "id" = ${seeded.operatorId}::uuid
            AND "status" = 'active'
        `,
      ).toBe(1);
      await expect(
        prisma.$executeRaw`
          UPDATE "osv_listing_provider_contact_authorization"
          SET "state" = 'consumed_for_listing_execution',
              "consumed_at" = CURRENT_TIMESTAMP,
              "consumed_by_synchronization_request_id" = ${seeded.requestId}::uuid,
              "consumed_by_synchronization_run_id" = ${seeded.runId}::uuid
          WHERE "id" = ${seeded.authorization.id}::uuid
            AND "state" = 'issued'
            AND CURRENT_TIMESTAMP < "expires_at"
        `,
      ).rejects.toThrow(/operator|restrict_violation/);
      expect(seeded.authorization.state).toBe('issued');
      expect(seeded.authorization.consumedAt).toBeNull();

      const listing = await seedConsumedListing();
      const preflight = await prisma.osvCanaryProviderFreePreflightAttestation.create({
        data: preflightAttestation({
          operatorId: listing.operatorId,
          sourceId: listing.source.id,
          requestId: listing.requestId,
          runId: listing.runId,
          capturedAt: listing.window.acknowledgedAt,
        }),
      });
      const expiredLegal = await prisma.osvListingProviderContactAuthorization.create({
        data: providerContactAuthorization(
          {
            operatorId: listing.operatorId,
            sourceId: listing.source.id,
            requestId: listing.requestId,
            runId: listing.runId,
            preflightId: preflight.id,
            sourceLegalDecisionId: listing.source.legalDecisionId,
            activePointerBaselineIdentity: preflight.activePointerBaselineIdentity,
            zeroFindingBaselineIdentity: preflight.zeroFindingBaselineIdentity,
            window: listing.window,
          },
          { legalRevalidationBoundaryAt: listing.window.issuedAt },
        ),
      });
      await expect(
        prisma.$executeRaw`
          UPDATE "osv_listing_provider_contact_authorization"
          SET "state" = 'consumed_for_listing_execution',
              "consumed_at" = CURRENT_TIMESTAMP,
              "consumed_by_synchronization_request_id" = ${listing.requestId}::uuid,
              "consumed_by_synchronization_run_id" = ${listing.runId}::uuid
          WHERE "id" = ${expiredLegal.id}::uuid
            AND "state" = 'issued'
            AND CURRENT_TIMESTAMP < "expires_at"
        `,
      ).rejects.toThrow(/legal|restrict_violation/);
    });

    it('blocks parent canary terminalization while a child grant is outstanding and still denies consume if the lineage trigger is bypassed', async () => {
      const seeded = await seedIssuedProviderContact();
      await expect(
        prisma.$executeRaw`
          UPDATE "osv_canary_authorization"
          SET "state" = 'completed',
              "terminal_at" = CURRENT_TIMESTAMP,
              "terminal_disposition" = 'completed'
          WHERE "id" = ${seeded.source.id}::uuid
            AND "state" = 'consumed'
        `,
      ).rejects.toThrow(/outstanding|restrict_violation/);
      expect(
        await prisma.$executeRaw`
          UPDATE "osv_listing_provider_contact_authorization"
          SET "state" = 'cancelled',
              "terminal_at" = CURRENT_TIMESTAMP,
              "terminal_disposition" = 'cancelled'
          WHERE "id" = ${seeded.authorization.id}::uuid
            AND "state" = 'issued'
        `,
      ).toBe(1);
      expect(
        await prisma.$executeRaw`
          UPDATE "osv_canary_authorization"
          SET "state" = 'completed',
              "terminal_at" = CURRENT_TIMESTAMP,
              "terminal_disposition" = 'completed'
          WHERE "id" = ${seeded.source.id}::uuid
            AND "state" = 'consumed'
        `,
      ).toBe(1);

      const outstanding = await seedIssuedProviderContact();
      await prisma.$executeRaw`
        ALTER TABLE "osv_canary_authorization"
        DISABLE TRIGGER osv_canary_authorization_provider_contact_lineage
      `;
      try {
        expect(
          await prisma.$executeRaw`
            UPDATE "osv_canary_authorization"
            SET "state" = 'completed',
                "terminal_at" = CURRENT_TIMESTAMP,
                "terminal_disposition" = 'completed'
            WHERE "id" = ${outstanding.source.id}::uuid
              AND "state" = 'consumed'
          `,
        ).toBe(1);
        await expect(
          prisma.$executeRaw`
            UPDATE "osv_listing_provider_contact_authorization"
            SET "state" = 'consumed_for_listing_execution',
                "consumed_at" = CURRENT_TIMESTAMP,
                "consumed_by_synchronization_request_id" = ${outstanding.requestId}::uuid,
                "consumed_by_synchronization_run_id" = ${outstanding.runId}::uuid
            WHERE "id" = ${outstanding.authorization.id}::uuid
              AND "state" = 'issued'
              AND CURRENT_TIMESTAMP < "expires_at"
          `,
        ).rejects.toThrow(/consumed|restrict_violation/);
        const stillIssued = await prisma.osvListingProviderContactAuthorization.findUniqueOrThrow({
          where: { id: outstanding.authorization.id },
        });
        expect(stillIssued.state).toBe('issued');
        expect(stillIssued.consumedAt).toBeNull();
      } finally {
        await prisma.$executeRaw`
          ALTER TABLE "osv_canary_authorization"
          ENABLE TRIGGER osv_canary_authorization_provider_contact_lineage
        `;
      }
    });

    it('rejects consumption exactly at expiration using database time', async () => {
      const listing = await seedConsumedListing();
      const clock = await prisma.$queryRaw<Array<{ issued: Date; expires: Date }>>`
        SELECT
          (CURRENT_TIMESTAMP - INTERVAL '3600 seconds') AS issued,
          CURRENT_TIMESTAMP AS expires
      `;
      const issuedAt = clock[0]?.issued;
      const expiresAt = clock[0]?.expires;
      if (!(issuedAt instanceof Date) || !(expiresAt instanceof Date)) {
        throw new Error('database clock unavailable');
      }
      const preflight = await prisma.osvCanaryProviderFreePreflightAttestation.create({
        data: preflightAttestation({
          operatorId: listing.operatorId,
          sourceId: listing.source.id,
          requestId: listing.requestId,
          runId: listing.runId,
          capturedAt: new Date(issuedAt.getTime() - 1_000),
        }),
      });
      const authorization = await prisma.osvListingProviderContactAuthorization.create({
        data: providerContactAuthorization({
          operatorId: listing.operatorId,
          sourceId: listing.source.id,
          requestId: listing.requestId,
          runId: listing.runId,
          preflightId: preflight.id,
          sourceLegalDecisionId: listing.source.legalDecisionId,
          activePointerBaselineIdentity: preflight.activePointerBaselineIdentity,
          zeroFindingBaselineIdentity: preflight.zeroFindingBaselineIdentity,
          window: {
            issuedAt,
            expiresAt,
            createdAt: issuedAt,
            acknowledgedAt: new Date(issuedAt.getTime() - 1_000),
          },
        }),
      });
      const consume = await prisma.$executeRaw`
        UPDATE "osv_listing_provider_contact_authorization"
        SET "state" = 'consumed_for_listing_execution',
            "consumed_at" = CURRENT_TIMESTAMP,
            "consumed_by_synchronization_request_id" = ${listing.requestId}::uuid,
            "consumed_by_synchronization_run_id" = ${listing.runId}::uuid
        WHERE "id" = ${authorization.id}::uuid
          AND "state" = 'issued'
          AND CURRENT_TIMESTAMP < "expires_at"
      `;
      expect(consume).toBe(0);
      const reloaded = await prisma.osvListingProviderContactAuthorization.findUniqueOrThrow({
        where: { id: authorization.id },
      });
      expect(reloaded.state).toBe('issued');
      expect(reloaded.consumedAt).toBeNull();
    });

    it('rejects preflight and provider-contact insert after operator revocation', async () => {
      const listing = await seedConsumedListing();
      expect(
        await prisma.$executeRaw`
          UPDATE "osv_canary_instance_operator_identity"
          SET "status" = 'revoked',
              "revoked_at" = CURRENT_TIMESTAMP
          WHERE "id" = ${listing.operatorId}::uuid
            AND "status" = 'active'
        `,
      ).toBe(1);
      await expect(
        prisma.osvCanaryProviderFreePreflightAttestation.create({
          data: preflightAttestation({
            operatorId: listing.operatorId,
            sourceId: listing.source.id,
            requestId: listing.requestId,
            runId: listing.runId,
            capturedAt: listing.window.acknowledgedAt,
          }),
        }),
      ).rejects.toThrow(/operator|restrict_violation/);
    });

    it('rejects future preflight timestamps and issued_at before preflight capture', async () => {
      const listing = await seedConsumedListing();
      const future = new Date(Date.now() + 86_400_000);
      await expect(
        prisma.osvCanaryProviderFreePreflightAttestation.create({
          data: preflightAttestation(
            {
              operatorId: listing.operatorId,
              sourceId: listing.source.id,
              requestId: listing.requestId,
              runId: listing.runId,
              capturedAt: future,
            },
            { createdAt: future },
          ),
        }),
      ).rejects.toThrow(/captured_at|created_at|restrict_violation/);

      const lateCapture = new Date(listing.window.issuedAt.getTime() + 2_000);
      const preflight = await prisma.osvCanaryProviderFreePreflightAttestation.create({
        data: preflightAttestation({
          operatorId: listing.operatorId,
          sourceId: listing.source.id,
          requestId: listing.requestId,
          runId: listing.runId,
          capturedAt: lateCapture,
        }),
      });
      await expect(
        prisma.osvListingProviderContactAuthorization.create({
          data: providerContactAuthorization({
            operatorId: listing.operatorId,
            sourceId: listing.source.id,
            requestId: listing.requestId,
            runId: listing.runId,
            preflightId: preflight.id,
            sourceLegalDecisionId: listing.source.legalDecisionId,
            activePointerBaselineIdentity: preflight.activePointerBaselineIdentity,
            zeroFindingBaselineIdentity: preflight.zeroFindingBaselineIdentity,
            window: listing.window,
          }),
        }),
      ).rejects.toThrow(/precede preflight captured_at|restrict_violation/);
    });

    it('rejects another run preflight, consumed insert, colliding legal ids, and wrong TTL', async () => {
      const first = await seedIssuedProviderContact();
      const second = await seedConsumedListing();
      const secondPreflight = await prisma.osvCanaryProviderFreePreflightAttestation.create({
        data: preflightAttestation({
          operatorId: second.operatorId,
          sourceId: second.source.id,
          requestId: second.requestId,
          runId: second.runId,
          capturedAt: second.window.acknowledgedAt,
        }),
      });
      await expect(
        prisma.osvListingProviderContactAuthorization.create({
          data: providerContactAuthorization({
            operatorId: second.operatorId,
            sourceId: second.source.id,
            requestId: second.requestId,
            runId: second.runId,
            preflightId: first.preflight.id,
            sourceLegalDecisionId: second.source.legalDecisionId,
            activePointerBaselineIdentity: secondPreflight.activePointerBaselineIdentity,
            zeroFindingBaselineIdentity: secondPreflight.zeroFindingBaselineIdentity,
            window: second.window,
          }),
        }),
      ).rejects.toThrow();
      await expect(
        prisma.osvListingProviderContactAuthorization.create({
          data: providerContactAuthorization(
            {
              operatorId: second.operatorId,
              sourceId: second.source.id,
              requestId: second.requestId,
              runId: second.runId,
              preflightId: secondPreflight.id,
              sourceLegalDecisionId: second.source.legalDecisionId,
              activePointerBaselineIdentity: secondPreflight.activePointerBaselineIdentity,
              zeroFindingBaselineIdentity: secondPreflight.zeroFindingBaselineIdentity,
              window: second.window,
            },
            { state: 'consumed_for_listing_execution' },
          ),
        }),
      ).rejects.toThrow(/inserted as issued|restrict_violation/);
      await expect(
        prisma.osvListingProviderContactAuthorization.create({
          data: providerContactAuthorization(
            {
              operatorId: second.operatorId,
              sourceId: second.source.id,
              requestId: second.requestId,
              runId: second.runId,
              preflightId: secondPreflight.id,
              sourceLegalDecisionId: second.source.legalDecisionId,
              activePointerBaselineIdentity: secondPreflight.activePointerBaselineIdentity,
              zeroFindingBaselineIdentity: secondPreflight.zeroFindingBaselineIdentity,
              window: second.window,
            },
            { legalDecisionId: second.source.legalDecisionId },
          ),
        }),
      ).rejects.toThrow();
      await expect(
        prisma.osvListingProviderContactAuthorization.create({
          data: providerContactAuthorization(
            {
              operatorId: second.operatorId,
              sourceId: second.source.id,
              requestId: second.requestId,
              runId: second.runId,
              preflightId: secondPreflight.id,
              sourceLegalDecisionId: second.source.legalDecisionId,
              activePointerBaselineIdentity: secondPreflight.activePointerBaselineIdentity,
              zeroFindingBaselineIdentity: secondPreflight.zeroFindingBaselineIdentity,
              window: second.window,
            },
            { expiresAt: new Date(second.window.issuedAt.getTime() + 7_200_000) },
          ),
        }),
      ).rejects.toThrow();
    });

    it('rejects direct mutation of immutable bindings and preflight updates', async () => {
      const seeded = await seedIssuedProviderContact();
      const otherId = randomUUID();
      await expect(
        prisma.$executeRaw`
          UPDATE "osv_listing_provider_contact_authorization"
          SET "approved_prefix" = 'npm/'
          WHERE "id" = ${seeded.authorization.id}::uuid
        `,
      ).rejects.toThrow();
      await expect(
        prisma.$executeRaw`
          UPDATE "osv_listing_provider_contact_authorization"
          SET "provider_identity" = 'github_advisory_database'
          WHERE "id" = ${seeded.authorization.id}::uuid
        `,
      ).rejects.toThrow();
      await expect(
        prisma.$executeRaw`
          UPDATE "osv_listing_provider_contact_authorization"
          SET "phase" = 'bounded_body'
          WHERE "id" = ${seeded.authorization.id}::uuid
        `,
      ).rejects.toThrow();
      await expect(
        prisma.$executeRaw`
          UPDATE "osv_listing_provider_contact_authorization"
          SET "synchronization_run_id" = ${otherId}::uuid
          WHERE "id" = ${seeded.authorization.id}::uuid
        `,
      ).rejects.toThrow();
      await expect(
        prisma.$executeRaw`
          UPDATE "osv_listing_provider_contact_authorization"
          SET "expires_at" = "expires_at" + INTERVAL '1 second'
          WHERE "id" = ${seeded.authorization.id}::uuid
        `,
      ).rejects.toThrow();
      await expect(
        prisma.$executeRaw`
          UPDATE "osv_listing_provider_contact_authorization"
          SET "issued_at" = "issued_at" + INTERVAL '1 second'
          WHERE "id" = ${seeded.authorization.id}::uuid
        `,
      ).rejects.toThrow();
      await expect(
        prisma.$executeRaw`
          UPDATE "osv_listing_provider_contact_authorization"
          SET "runtime_version_set_fingerprint" = ${OTHER_FINGERPRINT}
          WHERE "id" = ${seeded.authorization.id}::uuid
        `,
      ).rejects.toThrow();
      await expect(
        prisma.$executeRaw`
          UPDATE "osv_listing_provider_contact_authorization"
          SET "preflight_evidence_id" = ${otherId}::uuid
          WHERE "id" = ${seeded.authorization.id}::uuid
        `,
      ).rejects.toThrow();
      await expect(
        prisma.$executeRaw`
          UPDATE "osv_listing_provider_contact_authorization"
          SET "finding_authorization" = 'permitted'
          WHERE "id" = ${seeded.authorization.id}::uuid
        `,
      ).rejects.toThrow();
      await expect(
        prisma.$executeRaw`
          UPDATE "osv_canary_provider_free_preflight_attestation"
          SET "provider_contact_authorized" = TRUE
          WHERE "id" = ${seeded.preflight.id}::uuid
        `,
      ).rejects.toThrow();
      const unchanged = await prisma.osvListingProviderContactAuthorization.findUniqueOrThrow({
        where: { id: seeded.authorization.id },
      });
      expect(unchanged.state).toBe('issued');
      expect(unchanged.approvedPrefix).toBe('crates.io/');
      expect(unchanged.expiresAt.toISOString()).toBe(seeded.authorization.expiresAt.toISOString());
    });

    it('rolls back a failed consumption so no partial terminal metadata remains', async () => {
      const seeded = await seedIssuedProviderContact();
      await expect(
        prisma.$transaction(async (tx) => {
          await tx.$executeRaw`
            UPDATE "osv_listing_provider_contact_authorization"
            SET "state" = 'consumed_for_listing_execution',
                "consumed_at" = CURRENT_TIMESTAMP,
                "consumed_by_synchronization_request_id" = ${seeded.requestId}::uuid,
                "consumed_by_synchronization_run_id" = ${seeded.runId}::uuid
            WHERE "id" = ${seeded.authorization.id}::uuid
              AND "state" = 'issued'
              AND CURRENT_TIMESTAMP < "expires_at"
          `;
          await tx.$executeRaw`
            UPDATE "osv_listing_provider_contact_authorization"
            SET "approved_prefix" = 'npm/'
            WHERE "id" = ${seeded.authorization.id}::uuid
          `;
        }),
      ).rejects.toThrow();
      const reloaded = await prisma.osvListingProviderContactAuthorization.findUniqueOrThrow({
        where: { id: seeded.authorization.id },
      });
      expect(reloaded.state).toBe('issued');
      expect(reloaded.consumedAt).toBeNull();
      expect(reloaded.consumedBySynchronizationRunId).toBeNull();
      expect(reloaded.terminalAt).toBeNull();
      expect(reloaded.approvedPrefix).toBe('crates.io/');
    });

    it('rejects a future consumed_at and a second distinct consumed_at after the winner', async () => {
      const seeded = await seedIssuedProviderContact();
      await expect(
        prisma.$executeRaw`
          UPDATE "osv_listing_provider_contact_authorization"
          SET "state" = 'consumed_for_listing_execution',
              "consumed_at" = CURRENT_TIMESTAMP + INTERVAL '60 seconds',
              "consumed_by_synchronization_request_id" = ${seeded.requestId}::uuid,
              "consumed_by_synchronization_run_id" = ${seeded.runId}::uuid
          WHERE "id" = ${seeded.authorization.id}::uuid
            AND "state" = 'issued'
            AND CURRENT_TIMESTAMP < "expires_at"
        `,
      ).rejects.toThrow(/consumed_at|restrict_violation/);
      expect(
        await prisma.$executeRaw`
          UPDATE "osv_listing_provider_contact_authorization"
          SET "state" = 'consumed_for_listing_execution',
              "consumed_at" = CURRENT_TIMESTAMP,
              "consumed_by_synchronization_request_id" = ${seeded.requestId}::uuid,
              "consumed_by_synchronization_run_id" = ${seeded.runId}::uuid
          WHERE "id" = ${seeded.authorization.id}::uuid
            AND "state" = 'issued'
            AND CURRENT_TIMESTAMP < "expires_at"
        `,
      ).toBe(1);
      const winner = await prisma.osvListingProviderContactAuthorization.findUniqueOrThrow({
        where: { id: seeded.authorization.id },
      });
      await expect(
        prisma.$executeRaw`
          UPDATE "osv_listing_provider_contact_authorization"
          SET "consumed_at" = ${winner.consumedAt}::timestamptz + INTERVAL '1 second'
          WHERE "id" = ${seeded.authorization.id}::uuid
            AND "state" = 'consumed_for_listing_execution'
        `,
      ).rejects.toThrow();
      const still = await prisma.osvListingProviderContactAuthorization.findUniqueOrThrow({
        where: { id: seeded.authorization.id },
      });
      expect(still.consumedAt?.toISOString()).toBe(winner.consumedAt?.toISOString());
    });

    it('admits only the committed ordered state graph', async () => {
      const states = [
        'issued',
        'consumed_for_listing_execution',
        'completed',
        'failed',
        'cancelled',
        'revoked',
        'expired',
      ] as const;
      const allowed: Record<(typeof states)[number], ReadonlySet<(typeof states)[number]>> = {
        issued: new Set(['issued', 'consumed_for_listing_execution', 'revoked', 'cancelled']),
        consumed_for_listing_execution: new Set([
          'consumed_for_listing_execution',
          'completed',
          'failed',
          'cancelled',
        ]),
        completed: new Set(),
        failed: new Set(),
        cancelled: new Set(),
        revoked: new Set(),
        expired: new Set(),
      };

      async function seedState(state: (typeof states)[number]) {
        if (state === 'expired') {
          const listing = await seedConsumedListing();
          const expiredWindow = liveWindow(3_601_000);
          const preflight = await prisma.osvCanaryProviderFreePreflightAttestation.create({
            data: preflightAttestation({
              operatorId: listing.operatorId,
              sourceId: listing.source.id,
              requestId: listing.requestId,
              runId: listing.runId,
              capturedAt: expiredWindow.acknowledgedAt,
            }),
          });
          const authorization = await prisma.osvListingProviderContactAuthorization.create({
            data: providerContactAuthorization({
              operatorId: listing.operatorId,
              sourceId: listing.source.id,
              requestId: listing.requestId,
              runId: listing.runId,
              preflightId: preflight.id,
              sourceLegalDecisionId: listing.source.legalDecisionId,
              activePointerBaselineIdentity: preflight.activePointerBaselineIdentity,
              zeroFindingBaselineIdentity: preflight.zeroFindingBaselineIdentity,
              window: expiredWindow,
            }),
          });
          expect(
            await prisma.$executeRaw`
              UPDATE "osv_listing_provider_contact_authorization"
              SET "state" = 'expired',
                  "terminal_at" = CURRENT_TIMESTAMP,
                  "terminal_disposition" = 'expired'
              WHERE "id" = ${authorization.id}::uuid
                AND "state" = 'issued'
                AND CURRENT_TIMESTAMP >= "expires_at"
            `,
          ).toBe(1);
          return { ...listing, authorization: { ...authorization, state: 'expired' as const } };
        }
        const seeded = await seedIssuedProviderContact();
        if (state === 'issued') {
          return seeded;
        }
        if (state === 'revoked') {
          expect(
            await prisma.$executeRaw`
              UPDATE "osv_listing_provider_contact_authorization"
              SET "state" = 'revoked',
                  "terminal_at" = CURRENT_TIMESTAMP,
                  "terminal_disposition" = 'revoked',
                  "revoked_at" = CURRENT_TIMESTAMP,
                  "revoked_by_operator_identity_id" = ${seeded.operatorId}::uuid
              WHERE "id" = ${seeded.authorization.id}::uuid
                AND "state" = 'issued'
                AND CURRENT_TIMESTAMP < "expires_at"
            `,
          ).toBe(1);
          return seeded;
        }
        if (state === 'cancelled') {
          expect(
            await prisma.$executeRaw`
              UPDATE "osv_listing_provider_contact_authorization"
              SET "state" = 'cancelled',
                  "terminal_at" = CURRENT_TIMESTAMP,
                  "terminal_disposition" = 'cancelled'
              WHERE "id" = ${seeded.authorization.id}::uuid
                AND "state" = 'issued'
            `,
          ).toBe(1);
          return seeded;
        }
        expect(
          await prisma.$executeRaw`
            UPDATE "osv_listing_provider_contact_authorization"
            SET "state" = 'consumed_for_listing_execution',
                "consumed_at" = CURRENT_TIMESTAMP,
                "consumed_by_synchronization_request_id" = ${seeded.requestId}::uuid,
                "consumed_by_synchronization_run_id" = ${seeded.runId}::uuid
            WHERE "id" = ${seeded.authorization.id}::uuid
              AND "state" = 'issued'
              AND CURRENT_TIMESTAMP < "expires_at"
          `,
        ).toBe(1);
        if (state === 'consumed_for_listing_execution') {
          return seeded;
        }
        if (state === 'completed') {
          expect(
            await prisma.$executeRaw`
              UPDATE "osv_listing_provider_contact_authorization"
              SET "state" = 'completed',
                  "terminal_at" = CURRENT_TIMESTAMP,
                  "terminal_disposition" = 'completed'
              WHERE "id" = ${seeded.authorization.id}::uuid
                AND "state" = 'consumed_for_listing_execution'
            `,
          ).toBe(1);
          return seeded;
        }
        expect(
          await prisma.$executeRaw`
            UPDATE "osv_listing_provider_contact_authorization"
            SET "state" = 'failed',
                "terminal_at" = CURRENT_TIMESTAMP,
                "terminal_disposition" = 'failed',
                "terminal_reason_code" = 'timeout'
            WHERE "id" = ${seeded.authorization.id}::uuid
              AND "state" = 'consumed_for_listing_execution'
          `,
        ).toBe(1);
        return seeded;
      }

      for (const fromState of states) {
        for (const toState of states) {
          const seeded = await seedState(fromState);
          const permitted = allowed[fromState].has(toState);
          if (permitted && fromState === toState) {
            expect(
              await prisma.$executeRaw(
                Prisma.sql`
                  UPDATE "osv_listing_provider_contact_authorization"
                  SET "state" = ${toState}::"osv_listing_provider_contact_authorization_state"
                  WHERE "id" = ${seeded.authorization.id}::uuid
                `,
              ),
            ).toBe(1);
            continue;
          }
          if (permitted && fromState === 'issued' && toState === 'consumed_for_listing_execution') {
            await expect(
              prisma.$executeRaw`
                UPDATE "osv_listing_provider_contact_authorization"
                SET "state" = 'consumed_for_listing_execution',
                    "consumed_at" = CURRENT_TIMESTAMP,
                    "consumed_by_synchronization_request_id" = ${seeded.requestId}::uuid,
                    "consumed_by_synchronization_run_id" = ${seeded.runId}::uuid
                WHERE "id" = ${seeded.authorization.id}::uuid
              `,
            ).resolves.toBe(1);
            continue;
          }
          if (permitted && fromState === 'issued' && toState === 'revoked') {
            await expect(
              prisma.$executeRaw`
                UPDATE "osv_listing_provider_contact_authorization"
                SET "state" = 'revoked',
                    "terminal_at" = CURRENT_TIMESTAMP,
                    "terminal_disposition" = 'revoked',
                    "revoked_at" = CURRENT_TIMESTAMP,
                    "revoked_by_operator_identity_id" = ${seeded.operatorId}::uuid
                WHERE "id" = ${seeded.authorization.id}::uuid
              `,
            ).resolves.toBe(1);
            continue;
          }
          if (permitted && fromState === 'issued' && toState === 'cancelled') {
            await expect(
              prisma.$executeRaw`
                UPDATE "osv_listing_provider_contact_authorization"
                SET "state" = 'cancelled',
                    "terminal_at" = CURRENT_TIMESTAMP,
                    "terminal_disposition" = 'cancelled'
                WHERE "id" = ${seeded.authorization.id}::uuid
              `,
            ).resolves.toBe(1);
            continue;
          }
          if (
            permitted &&
            fromState === 'consumed_for_listing_execution' &&
            toState === 'completed'
          ) {
            await expect(
              prisma.$executeRaw`
                UPDATE "osv_listing_provider_contact_authorization"
                SET "state" = 'completed',
                    "terminal_at" = CURRENT_TIMESTAMP,
                    "terminal_disposition" = 'completed'
                WHERE "id" = ${seeded.authorization.id}::uuid
              `,
            ).resolves.toBe(1);
            continue;
          }
          if (permitted && fromState === 'consumed_for_listing_execution' && toState === 'failed') {
            await expect(
              prisma.$executeRaw`
                UPDATE "osv_listing_provider_contact_authorization"
                SET "state" = 'failed',
                    "terminal_at" = CURRENT_TIMESTAMP,
                    "terminal_disposition" = 'failed',
                    "terminal_reason_code" = 'timeout'
                WHERE "id" = ${seeded.authorization.id}::uuid
              `,
            ).resolves.toBe(1);
            continue;
          }
          if (
            permitted &&
            fromState === 'consumed_for_listing_execution' &&
            toState === 'cancelled'
          ) {
            await expect(
              prisma.$executeRaw`
                UPDATE "osv_listing_provider_contact_authorization"
                SET "state" = 'cancelled',
                    "terminal_at" = CURRENT_TIMESTAMP,
                    "terminal_disposition" = 'cancelled'
                WHERE "id" = ${seeded.authorization.id}::uuid
              `,
            ).resolves.toBe(1);
            continue;
          }
          await expect(
            prisma.$executeRaw(
              Prisma.sql`
                UPDATE "osv_listing_provider_contact_authorization"
                SET "state" = ${toState}::"osv_listing_provider_contact_authorization_state"
                WHERE "id" = ${seeded.authorization.id}::uuid
              `,
            ),
          ).rejects.toThrow();
        }
      }
    });
  },
);
