import { randomUUID } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
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
const ISSUED_AT = new Date('2026-09-08T12:00:00.000Z');
const EXPIRES_AT = new Date('2026-09-08T13:00:00.000Z');
const ACKNOWLEDGED_AT = new Date('2026-09-08T11:59:00.000Z');
const LEGAL_ISSUED_AT = new Date('2026-09-08T11:00:00.000Z');
const LEGAL_REVALIDATE_AT = new Date('2026-09-09T11:00:00.000Z');
const TERMINAL_AT = new Date('2026-09-08T12:45:00.000Z');
const PAST_ISSUED_AT = new Date('2026-09-08T10:00:00.000Z');
const PAST_EXPIRES_AT = new Date('2026-09-08T11:00:00.000Z');
const PAST_ACKNOWLEDGED_AT = new Date('2026-09-08T09:59:00.000Z');

const srcDir = path.dirname(fileURLToPath(import.meta.url));
const workspaceRoot = path.join(srcDir, '..', '..', '..');

function liveWindow(issuedAgoMs = 5_000): {
  issuedAt: Date;
  expiresAt: Date;
  createdAt: Date;
  runbookAcknowledgedAt: Date;
  haltAcknowledgedAt: Date;
} {
  const issuedAt = new Date(Date.now() - issuedAgoMs);
  return {
    issuedAt,
    expiresAt: new Date(issuedAt.getTime() + 3_600_000),
    createdAt: issuedAt,
    runbookAcknowledgedAt: new Date(issuedAt.getTime() - 1_000),
    haltAcknowledgedAt: new Date(issuedAt.getTime() - 1_000),
  };
}

function operator(
  overrides: Partial<Prisma.OsvCanaryInstanceOperatorIdentityUncheckedCreateInput> = {},
): Prisma.OsvCanaryInstanceOperatorIdentityUncheckedCreateInput {
  return {
    id: randomUUID(),
    identitySchemaVersion: 'osv_canary_instance_operator_identity_v1',
    identityType: 'instance_operator',
    authenticationSource: 'local_host_control_of_one_shot_administrative_command',
    provenanceIdentifier: 'configured_instance_operator_attestation_v1',
    displayLabel: `canary-operator-${randomUUID().slice(0, 8)}`,
    establishedAt: ISSUED_AT,
    createdAt: ISSUED_AT,
    status: 'active',
    ...overrides,
  };
}

function canaryRequest(
  overrides: Partial<Prisma.OsvRuntimeSynchronizationRequestUncheckedCreateInput> = {},
): Prisma.OsvRuntimeSynchronizationRequestUncheckedCreateInput {
  return {
    jobType: 'intelligence.osv.sync',
    jobSchemaVersion: 'osv_runtime_sync_job_schema_v1',
    synchronizationReason: 'operator_canary',
    workScope: CANARY_SCOPE,
    leaseScope: LEASE_SCOPE,
    catalogScope: 'osv_gcs_six_prefix_public_export_v1',
    versionSetFingerprint: FINGERPRINT,
    requestedAt: ISSUED_AT,
    createdAt: ISSUED_AT,
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
    createdAt: ISSUED_AT,
    updatedAt: ISSUED_AT,
    ...overrides,
  };
}

function listingAuthorization(
  operatorId: string,
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
    legalDecisionIssuedAt: LEGAL_ISSUED_AT,
    legalDecisionRevalidationBoundaryAt: LEGAL_REVALIDATE_AT,
    legalDecisionResponsibleRole:
      'instance_legal_and_provenance_reviewer_countersigned_by_instance_operator',
    legalDecisionEvidenceSetId: randomUUID(),
    runbookSetIdentifier: 'osv_canary_runbook_set_v1',
    runbookVersion: 'osv_canary_runbook_outlines_v1',
    runbookAcknowledgedAt: ACKNOWLEDGED_AT,
    runbookEmergencyHaltProcedure: 'stop_next_protected_stage_production_remains_halted',
    haltAcknowledgementIdentifier: 'osv_canary_halt_control_acknowledgement_v1',
    haltAcknowledgedAt: ACKNOWLEDGED_AT,
    activationProhibitionIdentifier: 'osv_canary_activation_prohibition_v1',
    retryProhibitionIdentifier: 'osv_canary_automatic_retry_prohibition_v1',
    issuedAt: ISSUED_AT,
    expiresAt: EXPIRES_AT,
    state: 'issued',
    createdAt: ISSUED_AT,
    ...overrides,
  };
}

function boundedBodyAuthorization(
  operatorId: string,
  listing: {
    id: string;
    requestId: string;
    runId: string;
  },
  overrides: Partial<Prisma.OsvCanaryAuthorizationUncheckedCreateInput> = {},
): Prisma.OsvCanaryAuthorizationUncheckedCreateInput {
  return listingAuthorization(operatorId, {
    phase: 'bounded_body',
    authorizationPurpose: 'bounded_body_compatibility',
    budgetProfileIdentifier: 'osv_canary_bounded_body_budget_v1',
    bodyLegalDecisionId: randomUUID(),
    bodyLegalDecisionPhase: 'bounded_body',
    bodyLegalDecisionPermittedOperation: 'retrieve_provider_bodies',
    bodyLegalDecisionIssuedAt: LEGAL_ISSUED_AT,
    bodyLegalDecisionRevalidationBoundaryAt: LEGAL_REVALIDATE_AT,
    bodyLegalDecisionEvidenceSetId: randomUUID(),
    bodyRetrieveDisposition: 'required_current_before_bounded_body',
    bodyTransientInspectionDisposition: 'permitted_for_license_evaluation_only',
    bodyPrivateRetentionDisposition: 'reject_body_retrieval_until_retention_resolved',
    bodyParseDisposition: 'license_inspection_only_before_retention',
    bodyExternalExposureDisposition: 'forbidden',
    bodyMatchingDisposition: 'forbidden',
    listingReviewEvidenceIdentifier: 'osv_canary_listing_review_evidence_v1',
    listingReviewId: randomUUID(),
    listingAuthorizationId: listing.id,
    listingRequestId: listing.requestId,
    listingRunId: listing.runId,
    listingCanonicalInventoryEvidenceId: randomUUID(),
    listingReviewVerdict: 'listing_canary_evidence_accepted',
    listingReviewedAt: ISSUED_AT,
    listingReviewerRole: 'instance_canary_evidence_reviewer',
    bodySelectionAlgorithmIdentifier: 'osv_canary_bounded_body_selection_v1',
    ...overrides,
  });
}

describe(
  'session 13 Batch 2B OSV canary authorization SQL constraints',
  { timeout: 90_000 },
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

    async function consumeIssued(
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

    async function completeConsumed(authorizationId: string): Promise<number> {
      return prisma.$executeRaw`
        UPDATE "osv_canary_authorization"
        SET "state" = 'completed',
            "terminal_at" = CURRENT_TIMESTAMP,
            "terminal_disposition" = 'completed'
        WHERE "id" = ${authorizationId}::uuid
          AND "state" = 'consumed'
      `;
    }

    async function seedCompletedListing(): Promise<{
      operatorId: string;
      listing: { id: string; requestId: string; runId: string; terminalAt: Date };
    }> {
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
      const listing = await prisma.osvCanaryAuthorization.create({
        data: listingAuthorization(createdOperator.id, window),
      });
      expect(await consumeIssued(listing.id, request.id, run.id)).toBe(1);
      expect(await completeConsumed(listing.id)).toBe(1);
      const completed = await prisma.osvCanaryAuthorization.findUniqueOrThrow({
        where: { id: listing.id },
      });
      expect(completed.state).toBe('completed');
      expect(completed.terminalAt).not.toBeNull();
      return {
        operatorId: createdOperator.id,
        listing: {
          id: listing.id,
          requestId: request.id,
          runId: run.id,
          terminalAt: completed.terminalAt as Date,
        },
      };
    }

    function bodyAuthorization(
      operatorId: string,
      listing: { id: string; requestId: string; runId: string; terminalAt: Date },
      overrides: Partial<Prisma.OsvCanaryAuthorizationUncheckedCreateInput> = {},
    ): Prisma.OsvCanaryAuthorizationUncheckedCreateInput {
      const issuedAt = new Date(listing.terminalAt.getTime() + 1_000);
      const listingReviewedAt = new Date(listing.terminalAt.getTime() + 50);
      return boundedBodyAuthorization(operatorId, listing, {
        issuedAt,
        expiresAt: new Date(issuedAt.getTime() + 3_600_000),
        createdAt: issuedAt,
        runbookAcknowledgedAt: listing.terminalAt,
        haltAcknowledgedAt: listing.terminalAt,
        listingReviewedAt,
        ...overrides,
      });
    }

    it('does not seed operator identity, authorization, Finding, or tenant rows', async () => {
      expect(await prisma.osvCanaryInstanceOperatorIdentity.count()).toBe(0);
      expect(await prisma.osvCanaryAuthorization.count()).toBe(0);
      expect(await prisma.finding.count()).toBe(0);
      expect(await prisma.organization.count()).toBe(0);
      expect(await prisma.user.count()).toBe(0);
    });

    it('accepts a non-anonymous instance operator and listing-only authorization', async () => {
      const createdOperator = await prisma.osvCanaryInstanceOperatorIdentity.create({
        data: operator({ displayLabel: 'canary-operator-1' }),
      });
      const authorization = await prisma.osvCanaryAuthorization.create({
        data: listingAuthorization(createdOperator.id),
      });
      expect(createdOperator.identityType).toBe('instance_operator');
      expect(createdOperator.status).toBe('active');
      expect(authorization.phase).toBe('listing_only');
      expect(authorization.state).toBe('issued');
      expect(authorization.listingReviewId).toBeNull();
      expect(authorization.bodyLegalDecisionId).toBeNull();
      expect(authorization.expiresAt.toISOString()).toBe(EXPIRES_AT.toISOString());
    });

    it('accepts bounded-body authorization only with completed listing-review evidence', async () => {
      const context = await seedCompletedListing();
      const body = await prisma.osvCanaryAuthorization.create({
        data: bodyAuthorization(context.operatorId, context.listing),
      });
      expect(body.phase).toBe('bounded_body');
      expect(body.listingAuthorizationId).toBe(context.listing.id);
      expect(body.bodySelectionAlgorithmIdentifier).toBe('osv_canary_bounded_body_selection_v1');
      expect(body.bodyRetrieveDisposition).toBe('required_current_before_bounded_body');
      await expect(
        prisma.osvCanaryAuthorization.create({
          data: bodyAuthorization(context.operatorId, {
            ...context.listing,
            id: body.id,
          }),
        }),
      ).rejects.toThrow(/listing_only|restrict_violation|listing review/);
    });

    it('rejects whitespace, oversized, tenant, and control-character operator provenance', async () => {
      await expect(
        prisma.osvCanaryInstanceOperatorIdentity.create({
          data: operator({ authenticationSource: 'organization_member' }),
        }),
      ).rejects.toThrow();
      await expect(
        prisma.osvCanaryInstanceOperatorIdentity.create({
          data: operator({ provenanceIdentifier: ' configured_instance_operator_attestation_v1' }),
        }),
      ).rejects.toThrow();
      await expect(
        prisma.osvCanaryInstanceOperatorIdentity.create({
          data: operator({ provenanceIdentifier: `${'x'.repeat(129)}` }),
        }),
      ).rejects.toThrow();
      await expect(
        prisma.osvCanaryInstanceOperatorIdentity.create({
          data: operator({ displayLabel: 'canary\toperator' }),
        }),
      ).rejects.toThrow();
      await expect(
        prisma.osvCanaryInstanceOperatorIdentity.create({
          data: operator({ displayLabel: 'canary\u0301operator' }),
        }),
      ).rejects.toThrow();
      await expect(
        prisma.osvCanaryInstanceOperatorIdentity.create({
          data: operator({ status: 'revoked', revokedAt: TERMINAL_AT }),
        }),
      ).rejects.toThrow(/active|restrict_violation/);
    });

    it('rejects anonymous, tenant, and malformed operator identity', async () => {
      await expect(
        prisma.osvCanaryInstanceOperatorIdentity.create({
          data: operator({ identityType: 'anonymous' }),
        }),
      ).rejects.toThrow();
      await expect(
        prisma.osvCanaryInstanceOperatorIdentity.create({
          data: operator({ identityType: 'tenant_user' }),
        }),
      ).rejects.toThrow();
      await expect(
        prisma.osvCanaryInstanceOperatorIdentity.create({
          data: operator({ authenticationSource: 'tenant_session' }),
        }),
      ).rejects.toThrow();
      await expect(
        prisma.osvCanaryInstanceOperatorIdentity.create({
          data: operator({ displayLabel: '' }),
        }),
      ).rejects.toThrow();
      await expect(
        prisma.osvCanaryInstanceOperatorIdentity.create({
          data: operator({ displayLabel: 'has space' }),
        }),
      ).rejects.toThrow();
      await expect(
        prisma.$executeRaw`
        INSERT INTO "osv_canary_instance_operator_identity" (
          "id", "identity_schema_version", "identity_type", "authentication_source",
          "provenance_identifier", "display_label", "established_at", "status"
        ) VALUES (
          '11111111-1111-1111-8111-111111111111'::uuid,
          'osv_canary_instance_operator_identity_v1', 'instance_operator',
          'local_host_control_of_one_shot_administrative_command',
          'configured_instance_operator_attestation_v1', 'canary-operator-uuid',
          ${ISSUED_AT}, 'active'
        )
      `,
      ).rejects.toThrow();
    });

    it('rejects invalid phase, combined purpose, unknown provider, and malformed fingerprint', async () => {
      const createdOperator = await prisma.osvCanaryInstanceOperatorIdentity.create({
        data: operator(),
      });
      await expect(
        prisma.$executeRaw`
        INSERT INTO "osv_canary_authorization" (
          "id", "operator_identity_id", "authorization_schema_version",
          "canary_architecture_identifier", "runtime_architecture_identifier",
          "listing_protocol_identifier", "actor_kind", "phase", "synchronization_reason",
          "authorization_purpose", "provider_prefix", "source_identifier", "family",
          "canary_policy_identifier", "work_scope", "lease_scope",
          "runtime_version_set_fingerprint", "budget_profile_identifier",
          "unused_ttl_seconds", "single_use_policy", "catalog_activation_authorization",
          "matching_authorization", "finding_authorization", "postcanary_review_requirement",
          "legal_decision_reference_identifier", "legal_decision_id",
          "legal_decision_source_registry_version", "legal_decision_phase",
          "legal_decision_permitted_operation", "legal_decision_state",
          "legal_decision_issuance", "legal_decision_issued_at",
          "legal_decision_revalidation_boundary_at", "legal_decision_responsible_role",
          "legal_decision_evidence_set_id", "runbook_set_identifier", "runbook_version",
          "runbook_acknowledged_at", "runbook_emergency_halt_procedure",
          "halt_acknowledgement_identifier", "halt_acknowledged_at",
          "activation_prohibition_identifier", "retry_prohibition_identifier",
          "issued_at", "expires_at", "state"
        ) VALUES (
          ${randomUUID()}::uuid, ${createdOperator.id}::uuid,
          'osv_canary_execution_authorization_record_v1',
          'osv_first_real_provider_canary_authorization_v1',
          'osv_runtime_enablement_architecture_v1', 'osv_gcs_json_objects_list_v1',
          'instance_operator', 'listing_only', 'operator_canary',
          'bounded_body_compatibility', 'crates.io/', 'rustsec_advisory_database',
          'RUSTSEC', 'osv_disabled_first_provider_canary_policy_v1',
          ${CANARY_SCOPE}::osv_runtime_work_scope, ${LEASE_SCOPE}, ${FINGERPRINT},
          'osv_canary_listing_only_budget_v1', 3600, 'single_use', 'prohibited',
          'prohibited', 'prohibited', 'required', 'osv_canary_legal_decision_reference_v1',
          ${randomUUID()}::uuid, 'osv_source_license_registry_v1', 'listing_only',
          'list_object_metadata', 'recorded_reference_not_execution_authority',
          'blocking_preexecution_dependency_not_issued_in_batch_2a',
          ${LEGAL_ISSUED_AT}, ${LEGAL_REVALIDATE_AT},
          'instance_legal_and_provenance_reviewer_countersigned_by_instance_operator',
          ${randomUUID()}::uuid, 'osv_canary_runbook_set_v1', 'osv_canary_runbook_outlines_v1',
          ${ACKNOWLEDGED_AT}, 'stop_next_protected_stage_production_remains_halted',
          'osv_canary_halt_control_acknowledgement_v1', ${ACKNOWLEDGED_AT},
          'osv_canary_activation_prohibition_v1', 'osv_canary_automatic_retry_prohibition_v1',
          ${ISSUED_AT}, ${EXPIRES_AT}, 'issued'
        )
      `,
      ).rejects.toThrow();
      await expect(
        prisma.osvCanaryAuthorization.create({
          data: listingAuthorization(createdOperator.id, { providerPrefix: 'npm/' }),
        }),
      ).rejects.toThrow();
      await expect(
        prisma.osvCanaryAuthorization.create({
          data: listingAuthorization(createdOperator.id, {
            runtimeVersionSetFingerprint: 'A'.repeat(64),
          }),
        }),
      ).rejects.toThrow();
    });

    it('rejects listing-only rows with body policy or listing-review evidence', async () => {
      const createdOperator = await prisma.osvCanaryInstanceOperatorIdentity.create({
        data: operator(),
      });
      await expect(
        prisma.osvCanaryAuthorization.create({
          data: listingAuthorization(createdOperator.id, {
            bodySelectionAlgorithmIdentifier: 'osv_canary_bounded_body_selection_v1',
          }),
        }),
      ).rejects.toThrow();
      await expect(
        prisma.osvCanaryAuthorization.create({
          data: listingAuthorization(createdOperator.id, {
            listingReviewId: randomUUID(),
          }),
        }),
      ).rejects.toThrow();
      await expect(
        prisma.osvCanaryAuthorization.create({
          data: listingAuthorization(createdOperator.id, {
            budgetProfileIdentifier: 'osv_canary_bounded_body_budget_v1',
          }),
        }),
      ).rejects.toThrow();
    });

    it('rejects bounded-body without review evidence, selection policy, or body legal decision', async () => {
      const context = await seedCompletedListing();
      await expect(
        prisma.osvCanaryAuthorization.create({
          data: bodyAuthorization(context.operatorId, context.listing, {
            listingReviewId: null,
            listingAuthorizationId: null,
            listingRequestId: null,
            listingRunId: null,
            listingCanonicalInventoryEvidenceId: null,
            listingReviewVerdict: null,
            listingReviewedAt: null,
            listingReviewerRole: null,
            listingReviewEvidenceIdentifier: null,
            bodySelectionAlgorithmIdentifier: null,
          }),
        }),
      ).rejects.toThrow();
      await expect(
        prisma.osvCanaryAuthorization.create({
          data: bodyAuthorization(context.operatorId, context.listing, {
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
          }),
        }),
      ).rejects.toThrow();
    });

    it('rejects activation-permitted, retry-permitted, and arbitrary budget acknowledgements', async () => {
      const createdOperator = await prisma.osvCanaryInstanceOperatorIdentity.create({
        data: operator(),
      });
      await expect(
        prisma.osvCanaryAuthorization.create({
          data: listingAuthorization(createdOperator.id, {
            catalogActivationAuthorization: 'permitted',
          }),
        }),
      ).rejects.toThrow();
      await expect(
        prisma.osvCanaryAuthorization.create({
          data: listingAuthorization(createdOperator.id, {
            retryProhibitionIdentifier: 'osv_canary_automatic_retry_permitted_v1',
          }),
        }),
      ).rejects.toThrow();
      await expect(
        prisma.osvCanaryAuthorization.create({
          data: listingAuthorization(createdOperator.id, {
            unusedTtlSeconds: 7200,
          }),
        }),
      ).rejects.toThrow();
    });

    it('rejects issued consumption bindings and consumed rows without request or run', async () => {
      const createdOperator = await prisma.osvCanaryInstanceOperatorIdentity.create({
        data: operator(),
      });
      const request = await prisma.osvRuntimeSynchronizationRequest.create({
        data: canaryRequest(),
      });
      await expect(
        prisma.osvCanaryAuthorization.create({
          data: listingAuthorization(createdOperator.id, {
            consumedBySynchronizationRequestId: request.id,
          }),
        }),
      ).rejects.toThrow();
      await expect(
        prisma.osvCanaryAuthorization.create({
          data: listingAuthorization(createdOperator.id, {
            state: 'consumed',
            consumedAt: ISSUED_AT,
          }),
        }),
      ).rejects.toThrow();
    });

    it('rejects completed without terminal time, failed without reason, revoked without time, and expired without valid expiration', async () => {
      const createdOperator = await prisma.osvCanaryInstanceOperatorIdentity.create({
        data: operator(),
      });
      await expect(
        prisma.osvCanaryAuthorization.create({
          data: listingAuthorization(createdOperator.id, {
            state: 'completed',
            terminalDisposition: 'completed',
          }),
        }),
      ).rejects.toThrow();
      const request = await prisma.osvRuntimeSynchronizationRequest.create({
        data: canaryRequest(),
      });
      const run = await prisma.osvRuntimeSynchronizationRun.create({
        data: canaryRun(request),
      });
      await expect(
        prisma.osvCanaryAuthorization.create({
          data: listingAuthorization(createdOperator.id, {
            state: 'failed',
            consumedAt: ISSUED_AT,
            consumedBySynchronizationRequestId: request.id,
            consumedBySynchronizationRunId: run.id,
            terminalAt: TERMINAL_AT,
            terminalDisposition: 'failed',
          }),
        }),
      ).rejects.toThrow();
      await expect(
        prisma.osvCanaryAuthorization.create({
          data: listingAuthorization(createdOperator.id, {
            state: 'revoked',
            terminalAt: TERMINAL_AT,
            terminalDisposition: 'revoked',
          }),
        }),
      ).rejects.toThrow();
      await expect(
        prisma.osvCanaryAuthorization.create({
          data: listingAuthorization(createdOperator.id, {
            state: 'expired',
            issuedAt: PAST_ISSUED_AT,
            expiresAt: PAST_EXPIRES_AT,
            terminalAt: new Date('2026-09-08T10:30:00.000Z'),
            terminalDisposition: 'expired',
          }),
        }),
      ).rejects.toThrow();
    });

    it('consumes exactly once, reloads same-run binding, and rejects a different run', async () => {
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
      const otherRequest = await prisma.osvRuntimeSynchronizationRequest.create({
        data: canaryRequest({ requestedAt: window.issuedAt, createdAt: window.issuedAt }),
      });
      const otherRun = await prisma.osvRuntimeSynchronizationRun.create({
        data: canaryRun(otherRequest, { createdAt: window.issuedAt, updatedAt: window.issuedAt }),
      });
      const authorization = await prisma.osvCanaryAuthorization.create({
        data: listingAuthorization(createdOperator.id, window),
      });
      expect(await consumeIssued(authorization.id, request.id, run.id)).toBe(1);
      expect(await consumeIssued(authorization.id, request.id, run.id)).toBe(0);
      const reloaded = await prisma.osvCanaryAuthorization.findUniqueOrThrow({
        where: { id: authorization.id },
      });
      expect(reloaded.state).toBe('consumed');
      expect(reloaded.consumedBySynchronizationRunId).toBe(run.id);
      await expect(
        prisma.$executeRaw`
          UPDATE "osv_canary_authorization"
          SET "state" = 'consumed',
              "consumed_at" = CURRENT_TIMESTAMP,
              "consumed_by_synchronization_request_id" = ${otherRequest.id}::uuid,
              "consumed_by_synchronization_run_id" = ${otherRun.id}::uuid
          WHERE "id" = ${authorization.id}::uuid
            AND "state" = 'consumed'
        `,
      ).rejects.toThrow(/immutable|restrict_violation/);
      await expect(
        prisma.osvCanaryAuthorization.create({
          data: listingAuthorization(createdOperator.id, {
            ...window,
            state: 'consumed',
            consumedAt: window.issuedAt,
            consumedBySynchronizationRequestId: request.id,
            consumedBySynchronizationRunId: run.id,
          }),
        }),
      ).rejects.toThrow(/issued|restrict_violation/);
    });

    it('admits one CAS winner when two consumers target one issued authorization', async () => {
      const window = liveWindow();
      const createdOperator = await prisma.osvCanaryInstanceOperatorIdentity.create({
        data: operator({ establishedAt: window.issuedAt, createdAt: window.issuedAt }),
      });
      const firstRequest = await prisma.osvRuntimeSynchronizationRequest.create({
        data: canaryRequest({ requestedAt: window.issuedAt, createdAt: window.issuedAt }),
      });
      const firstRun = await prisma.osvRuntimeSynchronizationRun.create({
        data: canaryRun(firstRequest, { createdAt: window.issuedAt, updatedAt: window.issuedAt }),
      });
      const secondRequest = await prisma.osvRuntimeSynchronizationRequest.create({
        data: canaryRequest({ requestedAt: window.issuedAt, createdAt: window.issuedAt }),
      });
      const secondRun = await prisma.osvRuntimeSynchronizationRun.create({
        data: canaryRun(secondRequest, { createdAt: window.issuedAt, updatedAt: window.issuedAt }),
      });
      const authorization = await prisma.osvCanaryAuthorization.create({
        data: listingAuthorization(createdOperator.id, window),
      });
      const clientA = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
      const clientB = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
      try {
        const results = await Promise.allSettled([
          clientA.$executeRaw`
            UPDATE "osv_canary_authorization"
            SET "state" = 'consumed',
                "consumed_at" = CURRENT_TIMESTAMP,
                "consumed_by_synchronization_request_id" = ${firstRequest.id}::uuid,
                "consumed_by_synchronization_run_id" = ${firstRun.id}::uuid
            WHERE "id" = ${authorization.id}::uuid
              AND "state" = 'issued'
              AND CURRENT_TIMESTAMP < "expires_at"
          `,
          clientB.$executeRaw`
            UPDATE "osv_canary_authorization"
            SET "state" = 'consumed',
                "consumed_at" = CURRENT_TIMESTAMP,
                "consumed_by_synchronization_request_id" = ${secondRequest.id}::uuid,
                "consumed_by_synchronization_run_id" = ${secondRun.id}::uuid
            WHERE "id" = ${authorization.id}::uuid
              AND "state" = 'issued'
              AND CURRENT_TIMESTAMP < "expires_at"
          `,
        ]);
        const updates = results.map((result) => (result.status === 'fulfilled' ? result.value : 0));
        expect(updates.filter((value) => value === 1)).toHaveLength(1);
        expect(updates.filter((value) => value === 0)).toHaveLength(1);
        const winner = await prisma.osvCanaryAuthorization.findUniqueOrThrow({
          where: { id: authorization.id },
        });
        expect(winner.state).toBe('consumed');
        expect([firstRun.id, secondRun.id]).toContain(winner.consumedBySynchronizationRunId);
      } finally {
        await clientA.$disconnect();
        await clientB.$disconnect();
      }
    });

    it('lets revocation and consumption race to one winner', async () => {
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
      const authorization = await prisma.osvCanaryAuthorization.create({
        data: listingAuthorization(createdOperator.id, window),
      });
      const clientA = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
      const clientB = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
      try {
        const results = await Promise.allSettled([
          clientA.$executeRaw`
            UPDATE "osv_canary_authorization"
            SET "state" = 'consumed',
                "consumed_at" = CURRENT_TIMESTAMP,
                "consumed_by_synchronization_request_id" = ${request.id}::uuid,
                "consumed_by_synchronization_run_id" = ${run.id}::uuid
            WHERE "id" = ${authorization.id}::uuid
              AND "state" = 'issued'
              AND CURRENT_TIMESTAMP < "expires_at"
          `,
          clientB.$executeRaw`
            UPDATE "osv_canary_authorization"
            SET "state" = 'revoked',
                "revoked_at" = CURRENT_TIMESTAMP,
                "revoked_by_operator_identity_id" = ${createdOperator.id}::uuid,
                "terminal_at" = CURRENT_TIMESTAMP,
                "terminal_disposition" = 'revoked'
            WHERE "id" = ${authorization.id}::uuid
              AND "state" = 'issued'
              AND CURRENT_TIMESTAMP < "expires_at"
          `,
        ]);
        const updates = results.map((result) => (result.status === 'fulfilled' ? result.value : 0));
        expect(updates.filter((value) => value === 1)).toHaveLength(1);
        const winner = await prisma.osvCanaryAuthorization.findUniqueOrThrow({
          where: { id: authorization.id },
        });
        expect(['consumed', 'revoked']).toContain(winner.state);
      } finally {
        await clientA.$disconnect();
        await clientB.$disconnect();
      }
    });

    it('uses issued_at plus 3600 seconds and rejects consume at or after expires_at', async () => {
      const createdOperator = await prisma.osvCanaryInstanceOperatorIdentity.create({
        data: operator({ establishedAt: PAST_ISSUED_AT, createdAt: PAST_ISSUED_AT }),
      });
      const request = await prisma.osvRuntimeSynchronizationRequest.create({
        data: canaryRequest({ requestedAt: PAST_ISSUED_AT, createdAt: PAST_ISSUED_AT }),
      });
      const run = await prisma.osvRuntimeSynchronizationRun.create({
        data: canaryRun(request, { createdAt: PAST_ISSUED_AT, updatedAt: PAST_ISSUED_AT }),
      });
      const authorization = await prisma.osvCanaryAuthorization.create({
        data: listingAuthorization(createdOperator.id, {
          issuedAt: PAST_ISSUED_AT,
          expiresAt: PAST_EXPIRES_AT,
          createdAt: PAST_ISSUED_AT,
          runbookAcknowledgedAt: PAST_ACKNOWLEDGED_AT,
          haltAcknowledgedAt: PAST_ACKNOWLEDGED_AT,
          legalDecisionIssuedAt: new Date('2026-09-08T09:00:00.000Z'),
          legalDecisionRevalidationBoundaryAt: new Date('2026-09-08T09:30:00.000Z'),
        }),
      });
      const atBoundary = await prisma.$executeRaw`
        UPDATE "osv_canary_authorization"
        SET "state" = 'consumed',
            "consumed_at" = CURRENT_TIMESTAMP,
            "consumed_by_synchronization_request_id" = ${request.id}::uuid,
            "consumed_by_synchronization_run_id" = ${run.id}::uuid
        WHERE "id" = ${authorization.id}::uuid
          AND "state" = 'issued'
          AND CURRENT_TIMESTAMP < "expires_at"
      `;
      expect(atBoundary).toBe(0);
      await expect(
        prisma.$executeRaw`
          UPDATE "osv_canary_authorization"
          SET "state" = 'consumed',
              "consumed_at" = ${PAST_ISSUED_AT},
              "consumed_by_synchronization_request_id" = ${request.id}::uuid,
              "consumed_by_synchronization_run_id" = ${run.id}::uuid
          WHERE "id" = ${authorization.id}::uuid
            AND "state" = 'issued'
        `,
      ).rejects.toThrow(/expired|restrict_violation/);
      const expired = await prisma.$executeRaw`
        UPDATE "osv_canary_authorization"
        SET "state" = 'expired',
            "terminal_at" = CURRENT_TIMESTAMP,
            "terminal_disposition" = 'expired'
        WHERE "id" = ${authorization.id}::uuid
          AND "state" = 'issued'
          AND CURRENT_TIMESTAMP >= "expires_at"
      `;
      expect(expired).toBe(1);
    });

    it('lets cancellation and completion race to one compatible terminal', async () => {
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
      const authorization = await prisma.osvCanaryAuthorization.create({
        data: listingAuthorization(createdOperator.id, window),
      });
      expect(await consumeIssued(authorization.id, request.id, run.id)).toBe(1);
      const clientA = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
      const clientB = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
      try {
        const results = await Promise.allSettled([
          clientA.$executeRaw`
            UPDATE "osv_canary_authorization"
            SET "state" = 'completed',
                "terminal_at" = CURRENT_TIMESTAMP,
                "terminal_disposition" = 'completed'
            WHERE "id" = ${authorization.id}::uuid
              AND "state" = 'consumed'
          `,
          clientB.$executeRaw`
            UPDATE "osv_canary_authorization"
            SET "state" = 'cancelled',
                "terminal_at" = CURRENT_TIMESTAMP,
                "terminal_disposition" = 'cancelled'
            WHERE "id" = ${authorization.id}::uuid
              AND "state" = 'consumed'
          `,
        ]);
        const updates = results.map((result) => (result.status === 'fulfilled' ? result.value : 0));
        expect(updates.filter((value) => value === 1)).toHaveLength(1);
        const winner = await prisma.osvCanaryAuthorization.findUniqueOrThrow({
          where: { id: authorization.id },
        });
        expect(['completed', 'cancelled']).toContain(winner.state);
        expect(winner.consumedBySynchronizationRunId).toBe(run.id);
      } finally {
        await clientA.$disconnect();
        await clientB.$disconnect();
      }
    });

    it('keeps identical operator and authorization inserts to one authority', async () => {
      const identity = operator();
      const first = await Promise.allSettled([
        prisma.osvCanaryInstanceOperatorIdentity.create({ data: identity }),
        prisma.osvCanaryInstanceOperatorIdentity.create({ data: identity }),
      ]);
      expect(first.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
      expect(first.filter((result) => result.status === 'rejected')).toHaveLength(1);

      const createdOperator = await prisma.osvCanaryInstanceOperatorIdentity.findUniqueOrThrow({
        where: { id: identity.id },
      });
      const authorization = listingAuthorization(createdOperator.id);
      const second = await Promise.allSettled([
        prisma.osvCanaryAuthorization.create({ data: authorization }),
        prisma.osvCanaryAuthorization.create({ data: authorization }),
      ]);
      expect(second.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
      expect(second.filter((result) => result.status === 'rejected')).toHaveLength(1);
      await expect(
        prisma.osvCanaryAuthorization.create({
          data: listingAuthorization(createdOperator.id, {
            id: authorization.id,
            authorizationPurpose: 'approved_listing_repetition',
          }),
        }),
      ).rejects.toThrow();
    });

    it('forbids deleting operator identity, authorization, request, or run evidence', async () => {
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
      const authorization = await prisma.osvCanaryAuthorization.create({
        data: listingAuthorization(createdOperator.id, window),
      });
      expect(await consumeIssued(authorization.id, request.id, run.id)).toBe(1);
      await expect(
        prisma.osvCanaryAuthorization.delete({ where: { id: authorization.id } }),
      ).rejects.toThrow();
      await expect(
        prisma.osvCanaryInstanceOperatorIdentity.delete({ where: { id: createdOperator.id } }),
      ).rejects.toThrow();
      await expect(
        prisma.osvRuntimeSynchronizationRequest.delete({ where: { id: request.id } }),
      ).rejects.toThrow();
      await expect(
        prisma.osvRuntimeSynchronizationRun.delete({ where: { id: run.id } }),
      ).rejects.toThrow();
      await expect(
        prisma.osvCanaryAuthorization.update({
          where: { id: authorization.id },
          data: { phase: 'bounded_body' },
        }),
      ).rejects.toThrow();
      await expect(
        prisma.osvCanaryAuthorization.update({
          where: { id: authorization.id },
          data: { state: 'issued', consumedAt: null },
        }),
      ).rejects.toThrow();
    });

    it('revokes an issued operator identity once and keeps authorization evidence', async () => {
      const createdOperator = await prisma.osvCanaryInstanceOperatorIdentity.create({
        data: operator(),
      });
      const authorization = await prisma.osvCanaryAuthorization.create({
        data: listingAuthorization(createdOperator.id),
      });
      const revoked = await prisma.osvCanaryInstanceOperatorIdentity.update({
        where: { id: createdOperator.id },
        data: { status: 'revoked', revokedAt: TERMINAL_AT },
      });
      expect(revoked.status).toBe('revoked');
      await expect(
        prisma.osvCanaryInstanceOperatorIdentity.update({
          where: { id: createdOperator.id },
          data: { status: 'active', revokedAt: null },
        }),
      ).rejects.toThrow();
      expect(await prisma.osvCanaryAuthorization.count({ where: { id: authorization.id } })).toBe(
        1,
      );
    });

    it('rejects bounded-body review of issued, in-progress, mismatched, or reused listing evidence', async () => {
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
      const issuedListing = await prisma.osvCanaryAuthorization.create({
        data: listingAuthorization(createdOperator.id, window),
      });
      await expect(
        prisma.osvCanaryAuthorization.create({
          data: boundedBodyAuthorization(createdOperator.id, {
            id: issuedListing.id,
            requestId: request.id,
            runId: run.id,
          }),
        }),
      ).rejects.toThrow(/completed|restrict_violation|listing review/);

      expect(await consumeIssued(issuedListing.id, request.id, run.id)).toBe(1);
      await expect(
        prisma.osvCanaryAuthorization.create({
          data: boundedBodyAuthorization(createdOperator.id, {
            id: issuedListing.id,
            requestId: request.id,
            runId: run.id,
          }),
        }),
      ).rejects.toThrow(/completed|restrict_violation|listing review/);

      expect(await completeConsumed(issuedListing.id)).toBe(1);
      const completed = await prisma.osvCanaryAuthorization.findUniqueOrThrow({
        where: { id: issuedListing.id },
      });
      const listing = {
        id: issuedListing.id,
        requestId: request.id,
        runId: run.id,
        terminalAt: completed.terminalAt as Date,
      };
      const otherRequest = await prisma.osvRuntimeSynchronizationRequest.create({
        data: canaryRequest({ requestedAt: window.issuedAt, createdAt: window.issuedAt }),
      });
      const otherRun = await prisma.osvRuntimeSynchronizationRun.create({
        data: canaryRun(otherRequest, { createdAt: window.issuedAt, updatedAt: window.issuedAt }),
      });
      await expect(
        prisma.osvCanaryAuthorization.create({
          data: bodyAuthorization(createdOperator.id, {
            ...listing,
            requestId: otherRequest.id,
            runId: otherRun.id,
          }),
        }),
      ).rejects.toThrow(/match the consumed listing|restrict_violation|listing review/);
      await expect(
        prisma.osvCanaryAuthorization.create({
          data: bodyAuthorization(createdOperator.id, listing, {
            runtimeVersionSetFingerprint: OTHER_FINGERPRINT,
          }),
        }),
      ).rejects.toThrow(/fingerprint|restrict_violation|listing review/);

      const firstBody = await prisma.osvCanaryAuthorization.create({
        data: bodyAuthorization(createdOperator.id, listing),
      });
      expect(firstBody.listingAuthorizationId).toBe(issuedListing.id);
      await expect(
        prisma.osvCanaryAuthorization.create({
          data: bodyAuthorization(createdOperator.id, listing, {
            listingReviewId: randomUUID(),
          }),
        }),
      ).rejects.toThrow();
    });

    it('rejects listing legal decision reuse as body legal authority and production scope', async () => {
      const context = await seedCompletedListing();
      const listingLegalId = randomUUID();
      await expect(
        prisma.osvCanaryAuthorization.create({
          data: bodyAuthorization(context.operatorId, context.listing, {
            legalDecisionId: listingLegalId,
            bodyLegalDecisionId: listingLegalId,
          }),
        }),
      ).rejects.toThrow();
      await expect(
        prisma.osvCanaryAuthorization.create({
          data: listingAuthorization(context.operatorId, {
            workScope: 'osv_runtime_production_scope_six_prefix_v1',
          }),
        }),
      ).rejects.toThrow();
    });

    it('keeps canary tables free of tenant, token, body, credential, and Finding columns', async () => {
      const forbidden = await prisma.$queryRaw<Array<{ table_name: string; column_name: string }>>`
      SELECT table_name, column_name
      FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name IN (
          'osv_canary_instance_operator_identity',
          'osv_canary_authorization'
        )
        AND column_name IN (
          'organization_id',
          'tenant_id',
          'user_id',
          'tenant_user_id',
          'asset_id',
          'component_id',
          'component_occurrence_id',
          'finding_id',
          'finding_observation_id',
          'evidence_id',
          'risk_calculation_id',
          'password',
          'api_key',
          'bearer_token',
          'cookie',
          'private_key',
          'holder_token',
          'holder_token_digest',
          'page_token',
          'token_digest',
          'body',
          'url',
          'payload'
        )
    `;
      expect(forbidden).toEqual([]);
      const jsonColumns = await prisma.$queryRaw<Array<{ column_name: string }>>`
      SELECT column_name
      FROM information_schema.columns
      WHERE table_schema = 'public'
        AND table_name LIKE 'osv_canary_%'
        AND data_type IN ('json', 'jsonb')
    `;
      expect(jsonColumns).toEqual([]);
      const cascadeDeletes = await prisma.$queryRaw<Array<{ name: string }>>`
      SELECT c.conname AS name
      FROM pg_constraint c
      JOIN pg_class rel ON rel.oid = c.conrelid
      WHERE c.contype = 'f'
        AND rel.relname LIKE 'osv_canary_%'
        AND c.confdeltype = 'c'
    `;
      expect(cascadeDeletes).toEqual([]);
      expect(await prisma.finding.count()).toBe(0);
      expect(await prisma.osvActiveCatalogPointer.count()).toBe(0);
    });

    it('keeps schema free of production composition while exposing uncomposed adapters', () => {
      expect(existsSync(path.join(srcDir, 'osv-canary-authorization-persistence.ts'))).toBe(true);
      const schema = readFileSync(path.join(srcDir, '../prisma/schema.prisma'), 'utf8');
      expect(schema).toContain('model OsvCanaryInstanceOperatorIdentity');
      expect(schema).toContain('model OsvCanaryAuthorization');
      expect(schema).not.toContain('createOsvCanaryAuthorizationPersistence');
      const production = [
        'apps/worker/src/main.ts',
        'apps/worker/src/app.ts',
        'apps/worker/src/queue-job-router.ts',
        'apps/api/src/app.ts',
        'apps/api/src/server.ts',
      ] as const;
      for (const relative of production) {
        const source = readFileSync(path.join(workspaceRoot, relative), 'utf8');
        expect(source, relative).not.toContain('OsvCanaryAuthorization');
        expect(source, relative).not.toContain('osv_canary_authorization');
        expect(source, relative).not.toContain('intelligence.osv.sync');
      }
    });
  },
);
