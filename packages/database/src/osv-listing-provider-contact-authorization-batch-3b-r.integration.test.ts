/**
 * Session 13 Batch 3B-R provider-free cross-layer rehearsal.
 * Uses actual canary, request/run, and provider-contact adapters against
 * disposable PostgreSQL. Evaluation remains uncomposed. No provider DNS,
 * HTTP, lease acquisition, timer, activation, matching, or Finding writes.
 */

import { inspect } from 'node:util';
import { randomUUID } from 'node:crypto';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { PrismaClient } from '@prisma/client';
import {
  createClosedOsvRuntimeSyncJobInput,
  createOsvCanaryActivationProhibitionAcknowledgement,
  createOsvCanaryAuthorizationConsumePersistenceCommand,
  createOsvCanaryAuthorizationEnsureCommand,
  createOsvCanaryAutomaticRetryProhibitionAcknowledgement,
  createOsvCanaryHaltControlAcknowledgement,
  createOsvCanaryLegalDecisionReference,
  createOsvCanaryOperatorEnsureCommand,
  createOsvCanaryOperatorRevokeCommand,
  createOsvCanaryRunbookAcknowledgement,
  createOsvListingProviderContactAuthorizationConsumeCommand,
  createOsvListingProviderContactAuthorizationInspectForRunQuery,
  createOsvListingProviderContactAuthorizationIssueCommand,
  createOsvListingProviderContactAuthorizationLookupQuery,
  createOsvListingProviderContactAuthorizationRevokeCommand,
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
  osvCanaryRuntimeVersionSetFingerprint,
  type OsvListingProviderContactPersistenceResult,
} from '@patchpilot/vulnerability-intelligence';

import { createOsvCanaryAuthorizationPersistence } from './osv-canary-authorization-persistence.js';
import { createOsvListingProviderContactAuthorizationPersistence } from './osv-listing-provider-contact-authorization-persistence.js';
import { createOsvRuntimeCoordinationPersistence } from './osv-runtime-coordination-persistence.js';
import {
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
} from './integration-database.js';

const ACK = '2026-09-08T11:00:00Z';
const LEGAL_ISSUED = '2026-09-08T10:00:00Z';
const LEGAL_REVALIDATE = '2099-09-09T10:00:00Z';
const FINGERPRINT = osvCanaryRuntimeVersionSetFingerprint();
const ARTIFACT = 'patchpilot.canary.artifact.1';
const CANARY_SCOPE = 'osv_runtime_canary_scope_crates_io_rustsec_v1';
const LEASE_SCOPE = 'osv_runtime_lease_scope_osv_gcs_public_export_v1';
const APPLICATION_TESTED = 'application_control_implemented_and_tested';
const DEPLOYMENT_CONFIGURED = 'deployment_control_configured';
const WRONG_FINGERPRINT = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';

function expectOk<T>(
  result:
    | OsvListingProviderContactPersistenceResult<T>
    | { ok: true; value: T }
    | { ok: false; code: string },
  label: string,
): T {
  if (!result.ok) {
    throw new Error(`${label}: ${result.code}`);
  }
  return result.value;
}

function uuid(): string {
  return randomUUID();
}

function displayLabel(): string {
  return `canary-op-${uuid().slice(0, 8)}`;
}

describe(
  'session 13 Batch 3B-R listing provider-contact authorization chain rehearsal',
  {
    timeout: 180_000,
  },
  () => {
    let databaseName: string;
    let databaseUrl: string;
    let admin: PrismaClient;
    let prisma: PrismaClient;
    let canary: ReturnType<typeof createOsvCanaryAuthorizationPersistence>;
    let coordination: ReturnType<typeof createOsvRuntimeCoordinationPersistence>;
    let adapters: ReturnType<typeof createOsvListingProviderContactAuthorizationPersistence>;

    beforeAll(async () => {
      const ephemeral = await createEphemeralDatabase('it');
      databaseName = ephemeral.databaseName;
      databaseUrl = ephemeral.databaseUrl;
      admin = ephemeral.admin;
      await deployMigrations(ephemeral.databaseUrl);
      prisma = new PrismaClient({
        datasources: { db: { url: ephemeral.databaseUrl } },
      });
      canary = createOsvCanaryAuthorizationPersistence(prisma);
      coordination = createOsvRuntimeCoordinationPersistence(prisma);
      adapters = createOsvListingProviderContactAuthorizationPersistence(prisma);
    });

    afterAll(async () => {
      if (prisma !== undefined) {
        await prisma.$disconnect();
      }
      if (admin !== undefined && databaseName !== undefined) {
        await dropEphemeralDatabase(admin, databaseName);
      }
    });

    async function ensureOperator(operatorAttestationId = uuid(), label = displayLabel()) {
      return expectOk(
        await canary.operators.ensure(
          expectOk(
            createOsvCanaryOperatorEnsureCommand({
              operatorAttestationId,
              identityType: 'instance_operator',
              authenticationSource: 'local_host_control_of_one_shot_administrative_command',
              displayLabel: label,
              provenanceIdentifier: 'configured_instance_operator_attestation_v1',
            }),
            'operator command',
          ),
        ),
        'operator ensure',
      );
    }

    function listingLegal(decisionId = uuid(), evidenceSetId = uuid()) {
      return expectOk(
        createOsvCanaryLegalDecisionReference({
          decisionId,
          sourceRegistryVersion: 'osv_source_license_registry_v1',
          sourceIdentifier: 'rustsec_advisory_database',
          family: 'RUSTSEC',
          phase: 'listing_only',
          permittedOperation: 'list_object_metadata',
          issuedAt: LEGAL_ISSUED,
          revalidationBoundaryAt: LEGAL_REVALIDATE,
          responsibleRole:
            'instance_legal_and_provenance_reviewer_countersigned_by_instance_operator',
          evidenceSetId,
        }),
        'listing legal',
      );
    }

    async function ensureListing(operatorAttestationId: string, authorizationId = uuid()) {
      return expectOk(
        await canary.authorizations.ensure(
          expectOk(
            createOsvCanaryAuthorizationEnsureCommand({
              authorizationId,
              operatorAttestationId,
              phase: 'listing_only',
              authorizationPurpose: 'initial_listing_compatibility',
              legalDecisionReference: listingLegal(),
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
    }

    async function seedCanaryRun() {
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
      const idempotency = expectOk(
        createOsvRuntimeJobIdempotencyIdentity({
          workScope: payload.workScope,
          reason: payload.synchronizationReason,
          versionSetFingerprint: payload.versionSetFingerprint,
          requestKind: 'operator_request',
          schedulerWindowId: null,
          operatorRequestId: uuid(),
        }),
        'idempotency',
      );
      const request = expectOk(
        await coordination.requests.ensure(
          expectOk(
            createOsvRuntimeSynchronizationRequestEnsureCommand({
              payload,
              idempotency,
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
      return { request: request.request, run: run.run };
    }

    async function seedConsumedListing() {
      const operator = await ensureOperator();
      const operatorAttestationId = operator.operator.identity.operatorAttestationId;
      const listing = await ensureListing(operatorAttestationId);
      const sourceId = listing.authorization.snapshot.record.authorizationId;
      const sourceLegalDecisionId =
        listing.authorization.snapshot.record.legalDecisionReference.decisionId;
      const { request, run } = await seedCanaryRun();
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
              requestId: request.id,
              runId: run.id,
            }),
            'canary consume command',
          ),
        ),
        'canary consume',
      );
      return {
        operatorAttestationId,
        sourceId,
        sourceLegalDecisionId,
        requestId: request.id,
        runId: run.id,
      };
    }

    async function insertPreflight(input: {
      readonly operatorId: string;
      readonly sourceId: string;
      readonly requestId: string;
      readonly runId: string;
      readonly activePointer: string;
      readonly zeroFinding: string;
    }) {
      const capturedAt = new Date('2026-09-08T11:30:00.000Z');
      return prisma.osvCanaryProviderFreePreflightAttestation.create({
        data: {
          id: uuid(),
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
          activePointerBaselineIdentity: input.activePointer,
          zeroFindingBaselineIdentity: input.zeroFinding,
          outcome: 'canary_execution_preflight_passed_provider_contact_not_authorized',
          providerContactAuthorized: false,
          executionPermitted: false,
          acceptedForProviderContactAuth: true,
          capturedAt,
          createdAt: capturedAt,
        },
      });
    }

    function evidence(sourceCanaryLegalDecisionId: string) {
      return {
        legalApproval: expectOk(
          createOsvListingProviderContactLegalApproval({
            decisionId: uuid(),
            sourceCanaryLegalDecisionId,
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
          createOsvListingProviderContactHaltProcedureAcknowledgement({ acknowledgedAt: ACK }),
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
      };
    }

    async function issueFresh() {
      const listing = await seedConsumedListing();
      const activePointer = uuid();
      const zeroFinding = uuid();
      const preflight = await insertPreflight({
        operatorId: listing.operatorAttestationId,
        sourceId: listing.sourceId,
        requestId: listing.requestId,
        runId: listing.runId,
        activePointer,
        zeroFinding,
      });
      const packed = evidence(listing.sourceLegalDecisionId);
      const command = expectOk(
        createOsvListingProviderContactAuthorizationIssueCommand({
          providerContactAuthorizationId: uuid(),
          sourceCanaryAuthorizationId: listing.sourceId,
          operatorAttestationId: listing.operatorAttestationId,
          synchronizationRequestId: listing.requestId,
          synchronizationRunId: listing.runId,
          preflightEvidenceId: preflight.id,
          activePointerBaselineIdentity: activePointer,
          zeroFindingBaselineIdentity: zeroFinding,
          ...packed,
        }),
        'issue command',
      );
      const issued = expectOk(await adapters.issue(command), 'issue');
      return { listing, preflight, packed, command, issued };
    }

    function consumeCommand(issued: Awaited<ReturnType<typeof issueFresh>>) {
      return expectOk(
        createOsvListingProviderContactAuthorizationConsumeCommand({
          authorizationId: issued.issued.record.providerContactAuthorizationId,
          operatorAttestationId: issued.listing.operatorAttestationId,
          sourceCanaryAuthorizationId: issued.listing.sourceId,
          synchronizationRequestId: issued.listing.requestId,
          synchronizationRunId: issued.listing.runId,
          preflightEvidenceId: issued.preflight.id,
          providerIdentity: 'rustsec_advisory_database',
          approvedPrefix: 'crates.io/',
          canaryPolicyIdentifier: 'osv_disabled_first_provider_canary_policy_v1',
          listingBudgetProfile: 'osv_canary_listing_only_budget_v1',
          runtimeVersionSetFingerprint: FINGERPRINT,
          legalDecisionId: issued.issued.record.legalDecisionId,
          egressEvidenceId: issued.issued.record.egressEvidenceId,
          deploymentId: issued.issued.record.deploymentId,
        }),
        'consume command',
      );
    }

    it('ends the listing-only chain after single-use consumption without provider execution', async () => {
      const findingsBefore = await prisma.finding.count();
      const leasesBefore = await prisma.osvRuntimeLeaseProjection.count();
      const fresh = await issueFresh();
      expect(fresh.issued.status).toBe('created');
      expect(fresh.issued.record.state).toBe('issued');
      expect(fresh.issued.record.providerBodyProhibited).toBe(true);
      expect(fresh.issued.record.activationProhibited).toBe(true);
      expect(fresh.preflight.providerContactAuthorized).toBe(false);
      const inspected = expectOk(
        await adapters.inspectForRun(
          expectOk(
            createOsvListingProviderContactAuthorizationInspectForRunQuery({
              authorizationId: fresh.issued.record.providerContactAuthorizationId,
              synchronizationRequestId: fresh.listing.requestId,
              synchronizationRunId: fresh.listing.runId,
            }),
            'inspect query',
          ),
        ),
        'inspect',
      );
      expect(inspected.status).toBe('issued');
      expect(inspected.record?.state).toBe('issued');
      const consumed = expectOk(await adapters.consume(consumeCommand(fresh)), 'consume');
      expect(consumed.outcome).toBe('consumed');
      expect(consumed.providerOperationExecuted).toBe(false);
      expect(consumed.remainingRuntimeGatesRequired).toBe(true);
      expect(consumed.executionPermitted).toBe(false);
      const replay = expectOk(await adapters.consume(consumeCommand(fresh)), 'same-run replay');
      expect(replay.outcome).toBe('already_consumed_same_run');
      expect(replay.record.consumedAt).toBe(consumed.record.consumedAt);
      expect(replay.providerOperationExecuted).toBe(false);
      expect(replay.executionPermitted).toBe(false);
      const otherRun = await seedCanaryRun();
      const different = await adapters.consume(
        expectOk(
          createOsvListingProviderContactAuthorizationConsumeCommand({
            authorizationId: fresh.issued.record.providerContactAuthorizationId,
            operatorAttestationId: fresh.listing.operatorAttestationId,
            sourceCanaryAuthorizationId: fresh.listing.sourceId,
            synchronizationRequestId: otherRun.request.id,
            synchronizationRunId: otherRun.run.id,
            preflightEvidenceId: fresh.preflight.id,
            providerIdentity: 'rustsec_advisory_database',
            approvedPrefix: 'crates.io/',
            canaryPolicyIdentifier: 'osv_disabled_first_provider_canary_policy_v1',
            listingBudgetProfile: 'osv_canary_listing_only_budget_v1',
            runtimeVersionSetFingerprint: FINGERPRINT,
            legalDecisionId: fresh.issued.record.legalDecisionId,
            egressEvidenceId: fresh.issued.record.egressEvidenceId,
            deploymentId: fresh.issued.record.deploymentId,
          }),
          'different-run command',
        ),
      );
      expect(different.ok).toBe(false);
      if (different.ok) {
        throw new Error('expected different-run rejection');
      }
      expect(different.code).toBe('already_consumed_other_run');
      expect(`${JSON.stringify(different)}\n${inspect(different)}`).not.toContain(otherRun.run.id);
      expect(await prisma.finding.count()).toBe(findingsBefore);
      expect(await prisma.osvRuntimeLeaseProjection.count()).toBe(leasesBefore);
      expect(await prisma.vulnerability.count()).toBe(0);
    });

    it('rejects operator, canary, request, run, preflight, and policy substitutions', async () => {
      const fresh = await issueFresh();
      const otherOperator = await ensureOperator();
      const wrongOperator = await adapters.consume(
        expectOk(
          createOsvListingProviderContactAuthorizationConsumeCommand({
            authorizationId: fresh.issued.record.providerContactAuthorizationId,
            operatorAttestationId: otherOperator.operator.identity.operatorAttestationId,
            sourceCanaryAuthorizationId: fresh.listing.sourceId,
            synchronizationRequestId: fresh.listing.requestId,
            synchronizationRunId: fresh.listing.runId,
            preflightEvidenceId: fresh.preflight.id,
            providerIdentity: 'rustsec_advisory_database',
            approvedPrefix: 'crates.io/',
            canaryPolicyIdentifier: 'osv_disabled_first_provider_canary_policy_v1',
            listingBudgetProfile: 'osv_canary_listing_only_budget_v1',
            runtimeVersionSetFingerprint: FINGERPRINT,
            legalDecisionId: fresh.issued.record.legalDecisionId,
            egressEvidenceId: fresh.issued.record.egressEvidenceId,
            deploymentId: fresh.issued.record.deploymentId,
          }),
          'wrong operator command',
        ),
      );
      expect(wrongOperator.ok).toBe(false);
      const otherListing = await seedConsumedListing();
      const wrongCanary = await adapters.consume(
        expectOk(
          createOsvListingProviderContactAuthorizationConsumeCommand({
            authorizationId: fresh.issued.record.providerContactAuthorizationId,
            operatorAttestationId: fresh.listing.operatorAttestationId,
            sourceCanaryAuthorizationId: otherListing.sourceId,
            synchronizationRequestId: fresh.listing.requestId,
            synchronizationRunId: fresh.listing.runId,
            preflightEvidenceId: fresh.preflight.id,
            providerIdentity: 'rustsec_advisory_database',
            approvedPrefix: 'crates.io/',
            canaryPolicyIdentifier: 'osv_disabled_first_provider_canary_policy_v1',
            listingBudgetProfile: 'osv_canary_listing_only_budget_v1',
            runtimeVersionSetFingerprint: FINGERPRINT,
            legalDecisionId: fresh.issued.record.legalDecisionId,
            egressEvidenceId: fresh.issued.record.egressEvidenceId,
            deploymentId: fresh.issued.record.deploymentId,
          }),
          'wrong canary command',
        ),
      );
      expect(wrongCanary.ok).toBe(false);
      const otherRun = await seedCanaryRun();
      const wrongRequest = await adapters.consume(
        expectOk(
          createOsvListingProviderContactAuthorizationConsumeCommand({
            authorizationId: fresh.issued.record.providerContactAuthorizationId,
            operatorAttestationId: fresh.listing.operatorAttestationId,
            sourceCanaryAuthorizationId: fresh.listing.sourceId,
            synchronizationRequestId: otherRun.request.id,
            synchronizationRunId: fresh.listing.runId,
            preflightEvidenceId: fresh.preflight.id,
            providerIdentity: 'rustsec_advisory_database',
            approvedPrefix: 'crates.io/',
            canaryPolicyIdentifier: 'osv_disabled_first_provider_canary_policy_v1',
            listingBudgetProfile: 'osv_canary_listing_only_budget_v1',
            runtimeVersionSetFingerprint: FINGERPRINT,
            legalDecisionId: fresh.issued.record.legalDecisionId,
            egressEvidenceId: fresh.issued.record.egressEvidenceId,
            deploymentId: fresh.issued.record.deploymentId,
          }),
          'wrong request command',
        ),
      );
      expect(wrongRequest.ok).toBe(false);
      const wrongPreflight = await adapters.consume(
        expectOk(
          createOsvListingProviderContactAuthorizationConsumeCommand({
            authorizationId: fresh.issued.record.providerContactAuthorizationId,
            operatorAttestationId: fresh.listing.operatorAttestationId,
            sourceCanaryAuthorizationId: fresh.listing.sourceId,
            synchronizationRequestId: fresh.listing.requestId,
            synchronizationRunId: fresh.listing.runId,
            preflightEvidenceId: uuid(),
            providerIdentity: 'rustsec_advisory_database',
            approvedPrefix: 'crates.io/',
            canaryPolicyIdentifier: 'osv_disabled_first_provider_canary_policy_v1',
            listingBudgetProfile: 'osv_canary_listing_only_budget_v1',
            runtimeVersionSetFingerprint: FINGERPRINT,
            legalDecisionId: fresh.issued.record.legalDecisionId,
            egressEvidenceId: fresh.issued.record.egressEvidenceId,
            deploymentId: fresh.issued.record.deploymentId,
          }),
          'wrong preflight command',
        ),
      );
      expect(wrongPreflight.ok).toBe(false);
      if (wrongPreflight.ok) {
        throw new Error('expected preflight mismatch');
      }
      expect(wrongPreflight.code).toBe('preflight_mismatch');
      expect(
        createOsvListingProviderContactAuthorizationConsumeCommand({
          authorizationId: fresh.issued.record.providerContactAuthorizationId,
          operatorAttestationId: fresh.listing.operatorAttestationId,
          sourceCanaryAuthorizationId: fresh.listing.sourceId,
          synchronizationRequestId: fresh.listing.requestId,
          synchronizationRunId: fresh.listing.runId,
          preflightEvidenceId: fresh.preflight.id,
          providerIdentity: 'github_advisory_database',
          approvedPrefix: 'crates.io/',
          canaryPolicyIdentifier: 'osv_disabled_first_provider_canary_policy_v1',
          listingBudgetProfile: 'osv_canary_listing_only_budget_v1',
          runtimeVersionSetFingerprint: FINGERPRINT,
          legalDecisionId: fresh.issued.record.legalDecisionId,
          egressEvidenceId: fresh.issued.record.egressEvidenceId,
          deploymentId: fresh.issued.record.deploymentId,
        }).ok,
      ).toBe(false);
      expect(
        createOsvListingProviderContactAuthorizationConsumeCommand({
          authorizationId: fresh.issued.record.providerContactAuthorizationId,
          operatorAttestationId: fresh.listing.operatorAttestationId,
          sourceCanaryAuthorizationId: fresh.listing.sourceId,
          synchronizationRequestId: fresh.listing.requestId,
          synchronizationRunId: fresh.listing.runId,
          preflightEvidenceId: fresh.preflight.id,
          providerIdentity: 'rustsec_advisory_database',
          approvedPrefix: 'npm/',
          canaryPolicyIdentifier: 'osv_disabled_first_provider_canary_policy_v1',
          listingBudgetProfile: 'osv_canary_listing_only_budget_v1',
          runtimeVersionSetFingerprint: FINGERPRINT,
          legalDecisionId: fresh.issued.record.legalDecisionId,
          egressEvidenceId: fresh.issued.record.egressEvidenceId,
          deploymentId: fresh.issued.record.deploymentId,
        }).ok,
      ).toBe(false);
      expect(
        createOsvListingProviderContactAuthorizationConsumeCommand({
          authorizationId: fresh.issued.record.providerContactAuthorizationId,
          operatorAttestationId: fresh.listing.operatorAttestationId,
          sourceCanaryAuthorizationId: fresh.listing.sourceId,
          synchronizationRequestId: fresh.listing.requestId,
          synchronizationRunId: fresh.listing.runId,
          preflightEvidenceId: fresh.preflight.id,
          providerIdentity: 'rustsec_advisory_database',
          approvedPrefix: 'crates.io/',
          canaryPolicyIdentifier: 'osv_listing_pagination_policy_v1',
          listingBudgetProfile: 'osv_canary_listing_only_budget_v1',
          runtimeVersionSetFingerprint: FINGERPRINT,
          legalDecisionId: fresh.issued.record.legalDecisionId,
          egressEvidenceId: fresh.issued.record.egressEvidenceId,
          deploymentId: fresh.issued.record.deploymentId,
        }).ok,
      ).toBe(false);
      expect(
        createOsvListingProviderContactAuthorizationConsumeCommand({
          authorizationId: fresh.issued.record.providerContactAuthorizationId,
          operatorAttestationId: fresh.listing.operatorAttestationId,
          sourceCanaryAuthorizationId: fresh.listing.sourceId,
          synchronizationRequestId: fresh.listing.requestId,
          synchronizationRunId: fresh.listing.runId,
          preflightEvidenceId: fresh.preflight.id,
          providerIdentity: 'rustsec_advisory_database',
          approvedPrefix: 'crates.io/',
          canaryPolicyIdentifier: 'osv_disabled_first_provider_canary_policy_v1',
          listingBudgetProfile: 'osv_canary_listing_only_budget_v1',
          runtimeVersionSetFingerprint: WRONG_FINGERPRINT,
          legalDecisionId: fresh.issued.record.legalDecisionId,
          egressEvidenceId: fresh.issued.record.egressEvidenceId,
          deploymentId: fresh.issued.record.deploymentId,
        }).ok,
      ).toBe(false);
      const stored = expectOk(
        await adapters.findById(
          expectOk(
            createOsvListingProviderContactAuthorizationLookupQuery({
              authorizationId: fresh.issued.record.providerContactAuthorizationId,
            }),
            'after substitution lookup',
          ),
        ),
        'after substitution stored',
      );
      expect(stored.state).toBe('issued');
      expect(stored.consumedAt).toBeNull();
    });

    it('keeps issuance idempotent, conflicts immutable, and concurrent consume single-winner', async () => {
      const fresh = await issueFresh();
      const replay = expectOk(await adapters.issue(fresh.command), 'duplicate issue');
      expect(replay.status).toBe('already_applied');
      const conflict = await adapters.issue(
        expectOk(
          createOsvListingProviderContactAuthorizationIssueCommand({
            providerContactAuthorizationId: uuid(),
            sourceCanaryAuthorizationId: fresh.listing.sourceId,
            operatorAttestationId: fresh.listing.operatorAttestationId,
            synchronizationRequestId: fresh.listing.requestId,
            synchronizationRunId: fresh.listing.runId,
            preflightEvidenceId: fresh.preflight.id,
            activePointerBaselineIdentity: fresh.command.activePointerBaselineIdentity,
            zeroFindingBaselineIdentity: fresh.command.zeroFindingBaselineIdentity,
            ...evidence(fresh.listing.sourceLegalDecisionId),
          }),
          'conflict command',
        ),
      );
      expect(conflict.ok).toBe(false);
      if (conflict.ok) {
        throw new Error('expected immutable_conflict');
      }
      expect(conflict.code).toBe('immutable_conflict');

      const concurrent = await issueFresh();
      const consume = consumeCommand(concurrent);
      const clients = [
        new PrismaClient({ datasources: { db: { url: databaseUrl } } }),
        new PrismaClient({ datasources: { db: { url: databaseUrl } } }),
      ];
      try {
        const left = createOsvListingProviderContactAuthorizationPersistence(clients[0]!);
        const right = createOsvListingProviderContactAuthorizationPersistence(clients[1]!);
        const [leftResult, rightResult] = await Promise.all([
          left.consume(consume),
          right.consume(consume),
        ]);
        const outcomes = [leftResult, rightResult].map((result) =>
          result.ok ? result.value.outcome : result.code,
        );
        expect(outcomes.filter((outcome) => outcome === 'consumed').length).toBe(1);
        expect(
          outcomes.filter(
            (outcome) => outcome === 'consumed' || outcome === 'already_consumed_same_run',
          ).length,
        ).toBeGreaterThanOrEqual(1);
        const stored = expectOk(
          await adapters.findById(
            expectOk(
              createOsvListingProviderContactAuthorizationLookupQuery({
                authorizationId: concurrent.issued.record.providerContactAuthorizationId,
              }),
              'concurrent lookup',
            ),
          ),
          'concurrent stored',
        );
        expect(stored.state).toBe('consumed_for_listing_execution');
      } finally {
        await Promise.all(clients.map((client) => client.$disconnect()));
      }
    });

    it('refuses revoked and expired authority and does not acquire a lease', async () => {
      const leasesBefore = await prisma.osvRuntimeLeaseProjection.count();
      const fresh = await issueFresh();
      expectOk(
        await adapters.revoke(
          expectOk(
            createOsvListingProviderContactAuthorizationRevokeCommand({
              authorizationId: fresh.issued.record.providerContactAuthorizationId,
              operatorAttestationId: fresh.listing.operatorAttestationId,
            }),
            'revoke command',
          ),
        ),
        'revoke',
      );
      const consume = await adapters.consume(consumeCommand(fresh));
      expect(consume.ok).toBe(false);
      if (consume.ok) {
        throw new Error('expected revoked consume failure');
      }
      expect(consume.code).toBe('authorization_revoked');

      const live = await issueFresh();
      expectOk(
        await canary.operators.revoke(
          expectOk(
            createOsvCanaryOperatorRevokeCommand({
              operatorAttestationId: live.listing.operatorAttestationId,
            }),
            'operator revoke command',
          ),
        ),
        'operator revoke',
      );
      const afterOperator = await adapters.consume(consumeCommand(live));
      expect(afterOperator.ok).toBe(false);
      if (afterOperator.ok) {
        throw new Error('expected operator_revoked');
      }
      expect(afterOperator.code).toBe('operator_revoked');
      expect(await prisma.osvRuntimeLeaseProjection.count()).toBe(leasesBefore);
    });
  },
);
