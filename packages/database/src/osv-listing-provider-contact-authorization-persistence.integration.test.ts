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
const MARKERS = [
  'supersecret-password',
  'Bearer sk-live',
  'holder-token-proof',
  'pageToken=opaque',
  'provider-body-bytes',
  's3://bucket/locator',
  'this is legal prose about CC0',
  'org-tenant-id-marker',
  'finding-id-marker',
];

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

function confidential(value: unknown): string {
  return `${JSON.stringify(value)}\n${inspect(value, { depth: 8 })}`;
}

describe(
  'session 13 Batch 3B-A OSV listing provider-contact authorization adapters',
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
      readonly capturedAt?: Date;
    }) {
      const capturedAt = input.capturedAt ?? new Date('2026-09-08T11:30:00.000Z');
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

    it('issues listing-only authority once and treats exact duplicates as already_applied', async () => {
      const fresh = await issueFresh();
      expect(fresh.issued.status).toBe('created');
      expect(fresh.issued.record.state).toBe('issued');
      expect(fresh.issued.record.phase).toBe('listing_only');
      expect(fresh.issued.record.providerBodyProhibited).toBe(true);
      const replay = expectOk(await adapters.issue(fresh.command), 'duplicate issue');
      expect(replay.status).toBe('already_applied');
      expect(replay.record.providerContactAuthorizationId).toBe(
        fresh.issued.record.providerContactAuthorizationId,
      );
      expect(replay.record.issuedAt).toBe(fresh.issued.record.issuedAt);
      for (const marker of MARKERS) {
        expect(confidential(fresh.issued)).not.toContain(marker);
      }
    });

    it('rejects conflicting issuance against the same source without overwriting', async () => {
      const fresh = await issueFresh();
      const conflict = expectOk(
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
      );
      const result = await adapters.issue(conflict);
      expect(result.ok).toBe(false);
      if (result.ok) {
        throw new Error('expected immutable_conflict');
      }
      expect(result.code).toBe('immutable_conflict');
      const lookup = expectOk(
        await adapters.findById(
          expectOk(
            createOsvListingProviderContactAuthorizationLookupQuery({
              authorizationId: fresh.issued.record.providerContactAuthorizationId,
            }),
            'lookup',
          ),
        ),
        'lookup after conflict',
      );
      expect(lookup.providerContactAuthorizationId).toBe(
        fresh.issued.record.providerContactAuthorizationId,
      );
      expect(lookup.state).toBe('issued');
    });

    it('does not insert when preflight evidence is missing', async () => {
      const listing = await seedConsumedListing();
      const packed = evidence(listing.sourceLegalDecisionId);
      const authorizationId = uuid();
      const result = await adapters.issue(
        expectOk(
          createOsvListingProviderContactAuthorizationIssueCommand({
            providerContactAuthorizationId: authorizationId,
            sourceCanaryAuthorizationId: listing.sourceId,
            operatorAttestationId: listing.operatorAttestationId,
            synchronizationRequestId: listing.requestId,
            synchronizationRunId: listing.runId,
            preflightEvidenceId: uuid(),
            activePointerBaselineIdentity: uuid(),
            zeroFindingBaselineIdentity: uuid(),
            ...packed,
          }),
          'missing preflight command',
        ),
      );
      expect(result.ok).toBe(false);
      if (result.ok) {
        throw new Error('expected preflight failure');
      }
      expect(result.code).toBe('preflight_evidence_invalid');
      const lookup = await adapters.findById(
        expectOk(
          createOsvListingProviderContactAuthorizationLookupQuery({ authorizationId }),
          'absent lookup',
        ),
      );
      expect(lookup.ok).toBe(false);
    });

    it('inspects without consuming and consumes at most once for the exact run', async () => {
      const fresh = await issueFresh();
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
      expect(consumed.record.state).toBe('consumed_for_listing_execution');
      expect(consumed.record.consumedAt).not.toBeNull();
      const replay = expectOk(await adapters.consume(consumeCommand(fresh)), 'same-run replay');
      expect(replay.outcome).toBe('already_consumed_same_run');
      expect(replay.record.consumedAt).toBe(consumed.record.consumedAt);
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
      expect(confidential(different)).not.toContain(otherRun.run.id);
      const after = expectOk(
        await adapters.findById(
          expectOk(
            createOsvListingProviderContactAuthorizationLookupQuery({
              authorizationId: fresh.issued.record.providerContactAuthorizationId,
            }),
            'after consume lookup',
          ),
        ),
        'after consume',
      );
      expect(after.consumedAt).toBe(consumed.record.consumedAt);
      expect(after.state).toBe('consumed_for_listing_execution');
    });

    it('revokes issued authority and refuses to revoke consumed authority', async () => {
      const fresh = await issueFresh();
      const revoked = expectOk(
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
      expect(revoked.status).toBe('transitioned');
      expect(revoked.record.state).toBe('revoked');
      const replay = expectOk(
        await adapters.revoke(
          expectOk(
            createOsvListingProviderContactAuthorizationRevokeCommand({
              authorizationId: fresh.issued.record.providerContactAuthorizationId,
              operatorAttestationId: fresh.listing.operatorAttestationId,
            }),
            'revoke replay',
          ),
        ),
        'revoke replay',
      );
      expect(replay.status).toBe('already_applied');
      const consume = await adapters.consume(consumeCommand(fresh));
      expect(consume.ok).toBe(false);
      if (consume.ok) {
        throw new Error('expected revoked consume failure');
      }
      expect(consume.code).toBe('authorization_revoked');

      const live = await issueFresh();
      expectOk(await adapters.consume(consumeCommand(live)), 'consume before revoke');
      const afterConsume = await adapters.revoke(
        expectOk(
          createOsvListingProviderContactAuthorizationRevokeCommand({
            authorizationId: live.issued.record.providerContactAuthorizationId,
            operatorAttestationId: live.listing.operatorAttestationId,
          }),
          'revoke consumed',
        ),
      );
      expect(afterConsume.ok).toBe(false);
      if (afterConsume.ok) {
        throw new Error('expected consumed revoke failure');
      }
      expect(afterConsume.code).toBe('authorization_terminal');
    });

    it('treats database time equal to expiresAt as expired and does not consume', async () => {
      const listing = await seedConsumedListing();
      const activePointer = uuid();
      const zeroFinding = uuid();
      const issuedAt = new Date(Date.now() - 3_600_000);
      const preflight = await insertPreflight({
        operatorId: listing.operatorAttestationId,
        sourceId: listing.sourceId,
        requestId: listing.requestId,
        runId: listing.runId,
        activePointer,
        zeroFinding,
        capturedAt: new Date(issuedAt.getTime() - 1_000),
      });
      const packed = evidence(listing.sourceLegalDecisionId);
      const authorizationId = uuid();
      await prisma.$executeRaw`
      INSERT INTO "osv_listing_provider_contact_authorization" (
        "id", "authorization_schema_version", "source_canary_authorization_id",
        "operator_identity_id", "synchronization_request_id", "synchronization_run_id",
        "preflight_evidence_id", "phase", "provider_identity", "bucket_identity",
        "listing_api_path_policy", "listing_protocol", "approved_prefix", "family",
        "canary_policy_identifier", "listing_budget_profile", "work_scope", "lease_scope",
        "synchronization_reason", "runtime_architecture_identifier",
        "runtime_version_set_fingerprint", "query_grammar_policy", "transport_policy",
        "content_encoding_policy", "redirect_policy", "unused_ttl_seconds",
        "single_use_policy", "provider_retry_authorization", "provider_body_authorization",
        "parser_authorization", "catalog_activation_authorization", "matching_authorization",
        "finding_authorization", "legal_approval_identifier", "legal_decision_id",
        "source_canary_legal_decision_id", "legal_decision_source_registry_version",
        "legal_listing_metadata_permission", "legal_body_retrieval_permission",
        "legal_parsing_permission", "legal_matching_permission", "legal_issued_at",
        "legal_revalidation_boundary_at", "legal_evidence_set_id", "legal_approval_role",
        "legal_supersession_status", "egress_evidence_identifier", "egress_evidence_id",
        "egress_evidence_version", "egress_reviewer_role", "egress_reviewed_at",
        "provider_connectivity_exercised", "deployment_approval_identifier", "deployment_id",
        "environment_class", "runtime_artifact_version", "configuration_fingerprint",
        "observability_policy", "deployment_approval_role", "deployment_approved_at",
        "invalidates_on_deployment_change", "heartbeat_policy_identifier",
        "deadline_policy_identifier", "runbook_set_identifier", "runbook_version",
        "runbook_acknowledged_at", "halt_procedure_identifier", "halt_acknowledged_at",
        "containment_catalog_identifier", "containment_acknowledged_at",
        "postcanary_review_policy_identifier", "required_review_role", "reviewer_assigned_at",
        "issuing_operator_may_review", "automatic_progression",
        "evidence_retention_policy_identifier", "retention_acknowledged_at",
        "active_pointer_baseline_identity", "zero_finding_baseline_identity",
        "issued_at", "expires_at", "state", "created_at"
      ) VALUES (
        ${authorizationId}::uuid, 'osv_listing_only_provider_contact_authorization_v1',
        ${listing.sourceId}::uuid, ${listing.operatorAttestationId}::uuid,
        ${listing.requestId}::uuid, ${listing.runId}::uuid, ${preflight.id}::uuid,
        'listing_only', 'rustsec_advisory_database', 'osv-vulnerabilities',
        '/storage/v1/b/osv-vulnerabilities/o', 'osv_gcs_json_objects_list_v1',
        'crates.io/', 'RUSTSEC', 'osv_disabled_first_provider_canary_policy_v1',
        'osv_canary_listing_only_budget_v1',
        'osv_runtime_canary_scope_crates_io_rustsec_v1'::"osv_runtime_work_scope",
        'osv_runtime_lease_scope_osv_gcs_public_export_v1',
        'operator_canary'::"osv_runtime_synchronization_reason",
        'osv_runtime_enablement_architecture_v1', ${FINGERPRINT}, 'committed',
        'osv_transport_policy_v1', 'identity', 'error', 3600, 'single_use',
        'prohibited', 'prohibited', 'prohibited', 'prohibited', 'prohibited', 'prohibited',
        'osv_listing_provider_contact_legal_approval_v1', ${packed.legalApproval.decisionId}::uuid,
        ${listing.sourceLegalDecisionId}::uuid, 'osv_source_license_registry_v1',
        'approved', 'prohibited', 'prohibited', 'prohibited',
        ${new Date(LEGAL_ISSUED)}, ${new Date(LEGAL_REVALIDATE)},
        ${packed.legalApproval.evidenceSetId}::uuid,
        'instance_legal_and_provenance_reviewer_countersigned_by_instance_operator',
        'current', 'osv_listing_provider_contact_egress_evidence_v1',
        ${packed.egressEvidence.egressEvidenceId}::uuid,
        'osv_listing_provider_contact_egress_evidence_v1',
        'instance_operator_deployment_reviewer', ${new Date(ACK)}, FALSE,
        'osv_listing_provider_contact_deployment_approval_v1',
        ${packed.deploymentApproval.deploymentId}::uuid,
        'dedicated_instance_operator_process', ${ARTIFACT}, ${FINGERPRINT},
        'osv_listing_provider_contact_observability_policy_v1',
        'instance_operator_deployment_reviewer', ${new Date(ACK)}, TRUE,
        'osv_canary_runtime_controls_v1', 'osv_canary_runtime_controls_v1',
        'osv_listing_provider_contact_runbook_set_v1',
        'osv_listing_provider_contact_runbook_v1', ${new Date(ACK)},
        'osv_listing_provider_contact_halt_procedure_v1', ${new Date(ACK)},
        'osv_listing_provider_contact_emergency_containment_v1', ${new Date(ACK)},
        'osv_listing_provider_contact_postcanary_review_v1',
        'instance_canary_evidence_reviewer', ${new Date(ACK)}, FALSE, FALSE,
        'osv_listing_provider_contact_retention_disposition_v1', ${new Date(ACK)},
        ${activePointer}::uuid, ${zeroFinding}::uuid,
        CURRENT_TIMESTAMP - INTERVAL '3600 seconds', CURRENT_TIMESTAMP, 'issued',
        CURRENT_TIMESTAMP - INTERVAL '3600 seconds'
      )
    `;
      const inspected = expectOk(
        await adapters.inspectForRun(
          expectOk(
            createOsvListingProviderContactAuthorizationInspectForRunQuery({
              authorizationId,
              synchronizationRequestId: listing.requestId,
              synchronizationRunId: listing.runId,
            }),
            'expired inspect',
          ),
        ),
        'expired inspect',
      );
      expect(inspected.status).toBe('expired');
      expect(inspected.persistedState).toBe('issued');
      const consume = await adapters.consume(
        expectOk(
          createOsvListingProviderContactAuthorizationConsumeCommand({
            authorizationId,
            operatorAttestationId: listing.operatorAttestationId,
            sourceCanaryAuthorizationId: listing.sourceId,
            synchronizationRequestId: listing.requestId,
            synchronizationRunId: listing.runId,
            preflightEvidenceId: preflight.id,
            providerIdentity: 'rustsec_advisory_database',
            approvedPrefix: 'crates.io/',
            canaryPolicyIdentifier: 'osv_disabled_first_provider_canary_policy_v1',
            listingBudgetProfile: 'osv_canary_listing_only_budget_v1',
            runtimeVersionSetFingerprint: FINGERPRINT,
            legalDecisionId: packed.legalApproval.decisionId,
            egressEvidenceId: packed.egressEvidence.egressEvidenceId,
            deploymentId: packed.deploymentApproval.deploymentId,
          }),
          'expired consume',
        ),
      );
      expect(consume.ok).toBe(false);
      if (consume.ok) {
        throw new Error('expected expired consume failure');
      }
      expect(consume.code).toBe('authorization_expired');
      const stored = expectOk(
        await adapters.findById(
          expectOk(
            createOsvListingProviderContactAuthorizationLookupQuery({ authorizationId }),
            'expired lookup',
          ),
        ),
        'expired stored',
      );
      expect(stored.state).toBe('issued');
      expect(stored.consumedAt).toBeNull();
    });

    it('lets exactly one concurrent consumer win', async () => {
      const fresh = await issueFresh();
      const command = consumeCommand(fresh);
      const clients = [
        new PrismaClient({ datasources: { db: { url: databaseUrl } } }),
        new PrismaClient({ datasources: { db: { url: databaseUrl } } }),
      ];
      try {
        const left = createOsvListingProviderContactAuthorizationPersistence(clients[0]!);
        const right = createOsvListingProviderContactAuthorizationPersistence(clients[1]!);
        const [leftResult, rightResult] = await Promise.all([
          left.consume(command),
          right.consume(command),
        ]);
        const outcomes = [leftResult, rightResult].map((result) =>
          result.ok ? result.value.outcome : result.code,
        );
        expect(outcomes.filter((outcome) => outcome === 'consumed')).toHaveLength(1);
        expect(
          outcomes.filter(
            (outcome) =>
              outcome === 'already_consumed_same_run' || outcome === 'serialization_failure',
          ).length,
        ).toBeGreaterThanOrEqual(1);
      } finally {
        await Promise.all(clients.map((client) => client.$disconnect()));
      }
    });

    it('lets consume or revoke win, never both', async () => {
      const fresh = await issueFresh();
      const consume = consumeCommand(fresh);
      const revoke = expectOk(
        createOsvListingProviderContactAuthorizationRevokeCommand({
          authorizationId: fresh.issued.record.providerContactAuthorizationId,
          operatorAttestationId: fresh.listing.operatorAttestationId,
        }),
        'revoke concurrent',
      );
      const clients = [
        new PrismaClient({ datasources: { db: { url: databaseUrl } } }),
        new PrismaClient({ datasources: { db: { url: databaseUrl } } }),
      ];
      try {
        const left = createOsvListingProviderContactAuthorizationPersistence(clients[0]!);
        const right = createOsvListingProviderContactAuthorizationPersistence(clients[1]!);
        const [consumeResult, revokeResult] = await Promise.all([
          left.consume(consume),
          right.revoke(revoke),
        ]);
        const consumeWon = consumeResult.ok && consumeResult.value.outcome === 'consumed';
        const revokeWon = revokeResult.ok && revokeResult.value.status === 'transitioned';
        expect(Number(consumeWon) + Number(revokeWon)).toBeLessThanOrEqual(1);
        const stored = expectOk(
          await adapters.findById(
            expectOk(
              createOsvListingProviderContactAuthorizationLookupQuery({
                authorizationId: fresh.issued.record.providerContactAuthorizationId,
              }),
              'concurrent consume/revoke lookup',
            ),
          ),
          'concurrent consume/revoke stored',
        );
        expect(['issued', 'consumed_for_listing_execution', 'revoked']).toContain(stored.state);
        if (consumeWon) {
          expect(stored.state).toBe('consumed_for_listing_execution');
          expect(stored.revokedAt).toBeNull();
        }
        if (revokeWon) {
          expect(stored.state).toBe('revoked');
          expect(stored.consumedAt).toBeNull();
        }
        expect(stored.state === 'consumed_for_listing_execution' && stored.revokedAt !== null).toBe(
          false,
        );
      } finally {
        await Promise.all(clients.map((client) => client.$disconnect()));
      }
    });

    it('does not write Findings and omits confidential markers from public results', async () => {
      const before = await prisma.finding.count();
      const fresh = await issueFresh();
      expectOk(await adapters.consume(consumeCommand(fresh)), 'consume for confidentiality');
      const after = await prisma.finding.count();
      expect(after).toBe(before);
      const text = confidential(fresh.issued);
      for (const marker of MARKERS) {
        expect(text).not.toContain(marker);
      }
      expect(text).not.toContain('SELECT');
      expect(text).not.toContain('organizationId');
    });

    it('rejects issuance when the source canary authorization is not consumed', async () => {
      const operator = await ensureOperator();
      const operatorAttestationId = operator.operator.identity.operatorAttestationId;
      const listing = await ensureListing(operatorAttestationId);
      const { request, run } = await seedCanaryRun();
      const packed = evidence(
        listing.authorization.snapshot.record.legalDecisionReference.decisionId,
      );
      const authorizationId = uuid();
      const result = await adapters.issue(
        expectOk(
          createOsvListingProviderContactAuthorizationIssueCommand({
            providerContactAuthorizationId: authorizationId,
            sourceCanaryAuthorizationId: listing.authorization.snapshot.record.authorizationId,
            operatorAttestationId,
            synchronizationRequestId: request.id,
            synchronizationRunId: run.id,
            preflightEvidenceId: uuid(),
            activePointerBaselineIdentity: uuid(),
            zeroFindingBaselineIdentity: uuid(),
            ...packed,
          }),
          'unconsumed source command',
        ),
      );
      expect(result.ok).toBe(false);
      if (result.ok) {
        throw new Error('expected unconsumed source failure');
      }
      expect(result.code).toBe('canary_authorization_not_consumed');
      const lookup = await adapters.findById(
        expectOk(
          createOsvListingProviderContactAuthorizationLookupQuery({ authorizationId }),
          'unconsumed lookup',
        ),
      );
      expect(lookup.ok).toBe(false);
    });

    it('classifies consume after operator revocation as operator_revoked', async () => {
      const fresh = await issueFresh();
      expectOk(
        await canary.operators.revoke(
          expectOk(
            createOsvCanaryOperatorRevokeCommand({
              operatorAttestationId: fresh.listing.operatorAttestationId,
            }),
            'operator revoke command',
          ),
        ),
        'operator revoke',
      );
      const consume = await adapters.consume(consumeCommand(fresh));
      expect(consume.ok).toBe(false);
      if (consume.ok) {
        throw new Error('expected operator_revoked consume failure');
      }
      expect(consume.code).toBe('operator_revoked');
      const stored = expectOk(
        await adapters.findById(
          expectOk(
            createOsvListingProviderContactAuthorizationLookupQuery({
              authorizationId: fresh.issued.record.providerContactAuthorizationId,
            }),
            'after operator revoke lookup',
          ),
        ),
        'after operator revoke stored',
      );
      expect(stored.state).toBe('issued');
      expect(stored.consumedAt).toBeNull();
    });

    it('does not report issued binding mismatch as already consumed', async () => {
      const fresh = await issueFresh();
      const mismatched = await adapters.consume(
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
          'wrong preflight consume',
        ),
      );
      expect(mismatched.ok).toBe(false);
      if (mismatched.ok) {
        throw new Error('expected preflight mismatch');
      }
      expect(mismatched.code).toBe('preflight_mismatch');
      expect(mismatched.code).not.toBe('already_consumed_same_run');
      expect(mismatched.code).not.toBe('already_consumed_other_run');
    });

    it('inspects without mutating timestamps or consumption', async () => {
      const fresh = await issueFresh();
      const authorizationId = fresh.issued.record.providerContactAuthorizationId;
      const before = await prisma.$queryRaw<
        Array<{ xmin: string; issued_at: Date; expires_at: Date; consumed_at: Date | null }>
      >`
        SELECT xmin::text AS xmin, issued_at, expires_at, consumed_at
        FROM "osv_listing_provider_contact_authorization"
        WHERE "id" = ${authorizationId}::uuid
      `;
      expectOk(
        await adapters.inspectForRun(
          expectOk(
            createOsvListingProviderContactAuthorizationInspectForRunQuery({
              authorizationId,
              synchronizationRequestId: fresh.listing.requestId,
              synchronizationRunId: fresh.listing.runId,
            }),
            'immutability inspect',
          ),
        ),
        'immutability inspect',
      );
      const after = await prisma.$queryRaw<
        Array<{ xmin: string; issued_at: Date; expires_at: Date; consumed_at: Date | null }>
      >`
        SELECT xmin::text AS xmin, issued_at, expires_at, consumed_at
        FROM "osv_listing_provider_contact_authorization"
        WHERE "id" = ${authorizationId}::uuid
      `;
      expect(after[0]?.xmin).toBe(before[0]?.xmin);
      expect(after[0]?.issued_at.getTime()).toBe(before[0]?.issued_at.getTime());
      expect(after[0]?.expires_at.getTime()).toBe(before[0]?.expires_at.getTime());
      expect(after[0]?.consumed_at).toBeNull();
    });

    it('converges concurrent identical issuance onto one immutable row', async () => {
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
        'concurrent issue command',
      );
      const clients = [
        new PrismaClient({ datasources: { db: { url: databaseUrl } } }),
        new PrismaClient({ datasources: { db: { url: databaseUrl } } }),
      ];
      try {
        const left = createOsvListingProviderContactAuthorizationPersistence(clients[0]!);
        const right = createOsvListingProviderContactAuthorizationPersistence(clients[1]!);
        const [leftResult, rightResult] = await Promise.all([
          left.issue(command),
          right.issue(command),
        ]);
        const statuses = [leftResult, rightResult].map((result) =>
          result.ok ? result.value.status : result.code,
        );
        expect(
          statuses.filter((status) => status === 'created' || status === 'already_applied').length,
        ).toBeGreaterThanOrEqual(1);
        expect(statuses.filter((status) => status === 'created').length).toBeLessThanOrEqual(1);
        expect(
          await prisma.osvListingProviderContactAuthorization.count({
            where: { sourceCanaryAuthorizationId: listing.sourceId },
          }),
        ).toBe(1);
      } finally {
        await Promise.all(clients.map((client) => client.$disconnect()));
      }
    });
  },
);
