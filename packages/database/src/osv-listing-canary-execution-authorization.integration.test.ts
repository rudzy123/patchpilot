/**
 * Session 13 Batch 3C-Auth listing-canary execution-authorization PostgreSQL
 * rehearsal. Composes Batch 2C, Batch 7, Batch 3B-A adapters, halt, heartbeat,
 * deadline, and the uncomposed execution-authorization service.
 * No real provider contact, body retrieval, parser, activation, matching,
 * or Finding writes.
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
  createOsvCanaryInstanceOperatorIdentity,
  createOsvCanaryLegalDecisionReference,
  createOsvCanaryOperatorEnsureCommand,
  createOsvCanaryRunbookAcknowledgement,
  createOsvListingCanaryExecutionAuthorizationInput,
  createOsvListingCanaryExecutionAuthorizationService,
  createOsvListingCanaryExecutionConfirmation,
  createOsvListingProviderContactAuthorizationIssueCommand,
  createOsvListingProviderContactContainmentAcknowledgement,
  createOsvListingProviderContactDeploymentApproval,
  createOsvListingProviderContactEgressEvidence,
  createOsvListingProviderContactHaltProcedureAcknowledgement,
  createOsvListingProviderContactLegalApproval,
  createOsvListingProviderContactRetentionDisposition,
  createOsvListingProviderContactReviewerAssignment,
  createOsvListingProviderContactRunbookAcknowledgement,
  createOsvRuntimeHaltStatePort,
  createOsvRuntimeJobIdempotencyIdentity,
  createOsvRuntimeSynchronizationRequestEnsureCommand,
  createOsvRuntimeSynchronizationRunEnsureCommand,
  createOsvRuntimeSyncJobPayload,
  createOsvRuntimeTrustedHaltSnapshot,
  defaultOsvRuntimeHaltSnapshot,
  OSV_GCS_JSON_OBJECTS_LIST_HOST,
  OSV_GCS_JSON_OBJECTS_LIST_PATH,
  OSV_GCS_JSON_OBJECTS_LIST_REDIRECT_POLICY,
  OSV_GCS_JSON_OBJECTS_LIST_SCHEME,
  OSV_LISTING_CANARY_EXECUTION_AUTHORIZATION_EGRESS_POLICY_ID,
  OSV_LISTING_CANARY_EXECUTION_AUTHORIZATION_EXPECTED_BUDGET,
  OSV_LISTING_CANARY_EXECUTION_AUTHORIZATION_EXPECTED_POLICY,
  OSV_LISTING_CANARY_EXECUTION_AUTHORIZATION_EXPECTED_PREFIX,
  OSV_LISTING_CANARY_EXECUTION_AUTHORIZATION_EXPECTED_PROVIDER,
  OSV_LISTING_CANARY_EXECUTION_AUTHORIZATION_LEASE_SCOPE,
  OSV_LISTING_CANARY_EXECUTION_AUTHORIZATION_PHASE,
  OSV_LISTING_CANARY_EXECUTION_AUTHORIZATION_SCHEMA_VERSION,
  OSV_LISTING_CANARY_EXECUTION_AUTHORIZATION_SUCCESS_OUTCOME,
  osvCanaryRuntimeVersionSetFingerprint,
  type OsvCanaryAuthorizationResult,
  type OsvCanaryInstanceOperatorIdentity,
  type OsvCanaryMonotonicClockPort,
  type OsvCanaryOneShotSchedulerPort,
  type OsvCanaryPhase,
} from '@patchpilot/vulnerability-intelligence';

import { createOsvCanaryAuthorizationPersistence } from './osv-canary-authorization-persistence.js';
import { createOsvCanaryPreflightReadiness } from './osv-canary-preflight-readiness.js';
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
const APPLICATION_TESTED = 'application_control_implemented_and_tested';
const DEPLOYMENT_CONFIGURED = 'deployment_control_configured';
const PROOF = 'supersecret-password';
const MARKERS = [
  PROOF,
  'holder-token-proof',
  'pageToken=opaque',
  'provider-body-bytes',
  's3://bucket/locator',
  'org-tenant-id-marker',
  'finding-id-marker',
];

function expectOk<T>(
  result: OsvCanaryAuthorizationResult<T> | { ok: true; value: T } | { ok: false; code: string },
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

function createFakeClock(start = 0): OsvCanaryMonotonicClockPort {
  const now = start;
  return {
    now: () => now,
  };
}

function createFakeScheduler(clock: { now(): number }): OsvCanaryOneShotSchedulerPort {
  const items: Array<{ fireAt: number; callback: () => void; cancelled: boolean }> = [];
  return {
    schedule(delayMs, callback) {
      const item = { fireAt: clock.now() + delayMs, callback, cancelled: false };
      items.push(item);
      return {
        cancel() {
          item.cancelled = true;
        },
      };
    },
  };
}

function rehearsalEgress() {
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

describe(
  'session 13 Batch 3C-Auth listing-canary execution-authorization rehearsal',
  {
    timeout: 180_000,
  },
  () => {
    let databaseName: string;
    let admin: PrismaClient;
    let prisma: PrismaClient;
    let canary: ReturnType<typeof createOsvCanaryAuthorizationPersistence>;
    let coordination: ReturnType<typeof createOsvRuntimeCoordinationPersistence>;
    let providerContact: ReturnType<typeof createOsvListingProviderContactAuthorizationPersistence>;
    let readiness: ReturnType<typeof createOsvCanaryPreflightReadiness>;

    beforeAll(async () => {
      const ephemeral = await createEphemeralDatabase('it');
      databaseName = ephemeral.databaseName;
      admin = ephemeral.admin;
      await deployMigrations(ephemeral.databaseUrl);
      prisma = new PrismaClient({
        datasources: { db: { url: ephemeral.databaseUrl } },
      });
      canary = createOsvCanaryAuthorizationPersistence(prisma);
      coordination = createOsvRuntimeCoordinationPersistence(prisma);
      providerContact = createOsvListingProviderContactAuthorizationPersistence(prisma);
      readiness = createOsvCanaryPreflightReadiness(prisma);
    });

    afterAll(async () => {
      if (prisma !== undefined) {
        await prisma.$disconnect();
      }
      if (admin !== undefined && databaseName !== undefined) {
        await dropEphemeralDatabase(admin, databaseName);
      }
    });

    function identityOf(operatorAttestationId: string): OsvCanaryInstanceOperatorIdentity {
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

    async function ensureOperator() {
      const operatorAttestationId = uuid();
      return expectOk(
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
    }

    async function seedIssuedProviderContact() {
      const operator = await ensureOperator();
      const operatorAttestationId = operator.operator.identity.operatorAttestationId;
      const listing = expectOk(
        await canary.authorizations.ensure(
          expectOk(
            createOsvCanaryAuthorizationEnsureCommand({
              authorizationId: uuid(),
              operatorAttestationId,
              phase: 'listing_only',
              authorizationPurpose: 'initial_listing_compatibility',
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
          leaseScope: OSV_LISTING_CANARY_EXECUTION_AUTHORIZATION_LEASE_SCOPE,
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
      };
    }

    function compose(
      operatorAttestationId: string,
      halt = createOsvRuntimeHaltStatePort(
        createOsvRuntimeTrustedHaltSnapshot({
          control: 'permitted_by_halt_control',
          source: 'explicit',
        }),
      ),
    ) {
      const clock = createFakeClock();
      return createOsvListingCanaryExecutionAuthorizationService({
        authentication: {
          authenticate() {
            return { outcome: 'authenticated', operator: identityOf(operatorAttestationId) };
          },
        },
        authorization: canary,
        providerContact,
        synchronization: readiness.synchronization,
        coordination,
        haltState: halt,
        egressReadiness: rehearsalEgress(),
        clock,
        scheduler: createFakeScheduler(clock),
      });
    }

    function executionInput(seed: Awaited<ReturnType<typeof seedIssuedProviderContact>>) {
      const confirmationId = uuid();
      const confirmation = expectOk(
        createOsvListingCanaryExecutionConfirmation({
          confirmationId,
          providerContactAuthorizationId: seed.providerContactAuthorizationId,
          sourceCanaryAuthorizationId: seed.sourceId,
          synchronizationRequestId: seed.requestId,
          synchronizationRunId: seed.runId,
          phase: OSV_LISTING_CANARY_EXECUTION_AUTHORIZATION_PHASE,
          approvedPrefix: OSV_LISTING_CANARY_EXECUTION_AUTHORIZATION_EXPECTED_PREFIX,
          canaryPolicyIdentifier: OSV_LISTING_CANARY_EXECUTION_AUTHORIZATION_EXPECTED_POLICY,
          runtimeVersionSetFingerprint: FINGERPRINT,
          proofMaterial: PROOF,
        }),
        'confirmation',
      );
      return expectOk(
        createOsvListingCanaryExecutionAuthorizationInput({
          executionAuthorizationSchemaVersion:
            OSV_LISTING_CANARY_EXECUTION_AUTHORIZATION_SCHEMA_VERSION,
          operatorExecutionConfirmationId: confirmationId,
          providerContactAuthorizationId: seed.providerContactAuthorizationId,
          sourceCanaryAuthorizationId: seed.sourceId,
          synchronizationRequestId: seed.requestId,
          synchronizationRunId: seed.runId,
          preflightEvidenceId: seed.preflightId,
          phase: OSV_LISTING_CANARY_EXECUTION_AUTHORIZATION_PHASE,
          expectedProvider: OSV_LISTING_CANARY_EXECUTION_AUTHORIZATION_EXPECTED_PROVIDER,
          expectedPrefix: OSV_LISTING_CANARY_EXECUTION_AUTHORIZATION_EXPECTED_PREFIX,
          expectedCanaryPolicy: OSV_LISTING_CANARY_EXECUTION_AUTHORIZATION_EXPECTED_POLICY,
          expectedBudgetProfile: OSV_LISTING_CANARY_EXECUTION_AUTHORIZATION_EXPECTED_BUDGET,
          expectedRuntimeVersionSetFingerprint: FINGERPRINT,
          expectedEgressPolicyId: OSV_LISTING_CANARY_EXECUTION_AUTHORIZATION_EGRESS_POLICY_ID,
          expectedLeaseScope: OSV_LISTING_CANARY_EXECUTION_AUTHORIZATION_LEASE_SCOPE,
          correlationId: uuid(),
          executionConfirmation: confirmation,
        }),
        'input',
      );
    }

    it('prepares one listing-only permit against disposable PostgreSQL without provider contact', async () => {
      const seed = await seedIssuedProviderContact();
      const service = compose(seed.operatorAttestationId);
      const result = await service.authorizeListingCanaryExecution(executionInput(seed));
      expect(result.ok).toBe(true);
      if (!result.ok) {
        throw new Error(result.code);
      }
      expect(result.outcome).toBe(OSV_LISTING_CANARY_EXECUTION_AUTHORIZATION_SUCCESS_OUTCOME);
      expect(result.executionPermitEstablishedClassification).toBe('established');
      expect(result.leaseAcquired).toBe(true);
      expect(result.leaseReleaseOutcome).toBe('released');
      expect(result.providerAttemptsPerformed).toBe(0);
      expect(result.externalHttpRequests).toBe(0);
      expect(result.bodyRequests).toBe(0);
      expect(result.findingWrites).toBe(0);
      const blob = `${JSON.stringify(result)}\n${inspect(result, { depth: 6 })}`;
      for (const marker of MARKERS) {
        expect(blob).not.toContain(marker);
      }
      const replay = await service.authorizeListingCanaryExecution(executionInput(seed));
      expect(replay.ok).toBe(true);
      if (!replay.ok) {
        throw new Error(replay.code);
      }
      expect(replay.replayMode).toBe('same_run_status_inspection');
      expect(replay.executionPermitEstablishedClassification).toBe('not_established');
      expect(replay.leaseAcquired).toBe(false);
    });

    it('blocks default halt before lease acquisition', async () => {
      const seed = await seedIssuedProviderContact();
      const service = compose(
        seed.operatorAttestationId,
        createOsvRuntimeHaltStatePort(defaultOsvRuntimeHaltSnapshot()),
      );
      const result = await service.authorizeListingCanaryExecution(executionInput(seed));
      expect(result.ok).toBe(false);
      if (result.ok) {
        throw new Error('expected halt');
      }
      expect(result.code).toBe('halt_engaged');
      expect(result.leaseAcquired).toBe(false);
      expect(result.providerAttemptsPerformed).toBe(0);
    });

    it('rejects a confirmation bound to another run', async () => {
      const seed = await seedIssuedProviderContact();
      const confirmationId = uuid();
      const confirmation = expectOk(
        createOsvListingCanaryExecutionConfirmation({
          confirmationId,
          providerContactAuthorizationId: seed.providerContactAuthorizationId,
          sourceCanaryAuthorizationId: seed.sourceId,
          synchronizationRequestId: seed.requestId,
          synchronizationRunId: uuid(),
          phase: OSV_LISTING_CANARY_EXECUTION_AUTHORIZATION_PHASE,
          approvedPrefix: OSV_LISTING_CANARY_EXECUTION_AUTHORIZATION_EXPECTED_PREFIX,
          canaryPolicyIdentifier: OSV_LISTING_CANARY_EXECUTION_AUTHORIZATION_EXPECTED_POLICY,
          runtimeVersionSetFingerprint: FINGERPRINT,
          proofMaterial: PROOF,
        }),
        'foreign confirmation',
      );
      const service = compose(seed.operatorAttestationId);
      const parsed = createOsvListingCanaryExecutionAuthorizationInput({
        executionAuthorizationSchemaVersion:
          OSV_LISTING_CANARY_EXECUTION_AUTHORIZATION_SCHEMA_VERSION,
        operatorExecutionConfirmationId: confirmationId,
        providerContactAuthorizationId: seed.providerContactAuthorizationId,
        sourceCanaryAuthorizationId: seed.sourceId,
        synchronizationRequestId: seed.requestId,
        synchronizationRunId: seed.runId,
        preflightEvidenceId: seed.preflightId,
        phase: OSV_LISTING_CANARY_EXECUTION_AUTHORIZATION_PHASE,
        expectedProvider: OSV_LISTING_CANARY_EXECUTION_AUTHORIZATION_EXPECTED_PROVIDER,
        expectedPrefix: OSV_LISTING_CANARY_EXECUTION_AUTHORIZATION_EXPECTED_PREFIX,
        expectedCanaryPolicy: OSV_LISTING_CANARY_EXECUTION_AUTHORIZATION_EXPECTED_POLICY,
        expectedBudgetProfile: OSV_LISTING_CANARY_EXECUTION_AUTHORIZATION_EXPECTED_BUDGET,
        expectedRuntimeVersionSetFingerprint: FINGERPRINT,
        expectedEgressPolicyId: OSV_LISTING_CANARY_EXECUTION_AUTHORIZATION_EGRESS_POLICY_ID,
        expectedLeaseScope: OSV_LISTING_CANARY_EXECUTION_AUTHORIZATION_LEASE_SCOPE,
        correlationId: uuid(),
        executionConfirmation: confirmation,
      });
      expect(parsed.ok).toBe(true);
      if (!parsed.ok) {
        throw new Error(parsed.code);
      }
      const result = await service.authorizeListingCanaryExecution(parsed.value);
      expect(result.ok).toBe(false);
      if (result.ok) {
        throw new Error('expected mismatch');
      }
      expect(result.code).toBe('operator_confirmation_mismatch');
      expect(result.leaseAcquired).toBe(false);
    });
  },
);
