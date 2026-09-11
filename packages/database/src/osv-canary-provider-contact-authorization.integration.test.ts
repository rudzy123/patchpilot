/**
 * Session 13 Batch 3B listing-only provider-contact authorization rehearsal.
 * Composes actual operator and canary-authorization adapters, request/run
 * reload, and constructed evidence seams. No real provider contact, DNS,
 * HTTP, lease mutation, timer, body retrieval, parser, activation, matching,
 * or Finding writes.
 */

import { randomUUID } from 'node:crypto';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { PrismaClient } from '@prisma/client';
import {
  createOsvCanaryAcceptedPreflightEvidence,
  createOsvCanaryActivationProhibitionAcknowledgement,
  createOsvCanaryAuthorizationEnsureCommand,
  createOsvCanaryAutomaticRetryProhibitionAcknowledgement,
  createOsvCanaryHaltControlAcknowledgement,
  createOsvCanaryInstanceOperatorIdentity,
  createOsvCanaryLegalDecisionReference,
  createOsvCanaryOneShotCommandInput,
  createOsvCanaryOneShotCommandService,
  createOsvCanaryOperatorAuthenticationProof,
  createOsvCanaryOperatorEnsureCommand,
  createOsvCanaryOperatorRevokeCommand,
  createOsvCanaryPreflightInput,
  createOsvCanaryPreflightService,
  createOsvCanaryRunbookAcknowledgement,
  createOsvListingProviderContactAuthorizationInput,
  createOsvListingProviderContactAuthorizationService,
  createOsvListingProviderContactConfirmation,
  createOsvListingProviderContactContainmentAcknowledgement,
  createOsvListingProviderContactDeploymentApproval,
  createOsvListingProviderContactEgressEvidence,
  createOsvListingProviderContactHaltProcedureAcknowledgement,
  createOsvListingProviderContactLegalApproval,
  createOsvListingProviderContactRetentionDisposition,
  createOsvListingProviderContactReviewerAssignment,
  createOsvListingProviderContactRunbookAcknowledgement,
  createOsvRuntimeHaltStatePort,
  createOsvRuntimeTrustedHaltSnapshot,
  defaultOsvRuntimeHaltSnapshot,
  OSV_CANARY_DEADLINE_CONTROLLER_POLICY,
  OSV_CANARY_HEARTBEAT_CONTROLLER_POLICY,
  OSV_LISTING_PROVIDER_CONTACT_HALT_PROCEDURE_IDENTIFIER,
  OSV_LISTING_PROVIDER_CONTACT_OBSERVABILITY_POLICY_IDENTIFIER,
  synchronizationPortFromRuntimePersistence,
  osvCanaryRuntimeVersionSetFingerprint,
  type OsvCanaryAuthorizationResult,
  type OsvCanaryInstanceOperatorIdentity,
  type OsvCanaryPreflightDependencies,
  type OsvCanaryPreflightSuccess,
} from '@patchpilot/vulnerability-intelligence';

import { createOsvCanaryAuthorizationPersistence } from './osv-canary-authorization-persistence.js';
import { createOsvCanaryPreflightReadiness } from './osv-canary-preflight-readiness.js';
import { mapRequest, mapRun } from './osv-runtime-coordination-mappers.js';
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
const PROOF = 'supersecret-password';
const APPLICATION_TESTED = 'application_control_implemented_and_tested';
const DEPLOYMENT_CONFIGURED = 'deployment_control_configured';
const ARTIFACT = 'patchpilot.canary.artifact.1';
const CONFIG = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

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

describe(
  'session 13 Batch 3B OSV listing provider-contact authorization rehearsal',
  { timeout: 180_000 },
  () => {
    let databaseName: string;
    let admin: PrismaClient;
    let prisma: PrismaClient;
    let adapters: ReturnType<typeof createOsvCanaryAuthorizationPersistence>;
    let coordination: ReturnType<typeof createOsvRuntimeCoordinationPersistence>;
    let readiness: ReturnType<typeof createOsvCanaryPreflightReadiness>;

    beforeAll(async () => {
      const ephemeral = await createEphemeralDatabase('it');
      databaseName = ephemeral.databaseName;
      admin = ephemeral.admin;
      await deployMigrations(ephemeral.databaseUrl);
      prisma = new PrismaClient({
        datasources: { db: { url: ephemeral.databaseUrl } },
      });
      adapters = createOsvCanaryAuthorizationPersistence(prisma);
      coordination = createOsvRuntimeCoordinationPersistence(prisma);
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

    async function inspectByOperatorRequestId(operatorRequestId: string) {
      const request = await prisma.osvRuntimeSynchronizationRequest.findUnique({
        where: { operatorRequestId },
      });
      if (request === null) {
        return { status: 'absent' as const };
      }
      const run = await prisma.osvRuntimeSynchronizationRun.findUnique({
        where: { requestId: request.id },
      });
      return {
        status: 'found' as const,
        request: mapRequest(request),
        run: run === null ? null : mapRun(run),
      };
    }

    function commandService(operatorAttestationId: string) {
      return createOsvCanaryOneShotCommandService({
        authentication: {
          authenticate() {
            return { outcome: 'authenticated', operator: identityOf(operatorAttestationId) };
          },
        },
        authorization: adapters,
        synchronization: synchronizationPortFromRuntimePersistence({
          requests: coordination.requests,
          runs: coordination.runs,
          inspectByOperatorRequestId,
        }),
        haltState: createOsvRuntimeHaltStatePort(
          createOsvRuntimeTrustedHaltSnapshot({
            control: 'permitted_by_halt_control',
            source: 'explicit',
          }),
        ),
      });
    }

    function listingLegal() {
      return expectOk(
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
      );
    }

    async function consumeListing() {
      const operatorAttestationId = uuid();
      expectOk(
        await adapters.operators.ensure(
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
        await adapters.authorizations.ensure(
          expectOk(
            createOsvCanaryAuthorizationEnsureCommand({
              authorizationId: uuid(),
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
      const authorizationId = listing.authorization.snapshot.record.authorizationId;
      const prepared = await commandService(operatorAttestationId).prepareAuthorizedCanaryExecution(
        expectOk(
          createOsvCanaryOneShotCommandInput({
            commandSchemaVersion: 'osv_canary_one_shot_command_v1',
            authorizationId,
            phase: 'listing_only',
            expectedProvider: 'rustsec_advisory_database',
            expectedPrefix: 'crates.io/',
            expectedCanaryPolicy: 'osv_disabled_first_provider_canary_policy_v1',
            expectedBudgetProfile: 'osv_canary_listing_only_budget_v1',
            expectedRuntimeVersionSetFingerprint: FINGERPRINT,
            operatorRequestId: uuid(),
            correlationId: uuid(),
            commandReason: 'operator_canary',
            authenticationProof: createOsvCanaryOperatorAuthenticationProof(PROOF),
          }),
          'command input',
        ),
      );
      expect(prepared.ok).toBe(true);
      if (!prepared.ok) {
        throw new Error(prepared.code);
      }
      return {
        operatorAttestationId,
        authorizationId,
        requestId: prepared.synchronizationRequestId,
        runId: prepared.synchronizationRunId,
        sourceLegalDecisionId:
          listing.authorization.snapshot.record.legalDecisionReference.decisionId,
      };
    }

    async function acceptedPreflight(consumed: Awaited<ReturnType<typeof consumeListing>>) {
      const dependencies: OsvCanaryPreflightDependencies = {
        authorization: adapters,
        synchronization: readiness.synchronization,
        haltState: createOsvRuntimeHaltStatePort(
          createOsvRuntimeTrustedHaltSnapshot({
            control: 'permitted_by_halt_control',
            source: 'explicit',
          }),
        ),
        leaseInspection: readiness.leaseInspection,
        heartbeatReadiness: {
          inspect() {
            return Promise.resolve({
              ready: true as const,
              policyIdentifier: OSV_CANARY_HEARTBEAT_CONTROLLER_POLICY.schemaVersion,
              intervalMs: 60_000,
              leaseTtlMs: 900_000,
              maxInFlight: 1 as const,
              pendingCapacity: 0 as const,
              timerStarted: false as const,
              stopProtocol: OSV_CANARY_HEARTBEAT_CONTROLLER_POLICY.stopProtocol,
              delayedCallbackCatchUp: false as const,
            });
          },
        },
        deadlineReadiness: {
          inspect(input: { readonly phase: 'listing_only' | 'bounded_body' }) {
            return Promise.resolve({
              ready: true as const,
              phase: input.phase,
              durationMs: 1_800_000,
              monotonicClockAvailable: true as const,
              oneTimerMaximum: true as const,
              timerArmed: false as const,
              cancellationTargetAvailable: true as const,
              elapsedAuthority: OSV_CANARY_DEADLINE_CONTROLLER_POLICY.elapsedAuthority,
            });
          },
        },
        egressReadiness: {
          inspect(input: { readonly phase: 'listing_only' | 'bounded_body' }) {
            return Promise.resolve({
              ready: true as const,
              dnsLookupCount: 0 as const,
              providerCallCount: 0 as const,
              tlsConnectionCount: 0 as const,
              host: 'storage.googleapis.com',
              scheme: 'https',
              port: 443 as const,
              listingPath: '/storage/v1/b/osv-vulnerabilities/o',
              bucket: 'osv-vulnerabilities',
              redirectPolicy: 'error',
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
        },
        databaseReadiness: readiness.databaseReadiness,
        objectStorageReadiness: {
          inspect() {
            return Promise.resolve({ ready: true as const, mutated: false as const });
          },
        },
        parserReadiness: {
          inspect() {
            return Promise.resolve({
              ready: true as const,
              mutated: false as const,
              activeCapacity: 1 as const,
              pendingCapacity: 0 as const,
            });
          },
        },
        acquisitionPersistenceReadiness: readiness.acquisitionPersistenceReadiness,
        observabilityReadiness: {
          inspect() {
            return Promise.resolve({
              ready: true as const,
              eventCatalogIdentifier: 'osv_canary_preflight_operational_event_catalog_v1',
              requiredCountersRegistered: true as const,
              metricLabelsClosed: true as const,
              safeLogBindings: true as const,
              safeTraceAttributes: true as const,
              providerAttemptCounters: 0 as const,
            });
          },
        },
        activePointerBaseline: readiness.activePointerBaseline,
        zeroFindingBaseline: readiness.zeroFindingBaseline,
        eventSink: {
          emit() {
            return undefined;
          },
        },
      };
      const result = await createOsvCanaryPreflightService(
        dependencies,
      ).evaluateCanaryExecutionPreflight(
        expectOk(
          createOsvCanaryPreflightInput({
            preflightSchemaVersion: 'osv_canary_execution_preflight_v1',
            authorizationId: consumed.authorizationId,
            synchronizationRequestId: consumed.requestId,
            synchronizationRunId: consumed.runId,
            phase: 'listing_only',
            expectedProvider: 'rustsec_advisory_database',
            expectedPrefix: 'crates.io/',
            expectedCanaryPolicy: 'osv_disabled_first_provider_canary_policy_v1',
            expectedBudgetProfile: 'osv_canary_listing_only_budget_v1',
            expectedRuntimeVersionSetFingerprint: FINGERPRINT,
            correlationId: uuid(),
          }),
          'preflight input',
        ),
      );
      if (!result.ok) {
        throw new Error(`preflight failed: ${result.code}`);
      }
      expect(result.providerContactAuthorized).toBe(false);
      return result;
    }

    function evidencePackage(input: {
      readonly consumed: Awaited<ReturnType<typeof consumeListing>>;
      readonly preflight: OsvCanaryPreflightSuccess;
      readonly haltProcedureReady?: boolean;
    }) {
      const preflightEvidenceId = uuid();
      const legal = expectOk(
        createOsvListingProviderContactLegalApproval({
          decisionId: uuid(),
          sourceCanaryLegalDecisionId: input.consumed.sourceLegalDecisionId,
          issuedAt: LEGAL_ISSUED,
          revalidationBoundaryAt: LEGAL_REVALIDATE,
          evidenceSetId: uuid(),
          approvalRole: 'instance_legal_and_provenance_reviewer_countersigned_by_instance_operator',
          supersessionStatus: 'current',
        }),
        'contact legal',
      );
      const egress = expectOk(
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
      );
      const deployment = expectOk(
        createOsvListingProviderContactDeploymentApproval({
          deploymentId: uuid(),
          environmentClass: 'dedicated_instance_operator_process',
          egressPolicyVersion: 'osv_listing_provider_contact_egress_evidence_v1',
          runtimeArtifactVersion: ARTIFACT,
          configurationFingerprint: CONFIG,
          providerTransportPolicy: 'osv_transport_policy_v1',
          observabilityPolicy: OSV_LISTING_PROVIDER_CONTACT_OBSERVABILITY_POLICY_IDENTIFIER,
          runbookVersion: 'osv_listing_provider_contact_runbook_v1',
          approvalRole: 'instance_operator_deployment_reviewer',
          approvedAt: ACK,
          invalidatesOnDeploymentChange: true,
        }),
        'deployment',
      );
      const parsed = createOsvListingProviderContactAuthorizationInput({
        authorizationSchemaVersion: 'osv_listing_only_provider_contact_authorization_v1',
        providerContactAuthorizationId: uuid(),
        sourceCanaryAuthorizationId: input.consumed.authorizationId,
        synchronizationRequestId: input.consumed.requestId,
        synchronizationRunId: input.consumed.runId,
        preflightEvidenceId,
        acceptedPreflightEvidence: expectOk(
          createOsvCanaryAcceptedPreflightEvidence({
            preflightEvidenceId,
            preflightResult: input.preflight,
          }),
          'evidence',
        ),
        phase: 'listing_only',
        expectedProvider: 'rustsec_advisory_database',
        expectedPrefix: 'crates.io/',
        expectedCanaryPolicy: 'osv_disabled_first_provider_canary_policy_v1',
        expectedBudgetProfile: 'osv_canary_listing_only_budget_v1',
        expectedRuntimeVersionSetFingerprint: FINGERPRINT,
        correlationId: uuid(),
        operatorConfirmation: createOsvListingProviderContactConfirmation(PROOF),
        legalApproval: legal,
        egressEvidence: egress,
        deploymentApproval: deployment,
        haltProcedureAcknowledgement: expectOk(
          createOsvListingProviderContactHaltProcedureAcknowledgement({ acknowledgedAt: ACK }),
          'halt ack',
        ),
        runbookAcknowledgement: expectOk(
          createOsvListingProviderContactRunbookAcknowledgement({
            runbookSetIdentifier: 'osv_listing_provider_contact_runbook_set_v1',
            runbookVersion: 'osv_listing_provider_contact_runbook_v1',
            acknowledgedAt: ACK,
          }),
          'runbook ack',
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
        activePointerBaselineIdentity: uuid(),
        zeroFindingBaselineIdentity: uuid(),
      });
      return {
        input: expectOk(parsed, 'contact input'),
        legal,
        egress,
        deployment,
        haltProcedureReady: input.haltProcedureReady !== false,
      };
    }

    function compose(input: {
      readonly consumed: Awaited<ReturnType<typeof consumeListing>>;
      readonly package: ReturnType<typeof evidencePackage>;
      readonly haltProcedureReady?: boolean;
      readonly eventSink?: { emit(): unknown };
      readonly legalResult?: { current: unknown };
      readonly hooks?: {
        afterPreflight?(): void;
        afterLegal?(): void;
        beforeResult?(): void;
      };
    }) {
      const dnsCalls = { value: 0 };
      const httpCalls = { value: 0 };
      const leaseCalls = { value: 0 };
      const timerStarts = { value: 0 };
      const legalResult = input.legalResult ?? { current: input.package.legal };
      const service = createOsvListingProviderContactAuthorizationService({
        authentication: {
          authenticate() {
            return {
              outcome: 'authenticated',
              operator: identityOf(input.consumed.operatorAttestationId),
            };
          },
        },
        authorization: adapters,
        synchronization: readiness.synchronization,
        haltState: createOsvRuntimeHaltStatePort(defaultOsvRuntimeHaltSnapshot()),
        authorizationTime: {
          async current() {
            const rows = await prisma.$queryRaw<Array<{ now: Date }>>`
              SELECT CURRENT_TIMESTAMP AS now
            `;
            const now = rows[0]?.now;
            if (!(now instanceof Date)) {
              return { status: 'unavailable' as const };
            }
            return {
              status: 'observed' as const,
              databaseNow: now.toISOString().replace(/\.\d{3}Z$/, 'Z'),
            };
          },
        },
        legalAuthority: {
          inspect() {
            return Promise.resolve(legalResult.current);
          },
        },
        egressEvidence: {
          inspect() {
            return Promise.resolve(input.package.egress);
          },
        },
        deploymentApproval: {
          inspect() {
            return Promise.resolve(input.package.deployment);
          },
        },
        heartbeatPolicy: {
          inspect() {
            return Promise.resolve({
              ready: true as const,
              policyIdentifier: OSV_CANARY_HEARTBEAT_CONTROLLER_POLICY.schemaVersion,
              intervalMs: 60_000,
              leaseTtlMs: 900_000,
              maxInFlight: 1 as const,
              pendingCapacity: 0 as const,
              timerStarted: false as const,
              stopProtocol: OSV_CANARY_HEARTBEAT_CONTROLLER_POLICY.stopProtocol,
              delayedCallbackCatchUp: false as const,
            });
          },
        },
        deadlinePolicy: {
          inspect() {
            return Promise.resolve({
              ready: true as const,
              phase: 'listing_only' as const,
              durationMs: 1_800_000,
              monotonicClockAvailable: true as const,
              oneTimerMaximum: true as const,
              timerArmed: false as const,
              cancellationTargetAvailable: true as const,
              elapsedAuthority: OSV_CANARY_DEADLINE_CONTROLLER_POLICY.elapsedAuthority,
            });
          },
        },
        observability: {
          inspect() {
            return Promise.resolve({
              ready: true as const,
              eventCatalogIdentifier: OSV_LISTING_PROVIDER_CONTACT_OBSERVABILITY_POLICY_IDENTIFIER,
              requiredCountersRegistered: true as const,
              metricLabelsClosed: true as const,
              safeLogBindings: true as const,
              safeTraceAttributes: true as const,
              providerAttemptCounters: 0 as const,
              dnsLookupCount: 0 as const,
              httpCount: 0 as const,
            });
          },
        },
        activePointerBaseline: {
          inspect() {
            return readiness.activePointerBaseline.capture();
          },
        },
        zeroFindingBaseline: {
          inspect() {
            return readiness.zeroFindingBaseline.capture();
          },
        },
        haltProcedure: {
          inspect() {
            if (input.haltProcedureReady === false) {
              return Promise.resolve({ ready: false });
            }
            return Promise.resolve({
              ready: true as const,
              procedureIdentifier: OSV_LISTING_PROVIDER_CONTACT_HALT_PROCEDURE_IDENTIFIER,
            });
          },
        },
        eventSink: input.eventSink,
        hooks: input.hooks,
      });
      return { service, dnsCalls, httpCalls, leaseCalls, timerStarts };
    }

    it('fails closed with persistence_required and does not contact a provider', async () => {
      const consumed = await consumeListing();
      const preflight = await acceptedPreflight(consumed);
      const packed = evidencePackage({ consumed, preflight });
      const { service, dnsCalls, httpCalls, leaseCalls, timerStarts } = compose({
        consumed,
        package: packed,
      });
      const result = await service.evaluateOsvListingProviderContactAuthorization(packed.input);
      expect(result.ok).toBe(false);
      if (result.ok) {
        throw new Error('expected persistence_required');
      }
      expect(result.code).toBe('persistence_required');
      expect(result.providerContactAuthorizationPrepared).toBe(false);
      expect(result.providerContactAuthorizationConsumed).toBe(false);
      expect(result.providerContactStarted).toBe(false);
      expect(result.leaseAcquired).toBe(false);
      expect(result.providerCalls).toBe(0);
      expect(await prisma.osvListingProviderContactAuthorization.count()).toBe(0);
      expect(await prisma.osvCanaryProviderFreePreflightAttestation.count()).toBe(0);
      expect(dnsCalls.value).toBe(0);
      expect(httpCalls.value).toBe(0);
      expect(leaseCalls.value).toBe(0);
      expect(timerStarts.value).toBe(0);
    });

    it('fails when the halt procedure is not ready and does not clear halt', async () => {
      const consumed = await consumeListing();
      const preflight = await acceptedPreflight(consumed);
      const packed = evidencePackage({ consumed, preflight });
      const { service } = compose({ consumed, package: packed, haltProcedureReady: false });
      const result = await service.evaluateOsvListingProviderContactAuthorization(packed.input);
      expect(result.ok).toBe(false);
      if (result.ok) {
        throw new Error('expected halt procedure not ready');
      }
      expect(result.code).toBe('halt_procedure_not_ready');
      expect(result.providerCalls).toBe(0);
    });

    it('fails closed when the operator is revoked before authority inspection', async () => {
      const consumed = await consumeListing();
      const preflight = await acceptedPreflight(consumed);
      const packed = evidencePackage({ consumed, preflight });
      await adapters.operators.revoke(
        expectOk(
          createOsvCanaryOperatorRevokeCommand({
            operatorAttestationId: consumed.operatorAttestationId,
          }),
          'revoke command',
        ),
      );
      const { service } = compose({ consumed, package: packed });
      const result = await service.evaluateOsvListingProviderContactAuthorization(packed.input);
      expect(result.ok).toBe(false);
      if (result.ok) {
        throw new Error('expected revoked');
      }
      expect(result.code).toBe('operator_revoked');
    });

    it('fails closed when legal approval is invalidated during evaluation', async () => {
      const consumed = await consumeListing();
      const preflight = await acceptedPreflight(consumed);
      const packed = evidencePackage({ consumed, preflight });
      const legalResult = { current: packed.legal as unknown };
      const { service, dnsCalls, httpCalls } = compose({
        consumed,
        package: packed,
        legalResult,
        hooks: {
          afterPreflight() {
            legalResult.current = { status: 'expired' };
          },
        },
      });
      const result = await service.evaluateOsvListingProviderContactAuthorization(packed.input);
      expect(result.ok).toBe(false);
      if (result.ok) {
        throw new Error('expected expired legal');
      }
      expect(result.code).toBe('legal_authorization_expired');
      expect(result.providerCalls).toBe(0);
      expect(dnsCalls.value).toBe(0);
      expect(httpCalls.value).toBe(0);
    });

    it('cancels before the final result without mutating lease or contacting a provider', async () => {
      const consumed = await consumeListing();
      const preflight = await acceptedPreflight(consumed);
      const packed = evidencePackage({ consumed, preflight });
      const controller = new AbortController();
      const parsed = createOsvListingProviderContactAuthorizationInput({
        ...packed.input,
        operatorConfirmation: createOsvListingProviderContactConfirmation(PROOF),
        signal: controller.signal,
      });
      const cancelledInput = expectOk(parsed, 'cancelled input');
      const { service } = compose({
        consumed,
        package: packed,
        hooks: {
          beforeResult() {
            controller.abort();
          },
        },
      });
      const result = await service.evaluateOsvListingProviderContactAuthorization(cancelledInput);
      expect(result.ok).toBe(false);
      if (result.ok) {
        throw new Error('expected cancellation');
      }
      expect(result.code).toBe('cancellation_observed');
      expect(result.providerCalls).toBe(0);
      expect(result.leaseMutationCount).toBe(0);
    });

    it('rejects concurrent identical evaluations because durable issuance is required', async () => {
      const consumed = await consumeListing();
      const preflight = await acceptedPreflight(consumed);
      const first = evidencePackage({ consumed, preflight });
      const second = evidencePackage({ consumed, preflight });
      const a = compose({ consumed, package: first });
      const b = compose({ consumed, package: second });
      const [left, right] = await Promise.all([
        a.service.evaluateOsvListingProviderContactAuthorization(first.input),
        b.service.evaluateOsvListingProviderContactAuthorization(second.input),
      ]);
      expect(left.ok).toBe(false);
      expect(right.ok).toBe(false);
      if (left.ok || right.ok) {
        throw new Error('expected persistence_required');
      }
      expect(left.code).toBe('persistence_required');
      expect(right.code).toBe('persistence_required');
      expect(left.providerContactAuthorizationPrepared).toBe(false);
      expect(right.providerContactAuthorizationPrepared).toBe(false);
    });

    it('rejects a conflicting request or run binding', async () => {
      const consumed = await consumeListing();
      const preflight = await acceptedPreflight(consumed);
      const packed = evidencePackage({ consumed, preflight });
      const parsed = createOsvListingProviderContactAuthorizationInput({
        ...packed.input,
        operatorConfirmation: createOsvListingProviderContactConfirmation(PROOF),
        synchronizationRunId: uuid(),
      });
      const conflict = expectOk(parsed, 'conflict input');
      const { service } = compose({ consumed, package: packed });
      const result = await service.evaluateOsvListingProviderContactAuthorization(conflict);
      expect(result.ok).toBe(false);
      if (result.ok) {
        throw new Error('expected mismatch');
      }
      expect(result.code).toBe('request_or_run_mismatch');
      expect(result.providerCalls).toBe(0);
    });

    it('treats event-sink failure as nonauthoritative', async () => {
      const consumed = await consumeListing();
      const preflight = await acceptedPreflight(consumed);
      const packed = evidencePackage({ consumed, preflight });
      const { service } = compose({
        consumed,
        package: packed,
        eventSink: {
          emit() {
            throw new Error('sink failed');
          },
        },
      });
      const result = await service.evaluateOsvListingProviderContactAuthorization(packed.input);
      expect(result.ok).toBe(false);
      if (result.ok) {
        throw new Error('expected persistence_required');
      }
      expect(result.code).toBe('persistence_required');
      expect(result.providerContactStarted).toBe(false);
    });
  },
);
