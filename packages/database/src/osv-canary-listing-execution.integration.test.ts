/**
 * Session 13 Batch 3A listing-only execution-bridge PostgreSQL rehearsal.
 * Composes Batch 2C, Batch 7, Batch 2D, Batch 2E, Batch 2F, and the
 * uncomposed Batch 3A bridge against a scripted listing port.
 * No real provider contact, body retrieval, parser, activation, matching,
 * or Finding writes. The scripted listing-capability constructor is imported
 * from compiled dist because it is not a public package export.
 */

import { inspect } from 'node:util';
import { randomUUID } from 'node:crypto';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { PrismaClient } from '@prisma/client';
import {
  createClosedOsvRuntimeSyncJobInput,
  createOsvCanaryAcceptedPreflightEvidence,
  createOsvCanaryActivationProhibitionAcknowledgement,
  createOsvCanaryAuthorizationEnsureCommand,
  createOsvCanaryAutomaticRetryProhibitionAcknowledgement,
  createOsvCanaryExecutionConfirmation,
  createOsvCanaryHaltControlAcknowledgement,
  createOsvCanaryInstanceOperatorIdentity,
  createOsvCanaryLegalDecisionReference,
  createOsvCanaryListingExecutionInput,
  createOsvCanaryListingOnlyExecutionBridge,
  createOsvListedObjectObservation,
  createOsvListingPage,
  createOsvListingPageTransportSuccess,
  createOsvTransportFailure,
  createOsvCanaryOneShotCommandInput,
  createOsvCanaryOneShotCommandService,
  createOsvCanaryOperatorAuthenticationProof,
  createOsvCanaryOperatorEnsureCommand,
  createOsvCanaryPreflightInput,
  createOsvCanaryPreflightService,
  createOsvCanaryRunbookAcknowledgement,
  createOsvRuntimeHaltStatePort,
  createOsvRuntimeJobIdempotencyIdentity,
  createOsvRuntimeLeaseAcquirePersistenceCommand,
  createOsvRuntimeLeaseAcquireSecretForOwner,
  createOsvRuntimeLeaseReleaseCommand,
  createOsvRuntimeSynchronizationRequestEnsureCommand,
  createOsvRuntimeSynchronizationRunEnsureCommand,
  createOsvRuntimeSyncJobPayload,
  createOsvRuntimeTrustedHaltSnapshot,
  defaultOsvRuntimeHaltSnapshot,
  OSV_CANARY_DEADLINE_CONTROLLER_POLICY,
  OSV_CANARY_DEADLINE_MS,
  OSV_CANARY_HEARTBEAT_CONTROLLER_POLICY,
  OSV_CANARY_HEARTBEAT_INTERVAL_MS,
  OSV_CANARY_LEASE_TTL_MS,
  OSV_CANARY_LISTING_EXECUTION_SUCCESS_OUTCOME,
  OSV_GCS_JSON_OBJECTS_LIST_HOST,
  OSV_GCS_JSON_OBJECTS_LIST_PATH,
  OSV_GCS_JSON_OBJECTS_LIST_REDIRECT_POLICY,
  OSV_GCS_JSON_OBJECTS_LIST_SCHEME,
  OSV_RUNTIME_ENABLEMENT_ARCHITECTURE_IDENTIFIER,
  OSV_RUNTIME_RETRY_POLICY_IDENTIFIER,
  osvCanaryRuntimeVersionSetFingerprint,
  synchronizationPortFromRuntimePersistence,
  type OsvCanaryAuthorizationResult,
  type OsvCanaryInstanceOperatorIdentity,
  type OsvCanaryPhase,
  type OsvCanaryPreflightDependencies,
  type OsvCanaryPreflightSuccess,
  type OsvCanaryMonotonicClockPort,
  type OsvCanaryOneShotSchedulerPort,
} from '@patchpilot/vulnerability-intelligence';

import { createOsvCanaryScriptedListingCapability } from '../../vulnerability-intelligence/dist/osv/canary-listing-execution/capability.js';
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
const EXECUTION_PROOF = 'execution-confirmation-secret';
const HOLDER = '44444444-4444-4444-8444-444444444444';
const MARKERS = [
  EXECUTION_PROOF,
  PROOF,
  'holder-token-proof',
  'pageToken=opaque',
  'provider-body-bytes',
  's3://bucket/locator',
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

function convergedListingPort(): {
  readonly port: { listPage(): Promise<unknown> };
  readonly callCount: () => number;
} {
  const observation = expectOk(
    createOsvListedObjectObservation({
      objectKey: 'crates.io/RUSTSEC-2000-0001.json',
      generation: '1',
      declaredSizeBytes: 12,
      contentType: 'application/json',
    }),
    'observation',
  );
  const page = expectOk(
    createOsvListingPage({
      providerPrefix: 'crates.io/',
      items: [observation],
      itemCount: 1,
      complete: true,
    }),
    'page',
  );
  const success = expectOk(
    createOsvListingPageTransportSuccess({
      page,
      responseByteCount: 32,
    }),
    'listing success',
  );
  let calls = 0;
  return {
    port: {
      async listPage() {
        calls += 1;
        return success;
      },
    },
    callCount: () => calls,
  };
}

function failureListingPort(kind: 'http_429'): {
  readonly port: { listPage(): Promise<unknown> };
  readonly callCount: () => number;
} {
  const failure = expectOk(createOsvTransportFailure({ kind }), 'transport failure');
  let calls = 0;
  return {
    port: {
      async listPage() {
        calls += 1;
        return { ok: false as const, failure };
      },
    },
    callCount: () => calls,
  };
}

function createFakeClock(start = 0): OsvCanaryMonotonicClockPort & { advance(ms: number): void } {
  let now = start;
  return {
    now: () => now,
    advance(ms) {
      now += ms;
    },
  };
}

function createFakeScheduler(clock: { now(): number }): OsvCanaryOneShotSchedulerPort & {
  pendingCount(): number;
} {
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
    pendingCount() {
      return items.filter((item) => !item.cancelled).length;
    },
  };
}

function rehearsalHeartbeatReadiness() {
  return {
    inspect() {
      return Promise.resolve({
        ready: true as const,
        policyIdentifier: OSV_CANARY_HEARTBEAT_CONTROLLER_POLICY.schemaVersion,
        intervalMs: OSV_CANARY_HEARTBEAT_INTERVAL_MS,
        leaseTtlMs: OSV_CANARY_LEASE_TTL_MS,
        maxInFlight: 1 as const,
        pendingCapacity: 0 as const,
        timerStarted: false as const,
        stopProtocol: OSV_CANARY_HEARTBEAT_CONTROLLER_POLICY.stopProtocol,
        delayedCallbackCatchUp: false as const,
      });
    },
  };
}

function rehearsalDeadlineReadiness() {
  return {
    inspect(input: { readonly phase: OsvCanaryPhase }) {
      return Promise.resolve({
        ready: true as const,
        phase: input.phase,
        durationMs: OSV_CANARY_DEADLINE_MS,
        monotonicClockAvailable: true as const,
        oneTimerMaximum: true as const,
        timerArmed: false as const,
        cancellationTargetAvailable: true as const,
        elapsedAuthority: OSV_CANARY_DEADLINE_CONTROLLER_POLICY.elapsedAuthority,
      });
    },
  };
}

function rehearsalEgressReadiness() {
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

function rehearsalObjectStorageReadiness() {
  return {
    inspect() {
      return Promise.resolve({
        ready: true as const,
        mutated: false as const,
      });
    },
  };
}

function rehearsalParserReadiness() {
  return {
    inspect() {
      return Promise.resolve({
        ready: true as const,
        mutated: false as const,
        activeCapacity: 1 as const,
        pendingCapacity: 0 as const,
      });
    },
  };
}

function rehearsalObservabilityReadiness() {
  return {
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
  };
}

describe(
  'session 13 Batch 3A OSV canary listing-only execution rehearsal',
  {
    timeout: 180_000,
  },
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

    function releasedHalt() {
      return createOsvRuntimeHaltStatePort(
        createOsvRuntimeTrustedHaltSnapshot({
          control: 'permitted_by_halt_control',
          source: 'explicit',
        }),
      );
    }

    function defaultHalt() {
      return createOsvRuntimeHaltStatePort(defaultOsvRuntimeHaltSnapshot());
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
        haltState: releasedHalt(),
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

    async function ensureOperator(operatorAttestationId = uuid()) {
      return expectOk(
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
    }

    async function ensureListing(operatorAttestationId: string, authorizationId = uuid()) {
      return expectOk(
        await adapters.authorizations.ensure(
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

    function commandInput(authorizationId: string) {
      return expectOk(
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
      );
    }

    function composePreflight(): ReturnType<typeof createOsvCanaryPreflightService> {
      const dependencies: OsvCanaryPreflightDependencies = {
        authorization: adapters,
        synchronization: readiness.synchronization,
        haltState: releasedHalt(),
        leaseInspection: readiness.leaseInspection,
        heartbeatReadiness: rehearsalHeartbeatReadiness(),
        deadlineReadiness: rehearsalDeadlineReadiness(),
        egressReadiness: rehearsalEgressReadiness(),
        databaseReadiness: readiness.databaseReadiness,
        objectStorageReadiness: rehearsalObjectStorageReadiness(),
        parserReadiness: rehearsalParserReadiness(),
        acquisitionPersistenceReadiness: readiness.acquisitionPersistenceReadiness,
        observabilityReadiness: rehearsalObservabilityReadiness(),
        activePointerBaseline: readiness.activePointerBaseline,
        zeroFindingBaseline: readiness.zeroFindingBaseline,
        eventSink: {
          emit() {
            return undefined;
          },
        },
      };
      return createOsvCanaryPreflightService(dependencies);
    }

    async function consumeListing() {
      const operatorAttestationId = uuid();
      await ensureOperator(operatorAttestationId);
      const listing = await ensureListing(operatorAttestationId);
      const authorizationId = listing.authorization.snapshot.record.authorizationId;
      const prepared = await commandService(operatorAttestationId).prepareAuthorizedCanaryExecution(
        commandInput(authorizationId),
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
      };
    }

    async function acceptedPreflight(consumed: Awaited<ReturnType<typeof consumeListing>>) {
      const result = await composePreflight().evaluateCanaryExecutionPreflight(
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

    function composeBridge(input: {
      readonly operatorAttestationId: string;
      readonly halt?: ReturnType<typeof releasedHalt>;
      readonly listing?: ReturnType<typeof convergedListingPort>;
    }) {
      const clock = createFakeClock();
      const scheduler = createFakeScheduler(clock);
      const scripted = input.listing ?? convergedListingPort();
      const capability = createOsvCanaryScriptedListingCapability(scripted.port);
      if (capability === null) {
        throw new Error('scripted capability');
      }
      const service = createOsvCanaryListingOnlyExecutionBridge({
        authentication: {
          authenticate() {
            return {
              outcome: 'authenticated',
              operator: identityOf(input.operatorAttestationId),
            };
          },
        },
        authorization: adapters,
        synchronization: readiness.synchronization,
        coordination,
        haltState: input.halt ?? releasedHalt(),
        egressReadiness: rehearsalEgressReadiness(),
        clock,
        scheduler,
        listingCapability: capability,
      });
      return { service, scheduler, scripted, clock };
    }

    function executionInput(input: {
      readonly authorizationId: string;
      readonly requestId: string;
      readonly runId: string;
      readonly preflight: OsvCanaryPreflightSuccess;
      readonly signal?: AbortSignal;
    }) {
      const evidenceId = uuid();
      const evidence = expectOk(
        createOsvCanaryAcceptedPreflightEvidence({
          preflightEvidenceId: evidenceId,
          preflightResult: input.preflight,
        }),
        'preflight evidence',
      );
      const base: Record<string, unknown> = {
        executionSchemaVersion: 'osv_canary_listing_only_execution_v1',
        authorizationId: input.authorizationId,
        synchronizationRequestId: input.requestId,
        synchronizationRunId: input.runId,
        preflightEvidenceId: evidenceId,
        acceptedPreflightEvidence: evidence,
        phase: 'listing_only',
        expectedProvider: 'rustsec_advisory_database',
        expectedPrefix: 'crates.io/',
        expectedCanaryPolicy: 'osv_disabled_first_provider_canary_policy_v1',
        expectedBudgetProfile: 'osv_canary_listing_only_budget_v1',
        expectedRuntimeVersionSetFingerprint: FINGERPRINT,
        correlationId: uuid(),
        executionConfirmation: createOsvCanaryExecutionConfirmation(EXECUTION_PROOF),
      };
      if (input.signal !== undefined) {
        base['signal'] = input.signal;
      }
      return expectOk(createOsvCanaryListingExecutionInput(base), 'execution input');
    }

    function expectConfidential(value: unknown): void {
      const blob = `${JSON.stringify(value)}\n${inspect(value)}\n${String(value)}`;
      for (const marker of MARKERS) {
        expect(blob).not.toContain(marker);
      }
    }

    it('converges one scripted listing-only A/B pair without real provider contact', async () => {
      const consumed = await consumeListing();
      const preflight = await acceptedPreflight(consumed);
      const before = {
        findings: await prisma.finding.count(),
        pointers: await prisma.osvActiveCatalogPointer.count(),
      };
      const { service, scheduler, scripted } = composeBridge({
        operatorAttestationId: consumed.operatorAttestationId,
      });
      const result = await service.executeListingOnlyCanary(
        executionInput({
          authorizationId: consumed.authorizationId,
          requestId: consumed.requestId,
          runId: consumed.runId,
          preflight,
        }),
      );
      if (!result.ok) {
        throw new Error(`${result.code} stage=${result.reachedStage}`);
      }
      expect(result.ok).toBe(true);
      expect(result.outcome).toBe(OSV_CANARY_LISTING_EXECUTION_SUCCESS_OUTCOME);
      expect(result.executionMode).toBe('scripted_provider_only');
      expect(result.realProviderContactAuthorized).toBe(false);
      expect(result.phase).toBe('listing_only');
      expect(result.inventoryDisposition).toBe('converged');
      expect(result.providerHttpCalls).toBe(0);
      expect(result.bodyCalls).toBe(0);
      expect(result.parserCalls).toBe(0);
      expect(result.activationCalls).toBe(0);
      expect(result.matchingCalls).toBe(0);
      expect(result.findingWrites).toBe(0);
      expect(result.scriptedListingCalls).toBe(2);
      expect(scripted.callCount()).toBe(2);
      expect(result.heartbeatOutcome).toBe('stopped');
      expect(result.deadlineOutcome).toBe('completed');
      expect(result.leaseReleaseOutcome).toBe('released');
      expect(result.runTerminalOutcome).toBe('completed');
      expect(result.authorizationTerminalOutcome).toBe('completed');
      expect(result.remainingGates).toContain('provider_contact_separately_authorized');
      expect(scheduler.pendingCount()).toBe(0);
      expect(await prisma.finding.count()).toBe(before.findings);
      expect(await prisma.osvActiveCatalogPointer.count()).toBe(before.pointers);
      expectConfidential(result);
    });

    it('blocks default halt before lease and allows same-run redelivery after halt release', async () => {
      const consumed = await consumeListing();
      const preflight = await acceptedPreflight(consumed);
      const halted = composeBridge({
        operatorAttestationId: consumed.operatorAttestationId,
        halt: defaultHalt(),
      });
      const blocked = await halted.service.executeListingOnlyCanary(
        executionInput({
          authorizationId: consumed.authorizationId,
          requestId: consumed.requestId,
          runId: consumed.runId,
          preflight,
        }),
      );
      expect(blocked.ok).toBe(false);
      if (blocked.ok) {
        throw new Error('expected halt');
      }
      expect(blocked.code).toBe('halt_engaged');
      expect(blocked.leaseReleaseOutcome).toBe('not_attempted');
      expect(halted.scripted.callCount()).toBe(0);
      const authorization = await prisma.osvCanaryAuthorization.findUniqueOrThrow({
        where: { id: consumed.authorizationId },
      });
      expect(authorization.state).toBe('consumed');
      const released = composeBridge({
        operatorAttestationId: consumed.operatorAttestationId,
      });
      const retry = await released.service.executeListingOnlyCanary(
        executionInput({
          authorizationId: consumed.authorizationId,
          requestId: consumed.requestId,
          runId: consumed.runId,
          preflight,
        }),
      );
      if (!retry.ok) {
        throw new Error(`${retry.code} stage=${retry.reachedStage}`);
      }
      expect(retry.ok).toBe(true);
      expect(retry.outcome).toBe(OSV_CANARY_LISTING_EXECUTION_SUCCESS_OUTCOME);
      expect(released.scripted.callCount()).toBe(2);
    });

    it('rejects a different-run authorization binding', async () => {
      const consumed = await consumeListing();
      const preflight = await acceptedPreflight(consumed);
      const { service, scripted } = composeBridge({
        operatorAttestationId: consumed.operatorAttestationId,
      });
      const result = await service.executeListingOnlyCanary(
        executionInput({
          authorizationId: consumed.authorizationId,
          requestId: consumed.requestId,
          runId: uuid(),
          preflight,
        }),
      );
      expect(result.ok).toBe(false);
      if (result.ok) {
        throw new Error('expected mismatch');
      }
      expect([
        'authorization_run_mismatch',
        'authorization_consumed_other_run',
        'preflight_evidence_stale',
      ]).toContain(result.code);
      expect(scripted.callCount()).toBe(0);
    });

    it('does not list when the global lease is held by another run', async () => {
      const consumed = await consumeListing();
      const preflight = await acceptedPreflight(consumed);
      const job = expectOk(
        createOsvRuntimeSyncJobPayload(
          createClosedOsvRuntimeSyncJobInput({
            synchronizationReason: 'operator_canary',
            requestedAt: '2026-09-08T12:00:00Z',
            correlationId: uuid(),
          }),
        ),
        'payload',
      );
      const otherRequest = expectOk(
        await coordination.requests.ensure(
          expectOk(
            createOsvRuntimeSynchronizationRequestEnsureCommand({
              payload: job,
              idempotency: expectOk(
                createOsvRuntimeJobIdempotencyIdentity({
                  workScope: job.workScope,
                  reason: job.synchronizationReason,
                  versionSetFingerprint: job.versionSetFingerprint,
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
        'other request',
      );
      const otherRun = expectOk(
        await coordination.runs.ensure(
          expectOk(
            createOsvRuntimeSynchronizationRunEnsureCommand({ requestId: otherRequest.request.id }),
            'other run command',
          ),
        ),
        'other run',
      );
      const acquired = expectOk(
        await coordination.leases.acquire(
          expectOk(
            createOsvRuntimeLeaseAcquirePersistenceCommand({
              runId: otherRun.run.id,
              secret: expectOk(
                createOsvRuntimeLeaseAcquireSecretForOwner({ holderToken: HOLDER }),
                'secret',
              ),
              architectureIdentifier: OSV_RUNTIME_ENABLEMENT_ARCHITECTURE_IDENTIFIER,
              retryPolicyIdentifier: OSV_RUNTIME_RETRY_POLICY_IDENTIFIER,
              expectedLeaseRevision: null,
              expectedFencingToken: null,
            }),
            'acquire command',
          ),
        ),
        'acquire',
      );
      if (acquired.proof === null) {
        throw new Error('missing other-owner proof');
      }
      try {
        const { service, scripted } = composeBridge({
          operatorAttestationId: consumed.operatorAttestationId,
        });
        const result = await service.executeListingOnlyCanary(
          executionInput({
            authorizationId: consumed.authorizationId,
            requestId: consumed.requestId,
            runId: consumed.runId,
            preflight,
          }),
        );
        expect(result.ok).toBe(false);
        if (result.ok) {
          throw new Error('expected held-by-other');
        }
        expect(result.code).toBe('lease_held_by_other');
        expect(scripted.callCount()).toBe(0);
      } finally {
        expectOk(
          await coordination.leases.release(
            expectOk(
              createOsvRuntimeLeaseReleaseCommand({
                proof: acquired.proof,
                reason: 'completed',
              }),
              'release command',
            ),
          ),
          'release other owner',
        );
      }
    });

    it('records HTTP 429 without an automatic second listing attempt', async () => {
      const consumed = await consumeListing();
      const preflight = await acceptedPreflight(consumed);
      const { service, scripted } = composeBridge({
        operatorAttestationId: consumed.operatorAttestationId,
        listing: failureListingPort('http_429'),
      });
      const result = await service.executeListingOnlyCanary(
        executionInput({
          authorizationId: consumed.authorizationId,
          requestId: consumed.requestId,
          runId: consumed.runId,
          preflight,
        }),
      );
      expect(result.ok).toBe(false);
      if (result.ok) {
        throw new Error('expected 429');
      }
      expect(result.code).toBe('http_429');
      expect(scripted.callCount()).toBe(1);
      expect(result.automaticRetry).toBe(false);
    });

    it('replays a completed same-run terminal without a second listing', async () => {
      const consumed = await consumeListing();
      const preflight = await acceptedPreflight(consumed);
      const first = composeBridge({
        operatorAttestationId: consumed.operatorAttestationId,
      });
      const success = await first.service.executeListingOnlyCanary(
        executionInput({
          authorizationId: consumed.authorizationId,
          requestId: consumed.requestId,
          runId: consumed.runId,
          preflight,
        }),
      );
      if (!success.ok) {
        throw new Error(`${success.code} stage=${success.reachedStage}`);
      }
      expect(success.ok).toBe(true);
      const second = composeBridge({
        operatorAttestationId: consumed.operatorAttestationId,
      });
      const replay = await second.service.executeListingOnlyCanary(
        executionInput({
          authorizationId: consumed.authorizationId,
          requestId: consumed.requestId,
          runId: consumed.runId,
          preflight,
        }),
      );
      expect(replay.ok).toBe(true);
      if (!replay.ok) {
        throw new Error(replay.code);
      }
      expect(replay.replayMode).toBe('same_run_status_inspection');
      expect(second.scripted.callCount()).toBe(0);
      expect(replay.providerHttpCalls).toBe(0);
    });

    it('rejects a second concurrent invocation on the same service instance', async () => {
      const consumed = await consumeListing();
      const preflight = await acceptedPreflight(consumed);
      let release: (() => void) | undefined;
      const gate = new Promise<void>((resolve) => {
        release = resolve;
      });
      const inner = convergedListingPort();
      const gated = {
        async listPage() {
          await gate;
          return inner.port.listPage();
        },
      };
      const capability = createOsvCanaryScriptedListingCapability(gated);
      if (capability === null) {
        throw new Error('scripted capability');
      }
      const clock = createFakeClock();
      const scheduler = createFakeScheduler(clock);
      const service = createOsvCanaryListingOnlyExecutionBridge({
        authentication: {
          authenticate() {
            return {
              outcome: 'authenticated',
              operator: identityOf(consumed.operatorAttestationId),
            };
          },
        },
        authorization: adapters,
        synchronization: readiness.synchronization,
        coordination,
        haltState: releasedHalt(),
        egressReadiness: rehearsalEgressReadiness(),
        clock,
        scheduler,
        listingCapability: capability,
      });
      const firstPromise = service.executeListingOnlyCanary(
        executionInput({
          authorizationId: consumed.authorizationId,
          requestId: consumed.requestId,
          runId: consumed.runId,
          preflight,
        }),
      );
      await Promise.resolve();
      const concurrent = await service.executeListingOnlyCanary(
        executionInput({
          authorizationId: consumed.authorizationId,
          requestId: consumed.requestId,
          runId: consumed.runId,
          preflight,
        }),
      );
      expect(concurrent.ok).toBe(false);
      if (concurrent.ok) {
        throw new Error('expected concurrent rejection');
      }
      expect(concurrent.code).toBe('internal_failure');
      release?.();
      const first = await firstPromise;
      if (!first.ok) {
        throw new Error(`${first.code} stage=${first.reachedStage}`);
      }
      expect(first.ok).toBe(true);
    });
  },
);
