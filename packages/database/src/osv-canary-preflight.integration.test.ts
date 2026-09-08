/**
 * Session 13 Batch 2F executable preflight PostgreSQL rehearsal.
 * Composes Batch 2C, Batch 7, and Batch 2D adapters with the preflight
 * service. No provider contact, lease mutation inside preflight, timers,
 * activation, matching, or Finding writes.
 */

import { inspect } from 'node:util';
import { randomUUID } from 'node:crypto';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { PrismaClient } from '@prisma/client';
import {
  createClosedOsvRuntimeSyncJobInput,
  createOsvCanaryActivationProhibitionAcknowledgement,
  createOsvCanaryAuthorizationEnsureCommand,
  createOsvCanaryAuthorizationLookupQuery,
  createOsvCanaryAuthorizationTerminalCommand,
  createOsvCanaryAutomaticRetryProhibitionAcknowledgement,
  createOsvCanaryHaltControlAcknowledgement,
  createOsvCanaryInstanceOperatorIdentity,
  createOsvCanaryLegalDecisionReference,
  createOsvCanaryListingReviewEvidence,
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
  OSV_CANARY_PREFLIGHT_SUCCESS_OUTCOME,
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
const HOLDER = '44444444-4444-4444-8444-444444444444';

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

describe('session 13 Batch 2F OSV canary preflight rehearsal', { timeout: 180_000 }, () => {
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

  function bodyLegal() {
    return expectOk(
      createOsvCanaryLegalDecisionReference({
        decisionId: uuid(),
        sourceRegistryVersion: 'osv_source_license_registry_v1',
        sourceIdentifier: 'rustsec_advisory_database',
        family: 'RUSTSEC',
        phase: 'bounded_body',
        permittedOperation: 'retrieve_provider_bodies',
        issuedAt: LEGAL_ISSUED,
        revalidationBoundaryAt: LEGAL_REVALIDATE,
        responsibleRole:
          'instance_legal_and_provenance_reviewer_countersigned_by_instance_operator',
        evidenceSetId: uuid(),
      }),
      'body legal',
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

  function commandInput(input: {
    readonly authorizationId: string;
    readonly operatorRequestId?: string;
    readonly correlationId?: string;
    readonly phase?: 'listing_only' | 'bounded_body';
  }) {
    const phase = input.phase ?? 'listing_only';
    return expectOk(
      createOsvCanaryOneShotCommandInput({
        commandSchemaVersion: 'osv_canary_one_shot_command_v1',
        authorizationId: input.authorizationId,
        phase,
        expectedProvider: 'rustsec_advisory_database',
        expectedPrefix: 'crates.io/',
        expectedCanaryPolicy: 'osv_disabled_first_provider_canary_policy_v1',
        expectedBudgetProfile:
          phase === 'listing_only'
            ? 'osv_canary_listing_only_budget_v1'
            : 'osv_canary_bounded_body_budget_v1',
        expectedRuntimeVersionSetFingerprint: FINGERPRINT,
        operatorRequestId: input.operatorRequestId ?? uuid(),
        correlationId: input.correlationId ?? uuid(),
        commandReason: 'operator_canary',
        authenticationProof: createOsvCanaryOperatorAuthenticationProof(PROOF),
      }),
      'command input',
    );
  }

  function preflightInput(input: {
    readonly authorizationId: string;
    readonly requestId: string;
    readonly runId: string;
    readonly phase?: 'listing_only' | 'bounded_body';
    readonly signal?: AbortSignal;
  }) {
    const phase = input.phase ?? 'listing_only';
    const base: Record<string, unknown> = {
      preflightSchemaVersion: 'osv_canary_execution_preflight_v1',
      authorizationId: input.authorizationId,
      synchronizationRequestId: input.requestId,
      synchronizationRunId: input.runId,
      phase,
      expectedProvider: 'rustsec_advisory_database',
      expectedPrefix: 'crates.io/',
      expectedCanaryPolicy: 'osv_disabled_first_provider_canary_policy_v1',
      expectedBudgetProfile:
        phase === 'listing_only'
          ? 'osv_canary_listing_only_budget_v1'
          : 'osv_canary_bounded_body_budget_v1',
      expectedRuntimeVersionSetFingerprint: FINGERPRINT,
      correlationId: uuid(),
    };
    if (input.signal !== undefined) {
      base['signal'] = input.signal;
    }
    return expectOk(createOsvCanaryPreflightInput(base), 'preflight input');
  }

  function composePreflight(
    overrides?: Partial<OsvCanaryPreflightDependencies>,
  ): ReturnType<typeof createOsvCanaryPreflightService> {
    const events: string[] = [];
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
        emit(event) {
          events.push(event.eventCode);
        },
      },
      ...overrides,
    };
    return createOsvCanaryPreflightService(dependencies);
  }

  async function consumeListing() {
    const operatorAttestationId = uuid();
    await ensureOperator(operatorAttestationId);
    const listing = await ensureListing(operatorAttestationId);
    const authorizationId = listing.authorization.snapshot.record.authorizationId;
    const prepared = await commandService(operatorAttestationId).prepareAuthorizedCanaryExecution(
      commandInput({ authorizationId }),
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

  it('passes listing-only preflight without lease mutation, timers, or Findings', async () => {
    const consumed = await consumeListing();
    const before = {
      findings: await prisma.finding.count(),
      pointers: await prisma.osvActiveCatalogPointer.count(),
      leases: await prisma.osvRuntimeLeaseProjection.count(),
    };
    let parserCalls = 0;
    let storageCalls = 0;
    const service = composePreflight({
      parserReadiness: {
        inspect() {
          parserCalls += 1;
          return rehearsalParserReadiness().inspect();
        },
      },
      objectStorageReadiness: {
        inspect() {
          storageCalls += 1;
          return rehearsalObjectStorageReadiness().inspect();
        },
      },
    });
    const result = await service.evaluateCanaryExecutionPreflight(
      preflightInput({
        authorizationId: consumed.authorizationId,
        requestId: consumed.requestId,
        runId: consumed.runId,
      }),
    );
    expect(result.ok).toBe(true);
    if (!result.ok) {
      throw new Error(result.code);
    }
    expect(result.outcome).toBe(OSV_CANARY_PREFLIGHT_SUCCESS_OUTCOME);
    expect(result.executionPermitted).toBe(false);
    expect(result.providerContactAuthorized).toBe(false);
    expect(result.providerCallCount).toBe(0);
    expect(result.leaseMutationCount).toBe(0);
    expect(result.timerStartCount).toBe(0);
    expect(result.localDependencies.parser.checked).toBe(false);
    expect(parserCalls).toBe(0);
    expect(storageCalls).toBe(0);
    expect(result.remainingGates).toContain('provider_contact_separately_authorized');
    expect(await prisma.finding.count()).toBe(before.findings);
    expect(await prisma.osvActiveCatalogPointer.count()).toBe(before.pointers);
    expect(await prisma.osvRuntimeLeaseProjection.count()).toBe(before.leases);
    expect(inspect(result)).not.toContain('holderToken');
    expect(inspect(result)).not.toContain(PROOF);
  });

  it('passes bounded-body only after listing review, storage, and parser readiness', async () => {
    const listing = await consumeListing();
    expectOk(
      await adapters.authorizations.recordTerminal(
        expectOk(
          createOsvCanaryAuthorizationTerminalCommand({
            authorizationId: listing.authorizationId,
            operatorAttestationId: listing.operatorAttestationId,
            requestId: listing.requestId,
            runId: listing.runId,
            disposition: 'completed',
            terminalReasonCode: null,
          }),
          'complete listing',
        ),
      ),
      'complete listing',
    );
    const completedListing = expectOk(
      await adapters.authorizations.lookup(
        expectOk(
          createOsvCanaryAuthorizationLookupQuery({ authorizationId: listing.authorizationId }),
          'lookup',
        ),
      ),
      'lookup',
    );
    const bodyId = uuid();
    expectOk(
      await adapters.authorizations.ensure(
        expectOk(
          createOsvCanaryAuthorizationEnsureCommand({
            authorizationId: bodyId,
            operatorAttestationId: listing.operatorAttestationId,
            phase: 'bounded_body',
            authorizationPurpose: 'bounded_body_compatibility',
            legalDecisionReference: listingLegal(),
            bodyLegalDecisionReference: bodyLegal(),
            listingReviewEvidence: expectOk(
              createOsvCanaryListingReviewEvidence({
                listingAuthorizationId: listing.authorizationId,
                listingRunId: listing.runId,
                reviewId: uuid(),
                providerPrefix: 'crates.io/',
                sourceIdentifier: 'rustsec_advisory_database',
                canonicalInventoryEvidenceId: uuid(),
                canaryPolicyIdentifier: 'osv_disabled_first_provider_canary_policy_v1',
                workScope: 'osv_runtime_canary_scope_crates_io_rustsec_v1',
                runtimeVersionSetFingerprint: FINGERPRINT,
                verdict: 'listing_canary_evidence_accepted',
                reviewedAt: completedListing.terminalAt ?? ACK,
                reviewerRole: 'instance_canary_evidence_reviewer',
              }),
              'review',
            ),
            runbookAcknowledgement: expectOk(
              createOsvCanaryRunbookAcknowledgement({
                runbookSetIdentifier: 'osv_canary_runbook_set_v1',
                runbookVersion: 'osv_canary_runbook_outlines_v1',
                acknowledgedAt: ACK,
                phase: 'bounded_body',
              }),
              'body runbook',
            ),
            haltControlAcknowledgement: expectOk(
              createOsvCanaryHaltControlAcknowledgement({ acknowledgedAt: ACK }),
              'body halt',
            ),
            activationProhibitionAcknowledgement: expectOk(
              createOsvCanaryActivationProhibitionAcknowledgement(),
              'body activation',
            ),
            automaticRetryProhibitionAcknowledgement: expectOk(
              createOsvCanaryAutomaticRetryProhibitionAcknowledgement(),
              'body retry',
            ),
          }),
          'body ensure command',
        ),
      ),
      'body ensure',
    );
    const prepared = await commandService(
      listing.operatorAttestationId,
    ).prepareAuthorizedCanaryExecution(
      commandInput({ authorizationId: bodyId, phase: 'bounded_body' }),
    );
    expect(prepared.ok).toBe(true);
    if (!prepared.ok) {
      throw new Error(prepared.code);
    }
    let parserCalls = 0;
    let storageCalls = 0;
    const service = composePreflight({
      parserReadiness: {
        inspect() {
          parserCalls += 1;
          return rehearsalParserReadiness().inspect();
        },
      },
      objectStorageReadiness: {
        inspect() {
          storageCalls += 1;
          return rehearsalObjectStorageReadiness().inspect();
        },
      },
    });
    const result = await service.evaluateCanaryExecutionPreflight(
      preflightInput({
        authorizationId: bodyId,
        requestId: prepared.synchronizationRequestId,
        runId: prepared.synchronizationRunId,
        phase: 'bounded_body',
      }),
    );
    expect(result.ok).toBe(true);
    expect(parserCalls).toBe(1);
    expect(storageCalls).toBe(1);
  });

  it('blocks default halt, unconsumed authorization, and different-run reuse', async () => {
    const operatorAttestationId = uuid();
    await ensureOperator(operatorAttestationId);
    const listing = await ensureListing(operatorAttestationId);
    const authorizationId = listing.authorization.snapshot.record.authorizationId;
    const halted = composePreflight({
      haltState: createOsvRuntimeHaltStatePort(defaultOsvRuntimeHaltSnapshot()),
    });
    const issued = await halted.evaluateCanaryExecutionPreflight(
      preflightInput({
        authorizationId,
        requestId: uuid(),
        runId: uuid(),
      }),
    );
    expect(issued.ok).toBe(false);
    if (!issued.ok) {
      expect(issued.code).toBe('authorization_not_consumed');
    }
    const consumed = await consumeListing();
    const mismatch = await composePreflight().evaluateCanaryExecutionPreflight(
      preflightInput({
        authorizationId: consumed.authorizationId,
        requestId: consumed.requestId,
        runId: uuid(),
      }),
    );
    expect(mismatch.ok).toBe(false);
    if (!mismatch.ok) {
      expect(mismatch.code).toBe('authorization_run_mismatch');
    }
    const defaultHalt = await composePreflight({
      haltState: createOsvRuntimeHaltStatePort(defaultOsvRuntimeHaltSnapshot()),
    }).evaluateCanaryExecutionPreflight(
      preflightInput({
        authorizationId: consumed.authorizationId,
        requestId: consumed.requestId,
        runId: consumed.runId,
      }),
    );
    expect(defaultHalt.ok).toBe(false);
    if (!defaultHalt.ok) {
      expect(defaultHalt.code).toBe('halt_engaged');
      expect(defaultHalt.authorizationConsumed).toBe(true);
    }
  });

  it('rejects malformed lease inspection and observability probe failure', async () => {
    const consumed = await consumeListing();
    const malformed = await composePreflight({
      leaseInspection: {
        inspectScope: async () => null,
      },
    }).evaluateCanaryExecutionPreflight(
      preflightInput({
        authorizationId: consumed.authorizationId,
        requestId: consumed.requestId,
        runId: consumed.runId,
      }),
    );
    expect(malformed.ok).toBe(false);
    if (!malformed.ok) {
      expect(malformed.code).toBe('dependency_result_malformed');
    }
    const sinkFail = await composePreflight({
      eventSink: {
        emit() {
          throw new Error('sink_failed');
        },
      },
    }).evaluateCanaryExecutionPreflight(
      preflightInput({
        authorizationId: consumed.authorizationId,
        requestId: consumed.requestId,
        runId: consumed.runId,
      }),
    );
    expect(sinkFail.ok).toBe(false);
    if (!sinkFail.ok) {
      expect(sinkFail.code).toBe('observability_not_ready');
    }
  });

  it('observes cancellation and leaves Findings and pointers unchanged', async () => {
    const consumed = await consumeListing();
    const controller = new AbortController();
    controller.abort();
    const before = {
      findings: await prisma.finding.count(),
      pointers: await prisma.osvActiveCatalogPointer.count(),
    };
    const result = await composePreflight().evaluateCanaryExecutionPreflight(
      preflightInput({
        authorizationId: consumed.authorizationId,
        requestId: consumed.requestId,
        runId: consumed.runId,
        signal: controller.signal,
      }),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe('cancellation_observed');
    }
    expect(await prisma.finding.count()).toBe(before.findings);
    expect(await prisma.osvActiveCatalogPointer.count()).toBe(before.pointers);
  });

  it('blocks lease held by another without mutating the projection', async () => {
    const consumed = await consumeListing();
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
    const request = expectOk(
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
          createOsvRuntimeSynchronizationRunEnsureCommand({ requestId: request.request.id }),
          'other run command',
        ),
      ),
      'other run',
    );
    const before = await prisma.osvRuntimeLeaseProjection.count();
    expectOk(
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
    const result = await composePreflight().evaluateCanaryExecutionPreflight(
      preflightInput({
        authorizationId: consumed.authorizationId,
        requestId: consumed.requestId,
        runId: consumed.runId,
      }),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe('lease_unavailable');
      expect(result.leaseMutationCount).toBe(0);
    }
    expect(await prisma.osvRuntimeLeaseProjection.count()).toBe(before + 1);
  });
});
