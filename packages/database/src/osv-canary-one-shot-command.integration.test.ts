/**
 * Session 13 Batch 2D one-shot command PostgreSQL integration tests.
 * Composes Batch 2C and Batch 7 adapters. No provider contact, lease
 * acquisition, or OSV enablement.
 */

import { inspect } from 'node:util';
import { randomUUID } from 'node:crypto';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { PrismaClient } from '@prisma/client';
import {
  createClosedOsvRuntimeSyncJobInput,
  createOsvCanaryActivationProhibitionAcknowledgement,
  createOsvCanaryAuthorizationCancelCommand,
  createOsvCanaryAuthorizationEnsureCommand,
  createOsvCanaryAuthorizationLookupQuery,
  createOsvCanaryAuthorizationRevokeCommand,
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
  createOsvCanaryOperatorRevokeCommand,
  createOsvCanaryRunbookAcknowledgement,
  createOsvRuntimeHaltStatePort,
  createOsvRuntimeJobIdempotencyIdentity,
  createOsvRuntimeSynchronizationRequestEnsureCommand,
  createOsvRuntimeSynchronizationRunEnsureCommand,
  createOsvRuntimeSyncJobPayload,
  createOsvRuntimeTrustedHaltSnapshot,
  defaultOsvRuntimeHaltSnapshot,
  osvCanaryRuntimeVersionSetFingerprint,
  synchronizationPortFromRuntimePersistence,
  type OsvCanaryAuthorizationPersistencePort,
  type OsvCanaryAuthorizationResult,
  type OsvCanaryInstanceOperatorIdentity,
} from '@patchpilot/vulnerability-intelligence';

import { createOsvCanaryAuthorizationPersistence } from './osv-canary-authorization-persistence.js';
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

describe('session 13 Batch 2D OSV canary one-shot command', { timeout: 180_000 }, () => {
  let databaseName: string;
  let databaseUrl: string;
  let admin: PrismaClient;
  let prisma: PrismaClient;
  let adapters: ReturnType<typeof createOsvCanaryAuthorizationPersistence>;
  let coordination: ReturnType<typeof createOsvRuntimeCoordinationPersistence>;

  beforeAll(async () => {
    const ephemeral = await createEphemeralDatabase('it');
    databaseName = ephemeral.databaseName;
    databaseUrl = ephemeral.databaseUrl;
    admin = ephemeral.admin;
    await deployMigrations(ephemeral.databaseUrl);
    prisma = new PrismaClient({
      datasources: { db: { url: ephemeral.databaseUrl } },
    });
    adapters = createOsvCanaryAuthorizationPersistence(prisma);
    coordination = createOsvRuntimeCoordinationPersistence(prisma);
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

  function commandService(input?: {
    readonly operatorAttestationId: string;
    readonly authorization?: OsvCanaryAuthorizationPersistencePort;
    readonly halt?: ReturnType<typeof createOsvRuntimeHaltStatePort>;
    readonly consumeAbort?: AbortController;
  }) {
    const operatorAttestationId = input?.operatorAttestationId ?? uuid();
    const authorization = input?.authorization ?? adapters;
    const consumeAbort = input?.consumeAbort;
    const wrapped: OsvCanaryAuthorizationPersistencePort =
      consumeAbort === undefined
        ? authorization
        : {
            operators: authorization.operators,
            authorizations: {
              ensure: (command) => authorization.authorizations.ensure(command),
              lookup: (command) => authorization.authorizations.lookup(command),
              inspectValidity: (command) => authorization.authorizations.inspectValidity(command),
              consume: async (command) => {
                const result = await authorization.authorizations.consume(command);
                consumeAbort.abort();
                return result;
              },
              revoke: (command) => authorization.authorizations.revoke(command),
              cancel: (command) => authorization.authorizations.cancel(command),
              expire: (command) => authorization.authorizations.expire(command),
              recordTerminal: (command) => authorization.authorizations.recordTerminal(command),
            },
          };
    return createOsvCanaryOneShotCommandService({
      authentication: {
        authenticate() {
          return { outcome: 'authenticated', operator: identityOf(operatorAttestationId) };
        },
      },
      authorization: wrapped,
      synchronization: synchronizationPortFromRuntimePersistence({
        requests: coordination.requests,
        runs: coordination.runs,
        inspectByOperatorRequestId,
      }),
      haltState: input?.halt ?? releasedHalt(),
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

  async function insertExpiredIssuedListing(operatorAttestationId: string): Promise<string> {
    const authorizationId = uuid();
    await prisma.$executeRaw`
      INSERT INTO "osv_canary_authorization" (
        "id", "operator_identity_id", "authorization_schema_version",
        "canary_architecture_identifier", "runtime_architecture_identifier",
        "listing_protocol_identifier", "actor_kind", "phase", "synchronization_reason",
        "authorization_purpose", "provider_prefix", "source_identifier", "family",
        "canary_policy_identifier", "work_scope", "lease_scope",
        "runtime_version_set_fingerprint", "budget_profile_identifier", "unused_ttl_seconds",
        "single_use_policy", "catalog_activation_authorization", "matching_authorization",
        "finding_authorization", "postcanary_review_requirement",
        "legal_decision_reference_identifier", "legal_decision_id",
        "legal_decision_source_registry_version", "legal_decision_phase",
        "legal_decision_permitted_operation", "legal_decision_state", "legal_decision_issuance",
        "legal_decision_issued_at", "legal_decision_revalidation_boundary_at",
        "legal_decision_responsible_role", "legal_decision_evidence_set_id",
        "runbook_set_identifier", "runbook_version", "runbook_acknowledged_at",
        "runbook_emergency_halt_procedure", "halt_acknowledgement_identifier",
        "halt_acknowledged_at", "activation_prohibition_identifier",
        "retry_prohibition_identifier", "issued_at", "expires_at", "state", "created_at"
      ) VALUES (
        ${authorizationId}::uuid, ${operatorAttestationId}::uuid,
        'osv_canary_execution_authorization_record_v1',
        'osv_first_real_provider_canary_authorization_v1',
        'osv_runtime_enablement_architecture_v1', 'osv_gcs_json_objects_list_v1',
        'instance_operator', 'listing_only', 'operator_canary',
        'initial_listing_compatibility', 'crates.io/', 'rustsec_advisory_database',
        'RUSTSEC', 'osv_disabled_first_provider_canary_policy_v1',
        'osv_runtime_canary_scope_crates_io_rustsec_v1',
        'osv_runtime_lease_scope_osv_gcs_public_export_v1', ${FINGERPRINT},
        'osv_canary_listing_only_budget_v1', 3600, 'single_use', 'prohibited',
        'prohibited', 'prohibited', 'required',
        'osv_canary_legal_decision_reference_v1', ${uuid()}::uuid,
        'osv_source_license_registry_v1', 'listing_only', 'list_object_metadata',
        'recorded_reference_not_execution_authority',
        'blocking_preexecution_dependency_not_issued_in_batch_2a',
        ${new Date(LEGAL_ISSUED)}, ${new Date(LEGAL_REVALIDATE)},
        'instance_legal_and_provenance_reviewer_countersigned_by_instance_operator',
        ${uuid()}::uuid, 'osv_canary_runbook_set_v1', 'osv_canary_runbook_outlines_v1',
        ${new Date(ACK)}, 'stop_next_protected_stage_production_remains_halted',
        'osv_canary_halt_control_acknowledgement_v1', ${new Date(ACK)},
        'osv_canary_activation_prohibition_v1',
        'osv_canary_automatic_retry_prohibition_v1',
        CURRENT_TIMESTAMP - INTERVAL '3600 seconds',
        CURRENT_TIMESTAMP,
        'issued', CURRENT_TIMESTAMP - INTERVAL '3600 seconds'
      )
    `;
    return authorizationId;
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
    readonly signal?: AbortSignal;
  }) {
    const phase = input.phase ?? 'listing_only';
    const base: Record<string, unknown> = {
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
    };
    if (input.signal !== undefined) {
      base['signal'] = input.signal;
    }
    return expectOk(createOsvCanaryOneShotCommandInput(base), 'command input');
  }

  async function counts() {
    return {
      leases: await prisma.osvRuntimeLeaseProjection.count(),
      attempts: await prisma.osvRuntimeStageAttempt.count(),
      pointers: await prisma.osvActiveCatalogPointer.count(),
      findings: await prisma.finding.count(),
      organizations: await prisma.organization.count(),
      requests: await prisma.osvRuntimeSynchronizationRequest.count(),
      runs: await prisma.osvRuntimeSynchronizationRun.count(),
    };
  }

  it('prepares listing-only and bounded-body commands without lease or Finding writes', async () => {
    const before = await counts();
    const operatorAttestationId = uuid();
    await ensureOperator(operatorAttestationId);
    const listing = await ensureListing(operatorAttestationId);
    const listingId = listing.authorization.snapshot.record.authorizationId;
    const service = commandService({ operatorAttestationId });
    const listingResult = await service.prepareAuthorizedCanaryExecution(
      commandInput({ authorizationId: listingId }),
    );
    expect(listingResult.ok).toBe(true);
    if (!listingResult.ok) {
      return;
    }
    expect(listingResult.outcome).toBe('authorized_preflight_required');
    expect(listingResult.authorizationConsumptionOutcome).toBe('consumed_now');
    expect(listingResult.executionPermitted).toBe(false);
    expect(listingResult.providerCallCount).toBe(0);
    expect(listingResult.leaseCallCount).toBe(0);
    const completed = expectOk(
      await adapters.authorizations.recordTerminal(
        expectOk(
          createOsvCanaryAuthorizationTerminalCommand({
            authorizationId: listingId,
            operatorAttestationId,
            requestId: listingResult.synchronizationRequestId,
            runId: listingResult.synchronizationRunId,
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
        expectOk(createOsvCanaryAuthorizationLookupQuery({ authorizationId: listingId }), 'lookup'),
      ),
      'lookup',
    );
    const review = expectOk(
      createOsvCanaryListingReviewEvidence({
        listingAuthorizationId: listingId,
        listingRunId: listingResult.synchronizationRunId,
        reviewId: uuid(),
        providerPrefix: 'crates.io/',
        sourceIdentifier: 'rustsec_advisory_database',
        canonicalInventoryEvidenceId: uuid(),
        canaryPolicyIdentifier: 'osv_disabled_first_provider_canary_policy_v1',
        workScope: 'osv_runtime_canary_scope_crates_io_rustsec_v1',
        runtimeVersionSetFingerprint: FINGERPRINT,
        verdict: 'listing_canary_evidence_accepted',
        reviewedAt: completedListing.terminalAt ?? completed.authorization.terminalAt ?? ACK,
        reviewerRole: 'instance_canary_evidence_reviewer',
      }),
      'review',
    );
    const bodyId = uuid();
    expectOk(
      await adapters.authorizations.ensure(
        expectOk(
          createOsvCanaryAuthorizationEnsureCommand({
            authorizationId: bodyId,
            operatorAttestationId,
            phase: 'bounded_body',
            authorizationPurpose: 'bounded_body_compatibility',
            legalDecisionReference: listingLegal(),
            bodyLegalDecisionReference: bodyLegal(),
            listingReviewEvidence: review,
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
          'body command',
        ),
      ),
      'body ensure',
    );
    const bodyResult = await service.prepareAuthorizedCanaryExecution(
      commandInput({ authorizationId: bodyId, phase: 'bounded_body' }),
    );
    expect(bodyResult.ok).toBe(true);
    if (bodyResult.ok) {
      expect(bodyResult.phase).toBe('bounded_body');
      expect(bodyResult.executionPermitted).toBe(false);
    }
    const after = await counts();
    expect(after.leases).toBe(before.leases);
    expect(after.attempts).toBe(before.attempts);
    expect(after.pointers).toBe(before.pointers);
    expect(after.findings).toBe(before.findings);
    expect(after.organizations).toBe(before.organizations);
    const serialized = `${JSON.stringify(listingResult)}\n${inspect(listingResult)}`;
    expect(serialized).not.toContain(PROOF);
    expect(serialized).not.toContain('holderToken');
    expect(serialized).not.toContain('organizationId');
  });

  it('rejects unknown operators, revoked operators, and operator identity mismatch', async () => {
    const known = uuid();
    const other = uuid();
    await ensureOperator(known);
    await ensureOperator(other);
    const listing = await ensureListing(other);
    const absent = await commandService({
      operatorAttestationId: uuid(),
    }).prepareAuthorizedCanaryExecution(
      commandInput({ authorizationId: listing.authorization.snapshot.record.authorizationId }),
    );
    expect(absent.ok).toBe(false);
    if (!absent.ok) {
      expect(absent.code).toBe('operator_absent');
    }
    const mismatch = await commandService({
      operatorAttestationId: known,
    }).prepareAuthorizedCanaryExecution(
      commandInput({ authorizationId: listing.authorization.snapshot.record.authorizationId }),
    );
    expect(mismatch.ok).toBe(false);
    if (!mismatch.ok) {
      expect(mismatch.code).toBe('authorization_absent');
    }
    expectOk(
      await adapters.operators.revoke(
        expectOk(createOsvCanaryOperatorRevokeCommand({ operatorAttestationId: other }), 'revoke'),
      ),
      'revoke',
    );
    const revoked = await commandService({
      operatorAttestationId: other,
    }).prepareAuthorizedCanaryExecution(
      commandInput({ authorizationId: listing.authorization.snapshot.record.authorizationId }),
    );
    expect(revoked.ok).toBe(false);
    if (!revoked.ok) {
      expect(revoked.code).toBe('operator_revoked');
    }
  });

  it('leaves issued authorization available when halt is engaged', async () => {
    const operatorAttestationId = uuid();
    await ensureOperator(operatorAttestationId);
    const listing = await ensureListing(operatorAttestationId);
    const authorizationId = listing.authorization.snapshot.record.authorizationId;
    const before = await prisma.osvRuntimeSynchronizationRequest.count();
    const result = await commandService({
      operatorAttestationId,
      halt: createOsvRuntimeHaltStatePort(defaultOsvRuntimeHaltSnapshot()),
    }).prepareAuthorizedCanaryExecution(commandInput({ authorizationId }));
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe('halt_engaged');
      expect(result.authorizationConsumed).toBe(false);
    }
    expect(await prisma.osvRuntimeSynchronizationRequest.count()).toBe(before);
    const validity = expectOk(
      await adapters.authorizations.inspectValidity(
        expectOk(createOsvCanaryAuthorizationLookupQuery({ authorizationId }), 'validity'),
      ),
      'validity',
    );
    expect(validity.status === 'issued_and_unexpired' || validity.persistedState === 'issued').toBe(
      true,
    );
  });

  it('replays request and run authority, then treats same-run command replay as status reuse', async () => {
    const operatorAttestationId = uuid();
    await ensureOperator(operatorAttestationId);
    const listing = await ensureListing(operatorAttestationId);
    const authorizationId = listing.authorization.snapshot.record.authorizationId;
    const operatorRequestId = uuid();
    const correlationId = uuid();
    const payload = expectOk(
      createOsvRuntimeSyncJobPayload(
        createClosedOsvRuntimeSyncJobInput({
          synchronizationReason: 'operator_canary',
          requestedAt: listing.authorization.snapshot.record.issuedAt,
          correlationId,
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
                operatorRequestId,
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
    const service = commandService({ operatorAttestationId });
    const first = await service.prepareAuthorizedCanaryExecution(
      commandInput({ authorizationId, operatorRequestId, correlationId }),
    );
    expect(first.ok).toBe(true);
    if (first.ok) {
      expect(first.synchronizationRequestId).toBe(request.request.id);
      expect(first.synchronizationRunId).toBe(run.run.id);
      expect(first.authorizationConsumptionOutcome).toBe('consumed_now');
    }
    const second = await service.prepareAuthorizedCanaryExecution(
      commandInput({ authorizationId, operatorRequestId, correlationId }),
    );
    expect(second.ok).toBe(true);
    if (second.ok) {
      expect(second.authorizationConsumptionOutcome).toBe('already_consumed_same_run');
      expect(second.executionPermitted).toBe(false);
    }
    const other = await service.prepareAuthorizedCanaryExecution(
      commandInput({ authorizationId, operatorRequestId: uuid() }),
    );
    expect(other.ok).toBe(false);
    if (!other.ok) {
      expect(other.code).toBe('authorization_consumed_other_run');
    }
  });

  it('expires, revokes, and cancels before consumption without creating a second authorization', async () => {
    const operatorAttestationId = uuid();
    await ensureOperator(operatorAttestationId);
    const expiredId = await insertExpiredIssuedListing(operatorAttestationId);
    const expired = await commandService({
      operatorAttestationId,
    }).prepareAuthorizedCanaryExecution(commandInput({ authorizationId: expiredId }));
    expect(expired.ok).toBe(false);
    if (!expired.ok) {
      expect(expired.code).toBe('authorization_expired');
    }
    const revokedListing = await ensureListing(operatorAttestationId);
    const revokedId = revokedListing.authorization.snapshot.record.authorizationId;
    expectOk(
      await adapters.authorizations.revoke(
        expectOk(
          createOsvCanaryAuthorizationRevokeCommand({
            authorizationId: revokedId,
            operatorAttestationId,
          }),
          'revoke auth',
        ),
      ),
      'revoke auth',
    );
    const revoked = await commandService({
      operatorAttestationId,
    }).prepareAuthorizedCanaryExecution(commandInput({ authorizationId: revokedId }));
    expect(revoked.ok).toBe(false);
    if (!revoked.ok) {
      expect(revoked.code).toBe('authorization_revoked');
    }
    const cancelledListing = await ensureListing(operatorAttestationId);
    const cancelledId = cancelledListing.authorization.snapshot.record.authorizationId;
    expectOk(
      await adapters.authorizations.cancel(
        expectOk(
          createOsvCanaryAuthorizationCancelCommand({
            authorizationId: cancelledId,
            operatorAttestationId,
          }),
          'cancel',
        ),
      ),
      'cancel',
    );
    const cancelled = await commandService({
      operatorAttestationId,
    }).prepareAuthorizedCanaryExecution(commandInput({ authorizationId: cancelledId }));
    expect(cancelled.ok).toBe(false);
    if (!cancelled.ok) {
      expect(cancelled.code).toBe('authorization_cancelled');
    }
  });

  it('admits one concurrent same-run winner and rejects a concurrent different-run', async () => {
    const operatorAttestationId = uuid();
    await ensureOperator(operatorAttestationId);
    const listing = await ensureListing(operatorAttestationId);
    const authorizationId = listing.authorization.snapshot.record.authorizationId;
    const operatorRequestId = uuid();
    const correlationId = uuid();
    const payload = expectOk(
      createOsvRuntimeSyncJobPayload(
        createClosedOsvRuntimeSyncJobInput({
          synchronizationReason: 'operator_canary',
          requestedAt: listing.authorization.snapshot.record.issuedAt,
          correlationId,
        }),
      ),
      'concurrent payload',
    );
    const concurrentRequest = expectOk(
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
                operatorRequestId,
              }),
              'concurrent idempotency',
            ),
            requestState: 'accepted',
          }),
          'concurrent request command',
        ),
      ),
      'concurrent request',
    );
    expectOk(
      await coordination.runs.ensure(
        expectOk(
          createOsvRuntimeSynchronizationRunEnsureCommand({
            requestId: concurrentRequest.request.id,
          }),
          'concurrent run command',
        ),
      ),
      'concurrent run',
    );
    const leftClient = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
    const rightClient = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
    try {
      const leftAuth = createOsvCanaryAuthorizationPersistence(leftClient);
      const rightAuth = createOsvCanaryAuthorizationPersistence(rightClient);
      const leftCoord = createOsvRuntimeCoordinationPersistence(leftClient);
      const rightCoord = createOsvRuntimeCoordinationPersistence(rightClient);
      const left = createOsvCanaryOneShotCommandService({
        authentication: {
          authenticate() {
            return { outcome: 'authenticated', operator: identityOf(operatorAttestationId) };
          },
        },
        authorization: leftAuth,
        synchronization: synchronizationPortFromRuntimePersistence({
          requests: leftCoord.requests,
          runs: leftCoord.runs,
          inspectByOperatorRequestId,
        }),
        haltState: releasedHalt(),
      });
      const right = createOsvCanaryOneShotCommandService({
        authentication: {
          authenticate() {
            return { outcome: 'authenticated', operator: identityOf(operatorAttestationId) };
          },
        },
        authorization: rightAuth,
        synchronization: synchronizationPortFromRuntimePersistence({
          requests: rightCoord.requests,
          runs: rightCoord.runs,
          inspectByOperatorRequestId,
        }),
        haltState: releasedHalt(),
      });
      const [sameLeft, sameRight] = await Promise.all([
        left.prepareAuthorizedCanaryExecution(
          commandInput({ authorizationId, operatorRequestId, correlationId }),
        ),
        right.prepareAuthorizedCanaryExecution(
          commandInput({ authorizationId, operatorRequestId, correlationId }),
        ),
      ]);
      const describeResult = (
        result: Awaited<ReturnType<typeof left.prepareAuthorizedCanaryExecution>>,
      ): string => (result.ok ? result.authorizationConsumptionOutcome : result.code);
      const concurrentOutcomes = [describeResult(sameLeft), describeResult(sameRight)];
      expect(concurrentOutcomes, concurrentOutcomes.join(' ')).toContain('consumed_now');
      expect(
        concurrentOutcomes.every(
          (outcome) =>
            outcome === 'consumed_now' ||
            outcome === 'already_consumed_same_run' ||
            outcome === 'database_unavailable',
        ),
        concurrentOutcomes.join(' '),
      ).toBe(true);
      expect(sameLeft.ok ? sameLeft.executionPermitted : sameLeft.leaseCallCount).toBe(
        sameLeft.ok ? false : 0,
      );
      expect(sameRight.ok ? sameRight.executionPermitted : sameRight.leaseCallCount).toBe(
        sameRight.ok ? false : 0,
      );
      const otherListing = await ensureListing(operatorAttestationId);
      const otherId = otherListing.authorization.snapshot.record.authorizationId;
      const [first, second] = await Promise.all([
        left.prepareAuthorizedCanaryExecution(commandInput({ authorizationId: otherId })),
        right.prepareAuthorizedCanaryExecution(commandInput({ authorizationId: otherId })),
      ]);
      const codes = [first, second].map((result) =>
        result.ok ? result.authorizationConsumptionOutcome : result.code,
      );
      expect(codes).toContain('consumed_now');
      expect(
        codes.includes('already_consumed_same_run') ||
          codes.includes('authorization_consumed_other_run') ||
          codes.includes('database_unavailable'),
      ).toBe(true);
      expect(first.ok ? first.executionPermitted : first.leaseCallCount).toBe(first.ok ? false : 0);
    } finally {
      await leftClient.$disconnect();
      await rightClient.$disconnect();
    }
  });

  it('cancels before consumption and reports consumed status after committed consumption', async () => {
    const operatorAttestationId = uuid();
    await ensureOperator(operatorAttestationId);
    const listing = await ensureListing(operatorAttestationId);
    const authorizationId = listing.authorization.snapshot.record.authorizationId;
    const controller = new AbortController();
    controller.abort();
    const cancelled = await commandService({
      operatorAttestationId,
    }).prepareAuthorizedCanaryExecution(
      commandInput({ authorizationId, signal: controller.signal }),
    );
    expect(cancelled.ok).toBe(false);
    if (!cancelled.ok) {
      expect(cancelled.code).toBe('cancelled');
      expect(cancelled.authorizationConsumed).toBe(false);
    }
    const after = new AbortController();
    const consumed = await commandService({
      operatorAttestationId,
      consumeAbort: after,
    }).prepareAuthorizedCanaryExecution(commandInput({ authorizationId, signal: after.signal }));
    expect(consumed.ok).toBe(true);
    if (consumed.ok) {
      expect(consumed.authorizationConsumptionOutcome).toBe('consumed_now');
      expect(consumed.cancellation.observed).toBe(true);
    }
  });
});
