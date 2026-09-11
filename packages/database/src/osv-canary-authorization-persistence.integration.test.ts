import { inspect } from 'node:util';
import { randomUUID } from 'node:crypto';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { PrismaClient } from '@prisma/client';
import {
  createClosedOsvRuntimeSyncJobInput,
  createOsvCanaryActivationProhibitionAcknowledgement,
  createOsvCanaryAuthorizationCancelCommand,
  createOsvCanaryAuthorizationConsumePersistenceCommand,
  createOsvCanaryAuthorizationEnsureCommand,
  createOsvCanaryAuthorizationExpireCommand,
  createOsvCanaryAuthorizationLookupQuery,
  createOsvCanaryAuthorizationRevokeCommand,
  createOsvCanaryAuthorizationTerminalCommand,
  createOsvCanaryAutomaticRetryProhibitionAcknowledgement,
  createOsvCanaryHaltControlAcknowledgement,
  createOsvCanaryLegalDecisionReference,
  createOsvCanaryListingReviewEvidence,
  createOsvCanaryOperatorEnsureCommand,
  createOsvCanaryOperatorLookupQuery,
  createOsvCanaryOperatorRevokeCommand,
  createOsvCanaryRunbookAcknowledgement,
  createOsvRuntimeJobIdempotencyIdentity,
  createOsvRuntimeSynchronizationRequestEnsureCommand,
  createOsvRuntimeSynchronizationRunEnsureCommand,
  createOsvRuntimeSyncJobPayload,
  osvCanaryRuntimeVersionSetFingerprint,
  type OsvCanaryAuthorizationResult,
} from '@patchpilot/vulnerability-intelligence';

import { createOsvCanaryAuthorizationPersistence } from './osv-canary-authorization-persistence.js';
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

function displayLabel(): string {
  return `canary-op-${uuid().slice(0, 8)}`;
}

describe('session 13 Batch 2C OSV canary authorization adapters', { timeout: 180_000 }, () => {
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

  async function ensureOperator(operatorAttestationId = uuid(), label = displayLabel()) {
    return expectOk(
      await adapters.operators.ensure(
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

  function bodyLegal(decisionId = uuid(), evidenceSetId = uuid()) {
    return expectOk(
      createOsvCanaryLegalDecisionReference({
        decisionId,
        sourceRegistryVersion: 'osv_source_license_registry_v1',
        sourceIdentifier: 'rustsec_advisory_database',
        family: 'RUSTSEC',
        phase: 'bounded_body',
        permittedOperation: 'retrieve_provider_bodies',
        issuedAt: LEGAL_ISSUED,
        revalidationBoundaryAt: LEGAL_REVALIDATE,
        responsibleRole:
          'instance_legal_and_provenance_reviewer_countersigned_by_instance_operator',
        evidenceSetId,
      }),
      'body legal',
    );
  }

  function listingEnsureInput(operatorAttestationId: string, authorizationId = uuid()) {
    return {
      authorizationId,
      operatorAttestationId,
      phase: 'listing_only' as const,
      authorizationPurpose: 'initial_listing_compatibility' as const,
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
    };
  }

  async function ensureListing(operatorAttestationId: string, authorizationId = uuid()) {
    return expectOk(
      await adapters.authorizations.ensure(
        expectOk(
          createOsvCanaryAuthorizationEnsureCommand(
            listingEnsureInput(operatorAttestationId, authorizationId),
          ),
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

  async function consumeListing(
    authorizationId: string,
    operatorAttestationId: string,
    requestId: string,
    runId: string,
  ) {
    return expectOk(
      await adapters.authorizations.consume(
        expectOk(
          createOsvCanaryAuthorizationConsumePersistenceCommand({
            authorizationId,
            operatorAttestationId,
            phase: 'listing_only',
            providerPrefix: 'crates.io/',
            canaryPolicyIdentifier: 'osv_disabled_first_provider_canary_policy_v1',
            runtimeVersionSetFingerprint: FINGERPRINT,
            requestId,
            runId,
          }),
          'consume command',
        ),
      ),
      'consume',
    );
  }

  it('ensures operator identity insert-once and detects immutable conflicts', async () => {
    const operatorAttestationId = uuid();
    const label = displayLabel();
    const created = await ensureOperator(operatorAttestationId, label);
    expect(created.status).toBe('created');
    expect(created.operator.identity.status).toBe('active');
    expect(created.operator.revokedAt).toBeNull();
    const replay = await ensureOperator(operatorAttestationId, label);
    expect(replay.status).toBe('already_applied');
    expect(replay.operator.identity.establishedAt).toBe(created.operator.identity.establishedAt);
    const conflict = await adapters.operators.ensure(
      expectOk(
        createOsvCanaryOperatorEnsureCommand({
          operatorAttestationId,
          identityType: 'instance_operator',
          authenticationSource: 'local_host_control_of_one_shot_administrative_command',
          displayLabel: displayLabel(),
          provenanceIdentifier: 'configured_instance_operator_attestation_v1',
        }),
        'conflict command',
      ),
    );
    expect(conflict.ok).toBe(false);
    if (!conflict.ok) {
      expect(conflict.code).toBe('immutable_conflict');
    }
  });

  it('inspects operator authority and revokes with database time', async () => {
    const operatorAttestationId = uuid();
    const established = await ensureOperator(operatorAttestationId);
    const current = expectOk(
      await adapters.operators.inspectAuthority(
        expectOk(createOsvCanaryOperatorLookupQuery({ operatorAttestationId }), 'lookup'),
      ),
      'inspect',
    );
    expect(current.status).toBe('current');
    const revoked = expectOk(
      await adapters.operators.revoke(
        expectOk(createOsvCanaryOperatorRevokeCommand({ operatorAttestationId }), 'revoke'),
      ),
      'revoke',
    );
    expect(revoked.status).toBe('transitioned');
    expect(revoked.operator.identity.status).toBe('revoked');
    expect(revoked.operator.revokedAt).not.toBeNull();
    const replay = expectOk(
      await adapters.operators.revoke(
        expectOk(createOsvCanaryOperatorRevokeCommand({ operatorAttestationId }), 'revoke replay'),
      ),
      'revoke replay',
    );
    expect(replay.status).toBe('already_applied');
    const revokedEnsure = await adapters.operators.ensure(
      expectOk(
        createOsvCanaryOperatorEnsureCommand({
          operatorAttestationId,
          identityType: 'instance_operator',
          authenticationSource: 'local_host_control_of_one_shot_administrative_command',
          displayLabel: established.operator.identity.displayLabel,
          provenanceIdentifier: 'configured_instance_operator_attestation_v1',
        }),
        'revoked ensure command',
      ),
    );
    expect(revokedEnsure.ok).toBe(false);
    if (!revokedEnsure.ok) {
      expect(revokedEnsure.code).toBe('operator_revoked');
    }
    const absent = expectOk(
      await adapters.operators.lookup(
        expectOk(createOsvCanaryOperatorLookupQuery({ operatorAttestationId: uuid() }), 'absent'),
      ),
      'absent',
    );
    expect(absent.status).toBe('absent');
  });

  it('rejects authorization issuance for a revoked or missing operator', async () => {
    const operatorAttestationId = uuid();
    await ensureOperator(operatorAttestationId);
    await adapters.operators.revoke(
      expectOk(createOsvCanaryOperatorRevokeCommand({ operatorAttestationId }), 'revoke'),
    );
    const revoked = await adapters.authorizations.ensure(
      expectOk(
        createOsvCanaryAuthorizationEnsureCommand(listingEnsureInput(operatorAttestationId)),
        'ensure',
      ),
    );
    expect(revoked.ok).toBe(false);
    if (!revoked.ok) {
      expect(revoked.code).toBe('operator_revoked');
    }
    const missing = await adapters.authorizations.ensure(
      expectOk(createOsvCanaryAuthorizationEnsureCommand(listingEnsureInput(uuid())), 'missing'),
    );
    expect(missing.ok).toBe(false);
    if (!missing.ok) {
      expect(missing.code).toBe('not_found');
    }
  });

  it('ensures listing-only authorization with database-owned times and identical replay', async () => {
    const operator = await ensureOperator();
    const authorizationId = uuid();
    const command = expectOk(
      createOsvCanaryAuthorizationEnsureCommand(
        listingEnsureInput(operator.operator.identity.operatorAttestationId, authorizationId),
      ),
      'listing command',
    );
    const created = expectOk(await adapters.authorizations.ensure(command), 'listing ensure');
    expect(created.status).toBe('created');
    expect(created.authorization.snapshot.state).toBe('issued');
    expect(created.authorization.snapshot.record.phase).toBe('listing_only');
    expect(created.authorization.snapshot.record.listingReviewEvidence).toBeNull();
    expect(created.authorization.snapshot.record.bodyLegalDecisionReference).toBeNull();
    const issuedMs = Date.parse(created.authorization.snapshot.record.issuedAt);
    const expiresMs = Date.parse(created.authorization.snapshot.record.expiresAt);
    expect(expiresMs - issuedMs).toBe(3_600_000);
    const replay = expectOk(await adapters.authorizations.ensure(command), 'listing replay');
    expect(replay.status).toBe('already_applied');
    expect(replay.authorization.snapshot.record.issuedAt).toBe(
      created.authorization.snapshot.record.issuedAt,
    );
    const conflictInput = listingEnsureInput(
      operator.operator.identity.operatorAttestationId,
      authorizationId,
    );
    const conflict = await adapters.authorizations.ensure(
      expectOk(
        createOsvCanaryAuthorizationEnsureCommand({
          ...conflictInput,
          authorizationPurpose: 'approved_listing_repetition',
        }),
        'conflict',
      ),
    );
    expect(conflict.ok).toBe(false);
    if (!conflict.ok) {
      expect(conflict.code).toBe('immutable_conflict');
    }
  });

  it('consumes once, replays the same run, and rejects a different run', async () => {
    const operator = await ensureOperator();
    const operatorAttestationId = operator.operator.identity.operatorAttestationId;
    const listing = await ensureListing(operatorAttestationId);
    const first = await seedCanaryRun();
    const second = await seedCanaryRun();
    const consumed = await consumeListing(
      listing.authorization.snapshot.record.authorizationId,
      operatorAttestationId,
      first.request.id,
      first.run.id,
    );
    expect(consumed.outcome).toBe('consumed');
    expect(consumed.authorization.snapshot.state).toBe('consumed');
    expect(consumed.authorization.snapshot.consumption?.requestId).toBe(first.request.id);
    expect(consumed.authorization.snapshot.consumption?.runId).toBe(first.run.id);
    const replay = await consumeListing(
      listing.authorization.snapshot.record.authorizationId,
      operatorAttestationId,
      first.request.id,
      first.run.id,
    );
    expect(replay.outcome).toBe('already_consumed_same_run');
    expect(replay.authorization.snapshot.consumption?.consumedAt).toBe(
      consumed.authorization.snapshot.consumption?.consumedAt,
    );
    const other = await consumeListing(
      listing.authorization.snapshot.record.authorizationId,
      operatorAttestationId,
      second.request.id,
      second.run.id,
    );
    expect(other.outcome).toBe('already_consumed_other_run');
    const serialized = JSON.stringify(other);
    expect(serialized).not.toContain('password');
    expect(serialized).not.toContain('holderToken');
    expect(serialized).not.toContain('pageToken');
    expect(serialized).not.toContain('organizationId');
    expect(serialized).not.toContain('findingId');
  });

  it('rejects listing-only consumption for bounded-body phase and production requests', async () => {
    const operator = await ensureOperator();
    const operatorAttestationId = operator.operator.identity.operatorAttestationId;
    const listing = await ensureListing(operatorAttestationId);
    const canary = await seedCanaryRun();
    const phase = await adapters.authorizations.consume(
      expectOk(
        createOsvCanaryAuthorizationConsumePersistenceCommand({
          authorizationId: listing.authorization.snapshot.record.authorizationId,
          operatorAttestationId,
          phase: 'bounded_body',
          providerPrefix: 'crates.io/',
          canaryPolicyIdentifier: 'osv_disabled_first_provider_canary_policy_v1',
          runtimeVersionSetFingerprint: FINGERPRINT,
          requestId: canary.request.id,
          runId: canary.run.id,
        }),
        'phase consume',
      ),
    );
    expect(phase.ok).toBe(true);
    if (phase.ok) {
      expect(phase.value.outcome).toBe('policy_mismatch');
    }
    const productionPayload = expectOk(
      createOsvRuntimeSyncJobPayload(
        createClosedOsvRuntimeSyncJobInput({
          synchronizationReason: 'operator_production',
          requestedAt: '2026-09-08T12:00:00Z',
          correlationId: uuid(),
        }),
      ),
      'production payload',
    );
    const productionIdentity = expectOk(
      createOsvRuntimeJobIdempotencyIdentity({
        workScope: productionPayload.workScope,
        reason: productionPayload.synchronizationReason,
        versionSetFingerprint: productionPayload.versionSetFingerprint,
        requestKind: 'operator_request',
        schedulerWindowId: null,
        operatorRequestId: uuid(),
      }),
      'production identity',
    );
    const productionRequest = expectOk(
      await coordination.requests.ensure(
        expectOk(
          createOsvRuntimeSynchronizationRequestEnsureCommand({
            payload: productionPayload,
            idempotency: productionIdentity,
            requestState: 'accepted',
          }),
          'production request command',
        ),
      ),
      'production request',
    );
    const productionRun = expectOk(
      await coordination.runs.ensure(
        expectOk(
          createOsvRuntimeSynchronizationRunEnsureCommand({
            requestId: productionRequest.request.id,
          }),
          'production run command',
        ),
      ),
      'production run',
    );
    const production = await adapters.authorizations.consume(
      expectOk(
        createOsvCanaryAuthorizationConsumePersistenceCommand({
          authorizationId: listing.authorization.snapshot.record.authorizationId,
          operatorAttestationId,
          phase: 'listing_only',
          providerPrefix: 'crates.io/',
          canaryPolicyIdentifier: 'osv_disabled_first_provider_canary_policy_v1',
          runtimeVersionSetFingerprint: FINGERPRINT,
          requestId: productionRequest.request.id,
          runId: productionRun.run.id,
        }),
        'production consume',
      ),
    );
    expect(production.ok).toBe(false);
    if (!production.ok) {
      expect(production.code).toBe('request_run_mismatch');
    }
  });

  it('revokes, cancels, and terminals with database time and immutable replay', async () => {
    const operator = await ensureOperator();
    const operatorAttestationId = operator.operator.identity.operatorAttestationId;
    const issued = await ensureListing(operatorAttestationId);
    const revoked = expectOk(
      await adapters.authorizations.revoke(
        expectOk(
          createOsvCanaryAuthorizationRevokeCommand({
            authorizationId: issued.authorization.snapshot.record.authorizationId,
            operatorAttestationId,
          }),
          'revoke command',
        ),
      ),
      'revoke',
    );
    expect(revoked.status).toBe('transitioned');
    expect(revoked.authorization.snapshot.state).toBe('revoked');
    expect(revoked.authorization.revokedAt).not.toBeNull();
    const revokeReplay = expectOk(
      await adapters.authorizations.revoke(
        expectOk(
          createOsvCanaryAuthorizationRevokeCommand({
            authorizationId: issued.authorization.snapshot.record.authorizationId,
            operatorAttestationId,
          }),
          'revoke replay command',
        ),
      ),
      'revoke replay',
    );
    expect(revokeReplay.status).toBe('already_applied');
    const cancelledListing = await ensureListing(operatorAttestationId);
    const cancelled = expectOk(
      await adapters.authorizations.cancel(
        expectOk(
          createOsvCanaryAuthorizationCancelCommand({
            authorizationId: cancelledListing.authorization.snapshot.record.authorizationId,
            operatorAttestationId,
          }),
          'cancel command',
        ),
      ),
      'cancel',
    );
    expect(cancelled.authorization.snapshot.state).toBe('cancelled');
    const completable = await ensureListing(operatorAttestationId);
    const run = await seedCanaryRun();
    await consumeListing(
      completable.authorization.snapshot.record.authorizationId,
      operatorAttestationId,
      run.request.id,
      run.run.id,
    );
    const completed = expectOk(
      await adapters.authorizations.recordTerminal(
        expectOk(
          createOsvCanaryAuthorizationTerminalCommand({
            authorizationId: completable.authorization.snapshot.record.authorizationId,
            operatorAttestationId,
            requestId: run.request.id,
            runId: run.run.id,
            disposition: 'completed',
            terminalReasonCode: null,
          }),
          'terminal command',
        ),
      ),
      'terminal',
    );
    expect(completed.authorization.snapshot.state).toBe('completed');
    expect(completed.authorization.terminalReasonCode).toBeNull();
    const failedAttempt = await adapters.authorizations.recordTerminal(
      expectOk(
        createOsvCanaryAuthorizationTerminalCommand({
          authorizationId: completable.authorization.snapshot.record.authorizationId,
          operatorAttestationId,
          requestId: run.request.id,
          runId: run.run.id,
          disposition: 'failed',
          terminalReasonCode: 'canary_failed',
        }),
        'conflict terminal',
      ),
    );
    expect(failedAttempt.ok).toBe(false);
    if (!failedAttempt.ok) {
      expect(failedAttempt.code).toBe('immutable_conflict');
    }
    const issuedDirect = await ensureListing(operatorAttestationId);
    const skip = await adapters.authorizations.recordTerminal(
      expectOk(
        createOsvCanaryAuthorizationTerminalCommand({
          authorizationId: issuedDirect.authorization.snapshot.record.authorizationId,
          operatorAttestationId,
          requestId: run.request.id,
          runId: run.run.id,
          disposition: 'completed',
          terminalReasonCode: null,
        }),
        'skip consume',
      ),
    );
    expect(skip.ok).toBe(false);
    if (!skip.ok) {
      expect(skip.code).toBe('state_conflict');
    }
  });

  it('completes a listing authorization and issues bounded-body against accepted review', async () => {
    const operator = await ensureOperator();
    const operatorAttestationId = operator.operator.identity.operatorAttestationId;
    const listing = await ensureListing(operatorAttestationId);
    const run = await seedCanaryRun();
    await consumeListing(
      listing.authorization.snapshot.record.authorizationId,
      operatorAttestationId,
      run.request.id,
      run.run.id,
    );
    expectOk(
      await adapters.authorizations.recordTerminal(
        expectOk(
          createOsvCanaryAuthorizationTerminalCommand({
            authorizationId: listing.authorization.snapshot.record.authorizationId,
            operatorAttestationId,
            requestId: run.request.id,
            runId: run.run.id,
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
          createOsvCanaryAuthorizationLookupQuery({
            authorizationId: listing.authorization.snapshot.record.authorizationId,
          }),
          'completed listing lookup',
        ),
      ),
      'completed listing lookup',
    );
    const reviewedAt = completedListing.terminalAt ?? new Date().toISOString();
    const bodyId = uuid();
    const review = expectOk(
      createOsvCanaryListingReviewEvidence({
        listingAuthorizationId: listing.authorization.snapshot.record.authorizationId,
        listingRunId: run.run.id,
        reviewId: uuid(),
        providerPrefix: 'crates.io/',
        sourceIdentifier: 'rustsec_advisory_database',
        canonicalInventoryEvidenceId: uuid(),
        canaryPolicyIdentifier: 'osv_disabled_first_provider_canary_policy_v1',
        workScope: 'osv_runtime_canary_scope_crates_io_rustsec_v1',
        runtimeVersionSetFingerprint: FINGERPRINT,
        verdict: 'listing_canary_evidence_accepted',
        reviewedAt,
        reviewerRole: 'instance_canary_evidence_reviewer',
      }),
      'review',
    );
    const body = expectOk(
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
    expect(body.status).toBe('created');
    expect(body.authorization.snapshot.record.phase).toBe('bounded_body');
    expect(body.authorization.snapshot.record.budgetProfile.identifier).toBe(
      'osv_canary_bounded_body_budget_v1',
    );
  });

  it('lets exactly one concurrent consumer win', async () => {
    const operator = await ensureOperator();
    const operatorAttestationId = operator.operator.identity.operatorAttestationId;
    const listing = await ensureListing(operatorAttestationId);
    const first = await seedCanaryRun();
    const second = await seedCanaryRun();
    const clients = [
      new PrismaClient({ datasources: { db: { url: databaseUrl } } }),
      new PrismaClient({ datasources: { db: { url: databaseUrl } } }),
    ];
    try {
      const left = createOsvCanaryAuthorizationPersistence(clients[0]!);
      const right = createOsvCanaryAuthorizationPersistence(clients[1]!);
      const commandA = expectOk(
        createOsvCanaryAuthorizationConsumePersistenceCommand({
          authorizationId: listing.authorization.snapshot.record.authorizationId,
          operatorAttestationId,
          phase: 'listing_only',
          providerPrefix: 'crates.io/',
          canaryPolicyIdentifier: 'osv_disabled_first_provider_canary_policy_v1',
          runtimeVersionSetFingerprint: FINGERPRINT,
          requestId: first.request.id,
          runId: first.run.id,
        }),
        'left consume',
      );
      const commandB = expectOk(
        createOsvCanaryAuthorizationConsumePersistenceCommand({
          authorizationId: listing.authorization.snapshot.record.authorizationId,
          operatorAttestationId,
          phase: 'listing_only',
          providerPrefix: 'crates.io/',
          canaryPolicyIdentifier: 'osv_disabled_first_provider_canary_policy_v1',
          runtimeVersionSetFingerprint: FINGERPRINT,
          requestId: second.request.id,
          runId: second.run.id,
        }),
        'right consume',
      );
      const [leftResult, rightResult] = await Promise.all([
        left.authorizations.consume(commandA),
        right.authorizations.consume(commandB),
      ]);
      const outcomes = [leftResult, rightResult].map((result) =>
        result.ok ? result.value.outcome : result.code,
      );
      expect(outcomes.filter((outcome) => outcome === 'consumed')).toHaveLength(1);
      expect(
        outcomes.filter(
          (outcome) =>
            outcome === 'already_consumed_other_run' || outcome === 'serialization_failure',
        ).length,
      ).toBeGreaterThanOrEqual(1);
    } finally {
      await Promise.all(clients.map((client) => client.$disconnect()));
    }
  });

  it('uses database time for expiration and does not expire consumed authorizations', async () => {
    const operator = await ensureOperator();
    const operatorAttestationId = operator.operator.identity.operatorAttestationId;
    const live = await ensureListing(operatorAttestationId);
    const validity = expectOk(
      await adapters.authorizations.inspectValidity(
        expectOk(
          createOsvCanaryAuthorizationLookupQuery({
            authorizationId: live.authorization.snapshot.record.authorizationId,
          }),
          'validity query',
        ),
      ),
      'validity',
    );
    expect(validity.status).toBe('issued_and_unexpired');
    const expiredId = uuid();
    const issuedAt = new Date('2026-09-08T12:00:00.000Z');
    const expiresAt = new Date('2026-09-08T13:00:00.000Z');
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
        ${expiredId}::uuid, ${operatorAttestationId}::uuid,
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
        'osv_canary_automatic_retry_prohibition_v1', ${issuedAt}, ${expiresAt},
        'issued', ${issuedAt}
      )
    `;
    const expiredInspect = expectOk(
      await adapters.authorizations.inspectValidity(
        expectOk(
          createOsvCanaryAuthorizationLookupQuery({ authorizationId: expiredId }),
          'expired query',
        ),
      ),
      'expired inspect',
    );
    expect(expiredInspect.status).toBe('expired');
    const run = await seedCanaryRun();
    const expiredConsume = expectOk(
      await adapters.authorizations.consume(
        expectOk(
          createOsvCanaryAuthorizationConsumePersistenceCommand({
            authorizationId: expiredId,
            operatorAttestationId,
            phase: 'listing_only',
            providerPrefix: 'crates.io/',
            canaryPolicyIdentifier: 'osv_disabled_first_provider_canary_policy_v1',
            runtimeVersionSetFingerprint: FINGERPRINT,
            requestId: run.request.id,
            runId: run.run.id,
          }),
          'expired consume command',
        ),
      ),
      'expired consume',
    );
    expect(expiredConsume.outcome).toBe('expired');
    const durable = expectOk(
      await adapters.authorizations.expire(
        expectOk(
          createOsvCanaryAuthorizationExpireCommand({ authorizationId: expiredId }),
          'expire',
        ),
      ),
      'expire',
    );
    expect(durable.status).toBe('transitioned');
    expect(durable.authorization.snapshot.state).toBe('expired');
    const liveRun = await seedCanaryRun();
    const consumed = await consumeListing(
      live.authorization.snapshot.record.authorizationId,
      operatorAttestationId,
      liveRun.request.id,
      liveRun.run.id,
    );
    expect(consumed.outcome).toBe('consumed');
    const afterExpiryWindow = expectOk(
      await adapters.authorizations.inspectValidity(
        expectOk(
          createOsvCanaryAuthorizationLookupQuery({
            authorizationId: live.authorization.snapshot.record.authorizationId,
          }),
          'consumed validity',
        ),
      ),
      'consumed validity',
    );
    expect(afterExpiryWindow.status).toBe('consumed');
    const sameRun = await consumeListing(
      live.authorization.snapshot.record.authorizationId,
      operatorAttestationId,
      liveRun.request.id,
      liveRun.run.id,
    );
    expect(sameRun.outcome).toBe('already_consumed_same_run');
  });

  it('lets identical concurrent operator ensures settle on one identity', async () => {
    const operatorAttestationId = uuid();
    const label = displayLabel();
    const clients = [
      new PrismaClient({ datasources: { db: { url: databaseUrl } } }),
      new PrismaClient({ datasources: { db: { url: databaseUrl } } }),
    ];
    try {
      const left = createOsvCanaryAuthorizationPersistence(clients[0]!);
      const right = createOsvCanaryAuthorizationPersistence(clients[1]!);
      const command = expectOk(
        createOsvCanaryOperatorEnsureCommand({
          operatorAttestationId,
          identityType: 'instance_operator',
          authenticationSource: 'local_host_control_of_one_shot_administrative_command',
          displayLabel: label,
          provenanceIdentifier: 'configured_instance_operator_attestation_v1',
        }),
        'concurrent operator',
      );
      const [first, second] = await Promise.all([
        left.operators.ensure(command),
        right.operators.ensure(command),
      ]);
      const statuses = [first, second].map((result) =>
        result.ok ? result.value.status : result.code,
      );
      expect(statuses).toContain('created');
      expect(
        statuses.filter(
          (status) => status === 'already_applied' || status === 'serialization_failure',
        ).length,
      ).toBeGreaterThanOrEqual(1);
    } finally {
      await Promise.all(clients.map((client) => client.$disconnect()));
    }
  });

  it('lets revocation and consumption race to one winner', async () => {
    const operator = await ensureOperator();
    const operatorAttestationId = operator.operator.identity.operatorAttestationId;
    const listing = await ensureListing(operatorAttestationId);
    const run = await seedCanaryRun();
    const clients = [
      new PrismaClient({ datasources: { db: { url: databaseUrl } } }),
      new PrismaClient({ datasources: { db: { url: databaseUrl } } }),
    ];
    try {
      const left = createOsvCanaryAuthorizationPersistence(clients[0]!);
      const right = createOsvCanaryAuthorizationPersistence(clients[1]!);
      const [revokeResult, consumeResult] = await Promise.all([
        left.authorizations.revoke(
          expectOk(
            createOsvCanaryAuthorizationRevokeCommand({
              authorizationId: listing.authorization.snapshot.record.authorizationId,
              operatorAttestationId,
            }),
            'race revoke',
          ),
        ),
        right.authorizations.consume(
          expectOk(
            createOsvCanaryAuthorizationConsumePersistenceCommand({
              authorizationId: listing.authorization.snapshot.record.authorizationId,
              operatorAttestationId,
              phase: 'listing_only',
              providerPrefix: 'crates.io/',
              canaryPolicyIdentifier: 'osv_disabled_first_provider_canary_policy_v1',
              runtimeVersionSetFingerprint: FINGERPRINT,
              requestId: run.request.id,
              runId: run.run.id,
            }),
            'race consume',
          ),
        ),
      ]);
      const revokeWon = revokeResult.ok && revokeResult.value.status === 'transitioned';
      const consumeWon = consumeResult.ok && consumeResult.value.outcome === 'consumed';
      expect(Number(revokeWon) + Number(consumeWon)).toBe(1);
      const authoritative = expectOk(
        await adapters.authorizations.lookup(
          expectOk(
            createOsvCanaryAuthorizationLookupQuery({
              authorizationId: listing.authorization.snapshot.record.authorizationId,
            }),
            'race lookup',
          ),
        ),
        'race lookup',
      );
      expect(['revoked', 'consumed']).toContain(authoritative.snapshot.state);
    } finally {
      await Promise.all(clients.map((client) => client.$disconnect()));
    }
  });

  it('rejects consumption after the issuing operator is revoked', async () => {
    const operator = await ensureOperator();
    const operatorAttestationId = operator.operator.identity.operatorAttestationId;
    const listing = await ensureListing(operatorAttestationId);
    expectOk(
      await adapters.operators.revoke(
        expectOk(
          createOsvCanaryOperatorRevokeCommand({ operatorAttestationId }),
          'operator revoke',
        ),
      ),
      'operator revoke',
    );
    const run = await seedCanaryRun();
    const consume = await adapters.authorizations.consume(
      expectOk(
        createOsvCanaryAuthorizationConsumePersistenceCommand({
          authorizationId: listing.authorization.snapshot.record.authorizationId,
          operatorAttestationId,
          phase: 'listing_only',
          providerPrefix: 'crates.io/',
          canaryPolicyIdentifier: 'osv_disabled_first_provider_canary_policy_v1',
          runtimeVersionSetFingerprint: FINGERPRINT,
          requestId: run.request.id,
          runId: run.run.id,
        }),
        'revoked operator consume',
      ),
    );
    expect(consume.ok).toBe(false);
    if (!consume.ok) {
      expect(consume.code).toBe('operator_revoked');
    }
  });

  it('omits prohibited markers from adapter results and failures', async () => {
    const operator = await ensureOperator();
    const listing = await ensureListing(operator.operator.identity.operatorAttestationId);
    const payload = JSON.stringify(listing);
    const inspected = inspect(listing);
    for (const marker of MARKERS) {
      expect(payload).not.toContain(marker);
      expect(inspected).not.toContain(marker);
    }
    expect(payload).not.toContain('SELECT');
    expect(payload).not.toContain('password');
    expect(inspected).not.toContain('Prisma');
  });

  it('does not expose generic upsert or execute provider work', async () => {
    expect('upsert' in adapters.authorizations).toBe(false);
    expect('execute' in adapters.authorizations).toBe(false);
    expect('listAll' in adapters.authorizations).toBe(false);
  });
});
