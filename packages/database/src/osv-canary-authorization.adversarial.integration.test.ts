import { inspect } from 'node:util';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { PrismaClient } from '@prisma/client';
import {
  createClosedOsvRuntimeSyncJobInput,
  createOsvCanaryActivationProhibitionAcknowledgement,
  createOsvCanaryAuthorizationCancelCommand,
  createOsvCanaryAuthorizationConsumePersistenceCommand,
  createOsvCanaryAuthorizationEnsureCommand,
  createOsvCanaryAuthorizationExpireCommand,
  createOsvCanaryAuthorizationTerminalCommand,
  createOsvCanaryAutomaticRetryProhibitionAcknowledgement,
  createOsvCanaryHaltControlAcknowledgement,
  createOsvCanaryLegalDecisionReference,
  createOsvCanaryListingReviewEvidence,
  createOsvCanaryOperatorEnsureCommand,
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
const srcDir = path.dirname(fileURLToPath(import.meta.url));

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

describe(
  'session 13 Batch 2C-R OSV canary authorization adversarial adapters',
  {
    timeout: 180_000,
  },
  () => {
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
        datasources: { db: { url: databaseUrl } },
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

    function listingEnsureInput(
      operatorAttestationId: string,
      authorizationId = uuid(),
      legal = listingLegal(),
    ) {
      return {
        authorizationId,
        operatorAttestationId,
        phase: 'listing_only' as const,
        authorizationPurpose: 'initial_listing_compatibility' as const,
        legalDecisionReference: legal,
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

    it('rejects expired legal-decision substitution at issuance', async () => {
      const operator = await ensureOperator();
      const stale = listingLegal();
      const staleLegal = expectOk(
        createOsvCanaryLegalDecisionReference({
          decisionId: stale.decisionId,
          sourceRegistryVersion: 'osv_source_license_registry_v1',
          sourceIdentifier: 'rustsec_advisory_database',
          family: 'RUSTSEC',
          phase: 'listing_only',
          permittedOperation: 'list_object_metadata',
          issuedAt: '2020-01-01T00:00:00Z',
          revalidationBoundaryAt: '2020-01-02T00:00:00Z',
          responsibleRole:
            'instance_legal_and_provenance_reviewer_countersigned_by_instance_operator',
          evidenceSetId: uuid(),
        }),
        'stale legal',
      );
      const result = await adapters.authorizations.ensure(
        expectOk(
          createOsvCanaryAuthorizationEnsureCommand(
            listingEnsureInput(
              operator.operator.identity.operatorAttestationId,
              uuid(),
              staleLegal,
            ),
          ),
          'stale ensure',
        ),
      );
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.code).toBe('legal_gate_blocked');
      }
    });

    it('rejects bounded-body ensure against an uncompleted listing review', async () => {
      const operator = await ensureOperator();
      const operatorAttestationId = operator.operator.identity.operatorAttestationId;
      const listing = await ensureListing(operatorAttestationId);
      const run = await seedCanaryRun();
      const result = await adapters.authorizations.ensure(
        expectOk(
          createOsvCanaryAuthorizationEnsureCommand({
            authorizationId: uuid(),
            operatorAttestationId,
            phase: 'bounded_body',
            authorizationPurpose: 'bounded_body_compatibility',
            legalDecisionReference: listingLegal(),
            bodyLegalDecisionReference: expectOk(
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
            ),
            listingReviewEvidence: expectOk(
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
                reviewedAt: '2026-09-08T12:00:00Z',
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
          'body against issued listing',
        ),
      );
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.code).toBe('listing_review_not_accepted');
      }
    });

    it('rejects consumption exactly at expiry using database time', async () => {
      const operator = await ensureOperator();
      const operatorAttestationId = operator.operator.identity.operatorAttestationId;
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
      const run = await seedCanaryRun();
      const consume = expectOk(
        await adapters.authorizations.consume(
          expectOk(
            createOsvCanaryAuthorizationConsumePersistenceCommand({
              authorizationId,
              operatorAttestationId,
              phase: 'listing_only',
              providerPrefix: 'crates.io/',
              canaryPolicyIdentifier: 'osv_disabled_first_provider_canary_policy_v1',
              runtimeVersionSetFingerprint: FINGERPRINT,
              requestId: run.request.id,
              runId: run.run.id,
            }),
            'at-expiry consume',
          ),
        ),
        'at-expiry consume',
      );
      expect(consume.outcome).toBe('expired');
      expect(consume.authorization.snapshot.state).toBe('issued');
    });

    it('lets cancellation win over later consumption and keeps consumed replay after expiry window', async () => {
      const operator = await ensureOperator();
      const operatorAttestationId = operator.operator.identity.operatorAttestationId;
      const cancelledListing = await ensureListing(operatorAttestationId);
      expectOk(
        await adapters.authorizations.cancel(
          expectOk(
            createOsvCanaryAuthorizationCancelCommand({
              authorizationId: cancelledListing.authorization.snapshot.record.authorizationId,
              operatorAttestationId,
            }),
            'cancel',
          ),
        ),
        'cancel',
      );
      const run = await seedCanaryRun();
      const cancelledConsume = expectOk(
        await adapters.authorizations.consume(
          expectOk(
            createOsvCanaryAuthorizationConsumePersistenceCommand({
              authorizationId: cancelledListing.authorization.snapshot.record.authorizationId,
              operatorAttestationId,
              phase: 'listing_only',
              providerPrefix: 'crates.io/',
              canaryPolicyIdentifier: 'osv_disabled_first_provider_canary_policy_v1',
              runtimeVersionSetFingerprint: FINGERPRINT,
              requestId: run.request.id,
              runId: run.run.id,
            }),
            'consume cancelled',
          ),
        ),
        'cancelled consume',
      );
      expect(cancelledConsume.outcome).toBe('cancelled');
      const live = await ensureListing(operatorAttestationId);
      const consumed = expectOk(
        await adapters.authorizations.consume(
          expectOk(
            createOsvCanaryAuthorizationConsumePersistenceCommand({
              authorizationId: live.authorization.snapshot.record.authorizationId,
              operatorAttestationId,
              phase: 'listing_only',
              providerPrefix: 'crates.io/',
              canaryPolicyIdentifier: 'osv_disabled_first_provider_canary_policy_v1',
              runtimeVersionSetFingerprint: FINGERPRINT,
              requestId: run.request.id,
              runId: run.run.id,
            }),
            'consume live',
          ),
        ),
        'consume live',
      );
      expect(consumed.outcome).toBe('consumed');
      const expireConsumed = await adapters.authorizations.expire(
        expectOk(
          createOsvCanaryAuthorizationExpireCommand({
            authorizationId: live.authorization.snapshot.record.authorizationId,
          }),
          'expire consumed',
        ),
      );
      expect(expireConsumed.ok).toBe(false);
      if (!expireConsumed.ok) {
        expect(expireConsumed.code).toBe('state_conflict');
      }
      const replay = expectOk(
        await adapters.authorizations.consume(
          expectOk(
            createOsvCanaryAuthorizationConsumePersistenceCommand({
              authorizationId: live.authorization.snapshot.record.authorizationId,
              operatorAttestationId,
              phase: 'listing_only',
              providerPrefix: 'crates.io/',
              canaryPolicyIdentifier: 'osv_disabled_first_provider_canary_policy_v1',
              runtimeVersionSetFingerprint: FINGERPRINT,
              requestId: run.request.id,
              runId: run.run.id,
            }),
            'same-run after expiry attempt',
          ),
        ),
        'same-run replay',
      );
      expect(replay.outcome).toBe('already_consumed_same_run');
      expect(JSON.stringify(replay)).not.toContain('already_consumed_same_run is permission');
      expect(inspect(replay)).not.toContain('SELECT');
    });

    it('rejects mismatched request/run pairs and different-request same-run reuse', async () => {
      const operator = await ensureOperator();
      const operatorAttestationId = operator.operator.identity.operatorAttestationId;
      const listing = await ensureListing(operatorAttestationId);
      const first = await seedCanaryRun();
      const second = await seedCanaryRun();
      const crossed = await adapters.authorizations.consume(
        expectOk(
          createOsvCanaryAuthorizationConsumePersistenceCommand({
            authorizationId: listing.authorization.snapshot.record.authorizationId,
            operatorAttestationId,
            phase: 'listing_only',
            providerPrefix: 'crates.io/',
            canaryPolicyIdentifier: 'osv_disabled_first_provider_canary_policy_v1',
            runtimeVersionSetFingerprint: FINGERPRINT,
            requestId: first.request.id,
            runId: second.run.id,
          }),
          'crossed consume',
        ),
      );
      expect(crossed.ok).toBe(false);
      if (!crossed.ok) {
        expect(crossed.code).toBe('request_run_mismatch');
      }
    });

    it('lets conflicting concurrent operator ensures fail closed', async () => {
      const operatorAttestationId = uuid();
      const clients = [
        new PrismaClient({ datasources: { db: { url: databaseUrl } } }),
        new PrismaClient({ datasources: { db: { url: databaseUrl } } }),
      ];
      try {
        const left = createOsvCanaryAuthorizationPersistence(clients[0]!);
        const right = createOsvCanaryAuthorizationPersistence(clients[1]!);
        const [first, second] = await Promise.all([
          left.operators.ensure(
            expectOk(
              createOsvCanaryOperatorEnsureCommand({
                operatorAttestationId,
                identityType: 'instance_operator',
                authenticationSource: 'local_host_control_of_one_shot_administrative_command',
                displayLabel: displayLabel(),
                provenanceIdentifier: 'configured_instance_operator_attestation_v1',
              }),
              'left',
            ),
          ),
          right.operators.ensure(
            expectOk(
              createOsvCanaryOperatorEnsureCommand({
                operatorAttestationId,
                identityType: 'instance_operator',
                authenticationSource: 'local_host_control_of_one_shot_administrative_command',
                displayLabel: displayLabel(),
                provenanceIdentifier: 'configured_instance_operator_attestation_v1',
              }),
              'right',
            ),
          ),
        ]);
        const statuses = [first, second].map((result) =>
          result.ok ? result.value.status : result.code,
        );
        expect(statuses).toContain('created');
        expect(
          statuses.filter(
            (status) => status === 'immutable_conflict' || status === 'serialization_failure',
          ).length,
        ).toBeGreaterThanOrEqual(1);
      } finally {
        await Promise.all(clients.map((client) => client.$disconnect()));
      }
    });

    it('classifies zero-row terminal replay as immutable conflict', async () => {
      const operator = await ensureOperator();
      const operatorAttestationId = operator.operator.identity.operatorAttestationId;
      const listing = await ensureListing(operatorAttestationId);
      const run = await seedCanaryRun();
      expectOk(
        await adapters.authorizations.consume(
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
            'consume',
          ),
        ),
        'consume',
      );
      const completed = expectOk(
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
            'complete',
          ),
        ),
        'complete',
      );
      expect(completed.status).toBe('transitioned');
      const replay = expectOk(
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
            'complete replay',
          ),
        ),
        'complete replay',
      );
      expect(replay.status).toBe('already_applied');
      expect(replay.authorization.terminalAt).toBe(completed.authorization.terminalAt);
      const cancelAfter = await adapters.authorizations.cancel(
        expectOk(
          createOsvCanaryAuthorizationCancelCommand({
            authorizationId: listing.authorization.snapshot.record.authorizationId,
            operatorAttestationId,
          }),
          'cancel completed',
        ),
      );
      expect(cancelAfter.ok).toBe(false);
      if (!cancelAfter.ok) {
        expect(cancelAfter.code).toBe('state_conflict');
      }
    });

    it('rejects same-run consumed replay when the phase no longer matches', async () => {
      const operator = await ensureOperator();
      const operatorAttestationId = operator.operator.identity.operatorAttestationId;
      const listing = await ensureListing(operatorAttestationId);
      const run = await seedCanaryRun();
      expectOk(
        await adapters.authorizations.consume(
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
            'consume',
          ),
        ),
        'consume',
      );
      const replay = expectOk(
        await adapters.authorizations.consume(
          expectOk(
            createOsvCanaryAuthorizationConsumePersistenceCommand({
              authorizationId: listing.authorization.snapshot.record.authorizationId,
              operatorAttestationId,
              phase: 'bounded_body',
              providerPrefix: 'crates.io/',
              canaryPolicyIdentifier: 'osv_disabled_first_provider_canary_policy_v1',
              runtimeVersionSetFingerprint: FINGERPRINT,
              requestId: run.request.id,
              runId: run.run.id,
            }),
            'phase-changed consume',
          ),
        ),
        'phase-changed consume',
      );
      expect(replay.outcome).toBe('policy_mismatch');
      expect(replay.authorization.snapshot.state).toBe('consumed');
    });

    it('keeps queries bounded and omits tenant and Finding identifiers from adapters', () => {
      const source = readFileSync(
        path.join(srcDir, 'osv-canary-authorization-persistence.ts'),
        'utf8',
      );
      expect(source).not.toContain('findMany');
      expect(source).not.toContain('organizationId');
      expect(source).not.toContain('findingId');
      expect(source).not.toContain('setTimeout(');
      expect(source).not.toContain('while (true)');
      expect(source).not.toContain('storage.googleapis.com');
      expect(source).not.toContain("from 'node:https'");
    });
  },
);
