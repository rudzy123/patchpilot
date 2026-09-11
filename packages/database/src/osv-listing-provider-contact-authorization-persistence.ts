/**
 * Session 13 Batch 3B-A PostgreSQL adapters for listing-only OSV
 * provider-contact authorization issuance, inspection, revocation, and
 * atomic consumption.
 *
 * Durable authority only. Construction performs no I/O. Adapters do not
 * authenticate operators, start controllers, acquire leases, contact a
 * provider, enable OSV, or write Findings. Production composition does not
 * construct this factory. There is no row-revision column; compare-and-swap
 * uses issued state, exact bindings, and database time.
 */

import { Prisma, type PrismaClient } from '@prisma/client';
import {
  compareOsvListingProviderContactPersistedAuthorization,
  createOsvListingProviderContactConsumeResult,
  databaseNowIsExpired,
  isOsvListingProviderContactAuthorizationConsumeCommand,
  isOsvListingProviderContactAuthorizationInspectForRunQuery,
  isOsvListingProviderContactAuthorizationIssueCommand,
  isOsvListingProviderContactAuthorizationLookupQuery,
  isOsvListingProviderContactAuthorizationRevokeCommand,
  osvCanaryRuntimeVersionSetFingerprint,
  sameRunProviderContactConsumption,
  type OsvListingProviderContactAuthorizationConsumeCommand,
  type OsvListingProviderContactAuthorizationInspectForRunQuery,
  type OsvListingProviderContactAuthorizationIssueCommand,
  type OsvListingProviderContactAuthorizationLookupQuery,
  type OsvListingProviderContactAuthorizationPersistencePort,
  type OsvListingProviderContactAuthorizationRevokeCommand,
  type OsvListingProviderContactConsumeResult,
  type OsvListingProviderContactInspection,
  type OsvListingProviderContactIssueResult,
  type OsvListingProviderContactMutationResult,
  type OsvListingProviderContactPersistedAuthorization,
  type OsvListingProviderContactPersistenceRejectionCode,
  type OsvListingProviderContactPersistenceResult,
} from '@patchpilot/vulnerability-intelligence';

import { isRootPrismaClient, type PrismaClientLike } from './guards.js';
import {
  classifyProviderContactUniqueConflict,
  isRestrictViolation,
  isUniqueViolation,
  translateProviderContactAuthorizationFailure,
} from './osv-listing-provider-contact-authorization-errors.js';
import {
  coerceProviderContactAuthorizationRow,
  firstProviderContactRow,
  mapProviderContactAuthorization,
  OsvListingProviderContactAuthorizationMappingError,
  toIsoUtc,
  type ProviderContactAuthorizationRow,
} from './osv-listing-provider-contact-authorization-mappers.js';

const ROOT_CLIENT_REQUIRED =
  'OSV listing provider-contact authorization persistence requires the root database client.';
const FINGERPRINT = osvCanaryRuntimeVersionSetFingerprint();
const TERMINAL_CONSUME_STATES = new Set(['completed', 'failed', 'cancelled', 'revoked', 'expired']);
const TERMINAL_RUN_STATES = new Set(['cancelled', 'failed', 'completed', 'halted']);

export type OsvListingProviderContactAuthorizationPersistenceAdapters =
  OsvListingProviderContactAuthorizationPersistencePort;

export function createOsvListingProviderContactAuthorizationPersistence(
  client: PrismaClient,
): OsvListingProviderContactAuthorizationPersistenceAdapters {
  if (client === null || client === undefined || !isRootPrismaClient(client)) {
    throw new OsvListingProviderContactAuthorizationPersistenceFailure(ROOT_CLIENT_REQUIRED);
  }
  return createOsvListingProviderContactAuthorizationPersistenceForClient(client);
}

export function createOsvListingProviderContactAuthorizationPersistenceForClient(
  client: PrismaClientLike,
): OsvListingProviderContactAuthorizationPersistenceAdapters {
  return new PrismaOsvListingProviderContactAuthorizationRepository(client);
}

class OsvListingProviderContactAuthorizationPersistenceFailure extends Error {
  public constructor(message: string) {
    super(message);
    this.name = 'OsvListingProviderContactAuthorizationPersistenceFailure';
  }
}

function fail(
  code: OsvListingProviderContactPersistenceRejectionCode,
): OsvListingProviderContactPersistenceResult<never> {
  return { ok: false, code };
}

function mapCaught(error: unknown): OsvListingProviderContactPersistenceResult<never> {
  if (error instanceof OsvListingProviderContactAuthorizationMappingError) {
    return fail('malformed_authority');
  }
  return fail(translateProviderContactAuthorizationFailure(error));
}

async function runSerializable<T>(
  client: PrismaClientLike,
  fn: (tx: PrismaClientLike) => Promise<T>,
): Promise<T> {
  if (isRootPrismaClient(client)) {
    return client.$transaction(async (tx) => fn(tx), {
      isolationLevel: Prisma.TransactionIsolationLevel.Serializable,
      maxWait: 2000,
      timeout: 5000,
    });
  }
  return fn(client);
}

async function observeDatabaseNow(client: PrismaClientLike): Promise<Date> {
  const rows = await client.$queryRaw<Array<{ now: Date }>>`
    SELECT CURRENT_TIMESTAMP AS now
  `;
  const now = rows[0]?.now;
  if (!(now instanceof Date) || Number.isNaN(now.getTime())) {
    throw new OsvListingProviderContactAuthorizationMappingError('database time mapping failed.');
  }
  return now;
}

function timestampNotAfter(iso: string, now: Date): boolean {
  const parsed = Date.parse(iso);
  return !Number.isNaN(parsed) && parsed <= now.getTime();
}

async function loadAuthorization(
  client: PrismaClientLike,
  authorizationId: string,
): Promise<ProviderContactAuthorizationRow | null> {
  const rows = await client.$queryRaw<unknown[]>`
    SELECT *
    FROM "osv_listing_provider_contact_authorization"
    WHERE "id" = ${authorizationId}::uuid
  `;
  const row = firstProviderContactRow(rows, coerceProviderContactAuthorizationRow);
  return row === undefined ? null : row;
}

function mapRow(
  row: ProviderContactAuthorizationRow,
): OsvListingProviderContactPersistedAuthorization {
  return mapProviderContactAuthorization(row);
}

function sameIsoInstant(value: Date, iso: string): boolean {
  const parsed = Date.parse(iso);
  return !Number.isNaN(parsed) && value.getTime() === parsed;
}

function issueRowMatchesCommand(
  existing: ProviderContactAuthorizationRow,
  command: OsvListingProviderContactAuthorizationIssueCommand,
): boolean {
  return (
    sameIsoInstant(existing.egressReviewedAt, command.egressEvidence.reviewedAt) &&
    sameIsoInstant(existing.deploymentApprovedAt, command.deploymentApproval.approvedAt) &&
    sameIsoInstant(existing.runbookAcknowledgedAt, command.runbookAcknowledgement.acknowledgedAt) &&
    sameIsoInstant(
      existing.haltAcknowledgedAt,
      command.haltProcedureAcknowledgement.acknowledgedAt,
    ) &&
    sameIsoInstant(
      existing.containmentAcknowledgedAt,
      command.containmentAcknowledgement.acknowledgedAt,
    ) &&
    sameIsoInstant(existing.reviewerAssignedAt, command.reviewerAssignment.assignedAt) &&
    sameIsoInstant(existing.retentionAcknowledgedAt, command.retentionDisposition.acknowledgedAt) &&
    existing.runbookSetIdentifier === command.runbookAcknowledgement.runbookSetIdentifier &&
    existing.runbookVersion === command.runbookAcknowledgement.runbookVersion
  );
}

function bindingMismatch(
  existing: ProviderContactAuthorizationRow,
  command: OsvListingProviderContactAuthorizationConsumeCommand,
): OsvListingProviderContactPersistenceRejectionCode | null {
  if (existing.operatorIdentityId !== command.operatorAttestationId) {
    return 'identity_mismatch';
  }
  if (existing.sourceCanaryAuthorizationId !== command.sourceCanaryAuthorizationId) {
    return 'identity_mismatch';
  }
  if (existing.synchronizationRequestId !== command.synchronizationRequestId) {
    return 'request_mismatch';
  }
  if (existing.synchronizationRunId !== command.synchronizationRunId) {
    return 'run_mismatch';
  }
  if (existing.preflightEvidenceId !== command.preflightEvidenceId) {
    return 'preflight_mismatch';
  }
  if (existing.providerIdentity !== command.providerIdentity) {
    return 'provider_mismatch';
  }
  if (existing.approvedPrefix !== command.approvedPrefix) {
    return 'prefix_mismatch';
  }
  if (existing.canaryPolicyIdentifier !== command.canaryPolicyIdentifier) {
    return 'policy_mismatch';
  }
  if (existing.listingBudgetProfile !== command.listingBudgetProfile) {
    return 'budget_mismatch';
  }
  if (existing.runtimeVersionSetFingerprint !== command.runtimeVersionSetFingerprint) {
    return 'version_set_mismatch';
  }
  if (existing.legalDecisionId !== command.legalDecisionId) {
    return 'identity_mismatch';
  }
  if (existing.egressEvidenceId !== command.egressEvidenceId) {
    return 'identity_mismatch';
  }
  if (existing.deploymentId !== command.deploymentId) {
    return 'identity_mismatch';
  }
  return null;
}

class PrismaOsvListingProviderContactAuthorizationRepository implements OsvListingProviderContactAuthorizationPersistencePort {
  public constructor(private readonly client: PrismaClientLike) {}

  public async issue(
    command: OsvListingProviderContactAuthorizationIssueCommand,
  ): Promise<OsvListingProviderContactPersistenceResult<OsvListingProviderContactIssueResult>> {
    if (!isOsvListingProviderContactAuthorizationIssueCommand(command)) {
      return fail('not_constructed');
    }
    try {
      return await runSerializable(this.client, async (tx) => {
        const prepared = await this.validateIssuePrerequisites(tx, command);
        if (!prepared.ok) {
          return prepared;
        }
        return this.insertAuthorization(tx, command, prepared.value.fingerprint);
      });
    } catch (error) {
      if (isUniqueViolation(error)) {
        return this.reloadIssue(this.client, command, classifyProviderContactUniqueConflict(error));
      }
      if (isRestrictViolation(error)) {
        return fail('state_conflict');
      }
      return mapCaught(error);
    }
  }

  public async findById(
    query: OsvListingProviderContactAuthorizationLookupQuery,
  ): Promise<
    OsvListingProviderContactPersistenceResult<OsvListingProviderContactPersistedAuthorization>
  > {
    if (!isOsvListingProviderContactAuthorizationLookupQuery(query)) {
      return fail('not_constructed');
    }
    try {
      const row = await loadAuthorization(this.client, query.authorizationId);
      if (row === null) {
        return fail('authorization_not_found');
      }
      return { ok: true, value: mapRow(row) };
    } catch (error) {
      return mapCaught(error);
    }
  }

  public async inspectForRun(
    query: OsvListingProviderContactAuthorizationInspectForRunQuery,
  ): Promise<OsvListingProviderContactPersistenceResult<OsvListingProviderContactInspection>> {
    if (!isOsvListingProviderContactAuthorizationInspectForRunQuery(query)) {
      return fail('not_constructed');
    }
    try {
      const rows = await this.client.$queryRaw<unknown[]>`
        SELECT a.*, CURRENT_TIMESTAMP AS observed_at
        FROM "osv_listing_provider_contact_authorization" AS a
        WHERE a."id" = ${query.authorizationId}::uuid
      `;
      const raw = Array.isArray(rows) ? rows[0] : undefined;
      if (raw === undefined || raw === null) {
        return {
          ok: true,
          value: {
            status: 'absent',
            record: null,
            observedAt: null,
            persistedState: null,
          },
        };
      }
      if (typeof raw !== 'object') {
        throw new OsvListingProviderContactAuthorizationMappingError('row mapping failed.');
      }
      const record = raw as Record<string, unknown>;
      const observed =
        record['observed_at'] instanceof Date
          ? record['observed_at']
          : record['observedAt'] instanceof Date
            ? record['observedAt']
            : null;
      if (observed === null) {
        throw new OsvListingProviderContactAuthorizationMappingError(
          'database time mapping failed.',
        );
      }
      const observedAt = toIsoUtc(observed);
      let row: ProviderContactAuthorizationRow;
      try {
        row = coerceProviderContactAuthorizationRow(record);
      } catch (error) {
        if (error instanceof OsvListingProviderContactAuthorizationMappingError) {
          return {
            ok: true,
            value: {
              status: 'malformed_authority',
              record: null,
              observedAt,
              persistedState: null,
            },
          };
        }
        throw error;
      }
      if (row.synchronizationRequestId !== query.synchronizationRequestId) {
        return fail('request_mismatch');
      }
      if (row.synchronizationRunId !== query.synchronizationRunId) {
        return fail('run_mismatch');
      }
      const mapped = mapRow(row);
      let status: OsvListingProviderContactInspection['status'];
      if (row.state === 'issued') {
        status = databaseNowIsExpired(observedAt, toIsoUtc(row.expiresAt)) ? 'expired' : 'issued';
      } else if (row.state === 'consumed_for_listing_execution') {
        status =
          row.consumedBySynchronizationRequestId === query.synchronizationRequestId &&
          row.consumedBySynchronizationRunId === query.synchronizationRunId
            ? 'consumed_same_run'
            : 'consumed_other_run';
      } else {
        status = row.state;
      }
      return {
        ok: true,
        value: {
          status,
          record: status === 'consumed_other_run' ? null : mapped,
          observedAt,
          persistedState: row.state,
        },
      };
    } catch (error) {
      if (error instanceof OsvListingProviderContactAuthorizationMappingError) {
        return {
          ok: true,
          value: {
            status: 'malformed_authority',
            record: null,
            observedAt: null,
            persistedState: null,
          },
        };
      }
      const mapped = mapCaught(error);
      if (!mapped.ok && mapped.code === 'database_unavailable') {
        return {
          ok: true,
          value: {
            status: 'database_unavailable',
            record: null,
            observedAt: null,
            persistedState: null,
          },
        };
      }
      return mapped;
    }
  }

  public async consume(
    command: OsvListingProviderContactAuthorizationConsumeCommand,
  ): Promise<OsvListingProviderContactPersistenceResult<OsvListingProviderContactConsumeResult>> {
    if (!isOsvListingProviderContactAuthorizationConsumeCommand(command)) {
      return fail('not_constructed');
    }
    try {
      return await runSerializable(this.client, async (tx) => {
        const updated = await tx.$queryRaw<unknown[]>`
          UPDATE "osv_listing_provider_contact_authorization"
          SET
            "state" = 'consumed_for_listing_execution',
            "consumed_at" = CURRENT_TIMESTAMP,
            "consumed_by_synchronization_request_id" = ${command.synchronizationRequestId}::uuid,
            "consumed_by_synchronization_run_id" = ${command.synchronizationRunId}::uuid
          WHERE "id" = ${command.authorizationId}::uuid
            AND "state" = 'issued'
            AND "operator_identity_id" = ${command.operatorAttestationId}::uuid
            AND "source_canary_authorization_id" = ${command.sourceCanaryAuthorizationId}::uuid
            AND "synchronization_request_id" = ${command.synchronizationRequestId}::uuid
            AND "synchronization_run_id" = ${command.synchronizationRunId}::uuid
            AND "preflight_evidence_id" = ${command.preflightEvidenceId}::uuid
            AND "provider_identity" = ${command.providerIdentity}
            AND "approved_prefix" = ${command.approvedPrefix}
            AND "canary_policy_identifier" = ${command.canaryPolicyIdentifier}
            AND "listing_budget_profile" = ${command.listingBudgetProfile}
            AND "runtime_version_set_fingerprint" = ${command.runtimeVersionSetFingerprint}
            AND "legal_decision_id" = ${command.legalDecisionId}::uuid
            AND "egress_evidence_id" = ${command.egressEvidenceId}::uuid
            AND "deployment_id" = ${command.deploymentId}::uuid
            AND "phase" = 'listing_only'
            AND "provider_retry_authorization" = 'prohibited'
            AND "provider_body_authorization" = 'prohibited'
            AND "catalog_activation_authorization" = 'prohibited'
            AND CURRENT_TIMESTAMP >= "issued_at"
            AND CURRENT_TIMESTAMP < "expires_at"
            AND CURRENT_TIMESTAMP < "legal_revalidation_boundary_at"
            AND EXISTS (
              SELECT 1
              FROM "osv_canary_instance_operator_identity" AS operator
              WHERE operator."id" = "osv_listing_provider_contact_authorization"."operator_identity_id"
                AND operator."status" = 'active'
            )
          RETURNING *
        `;
        const consumed = firstProviderContactRow(updated, coerceProviderContactAuthorizationRow);
        if (consumed !== undefined) {
          return {
            ok: true as const,
            value: createOsvListingProviderContactConsumeResult({
              outcome: 'consumed',
              record: mapRow(consumed),
            }),
          };
        }
        return this.reloadConsume(tx, command);
      });
    } catch (error) {
      if (isUniqueViolation(error)) {
        try {
          return await this.reloadConsume(this.client, command);
        } catch (reloadError) {
          return mapCaught(reloadError);
        }
      }
      if (isRestrictViolation(error)) {
        try {
          return await this.reloadConsume(this.client, command);
        } catch (reloadError) {
          return mapCaught(reloadError);
        }
      }
      return mapCaught(error);
    }
  }

  public async revoke(
    command: OsvListingProviderContactAuthorizationRevokeCommand,
  ): Promise<OsvListingProviderContactPersistenceResult<OsvListingProviderContactMutationResult>> {
    if (!isOsvListingProviderContactAuthorizationRevokeCommand(command)) {
      return fail('not_constructed');
    }
    try {
      return await runSerializable(this.client, async (tx) => {
        const updated = await tx.$queryRaw<unknown[]>`
          UPDATE "osv_listing_provider_contact_authorization"
          SET
            "state" = 'revoked',
            "revoked_at" = CURRENT_TIMESTAMP,
            "revoked_by_operator_identity_id" = ${command.operatorAttestationId}::uuid,
            "terminal_at" = CURRENT_TIMESTAMP,
            "terminal_disposition" = 'revoked'
          WHERE "id" = ${command.authorizationId}::uuid
            AND "state" = 'issued'
            AND "operator_identity_id" = ${command.operatorAttestationId}::uuid
            AND CURRENT_TIMESTAMP < "expires_at"
            AND EXISTS (
              SELECT 1
              FROM "osv_canary_instance_operator_identity" AS operator
              WHERE operator."id" = ${command.operatorAttestationId}::uuid
                AND operator."status" = 'active'
            )
          RETURNING *
        `;
        const revoked = firstProviderContactRow(updated, coerceProviderContactAuthorizationRow);
        if (revoked !== undefined) {
          return {
            ok: true as const,
            value: {
              status: 'transitioned' as const,
              record: mapRow(revoked),
            },
          };
        }
        return this.reloadRevoke(tx, command);
      });
    } catch (error) {
      if (isRestrictViolation(error)) {
        try {
          return await this.reloadRevoke(this.client, command);
        } catch (reloadError) {
          return mapCaught(reloadError);
        }
      }
      return mapCaught(error);
    }
  }

  private async validateIssuePrerequisites(
    tx: PrismaClientLike,
    command: OsvListingProviderContactAuthorizationIssueCommand,
  ): Promise<OsvListingProviderContactPersistenceResult<{ readonly fingerprint: string }>> {
    const now = await observeDatabaseNow(tx);
    if (!timestampNotAfter(command.legalApproval.issuedAt, now)) {
      return fail('invalid_timestamp');
    }
    if (databaseNowIsExpired(toIsoUtc(now), command.legalApproval.revalidationBoundaryAt)) {
      return fail('legal_gate_blocked');
    }
    if (
      !timestampNotAfter(command.egressEvidence.reviewedAt, now) ||
      !timestampNotAfter(command.deploymentApproval.approvedAt, now) ||
      !timestampNotAfter(command.haltProcedureAcknowledgement.acknowledgedAt, now) ||
      !timestampNotAfter(command.runbookAcknowledgement.acknowledgedAt, now) ||
      !timestampNotAfter(command.containmentAcknowledgement.acknowledgedAt, now) ||
      !timestampNotAfter(command.reviewerAssignment.assignedAt, now) ||
      !timestampNotAfter(command.retentionDisposition.acknowledgedAt, now)
    ) {
      return fail('invalid_timestamp');
    }
    const operator = await tx.osvCanaryInstanceOperatorIdentity.findUnique({
      where: { id: command.operatorAttestationId },
    });
    if (operator === null) {
      return fail('operator_absent');
    }
    if (operator.status !== 'active') {
      return fail('operator_revoked');
    }
    const source = await tx.osvCanaryAuthorization.findUnique({
      where: { id: command.sourceCanaryAuthorizationId },
    });
    if (source === null) {
      return fail('canary_authorization_absent');
    }
    if (source.phase !== 'listing_only') {
      return fail('phase_mismatch');
    }
    if (source.state === 'completed' || source.state === 'failed' || source.state === 'cancelled') {
      return fail('canary_authorization_terminal');
    }
    if (source.state !== 'consumed') {
      return fail('canary_authorization_not_consumed');
    }
    if (source.operatorIdentityId !== command.operatorAttestationId) {
      return fail('identity_mismatch');
    }
    if (
      source.consumedBySynchronizationRequestId !== command.synchronizationRequestId ||
      source.consumedBySynchronizationRunId !== command.synchronizationRunId
    ) {
      return fail('request_mismatch');
    }
    if (source.sourceIdentifier !== 'rustsec_advisory_database') {
      return fail('provider_mismatch');
    }
    if (source.providerPrefix !== 'crates.io/') {
      return fail('prefix_mismatch');
    }
    if (source.canaryPolicyIdentifier !== 'osv_disabled_first_provider_canary_policy_v1') {
      return fail('policy_mismatch');
    }
    if (source.budgetProfileIdentifier !== 'osv_canary_listing_only_budget_v1') {
      return fail('budget_mismatch');
    }
    if (source.runtimeVersionSetFingerprint !== FINGERPRINT) {
      return fail('version_set_mismatch');
    }
    if (source.legalDecisionId !== command.legalApproval.sourceCanaryLegalDecisionId) {
      return fail('legal_gate_blocked');
    }
    if (source.catalogActivationAuthorization !== 'prohibited') {
      return fail('policy_mismatch');
    }
    const request = await tx.osvRuntimeSynchronizationRequest.findUnique({
      where: { id: command.synchronizationRequestId },
    });
    const run = await tx.osvRuntimeSynchronizationRun.findUnique({
      where: { id: command.synchronizationRunId },
    });
    if (request === null || run === null) {
      return fail('foreign_key_conflict');
    }
    if (
      run.requestId !== request.id ||
      request.synchronizationReason !== 'operator_canary' ||
      request.workScope !== 'osv_runtime_canary_scope_crates_io_rustsec_v1' ||
      request.versionSetFingerprint !== FINGERPRINT ||
      request.leaseScope !== 'osv_runtime_lease_scope_osv_gcs_public_export_v1'
    ) {
      return fail('request_mismatch');
    }
    if (TERMINAL_RUN_STATES.has(run.state)) {
      return fail('state_conflict');
    }
    const preflight = await tx.osvCanaryProviderFreePreflightAttestation.findUnique({
      where: { id: command.preflightEvidenceId },
    });
    if (preflight === null) {
      return fail('preflight_evidence_invalid');
    }
    if (
      preflight.sourceCanaryAuthorizationId !== command.sourceCanaryAuthorizationId ||
      preflight.operatorIdentityId !== command.operatorAttestationId ||
      preflight.synchronizationRequestId !== command.synchronizationRequestId ||
      preflight.synchronizationRunId !== command.synchronizationRunId ||
      preflight.phase !== 'listing_only' ||
      preflight.providerContactAuthorized !== false ||
      preflight.executionPermitted !== false ||
      preflight.acceptedForProviderContactAuth !== true ||
      preflight.activePointerBaselineIdentity !== command.activePointerBaselineIdentity ||
      preflight.zeroFindingBaselineIdentity !== command.zeroFindingBaselineIdentity ||
      preflight.runtimeVersionSetFingerprint !== FINGERPRINT
    ) {
      return fail('preflight_evidence_invalid');
    }
    return { ok: true, value: { fingerprint: source.runtimeVersionSetFingerprint } };
  }

  private async insertAuthorization(
    tx: PrismaClientLike,
    command: OsvListingProviderContactAuthorizationIssueCommand,
    fingerprint: string,
  ): Promise<OsvListingProviderContactPersistenceResult<OsvListingProviderContactIssueResult>> {
    const inserted = await tx.$queryRaw<unknown[]>`
      INSERT INTO "osv_listing_provider_contact_authorization" (
        "id",
        "authorization_schema_version",
        "source_canary_authorization_id",
        "operator_identity_id",
        "synchronization_request_id",
        "synchronization_run_id",
        "preflight_evidence_id",
        "phase",
        "provider_identity",
        "bucket_identity",
        "listing_api_path_policy",
        "listing_protocol",
        "approved_prefix",
        "family",
        "canary_policy_identifier",
        "listing_budget_profile",
        "work_scope",
        "lease_scope",
        "synchronization_reason",
        "runtime_architecture_identifier",
        "runtime_version_set_fingerprint",
        "query_grammar_policy",
        "transport_policy",
        "content_encoding_policy",
        "redirect_policy",
        "unused_ttl_seconds",
        "single_use_policy",
        "provider_retry_authorization",
        "provider_body_authorization",
        "parser_authorization",
        "catalog_activation_authorization",
        "matching_authorization",
        "finding_authorization",
        "legal_approval_identifier",
        "legal_decision_id",
        "source_canary_legal_decision_id",
        "legal_decision_source_registry_version",
        "legal_listing_metadata_permission",
        "legal_body_retrieval_permission",
        "legal_parsing_permission",
        "legal_matching_permission",
        "legal_issued_at",
        "legal_revalidation_boundary_at",
        "legal_evidence_set_id",
        "legal_approval_role",
        "legal_supersession_status",
        "egress_evidence_identifier",
        "egress_evidence_id",
        "egress_evidence_version",
        "egress_reviewer_role",
        "egress_reviewed_at",
        "provider_connectivity_exercised",
        "deployment_approval_identifier",
        "deployment_id",
        "environment_class",
        "runtime_artifact_version",
        "configuration_fingerprint",
        "observability_policy",
        "deployment_approval_role",
        "deployment_approved_at",
        "invalidates_on_deployment_change",
        "heartbeat_policy_identifier",
        "deadline_policy_identifier",
        "runbook_set_identifier",
        "runbook_version",
        "runbook_acknowledged_at",
        "halt_procedure_identifier",
        "halt_acknowledged_at",
        "containment_catalog_identifier",
        "containment_acknowledged_at",
        "postcanary_review_policy_identifier",
        "required_review_role",
        "reviewer_assigned_at",
        "issuing_operator_may_review",
        "automatic_progression",
        "evidence_retention_policy_identifier",
        "retention_acknowledged_at",
        "active_pointer_baseline_identity",
        "zero_finding_baseline_identity",
        "issued_at",
        "expires_at",
        "state",
        "created_at"
      )
      SELECT
        ${command.providerContactAuthorizationId}::uuid,
        'osv_listing_only_provider_contact_authorization_v1',
        ${command.sourceCanaryAuthorizationId}::uuid,
        ${command.operatorAttestationId}::uuid,
        ${command.synchronizationRequestId}::uuid,
        ${command.synchronizationRunId}::uuid,
        ${command.preflightEvidenceId}::uuid,
        'listing_only',
        'rustsec_advisory_database',
        'osv-vulnerabilities',
        '/storage/v1/b/osv-vulnerabilities/o',
        'osv_gcs_json_objects_list_v1',
        'crates.io/',
        'RUSTSEC',
        'osv_disabled_first_provider_canary_policy_v1',
        'osv_canary_listing_only_budget_v1',
        'osv_runtime_canary_scope_crates_io_rustsec_v1'::"osv_runtime_work_scope",
        'osv_runtime_lease_scope_osv_gcs_public_export_v1',
        'operator_canary'::"osv_runtime_synchronization_reason",
        'osv_runtime_enablement_architecture_v1',
        ${fingerprint},
        'committed',
        'osv_transport_policy_v1',
        'identity',
        'error',
        3600,
        'single_use',
        'prohibited',
        'prohibited',
        'prohibited',
        'prohibited',
        'prohibited',
        'prohibited',
        'osv_listing_provider_contact_legal_approval_v1',
        ${command.legalApproval.decisionId}::uuid,
        ${command.legalApproval.sourceCanaryLegalDecisionId}::uuid,
        'osv_source_license_registry_v1',
        'approved',
        'prohibited',
        'prohibited',
        'prohibited',
        ${new Date(command.legalApproval.issuedAt)},
        ${new Date(command.legalApproval.revalidationBoundaryAt)},
        ${command.legalApproval.evidenceSetId}::uuid,
        'instance_legal_and_provenance_reviewer_countersigned_by_instance_operator',
        'current',
        'osv_listing_provider_contact_egress_evidence_v1',
        ${command.egressEvidence.egressEvidenceId}::uuid,
        'osv_listing_provider_contact_egress_evidence_v1',
        'instance_operator_deployment_reviewer',
        ${new Date(command.egressEvidence.reviewedAt)},
        FALSE,
        'osv_listing_provider_contact_deployment_approval_v1',
        ${command.deploymentApproval.deploymentId}::uuid,
        'dedicated_instance_operator_process',
        ${command.deploymentApproval.runtimeArtifactVersion},
        ${command.deploymentApproval.configurationFingerprint},
        'osv_listing_provider_contact_observability_policy_v1',
        'instance_operator_deployment_reviewer',
        ${new Date(command.deploymentApproval.approvedAt)},
        TRUE,
        'osv_canary_runtime_controls_v1',
        'osv_canary_runtime_controls_v1',
        'osv_listing_provider_contact_runbook_set_v1',
        'osv_listing_provider_contact_runbook_v1',
        ${new Date(command.runbookAcknowledgement.acknowledgedAt)},
        'osv_listing_provider_contact_halt_procedure_v1',
        ${new Date(command.haltProcedureAcknowledgement.acknowledgedAt)},
        'osv_listing_provider_contact_emergency_containment_v1',
        ${new Date(command.containmentAcknowledgement.acknowledgedAt)},
        'osv_listing_provider_contact_postcanary_review_v1',
        'instance_canary_evidence_reviewer',
        ${new Date(command.reviewerAssignment.assignedAt)},
        FALSE,
        FALSE,
        'osv_listing_provider_contact_retention_disposition_v1',
        ${new Date(command.retentionDisposition.acknowledgedAt)},
        ${command.activePointerBaselineIdentity}::uuid,
        ${command.zeroFindingBaselineIdentity}::uuid,
        CURRENT_TIMESTAMP,
        CURRENT_TIMESTAMP + INTERVAL '3600 seconds',
        'issued'::"osv_listing_provider_contact_authorization_state",
        CURRENT_TIMESTAMP
      WHERE CURRENT_TIMESTAMP < ${new Date(command.legalApproval.revalidationBoundaryAt)}
      ON CONFLICT ("id") DO NOTHING
      RETURNING *
    `;
    const created = firstProviderContactRow(inserted, coerceProviderContactAuthorizationRow);
    if (created !== undefined) {
      return {
        ok: true,
        value: {
          status: 'created',
          record: mapRow(created),
        },
      };
    }
    return this.reloadIssue(tx, command, 'identity');
  }

  private async reloadIssue(
    client: PrismaClientLike,
    command: OsvListingProviderContactAuthorizationIssueCommand,
    conflict: ReturnType<typeof classifyProviderContactUniqueConflict>,
  ): Promise<OsvListingProviderContactPersistenceResult<OsvListingProviderContactIssueResult>> {
    let existing: ProviderContactAuthorizationRow | null = null;
    if (conflict === 'source') {
      const rows = await client.$queryRaw<unknown[]>`
        SELECT *
        FROM "osv_listing_provider_contact_authorization"
        WHERE "source_canary_authorization_id" = ${command.sourceCanaryAuthorizationId}::uuid
      `;
      existing = firstProviderContactRow(rows, coerceProviderContactAuthorizationRow) ?? null;
    } else if (conflict === 'request') {
      const rows = await client.$queryRaw<unknown[]>`
        SELECT *
        FROM "osv_listing_provider_contact_authorization"
        WHERE "synchronization_request_id" = ${command.synchronizationRequestId}::uuid
      `;
      existing = firstProviderContactRow(rows, coerceProviderContactAuthorizationRow) ?? null;
    } else if (conflict === 'run') {
      const rows = await client.$queryRaw<unknown[]>`
        SELECT *
        FROM "osv_listing_provider_contact_authorization"
        WHERE "synchronization_run_id" = ${command.synchronizationRunId}::uuid
      `;
      existing = firstProviderContactRow(rows, coerceProviderContactAuthorizationRow) ?? null;
    } else if (conflict === 'preflight') {
      const rows = await client.$queryRaw<unknown[]>`
        SELECT *
        FROM "osv_listing_provider_contact_authorization"
        WHERE "preflight_evidence_id" = ${command.preflightEvidenceId}::uuid
      `;
      existing = firstProviderContactRow(rows, coerceProviderContactAuthorizationRow) ?? null;
    } else {
      existing = await loadAuthorization(client, command.providerContactAuthorizationId);
    }
    if (existing === null) {
      const now = await observeDatabaseNow(client);
      if (databaseNowIsExpired(toIsoUtc(now), command.legalApproval.revalidationBoundaryAt)) {
        return fail('legal_gate_blocked');
      }
      return fail('immutable_conflict');
    }
    if (existing.state !== 'issued') {
      return fail('immutable_conflict');
    }
    const now = await observeDatabaseNow(client);
    if (databaseNowIsExpired(toIsoUtc(now), toIsoUtc(existing.expiresAt))) {
      return fail('immutable_conflict');
    }
    const mapped = mapRow(existing);
    if (
      compareOsvListingProviderContactPersistedAuthorization(mapped, command) !==
        'already_applied' ||
      !issueRowMatchesCommand(existing, command)
    ) {
      return fail('immutable_conflict');
    }
    return { ok: true, value: { status: 'already_applied', record: mapped } };
  }

  private async reloadConsume(
    client: PrismaClientLike,
    command: OsvListingProviderContactAuthorizationConsumeCommand,
  ): Promise<OsvListingProviderContactPersistenceResult<OsvListingProviderContactConsumeResult>> {
    const existing = await loadAuthorization(client, command.authorizationId);
    if (existing === null) {
      return fail('authorization_not_found');
    }
    const now = await observeDatabaseNow(client);
    if (existing.state === 'consumed_for_listing_execution') {
      const mapped = mapRow(existing);
      const mismatch = bindingMismatch(existing, command);
      if (
        mismatch === 'request_mismatch' ||
        mismatch === 'run_mismatch' ||
        !sameRunProviderContactConsumption(mapped, command)
      ) {
        return fail('already_consumed_other_run');
      }
      if (mismatch !== null) {
        return fail(mismatch);
      }
      return {
        ok: true,
        value: createOsvListingProviderContactConsumeResult({
          outcome: 'already_consumed_same_run',
          record: mapped,
        }),
      };
    }
    if (existing.state === 'revoked') {
      return fail('authorization_revoked');
    }
    if (existing.state === 'expired') {
      return fail('authorization_expired');
    }
    if (TERMINAL_CONSUME_STATES.has(existing.state)) {
      return fail('authorization_terminal');
    }
    const mismatch = bindingMismatch(existing, command);
    if (mismatch !== null) {
      return fail(mismatch);
    }
    const operator = await client.osvCanaryInstanceOperatorIdentity.findUnique({
      where: { id: existing.operatorIdentityId },
    });
    if (operator === null) {
      return fail('operator_absent');
    }
    if (operator.status !== 'active') {
      return fail('operator_revoked');
    }
    const source = await client.osvCanaryAuthorization.findUnique({
      where: { id: existing.sourceCanaryAuthorizationId },
    });
    if (source === null) {
      return fail('canary_authorization_absent');
    }
    if (source.state !== 'consumed') {
      return fail('canary_authorization_not_consumed');
    }
    const preflight = await client.osvCanaryProviderFreePreflightAttestation.findUnique({
      where: { id: existing.preflightEvidenceId },
    });
    if (
      preflight === null ||
      preflight.providerContactAuthorized !== false ||
      preflight.acceptedForProviderContactAuth !== true
    ) {
      return fail('preflight_evidence_invalid');
    }
    if (databaseNowIsExpired(toIsoUtc(now), toIsoUtc(existing.expiresAt))) {
      return fail('authorization_expired');
    }
    if (databaseNowIsExpired(toIsoUtc(now), toIsoUtc(existing.legalRevalidationBoundaryAt))) {
      return fail('legal_gate_blocked');
    }
    if (now.getTime() < existing.issuedAt.getTime()) {
      return fail('authorization_not_issued');
    }
    return fail('state_conflict');
  }

  private async reloadRevoke(
    client: PrismaClientLike,
    command: OsvListingProviderContactAuthorizationRevokeCommand,
  ): Promise<OsvListingProviderContactPersistenceResult<OsvListingProviderContactMutationResult>> {
    const existing = await loadAuthorization(client, command.authorizationId);
    if (existing === null) {
      return fail('authorization_not_found');
    }
    const mapped = mapRow(existing);
    if (
      existing.state === 'revoked' &&
      existing.revokedByOperatorIdentityId === command.operatorAttestationId
    ) {
      return { ok: true, value: { status: 'already_applied', record: mapped } };
    }
    if (existing.operatorIdentityId !== command.operatorAttestationId) {
      return fail('identity_mismatch');
    }
    const operator = await client.osvCanaryInstanceOperatorIdentity.findUnique({
      where: { id: command.operatorAttestationId },
    });
    if (operator === null) {
      return fail('operator_absent');
    }
    if (operator.status !== 'active') {
      return fail('operator_revoked');
    }
    if (existing.state === 'consumed_for_listing_execution') {
      return fail('authorization_terminal');
    }
    if (existing.state === 'expired') {
      return fail('authorization_expired');
    }
    if (TERMINAL_CONSUME_STATES.has(existing.state)) {
      return fail('authorization_terminal');
    }
    const now = await observeDatabaseNow(client);
    if (
      existing.state === 'issued' &&
      databaseNowIsExpired(toIsoUtc(now), toIsoUtc(existing.expiresAt))
    ) {
      return fail('authorization_expired');
    }
    return fail('state_conflict');
  }
}
