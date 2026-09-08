/**
 * Session 13 Batch 2C PostgreSQL adapters for instance-operator identity and
 * single-use OSV canary authorization.
 *
 * Durable authorization authority only. No operator authentication, CLI,
 * scheduler, heartbeat, deadline timer, provider I/O, retries, catalog
 * activation, matching, Findings, or production composition.
 *
 * Adapters perform one insert or one guarded update per command and do not
 * retry serialization internally.
 */

import { Prisma, type PrismaClient } from '@prisma/client';
import {
  classifyConsumedReplay,
  compareOsvCanaryPersistedAuthorization,
  compareOsvCanaryPersistedOperator,
  databaseNowIsExpired,
  getOsvCanaryBudgetProfile,
  isOsvCanaryAuthorizationCancelCommand,
  isOsvCanaryAuthorizationConsumePersistenceCommand,
  isOsvCanaryAuthorizationEnsureCommand,
  isOsvCanaryAuthorizationExpireCommand,
  isOsvCanaryAuthorizationLookupQuery,
  isOsvCanaryAuthorizationRevokeCommand,
  isOsvCanaryAuthorizationTerminalCommand,
  isOsvCanaryOperatorEnsureCommand,
  isOsvCanaryOperatorLookupQuery,
  isOsvCanaryOperatorRevokeCommand,
  osvCanaryRuntimeVersionSetFingerprint,
  type OsvCanaryAuthorizationCancelCommand,
  type OsvCanaryAuthorizationConsumePersistenceCommand,
  type OsvCanaryAuthorizationConsumePersistenceResult,
  type OsvCanaryAuthorizationEnsureCommand,
  type OsvCanaryAuthorizationEnsureResult,
  type OsvCanaryAuthorizationExpireCommand,
  type OsvCanaryAuthorizationLookupQuery,
  type OsvCanaryAuthorizationMutationResult,
  type OsvCanaryAuthorizationPersistencePort,
  type OsvCanaryAuthorizationRejectionCode,
  type OsvCanaryAuthorizationResult,
  type OsvCanaryAuthorizationRevokeCommand,
  type OsvCanaryAuthorizationTerminalCommand,
  type OsvCanaryAuthorizationValidityInspection,
  type OsvCanaryOperatorAuthorityInspection,
  type OsvCanaryOperatorEnsureCommand,
  type OsvCanaryOperatorEnsureResult,
  type OsvCanaryOperatorLookupQuery,
  type OsvCanaryOperatorRevokeCommand,
  type OsvCanaryOperatorRevokeResult,
  type OsvCanaryPersistedAuthorization,
} from '@patchpilot/vulnerability-intelligence';

import { isRootPrismaClient, type PrismaClientLike } from './guards.js';
import {
  isRestrictViolation,
  isUniqueViolation,
  classifyCanaryUniqueConflict,
  translateCanaryAuthorizationFailure,
} from './osv-canary-authorization-errors.js';
import {
  coerceAuthorizationRow,
  coerceOperatorRow,
  firstRow,
  mapAuthorization,
  mapOperator,
  OsvCanaryAuthorizationMappingError,
  toIsoUtc,
  type AuthorizationRow,
  type OperatorRow,
} from './osv-canary-authorization-mappers.js';

const ROOT_CLIENT_REQUIRED =
  'OSV canary authorization persistence requires the root database client.';
const FINGERPRINT = osvCanaryRuntimeVersionSetFingerprint();
const LISTING_BUDGET = getOsvCanaryBudgetProfile('listing_only').identifier;
const BODY_BUDGET = getOsvCanaryBudgetProfile('bounded_body').identifier;
const TERMINAL_RUN_STATES = new Set(['completed', 'failed', 'cancelled']);

export type OsvCanaryAuthorizationPersistenceAdapters = OsvCanaryAuthorizationPersistencePort;

export function createOsvCanaryAuthorizationPersistence(
  client: PrismaClient,
): OsvCanaryAuthorizationPersistenceAdapters {
  if (client === null || client === undefined || !isRootPrismaClient(client)) {
    throw new OsvCanaryAuthorizationPersistenceFailure(ROOT_CLIENT_REQUIRED);
  }
  return createOsvCanaryAuthorizationPersistenceForClient(client);
}

export function createOsvCanaryAuthorizationPersistenceForClient(
  client: PrismaClientLike,
): OsvCanaryAuthorizationPersistenceAdapters {
  return {
    operators: new PrismaOsvCanaryOperatorRepository(client),
    authorizations: new PrismaOsvCanaryAuthorizationRepository(client),
  };
}

class OsvCanaryAuthorizationPersistenceFailure extends Error {
  public constructor(message: string) {
    super(message);
    this.name = 'OsvCanaryAuthorizationPersistenceFailure';
  }
}

function fail(code: OsvCanaryAuthorizationRejectionCode): OsvCanaryAuthorizationResult<never> {
  return { ok: false, code };
}

function sqlUuid(value: string | null): Prisma.Sql {
  return value === null ? Prisma.sql`NULL::uuid` : Prisma.sql`${value}::uuid`;
}

function sqlText(value: string | null): Prisma.Sql {
  return value === null ? Prisma.sql`NULL` : Prisma.sql`${value}`;
}

function sqlTimestamp(value: Date | null): Prisma.Sql {
  return value === null ? Prisma.sql`NULL::timestamptz` : Prisma.sql`${value}`;
}

function sqlPhase(value: string | null): Prisma.Sql {
  return value === null
    ? Prisma.sql`NULL::"osv_canary_phase"`
    : Prisma.sql`${value}::"osv_canary_phase"`;
}

function sqlLegalOperation(value: string | null): Prisma.Sql {
  return value === null
    ? Prisma.sql`NULL::"osv_canary_legal_permitted_operation"`
    : Prisma.sql`${value}::"osv_canary_legal_permitted_operation"`;
}

function sqlListingVerdict(value: string | null): Prisma.Sql {
  return value === null
    ? Prisma.sql`NULL::"osv_canary_listing_review_verdict"`
    : Prisma.sql`${value}::"osv_canary_listing_review_verdict"`;
}

function consumeReplayOutcome(
  existing: AuthorizationRow,
  mapped: OsvCanaryPersistedAuthorization,
  command: OsvCanaryAuthorizationConsumePersistenceCommand,
): OsvCanaryAuthorizationResult<OsvCanaryAuthorizationConsumePersistenceResult> {
  if (existing.operatorIdentityId !== command.operatorAttestationId) {
    return { ok: true, value: { outcome: 'identity_mismatch', authorization: mapped } };
  }
  if (
    existing.phase !== command.phase ||
    existing.providerPrefix !== command.providerPrefix ||
    existing.canaryPolicyIdentifier !== command.canaryPolicyIdentifier ||
    existing.runtimeVersionSetFingerprint !== command.runtimeVersionSetFingerprint
  ) {
    return { ok: true, value: { outcome: 'policy_mismatch', authorization: mapped } };
  }
  return {
    ok: true,
    value: { outcome: classifyConsumedReplay(mapped, command), authorization: mapped },
  };
}

function mapCaught(error: unknown): OsvCanaryAuthorizationResult<never> {
  if (error instanceof OsvCanaryAuthorizationMappingError) {
    return fail('malformed_authority');
  }
  return fail(translateCanaryAuthorizationFailure(error));
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
    throw new OsvCanaryAuthorizationMappingError('database time mapping failed.');
  }
  return now;
}

async function loadOperator(
  client: PrismaClientLike,
  operatorAttestationId: string,
): Promise<OperatorRow | null> {
  const row = await client.osvCanaryInstanceOperatorIdentity.findUnique({
    where: { id: operatorAttestationId },
  });
  return row === null ? null : coerceOperatorRow(row);
}

async function loadAuthorization(
  client: PrismaClientLike,
  authorizationId: string,
): Promise<AuthorizationRow | null> {
  const row = await client.osvCanaryAuthorization.findUnique({
    where: { id: authorizationId },
  });
  return row === null ? null : coerceAuthorizationRow(row);
}

async function mapLoadedAuthorization(
  client: PrismaClientLike,
  row: AuthorizationRow,
): Promise<OsvCanaryPersistedAuthorization> {
  const operatorRow = await loadOperator(client, row.operatorIdentityId);
  if (operatorRow === null) {
    throw new OsvCanaryAuthorizationMappingError('issuing operator missing.');
  }
  return mapAuthorization(row, mapOperator(operatorRow));
}

class PrismaOsvCanaryOperatorRepository {
  public constructor(private readonly client: PrismaClientLike) {}

  public async ensure(
    command: OsvCanaryOperatorEnsureCommand,
  ): Promise<OsvCanaryAuthorizationResult<OsvCanaryOperatorEnsureResult>> {
    if (!isOsvCanaryOperatorEnsureCommand(command)) {
      return fail('not_constructed');
    }
    try {
      return await runSerializable(this.client, async (tx) => {
        const inserted = await tx.$queryRaw<unknown[]>`
          INSERT INTO "osv_canary_instance_operator_identity" (
            "id",
            "identity_schema_version",
            "identity_type",
            "authentication_source",
            "provenance_identifier",
            "display_label",
            "established_at",
            "status",
            "created_at"
          )
          VALUES (
            ${command.operatorAttestationId}::uuid,
            'osv_canary_instance_operator_identity_v1',
            'instance_operator',
            'local_host_control_of_one_shot_administrative_command',
            'configured_instance_operator_attestation_v1',
            ${command.displayLabel},
            CURRENT_TIMESTAMP,
            'active',
            CURRENT_TIMESTAMP
          )
          ON CONFLICT ("id") DO NOTHING
          RETURNING *
        `;
        const created = firstRow(inserted, coerceOperatorRow);
        if (created !== undefined) {
          return {
            ok: true as const,
            value: { status: 'created' as const, operator: mapOperator(created) },
          };
        }
        return this.reloadEnsure(tx, command);
      });
    } catch (error) {
      if (isUniqueViolation(error)) {
        return this.reloadEnsure(this.client, command);
      }
      return mapCaught(error);
    }
  }

  public async lookup(
    query: OsvCanaryOperatorLookupQuery,
  ): Promise<OsvCanaryAuthorizationResult<OsvCanaryOperatorAuthorityInspection>> {
    return this.inspectAuthority(query);
  }

  public async inspectAuthority(
    query: OsvCanaryOperatorLookupQuery,
  ): Promise<OsvCanaryAuthorizationResult<OsvCanaryOperatorAuthorityInspection>> {
    if (!isOsvCanaryOperatorLookupQuery(query)) {
      return fail('not_constructed');
    }
    try {
      const row = await loadOperator(this.client, query.operatorAttestationId);
      if (row === null) {
        return { ok: true, value: { status: 'absent', operator: null } };
      }
      const operator = mapOperator(row);
      return {
        ok: true,
        value: {
          status: operator.identity.status === 'revoked' ? 'revoked' : 'current',
          operator,
        },
      };
    } catch (error) {
      if (error instanceof OsvCanaryAuthorizationMappingError) {
        return { ok: true, value: { status: 'malformed_authority', operator: null } };
      }
      const mapped = mapCaught(error);
      if (!mapped.ok && mapped.code === 'database_unavailable') {
        return { ok: true, value: { status: 'database_unavailable', operator: null } };
      }
      return mapped;
    }
  }

  public async revoke(
    command: OsvCanaryOperatorRevokeCommand,
  ): Promise<OsvCanaryAuthorizationResult<OsvCanaryOperatorRevokeResult>> {
    if (!isOsvCanaryOperatorRevokeCommand(command)) {
      return fail('not_constructed');
    }
    try {
      return await runSerializable(this.client, async (tx) => {
        const updated = await tx.$queryRaw<unknown[]>`
          UPDATE "osv_canary_instance_operator_identity"
          SET
            "status" = 'revoked',
            "revoked_at" = CURRENT_TIMESTAMP
          WHERE "id" = ${command.operatorAttestationId}::uuid
            AND "status" = 'active'
          RETURNING *
        `;
        const revoked = firstRow(updated, coerceOperatorRow);
        if (revoked !== undefined) {
          return {
            ok: true as const,
            value: { status: 'transitioned' as const, operator: mapOperator(revoked) },
          };
        }
        const existing = await loadOperator(tx, command.operatorAttestationId);
        if (existing === null) {
          return fail('not_found');
        }
        if (existing.status === 'revoked') {
          return {
            ok: true as const,
            value: { status: 'already_applied' as const, operator: mapOperator(existing) },
          };
        }
        return fail('state_conflict');
      });
    } catch (error) {
      return mapCaught(error);
    }
  }

  private async reloadEnsure(
    client: PrismaClientLike,
    command: OsvCanaryOperatorEnsureCommand,
  ): Promise<OsvCanaryAuthorizationResult<OsvCanaryOperatorEnsureResult>> {
    const existing = await loadOperator(client, command.operatorAttestationId);
    if (existing === null) {
      return fail('not_found');
    }
    const mapped = mapOperator(existing);
    if (compareOsvCanaryPersistedOperator(mapped, command) === 'immutable_conflict') {
      return fail('immutable_conflict');
    }
    if (existing.status === 'revoked') {
      return fail('operator_revoked');
    }
    return { ok: true, value: { status: 'already_applied', operator: mapped } };
  }
}

class PrismaOsvCanaryAuthorizationRepository {
  public constructor(private readonly client: PrismaClientLike) {}

  public async ensure(
    command: OsvCanaryAuthorizationEnsureCommand,
  ): Promise<OsvCanaryAuthorizationResult<OsvCanaryAuthorizationEnsureResult>> {
    if (!isOsvCanaryAuthorizationEnsureCommand(command)) {
      return fail('not_constructed');
    }
    try {
      return await runSerializable(this.client, async (tx) => {
        const operator = await loadOperator(tx, command.operatorAttestationId);
        if (operator === null) {
          return fail('not_found');
        }
        if (operator.status !== 'active') {
          return fail('operator_revoked');
        }
        const now = await observeDatabaseNow(tx);
        const legalIssued = Date.parse(command.legalDecisionReference.issuedAt);
        if (Number.isNaN(legalIssued) || legalIssued > now.getTime()) {
          return fail('invalid_timestamp');
        }
        if (
          databaseNowIsExpired(toIsoUtc(now), command.legalDecisionReference.revalidationBoundaryAt)
        ) {
          return fail('legal_gate_blocked');
        }
        if (Date.parse(command.runbookAcknowledgement.acknowledgedAt) > now.getTime()) {
          return fail('invalid_timestamp');
        }
        if (Date.parse(command.haltControlAcknowledgement.acknowledgedAt) > now.getTime()) {
          return fail('invalid_timestamp');
        }
        if (command.phase === 'bounded_body') {
          const prepared = await this.prepareBoundedBodyInsert(tx, command, now);
          if (!prepared.ok) {
            return prepared;
          }
          return this.insertAuthorization(tx, command, prepared.value.listingRequestId);
        }
        return this.insertAuthorization(tx, command, null);
      });
    } catch (error) {
      if (isUniqueViolation(error)) {
        if (classifyCanaryUniqueConflict(error) === 'listing_review') {
          return fail('listing_review_mismatch');
        }
        const reloaded = await this.reloadEnsure(this.client, command);
        if (!reloaded.ok && reloaded.code === 'not_found') {
          return fail('immutable_conflict');
        }
        return reloaded;
      }
      if (command.phase === 'bounded_body' && isRestrictViolation(error)) {
        return fail('listing_review_mismatch');
      }
      return mapCaught(error);
    }
  }

  public async lookup(
    query: OsvCanaryAuthorizationLookupQuery,
  ): Promise<OsvCanaryAuthorizationResult<OsvCanaryPersistedAuthorization>> {
    if (!isOsvCanaryAuthorizationLookupQuery(query)) {
      return fail('not_constructed');
    }
    try {
      const row = await loadAuthorization(this.client, query.authorizationId);
      if (row === null) {
        return fail('not_found');
      }
      return { ok: true, value: await mapLoadedAuthorization(this.client, row) };
    } catch (error) {
      return mapCaught(error);
    }
  }

  public async inspectValidity(
    query: OsvCanaryAuthorizationLookupQuery,
  ): Promise<OsvCanaryAuthorizationResult<OsvCanaryAuthorizationValidityInspection>> {
    if (!isOsvCanaryAuthorizationLookupQuery(query)) {
      return fail('not_constructed');
    }
    try {
      return await runSerializable(this.client, async (tx) => {
        const now = await observeDatabaseNow(tx);
        const row = await loadAuthorization(tx, query.authorizationId);
        if (row === null) {
          return {
            ok: true as const,
            value: {
              status: 'absent' as const,
              authorization: null,
              observedAt: toIsoUtc(now),
              persistedState: null,
            },
          };
        }
        let authorization: OsvCanaryPersistedAuthorization;
        try {
          authorization = await mapLoadedAuthorization(tx, row);
        } catch (error) {
          if (error instanceof OsvCanaryAuthorizationMappingError) {
            return {
              ok: true as const,
              value: {
                status: 'malformed_authority' as const,
                authorization: null,
                observedAt: toIsoUtc(now),
                persistedState: row.state,
              },
            };
          }
          throw error;
        }
        const operator = await loadOperator(tx, row.operatorIdentityId);
        if (operator !== null && operator.status === 'revoked' && row.state === 'issued') {
          return {
            ok: true as const,
            value: {
              status: 'operator_revoked' as const,
              authorization,
              observedAt: toIsoUtc(now),
              persistedState: row.state,
            },
          };
        }
        let status: OsvCanaryAuthorizationValidityInspection['status'] =
          row.state === 'issued' ? 'issued_and_unexpired' : row.state;
        if (row.state === 'issued') {
          status = databaseNowIsExpired(toIsoUtc(now), toIsoUtc(row.expiresAt))
            ? 'expired'
            : 'issued_and_unexpired';
        }
        return {
          ok: true as const,
          value: {
            status,
            authorization,
            observedAt: toIsoUtc(now),
            persistedState: row.state,
          },
        };
      });
    } catch (error) {
      if (error instanceof OsvCanaryAuthorizationMappingError) {
        return {
          ok: true,
          value: {
            status: 'malformed_authority',
            authorization: null,
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
            authorization: null,
            observedAt: null,
            persistedState: null,
          },
        };
      }
      return mapped;
    }
  }

  public async consume(
    command: OsvCanaryAuthorizationConsumePersistenceCommand,
  ): Promise<OsvCanaryAuthorizationResult<OsvCanaryAuthorizationConsumePersistenceResult>> {
    if (!isOsvCanaryAuthorizationConsumePersistenceCommand(command)) {
      return fail('not_constructed');
    }
    try {
      return await runSerializable(this.client, async (tx) => {
        const operator = await loadOperator(tx, command.operatorAttestationId);
        if (operator === null) {
          return fail('not_found');
        }
        if (operator.status !== 'active') {
          const existing = await loadAuthorization(tx, command.authorizationId);
          if (existing === null) {
            return fail('not_found');
          }
          const mapped = await mapLoadedAuthorization(tx, existing);
          if (existing.state === 'consumed') {
            return consumeReplayOutcome(existing, mapped, command);
          }
          return fail('operator_revoked');
        }
        const request = await tx.osvRuntimeSynchronizationRequest.findUnique({
          where: { id: command.requestId },
        });
        const run = await tx.osvRuntimeSynchronizationRun.findUnique({
          where: { id: command.runId },
        });
        if (request === null || run === null) {
          return fail('not_found');
        }
        if (
          run.requestId !== request.id ||
          request.synchronizationReason !== 'operator_canary' ||
          request.workScope !== 'osv_runtime_canary_scope_crates_io_rustsec_v1' ||
          request.versionSetFingerprint !== command.runtimeVersionSetFingerprint ||
          request.leaseScope !== 'osv_runtime_lease_scope_osv_gcs_public_export_v1' ||
          TERMINAL_RUN_STATES.has(run.state)
        ) {
          return fail('request_run_mismatch');
        }
        const updated = await tx.$queryRaw<unknown[]>`
          UPDATE "osv_canary_authorization"
          SET
            "state" = 'consumed',
            "consumed_at" = CURRENT_TIMESTAMP,
            "consumed_by_synchronization_request_id" = ${command.requestId}::uuid,
            "consumed_by_synchronization_run_id" = ${command.runId}::uuid
          WHERE "id" = ${command.authorizationId}::uuid
            AND "state" = 'issued'
            AND "operator_identity_id" = ${command.operatorAttestationId}::uuid
            AND "phase" = ${command.phase}::"osv_canary_phase"
            AND "provider_prefix" = ${command.providerPrefix}
            AND "canary_policy_identifier" = ${command.canaryPolicyIdentifier}
            AND "runtime_version_set_fingerprint" = ${command.runtimeVersionSetFingerprint}
            AND CURRENT_TIMESTAMP < "expires_at"
            AND CURRENT_TIMESTAMP < "legal_decision_revalidation_boundary_at"
            AND (
              "body_legal_decision_revalidation_boundary_at" IS NULL
              OR CURRENT_TIMESTAMP < "body_legal_decision_revalidation_boundary_at"
            )
            AND EXISTS (
              SELECT 1
              FROM "osv_canary_instance_operator_identity" AS operator
              WHERE operator."id" = "osv_canary_authorization"."operator_identity_id"
                AND operator."status" = 'active'
            )
          RETURNING *
        `;
        const consumed = firstRow(updated, coerceAuthorizationRow);
        if (consumed !== undefined) {
          return {
            ok: true as const,
            value: {
              outcome: 'consumed' as const,
              authorization: await mapLoadedAuthorization(tx, consumed),
            },
          };
        }
        return this.reloadConsume(tx, command);
      });
    } catch (error) {
      if (isUniqueViolation(error)) {
        if (classifyCanaryUniqueConflict(error) === 'consume_binding') {
          return fail('request_run_mismatch');
        }
        return fail('immutable_conflict');
      }
      return mapCaught(error);
    }
  }

  public async revoke(
    command: OsvCanaryAuthorizationRevokeCommand,
  ): Promise<OsvCanaryAuthorizationResult<OsvCanaryAuthorizationMutationResult>> {
    if (!isOsvCanaryAuthorizationRevokeCommand(command)) {
      return fail('not_constructed');
    }
    try {
      return await runSerializable(this.client, async (tx) => {
        const operator = await loadOperator(tx, command.operatorAttestationId);
        if (operator === null) {
          return fail('not_found');
        }
        if (operator.status !== 'active') {
          return fail('operator_revoked');
        }
        const updated = await tx.$queryRaw<unknown[]>`
          UPDATE "osv_canary_authorization"
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
          RETURNING *
        `;
        const revoked = firstRow(updated, coerceAuthorizationRow);
        if (revoked !== undefined) {
          return {
            ok: true as const,
            value: {
              status: 'transitioned' as const,
              authorization: await mapLoadedAuthorization(tx, revoked),
            },
          };
        }
        return this.reloadRevoke(tx, command);
      });
    } catch (error) {
      return mapCaught(error);
    }
  }

  public async cancel(
    command: OsvCanaryAuthorizationCancelCommand,
  ): Promise<OsvCanaryAuthorizationResult<OsvCanaryAuthorizationMutationResult>> {
    if (!isOsvCanaryAuthorizationCancelCommand(command)) {
      return fail('not_constructed');
    }
    try {
      return await runSerializable(this.client, async (tx) => {
        const operator = await loadOperator(tx, command.operatorAttestationId);
        if (operator === null) {
          return fail('not_found');
        }
        if (operator.status !== 'active') {
          return fail('operator_revoked');
        }
        const updated = await tx.$queryRaw<unknown[]>`
          UPDATE "osv_canary_authorization"
          SET
            "state" = 'cancelled',
            "terminal_at" = CURRENT_TIMESTAMP,
            "terminal_disposition" = 'cancelled'
          WHERE "id" = ${command.authorizationId}::uuid
            AND "operator_identity_id" = ${command.operatorAttestationId}::uuid
            AND "state" IN ('issued', 'consumed')
          RETURNING *
        `;
        const cancelled = firstRow(updated, coerceAuthorizationRow);
        if (cancelled !== undefined) {
          return {
            ok: true as const,
            value: {
              status: 'transitioned' as const,
              authorization: await mapLoadedAuthorization(tx, cancelled),
            },
          };
        }
        return this.reloadCancel(tx, command);
      });
    } catch (error) {
      return mapCaught(error);
    }
  }

  public async expire(
    command: OsvCanaryAuthorizationExpireCommand,
  ): Promise<OsvCanaryAuthorizationResult<OsvCanaryAuthorizationMutationResult>> {
    if (!isOsvCanaryAuthorizationExpireCommand(command)) {
      return fail('not_constructed');
    }
    try {
      return await runSerializable(this.client, async (tx) => {
        const updated = await tx.$queryRaw<unknown[]>`
          UPDATE "osv_canary_authorization"
          SET
            "state" = 'expired',
            "terminal_at" = CURRENT_TIMESTAMP,
            "terminal_disposition" = 'expired'
          WHERE "id" = ${command.authorizationId}::uuid
            AND "state" = 'issued'
            AND CURRENT_TIMESTAMP >= "expires_at"
          RETURNING *
        `;
        const expired = firstRow(updated, coerceAuthorizationRow);
        if (expired !== undefined) {
          return {
            ok: true as const,
            value: {
              status: 'transitioned' as const,
              authorization: await mapLoadedAuthorization(tx, expired),
            },
          };
        }
        return this.reloadExpire(tx, command);
      });
    } catch (error) {
      return mapCaught(error);
    }
  }

  public async recordTerminal(
    command: OsvCanaryAuthorizationTerminalCommand,
  ): Promise<OsvCanaryAuthorizationResult<OsvCanaryAuthorizationMutationResult>> {
    if (!isOsvCanaryAuthorizationTerminalCommand(command)) {
      return fail('not_constructed');
    }
    try {
      return await runSerializable(this.client, async (tx) => {
        const updated = await tx.$queryRaw<unknown[]>`
          UPDATE "osv_canary_authorization"
          SET
            "state" = ${command.disposition}::"osv_canary_authorization_state",
            "terminal_at" = CURRENT_TIMESTAMP,
            "terminal_disposition" = ${command.disposition}::"osv_canary_authorization_state",
            "terminal_reason_code" = ${sqlText(command.terminalReasonCode)}
          WHERE "id" = ${command.authorizationId}::uuid
            AND "state" = 'consumed'
            AND "operator_identity_id" = ${command.operatorAttestationId}::uuid
            AND "consumed_by_synchronization_request_id" = ${command.requestId}::uuid
            AND "consumed_by_synchronization_run_id" = ${command.runId}::uuid
          RETURNING *
        `;
        const terminal = firstRow(updated, coerceAuthorizationRow);
        if (terminal !== undefined) {
          return {
            ok: true as const,
            value: {
              status: 'transitioned' as const,
              authorization: await mapLoadedAuthorization(tx, terminal),
            },
          };
        }
        return this.reloadTerminal(tx, command);
      });
    } catch (error) {
      return mapCaught(error);
    }
  }

  private async prepareBoundedBodyInsert(
    tx: PrismaClientLike,
    command: OsvCanaryAuthorizationEnsureCommand,
    now: Date,
  ): Promise<OsvCanaryAuthorizationResult<{ readonly listingRequestId: string }>> {
    const review = command.listingReviewEvidence;
    const bodyLegal = command.bodyLegalDecisionReference;
    if (review === null || bodyLegal === null) {
      return fail('listing_review_required');
    }
    if (Date.parse(bodyLegal.issuedAt) > now.getTime()) {
      return fail('invalid_timestamp');
    }
    if (databaseNowIsExpired(toIsoUtc(now), bodyLegal.revalidationBoundaryAt)) {
      return fail('legal_gate_blocked');
    }
    if (Date.parse(review.reviewedAt) > now.getTime()) {
      return fail('invalid_timestamp');
    }
    const listing = await loadAuthorization(tx, review.listingAuthorizationId);
    if (listing === null) {
      return fail('listing_review_mismatch');
    }
    if (listing.phase !== 'listing_only' || listing.state !== 'completed') {
      return fail('listing_review_not_accepted');
    }
    if (
      listing.consumedBySynchronizationRunId !== review.listingRunId ||
      listing.consumedBySynchronizationRequestId === null ||
      listing.runtimeVersionSetFingerprint !== review.runtimeVersionSetFingerprint ||
      listing.providerPrefix !== review.providerPrefix ||
      listing.canaryPolicyIdentifier !== review.canaryPolicyIdentifier
    ) {
      return fail('listing_review_mismatch');
    }
    if (
      listing.terminalAt !== null &&
      Date.parse(review.reviewedAt) < listing.terminalAt.getTime()
    ) {
      return fail('listing_review_mismatch');
    }
    return {
      ok: true,
      value: { listingRequestId: listing.consumedBySynchronizationRequestId },
    };
  }

  private async insertAuthorization(
    tx: PrismaClientLike,
    command: OsvCanaryAuthorizationEnsureCommand,
    listingRequestId: string | null,
  ): Promise<OsvCanaryAuthorizationResult<OsvCanaryAuthorizationEnsureResult>> {
    const budget = command.phase === 'listing_only' ? LISTING_BUDGET : BODY_BUDGET;
    const review = command.listingReviewEvidence;
    const bodyLegal = command.bodyLegalDecisionReference;
    const inserted = await tx.$queryRaw<unknown[]>`
      INSERT INTO "osv_canary_authorization" (
        "id",
        "operator_identity_id",
        "authorization_schema_version",
        "canary_architecture_identifier",
        "runtime_architecture_identifier",
        "listing_protocol_identifier",
        "actor_kind",
        "phase",
        "synchronization_reason",
        "authorization_purpose",
        "provider_prefix",
        "source_identifier",
        "family",
        "canary_policy_identifier",
        "work_scope",
        "lease_scope",
        "runtime_version_set_fingerprint",
        "budget_profile_identifier",
        "unused_ttl_seconds",
        "single_use_policy",
        "catalog_activation_authorization",
        "matching_authorization",
        "finding_authorization",
        "postcanary_review_requirement",
        "legal_decision_reference_identifier",
        "legal_decision_id",
        "legal_decision_source_registry_version",
        "legal_decision_phase",
        "legal_decision_permitted_operation",
        "legal_decision_state",
        "legal_decision_issuance",
        "legal_decision_issued_at",
        "legal_decision_revalidation_boundary_at",
        "legal_decision_responsible_role",
        "legal_decision_evidence_set_id",
        "body_legal_decision_id",
        "body_legal_decision_phase",
        "body_legal_decision_permitted_operation",
        "body_legal_decision_issued_at",
        "body_legal_decision_revalidation_boundary_at",
        "body_legal_decision_evidence_set_id",
        "body_retrieve_disposition",
        "body_transient_inspection_disposition",
        "body_private_retention_disposition",
        "body_parse_disposition",
        "body_external_exposure_disposition",
        "body_matching_disposition",
        "listing_review_evidence_identifier",
        "listing_review_id",
        "listing_authorization_id",
        "listing_request_id",
        "listing_run_id",
        "listing_canonical_inventory_evidence_id",
        "listing_review_verdict",
        "listing_reviewed_at",
        "listing_reviewer_role",
        "body_selection_algorithm_identifier",
        "runbook_set_identifier",
        "runbook_version",
        "runbook_acknowledged_at",
        "runbook_emergency_halt_procedure",
        "halt_acknowledgement_identifier",
        "halt_acknowledged_at",
        "activation_prohibition_identifier",
        "retry_prohibition_identifier",
        "issued_at",
        "expires_at",
        "state",
        "created_at"
      )
      VALUES (
        ${command.authorizationId}::uuid,
        ${command.operatorAttestationId}::uuid,
        'osv_canary_execution_authorization_record_v1',
        'osv_first_real_provider_canary_authorization_v1',
        'osv_runtime_enablement_architecture_v1',
        'osv_gcs_json_objects_list_v1',
        'instance_operator',
        ${command.phase}::"osv_canary_phase",
        'operator_canary'::"osv_runtime_synchronization_reason",
        ${command.authorizationPurpose}::"osv_canary_authorization_purpose",
        'crates.io/',
        'rustsec_advisory_database',
        'RUSTSEC',
        'osv_disabled_first_provider_canary_policy_v1',
        'osv_runtime_canary_scope_crates_io_rustsec_v1'::"osv_runtime_work_scope",
        'osv_runtime_lease_scope_osv_gcs_public_export_v1',
        ${FINGERPRINT},
        ${budget},
        3600,
        'single_use',
        'prohibited',
        'prohibited',
        'prohibited',
        'required',
        'osv_canary_legal_decision_reference_v1',
        ${command.legalDecisionReference.decisionId}::uuid,
        'osv_source_license_registry_v1',
        'listing_only'::"osv_canary_phase",
        'list_object_metadata'::"osv_canary_legal_permitted_operation",
        'recorded_reference_not_execution_authority',
        'blocking_preexecution_dependency_not_issued_in_batch_2a',
        ${new Date(command.legalDecisionReference.issuedAt)},
        ${new Date(command.legalDecisionReference.revalidationBoundaryAt)},
        'instance_legal_and_provenance_reviewer_countersigned_by_instance_operator',
        ${command.legalDecisionReference.evidenceSetId}::uuid,
        ${sqlUuid(bodyLegal?.decisionId ?? null)},
        ${sqlPhase(bodyLegal?.phase ?? null)},
        ${sqlLegalOperation(bodyLegal?.permittedOperation ?? null)},
        ${sqlTimestamp(bodyLegal === null ? null : new Date(bodyLegal.issuedAt))},
        ${sqlTimestamp(bodyLegal === null ? null : new Date(bodyLegal.revalidationBoundaryAt))},
        ${sqlUuid(bodyLegal?.evidenceSetId ?? null)},
        ${sqlText(bodyLegal === null ? null : 'required_current_before_bounded_body')},
        ${sqlText(bodyLegal === null ? null : 'permitted_for_license_evaluation_only')},
        ${sqlText(bodyLegal === null ? null : 'reject_body_retrieval_until_retention_resolved')},
        ${sqlText(bodyLegal === null ? null : 'license_inspection_only_before_retention')},
        ${sqlText(bodyLegal === null ? null : 'forbidden')},
        ${sqlText(bodyLegal === null ? null : 'forbidden')},
        ${sqlText(review === null ? null : 'osv_canary_listing_review_evidence_v1')},
        ${sqlUuid(review?.reviewId ?? null)},
        ${sqlUuid(review?.listingAuthorizationId ?? null)},
        ${sqlUuid(listingRequestId)},
        ${sqlUuid(review?.listingRunId ?? null)},
        ${sqlUuid(review?.canonicalInventoryEvidenceId ?? null)},
        ${sqlListingVerdict(review?.verdict ?? null)},
        ${
          review === null
            ? Prisma.sql`NULL::timestamptz`
            : Prisma.sql`GREATEST(
                (
                  SELECT listing."terminal_at"
                  FROM "osv_canary_authorization" AS listing
                  WHERE listing."id" = ${review.listingAuthorizationId}::uuid
                ),
                ${new Date(review.reviewedAt)}::timestamptz
              )`
        },
        ${sqlText(review?.reviewerRole ?? null)},
        ${sqlText(review === null ? null : 'osv_canary_bounded_body_selection_v1')},
        'osv_canary_runbook_set_v1',
        'osv_canary_runbook_outlines_v1',
        ${new Date(command.runbookAcknowledgement.acknowledgedAt)},
        'stop_next_protected_stage_production_remains_halted',
        'osv_canary_halt_control_acknowledgement_v1',
        ${new Date(command.haltControlAcknowledgement.acknowledgedAt)},
        'osv_canary_activation_prohibition_v1',
        'osv_canary_automatic_retry_prohibition_v1',
        CURRENT_TIMESTAMP,
        CURRENT_TIMESTAMP + INTERVAL '3600 seconds',
        'issued',
        CURRENT_TIMESTAMP
      )
      ON CONFLICT ("id") DO NOTHING
      RETURNING *
    `;
    const created = firstRow(inserted, coerceAuthorizationRow);
    if (created !== undefined) {
      return {
        ok: true,
        value: {
          status: 'created',
          authorization: await mapLoadedAuthorization(tx, created),
        },
      };
    }
    return this.reloadEnsure(tx, command);
  }

  private async reloadEnsure(
    client: PrismaClientLike,
    command: OsvCanaryAuthorizationEnsureCommand,
  ): Promise<OsvCanaryAuthorizationResult<OsvCanaryAuthorizationEnsureResult>> {
    const existing = await loadAuthorization(client, command.authorizationId);
    if (existing === null) {
      return fail('not_found');
    }
    const mapped = await mapLoadedAuthorization(client, existing);
    if (compareOsvCanaryPersistedAuthorization(mapped, command) === 'immutable_conflict') {
      return fail('immutable_conflict');
    }
    return { ok: true, value: { status: 'already_applied', authorization: mapped } };
  }

  private async reloadConsume(
    tx: PrismaClientLike,
    command: OsvCanaryAuthorizationConsumePersistenceCommand,
  ): Promise<OsvCanaryAuthorizationResult<OsvCanaryAuthorizationConsumePersistenceResult>> {
    const existing = await loadAuthorization(tx, command.authorizationId);
    if (existing === null) {
      return fail('not_found');
    }
    const mapped = await mapLoadedAuthorization(tx, existing);
    const now = await observeDatabaseNow(tx);
    if (existing.state === 'consumed') {
      return consumeReplayOutcome(existing, mapped, command);
    }
    const operator = await loadOperator(tx, existing.operatorIdentityId);
    if (existing.state === 'issued' && operator !== null && operator.status === 'revoked') {
      return fail('operator_revoked');
    }
    if (existing.state === 'expired') {
      return { ok: true, value: { outcome: 'expired', authorization: mapped } };
    }
    if (existing.state === 'revoked') {
      return { ok: true, value: { outcome: 'revoked', authorization: mapped } };
    }
    if (existing.state === 'cancelled') {
      return { ok: true, value: { outcome: 'cancelled', authorization: mapped } };
    }
    if (existing.state === 'completed' || existing.state === 'failed') {
      return { ok: true, value: { outcome: 'terminal', authorization: mapped } };
    }
    if (databaseNowIsExpired(toIsoUtc(now), toIsoUtc(existing.expiresAt))) {
      return { ok: true, value: { outcome: 'expired', authorization: mapped } };
    }
    if (
      databaseNowIsExpired(toIsoUtc(now), toIsoUtc(existing.legalDecisionRevalidationBoundaryAt)) ||
      (existing.bodyLegalDecisionRevalidationBoundaryAt !== null &&
        databaseNowIsExpired(
          toIsoUtc(now),
          toIsoUtc(existing.bodyLegalDecisionRevalidationBoundaryAt),
        ))
    ) {
      return { ok: true, value: { outcome: 'legal_gate_blocked', authorization: mapped } };
    }
    if (
      existing.phase !== command.phase ||
      existing.providerPrefix !== command.providerPrefix ||
      existing.canaryPolicyIdentifier !== command.canaryPolicyIdentifier ||
      existing.runtimeVersionSetFingerprint !== command.runtimeVersionSetFingerprint
    ) {
      return { ok: true, value: { outcome: 'policy_mismatch', authorization: mapped } };
    }
    if (existing.operatorIdentityId !== command.operatorAttestationId) {
      return { ok: true, value: { outcome: 'identity_mismatch', authorization: mapped } };
    }
    return fail('state_conflict');
  }

  private async reloadRevoke(
    tx: PrismaClientLike,
    command: OsvCanaryAuthorizationRevokeCommand,
  ): Promise<OsvCanaryAuthorizationResult<OsvCanaryAuthorizationMutationResult>> {
    const existing = await loadAuthorization(tx, command.authorizationId);
    if (existing === null) {
      return fail('not_found');
    }
    const mapped = await mapLoadedAuthorization(tx, existing);
    if (
      existing.state === 'revoked' &&
      existing.revokedByOperatorIdentityId === command.operatorAttestationId
    ) {
      return { ok: true, value: { status: 'already_applied', authorization: mapped } };
    }
    if (existing.state === 'expired') {
      return fail('state_conflict');
    }
    if (existing.operatorIdentityId !== command.operatorAttestationId) {
      return fail('identity_mismatch');
    }
    return fail('state_conflict');
  }

  private async reloadCancel(
    tx: PrismaClientLike,
    command: OsvCanaryAuthorizationCancelCommand,
  ): Promise<OsvCanaryAuthorizationResult<OsvCanaryAuthorizationMutationResult>> {
    const existing = await loadAuthorization(tx, command.authorizationId);
    if (existing === null) {
      return fail('not_found');
    }
    const mapped = await mapLoadedAuthorization(tx, existing);
    if (existing.state === 'cancelled') {
      return { ok: true, value: { status: 'already_applied', authorization: mapped } };
    }
    if (existing.operatorIdentityId !== command.operatorAttestationId) {
      return fail('identity_mismatch');
    }
    return fail('state_conflict');
  }

  private async reloadExpire(
    tx: PrismaClientLike,
    command: OsvCanaryAuthorizationExpireCommand,
  ): Promise<OsvCanaryAuthorizationResult<OsvCanaryAuthorizationMutationResult>> {
    const existing = await loadAuthorization(tx, command.authorizationId);
    if (existing === null) {
      return fail('not_found');
    }
    const mapped = await mapLoadedAuthorization(tx, existing);
    if (existing.state === 'expired') {
      return { ok: true, value: { status: 'already_applied', authorization: mapped } };
    }
    if (existing.state === 'consumed') {
      return fail('state_conflict');
    }
    const now = await observeDatabaseNow(tx);
    if (!databaseNowIsExpired(toIsoUtc(now), toIsoUtc(existing.expiresAt))) {
      return fail('state_conflict');
    }
    return fail('state_conflict');
  }

  private async reloadTerminal(
    tx: PrismaClientLike,
    command: OsvCanaryAuthorizationTerminalCommand,
  ): Promise<OsvCanaryAuthorizationResult<OsvCanaryAuthorizationMutationResult>> {
    const existing = await loadAuthorization(tx, command.authorizationId);
    if (existing === null) {
      return fail('not_found');
    }
    const mapped = await mapLoadedAuthorization(tx, existing);
    if (
      existing.state === command.disposition &&
      existing.terminalDisposition === command.disposition &&
      existing.terminalReasonCode === command.terminalReasonCode &&
      existing.consumedBySynchronizationRequestId === command.requestId &&
      existing.consumedBySynchronizationRunId === command.runId
    ) {
      return { ok: true, value: { status: 'already_applied', authorization: mapped } };
    }
    if (
      existing.state === 'completed' ||
      existing.state === 'failed' ||
      existing.state === 'cancelled'
    ) {
      return fail('immutable_conflict');
    }
    return fail('state_conflict');
  }
}
