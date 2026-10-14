/**
 * PostgreSQL instance advisory authority persistence.
 * Test reachable only. No deployment-local command, route, or package barrel.
 *
 * Lock order for grant, revoke, disable, and enable:
 * 1. Validate the strict command.
 * 2. Enable one purpose-specific transaction-local setting.
 * 3. Lock the target User.
 * 4. Lock that user's grant rows in id order.
 * 5. Classify replay, conflict, or a single mutation.
 * 6. Apply at most one mutation.
 * 7. Insert one audit event when the mutation is new.
 * 8. Validate stored state.
 * 9. Commit.
 *
 * Session rows are not rewritten. ADR 0019 invalidates sessions at request
 * time when User.status is disabled. Re-enablement does not restore a revoked
 * or expired session and does not revoke a live one.
 */

import { Prisma, type PrismaClient } from '@prisma/client';
import {
  INSTANCE_ADVISORY_AUDIT_ACTIONS,
  INSTANCE_ADVISORY_AUTHORIZATION_FACTS_SCHEMA_VERSION,
  INSTANCE_ADVISORY_AUTHORITY_SNAPSHOT_SCHEMA_VERSION,
  classifyInstanceAdvisoryAuthorityCommand,
  classifyInstanceAdvisoryAuthorization,
  classifyInstanceAdvisoryConcurrentGrantReread,
  classifyInstanceAdvisoryConcurrentRevocationReread,
  instanceAdvisoryAuditIntent,
  isCanonicalInstanceAdvisoryPrincipalId,
  isInstanceAdvisoryAuthority,
  isInstanceAdvisoryIssuanceClassification,
  parseInstanceAdvisoryAuthorizationReadRequest,
  parseInstanceAdvisoryAuthorityCommand,
  type InstanceAdvisoryAuditIntent,
  type InstanceAdvisoryAuthorizationFacts,
  type InstanceAdvisoryAuthorizationReadPort,
  type InstanceAdvisoryAuthorizationReadRequest,
  type InstanceAdvisoryAuthorizationReadResult,
  type InstanceAdvisoryAuthorityCommand,
  type InstanceAdvisoryAuthorityCommandPort,
  type InstanceAdvisoryAuthorityCommandResult,
  type InstanceAdvisoryAuthoritySnapshot,
  type InstanceAdvisoryRevokedGrantFact,
} from '@patchpilot/domain/instance-advisory-authority';

const GRANT_SETTING = 'patchpilot.instance_advisory_authority_grant';
const USER_STATUS_SETTING = 'patchpilot.instance_advisory_user_status';

export const INSTANCE_ADVISORY_AUTHORITY_LOCK_ORDER = [
  'validate_command',
  'enable_transaction_local_setting',
  'lock_target_user',
  'lock_grant_rows',
  'classify',
  'apply_one_mutation',
  'insert_audit',
  'validate_stored_state',
  'commit',
] as const;

export const INSTANCE_ADVISORY_AUTHORITY_PERSISTENCE_FAULTS = [
  'before_user_lock',
  'before_active_grant_load',
  'before_grant_insert',
  'before_revocation_update',
  'before_user_status_update',
  'before_audit_insert',
  'before_stored_state_validation',
  'skip_audit_insert',
] as const;

export type InstanceAdvisoryAuthorityPersistenceFault =
  (typeof INSTANCE_ADVISORY_AUTHORITY_PERSISTENCE_FAULTS)[number];

export type InstanceAdvisoryAuthorityPersistenceOptions = {
  readonly fault?: InstanceAdvisoryAuthorityPersistenceFault;
};

type CommandFailure = Exclude<
  InstanceAdvisoryAuthorityCommandResult,
  { readonly outcome: 'granted' | 'revoked' }
>;

type PersistenceFailure =
  | 'active_grant_unique'
  | 'concurrency_conflict'
  | 'transaction_aborted'
  | 'database_unavailable'
  | 'internal_failure';

class PersistenceStop extends Error {
  constructor(readonly outcome: 'transaction_aborted' | 'internal_failure') {
    super('instance advisory authority persistence stopped');
  }
}

type UserImage = {
  id: string;
  status: string;
  email: string;
  display_name: string;
  version: number;
  disabled_at: Date | null;
};

type GrantImage = {
  id: string;
  user_id: string;
  authority: string;
  issuance_classification: string;
  command_correlation_id: string;
  active: boolean;
};

/**
 * Rows written by this transaction. Global table counts are not used: under
 * Read Committed those counts change when another transaction commits.
 */
type TransactionWrites = {
  organizations: number;
  memberships: number;
  advisory_revisions: number;
  advisory_bindings: number;
  advisory_approvals: number;
  capabilities: number;
  product_match: number;
  findings: number;
  observations: number;
  sessions: number;
  other_users: number;
  target_user: number;
};

type LoadedState = {
  user: UserImage | null;
  grants: readonly GrantImage[];
  snapshot: InstanceAdvisoryAuthoritySnapshot;
};

export type InstanceAdvisoryAuthorityPersistence = {
  execute(
    command: InstanceAdvisoryAuthorityCommand,
    options?: InstanceAdvisoryAuthorityPersistenceOptions,
  ): Promise<InstanceAdvisoryAuthorityCommandResult>;
};

export function createInstanceAdvisoryAuthorityPersistence(
  client: PrismaClient,
): InstanceAdvisoryAuthorityPersistence {
  return {
    async execute(
      command: InstanceAdvisoryAuthorityCommand,
      options?: InstanceAdvisoryAuthorityPersistenceOptions,
    ): Promise<InstanceAdvisoryAuthorityCommandResult> {
      const parsed = parseInstanceAdvisoryAuthorityCommand(command);
      if (!parsed.ok) {
        return { outcome: 'invalid_command' };
      }
      try {
        return await client.$transaction((tx) =>
          applyInTransaction(tx, parsed.command, options?.fault),
        );
      } catch (error) {
        if (error instanceof PersistenceStop) {
          return { outcome: error.outcome };
        }
        const failure = classifyInstanceAdvisoryPersistenceFailure(error);
        if (failure === 'active_grant_unique' && parsed.command.operation === 'grant') {
          return rereadConcurrentGrant(client, parsed.command);
        }
        if (failure === 'active_grant_unique') {
          return { outcome: 'concurrency_conflict' };
        }
        return { outcome: failure };
      }
    },
  };
}

export function createInstanceAdvisoryAuthorizationRead(
  client: PrismaClient,
): InstanceAdvisoryAuthorizationReadPort {
  return {
    async readRequiredAuthority(
      request: InstanceAdvisoryAuthorizationReadRequest,
    ): Promise<InstanceAdvisoryAuthorizationReadResult> {
      const parsed = parseInstanceAdvisoryAuthorizationReadRequest(request);
      if (!parsed.ok) {
        return { outcome: 'internal_failure' };
      }
      try {
        const facts = await client.$transaction(async (tx) => {
          await tx.$queryRaw`SELECT set_config('transaction_read_only', 'on', true)`;
          await tx.$queryRaw`SELECT set_config('statement_timeout', '2000', true)`;
          return loadAuthorizationFacts(tx, parsed.request.userId, false);
        });
        return {
          outcome: classifyInstanceAdvisoryAuthorization(facts, parsed.request),
        };
      } catch (error) {
        const failure = classifyInstanceAdvisoryPersistenceFailure(error);
        if (failure === 'database_unavailable') {
          return { outcome: 'database_unavailable' };
        }
        return { outcome: 'internal_failure' };
      }
    },
  };
}

/**
 * Reloads user activity and the active grant inside the caller's transaction.
 * Later submission and approval transactions call this. It does not write and
 * does not accept a transaction callback from domain code.
 */
export async function reloadInstanceAdvisoryAuthorizationFacts(
  tx: Prisma.TransactionClient,
  request: InstanceAdvisoryAuthorizationReadRequest,
): Promise<InstanceAdvisoryAuthorizationFacts> {
  const parsed = parseInstanceAdvisoryAuthorizationReadRequest(request);
  if (!parsed.ok) {
    return unavailableFacts(request.userId, 'internal_failure');
  }
  return loadAuthorizationFacts(tx, parsed.request.userId, true);
}

export function classifyInstanceAdvisoryPersistenceFailure(error: unknown): PersistenceFailure {
  if (sqlState(error) === '23505' && errorText(error).includes(ACTIVE_GRANT_INDEX)) {
    return 'active_grant_unique';
  }
  const state = sqlState(error);
  if (state === '40001' || state === '40P01' || state === '55P03') {
    return 'concurrency_conflict';
  }
  if (
    state === '23505' ||
    state === '23514' ||
    state === '23503' ||
    state === '23502' ||
    state === '42501' ||
    state === '23001' ||
    state === '22P02' ||
    state === '22023'
  ) {
    return 'transaction_aborted';
  }
  if (isDatabaseUnavailable(error)) {
    return 'database_unavailable';
  }
  if (
    error instanceof Prisma.PrismaClientUnknownRequestError &&
    error.message.includes('Error querying the database: ERROR:')
  ) {
    return 'transaction_aborted';
  }
  if (error instanceof Prisma.PrismaClientKnownRequestError) {
    if (error.code === 'P2028' || error.code === 'P2034') {
      return 'transaction_aborted';
    }
    if (error.code === 'P2002' || error.code === 'P2003' || error.code === 'P2010') {
      return 'transaction_aborted';
    }
  }
  return 'internal_failure';
}

const ACTIVE_GRANT_INDEX = 'instance_advisory_authority_grant_one_active_user_idx';

async function applyInTransaction(
  tx: Prisma.TransactionClient,
  command: InstanceAdvisoryAuthorityCommand,
  fault: InstanceAdvisoryAuthorityPersistenceFault | undefined,
): Promise<InstanceAdvisoryAuthorityCommandResult> {
  const setting =
    command.operation === 'grant' || command.operation === 'revoke'
      ? GRANT_SETTING
      : USER_STATUS_SETTING;
  await tx.$queryRaw`
    SELECT set_config(${setting}, 'on', true) AS configured
  `;
  throwFault(fault, 'before_user_lock');
  const loaded = await loadState(tx, command.targetUserId, fault);
  if (loaded === 'absent_user') {
    return finishRead(tx, command, absentSnapshot(command.targetUserId));
  }
  const decision = classifyInstanceAdvisoryAuthorityCommand(command, loaded.snapshot);
  if (decision.write.kind === 'none') {
    return finishRead(tx, command, loaded.snapshot);
  }
  if (decision.outcome === 'granted' && command.operation === 'grant') {
    return insertGrant(tx, command, loaded, decision, fault);
  }
  if (decision.outcome === 'revoked' && command.operation === 'revoke') {
    return revokeGrant(tx, command, loaded, decision, fault);
  }
  if (decision.outcome === 'user_disabled' && command.operation === 'disable_user') {
    return updateUserStatus(tx, command, loaded, 'disabled', fault);
  }
  if (decision.outcome === 'user_enabled' && command.operation === 'enable_user') {
    return updateUserStatus(tx, command, loaded, 'active', fault);
  }
  throw new PersistenceStop('internal_failure');
}

async function insertGrant(
  tx: Prisma.TransactionClient,
  command: Extract<InstanceAdvisoryAuthorityCommand, { readonly operation: 'grant' }>,
  loaded: LoadedState,
  decision: ReturnType<typeof classifyInstanceAdvisoryAuthorityCommand>,
  fault: InstanceAdvisoryAuthorityPersistenceFault | undefined,
): Promise<InstanceAdvisoryAuthorityCommandResult> {
  throwFault(fault, 'before_grant_insert');
  const inserted = await tx.$queryRaw<Array<{ id: string }>>`
    INSERT INTO "instance_advisory_authority_grant" (
      "user_id",
      "authority",
      "issuance_classification",
      "issued_at",
      "revoked_at",
      "command_correlation_id"
    ) VALUES (
      ${command.targetUserId}::uuid,
      ${command.authority}::"instance_advisory_authority",
      ${command.issuanceClassification}::"instance_advisory_issuance_classification",
      CURRENT_TIMESTAMP,
      NULL,
      ${command.correlationId}::uuid
    )
    RETURNING "id"::text AS id
  `;
  const grantId = inserted[0]?.id;
  if (inserted.length !== 1 || !isCanonicalInstanceAdvisoryPrincipalId(grantId)) {
    throw new PersistenceStop('transaction_aborted');
  }
  const intent = instanceAdvisoryAuditIntent({
    decision,
    command,
    subjectId: grantId,
    authority: command.authority,
  });
  if (intent === null) {
    throw new PersistenceStop('internal_failure');
  }
  await writeAudit(tx, intent, fault);
  throwFault(fault, 'before_stored_state_validation');
  if (fault !== 'skip_audit_insert') {
    await assertGrantInserted(tx, command, loaded, grantId);
  }
  return { outcome: 'granted', grantId };
}

async function revokeGrant(
  tx: Prisma.TransactionClient,
  command: Extract<InstanceAdvisoryAuthorityCommand, { readonly operation: 'revoke' }>,
  loaded: LoadedState,
  decision: ReturnType<typeof classifyInstanceAdvisoryAuthorityCommand>,
  fault: InstanceAdvisoryAuthorityPersistenceFault | undefined,
): Promise<InstanceAdvisoryAuthorityCommandResult> {
  const intent = instanceAdvisoryAuditIntent({
    decision,
    command,
    subjectId: command.expectedGrantId,
    authority: command.expectedAuthority,
  });
  if (intent === null) {
    throw new PersistenceStop('internal_failure');
  }
  throwFault(fault, 'before_revocation_update');
  const updated = await tx.$executeRaw`
    UPDATE "instance_advisory_authority_grant"
    SET "revoked_at" = CURRENT_TIMESTAMP
    WHERE "id" = ${command.expectedGrantId}::uuid
      AND "user_id" = ${command.targetUserId}::uuid
      AND "authority" = ${command.expectedAuthority}::"instance_advisory_authority"
      AND "revoked_at" IS NULL
  `;
  if (Number(updated) !== 1) {
    const reread = await loadState(tx, command.targetUserId, undefined);
    if (reread === 'absent_user') {
      return { outcome: 'concurrency_conflict' };
    }
    const again = classifyInstanceAdvisoryConcurrentRevocationReread(command, reread.snapshot);
    if (again.write.kind !== 'none' || again.outcome === 'revoked' || again.outcome === 'granted') {
      return { outcome: 'concurrency_conflict' };
    }
    return { outcome: again.outcome };
  }
  await writeAudit(tx, intent, fault);
  throwFault(fault, 'before_stored_state_validation');
  if (fault !== 'skip_audit_insert') {
    await assertGrantRevoked(tx, command, loaded);
  }
  return { outcome: 'revoked', grantId: command.expectedGrantId };
}

async function updateUserStatus(
  tx: Prisma.TransactionClient,
  command: Extract<
    InstanceAdvisoryAuthorityCommand,
    { readonly operation: 'disable_user' | 'enable_user' }
  >,
  loaded: LoadedState,
  nextStatus: 'disabled' | 'active',
  fault: InstanceAdvisoryAuthorityPersistenceFault | undefined,
): Promise<InstanceAdvisoryAuthorityCommandResult> {
  const user = loaded.user;
  if (user === null) {
    throw new PersistenceStop('internal_failure');
  }
  const decision = classifyInstanceAdvisoryAuthorityCommand(command, loaded.snapshot);
  const intent = instanceAdvisoryAuditIntent({
    decision,
    command,
    subjectId: command.targetUserId,
    authority: null,
  });
  if (intent === null || decision.auditEvents !== 1) {
    throw new PersistenceStop('internal_failure');
  }
  throwFault(fault, 'before_user_status_update');
  const updated =
    nextStatus === 'disabled'
      ? await tx.$executeRaw`
          UPDATE "user"
          SET "status" = 'disabled'::"user_status",
              "disabled_at" = CURRENT_TIMESTAMP,
              "updated_at" = CURRENT_TIMESTAMP,
              "version" = "version" + 1
          WHERE "id" = ${command.targetUserId}::uuid
            AND "status" = 'active'::"user_status"
            AND "disabled_at" IS NULL
        `
      : await tx.$executeRaw`
          UPDATE "user"
          SET "status" = 'active'::"user_status",
              "disabled_at" = NULL,
              "updated_at" = CURRENT_TIMESTAMP,
              "version" = "version" + 1
          WHERE "id" = ${command.targetUserId}::uuid
            AND "status" = 'disabled'::"user_status"
            AND "disabled_at" IS NOT NULL
        `;
  if (Number(updated) !== 1) {
    return { outcome: 'concurrency_conflict' };
  }
  await writeAudit(tx, intent, fault);
  throwFault(fault, 'before_stored_state_validation');
  if (fault !== 'skip_audit_insert') {
    await assertUserStatus(tx, command, loaded, nextStatus, intent.action);
  }
  return { outcome: nextStatus === 'disabled' ? 'user_disabled' : 'user_enabled' };
}

async function writeAudit(
  tx: Prisma.TransactionClient,
  intent: InstanceAdvisoryAuditIntent,
  fault: InstanceAdvisoryAuthorityPersistenceFault | undefined,
): Promise<void> {
  if (fault === 'skip_audit_insert') {
    return;
  }
  throwFault(fault, 'before_audit_insert');
  const payload = JSON.stringify(intent.payload);
  const inserted = await tx.$queryRaw<Array<{ id: string }>>`
    INSERT INTO "audit_event" (
      "organization_id",
      "actor_user_id",
      "actor_membership_id",
      "actor_type",
      "action",
      "subject_type",
      "subject_id",
      "occurred_at",
      "correlation_id",
      "payload",
      "schema_version",
      "retention_category"
    ) VALUES (
      NULL,
      NULL,
      NULL,
      'system'::"audit_actor_type",
      ${intent.action},
      ${intent.subjectType},
      ${intent.subjectId}::uuid,
      CURRENT_TIMESTAMP,
      ${intent.correlationId},
      ${payload}::jsonb,
      1,
      'security'::"audit_retention_category"
    )
    RETURNING "id"::text AS id
  `;
  if (inserted.length !== 1) {
    throw new PersistenceStop('transaction_aborted');
  }
}

async function finishRead(
  tx: Prisma.TransactionClient,
  command: InstanceAdvisoryAuthorityCommand,
  snapshot: InstanceAdvisoryAuthoritySnapshot,
): Promise<CommandFailure> {
  await assertNoCollateralWrites(tx, command.targetUserId, 0);
  const decision = classifyInstanceAdvisoryAuthorityCommand(command, snapshot);
  if (decision.write.kind !== 'none' || decision.auditEvents !== 0) {
    throw new PersistenceStop('internal_failure');
  }
  if (decision.outcome === 'granted' || decision.outcome === 'revoked') {
    throw new PersistenceStop('internal_failure');
  }
  return { outcome: decision.outcome };
}

async function loadState(
  tx: Prisma.TransactionClient,
  userId: string,
  fault: InstanceAdvisoryAuthorityPersistenceFault | undefined,
): Promise<LoadedState | 'absent_user'> {
  const users = await tx.$queryRaw<UserImage[]>`
    SELECT
      "id"::text AS id,
      "status"::text AS status,
      "email",
      "display_name",
      "version",
      "disabled_at"
    FROM "user"
    WHERE "id" = ${userId}::uuid
    FOR UPDATE
  `;
  const user = users[0];
  if (users.length === 0 || user === undefined) {
    return 'absent_user';
  }
  user.version = Number(user.version);
  if (users.length !== 1) {
    throw new PersistenceStop('internal_failure');
  }
  throwFault(fault, 'before_active_grant_load');
  const grants = await tx.$queryRaw<GrantImage[]>`
    SELECT
      "id"::text AS id,
      "user_id"::text AS user_id,
      "authority"::text AS authority,
      "issuance_classification"::text AS issuance_classification,
      "command_correlation_id"::text AS command_correlation_id,
      ("revoked_at" IS NULL) AS active
    FROM "instance_advisory_authority_grant"
    WHERE "user_id" = ${userId}::uuid
    ORDER BY "id"
    FOR UPDATE
  `;
  return {
    user,
    grants,
    snapshot: snapshotFrom(userId, user, grants),
  };
}

function snapshotFrom(
  userId: string,
  user: UserImage,
  grants: readonly GrantImage[],
): InstanceAdvisoryAuthoritySnapshot {
  const activeRows = grants.filter((grant) => grant.active);
  const revokedRows = grants.filter((grant) => !grant.active);
  let malformed =
    user.id !== userId ||
    (user.status !== 'active' && user.status !== 'disabled') ||
    activeRows.length > 1;
  const activeGrant = activeRows.length === 1 ? toActiveFact(activeRows[0], userId) : null;
  if (activeRows.length === 1 && activeGrant === null) {
    malformed = true;
  }
  const revokedGrants: InstanceAdvisoryRevokedGrantFact[] = [];
  for (const grant of revokedRows) {
    const fact = toRevokedFact(grant, userId);
    if (fact === null) {
      malformed = true;
      continue;
    }
    revokedGrants.push(fact);
  }
  if (malformed) {
    return {
      schemaVersion: INSTANCE_ADVISORY_AUTHORITY_SNAPSHOT_SCHEMA_VERSION,
      user:
        user.status === 'active' || user.status === 'disabled'
          ? { existence: 'present', status: user.status }
          : { existence: 'present', status: 'active' },
      activeGrant: null,
      revokedGrants: [],
      malformed: true,
    };
  }
  return {
    schemaVersion: INSTANCE_ADVISORY_AUTHORITY_SNAPSHOT_SCHEMA_VERSION,
    user: {
      existence: 'present',
      status: user.status === 'disabled' ? 'disabled' : 'active',
    },
    activeGrant,
    revokedGrants,
    malformed: false,
  };
}

function absentSnapshot(userId: string): InstanceAdvisoryAuthoritySnapshot {
  return {
    schemaVersion: INSTANCE_ADVISORY_AUTHORITY_SNAPSHOT_SCHEMA_VERSION,
    user: { existence: 'absent' },
    activeGrant: null,
    revokedGrants: [],
    malformed: !isCanonicalInstanceAdvisoryPrincipalId(userId),
  };
}

function toActiveFact(
  grant: GrantImage | undefined,
  userId: string,
): InstanceAdvisoryAuthoritySnapshot['activeGrant'] {
  if (grant === undefined || !grantIdentityTrusted(grant, userId) || !grant.active) {
    return null;
  }
  return {
    grantId: grant.id,
    userId: grant.user_id,
    authority: grant.authority,
    issuanceClassification: grant.issuance_classification,
    lifecycle: 'active',
  };
}

function toRevokedFact(grant: GrantImage, userId: string): InstanceAdvisoryRevokedGrantFact | null {
  if (!grantIdentityTrusted(grant, userId) || grant.active) {
    return null;
  }
  return {
    grantId: grant.id,
    userId: grant.user_id,
    authority: grant.authority,
    issuanceClassification: grant.issuance_classification,
    lifecycle: 'revoked',
  };
}

function grantIdentityTrusted(
  grant: GrantImage,
  userId: string,
): grant is GrantImage & {
  authority: 'advisory_submit_local' | 'advisory_approve_for_product_evaluation';
  issuance_classification: 'deployment_local_command';
} {
  return (
    isCanonicalInstanceAdvisoryPrincipalId(grant.id) &&
    grant.user_id === userId &&
    isInstanceAdvisoryAuthority(grant.authority) &&
    isInstanceAdvisoryIssuanceClassification(grant.issuance_classification) &&
    isCanonicalInstanceAdvisoryPrincipalId(grant.command_correlation_id)
  );
}

async function assertGrantInserted(
  tx: Prisma.TransactionClient,
  command: Extract<InstanceAdvisoryAuthorityCommand, { readonly operation: 'grant' }>,
  loaded: LoadedState,
  grantId: string,
): Promise<void> {
  const user = loaded.user;
  if (user === null) {
    throw new PersistenceStop('internal_failure');
  }
  const stored = await tx.$queryRaw<Array<{ ok: boolean; audits: number }>>`
    SELECT
      (
        SELECT COUNT(*)
        FROM "instance_advisory_authority_grant"
        WHERE "user_id" = ${command.targetUserId}::uuid
          AND "revoked_at" IS NULL
      ) = 1
      AND EXISTS (
        SELECT 1
        FROM "instance_advisory_authority_grant"
        WHERE "id" = ${grantId}::uuid
          AND "user_id" = ${command.targetUserId}::uuid
          AND "authority" = ${command.authority}::"instance_advisory_authority"
          AND "issuance_classification" = ${command.issuanceClassification}::"instance_advisory_issuance_classification"
          AND "command_correlation_id" = ${command.correlationId}::uuid
          AND "revoked_at" IS NULL
          AND "issued_at" IS NOT DISTINCT FROM CURRENT_TIMESTAMP
      ) AS ok,
      (
        SELECT COUNT(*)
        FROM "audit_event"
        WHERE "action" = ${INSTANCE_ADVISORY_AUDIT_ACTIONS.granted}
          AND "subject_type" = 'instance_advisory_authority_grant'
          AND "subject_id" = ${grantId}::uuid
          AND "correlation_id" = ${command.correlationId}
          AND "organization_id" IS NULL
          AND "actor_type" = 'system'
          AND "actor_user_id" IS NULL
          AND xmin = pg_current_xact_id()::xid
      )::int AS audits
  `;
  const row = stored[0];
  if (row === undefined || row.ok !== true || Number(row.audits) !== 1) {
    throw new PersistenceStop('transaction_aborted');
  }
  await assertUserUnchanged(tx, user);
  await assertNoCollateralWrites(tx, command.targetUserId, 0);
  await assertPriorGrantsRemain(tx, command.targetUserId, loaded.grants, grantId);
}

async function assertGrantRevoked(
  tx: Prisma.TransactionClient,
  command: Extract<InstanceAdvisoryAuthorityCommand, { readonly operation: 'revoke' }>,
  loaded: LoadedState,
): Promise<void> {
  const user = loaded.user;
  if (user === null) {
    throw new PersistenceStop('internal_failure');
  }
  const stored = await tx.$queryRaw<Array<{ ok: boolean; audits: number }>>`
    SELECT
      (
        SELECT COUNT(*)
        FROM "instance_advisory_authority_grant"
        WHERE "user_id" = ${command.targetUserId}::uuid
          AND "revoked_at" IS NULL
      ) = 0
      AND EXISTS (
        SELECT 1
        FROM "instance_advisory_authority_grant"
        WHERE "id" = ${command.expectedGrantId}::uuid
          AND "user_id" = ${command.targetUserId}::uuid
          AND "authority" = ${command.expectedAuthority}::"instance_advisory_authority"
          AND "revoked_at" IS NOT DISTINCT FROM CURRENT_TIMESTAMP
      ) AS ok,
      (
        SELECT COUNT(*)
        FROM "audit_event"
        WHERE "action" = ${INSTANCE_ADVISORY_AUDIT_ACTIONS.revoked}
          AND "subject_id" = ${command.expectedGrantId}::uuid
          AND "correlation_id" = ${command.correlationId}
          AND "organization_id" IS NULL
          AND xmin = pg_current_xact_id()::xid
      )::int AS audits
  `;
  const row = stored[0];
  if (row === undefined || row.ok !== true || Number(row.audits) !== 1) {
    throw new PersistenceStop('transaction_aborted');
  }
  await assertUserUnchanged(tx, user);
  await assertNoCollateralWrites(tx, command.targetUserId, 0);
}

async function assertUserStatus(
  tx: Prisma.TransactionClient,
  command: InstanceAdvisoryAuthorityCommand,
  loaded: LoadedState,
  nextStatus: 'disabled' | 'active',
  action: string,
): Promise<void> {
  const user = loaded.user;
  if (user === null) {
    throw new PersistenceStop('internal_failure');
  }
  const stored = await tx.$queryRaw<
    Array<{ email: string; display_name: string; version: number; audits: number; fresh: boolean }>
  >`
    SELECT
      account."email",
      account."display_name",
      account."version",
      (
        SELECT COUNT(*)
        FROM "audit_event"
        WHERE "action" = ${action}
          AND "subject_type" = 'user'
          AND "subject_id" = ${command.targetUserId}::uuid
          AND "correlation_id" = ${command.correlationId}
          AND "organization_id" IS NULL
          AND xmin = pg_current_xact_id()::xid
      )::int AS audits,
      (
        account."status"::text = ${nextStatus}
        AND account."updated_at" IS NOT DISTINCT FROM CURRENT_TIMESTAMP
        AND (
          (${nextStatus} = 'disabled' AND account."disabled_at" IS NOT DISTINCT FROM CURRENT_TIMESTAMP)
          OR (${nextStatus} = 'active' AND account."disabled_at" IS NULL)
        )
      ) AS fresh
    FROM "user" AS account
    WHERE account."id" = ${command.targetUserId}::uuid
  `;
  const row = stored[0];
  if (
    row === undefined ||
    row.fresh !== true ||
    Number(row.audits) !== 1 ||
    row.email !== user.email ||
    row.display_name !== user.display_name ||
    Number(row.version) !== user.version + 1
  ) {
    throw new PersistenceStop('transaction_aborted');
  }
  const grants = await tx.$queryRaw<GrantImage[]>`
    SELECT
      "id"::text AS id,
      "user_id"::text AS user_id,
      "authority"::text AS authority,
      "issuance_classification"::text AS issuance_classification,
      "command_correlation_id"::text AS command_correlation_id,
      ("revoked_at" IS NULL) AS active
    FROM "instance_advisory_authority_grant"
    WHERE "user_id" = ${command.targetUserId}::uuid
    ORDER BY "id"
  `;
  if (grantFingerprint(grants) !== grantFingerprint(loaded.grants)) {
    throw new PersistenceStop('transaction_aborted');
  }
  await assertNoCollateralWrites(tx, command.targetUserId, 1);
}

async function assertUserUnchanged(tx: Prisma.TransactionClient, user: UserImage): Promise<void> {
  const stored = await tx.$queryRaw<UserImage[]>`
    SELECT
      "id"::text AS id,
      "status"::text AS status,
      "email",
      "display_name",
      "version",
      "disabled_at"
    FROM "user"
    WHERE "id" = ${user.id}::uuid
  `;
  const row = stored[0];
  if (
    stored.length !== 1 ||
    row === undefined ||
    row.status !== user.status ||
    row.email !== user.email ||
    row.display_name !== user.display_name ||
    Number(row.version) !== user.version ||
    (row.disabled_at === null) !== (user.disabled_at === null)
  ) {
    throw new PersistenceStop('transaction_aborted');
  }
}

async function assertPriorGrantsRemain(
  tx: Prisma.TransactionClient,
  userId: string,
  prior: readonly GrantImage[],
  insertedId: string,
): Promise<void> {
  const grants = await tx.$queryRaw<GrantImage[]>`
    SELECT
      "id"::text AS id,
      "user_id"::text AS user_id,
      "authority"::text AS authority,
      "issuance_classification"::text AS issuance_classification,
      "command_correlation_id"::text AS command_correlation_id,
      ("revoked_at" IS NULL) AS active
    FROM "instance_advisory_authority_grant"
    WHERE "user_id" = ${userId}::uuid
      AND "id" <> ${insertedId}::uuid
    ORDER BY "id"
  `;
  if (grantFingerprint(grants) !== grantFingerprint(prior)) {
    throw new PersistenceStop('transaction_aborted');
  }
}

async function assertNoCollateralWrites(
  tx: Prisma.TransactionClient,
  targetUserId: string,
  allowedTargetUserWrites: 0 | 1,
): Promise<void> {
  const writes = await transactionWrites(tx, targetUserId);
  if (
    writes.organizations !== 0 ||
    writes.memberships !== 0 ||
    writes.advisory_revisions !== 0 ||
    writes.advisory_bindings !== 0 ||
    writes.advisory_approvals !== 0 ||
    writes.capabilities !== 0 ||
    writes.product_match !== 0 ||
    writes.findings !== 0 ||
    writes.observations !== 0 ||
    writes.sessions !== 0 ||
    writes.other_users !== 0 ||
    writes.target_user !== allowedTargetUserWrites
  ) {
    throw new PersistenceStop('transaction_aborted');
  }
}

async function transactionWrites(
  tx: Prisma.TransactionClient,
  targetUserId: string,
): Promise<TransactionWrites> {
  const rows = await tx.$queryRaw<TransactionWrites[]>`
    SELECT
      (SELECT COUNT(*) FROM "organization" WHERE xmin = pg_current_xact_id()::xid)::int AS organizations,
      (SELECT COUNT(*) FROM "membership" WHERE xmin = pg_current_xact_id()::xid)::int AS memberships,
      (SELECT COUNT(*) FROM "advisory_revision" WHERE xmin = pg_current_xact_id()::xid)::int AS advisory_revisions,
      (SELECT COUNT(*) FROM "advisory_vulnerability_binding" WHERE xmin = pg_current_xact_id()::xid)::int AS advisory_bindings,
      (SELECT COUNT(*) FROM "maintainer_reviewed_advisory_approval" WHERE xmin = pg_current_xact_id()::xid)::int AS advisory_approvals,
      (SELECT COUNT(*) FROM "reviewer_capability_issuance" WHERE xmin = pg_current_xact_id()::xid)::int AS capabilities,
      (SELECT COUNT(*) FROM "product_match_evaluation_evidence" WHERE xmin = pg_current_xact_id()::xid)::int AS product_match,
      (SELECT COUNT(*) FROM "finding" WHERE xmin = pg_current_xact_id()::xid)::int AS findings,
      (SELECT COUNT(*) FROM "finding_observation" WHERE xmin = pg_current_xact_id()::xid)::int AS observations,
      (SELECT COUNT(*) FROM "session" WHERE xmin = pg_current_xact_id()::xid)::int AS sessions,
      (
        SELECT COUNT(*) FROM "user"
        WHERE xmin = pg_current_xact_id()::xid
          AND "id" <> ${targetUserId}::uuid
      )::int AS other_users,
      (
        SELECT COUNT(*) FROM "user"
        WHERE xmin = pg_current_xact_id()::xid
          AND "id" = ${targetUserId}::uuid
      )::int AS target_user
  `;
  const row = rows[0];
  if (row === undefined) {
    throw new PersistenceStop('internal_failure');
  }
  return {
    organizations: Number(row.organizations),
    memberships: Number(row.memberships),
    advisory_revisions: Number(row.advisory_revisions),
    advisory_bindings: Number(row.advisory_bindings),
    advisory_approvals: Number(row.advisory_approvals),
    capabilities: Number(row.capabilities),
    product_match: Number(row.product_match),
    findings: Number(row.findings),
    observations: Number(row.observations),
    sessions: Number(row.sessions),
    other_users: Number(row.other_users),
    target_user: Number(row.target_user),
  };
}

function grantFingerprint(grants: readonly GrantImage[]): string {
  return grants
    .map(
      (grant) =>
        `${grant.id}:${grant.authority}:${grant.issuance_classification}:${grant.command_correlation_id}:${grant.active ? 'active' : 'revoked'}`,
    )
    .join('|');
}

async function rereadConcurrentGrant(
  client: PrismaClient,
  command: Extract<InstanceAdvisoryAuthorityCommand, { readonly operation: 'grant' }>,
): Promise<InstanceAdvisoryAuthorityCommandResult> {
  try {
    return await client.$transaction(async (tx) => {
      const loaded = await loadState(tx, command.targetUserId, undefined);
      if (loaded === 'absent_user') {
        return { outcome: 'concurrency_conflict' as const };
      }
      const decision = classifyInstanceAdvisoryConcurrentGrantReread(command, loaded.snapshot);
      if (decision.write.kind !== 'none' || decision.auditEvents !== 0) {
        return { outcome: 'concurrency_conflict' as const };
      }
      if (decision.outcome === 'granted' || decision.outcome === 'revoked') {
        return { outcome: 'concurrency_conflict' as const };
      }
      return { outcome: decision.outcome };
    });
  } catch (error) {
    const failure = classifyInstanceAdvisoryPersistenceFailure(error);
    if (failure === 'database_unavailable') {
      return { outcome: 'database_unavailable' };
    }
    if (failure === 'active_grant_unique' || failure === 'concurrency_conflict') {
      return { outcome: 'concurrency_conflict' };
    }
    return { outcome: 'transaction_aborted' };
  }
}

type AuthorizationGrantRow = {
  user_id: string;
  authority: string;
  issuance_classification: string;
};

async function loadAuthorizationFacts(
  tx: Prisma.TransactionClient,
  userId: string,
  lockForShare: boolean,
): Promise<InstanceAdvisoryAuthorizationFacts> {
  if (!lockForShare) {
    return loadAuthorizationFactsInOneSnapshot(tx, userId);
  }
  const users = await tx.$queryRaw<Array<{ id: string; status: string }>>`
    SELECT "id"::text AS id, "status"::text AS status
    FROM "user"
    WHERE "id" = ${userId}::uuid
    FOR SHARE
  `;
  const grants = await tx.$queryRaw<AuthorizationGrantRow[]>`
    SELECT
      "user_id"::text AS user_id,
      "authority"::text AS authority,
      "issuance_classification"::text AS issuance_classification
    FROM "instance_advisory_authority_grant"
    WHERE "user_id" = ${userId}::uuid
      AND "revoked_at" IS NULL
    ORDER BY "id"
    FOR SHARE
  `;
  return authorizationFactsFrom(userId, users, grants);
}

/**
 * One statement so a disable that commits between two reads cannot pair an
 * active user image with a grant image from a later snapshot.
 */
async function loadAuthorizationFactsInOneSnapshot(
  tx: Prisma.TransactionClient,
  userId: string,
): Promise<InstanceAdvisoryAuthorizationFacts> {
  const rows = await tx.$queryRaw<
    Array<{
      id: string | null;
      status: string | null;
      grant_user_id: string | null;
      authority: string | null;
      issuance_classification: string | null;
    }>
  >`
    SELECT
      account."id"::text AS id,
      account."status"::text AS status,
      grant_row."user_id"::text AS grant_user_id,
      grant_row."authority"::text AS authority,
      grant_row."issuance_classification"::text AS issuance_classification
    FROM (SELECT ${userId}::uuid AS requested_id) AS requested
    LEFT JOIN "user" AS account ON account."id" = requested.requested_id
    LEFT JOIN "instance_advisory_authority_grant" AS grant_row
      ON grant_row."user_id" = account."id"
     AND grant_row."revoked_at" IS NULL
    ORDER BY grant_row."id"
  `;
  const first = rows[0];
  if (first === undefined) {
    return malformedFacts(userId);
  }
  if (first.id === null || first.status === null) {
    return {
      schemaVersion: INSTANCE_ADVISORY_AUTHORIZATION_FACTS_SCHEMA_VERSION,
      availability: 'loaded',
      userId,
      user: { existence: 'absent' },
      activeGrant: null,
      malformed: rows.some((row) => row.authority !== null),
    };
  }
  const grants: AuthorizationGrantRow[] = [];
  for (const row of rows) {
    if (
      row.grant_user_id === null ||
      row.authority === null ||
      row.issuance_classification === null
    ) {
      continue;
    }
    grants.push({
      user_id: row.grant_user_id,
      authority: row.authority,
      issuance_classification: row.issuance_classification,
    });
  }
  return authorizationFactsFrom(userId, [{ id: first.id, status: first.status }], grants);
}

function authorizationFactsFrom(
  userId: string,
  users: readonly { id: string; status: string }[],
  grants: readonly AuthorizationGrantRow[],
): InstanceAdvisoryAuthorizationFacts {
  if (users.length > 1) {
    return malformedFacts(userId);
  }
  const user = users[0];
  if (user === undefined) {
    return {
      schemaVersion: INSTANCE_ADVISORY_AUTHORIZATION_FACTS_SCHEMA_VERSION,
      availability: 'loaded',
      userId,
      user: { existence: 'absent' },
      activeGrant: null,
      malformed: grants.length !== 0,
    };
  }
  if (user.id !== userId || (user.status !== 'active' && user.status !== 'disabled')) {
    return malformedFacts(userId);
  }
  const status = user.status === 'disabled' ? 'disabled' : 'active';
  if (grants.length > 1) {
    return malformedFacts(userId);
  }
  const grant = grants[0];
  if (grant === undefined) {
    return {
      schemaVersion: INSTANCE_ADVISORY_AUTHORIZATION_FACTS_SCHEMA_VERSION,
      availability: 'loaded',
      userId,
      user: { existence: 'present', status },
      activeGrant: null,
      malformed: false,
    };
  }
  if (
    grant.user_id !== userId ||
    !isInstanceAdvisoryAuthority(grant.authority) ||
    !isInstanceAdvisoryIssuanceClassification(grant.issuance_classification)
  ) {
    return malformedFacts(userId);
  }
  return {
    schemaVersion: INSTANCE_ADVISORY_AUTHORIZATION_FACTS_SCHEMA_VERSION,
    availability: 'loaded',
    userId,
    user: { existence: 'present', status },
    activeGrant: {
      userId: grant.user_id,
      authority: grant.authority,
      issuanceClassification: grant.issuance_classification,
    },
    malformed: false,
  };
}

function malformedFacts(userId: string): InstanceAdvisoryAuthorizationFacts {
  return {
    schemaVersion: INSTANCE_ADVISORY_AUTHORIZATION_FACTS_SCHEMA_VERSION,
    availability: 'loaded',
    userId,
    user: { existence: 'absent' },
    activeGrant: null,
    malformed: true,
  };
}

function unavailableFacts(
  userId: string,
  availability: 'database_unavailable' | 'internal_failure',
): InstanceAdvisoryAuthorizationFacts {
  return {
    schemaVersion: INSTANCE_ADVISORY_AUTHORIZATION_FACTS_SCHEMA_VERSION,
    availability,
    userId: isCanonicalInstanceAdvisoryPrincipalId(userId) ? userId : userId,
    user: { existence: 'absent' },
    activeGrant: null,
    malformed: false,
  };
}

function throwFault(
  fault: InstanceAdvisoryAuthorityPersistenceFault | undefined,
  stage: InstanceAdvisoryAuthorityPersistenceFault,
): void {
  if (fault === stage) {
    throw new PersistenceStop('transaction_aborted');
  }
}

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : '';
}

function sqlState(error: unknown): string | null {
  if (error instanceof Prisma.PrismaClientKnownRequestError) {
    const metaCode = error.meta?.['code'];
    if (typeof metaCode === 'string') {
      return metaCode;
    }
  }
  if (error instanceof Error) {
    const match = /(?:Code: `|code: "|SQLSTATE )([0-9A-Z]{5})/.exec(error.message);
    if (match?.[1] !== undefined) {
      return match[1];
    }
  }
  if (typeof error === 'object' && error !== null && 'code' in error) {
    const code = error.code;
    if (typeof code === 'string' && /^[0-9A-Z]{5}$/.test(code)) {
      return code;
    }
  }
  return null;
}

function assertCommandPort(
  factory: (client: PrismaClient) => InstanceAdvisoryAuthorityCommandPort,
): void {
  void factory;
}

assertCommandPort(createInstanceAdvisoryAuthorityPersistence);

function isDatabaseUnavailable(error: unknown): boolean {
  if (
    error instanceof Prisma.PrismaClientInitializationError ||
    error instanceof Prisma.PrismaClientRustPanicError
  ) {
    return true;
  }
  if (error instanceof Prisma.PrismaClientKnownRequestError) {
    return (
      error.code === 'P1001' ||
      error.code === 'P1002' ||
      error.code === 'P1008' ||
      error.code === 'P1017' ||
      error.code === 'P2024'
    );
  }
  const text = errorText(error);
  return text.includes("Can't reach database server") || text.includes('ECONNREFUSED');
}
