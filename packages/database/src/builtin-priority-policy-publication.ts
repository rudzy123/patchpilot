/**
 * Deployment-local insert of the published built-in priority policy.
 * The allowlist is checked before any read. An unvalidated pair writes nothing.
 * Exact replay writes no second audit row. A different stored definition is an
 * immutable conflict. This module does not import the policy engine.
 */

import { createHash } from 'node:crypto';

import { Prisma, type PrismaClient } from '@prisma/client';
import {
  ADMITTED_PRIORITY_POLICY_PAIRS,
  BUILTIN_PRIORITY_POLICY_KEY,
  BUILTIN_PRIORITY_POLICY_VERSION,
  JSON_SCHEMA_VERSION_V1,
  RISK_POLICY_DEFINITION_SCHEMA_VERSION_V2,
  isAdmittedPriorityPolicyPair,
  type AdmittedPriorityPolicyPair,
} from '@patchpilot/domain';

import {
  RISK_POLICY_PUBLISHED_AUDIT_ACTION,
  RISK_POLICY_SUBJECT_TYPE,
} from './risk-calculation-persistence.js';

export const BUILTIN_PRIORITY_POLICY_PUBLICATION_ID = '55555555-5555-4555-8555-555555555502';

export const BUILTIN_PRIORITY_POLICY_DISPLAY_NAME = 'PatchPilot built-in P1-P4 priority policy';

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export type CanonicalJsonResult =
  { readonly ok: true; readonly value: string } | { readonly ok: false };

export type BuiltinPriorityPolicyPublicationRequest = {
  readonly correlationId: string;
  readonly definition: unknown;
  readonly canonicalJson: (value: unknown) => CanonicalJsonResult;
  readonly admittedPairs: readonly AdmittedPriorityPolicyPair[];
  readonly engineVersion: string;
};

export type BuiltinPriorityPolicyPublicationResult =
  | { readonly outcome: 'inserted'; readonly riskPolicyId: string }
  | { readonly outcome: 'already_applied'; readonly riskPolicyId: string }
  | { readonly outcome: 'unvalidated' }
  | { readonly outcome: 'immutable_conflict' }
  | { readonly outcome: 'persistence_failure' };

type StoredBuiltinRow = {
  readonly id: string;
  readonly organization_id: string | null;
  readonly scope: string;
  readonly policy_key: string;
  readonly version: number | bigint;
  readonly status: string;
  readonly policy_schema_version: number | bigint;
  readonly definition: unknown;
};

export async function publishBuiltinPriorityPolicy(
  client: PrismaClient,
  request: BuiltinPriorityPolicyPublicationRequest,
): Promise<BuiltinPriorityPolicyPublicationResult> {
  if (!UUID_PATTERN.test(request.correlationId)) {
    return { outcome: 'persistence_failure' };
  }
  const admitted = admit(request, request.definition);
  if (!admitted.ok) {
    return { outcome: 'unvalidated' };
  }
  try {
    return await client.$transaction((tx) => insertOrReplay(tx, request, admitted.hash), {
      isolationLevel: Prisma.TransactionIsolationLevel.ReadCommitted,
    });
  } catch (error) {
    if (!isUniqueViolation(error)) {
      return { outcome: 'persistence_failure' };
    }
    try {
      return await classifyExisting(client, request, admitted.hash);
    } catch {
      return { outcome: 'persistence_failure' };
    }
  }
}

export function productionPublicationAdmitsCurrentBuiltin(
  canonicalJson: (value: unknown) => CanonicalJsonResult,
  definition: unknown,
  engineVersion: string,
): boolean {
  return admit(
    {
      correlationId: '00000000-0000-4000-8000-000000000000',
      definition,
      canonicalJson,
      admittedPairs: ADMITTED_PRIORITY_POLICY_PAIRS,
      engineVersion,
    },
    definition,
  ).ok;
}

async function insertOrReplay(
  tx: Prisma.TransactionClient,
  request: BuiltinPriorityPolicyPublicationRequest,
  expectedHash: string,
): Promise<BuiltinPriorityPolicyPublicationResult> {
  const existing = await selectBuiltin(tx);
  if (existing.length > 1) {
    return { outcome: 'persistence_failure' };
  }
  const row = existing[0];
  if (row !== undefined) {
    return classifyRow(request, row, expectedHash);
  }
  const inserted = await tx.$queryRaw<Array<{ id: string }>>`
    INSERT INTO "risk_policy" (
      "id",
      "organization_id",
      "scope",
      "policy_key",
      "name",
      "version",
      "status",
      "policy_schema_version",
      "definition",
      "published_at",
      "created_by_membership_id"
    )
    VALUES (
      ${BUILTIN_PRIORITY_POLICY_PUBLICATION_ID}::uuid,
      NULL,
      'builtin'::"risk_policy_scope",
      ${BUILTIN_PRIORITY_POLICY_KEY},
      ${BUILTIN_PRIORITY_POLICY_DISPLAY_NAME},
      ${BUILTIN_PRIORITY_POLICY_VERSION}::int,
      'published'::"risk_policy_status",
      ${RISK_POLICY_DEFINITION_SCHEMA_VERSION_V2}::int,
      ${canonicalDefinitionJson(request)}::jsonb,
      CURRENT_TIMESTAMP,
      NULL
    )
    RETURNING "id"::text AS "id"
  `;
  const id = inserted[0]?.id?.toLowerCase();
  if (inserted.length !== 1 || id !== BUILTIN_PRIORITY_POLICY_PUBLICATION_ID) {
    throw new Error('builtin_priority_policy_insert_failed');
  }
  const payload = {
    schemaVersion: JSON_SCHEMA_VERSION_V1,
    riskPolicyId: id,
    policyKey: BUILTIN_PRIORITY_POLICY_KEY,
    policyVersion: BUILTIN_PRIORITY_POLICY_VERSION,
    policySchemaVersion: RISK_POLICY_DEFINITION_SCHEMA_VERSION_V2,
  };
  await tx.$executeRaw`
    INSERT INTO "audit_event" (
      "organization_id",
      "actor_user_id",
      "actor_membership_id",
      "actor_type",
      "action",
      "subject_type",
      "subject_id",
      "correlation_id",
      "payload",
      "schema_version",
      "retention_category"
    )
    VALUES (
      NULL,
      NULL,
      NULL,
      'system'::"audit_actor_type",
      ${RISK_POLICY_PUBLISHED_AUDIT_ACTION},
      ${RISK_POLICY_SUBJECT_TYPE},
      ${id}::uuid,
      ${request.correlationId},
      ${JSON.stringify(payload)}::jsonb,
      ${JSON_SCHEMA_VERSION_V1}::int,
      'security'::"audit_retention_category"
    )
  `;
  return { outcome: 'inserted', riskPolicyId: id };
}

async function classifyExisting(
  client: PrismaClient,
  request: BuiltinPriorityPolicyPublicationRequest,
  expectedHash: string,
): Promise<BuiltinPriorityPolicyPublicationResult> {
  const rows = await selectBuiltin(client);
  const row = rows[0];
  if (rows.length !== 1 || row === undefined) {
    return { outcome: 'immutable_conflict' };
  }
  return classifyRow(request, row, expectedHash);
}

function classifyRow(
  request: BuiltinPriorityPolicyPublicationRequest,
  row: StoredBuiltinRow,
  expectedHash: string,
): BuiltinPriorityPolicyPublicationResult {
  const id = row.id.toLowerCase();
  const version = typeof row.version === 'bigint' ? Number(row.version) : row.version;
  const schemaVersion =
    typeof row.policy_schema_version === 'bigint'
      ? Number(row.policy_schema_version)
      : row.policy_schema_version;
  const stored = admit(request, row.definition);
  const exact =
    id === BUILTIN_PRIORITY_POLICY_PUBLICATION_ID &&
    row.organization_id === null &&
    row.scope === 'builtin' &&
    row.policy_key === BUILTIN_PRIORITY_POLICY_KEY &&
    version === BUILTIN_PRIORITY_POLICY_VERSION &&
    row.status === 'published' &&
    schemaVersion === RISK_POLICY_DEFINITION_SCHEMA_VERSION_V2 &&
    stored.ok &&
    stored.hash === expectedHash;
  if (exact) {
    return { outcome: 'already_applied', riskPolicyId: id };
  }
  return { outcome: 'immutable_conflict' };
}

async function selectBuiltin(
  client: Prisma.TransactionClient | PrismaClient,
): Promise<StoredBuiltinRow[]> {
  return client.$queryRaw<StoredBuiltinRow[]>`
    SELECT
      "id"::text AS "id",
      "organization_id"::text AS "organization_id",
      "scope"::text AS "scope",
      "policy_key",
      "version",
      "status"::text AS "status",
      "policy_schema_version",
      "definition"
    FROM "risk_policy"
    WHERE "organization_id" IS NULL
      AND "policy_key" = ${BUILTIN_PRIORITY_POLICY_KEY}
      AND "version" = ${BUILTIN_PRIORITY_POLICY_VERSION}::int
  `;
}

function canonicalDefinitionJson(request: BuiltinPriorityPolicyPublicationRequest): string {
  const encoded = request.canonicalJson(request.definition);
  if (!encoded.ok) {
    throw new Error('builtin_priority_policy_canonical_failed');
  }
  return encoded.value;
}

function admit(
  request: BuiltinPriorityPolicyPublicationRequest,
  definition: unknown,
): { readonly ok: true; readonly hash: string } | { readonly ok: false } {
  let encoded: CanonicalJsonResult;
  try {
    encoded = request.canonicalJson(definition);
  } catch {
    return { ok: false };
  }
  if (!encoded.ok) {
    return { ok: false };
  }
  const hash = createHash('sha256').update(encoded.value, 'utf8').digest('hex');
  if (!isAdmittedPriorityPolicyPair(request.admittedPairs, request.engineVersion, hash)) {
    return { ok: false };
  }
  return { ok: true, hash };
}

function isUniqueViolation(error: unknown): boolean {
  if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') {
    return true;
  }
  return sqlState(error) === '23505';
}

function sqlState(error: unknown): string | null {
  if (typeof error === 'object' && error !== null && 'code' in error) {
    const code = error.code;
    if (typeof code === 'string' && /^[0-9A-Z]{5}$/.test(code)) {
      return code;
    }
  }
  return null;
}
