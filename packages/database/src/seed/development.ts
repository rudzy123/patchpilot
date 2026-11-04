import { Prisma } from '@prisma/client';
import { assertDevelopmentSeedAllowed, type DatabaseUrlSafety } from '@patchpilot/config';
import {
  JSON_SCHEMA_VERSION_V1,
  RISK_POLICY_DEFINITION_SCHEMA_VERSION_V2,
} from '@patchpilot/domain';

import { getPrismaClient } from '../client.js';
import { asJsonObject, normalizeEmail, normalizeSlug, type PrismaClientLike } from '../guards.js';

const ORG_A_ID = '11111111-1111-4111-8111-111111111111';
const ORG_B_ID = '22222222-2222-4222-8222-222222222222';
const USER_A_ID = '11111111-1111-4111-8111-1111111111aa';
const USER_B_ID = '22222222-2222-4222-8222-2222222222bb';
const VULN_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const BUILTIN_POLICY_ID = '33333333-3333-4333-8333-333333333333';
const ORG_A_POLICY_ID = '44444444-4444-4444-8444-444444444444';
const BUILTIN_POLICY_KEY = 'patchpilot.builtin.v0';
const ORG_A_POLICY_KEY = 'patchpilot.synthetic.org-a.v0';
/** Published builtin priority policy version 2. Distinct from the version 1 placeholder id. */
const BUILTIN_PRIORITY_POLICY_V2_ID = '55555555-5555-4555-8555-555555555502';
const BUILTIN_PRIORITY_POLICY_VERSION = 2;
const BUILTIN_PRIORITY_POLICY_DISPLAY_NAME = 'PatchPilot built-in P1-P4 priority policy';
const BUILTIN_PRIORITY_POLICY_PUBLISHED_AT = new Date('2026-01-01T00:00:00.000Z');

const builtinPriorityPolicySelect = Prisma.validator<Prisma.RiskPolicySelect>()({
  id: true,
  organizationId: true,
  createdByMembershipId: true,
  scope: true,
  policyKey: true,
  name: true,
  version: true,
  status: true,
  policySchemaVersion: true,
  definition: true,
});

export const developmentSeedIds = {
  organizationA: ORG_A_ID,
  organizationB: ORG_B_ID,
  userA: USER_A_ID,
  userB: USER_B_ID,
  vulnerability: VULN_ID,
  builtinRiskPolicy: BUILTIN_POLICY_ID,
  builtinPriorityPolicyVersion2: BUILTIN_PRIORITY_POLICY_V2_ID,
  organizationARiskPolicy: ORG_A_POLICY_ID,
} as const;

export type BuiltinPriorityPolicySeedRow = {
  readonly id: string;
  readonly organizationId: string | null;
  readonly createdByMembershipId: string | null;
  readonly scope: 'builtin' | 'organization';
  readonly policyKey: string;
  readonly name: string;
  readonly version: number;
  readonly status: 'draft' | 'published' | 'retired';
  readonly policySchemaVersion: number;
  readonly definition: unknown;
};

export type EnsurePublishedBuiltinPriorityPolicyResult =
  | {
      readonly outcome: 'inserted';
      readonly policy: BuiltinPriorityPolicySeedRow;
    }
  | {
      readonly outcome: 'already_applied';
      readonly policy: BuiltinPriorityPolicySeedRow;
    }
  | {
      readonly outcome: 'immutable_conflict';
      readonly policy: BuiltinPriorityPolicySeedRow;
    };

/**
 * Stored builtin version 2 does not match the supplied definition.
 * The stored row is left in place.
 */
export class BuiltinPriorityPolicyImmutableConflictError extends Error {
  public readonly outcome = 'immutable_conflict' as const;
  public readonly policyId: string;

  public constructor(policyId: string) {
    super(
      `Immutable conflict for builtin priority policy version 2 (${policyId}). The stored definition differs and was not updated or deleted.`,
    );
    this.name = 'BuiltinPriorityPolicyImmutableConflictError';
    this.policyId = policyId;
  }
}

type StoredBuiltinPriorityPolicyRow = Prisma.RiskPolicyGetPayload<{
  select: typeof builtinPriorityPolicySelect;
}>;

/**
 * Idempotent synthetic development seed.
 *
 * Omit both `builtinPriorityDefinition` and `canonicalJson` to skip builtin
 * priority policy version 2. Callers that only assert version 1 keep working,
 * and this module does not import the policy engine. Supply both fields to
 * publish version 2. `packages/database/src/seed/run.ts` is the seed
 * entrypoint that supplies the engine definition.
 *
 * Production `pnpm db:seed` remains refused. This function calls
 * `assertDevelopmentSeedAllowed` on the supplied env and throws before any
 * write when `PATCHPILOT_DEPLOYMENT_ENVIRONMENT` or `NODE_ENV` is
 * `production`. The database command script applies the same refusal to the
 * process env before starting the seed entrypoint. An immutable conflict on
 * version 2 throws and does not update or delete the stored policy.
 */
export type DevelopmentSeedOptions = {
  env: Readonly<Record<string, string | undefined>>;
  databaseUrl?: string;
  client?: PrismaClientLike;
  builtinPriorityDefinition?: unknown;
  canonicalJson?: (value: unknown) => string;
};

export async function seedDevelopmentData(options: DevelopmentSeedOptions): Promise<void> {
  assertDevelopmentSeedAllowed(options.env);
  const builtinPriority = readBuiltinPrioritySeedRequest(options);
  const client =
    options.client ??
    getPrismaClient(options.databaseUrl === undefined ? {} : { databaseUrl: options.databaseUrl });

  await client.user.upsert({
    where: { id: USER_A_ID },
    update: {
      email: normalizeEmail('owner-a@synthetic.patchpilot.test'),
      displayName: 'Synthetic Owner A',
      status: 'active',
    },
    create: {
      id: USER_A_ID,
      email: normalizeEmail('owner-a@synthetic.patchpilot.test'),
      displayName: 'Synthetic Owner A',
    },
  });

  await client.user.upsert({
    where: { id: USER_B_ID },
    update: {
      email: normalizeEmail('owner-b@synthetic.patchpilot.test'),
      displayName: 'Synthetic Owner B',
      status: 'active',
    },
    create: {
      id: USER_B_ID,
      email: normalizeEmail('owner-b@synthetic.patchpilot.test'),
      displayName: 'Synthetic Owner B',
    },
  });

  await upsertOrganization(client, ORG_A_ID, 'synthetic-org-a', 'Synthetic Organization A');
  await upsertOrganization(client, ORG_B_ID, 'synthetic-org-b', 'Synthetic Organization B');

  const membershipA = await upsertMembership(client, ORG_A_ID, USER_A_ID);
  await upsertMembership(client, ORG_B_ID, USER_B_ID);
  await ensureBuiltinRiskPolicy(client);
  if (builtinPriority !== undefined) {
    const published = await ensurePublishedBuiltinPriorityPolicy({
      client,
      definition: builtinPriority.definition,
      canonicalJson: builtinPriority.canonicalJson,
    });
    if (published.outcome === 'immutable_conflict') {
      throw new BuiltinPriorityPolicyImmutableConflictError(published.policy.id);
    }
  }
  await ensureOrganizationRiskPolicy(client, ORG_A_ID, membershipA.id);

  await client.vulnerability.upsert({
    where: { id: VULN_ID },
    update: {
      osvId: 'PATCHPILOT-SYNTH-VULN-1',
      cveId: null,
      status: 'active',
    },
    create: {
      id: VULN_ID,
      osvId: 'PATCHPILOT-SYNTH-VULN-1',
    },
  });

  await client.vulnerabilityAlias.upsert({
    where: {
      vulnerabilityId_alias: {
        vulnerabilityId: VULN_ID,
        alias: 'PATCHPILOT-SYNTH-ALIAS-1',
      },
    },
    update: {},
    create: {
      vulnerabilityId: VULN_ID,
      alias: 'PATCHPILOT-SYNTH-ALIAS-1',
    },
  });

  await client.vulnerabilitySourceRecord.upsert({
    where: {
      source_sourceIdentity_payloadSha256_normalizationVersion: {
        source: 'osv',
        sourceIdentity: 'PATCHPILOT-SYNTH-VULN-1',
        payloadSha256: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        normalizationVersion: 'test-1',
      },
    },
    update: {},
    create: {
      vulnerabilityId: VULN_ID,
      source: 'osv',
      sourceIdentity: 'PATCHPILOT-SYNTH-VULN-1',
      retrievedAt: new Date('2026-01-01T00:00:00.000Z'),
      payloadSha256: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      normalizationVersion: 'test-1',
      normalized: {
        schemaVersion: JSON_SCHEMA_VERSION_V1,
        summary: 'Synthetic vulnerability for local development.',
        severity: null,
        affectedPackages: [],
      },
    },
  });
}

async function upsertOrganization(
  client: PrismaClientLike,
  id: string,
  slug: string,
  name: string,
): Promise<void> {
  await client.organization.upsert({
    where: { id },
    update: {
      slug: normalizeSlug(slug, 'slug'),
      name,
      status: 'active',
    },
    create: {
      id,
      slug: normalizeSlug(slug, 'slug'),
      name,
    },
  });
}

async function upsertMembership(
  client: PrismaClientLike,
  organizationId: string,
  userId: string,
): Promise<{ id: string }> {
  return client.membership.upsert({
    where: {
      organizationId_userId: {
        organizationId,
        userId,
      },
    },
    update: {
      role: 'owner',
      status: 'active',
      revokedAt: null,
    },
    create: {
      organizationId,
      userId,
      role: 'owner',
      joinedAt: new Date('2026-01-01T00:00:00.000Z'),
    },
    select: { id: true },
  });
}

async function ensureBuiltinRiskPolicy(client: PrismaClientLike): Promise<void> {
  const existing = await client.riskPolicy.findFirst({
    where: {
      scope: 'builtin',
      organizationId: null,
      policyKey: BUILTIN_POLICY_KEY,
      version: 1,
    },
    select: { id: true },
  });
  if (existing !== null) {
    return;
  }

  await client.riskPolicy.create({
    data: {
      id: BUILTIN_POLICY_ID,
      organizationId: null,
      scope: 'builtin',
      policyKey: BUILTIN_POLICY_KEY,
      name: 'Synthetic built-in risk policy',
      version: 1,
      status: 'published',
      policySchemaVersion: JSON_SCHEMA_VERSION_V1,
      publishedAt: new Date('2026-01-01T00:00:00.000Z'),
      definition: asJsonObject(
        {
          schemaVersion: JSON_SCHEMA_VERSION_V1,
          policyKey: BUILTIN_POLICY_KEY,
          factorCatalog: [],
          weights: {},
        },
        'definition',
      ),
    },
  });
}

async function ensureOrganizationRiskPolicy(
  client: PrismaClientLike,
  organizationId: string,
  createdByMembershipId: string,
): Promise<void> {
  const existing = await client.riskPolicy.findFirst({
    where: {
      scope: 'organization',
      organizationId,
      policyKey: ORG_A_POLICY_KEY,
      version: 1,
    },
    select: { id: true },
  });
  if (existing !== null) {
    return;
  }

  await client.riskPolicy.create({
    data: {
      id: ORG_A_POLICY_ID,
      organizationId,
      scope: 'organization',
      policyKey: ORG_A_POLICY_KEY,
      name: 'Synthetic organization A risk policy',
      version: 1,
      status: 'published',
      policySchemaVersion: JSON_SCHEMA_VERSION_V1,
      publishedAt: new Date('2026-01-01T00:00:00.000Z'),
      createdByMembershipId,
      definition: asJsonObject(
        {
          schemaVersion: JSON_SCHEMA_VERSION_V1,
          policyKey: ORG_A_POLICY_KEY,
          factorCatalog: [],
          weights: {},
        },
        'definition',
      ),
    },
  });
}

/**
 * Inserts published builtin `patchpilot.builtin.v0` version 2 when that row
 * is absent. Version 1 is never read or written here.
 *
 * `canonicalJson` is injected so this module does not import the policy
 * engine. Display name is not part of the comparison. The definition is
 * stored as given.
 *
 * No stored version 2 row returns `inserted`. The same canonical JSON returns
 * `already_applied` and the stored row. A different definition, or a stored
 * value that cannot be canonicalized, returns `immutable_conflict` and the
 * stored row. Neither replay nor conflict updates or deletes a row.
 */
export async function ensurePublishedBuiltinPriorityPolicy(input: {
  client: PrismaClientLike;
  definition: unknown;
  canonicalJson: (value: unknown) => string;
}): Promise<EnsurePublishedBuiltinPriorityPolicyResult> {
  const suppliedCanonical = requireCanonicalString(input.canonicalJson, input.definition);
  const existing = await findBuiltinPriorityPolicyVersion2(input.client);
  if (existing !== null) {
    return classifyStoredDefinition(existing, suppliedCanonical, input.canonicalJson);
  }

  try {
    const created = await input.client.riskPolicy.create({
      data: {
        id: BUILTIN_PRIORITY_POLICY_V2_ID,
        organizationId: null,
        createdByMembershipId: null,
        scope: 'builtin',
        policyKey: BUILTIN_POLICY_KEY,
        name: BUILTIN_PRIORITY_POLICY_DISPLAY_NAME,
        version: BUILTIN_PRIORITY_POLICY_VERSION,
        status: 'published',
        policySchemaVersion: RISK_POLICY_DEFINITION_SCHEMA_VERSION_V2,
        publishedAt: BUILTIN_PRIORITY_POLICY_PUBLISHED_AT,
        definition: asJsonObject(requireDefinitionJson(input.definition), 'definition'),
      },
      select: builtinPriorityPolicySelect,
    });
    return { outcome: 'inserted', policy: toSeedRow(created) };
  } catch (error) {
    if (!isUniqueConflict(error)) {
      throw error;
    }
  }

  return classifyAfterUniqueConflict(input.client, suppliedCanonical, input.canonicalJson);
}

function readBuiltinPrioritySeedRequest(
  options: DevelopmentSeedOptions,
): { definition: unknown; canonicalJson: (value: unknown) => string } | undefined {
  const definition = options.builtinPriorityDefinition;
  const canonicalJson = options.canonicalJson;
  if (definition === undefined && canonicalJson === undefined) {
    return undefined;
  }
  if (definition === undefined || canonicalJson === undefined) {
    throw new Error(
      'Builtin priority policy version 2 requires both builtinPriorityDefinition and canonicalJson.',
    );
  }
  return { definition, canonicalJson };
}

async function findBuiltinPriorityPolicyVersion2(
  client: PrismaClientLike,
): Promise<StoredBuiltinPriorityPolicyRow | null> {
  return client.riskPolicy.findFirst({
    where: {
      scope: 'builtin',
      organizationId: null,
      policyKey: BUILTIN_POLICY_KEY,
      version: BUILTIN_PRIORITY_POLICY_VERSION,
    },
    orderBy: { id: 'asc' },
    select: builtinPriorityPolicySelect,
  });
}

async function findRiskPolicyById(
  client: PrismaClientLike,
  id: string,
): Promise<StoredBuiltinPriorityPolicyRow | null> {
  return client.riskPolicy.findUnique({
    where: { id },
    select: builtinPriorityPolicySelect,
  });
}

async function classifyAfterUniqueConflict(
  client: PrismaClientLike,
  suppliedCanonical: string,
  canonicalJson: (value: unknown) => string,
): Promise<EnsurePublishedBuiltinPriorityPolicyResult> {
  const byKey = await findBuiltinPriorityPolicyVersion2(client);
  if (byKey !== null) {
    return classifyStoredDefinition(byKey, suppliedCanonical, canonicalJson);
  }
  const byId = await findRiskPolicyById(client, BUILTIN_PRIORITY_POLICY_V2_ID);
  if (byId === null) {
    throw new Error(
      'Builtin priority policy version 2 hit a unique conflict and the stored row could not be reloaded.',
    );
  }
  if (!isTargetBuiltinPriorityPolicy(byId)) {
    return { outcome: 'immutable_conflict', policy: toSeedRow(byId) };
  }
  return classifyStoredDefinition(byId, suppliedCanonical, canonicalJson);
}

function classifyStoredDefinition(
  row: StoredBuiltinPriorityPolicyRow,
  suppliedCanonical: string,
  canonicalJson: (value: unknown) => string,
): EnsurePublishedBuiltinPriorityPolicyResult {
  const policy = toSeedRow(row);
  let storedCanonical: string;
  try {
    const encoded = canonicalJson(row.definition);
    if (typeof encoded !== 'string') {
      return { outcome: 'immutable_conflict', policy };
    }
    storedCanonical = encoded;
  } catch {
    return { outcome: 'immutable_conflict', policy };
  }
  if (storedCanonical === suppliedCanonical) {
    return { outcome: 'already_applied', policy };
  }
  return { outcome: 'immutable_conflict', policy };
}

function isTargetBuiltinPriorityPolicy(row: StoredBuiltinPriorityPolicyRow): boolean {
  return (
    row.scope === 'builtin' &&
    row.organizationId === null &&
    row.policyKey === BUILTIN_POLICY_KEY &&
    row.version === BUILTIN_PRIORITY_POLICY_VERSION
  );
}

function requireCanonicalString(canonicalJson: (value: unknown) => string, value: unknown): string {
  const encoded = canonicalJson(value);
  if (typeof encoded !== 'string') {
    throw new Error('canonicalJson must return a string.');
  }
  return encoded;
}

function requireDefinitionJson(definition: unknown): Prisma.JsonValue {
  if (definition === null || typeof definition !== 'object' || Array.isArray(definition)) {
    throw new Error('Builtin priority policy definition must be a JSON object.');
  }
  return definition as Prisma.JsonValue;
}

function toSeedRow(row: StoredBuiltinPriorityPolicyRow): BuiltinPriorityPolicySeedRow {
  return {
    id: row.id,
    organizationId: row.organizationId,
    createdByMembershipId: row.createdByMembershipId,
    scope: row.scope,
    policyKey: row.policyKey,
    name: row.name,
    version: row.version,
    status: row.status,
    policySchemaVersion: row.policySchemaVersion,
    definition: row.definition,
  };
}

function isUniqueConflict(error: unknown): boolean {
  return error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002';
}

export type { DatabaseUrlSafety };
