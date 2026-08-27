import { assertDevelopmentSeedAllowed, type DatabaseUrlSafety } from '@patchpilot/config';
import { JSON_SCHEMA_VERSION_V1 } from '@patchpilot/domain';

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

export const developmentSeedIds = {
  organizationA: ORG_A_ID,
  organizationB: ORG_B_ID,
  userA: USER_A_ID,
  userB: USER_B_ID,
  vulnerability: VULN_ID,
  builtinRiskPolicy: BUILTIN_POLICY_ID,
  organizationARiskPolicy: ORG_A_POLICY_ID,
} as const;

export async function seedDevelopmentData(options: {
  env: Readonly<Record<string, string | undefined>>;
  databaseUrl?: string;
  client?: PrismaClientLike;
}): Promise<void> {
  assertDevelopmentSeedAllowed(options.env);
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

export type { DatabaseUrlSafety };
