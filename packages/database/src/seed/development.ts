import { assertDevelopmentSeedAllowed, type DatabaseUrlSafety } from '@patchpilot/config';
import { JSON_SCHEMA_VERSION_V1 } from '@patchpilot/domain';

import { getPrismaClient } from '../client.js';
import type { PrismaClientLike } from '../guards.js';
import { normalizeEmail, normalizeSlug } from '../guards.js';

const ORG_A_ID = '11111111-1111-4111-8111-111111111111';
const ORG_B_ID = '22222222-2222-4222-8222-222222222222';
const USER_A_ID = '11111111-1111-4111-8111-1111111111aa';
const USER_B_ID = '22222222-2222-4222-8222-2222222222bb';
const VULN_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';

export const developmentSeedIds = {
  organizationA: ORG_A_ID,
  organizationB: ORG_B_ID,
  userA: USER_A_ID,
  userB: USER_B_ID,
  vulnerability: VULN_ID,
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

  await upsertMembership(client, ORG_A_ID, USER_A_ID);
  await upsertMembership(client, ORG_B_ID, USER_B_ID);

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
): Promise<void> {
  await client.membership.upsert({
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
  });
}

export type { DatabaseUrlSafety };
