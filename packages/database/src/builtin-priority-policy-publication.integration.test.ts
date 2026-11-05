/**
 * Built-in priority policy publication. Synthetic rows only.
 * The write uses the production admitted pair. An unadmitted pair writes nothing.
 * This file does not publish into a shared or developer database.
 */

import { randomUUID } from 'node:crypto';

import { PrismaClient } from '@prisma/client';
import {
  ADMITTED_PRIORITY_POLICY_PAIRS,
  BUILTIN_PRIORITY_POLICY_KEY,
  BUILTIN_PRIORITY_POLICY_VERSION,
} from '@patchpilot/domain';
import {
  POLICY_ENGINE_VERSION,
  canonicalJson,
  BUILTIN_PRIORITY_POLICY_DEFINITION,
} from '@patchpilot/policy-engine';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import {
  BUILTIN_PRIORITY_POLICY_PUBLICATION_ID,
  publishBuiltinPriorityPolicy,
} from './builtin-priority-policy-publication.js';
import {
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
} from './integration-database.js';

const CORRELATION = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const ADMITTED_DEFINITION_SHA256 =
  '7c1815d456ff6dcf9e19c218bcd5eaba73c265abc911027c3f50df41bb8504f7';

function productionRequest(correlationId: string, admittedPairs = ADMITTED_PRIORITY_POLICY_PAIRS) {
  return {
    correlationId,
    definition: BUILTIN_PRIORITY_POLICY_DEFINITION,
    canonicalJson,
    admittedPairs,
    engineVersion: POLICY_ENGINE_VERSION,
  };
}

async function openDatabase(scope: string): Promise<{
  database: Awaited<ReturnType<typeof createEphemeralDatabase>>;
  prisma: PrismaClient;
}> {
  const database = await createEphemeralDatabase('it', { scope });
  await deployMigrations(database.databaseUrl);
  return {
    database,
    prisma: new PrismaClient({ datasources: { db: { url: database.databaseUrl } } }),
  };
}

describe('builtin priority policy publication', () => {
  let database: Awaited<ReturnType<typeof createEphemeralDatabase>>;
  let prisma: PrismaClient;

  beforeAll(async () => {
    const opened = await openDatabase('publish');
    database = opened.database;
    prisma = opened.prisma;
  });

  afterAll(async () => {
    await prisma.$disconnect();
    await dropEphemeralDatabase(database.admin, database.databaseName);
  });

  it('inserts the admitted version 2 builtin once and writes nothing for an unadmitted pair', async () => {
    expect(ADMITTED_PRIORITY_POLICY_PAIRS).toEqual([
      {
        engineVersion: '@patchpilot/policy-engine@1',
        policyDefinitionSha256: ADMITTED_DEFINITION_SHA256,
        validationEntryId: 'V-0001',
      },
    ]);
    expect(POLICY_ENGINE_VERSION).toBe('@patchpilot/policy-engine@1');
    const inserted = await publishBuiltinPriorityPolicy(prisma, productionRequest(CORRELATION));
    expect(inserted).toEqual({
      outcome: 'inserted',
      riskPolicyId: BUILTIN_PRIORITY_POLICY_PUBLICATION_ID,
    });
    const replay = await publishBuiltinPriorityPolicy(prisma, productionRequest(randomUUID()));
    expect(replay).toEqual({
      outcome: 'already_applied',
      riskPolicyId: BUILTIN_PRIORITY_POLICY_PUBLICATION_ID,
    });
    const refused = await publishBuiltinPriorityPolicy(prisma, productionRequest(CORRELATION, []));
    const wrongHash = await publishBuiltinPriorityPolicy(
      prisma,
      productionRequest(CORRELATION, [
        {
          engineVersion: '@patchpilot/policy-engine@1',
          policyDefinitionSha256: '0'.repeat(64),
          validationEntryId: 'V-0001',
        },
      ]),
    );
    expect(refused).toEqual({ outcome: 'unvalidated' });
    expect(wrongHash).toEqual({ outcome: 'unvalidated' });
    expect(await prisma.riskPolicy.count()).toBe(1);
    const audits = await prisma.auditEvent.findMany({ where: { action: 'risk_policy.published' } });
    expect(audits).toHaveLength(1);
    expect(audits[0]).toMatchObject({
      actorType: 'system',
      actorUserId: null,
      organizationId: null,
      actorMembershipId: null,
      subjectType: 'risk_policy',
      subjectId: BUILTIN_PRIORITY_POLICY_PUBLICATION_ID,
      correlationId: CORRELATION,
    });
    const stored = await prisma.riskPolicy.findUniqueOrThrow({
      where: { id: BUILTIN_PRIORITY_POLICY_PUBLICATION_ID },
    });
    expect(stored.organizationId).toBeNull();
    expect(stored.scope).toBe('builtin');
    expect(stored.policyKey).toBe(BUILTIN_PRIORITY_POLICY_KEY);
    expect(stored.version).toBe(BUILTIN_PRIORITY_POLICY_VERSION);
    expect(stored.version).toBe(2);
    expect(stored.status).toBe('published');
    expect(stored.publishedAt?.toISOString()).not.toBe('2026-01-01T00:00:00.000Z');
    expect(JSON.stringify(audits[0]?.payload)).not.toContain('definition');
  });
});

describe('builtin priority policy publication conflict', () => {
  let database: Awaited<ReturnType<typeof createEphemeralDatabase>>;
  let prisma: PrismaClient;

  beforeAll(async () => {
    const opened = await openDatabase('conflict');
    database = opened.database;
    prisma = opened.prisma;
    await prisma.riskPolicy.create({
      data: {
        id: BUILTIN_PRIORITY_POLICY_PUBLICATION_ID,
        organizationId: null,
        scope: 'builtin',
        policyKey: 'patchpilot.builtin.v0',
        name: 'PatchPilot built-in P1-P4 priority policy',
        version: 2,
        status: 'published',
        policySchemaVersion: 2,
        publishedAt: new Date('2026-02-01T00:00:00.000Z'),
        definition: { schemaVersion: 2, policyKey: 'patchpilot.builtin.v0', marker: 'other' },
      },
    });
  });

  afterAll(async () => {
    await prisma.$disconnect();
    await dropEphemeralDatabase(database.admin, database.databaseName);
  });

  it('does not update a stored definition that differs', async () => {
    const result = await publishBuiltinPriorityPolicy(prisma, productionRequest(CORRELATION));
    expect(result).toEqual({ outcome: 'immutable_conflict' });
    expect(await prisma.auditEvent.count({ where: { action: 'risk_policy.published' } })).toBe(0);
    const stored = await prisma.riskPolicy.findUniqueOrThrow({
      where: { id: BUILTIN_PRIORITY_POLICY_PUBLICATION_ID },
    });
    expect(stored.definition).toMatchObject({ marker: 'other' });
  });
});
