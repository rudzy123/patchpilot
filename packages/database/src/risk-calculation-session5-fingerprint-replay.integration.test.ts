/**
 * Session 5 proof that an exact fingerprint replay keeps the original
 * RiskCalculation and the original priority.calculated audit event.
 * Synthetic rows only. This file does not call storage.googleapis.com or osv.dev.
 * The calculation entry point is the uncomposed use case. This file adds no route.
 */

import { randomUUID } from 'node:crypto';

import { Prisma, PrismaClient } from '@prisma/client';
import {
  createCalculateFindingRiskUseCase,
  createQueryActiveKevMembershipUseCase,
} from '@patchpilot/domain';
import {
  BUILTIN_PRIORITY_POLICY_DEFINITION,
  canonicalJson,
  evaluatePriority,
  parseFactInput,
  validatePolicyDefinition,
  validatePolicyOverride,
} from '@patchpilot/policy-engine';
import { createFoundationTestEnv } from '@patchpilot/test-utils';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { createActiveKevMembershipPersistence } from './active-kev-membership.js';
import { insertOpenFindingForConstraintTest } from './finding-constraint-fixture.js';
import {
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
} from './integration-database.js';
import { createRiskCalculationApplicationPersistence } from './risk-calculation-application-persistence.js';
import { ensurePublishedBuiltinPriorityPolicy, seedDevelopmentData } from './seed/development.js';
import { createAsset, createOrg } from './sbom-test-fixture.js';

const SESSION_ID = 'risk-calculation-session';
const FINGERPRINT_PATTERN = /^[a-f0-9]{64}$/;

type PreparedFinding = {
  readonly organizationId: string;
  readonly userId: string;
  readonly membershipId: string;
  readonly findingId: string;
};

type CalculationIdentity = {
  readonly id: string;
  readonly organizationId: string;
  readonly findingId: string;
  readonly inputFingerprint: string;
  readonly policyDefinitionSha256: string;
  readonly createdAt: string;
  readonly calculatedAt: string;
};

type AuditIdentity = {
  readonly id: string;
  readonly organizationId: string | null;
  readonly action: string;
  readonly subjectType: string;
  readonly subjectId: string;
  readonly occurredAt: string;
  readonly correlationId: string;
  readonly payload: Prisma.JsonValue;
};

let prisma: PrismaClient;
let database: Awaited<ReturnType<typeof createEphemeralDatabase>>;
let calculate: ReturnType<typeof createCalculateFindingRiskUseCase>;

function seedCanonical(value: unknown): string {
  const result = canonicalJson(value);
  if (!result.ok) {
    throw new Error(result.error.code);
  }
  return result.value;
}

function envelope(prepared: PreparedFinding) {
  return {
    actor: {
      userId: prepared.userId,
      sessionId: SESSION_ID,
      organizationId: prepared.organizationId,
      membershipId: prepared.membershipId,
      role: 'owner' as const,
    },
    command: { findingId: prepared.findingId },
  };
}

async function ensureBuiltin(): Promise<void> {
  const result = await ensurePublishedBuiltinPriorityPolicy({
    client: prisma,
    definition: BUILTIN_PRIORITY_POLICY_DEFINITION,
    canonicalJson: seedCanonical,
  });
  if (result.outcome === 'immutable_conflict') {
    throw new Error('builtin priority policy is immutable_conflict');
  }
}

async function prepareFinding(): Promise<PreparedFinding> {
  await ensureBuiltin();
  const suffix = randomUUID().replaceAll('-', '').slice(0, 12);
  const org = await createOrg(prisma, `s5-replay-${suffix}`);
  const asset = await createAsset(prisma, org.id, `asset-${suffix}`);
  const vulnerability = await prisma.vulnerability.create({
    data: { osvId: `PATCHPILOT-S5-${suffix}` },
  });
  const component = await prisma.component.create({
    data: {
      organizationId: org.id,
      identityKey: `npm|s5-placeholder-${suffix}`,
      ecosystem: 'npm',
      name: `s5-placeholder-${suffix}`,
    },
  });
  const created = await insertOpenFindingForConstraintTest(prisma, {
    organizationId: org.id,
    assetId: asset.id,
    vulnerabilityId: vulnerability.id,
    componentId: component.id,
  });
  const owner = await prisma.user.create({
    data: {
      email: `s5-owner-${suffix}@synthetic.patchpilot.test`,
      displayName: `s5-owner-${suffix}`,
    },
  });
  const membership = await prisma.membership.create({
    data: { organizationId: org.id, userId: owner.id, role: 'owner' },
  });
  return {
    organizationId: org.id,
    userId: owner.id,
    membershipId: membership.id,
    findingId: created.finding.id,
  };
}

async function calculationIdentities(
  organizationId: string,
  findingId: string,
): Promise<readonly CalculationIdentity[]> {
  const rows = await prisma.riskCalculation.findMany({
    where: { organizationId, findingId },
    orderBy: { id: 'asc' },
    select: {
      id: true,
      organizationId: true,
      findingId: true,
      inputFingerprint: true,
      policyDefinitionSha256: true,
      createdAt: true,
      calculatedAt: true,
    },
  });
  return rows.map((row) => ({
    id: row.id,
    organizationId: row.organizationId,
    findingId: row.findingId,
    inputFingerprint: row.inputFingerprint.trim(),
    policyDefinitionSha256: row.policyDefinitionSha256.trim(),
    createdAt: row.createdAt.toISOString(),
    calculatedAt: row.calculatedAt.toISOString(),
  }));
}

async function priorityAuditIdentities(organizationId: string): Promise<readonly AuditIdentity[]> {
  const rows = await prisma.auditEvent.findMany({
    where: { organizationId, action: 'priority.calculated' },
    orderBy: { id: 'asc' },
    select: {
      id: true,
      organizationId: true,
      action: true,
      subjectType: true,
      subjectId: true,
      occurredAt: true,
      correlationId: true,
      payload: true,
    },
  });
  return rows.map((row) => ({
    id: row.id,
    organizationId: row.organizationId,
    action: row.action,
    subjectType: row.subjectType,
    subjectId: row.subjectId,
    occurredAt: row.occurredAt.toISOString(),
    correlationId: row.correlationId,
    payload: row.payload,
  }));
}

beforeAll(async () => {
  database = await createEphemeralDatabase('it');
  await deployMigrations(database.databaseUrl);
  prisma = new PrismaClient({ datasources: { db: { url: database.databaseUrl } } });
  await seedDevelopmentData({ env: createFoundationTestEnv(), client: prisma });
  const persistence = createRiskCalculationApplicationPersistence(prisma, {
    bindKevMembership: (client, asOf) =>
      createQueryActiveKevMembershipUseCase({
        membership: createActiveKevMembershipPersistence(client),
        kevEnabled: true,
        staleThresholdSeconds: 259_200,
        now: () => asOf,
      }),
  });
  calculate = createCalculateFindingRiskUseCase({
    engine: {
      parseFactInput,
      evaluatePriority,
      validatePolicyDefinition,
      validatePolicyOverride,
      canonicalJson,
    },
    persistence,
    builtinDefinition: BUILTIN_PRIORITY_POLICY_DEFINITION,
  });
});

afterAll(async () => {
  await prisma.$disconnect();
  await dropEphemeralDatabase(database.admin, database.databaseName);
});

describe('session 5 exact fingerprint replay', () => {
  it('keeps the same RiskCalculation and priority.calculated audit row on exact replay', async () => {
    const prepared = await prepareFinding();
    const input = envelope(prepared);
    const first = await calculate.execute(input);
    expect(first.kind, JSON.stringify(first)).toBe('calculated');
    if (first.kind !== 'calculated') {
      return;
    }

    const calculations = await calculationIdentities(prepared.organizationId, prepared.findingId);
    const audits = await priorityAuditIdentities(prepared.organizationId);
    expect(calculations).toHaveLength(1);
    expect(audits).toHaveLength(1);
    const calculation = calculations[0];
    const audit = audits[0];
    if (calculation === undefined || audit === undefined) {
      throw new Error('expected one calculation and one priority.calculated audit');
    }
    expect(calculation.id).toBe(first.calculation.id);
    expect(calculation.findingId).toBe(prepared.findingId);
    expect(calculation.inputFingerprint).toBe(first.calculation.inputFingerprint);
    expect(calculation.inputFingerprint).toMatch(FINGERPRINT_PATTERN);
    expect(audit.subjectType).toBe('finding');
    expect(audit.subjectId).toBe(prepared.findingId);
    expect(audit.action).toBe('priority.calculated');

    const replay = await calculate.execute(input);
    expect(replay.kind, JSON.stringify(replay)).toBe('replayed');
    if (replay.kind !== 'replayed') {
      return;
    }
    expect(replay.calculation.id).toBe(calculation.id);
    expect(replay.calculation.inputFingerprint).toBe(calculation.inputFingerprint);

    expect(await calculationIdentities(prepared.organizationId, prepared.findingId)).toEqual(
      calculations,
    );
    expect(await priorityAuditIdentities(prepared.organizationId)).toEqual(audits);
    const storedCalculation = await prisma.riskCalculation.findUnique({
      where: { id: calculation.id },
      select: { id: true, organizationId: true, findingId: true },
    });
    const storedAudit = await prisma.auditEvent.findUnique({
      where: { id: audit.id },
      select: { id: true, organizationId: true, action: true, subjectId: true },
    });
    expect(storedCalculation).toEqual({
      id: calculation.id,
      organizationId: prepared.organizationId,
      findingId: prepared.findingId,
    });
    expect(storedAudit).toEqual({
      id: audit.id,
      organizationId: prepared.organizationId,
      action: 'priority.calculated',
      subjectId: prepared.findingId,
    });

    const finding = await prisma.finding.findFirstOrThrow({
      where: { id: prepared.findingId, organizationId: prepared.organizationId },
      select: { state: true, version: true, currentRiskCalculationId: true, dueAt: true },
    });
    expect(finding.state).toBe('open');
    expect(finding.version).toBe(1);
    expect(finding.currentRiskCalculationId).toBeNull();
    expect(finding.dueAt).toBeNull();
  });
});
