import { createHash, randomUUID } from 'node:crypto';

import { Prisma, PrismaClient } from '@prisma/client';
import {
  BUILTIN_PRIORITY_POLICY_KEY,
  BUILTIN_PRIORITY_POLICY_VERSION,
  JSON_SCHEMA_VERSION_V1,
  PRIORITY_CALCULATION_ENGINE_VERSION,
  RISK_CALCULATION_FACTORS_SCHEMA_VERSION_V2,
  compareStoredRemediationRank,
  createReadRemediationQueueUseCase,
} from '@patchpilot/domain';
import {
  BUILTIN_PRIORITY_POLICY_DEFINITION,
  POLICY_ENGINE_VERSION,
  canonicalJson,
  compareForRemediationQueue,
  evaluatePriority,
  parseFactInput,
  validatePolicyDefinition,
  type PriorityEvaluation,
  type PriorityFactInput,
} from '@patchpilot/policy-engine';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { publishBuiltinPriorityPolicy } from './builtin-priority-policy-publication.js';
import { insertOpenFindingForConstraintTest } from './finding-constraint-fixture.js';
import {
  createEphemeralDatabase,
  deployMigrations,
  dropEphemeralDatabase,
} from './integration-database.js';
import { readRemediationQueuePage } from './remediation-queue-persistence.js';
import { createRiskCalculationApplicationPersistence } from './risk-calculation-application-persistence.js';
import { createAsset, createOrg } from './sbom-test-fixture.js';

const BASE_FACTS: PriorityFactInput = {
  source_severity: { state: 'unavailable' },
  kev_listed: { state: 'unavailable', reason: 'no_active_generation' },
  environment_sensitivity: { state: 'unavailable' },
  internet_exposure: { state: 'unavailable' },
  business_criticality: { state: 'unavailable' },
  asset_data_classification: { state: 'unavailable' },
  direct_dependency: { state: 'unavailable' },
  fix_available: { state: 'unavailable' },
  finding_age_days: { state: 'unavailable' },
  advisory_withdrawn: { state: 'unavailable' },
};

function hashDefinition(definition: unknown): string {
  const encoded = canonicalJson(definition);
  if (!encoded.ok) {
    throw new Error('definition must canonicalize');
  }
  return createHash('sha256').update(encoded.value, 'utf8').digest('hex');
}

function evaluate(overrides: Partial<PriorityFactInput>): PriorityEvaluation {
  const facts = parseFactInput({ ...BASE_FACTS, ...overrides });
  const definition = validatePolicyDefinition(structuredClone(BUILTIN_PRIORITY_POLICY_DEFINITION));
  if (!facts.ok || !definition.ok) {
    throw new Error('queue fixture must evaluate');
  }
  const result = evaluatePriority(definition.value, facts.value);
  if (!result.ok) {
    throw new Error(`queue fixture evaluation failed: ${result.error.kind}`);
  }
  return result.value;
}

function factorDocument(evaluation: PriorityEvaluation): Record<string, unknown> {
  return {
    schemaVersion: RISK_CALCULATION_FACTORS_SCHEMA_VERSION_V2,
    factors: evaluation.factors,
    rules: evaluation.rules,
    escalationReasons: evaluation.escalation.reasons,
    evidenceSummary: evaluation.evidenceSummary,
    weightedScoreCenti: evaluation.weightedScoreCenti,
    upliftCenti: evaluation.upliftCenti,
    sources: {
      evidenceIds: [],
      advisoryRevisionIds: [],
      componentOccurrenceIds: [],
      intelligenceSourceRecordIds: [],
      kev: { state: 'unavailable', reason: 'no_active_generation' },
    },
  };
}

describe('remediation queue persistence', () => {
  let databaseUrl: string;
  let databaseName: string;
  let admin: PrismaClient;
  let prisma: PrismaClient;

  beforeAll(async () => {
    const ephemeral = await createEphemeralDatabase('it', { scope: 'queue' });
    databaseUrl = ephemeral.databaseUrl;
    databaseName = ephemeral.databaseName;
    admin = ephemeral.admin;
    await deployMigrations(databaseUrl);
    prisma = new PrismaClient({ datasources: { db: { url: databaseUrl } } });
  });

  afterAll(async () => {
    if (prisma !== undefined) {
      await prisma.$disconnect();
    }
    if (admin !== undefined && databaseName !== undefined) {
      await dropEphemeralDatabase(admin, databaseName);
    }
  });

  it('keeps each organization in its own partition and orders ranked rows with the engine', async () => {
    expect(POLICY_ENGINE_VERSION).toBe(PRIORITY_CALCULATION_ENGINE_VERSION);
    const hash = hashDefinition(BUILTIN_PRIORITY_POLICY_DEFINITION);
    const admitted = [
      {
        engineVersion: PRIORITY_CALCULATION_ENGINE_VERSION,
        policyDefinitionSha256: hash,
        validationEntryId: 'V-test',
      },
    ];
    const published = await publishBuiltinPriorityPolicy(prisma, {
      correlationId: randomUUID(),
      definition: BUILTIN_PRIORITY_POLICY_DEFINITION,
      canonicalJson,
      admittedPairs: admitted,
      engineVersion: PRIORITY_CALCULATION_ENGINE_VERSION,
    });
    expect(published.outcome === 'inserted' || published.outcome === 'already_applied').toBe(true);
    if (published.outcome !== 'inserted' && published.outcome !== 'already_applied') {
      return;
    }
    const home = await createOrg(prisma, `queue-home-${randomUUID().slice(0, 8)}`);
    const foreign = await createOrg(prisma, `queue-foreign-${randomUUID().slice(0, 8)}`);
    const vulnerability = await prisma.vulnerability.create({
      data: { osvId: `QUEUE-${randomUUID()}` },
    });
    const homeComponent = await prisma.component.create({
      data: {
        organizationId: home.id,
        identityKey: `npm|queue-home-${randomUUID()}`,
        ecosystem: 'npm',
        name: 'queue-home',
      },
    });
    const foreignComponent = await prisma.component.create({
      data: {
        organizationId: foreign.id,
        identityKey: `npm|queue-foreign-${randomUUID()}`,
        ecosystem: 'npm',
        name: 'queue-foreign',
      },
    });
    const equal = evaluate({
      kev_listed: { state: 'observed', value: 'listed_catalog_current' },
    });
    const high = evaluate({
      source_severity: { state: 'observed', values: ['critical'] },
      kev_listed: { state: 'observed', value: 'listed_catalog_current' },
      environment_sensitivity: { state: 'observed', value: 'non_production' },
      internet_exposure: { state: 'observed', value: 'internal' },
      business_criticality: { state: 'observed', value: 'critical' },
    });
    expect(high.priority).toBeGreaterThan(equal.priority);
    const early = await insertFinding(home.id, 'queue <asset>', homeComponent.id, vulnerability.id);
    await delay(30);
    const later = await insertFinding(home.id, 'queue later', homeComponent.id, vulnerability.id);
    await delay(30);
    const highest = await insertFinding(home.id, 'queue high', homeComponent.id, vulnerability.id);
    const otherPolicy = await insertFinding(
      home.id,
      'queue other',
      homeComponent.id,
      vulnerability.id,
    );
    const missing = await insertFinding(
      home.id,
      'queue missing',
      homeComponent.id,
      vulnerability.id,
    );
    const outside = await insertFinding(
      foreign.id,
      'queue foreign',
      foreignComponent.id,
      vulnerability.id,
    );
    await insertCalculation(early, equal, hash, published.riskPolicyId);
    await insertCalculation(later, equal, hash, published.riskPolicyId);
    await insertCalculation(highest, high, hash, published.riskPolicyId);
    await insertCalculation(otherPolicy, equal, 'b'.repeat(64), published.riskPolicyId);
    await insertCalculation(outside, high, hash, published.riskPolicyId);

    const read = await readRemediationQueuePage(prisma, {
      organizationId: home.id,
      section: 'ranked',
      referencePolicyDefinitionSha256: hash,
      referenceEngineVersion: PRIORITY_CALCULATION_ENGINE_VERSION,
      limit: 50,
      cursor: null,
    });
    expect(read.kind).toBe('page');
    if (read.kind !== 'page') {
      return;
    }
    expect(read.counts).toEqual({ ranked: 3, incomparable: 1, not_calculated: 1 });
    expect(read.findingCount).toBe(5);
    const evaluations = new Map<string, PriorityEvaluation>([
      [early.id, equal],
      [later.id, equal],
      [highest.id, high],
    ]);
    const expected = [...read.rows].sort((left, right) => {
      const leftEvaluation = evaluations.get(left.findingId);
      const rightEvaluation = evaluations.get(right.findingId);
      if (leftEvaluation === undefined || rightEvaluation === undefined) {
        throw new Error('ranked row is outside the fixture');
      }
      const engineOrder = compareForRemediationQueue(leftEvaluation, rightEvaluation);
      expect(engineOrder).not.toBe('incomparable');
      if (engineOrder !== 0 && engineOrder !== 'incomparable') {
        return engineOrder;
      }
      const stored = compareStoredRemediationRank(
        {
          policyKey: leftEvaluation.policyKey,
          priority: leftEvaluation.priority,
          escalationRecommended: leftEvaluation.escalation.recommended,
          kevListed: left.calculation?.kevListed ?? false,
          severityPercent:
            leftEvaluation.factors.find((row) => row.factorId === 'source_severity')
              ?.normalizedPercent ?? 0,
          firstObservedAt: left.firstObservedAt,
          findingId: left.findingId,
        },
        {
          policyKey: rightEvaluation.policyKey,
          priority: rightEvaluation.priority,
          escalationRecommended: rightEvaluation.escalation.recommended,
          kevListed: right.calculation?.kevListed ?? false,
          severityPercent:
            rightEvaluation.factors.find((row) => row.factorId === 'source_severity')
              ?.normalizedPercent ?? 0,
          firstObservedAt: right.firstObservedAt,
          findingId: right.findingId,
        },
      );
      expect(stored).not.toBe('incomparable');
      return stored === 'incomparable' ? 0 : stored;
    });
    expect(read.rows.map((row) => row.findingId)).toEqual(expected.map((row) => row.findingId));
    expect(read.rows[0]?.findingId).toBe(highest.id);
    expect(read.rows.map((row) => row.findingId)).not.toContain(outside.id);
    expect(read.rows.map((row) => row.findingId)).not.toContain(missing.id);
    expect(read.rows.map((row) => row.findingId)).not.toContain(otherPolicy.id);
    expect(read.rows[0]?.componentName).toBe('reviewed-npm-widget');
    expect(read.rows[0]?.componentVersion).toBe('1.1.0');
    expect(read.rows.find((row) => row.findingId === early.id)?.assetName).toBe('queue <asset>');

    const useCase = createReadRemediationQueueUseCase({
      persistence: {
        findPublishedBuiltinPriorityPolicy: () =>
          createRiskCalculationApplicationPersistence(prisma, {
            bindKevMembership: () => ({
              queryActiveKevMembership: () => {
                throw new Error('queue read does not query KEV membership');
              },
            }),
          }).findPublishedBuiltinPriorityPolicy(),
        readRemediationQueue: (query) => readRemediationQueuePage(prisma, query),
      },
      admittedPairs: admitted,
      referenceEngineVersion: PRIORITY_CALCULATION_ENGINE_VERSION,
      hashPolicyDefinition: hashDefinition,
    });
    const actor = {
      userId: '11111111-1111-4111-8111-111111111111',
      sessionId: 'queue-session',
      organizationId: home.id,
      membershipId: '22222222-2222-4222-8222-222222222222',
      role: 'owner' as const,
    };
    const full = await useCase.execute({
      actor,
      command: { section: 'ranked', limit: 50, cursor: null },
    });
    const repeat = await useCase.execute({
      actor,
      command: { section: 'ranked', limit: 50, cursor: null },
    });
    expect(full.kind).toBe('page');
    expect(repeat.kind).toBe('page');
    if (full.kind !== 'page' || repeat.kind !== 'page') {
      return;
    }
    const order = full.page.rows.map((row) => row.findingId);
    expect(repeat.page.rows.map((row) => row.findingId)).toEqual(order);
    expect(full.page.reference).toEqual({
      policyKey: BUILTIN_PRIORITY_POLICY_KEY,
      policyVersion: BUILTIN_PRIORITY_POLICY_VERSION,
      policyDefinitionSha256: hash,
      engineVersion: PRIORITY_CALCULATION_ENGINE_VERSION,
    });
    const first = await useCase.execute({
      actor,
      command: { section: 'ranked', limit: 1, cursor: null },
    });
    expect(first.kind).toBe('page');
    if (first.kind !== 'page' || first.page.nextCursor === null) {
      throw new Error('ranked page must continue');
    }
    expect(first.page.rows[0]?.findingId).toBe(order[0]);
    const second = await useCase.execute({
      actor,
      command: { section: 'ranked', limit: 1, cursor: first.page.nextCursor },
    });
    expect(second.kind).toBe('page');
    if (second.kind !== 'page') {
      return;
    }
    expect(second.page.rows.map((row) => row.findingId)).toEqual([order[1]]);
    const incomparable = await useCase.execute({
      actor,
      command: { section: 'incomparable', limit: 20, cursor: null },
    });
    const notCalculated = await useCase.execute({
      actor,
      command: { section: 'not_calculated', limit: 20, cursor: null },
    });
    expect(incomparable.kind).toBe('page');
    expect(notCalculated.kind).toBe('page');
    if (incomparable.kind === 'page') {
      expect(incomparable.page.rows.map((row) => row.findingId)).toEqual([otherPolicy.id]);
      expect(incomparable.page.rows[0]).toEqual(
        expect.objectContaining({ comparisonMessage: 'recalculation required for comparison' }),
      );
    }
    if (notCalculated.kind === 'page') {
      expect(notCalculated.page.rows).toEqual([expect.objectContaining({ findingId: missing.id })]);
      expect(notCalculated.page.rows[0]).not.toHaveProperty('priority');
      expect(notCalculated.page.rows[0]).not.toHaveProperty('priorityBand');
    }
    const foreignPage = await useCase.execute({
      actor: { ...actor, organizationId: foreign.id },
      command: { section: 'ranked', limit: 20, cursor: null },
    });
    expect(foreignPage.kind).toBe('page');
    if (foreignPage.kind === 'page') {
      expect(foreignPage.page.counts).toEqual({ ranked: 1, incomparable: 0, not_calculated: 0 });
      expect(foreignPage.page.rows.map((row) => row.findingId)).toEqual([outside.id]);
    }
  }, 180_000);

  async function insertFinding(
    organizationId: string,
    assetName: string,
    componentId: string,
    vulnerabilityId: string,
  ) {
    const asset = await createAsset(prisma, organizationId, assetName);
    const created = await insertOpenFindingForConstraintTest(prisma, {
      organizationId,
      assetId: asset.id,
      vulnerabilityId,
      componentId,
    });
    return created.finding;
  }

  async function insertCalculation(
    finding: { id: string; organizationId: string; lastObservedAt: Date },
    evaluation: PriorityEvaluation,
    policyHash: string,
    riskPolicyId: string,
  ): Promise<void> {
    await prisma.riskCalculation.create({
      data: {
        organizationId: finding.organizationId,
        findingId: finding.id,
        riskPolicyId,
        policyVersion: BUILTIN_PRIORITY_POLICY_VERSION,
        policyDefinitionSha256: policyHash,
        calculatedAt: finding.lastObservedAt,
        factors: factorDocument(evaluation) as Prisma.InputJsonValue,
        result: {
          schemaVersion: JSON_SCHEMA_VERSION_V1,
          priority: evaluation.priority,
          priorityBand: evaluation.priorityBand,
          dueDateRecommendationDays: evaluation.dueDateRecommendationDays,
          escalationRecommendation: evaluation.escalation.recommended,
        },
        calculationEngineVersion: PRIORITY_CALCULATION_ENGINE_VERSION,
        calculationReason: 'initial',
        inputFingerprint: createHash('sha256').update(finding.id).digest('hex'),
      },
    });
  }
});

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, milliseconds);
  });
}
