import { createHash, randomUUID } from 'node:crypto';

import { Prisma, PrismaClient } from '@prisma/client';
import {
  ADMITTED_PRIORITY_POLICY_PAIRS,
  BUILTIN_PRIORITY_POLICY_KEY,
  BUILTIN_PRIORITY_POLICY_VERSION,
  JSON_SCHEMA_VERSION_V1,
  PRIORITY_CALCULATION_ENGINE_VERSION,
  RISK_CALCULATION_FACTORS_SCHEMA_VERSION_V2,
  compareStoredRemediationRank,
  REMEDIATION_QUEUE_EXPORT_CAP,
  createExportRemediationQueueUseCase,
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
import {
  exportRemediationQueueSnapshot,
  readRemediationQueuePage,
} from './remediation-queue-persistence.js';
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

  it('returns policy absence before any export audit row', async () => {
    const organizationId = '11111111-1111-4111-8111-111111111111';
    const result = await exportRemediationQueueSnapshot(
      prisma,
      {
        organizationId,
        actorUserId: '22222222-2222-4222-8222-222222222222',
        membershipId: '33333333-3333-4333-8333-333333333333',
        correlationId: 'export-before-policy',
        format: 'json',
        referenceEngineVersion: PRIORITY_CALCULATION_ENGINE_VERSION,
      },
      {
        admit: () => {
          throw new Error('export must not admit a missing policy');
        },
        complete: () => {
          throw new Error('export must not serialize a missing policy');
        },
      },
    );
    expect(result).toEqual({ kind: 'policy_absent' });
    expect(await exportAuditCount(prisma)).toBe(0);
  });

  it('keeps each organization in its own partition and orders ranked rows with the engine', async () => {
    expect(POLICY_ENGINE_VERSION).toBe(PRIORITY_CALCULATION_ENGINE_VERSION);
    const admittedPair = ADMITTED_PRIORITY_POLICY_PAIRS[0];
    if (admittedPair === undefined) {
      throw new Error('production priority pair is missing');
    }
    expect(admittedPair).toEqual({
      engineVersion: '@patchpilot/policy-engine@1',
      policyDefinitionSha256: '7c1815d456ff6dcf9e19c218bcd5eaba73c265abc911027c3f50df41bb8504f7',
      validationEntryId: 'V-0001',
    });
    const hash = hashDefinition(BUILTIN_PRIORITY_POLICY_DEFINITION);
    expect(hash).toBe(admittedPair.policyDefinitionSha256);
    expect(PRIORITY_CALCULATION_ENGINE_VERSION).toBe(admittedPair.engineVersion);
    const published = await publishBuiltinPriorityPolicy(prisma, {
      correlationId: randomUUID(),
      definition: BUILTIN_PRIORITY_POLICY_DEFINITION,
      canonicalJson,
      admittedPairs: ADMITTED_PRIORITY_POLICY_PAIRS,
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
    await delay(30);
    const otherEngine = await insertFinding(
      home.id,
      'queue engine',
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
    await insertCalculation(
      otherEngine,
      equal,
      hash,
      published.riskPolicyId,
      '@patchpilot/policy-engine@0',
    );
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
    expect(read.counts).toEqual({ ranked: 3, incomparable: 2, not_calculated: 1 });
    expect(read.findingCount).toBe(6);
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
    expect(read.rows.map((row) => row.findingId)).not.toContain(otherEngine.id);
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
      admittedPairs: ADMITTED_PRIORITY_POLICY_PAIRS,
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
      expect(incomparable.page.rows.map((row) => row.findingId)).toEqual([
        otherPolicy.id,
        otherEngine.id,
      ]);
      expect(incomparable.page.rows).toEqual([
        expect.objectContaining({ comparisonMessage: 'recalculation required for comparison' }),
        expect.objectContaining({ comparisonMessage: 'recalculation required for comparison' }),
      ]);
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
    engineVersion: string = PRIORITY_CALCULATION_ENGINE_VERSION,
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
        calculationEngineVersion: engineVersion,
        calculationReason: 'initial',
        inputFingerprint: createHash('sha256').update(finding.id).digest('hex'),
      },
    });
  }

  it('exports one snapshot, one audit row, and no stored file replay', async () => {
    const hash = hashDefinition(BUILTIN_PRIORITY_POLICY_DEFINITION);
    const published = await publishBuiltinPriorityPolicy(prisma, {
      correlationId: randomUUID(),
      definition: BUILTIN_PRIORITY_POLICY_DEFINITION,
      canonicalJson,
      admittedPairs: ADMITTED_PRIORITY_POLICY_PAIRS,
      engineVersion: PRIORITY_CALCULATION_ENGINE_VERSION,
    });
    expect(published.outcome === 'inserted' || published.outcome === 'already_applied').toBe(true);
    if (published.outcome !== 'inserted' && published.outcome !== 'already_applied') {
      return;
    }
    const home = await createOrg(prisma, `export-home-${randomUUID().slice(0, 8)}`);
    const foreign = await createOrg(prisma, `export-foreign-${randomUUID().slice(0, 8)}`);
    const vulnerability = await prisma.vulnerability.create({
      data: { osvId: `EXPORT-${randomUUID()}` },
    });
    const homeComponent = await prisma.component.create({
      data: {
        organizationId: home.id,
        identityKey: `npm|export-home-${randomUUID()}`,
        ecosystem: 'npm',
        name: 'export-home',
      },
    });
    const foreignComponent = await prisma.component.create({
      data: {
        organizationId: foreign.id,
        identityKey: `npm|export-foreign-${randomUUID()}`,
        ecosystem: 'npm',
        name: 'export-foreign',
      },
    });
    const low = evaluate({
      kev_listed: { state: 'observed', value: 'listed_catalog_current' },
    });
    const high = evaluate({
      source_severity: { state: 'observed', values: ['critical'] },
      kev_listed: { state: 'observed', value: 'listed_catalog_current' },
      environment_sensitivity: { state: 'observed', value: 'non_production' },
      internet_exposure: { state: 'observed', value: 'internal' },
      business_criticality: { state: 'observed', value: 'critical' },
    });
    const early = await insertFinding(home.id, 'export early', homeComponent.id, vulnerability.id);
    const later = await insertFinding(home.id, 'export later', homeComponent.id, vulnerability.id);
    const other = await insertFinding(home.id, 'export other', homeComponent.id, vulnerability.id);
    const missing = await insertFinding(
      home.id,
      'export missing',
      homeComponent.id,
      vulnerability.id,
    );
    const outside = await insertFinding(
      foreign.id,
      'export foreign',
      foreignComponent.id,
      vulnerability.id,
    );
    await insertCalculation(early, low, hash, published.riskPolicyId);
    await insertCalculation(later, high, hash, published.riskPolicyId);
    await insertCalculation(other, low, 'b'.repeat(64), published.riskPolicyId);
    await insertCalculation(outside, high, hash, published.riskPolicyId);
    const actor = await createExportActor(home.id);
    const before = await populationCounts(home.id);
    const policyCount = await prisma.riskPolicy.count();
    const useCase = exportUseCase();
    const correlationId = `export-${randomUUID()}`;
    const result = await useCase.execute({
      actor: actor.actor,
      command: { format: 'json', correlationId },
    });
    expect(result.kind).toBe('exported');
    if (result.kind !== 'exported') {
      return;
    }
    expect(result.document.counts).toEqual({ ranked: 2, incomparable: 1, not_calculated: 1 });
    expect(result.document.rowCount).toBe(4);
    expect(result.document.sections.not_calculated.map((row) => row.findingId)).toEqual([
      missing.id,
    ]);
    expect(result.document.sections.not_calculated[0]).not.toHaveProperty('priorityBand');
    expect(result.document.sections.incomparable.map((row) => row.findingId)).toEqual([other.id]);
    expect(result.document.sections.ranked.map((row) => row.findingId)).not.toContain(outside.id);
    const page = await readRemediationQueuePage(prisma, {
      organizationId: home.id,
      section: 'ranked',
      referencePolicyDefinitionSha256: hash,
      referenceEngineVersion: PRIORITY_CALCULATION_ENGINE_VERSION,
      limit: 50,
      cursor: null,
    });
    expect(page.kind).toBe('page');
    if (page.kind === 'page') {
      expect(result.document.sections.ranked.map((row) => row.findingId)).toEqual(
        page.rows.map((row) => row.findingId),
      );
    }
    expect(createHash('sha256').update(result.body).digest('hex')).toBe(result.sha256);
    const audit = await prisma.auditEvent.findFirstOrThrow({
      where: { organizationId: home.id, action: 'export.created', correlationId },
    });
    const payload = audit.payload;
    expect(payload).toMatchObject({
      schemaVersion: 1,
      purpose: 'remediation_queue_export',
      format: 'json',
      rowCount: 4,
      cap: REMEDIATION_QUEUE_EXPORT_CAP,
      sha256: result.sha256,
      byteLength: result.byteLength,
    });
    expect(JSON.stringify(payload)).not.toContain(early.id);
    expect(JSON.stringify(payload)).not.toContain('export early');
    expect(await populationCounts(home.id)).toEqual(before);
    expect(await prisma.riskPolicy.count()).toBe(policyCount);
    expect(
      await prisma.evidence.count({ where: { organizationId: home.id, kind: 'export_snapshot' } }),
    ).toBe(0);

    const replay = await useCase.execute({
      actor: actor.actor,
      command: { format: 'csv', correlationId },
    });
    expect(replay).toEqual({ kind: 'correlation_conflict' });
    expect(
      await prisma.auditEvent.count({
        where: { organizationId: home.id, action: 'export.created' },
      }),
    ).toBe(1);

    const failed = await exportRemediationQueueSnapshot(
      prisma,
      {
        organizationId: home.id,
        actorUserId: actor.actor.userId,
        membershipId: actor.actor.membershipId,
        correlationId: `export-fail-${randomUUID()}`,
        format: 'json',
        referenceEngineVersion: PRIORITY_CALCULATION_ENGINE_VERSION,
      },
      {
        admit: (definition) => {
          const admitted = hashDefinition(definition);
          return admitted.length === 64 ? { ok: true, hash: admitted } : { ok: false };
        },
        complete: () => {
          throw new Error('export serialization failed');
        },
      },
    );
    expect(failed).toEqual({ kind: 'unavailable' });
    expect(
      await prisma.auditEvent.count({
        where: { organizationId: home.id, action: 'export.created' },
      }),
    ).toBe(1);

    await prisma.asset.update({ where: { id: missing.assetId }, data: { name: '' } });
    const malformed = await useCase.execute({
      actor: actor.actor,
      command: { format: 'json', correlationId: `export-malformed-${randomUUID()}` },
    });
    expect(malformed).toEqual({ kind: 'unavailable' });
    expect(
      await prisma.auditEvent.count({
        where: { organizationId: home.id, action: 'export.created' },
      }),
    ).toBe(1);
  }, 120_000);

  it('exports 150 findings and writes no audit row at 151', async () => {
    const published = await publishBuiltinPriorityPolicy(prisma, {
      correlationId: randomUUID(),
      definition: BUILTIN_PRIORITY_POLICY_DEFINITION,
      canonicalJson,
      admittedPairs: ADMITTED_PRIORITY_POLICY_PAIRS,
      engineVersion: PRIORITY_CALCULATION_ENGINE_VERSION,
    });
    expect(published.outcome === 'inserted' || published.outcome === 'already_applied').toBe(true);
    if (published.outcome !== 'inserted' && published.outcome !== 'already_applied') {
      return;
    }
    const home = await createOrg(prisma, `export-cap-${randomUUID().slice(0, 8)}`);
    const component = await prisma.component.create({
      data: {
        organizationId: home.id,
        identityKey: `npm|export-cap-${randomUUID()}`,
        ecosystem: 'npm',
        name: 'export-cap',
      },
    });
    const actor = await createExportActor(home.id);
    for (let index = 0; index < REMEDIATION_QUEUE_EXPORT_CAP; index += 1) {
      const vulnerability = await prisma.vulnerability.create({
        data: { osvId: `EXPORT-CAP-${randomUUID()}` },
      });
      await insertFinding(home.id, `cap ${index}`, component.id, vulnerability.id);
    }
    const useCase = exportUseCase();
    const success = await useCase.execute({
      actor: actor.actor,
      command: { format: 'csv', correlationId: `export-cap-${randomUUID()}` },
    });
    expect(success.kind).toBe('exported');
    if (success.kind !== 'exported') {
      return;
    }
    expect(success.document.rowCount).toBe(REMEDIATION_QUEUE_EXPORT_CAP);
    expect(success.document.counts).toEqual({
      ranked: 0,
      incomparable: 0,
      not_calculated: REMEDIATION_QUEUE_EXPORT_CAP,
    });
    const overflowVulnerability = await prisma.vulnerability.create({
      data: { osvId: `EXPORT-CAP-OVERFLOW-${randomUUID()}` },
    });
    await insertFinding(home.id, 'cap overflow', component.id, overflowVulnerability.id);
    const overflow = await useCase.execute({
      actor: actor.actor,
      command: { format: 'json', correlationId: `export-cap-overflow-${randomUUID()}` },
    });
    expect(overflow).toEqual({ kind: 'cap_exceeded' });
    expect(
      await prisma.auditEvent.count({
        where: { organizationId: home.id, action: 'export.created' },
      }),
    ).toBe(1);
    expect(await prisma.finding.count({ where: { organizationId: home.id } })).toBe(
      REMEDIATION_QUEUE_EXPORT_CAP + 1,
    );
  }, 300_000);

  function exportUseCase() {
    return createExportRemediationQueueUseCase({
      persistence: {
        exportRemediationQueue: (query, hooks) =>
          exportRemediationQueueSnapshot(prisma, query, hooks),
      },
      admittedPairs: ADMITTED_PRIORITY_POLICY_PAIRS,
      referenceEngineVersion: PRIORITY_CALCULATION_ENGINE_VERSION,
      hashPolicyDefinition: hashDefinition,
      serializeExport: (document) => Buffer.from(JSON.stringify(document), 'utf8'),
    });
  }

  async function createExportActor(organizationId: string) {
    const user = await prisma.user.create({
      data: {
        email: `export-${randomUUID()}@synthetic.patchpilot.test`,
        displayName: 'Export owner',
      },
    });
    const membership = await prisma.membership.create({
      data: { organizationId, userId: user.id, role: 'owner' },
    });
    return {
      actor: {
        userId: user.id,
        sessionId: 'export-session',
        organizationId,
        membershipId: membership.id,
        role: 'owner' as const,
      },
    };
  }

  async function populationCounts(organizationId: string) {
    const [findings, calculations, reviews, evidence, productMatch] = await Promise.all([
      prisma.finding.count({ where: { organizationId } }),
      prisma.riskCalculation.count({ where: { organizationId } }),
      prisma.riskCalculationReview.count({ where: { organizationId } }),
      prisma.evidence.count({ where: { organizationId } }),
      prisma.productMatchEvaluationEvidence.count({ where: { organizationId } }),
    ]);
    return { findings, calculations, reviews, evidence, productMatch };
  }
});

function exportAuditCount(client: PrismaClient): Promise<number> {
  return client.auditEvent.count({ where: { action: 'export.created' } });
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, milliseconds);
  });
}
