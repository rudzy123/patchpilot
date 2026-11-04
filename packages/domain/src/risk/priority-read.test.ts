/**
 * Current-priority read. The engine port is not a dependency.
 * Signals compare stored identifiers only.
 */

import { describe, expect, it } from 'vitest';

import { PRIORITY_CALCULATION_ENGINE_VERSION } from './catalog.js';
import {
  BUILTIN_PRIORITY_POLICY_KEY,
  BUILTIN_PRIORITY_POLICY_VERSION,
} from './persistence-port.js';
import type { FindingPriorityCalculationRecord, FindingPriorityRead } from './persistence-port.js';
import {
  classifyPriorityInputChanges,
  createReadControlledFindingPriorityUseCase,
  FINDING_PRIORITY_REVIEW_NONE,
  type PriorityInputChangeComparison,
} from './priority-read.js';

const ORG = '11111111-1111-4111-8111-111111111111';
const ACTOR = '22222222-2222-4222-8222-222222222222';
const MEMBERSHIP = '33333333-3333-4333-8333-333333333333';
const FINDING = '44444444-4444-4444-8444-444444444444';
const POLICY = '55555555-5555-4555-8555-555555555555';
const CALCULATION = '66666666-6666-4666-8666-666666666666';
const HASH = 'a'.repeat(64);
const OTHER_HASH = 'b'.repeat(64);
const GENERATION = '77777777-7777-4777-8777-777777777777';
const OTHER_GENERATION = '88888888-8888-4888-8888-888888888888';
const CALCULATED_AT = new Date('2026-06-01T00:00:00.000Z');
const EARLIER = new Date('2026-05-01T00:00:00.000Z');
const LATER = new Date('2026-07-01T00:00:00.000Z');

function comparison(
  overrides: Partial<PriorityInputChangeComparison> = {},
): PriorityInputChangeComparison {
  return {
    storedPolicyDefinitionSha256: HASH,
    publishedPolicyDefinitionSha256: HASH,
    storedEngineVersion: PRIORITY_CALCULATION_ENGINE_VERSION,
    referenceEngineVersion: PRIORITY_CALCULATION_ENGINE_VERSION,
    storedKevGenerationId: null,
    activeKevGenerationId: null,
    lastObservedAt: EARLIER,
    assetUpdatedAt: EARLIER,
    calculatedAt: CALCULATED_AT,
    ...overrides,
  };
}

function calculation(
  overrides: Partial<FindingPriorityCalculationRecord> = {},
): FindingPriorityCalculationRecord {
  return {
    id: CALCULATION,
    riskPolicyId: POLICY,
    policyKey: BUILTIN_PRIORITY_POLICY_KEY,
    policyVersion: BUILTIN_PRIORITY_POLICY_VERSION,
    policyDefinitionSha256: HASH,
    calculatedAt: CALCULATED_AT,
    calculationEngineVersion: PRIORITY_CALCULATION_ENGINE_VERSION,
    calculationReason: 'initial',
    factors: {
      schemaVersion: 2,
      factors: [],
      rules: [],
      escalationReasons: [],
      evidenceSummary: { observed: 0, unknown: 0, unavailable: 10 },
      weightedScoreCenti: 0,
      upliftCenti: 0,
      sources: {
        evidenceIds: [],
        advisoryRevisionIds: [],
        componentOccurrenceIds: [],
        intelligenceSourceRecordIds: [],
        kev: { state: 'unavailable', reason: 'no_active_generation' },
      },
    },
    result: {
      schemaVersion: 1,
      priority: 0,
      priorityBand: 'P4',
      dueDateRecommendationDays: 180,
      escalationRecommendation: false,
    },
    lastObservedAt: EARLIER,
    assetUpdatedAt: EARLIER,
    activeKevGenerationId: null,
    ...overrides,
  };
}

describe('classifyPriorityInputChanges', () => {
  it('reports no signal when every stored identifier matches', () => {
    expect(classifyPriorityInputChanges(comparison())).toEqual({
      status: 'none_detected',
      signals: [],
    });
  });

  it('fires each signal only for its own identifier and keeps the closed order', () => {
    expect(
      classifyPriorityInputChanges(comparison({ publishedPolicyDefinitionSha256: OTHER_HASH }))
        ?.signals,
    ).toEqual(['policy_superseded']);
    expect(
      classifyPriorityInputChanges(comparison({ storedEngineVersion: 'engine-other' }))?.signals,
    ).toEqual(['engine_version_changed']);
    expect(
      classifyPriorityInputChanges(comparison({ activeKevGenerationId: GENERATION }))?.signals,
    ).toEqual(['kev_generation_changed']);
    expect(
      classifyPriorityInputChanges(
        comparison({ storedKevGenerationId: GENERATION, activeKevGenerationId: OTHER_GENERATION }),
      )?.signals,
    ).toEqual(['kev_generation_changed']);
    expect(classifyPriorityInputChanges(comparison({ lastObservedAt: LATER }))?.signals).toEqual([
      'observed_after_calculation',
    ]);
    expect(classifyPriorityInputChanges(comparison({ assetUpdatedAt: LATER }))?.signals).toEqual([
      'asset_updated_after_calculation',
    ]);
    expect(
      classifyPriorityInputChanges(
        comparison({
          lastObservedAt: CALCULATED_AT,
          assetUpdatedAt: CALCULATED_AT,
        }),
      )?.signals,
    ).toEqual([]);
    expect(
      classifyPriorityInputChanges(
        comparison({
          publishedPolicyDefinitionSha256: OTHER_HASH,
          storedEngineVersion: 'engine-other',
          activeKevGenerationId: GENERATION,
          lastObservedAt: LATER,
          assetUpdatedAt: LATER,
        }),
      ),
    ).toEqual({
      status: 'detected',
      signals: [
        'policy_superseded',
        'engine_version_changed',
        'kev_generation_changed',
        'observed_after_calculation',
        'asset_updated_after_calculation',
      ],
    });
  });
});

describe('createReadControlledFindingPriorityUseCase', () => {
  it('returns not_calculated without priority fields and does not hash when the Finding is absent', async () => {
    let hashes = 0;
    const reads: string[] = [];
    const useCase = createReadControlledFindingPriorityUseCase({
      admittedPairs: [
        {
          engineVersion: PRIORITY_CALCULATION_ENGINE_VERSION,
          policyDefinitionSha256: HASH,
          validationEntryId: 'fixture',
        },
      ],
      referenceEngineVersion: PRIORITY_CALCULATION_ENGINE_VERSION,
      hashPolicyDefinition() {
        hashes += 1;
        return HASH;
      },
      persistence: {
        async readFindingPriority(input) {
          reads.push(input.findingId);
          const absent: FindingPriorityRead = { kind: 'finding_absent' };
          return absent;
        },
      },
    });
    const absent = await useCase.execute({
      actor: {
        userId: ACTOR,
        sessionId: 'session',
        organizationId: ORG,
        membershipId: MEMBERSHIP,
        role: 'owner',
      },
      command: { findingId: FINDING },
    });
    expect(absent).toEqual({ kind: 'not_found' });
    expect(hashes).toBe(0);
    expect(reads).toEqual([FINDING]);
  });

  it('returns not_calculated only after an admitted builtin and omits band fields', async () => {
    const useCase = createReadControlledFindingPriorityUseCase({
      admittedPairs: [
        {
          engineVersion: PRIORITY_CALCULATION_ENGINE_VERSION,
          policyDefinitionSha256: HASH,
          validationEntryId: 'fixture',
        },
      ],
      referenceEngineVersion: PRIORITY_CALCULATION_ENGINE_VERSION,
      hashPolicyDefinition() {
        return HASH;
      },
      persistence: {
        async readFindingPriority() {
          return {
            kind: 'not_calculated',
            findingId: FINDING,
            publishedBuiltin: {
              id: POLICY,
              policyKey: BUILTIN_PRIORITY_POLICY_KEY,
              version: BUILTIN_PRIORITY_POLICY_VERSION,
              definition: { schemaVersion: 2 },
            },
          };
        },
      },
    });
    const result = await useCase.execute({
      actor: {
        userId: ACTOR,
        sessionId: 'session',
        organizationId: ORG,
        membershipId: MEMBERSHIP,
        role: 'admin',
      },
      command: { findingId: FINDING },
    });
    expect(result).toEqual({ kind: 'not_calculated', findingId: FINDING });
    expect(result).not.toHaveProperty('priorityBand');
    expect(result).not.toHaveProperty('priority');
  });

  it('fails closed when the published builtin is absent or unvalidated', async () => {
    const absentPolicy = createReadControlledFindingPriorityUseCase({
      admittedPairs: [
        {
          engineVersion: PRIORITY_CALCULATION_ENGINE_VERSION,
          policyDefinitionSha256: HASH,
          validationEntryId: 'fixture',
        },
      ],
      referenceEngineVersion: PRIORITY_CALCULATION_ENGINE_VERSION,
      hashPolicyDefinition() {
        return HASH;
      },
      persistence: {
        async readFindingPriority() {
          return { kind: 'not_calculated', findingId: FINDING, publishedBuiltin: null };
        },
      },
    });
    const unvalidated = createReadControlledFindingPriorityUseCase({
      admittedPairs: [],
      referenceEngineVersion: PRIORITY_CALCULATION_ENGINE_VERSION,
      hashPolicyDefinition() {
        return HASH;
      },
      persistence: {
        async readFindingPriority() {
          return {
            kind: 'calculated',
            findingId: FINDING,
            publishedBuiltin: {
              id: POLICY,
              policyKey: BUILTIN_PRIORITY_POLICY_KEY,
              version: BUILTIN_PRIORITY_POLICY_VERSION,
              definition: { schemaVersion: 2 },
            },
            calculation: calculation(),
          };
        },
      },
    });
    const actor = {
      userId: ACTOR,
      sessionId: 'session',
      organizationId: ORG,
      membershipId: MEMBERSHIP,
      role: 'owner' as const,
    };
    expect(await absentPolicy.execute({ actor, command: { findingId: FINDING } })).toEqual({
      kind: 'priority_policy_unavailable',
    });
    expect(await unvalidated.execute({ actor, command: { findingId: FINDING } })).toEqual({
      kind: 'priority_policy_unavailable',
    });
  });

  it('returns stored fields, comparability, and review none', async () => {
    const stored = calculation({
      factors: {
        ...calculation().factors,
        sources: {
          ...calculation().factors.sources,
          kev: {
            state: 'catalog',
            catalogVersion: '2026.1',
            catalogReleasedAt: '2026-06-01T00:00:00.000Z',
            freshness: 'current',
            generationId: GENERATION,
            snapshotSha256: null,
          },
        },
      },
      activeKevGenerationId: GENERATION,
    });
    const useCase = createReadControlledFindingPriorityUseCase({
      admittedPairs: [
        {
          engineVersion: PRIORITY_CALCULATION_ENGINE_VERSION,
          policyDefinitionSha256: HASH,
          validationEntryId: 'fixture',
        },
      ],
      referenceEngineVersion: PRIORITY_CALCULATION_ENGINE_VERSION,
      hashPolicyDefinition() {
        return HASH;
      },
      persistence: {
        async readFindingPriority() {
          return {
            kind: 'calculated',
            findingId: FINDING,
            publishedBuiltin: {
              id: POLICY,
              policyKey: BUILTIN_PRIORITY_POLICY_KEY,
              version: BUILTIN_PRIORITY_POLICY_VERSION,
              definition: { schemaVersion: 2 },
            },
            calculation: stored,
          };
        },
      },
    });
    const result = await useCase.execute({
      actor: {
        userId: ACTOR,
        sessionId: 'session',
        organizationId: ORG,
        membershipId: MEMBERSHIP,
        role: 'owner',
      },
      command: { findingId: FINDING },
    });
    expect(result).toEqual({
      kind: 'calculated',
      view: {
        findingId: FINDING,
        calculation: stored,
        comparability: 'reference',
        inputsChanged: { status: 'none_detected', signals: [] },
        review: FINDING_PRIORITY_REVIEW_NONE,
      },
    });
  });

  it('denies a member and rejects a client organization id', async () => {
    const useCase = createReadControlledFindingPriorityUseCase({
      admittedPairs: [],
      referenceEngineVersion: PRIORITY_CALCULATION_ENGINE_VERSION,
      hashPolicyDefinition() {
        return null;
      },
      persistence: {
        async readFindingPriority() {
          throw new Error('read should not run');
        },
      },
    });
    const member = await useCase.execute({
      actor: {
        userId: ACTOR,
        sessionId: 'session',
        organizationId: ORG,
        membershipId: MEMBERSHIP,
        role: 'member',
      },
      command: { findingId: FINDING },
    });
    const injected = await useCase.execute({
      actor: {
        userId: ACTOR,
        sessionId: 'session',
        organizationId: ORG,
        membershipId: MEMBERSHIP,
        role: 'owner',
      },
      command: { findingId: FINDING, organizationId: ORG },
    });
    expect(member).toEqual({ kind: 'unauthorized' });
    expect(injected).toEqual({ kind: 'unauthorized' });
  });
});
