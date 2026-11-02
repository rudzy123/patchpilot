import { describe, expect, it } from 'vitest';

import { BUILTIN_PRIORITY_POLICY_DEFINITION } from './builtin-definition.js';
import {
  ADVISORY_WITHDRAWN_TOKENS,
  ASSET_DATA_CLASSIFICATION_TOKENS,
  BUSINESS_CRITICALITY_TOKENS,
  DIRECT_DEPENDENCY_TOKENS,
  ENVIRONMENT_SENSITIVITY_TOKENS,
  FACTOR_IDS,
  FIX_AVAILABLE_TOKENS,
  INTERNET_EXPOSURE_TOKENS,
  KEV_OBSERVED_TOKENS,
  NORMALIZED_TOKEN_FACTOR_IDS,
  NORMALIZED_TOKEN_FACTORS,
  SEVERITY_RATINGS,
  type FactorId,
  type NormalizedTokenFactorId,
} from './catalog.js';
import type { PriorityEvaluation } from './evaluate.js';
import type { PriorityFactInput } from './facts.js';
import {
  BASE_FACTS,
  evaluateWith,
  OVERRIDE_OR_WEIGHTS,
  validatedDefinition,
  adrPolicyDefinitionInput,
} from './test-helper.js';

const P3_FACTS: Partial<PriorityFactInput> = {
  source_severity: { state: 'observed', values: ['critical'] },
  kev_listed: { state: 'observed', value: 'not_listed_catalog_current' },
  environment_sensitivity: { state: 'observed', value: 'production' },
  internet_exposure: { state: 'unknown', value: 'unknown' },
};

const B100_FACTS: Partial<PriorityFactInput> = {
  source_severity: { state: 'observed', values: ['critical'] },
  kev_listed: { state: 'observed', value: 'listed_catalog_current' },
  environment_sensitivity: { state: 'observed', value: 'production' },
  internet_exposure: { state: 'observed', value: 'internet_facing' },
  business_criticality: { state: 'observed', value: 'critical' },
  asset_data_classification: { state: 'observed', value: 'restricted' },
  direct_dependency: { state: 'observed', value: 'direct' },
  fix_available: { state: 'observed', value: 'available' },
  finding_age_days: { state: 'observed', value: 90 },
  advisory_withdrawn: { state: 'observed', value: 'not_withdrawn' },
};

const BACKGROUNDS = [
  { name: 'BASE', facts: {} },
  { name: 'P3', facts: P3_FACTS },
  { name: 'B100', facts: B100_FACTS },
] as const;

const AGE_DAYS = [0, 29, 30, 89, 90, 36500] as const;

function expectAccounting(result: PriorityEvaluation): void {
  const contributions = result.factors.reduce((total, row) => total + row.contributionCenti, 0);
  expect(contributions).toBe(result.weightedScoreCenti);
  expect(result.rules[0]?.upliftCenti).toBe(result.upliftCenti);
  expect(result.rules[1]?.upliftCenti).toBe(0);
  const total = result.weightedScoreCenti + result.upliftCenti;
  expect(result.priority).toBe(Math.floor((total + 50) / 100));
}

function observedFacts(factorId: FactorId): readonly PriorityFactInput[FactorId][] {
  switch (factorId) {
    case 'source_severity':
      return SEVERITY_RATINGS.map((value) => ({ state: 'observed', values: [value] }));
    case 'kev_listed':
      return KEV_OBSERVED_TOKENS.map((value) => ({ state: 'observed', value }));
    case 'environment_sensitivity':
      return ENVIRONMENT_SENSITIVITY_TOKENS.map((value) => ({ state: 'observed', value }));
    case 'internet_exposure':
      return INTERNET_EXPOSURE_TOKENS.map((value) => ({ state: 'observed', value }));
    case 'business_criticality':
      return BUSINESS_CRITICALITY_TOKENS.map((value) => ({ state: 'observed', value }));
    case 'asset_data_classification':
      return ASSET_DATA_CLASSIFICATION_TOKENS.map((value) => ({ state: 'observed', value }));
    case 'direct_dependency':
      return DIRECT_DEPENDENCY_TOKENS.map((value) => ({ state: 'observed', value }));
    case 'fix_available':
      return FIX_AVAILABLE_TOKENS.map((value) => ({ state: 'observed', value }));
    case 'finding_age_days':
      return AGE_DAYS.map((value) => ({ state: 'observed', value }));
    case 'advisory_withdrawn':
      return ADVISORY_WITHDRAWN_TOKENS.map((value) => ({ state: 'observed', value }));
  }
}

function unknownFacts(factorId: FactorId): readonly PriorityFactInput[FactorId][] {
  switch (factorId) {
    case 'source_severity':
      return [{ state: 'unknown', value: 'unrated' }];
    case 'kev_listed':
      return [
        { state: 'unknown', value: 'absent_catalog_stale' },
        { state: 'unknown', value: 'absent_catalog_disabled_with_history' },
      ];
    case 'internet_exposure':
      return [{ state: 'unknown', value: 'unknown' }];
    case 'business_criticality':
      return [{ state: 'unknown', value: 'unspecified' }];
    case 'asset_data_classification':
      return [{ state: 'unknown', value: 'unspecified' }];
    case 'fix_available':
      return [{ state: 'unknown', value: 'undetermined' }];
    default:
      return [];
  }
}

function evaluateReplacing<K extends FactorId>(
  background: Partial<PriorityFactInput>,
  factorId: K,
  fact: PriorityFactInput[K],
): PriorityEvaluation {
  return evaluateWith({ ...background, [factorId]: fact } as Partial<PriorityFactInput>);
}

function tokenPercent(factorId: NormalizedTokenFactorId, token: string): number {
  const table: Readonly<Record<string, number>> =
    BUILTIN_PRIORITY_POLICY_DEFINITION.normalization[factorId];
  const percent = table[token];
  if (percent === undefined) {
    throw new Error(`missing percent for ${factorId}`);
  }
  return percent;
}

function agePercent(days: number): number {
  let percent = 0;
  for (const bucket of BUILTIN_PRIORITY_POLICY_DEFINITION.normalization.finding_age_days) {
    if (days >= bucket.minDays) {
      percent = bucket.percent;
    }
  }
  return percent;
}

describe('priority properties', () => {
  it.each(BACKGROUNDS)(
    'M1 $name: replacing unknown or unavailable with an observed token never lowers priority',
    ({ name, facts }) => {
      for (const factorId of FACTOR_IDS) {
        const baselines = [BASE_FACTS[factorId], ...unknownFacts(factorId)];
        for (const baselineFact of baselines) {
          const missing = evaluateReplacing(facts, factorId, baselineFact);
          expectAccounting(missing);
          for (const observed of observedFacts(factorId)) {
            const present = evaluateReplacing(facts, factorId, observed);
            expectAccounting(present);
            expect(present.priority, `${name} ${factorId}`).toBeGreaterThanOrEqual(
              missing.priority,
            );
          }
        }
      }
    },
  );

  it.each(BACKGROUNDS)(
    'M2 $name: a token with a higher percent never lowers priority',
    ({ name, facts }) => {
      for (const factorId of NORMALIZED_TOKEN_FACTOR_IDS) {
        const scored = NORMALIZED_TOKEN_FACTORS[factorId].map((token) => {
          const observed = observedFacts(factorId).find((fact) => {
            if (fact.state !== 'observed') {
              return false;
            }
            if ('values' in fact) {
              return fact.values.length === 1 && fact.values[0] === token;
            }
            return 'value' in fact && fact.value === token;
          });
          if (observed === undefined) {
            throw new Error(`missing observed fact for ${factorId}`);
          }
          const result = evaluateReplacing(
            facts,
            factorId,
            observed as PriorityFactInput[typeof factorId],
          );
          expectAccounting(result);
          return { token, percent: tokenPercent(factorId, token), priority: result.priority };
        });
        for (const left of scored) {
          for (const right of scored) {
            if (left.percent > right.percent) {
              expect(
                left.priority,
                `${name} ${factorId} ${left.token} vs ${right.token}`,
              ).toBeGreaterThanOrEqual(right.priority);
            }
          }
        }
      }

      const ages = AGE_DAYS.map((days) => {
        const result = evaluateReplacing(facts, 'finding_age_days', {
          state: 'observed',
          value: days,
        });
        expectAccounting(result);
        return { days, percent: agePercent(days), priority: result.priority };
      });
      for (const left of ages) {
        for (const right of ages) {
          if (left.percent > right.percent) {
            expect(
              left.priority,
              `${name} age ${left.days} vs ${right.days}`,
            ).toBeGreaterThanOrEqual(right.priority);
          }
        }
      }
    },
  );

  it('M3 keeps contributions plus uplift equal to the rounded total', () => {
    const override = validatedDefinition({
      ...adrPolicyDefinitionInput(),
      weights: { ...OVERRIDE_OR_WEIGHTS },
    });
    const cases = [
      evaluateWith({}),
      evaluateWith(P3_FACTS),
      evaluateWith(B100_FACTS),
      evaluateWith(
        {
          source_severity: { state: 'observed', values: ['critical'] },
          business_criticality: { state: 'observed', value: 'high' },
          finding_age_days: { state: 'observed', value: 45 },
        },
        override,
      ),
      evaluateWith(
        {
          source_severity: { state: 'observed', values: ['high'] },
          kev_listed: { state: 'observed', value: 'listed_catalog_current' },
        },
        override,
      ),
    ];
    for (const result of cases) {
      expectAccounting(result);
    }
  });
});
