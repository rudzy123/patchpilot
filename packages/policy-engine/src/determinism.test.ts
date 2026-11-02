import { afterEach, describe, expect, it, vi } from 'vitest';

import { canonicalJson } from './canonical-json.js';
import { ESCALATION_REASONS, FACTOR_IDS, RULE_IDS } from './catalog.js';
import { deepFreeze } from './deep-freeze.js';
import { validatePolicyDefinition, type ValidatedPriorityPolicyDefinition } from './definition.js';
import { evaluatePriority, type PriorityEvaluation } from './evaluate.js';
import { parseFactInput, type ParsedPriorityFactInput, type PriorityFactInput } from './facts.js';
import {
  adrPolicyDefinitionInput,
  BASE_FACTS,
  evaluateWith,
  factsWith,
  validatedDefinition,
} from './test-helper.js';

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

function reverseKeysDeep(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(reverseKeysDeep);
  }
  if (typeof value === 'object' && value !== null) {
    return Object.fromEntries(
      Object.entries(value)
        .reverse()
        .map(([key, entry]) => [key, reverseKeysDeep(entry)]),
    );
  }
  return value;
}

function mustParse(input: unknown): ParsedPriorityFactInput {
  const result = parseFactInput(input);
  if (!result.ok) {
    throw new Error('facts must parse');
  }
  return result.value;
}

function mustValidate(input: unknown): ValidatedPriorityPolicyDefinition {
  const result = validatePolicyDefinition(input);
  if (!result.ok) {
    throw new Error('definition must validate');
  }
  return result.value;
}

function mustEvaluate(
  definition: ValidatedPriorityPolicyDefinition,
  facts: ParsedPriorityFactInput,
): PriorityEvaluation {
  const result = evaluatePriority(definition, facts);
  if (!result.ok) {
    throw new Error(`evaluation failed: ${result.error.kind}`);
  }
  return result.value;
}

function canonical(value: PriorityEvaluation): string {
  const encoded = canonicalJson(value);
  if (!encoded.ok) {
    throw new Error(`canonical JSON failed: ${encoded.error.code}`);
  }
  return encoded.value;
}

describe('evaluation determinism', () => {
  it('DT1 repeats one evaluation 100 times with byte-identical canonical JSON', () => {
    const definition = validatedDefinition();
    const facts = mustParse(factsWith(B100_FACTS));
    const first = mustEvaluate(definition, facts);
    const encoded = canonical(first);
    for (let index = 0; index < 100; index += 1) {
      const next = mustEvaluate(definition, facts);
      expect(next).toEqual(first);
      expect(canonical(next)).toBe(encoded);
    }
  });

  it('DT2 ignores key order in the facts and the definition', () => {
    const forward = mustEvaluate(
      mustValidate(adrPolicyDefinitionInput()),
      mustParse(factsWith(B100_FACTS)),
    );
    const reversed = mustEvaluate(
      mustValidate(reverseKeysDeep(adrPolicyDefinitionInput())),
      mustParse(reverseKeysDeep(factsWith(B100_FACTS))),
    );
    expect(reversed).toEqual(forward);
    expect(canonical(reversed)).toBe(canonical(forward));
    expect(reversed.factors.map((row) => row.factorId)).toEqual([...FACTOR_IDS]);
    expect(reversed.escalation.reasons).toEqual([...ESCALATION_REASONS]);
  });

  describe('DT3 without a clock or randomness', () => {
    afterEach(() => {
      vi.unstubAllGlobals();
      vi.restoreAllMocks();
    });

    it('evaluates when Date, Date.now, and Math.random throw', () => {
      const definition = validatedDefinition();
      const facts = mustParse(factsWith(B100_FACTS));
      const expected = mustEvaluate(definition, facts);
      const throwing = (): never => {
        throw new Error('clock or randomness read');
      };
      vi.spyOn(Date, 'now').mockImplementation(throwing);
      vi.spyOn(Math, 'random').mockImplementation(throwing);
      vi.stubGlobal('Date', throwing);
      const result = evaluatePriority(definition, facts);
      expect(result.ok && result.value).toEqual(expected);
    });
  });

  it('DT4 and DT5 accept deep-frozen facts and definitions and leave them unchanged', () => {
    const rawFacts = deepFreeze(structuredClone(factsWith(B100_FACTS)));
    const rawDefinition = deepFreeze(structuredClone(adrPolicyDefinitionInput()));
    const factsSnapshot = structuredClone(rawFacts);
    const definitionSnapshot = structuredClone(rawDefinition);
    const facts = mustParse(rawFacts);
    const definition = mustValidate(rawDefinition);
    expect(rawFacts).toEqual(factsSnapshot);
    expect(rawDefinition).toEqual(definitionSnapshot);
    const parsedSnapshot = structuredClone(facts);
    const validatedSnapshot = structuredClone(definition);
    const result = mustEvaluate(definition, facts);
    expect(facts).toEqual(parsedSnapshot);
    expect(definition).toEqual(validatedSnapshot);
    expect(Object.isFrozen(rawFacts)).toBe(true);
    expect(Object.isFrozen(rawFacts.kev_listed)).toBe(true);
    expect(Object.isFrozen(rawDefinition)).toBe(true);
    expect(Object.isFrozen(rawDefinition.normalization.finding_age_days[0])).toBe(true);
    expect(Object.isFrozen(facts)).toBe(true);
    expect(Object.isFrozen(definition)).toBe(true);
    expect(result.priority).toBe(100);
  });

  it('DT6 returns a deep-frozen result with no tenant identifiers', () => {
    const result = evaluateWith(B100_FACTS);
    expect(Object.isFrozen(result)).toBe(true);
    expect(Object.isFrozen(result.factors)).toBe(true);
    expect(Object.isFrozen(result.factors[0])).toBe(true);
    expect(Object.isFrozen(result.rules)).toBe(true);
    expect(Object.isFrozen(result.escalation)).toBe(true);
    expect(Object.isFrozen(result.escalation.reasons)).toBe(true);
    expect(Object.isFrozen(result.evidenceSummary)).toBe(true);
    expect(Object.keys(result).sort()).toEqual(
      [
        'dueDateRecommendationDays',
        'engineVersion',
        'escalation',
        'evidenceSummary',
        'factors',
        'policyKey',
        'priority',
        'priorityBand',
        'rules',
        'upliftCenti',
        'weightedScoreCenti',
      ].sort(),
    );
    expect(JSON.stringify(result)).not.toMatch(
      /organization|findingId|assetId|component|userId|secret/i,
    );
  });

  it('DT7 keeps factor rows, rule rows, and escalation reasons in fixed order', () => {
    const both = evaluateWith(B100_FACTS);
    expect(both.factors).toHaveLength(10);
    expect(both.factors.map((row) => row.factorId)).toEqual([...FACTOR_IDS]);
    expect(both.factors.map((row) => row.ordinal)).toEqual(FACTOR_IDS.map((_, index) => index + 1));
    expect(both.rules).toHaveLength(2);
    expect(both.rules.map((rule) => rule.ruleId)).toEqual([...RULE_IDS]);
    expect(both.escalation.reasons).toEqual([...ESCALATION_REASONS]);

    const internetOnly = evaluateWith({
      kev_listed: { state: 'observed', value: 'listed_catalog_current' },
      internet_exposure: { state: 'observed', value: 'internet_facing' },
      environment_sensitivity: { state: 'observed', value: 'non_production' },
    });
    expect(internetOnly.rules.map((rule) => rule.ruleId)).toEqual([...RULE_IDS]);
    expect(internetOnly.escalation.reasons).toEqual(['kev_internet_facing']);

    const none = evaluateWith({});
    expect(none.factors).toHaveLength(10);
    expect(none.rules.map((rule) => rule.ruleId)).toEqual([...RULE_IDS]);
    expect(none.escalation.reasons).toEqual([]);
  });

  it('DT8 rejects an unvalidated definition and unparsed facts at runtime', () => {
    const forgedDefinition = adrPolicyDefinitionInput() as ValidatedPriorityPolicyDefinition;
    const parsed = mustParse(BASE_FACTS);
    expect(evaluatePriority(forgedDefinition, parsed)).toEqual({
      ok: false,
      error: {
        kind: 'invalid_policy_definition',
        issues: [{ path: '$', code: 'definition_not_validated' }],
      },
    });

    const forgedFacts = structuredClone(BASE_FACTS) as ParsedPriorityFactInput;
    expect(evaluatePriority(validatedDefinition(), forgedFacts)).toEqual({
      ok: false,
      error: {
        kind: 'invalid_fact_input',
        issues: [{ factorId: null, code: 'facts_not_parsed' }],
      },
    });
  });

  it('DT8 rejects an unbranded definition at compile time', () => {
    const facts = mustParse(BASE_FACTS);
    // @ts-expect-error the definition must come from validatePolicyDefinition
    evaluatePriority(adrPolicyDefinitionInput(), facts);
  });
});
