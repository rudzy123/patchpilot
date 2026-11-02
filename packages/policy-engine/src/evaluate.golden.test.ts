import { describe, expect, it } from 'vitest';

import {
  EXPLANATION_CODES,
  FACTOR_IDS,
  RULE_IDS,
  type EscalationReason,
  type FactorId,
  type PriorityBand,
  type RuleExplanationCode,
  type SeverityRating,
} from './catalog.js';
import { validatePolicyDefinition, type ValidatedPriorityPolicyDefinition } from './definition.js';
import { evaluatePriority, type PriorityEvaluation } from './evaluate.js';
import {
  parseFactInput,
  type ParsedPriorityFactInput,
  type PriorityFactInput,
  type SourceSeverityFact,
} from './facts.js';
import { adrPolicyDefinitionInput, factsWith, OVERRIDE_OR_WEIGHTS } from './test-helper.js';

function definition(weights?: typeof OVERRIDE_OR_WEIGHTS): ValidatedPriorityPolicyDefinition {
  const input = adrPolicyDefinitionInput();
  const result = validatePolicyDefinition(weights === undefined ? input : { ...input, weights });
  if (!result.ok) {
    throw new Error('test definition must validate');
  }
  return result.value;
}

const BUILTIN = definition();
const OR = definition(OVERRIDE_OR_WEIGHTS);

function parse(facts: PriorityFactInput): ParsedPriorityFactInput {
  const result = parseFactInput(facts);
  if (!result.ok) {
    throw new Error('test facts must parse');
  }
  return result.value;
}

function evaluate(
  overrides: Partial<PriorityFactInput>,
  policy: ValidatedPriorityPolicyDefinition = BUILTIN,
): PriorityEvaluation {
  const result = evaluatePriority(policy, parse(factsWith(overrides)));
  if (!result.ok) {
    throw new Error(`evaluation failed: ${result.error.kind}`);
  }
  return result.value;
}

/** M3: contributions plus uplift are the total, and priority is one half-up rounding. */
function expectAccounting(result: PriorityEvaluation): void {
  const contributions = result.factors.reduce((total, row) => total + row.contributionCenti, 0);
  expect(contributions).toBe(result.weightedScoreCenti);
  expect(result.rules[0]?.upliftCenti).toBe(result.upliftCenti);
  expect(result.rules[1]?.upliftCenti).toBe(0);
  expect(result.priority).toBe(
    Math.floor((result.weightedScoreCenti + result.upliftCenti + 50) / 100),
  );
}

function severity(...values: SeverityRating[]): SourceSeverityFact {
  return { state: 'observed', values };
}

const STATUS_LETTER = {
  decisive: 'D',
  contributing: 'C',
  non_contributing: 'N',
  informational: 'I',
} as const;

type StatusLetter = (typeof STATUS_LETTER)[keyof typeof STATUS_LETTER];

function statuses(result: PriorityEvaluation): Record<FactorId, StatusLetter> {
  return Object.fromEntries(
    result.factors.map((row) => [row.factorId, STATUS_LETTER[row.status]]),
  ) as Record<FactorId, StatusLetter>;
}

function expectedStatuses(
  changes: Partial<Record<FactorId, StatusLetter>>,
): Record<FactorId, StatusLetter> {
  const defaults = Object.fromEntries(
    FACTOR_IDS.map((factorId) => [factorId, factorId === 'advisory_withdrawn' ? 'I' : 'N']),
  ) as Record<FactorId, StatusLetter>;
  return { ...defaults, ...changes };
}

const P1_FACTS: Partial<PriorityFactInput> = {
  source_severity: severity('critical'),
  kev_listed: { state: 'observed', value: 'listed_catalog_current' },
  environment_sensitivity: { state: 'observed', value: 'production' },
  internet_exposure: { state: 'observed', value: 'internet_facing' },
};

const B59_FACTS: Partial<PriorityFactInput> = {
  source_severity: severity('critical'),
  environment_sensitivity: { state: 'observed', value: 'production' },
  business_criticality: { state: 'observed', value: 'high' },
  asset_data_classification: { state: 'observed', value: 'restricted' },
  kev_listed: { state: 'observed', value: 'not_listed_catalog_current' },
};

const B100_FACTS: Partial<PriorityFactInput> = {
  ...P1_FACTS,
  business_criticality: { state: 'observed', value: 'critical' },
  asset_data_classification: { state: 'observed', value: 'restricted' },
  direct_dependency: { state: 'observed', value: 'direct' },
  fix_available: { state: 'observed', value: 'available' },
  finding_age_days: { state: 'observed', value: 90 },
  advisory_withdrawn: { state: 'observed', value: 'not_withdrawn' },
};

const P3_FACTS: Partial<PriorityFactInput> = {
  source_severity: severity('critical'),
  kev_listed: { state: 'observed', value: 'not_listed_catalog_current' },
  environment_sensitivity: { state: 'observed', value: 'production' },
  internet_exposure: { state: 'unknown', value: 'unknown' },
};

type ReferenceCase = {
  readonly name: string;
  readonly facts: Partial<PriorityFactInput>;
  readonly policy?: ValidatedPriorityPolicyDefinition;
  readonly weighted?: number;
  readonly uplift?: number;
  readonly priority: number;
  readonly band: PriorityBand;
  readonly due: number;
  readonly reasons?: readonly EscalationReason[];
  readonly statuses?: Partial<Record<FactorId, StatusLetter>>;
  readonly rules?: readonly [RuleExplanationCode, RuleExplanationCode];
  readonly summary?: readonly [number, number, number];
};

const REFERENCE_CASES: readonly ReferenceCase[] = [
  {
    name: 'U1 all unavailable',
    facts: {},
    weighted: 0,
    uplift: 0,
    priority: 0,
    band: 'P4',
    due: 180,
    statuses: {},
    rules: ['kev_minimum_band_not_triggered', 'kev_escalation_not_triggered'],
    summary: [0, 0, 10],
  },
  {
    name: 'P1 sketch Finding A',
    facts: P1_FACTS,
    weighted: 8000,
    uplift: 0,
    priority: 80,
    band: 'P1',
    due: 7,
    reasons: ['kev_production', 'kev_internet_facing'],
    statuses: {
      source_severity: 'D',
      kev_listed: 'D',
      environment_sensitivity: 'D',
      internet_exposure: 'D',
    },
    rules: ['kev_minimum_band_already_met', 'kev_escalation_recommended'],
  },
  {
    name: 'P2 boundary 60 and E3 no escalation without KEV',
    facts: {
      ...P1_FACTS,
      kev_listed: { state: 'observed', value: 'not_listed_catalog_current' },
    },
    priority: 60,
    band: 'P2',
    due: 30,
    statuses: { source_severity: 'D', environment_sensitivity: 'D', internet_exposure: 'D' },
    rules: ['kev_minimum_band_not_triggered', 'kev_escalation_not_triggered'],
  },
  {
    name: 'P3 sketch Finding B',
    facts: P3_FACTS,
    priority: 50,
    band: 'P3',
    due: 90,
    statuses: { source_severity: 'D', environment_sensitivity: 'C' },
    summary: [3, 1, 6],
  },
  {
    name: 'P4 full observed context',
    facts: {
      source_severity: severity('medium'),
      kev_listed: { state: 'observed', value: 'not_listed_catalog_current' },
      environment_sensitivity: { state: 'observed', value: 'non_production' },
      internet_exposure: { state: 'observed', value: 'internal' },
      business_criticality: { state: 'observed', value: 'low' },
      asset_data_classification: { state: 'observed', value: 'public' },
      direct_dependency: { state: 'observed', value: 'transitive' },
      fix_available: { state: 'observed', value: 'available' },
      finding_age_days: { state: 'observed', value: 10 },
      advisory_withdrawn: { state: 'observed', value: 'not_withdrawn' },
    },
    priority: 22,
    band: 'P4',
    due: 180,
    statuses: { source_severity: 'C', fix_available: 'C' },
    summary: [10, 0, 0],
  },
  {
    name: 'B79',
    facts: {
      source_severity: severity('critical'),
      kev_listed: { state: 'observed', value: 'listed_catalog_current' },
      environment_sensitivity: { state: 'observed', value: 'production' },
      business_criticality: { state: 'observed', value: 'high' },
      asset_data_classification: { state: 'observed', value: 'restricted' },
    },
    priority: 79,
    band: 'P2',
    due: 30,
    reasons: ['kev_production'],
    statuses: {
      source_severity: 'C',
      kev_listed: 'D',
      environment_sensitivity: 'D',
      business_criticality: 'C',
      asset_data_classification: 'C',
    },
  },
  {
    name: 'B59',
    facts: B59_FACTS,
    priority: 59,
    band: 'P3',
    due: 90,
    statuses: {
      source_severity: 'D',
      environment_sensitivity: 'C',
      business_criticality: 'C',
      asset_data_classification: 'C',
    },
  },
  {
    name: 'B40',
    facts: { source_severity: severity('critical') },
    priority: 40,
    band: 'P3',
    due: 90,
    statuses: { source_severity: 'D' },
  },
  {
    name: 'B39',
    facts: {
      source_severity: severity('high'),
      business_criticality: { state: 'observed', value: 'critical' },
      finding_age_days: { state: 'observed', value: 30 },
    },
    priority: 39,
    band: 'P4',
    due: 180,
    statuses: { source_severity: 'C', business_criticality: 'C', finding_age_days: 'C' },
  },
  {
    name: 'B100',
    facts: B100_FACTS,
    weighted: 10000,
    priority: 100,
    band: 'P1',
    due: 7,
    reasons: ['kev_production', 'kev_internet_facing'],
    statuses: {
      source_severity: 'D',
      kev_listed: 'D',
      environment_sensitivity: 'C',
      internet_exposure: 'C',
      business_criticality: 'C',
      asset_data_classification: 'C',
      direct_dependency: 'C',
      fix_available: 'C',
      finding_age_days: 'C',
    },
    summary: [10, 0, 0],
  },
  {
    name: 'R1 half-up crosses P3',
    policy: OR,
    facts: {
      source_severity: severity('critical'),
      business_criticality: { state: 'observed', value: 'high' },
      finding_age_days: { state: 'observed', value: 45 },
    },
    weighted: 3950,
    priority: 40,
    band: 'P3',
    due: 90,
    statuses: { source_severity: 'D', business_criticality: 'D', finding_age_days: 'D' },
  },
  {
    name: 'R2',
    policy: OR,
    facts: {
      source_severity: severity('critical'),
      business_criticality: { state: 'observed', value: 'high' },
    },
    weighted: 3850,
    priority: 39,
    band: 'P4',
    due: 180,
    statuses: { source_severity: 'C', business_criticality: 'C' },
  },
  {
    name: 'R3 below one half rounds down',
    policy: OR,
    facts: { source_severity: severity('high') },
    weighted: 2625,
    priority: 26,
    band: 'P4',
    due: 180,
    statuses: { source_severity: 'C' },
  },
  {
    name: 'R4 floor uplift under override',
    policy: OR,
    facts: {
      source_severity: severity('high'),
      kev_listed: { state: 'observed', value: 'listed_catalog_current' },
    },
    weighted: 5125,
    uplift: 875,
    priority: 60,
    band: 'P2',
    due: 30,
    statuses: { source_severity: 'C', kev_listed: 'D' },
    rules: ['kev_minimum_band_raised', 'kev_escalation_context_not_observed'],
  },
  {
    name: 'K9 floor raise',
    facts: {
      source_severity: severity('low'),
      kev_listed: { state: 'observed', value: 'listed_catalog_current' },
    },
    weighted: 3000,
    uplift: 3000,
    priority: 60,
    band: 'P2',
    due: 30,
    statuses: { source_severity: 'C', kev_listed: 'D' },
    rules: ['kev_minimum_band_raised', 'kev_escalation_context_not_observed'],
  },
  {
    name: 'K10 KEV only',
    facts: { kev_listed: { state: 'observed', value: 'listed_catalog_current' } },
    weighted: 2000,
    uplift: 4000,
    priority: 60,
    band: 'P2',
    due: 30,
    statuses: { kev_listed: 'D' },
  },
  {
    name: 'E1 internet-facing escalation',
    facts: {
      source_severity: severity('high'),
      kev_listed: { state: 'observed', value: 'listed_catalog_current' },
      environment_sensitivity: { state: 'observed', value: 'non_production' },
      internet_exposure: { state: 'observed', value: 'internet_facing' },
    },
    priority: 60,
    band: 'P2',
    due: 30,
    reasons: ['kev_internet_facing'],
    statuses: { internet_exposure: 'D', kev_listed: 'D', source_severity: 'C' },
  },
  {
    name: 'E2 context not observed',
    facts: {
      source_severity: severity('critical'),
      kev_listed: { state: 'observed', value: 'listed_catalog_current' },
      internet_exposure: { state: 'unknown', value: 'unknown' },
    },
    priority: 60,
    band: 'P2',
    due: 30,
    statuses: { source_severity: 'C', kev_listed: 'D' },
    rules: ['kev_minimum_band_already_met', 'kev_escalation_context_not_observed'],
  },
  {
    name: 'F5 fix decides a band',
    facts: { ...B59_FACTS, fix_available: { state: 'observed', value: 'available' } },
    priority: 61,
    band: 'P2',
    due: 30,
    statuses: {
      source_severity: 'D',
      environment_sensitivity: 'D',
      business_criticality: 'D',
      asset_data_classification: 'D',
      fix_available: 'D',
    },
  },
];

describe('evaluatePriority reference cases', () => {
  it.each(REFERENCE_CASES)('$name', (testCase) => {
    const result = evaluate(testCase.facts, testCase.policy);
    expect(result.priority).toBe(testCase.priority);
    expect(result.priorityBand).toBe(testCase.band);
    expect(result.dueDateRecommendationDays).toBe(testCase.due);
    expect(result.escalation).toEqual({
      recommended: (testCase.reasons ?? []).length > 0,
      reasons: testCase.reasons ?? [],
    });
    if (testCase.weighted !== undefined) {
      expect(result.weightedScoreCenti).toBe(testCase.weighted);
    }
    if (testCase.uplift !== undefined) {
      expect(result.upliftCenti).toBe(testCase.uplift);
    }
    if (testCase.statuses !== undefined) {
      expect(statuses(result)).toEqual(expectedStatuses(testCase.statuses));
    }
    if (testCase.rules !== undefined) {
      expect(result.rules.map((rule) => rule.explanationCode)).toEqual(testCase.rules);
    }
    if (testCase.summary !== undefined) {
      const [observed, unknown, unavailable] = testCase.summary;
      expect(result.evidenceSummary).toEqual({ observed, unknown, unavailable });
    }
  });

  it.each(REFERENCE_CASES)('$name keeps the arithmetic and row invariants', (testCase) => {
    const result = evaluate(testCase.facts, testCase.policy);
    expectAccounting(result);
    expect(result.factors.map((row) => row.factorId)).toEqual([...FACTOR_IDS]);
    expect(result.factors.map((row) => row.ordinal)).toEqual(FACTOR_IDS.map((_, i) => i + 1));
    expect(result.rules.map((rule) => rule.ruleId)).toEqual([...RULE_IDS]);
    for (const row of result.factors) {
      expect(EXPLANATION_CODES).toContain(row.explanationCode);
      expect(row.contributionCenti).toBe(row.weight * row.normalizedPercent);
    }
  });
});

describe('evaluatePriority KEV states', () => {
  const background: Partial<PriorityFactInput> = {
    source_severity: severity('critical'),
    environment_sensitivity: { state: 'observed', value: 'production' },
  };

  it.each([
    ['listed_catalog_current', 'kev_listed_catalog_current'],
    ['listed_catalog_stale', 'kev_listed_catalog_stale'],
    ['listed_catalog_disabled_with_history', 'kev_listed_catalog_disabled_with_history'],
  ] as const)('counts %s as listed', (value, code) => {
    const result = evaluate({ ...background, kev_listed: { state: 'observed', value } });
    expectAccounting(result);
    expect(result.priority).toBe(70);
    expect(result.priorityBand).toBe('P2');
    expect(result.dueDateRecommendationDays).toBe(30);
    expect(result.escalation.reasons).toEqual(['kev_production']);
    expect(result.factors[1]).toMatchObject({ inputState: 'observed', explanationCode: code });
  });

  it.each([
    [
      { state: 'observed', value: 'not_listed_catalog_current' },
      'observed',
      'kev_not_listed_catalog_current',
    ],
    [{ state: 'unknown', value: 'absent_catalog_stale' }, 'unknown', 'kev_absent_catalog_stale'],
    [
      { state: 'unknown', value: 'absent_catalog_disabled_with_history' },
      'unknown',
      'kev_absent_catalog_disabled_with_history',
    ],
    [
      { state: 'unavailable', reason: 'no_canonical_cve' },
      'unavailable',
      'kev_unavailable_no_canonical_cve',
    ],
    [
      { state: 'unavailable', reason: 'no_active_generation' },
      'unavailable',
      'kev_unavailable_no_active_generation',
    ],
  ] as const)('treats %o as not listed', (fact, inputState, code) => {
    const result = evaluate({ ...background, kev_listed: fact });
    expectAccounting(result);
    expect(result.priority).toBe(50);
    expect(result.priorityBand).toBe('P3');
    expect(result.dueDateRecommendationDays).toBe(90);
    expect(result.escalation.recommended).toBe(false);
    expect(result.factors[1]).toMatchObject({
      inputState,
      explanationCode: code,
      contributionCenti: 0,
    });
  });
});

describe('evaluatePriority withdrawn advisory', () => {
  it('W1 flags withdrawal without changing any other output', () => {
    const base = evaluate(P1_FACTS);
    const withdrawn = evaluate({
      ...P1_FACTS,
      advisory_withdrawn: { state: 'observed', value: 'withdrawn' },
    });
    expectAccounting(withdrawn);
    expect(withdrawn.weightedScoreCenti).toBe(base.weightedScoreCenti);
    expect(withdrawn.upliftCenti).toBe(base.upliftCenti);
    expect(withdrawn.priority).toBe(base.priority);
    expect(withdrawn.priorityBand).toBe(base.priorityBand);
    expect(withdrawn.dueDateRecommendationDays).toBe(base.dueDateRecommendationDays);
    expect(withdrawn.escalation).toEqual(base.escalation);
    expect(withdrawn.rules).toEqual(base.rules);
    expect(withdrawn.factors.slice(0, 9)).toEqual(base.factors.slice(0, 9));
    expect(withdrawn.factors[9]).toMatchObject({
      status: 'informational',
      inputState: 'observed',
      observedValue: 'withdrawn',
      normalizedPercent: 0,
      contributionCenti: 0,
      explanationCode: 'advisory_withdrawn_review_required',
    });
    expect(withdrawn.evidenceSummary).toEqual({ observed: 5, unknown: 0, unavailable: 5 });
  });

  it.each([
    [{ state: 'observed', value: 'not_withdrawn' }, 'advisory_not_withdrawn'],
    [{ state: 'unavailable' }, 'advisory_withdrawal_unavailable'],
  ] as const)('codes %o', (fact, code) => {
    const result = evaluate({ advisory_withdrawn: fact });
    expectAccounting(result);
    expect(result.factors[9]?.explanationCode).toBe(code);
  });
});

describe('evaluatePriority per-factor values', () => {
  const medium = { source_severity: severity('medium') };

  it.each([
    [{ state: 'observed', value: 'available' }, 22, 'fix_available'],
    [{ state: 'observed', value: 'not_available' }, 20, 'fix_not_available'],
    [{ state: 'unknown', value: 'undetermined' }, 20, 'fix_undetermined'],
    [{ state: 'unavailable' }, 20, 'fix_unavailable'],
  ] as const)('fix %o', (fact, priority, code) => {
    const result = evaluate({ ...medium, fix_available: fact });
    expectAccounting(result);
    expect(result.priority).toBe(priority);
    expect(result.priorityBand).toBe('P4');
    expect(result.dueDateRecommendationDays).toBe(180);
    expect(result.escalation.recommended).toBe(false);
    expect(result.factors[7]?.explanationCode).toBe(code);
  });

  it.each([
    [0, 20, 'age_under_30_days'],
    [29, 20, 'age_under_30_days'],
    [30, 21, 'age_30_to_89_days'],
    [89, 21, 'age_30_to_89_days'],
    [90, 22, 'age_90_days_or_more'],
    [36500, 22, 'age_90_days_or_more'],
  ] as const)('age %i days', (days, priority, code) => {
    const result = evaluate({ ...medium, finding_age_days: { state: 'observed', value: days } });
    expectAccounting(result);
    expect(result.priority).toBe(priority);
    expect(result.priorityBand).toBe('P4');
    expect(result.factors[8]).toMatchObject({ observedValue: days, explanationCode: code });
  });

  const tokenCases: readonly [FactorId, Partial<PriorityFactInput>[FactorId], number][] = [
    ['direct_dependency', { state: 'observed', value: 'direct' }, 23],
    ['direct_dependency', { state: 'observed', value: 'transitive' }, 20],
    ['direct_dependency', { state: 'unavailable' }, 20],
    ['environment_sensitivity', { state: 'observed', value: 'production' }, 30],
    ['environment_sensitivity', { state: 'observed', value: 'non_production' }, 20],
    ['environment_sensitivity', { state: 'unavailable' }, 20],
    ['internet_exposure', { state: 'observed', value: 'internet_facing' }, 30],
    ['internet_exposure', { state: 'observed', value: 'internal' }, 20],
    ['internet_exposure', { state: 'unknown', value: 'unknown' }, 20],
    ['internet_exposure', { state: 'unavailable' }, 20],
    ['business_criticality', { state: 'observed', value: 'critical' }, 28],
    ['business_criticality', { state: 'observed', value: 'high' }, 24],
    ['business_criticality', { state: 'observed', value: 'medium' }, 22],
    ['business_criticality', { state: 'observed', value: 'low' }, 20],
    ['business_criticality', { state: 'unknown', value: 'unspecified' }, 20],
    ['business_criticality', { state: 'unavailable' }, 20],
    ['asset_data_classification', { state: 'observed', value: 'restricted' }, 25],
    ['asset_data_classification', { state: 'observed', value: 'confidential' }, 23],
    ['asset_data_classification', { state: 'observed', value: 'internal' }, 21],
    ['asset_data_classification', { state: 'observed', value: 'public' }, 20],
    ['asset_data_classification', { state: 'unknown', value: 'unspecified' }, 20],
    ['asset_data_classification', { state: 'unavailable' }, 20],
  ];

  it.each(tokenCases)('%s %o', (factorId, fact, priority) => {
    const result = evaluate({ ...medium, [factorId]: fact });
    expectAccounting(result);
    expect(result.priority).toBe(priority);
    expect(result.priorityBand).toBe('P4');
    expect(result.escalation.recommended).toBe(false);
  });

  it.each([
    [severity('critical'), 40, 'P3'],
    [severity('high'), 30, 'P4'],
    [severity('medium'), 20, 'P4'],
    [severity('low'), 10, 'P4'],
    [severity('none'), 0, 'P4'],
    [{ state: 'unknown', value: 'unrated' }, 0, 'P4'],
    [{ state: 'unavailable' }, 0, 'P4'],
  ] as const)('severity alone %o', (fact, priority, band) => {
    const result = evaluate({ source_severity: fact });
    expectAccounting(result);
    expect(result.priority).toBe(priority);
    expect(result.priorityBand).toBe(band);
  });

  it('aggregates severity to the highest rating under any permutation', () => {
    const ratings = ['low', 'critical', 'medium'] as const;
    const permutations: SeverityRating[][] = [];
    for (const first of ratings) {
      for (const second of ratings) {
        if (second === first) {
          continue;
        }
        const third = ratings.find((rating) => rating !== first && rating !== second);
        if (third !== undefined) {
          permutations.push([first, second, third]);
        }
      }
    }
    expect(permutations).toHaveLength(6);
    const results = permutations.map((values) =>
      evaluate({ source_severity: severity(...values) }),
    );
    for (const result of results) {
      expectAccounting(result);
      expect(result.priority).toBe(40);
      expect(result.factors[0]).toMatchObject({
        observedValue: 'critical',
        explanationCode: 'severity_critical',
      });
      expect(result).toEqual(results[0]);
    }
  });
});
