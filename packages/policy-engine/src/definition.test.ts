import { describe, expect, it } from 'vitest';

import { validatePolicyDefinition, type PolicyDefinitionIssue } from './definition.js';
import { adrPolicyDefinitionInput, withPath } from './test-helper.js';

function issuesOf(input: unknown): readonly PolicyDefinitionIssue[] {
  const result = validatePolicyDefinition(input);
  if (result.ok) {
    throw new Error('expected invalid_policy_definition');
  }
  expect(result.error.kind).toBe('invalid_policy_definition');
  return result.error.issues;
}

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

describe('validatePolicyDefinition', () => {
  it('accepts the ADR 0045 definition as a deep-frozen canonical copy', () => {
    const input = adrPolicyDefinitionInput();
    const result = validatePolicyDefinition(input);
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    expect(result.value).toEqual(input);
    expect(result.value).not.toBe(input);
    expect(Object.isFrozen(result.value)).toBe(true);
    expect(Object.isFrozen(result.value.normalization.finding_age_days[0])).toBe(true);
  });

  it('produces identical canonical output regardless of key order', () => {
    const forward = validatePolicyDefinition(adrPolicyDefinitionInput());
    const reversed = validatePolicyDefinition(reverseKeysDeep(adrPolicyDefinitionInput()));
    expect(forward.ok && reversed.ok).toBe(true);
    if (forward.ok && reversed.ok) {
      expect(JSON.stringify(reversed.value)).toBe(JSON.stringify(forward.value));
    }
  });

  it('leaves a frozen input unchanged', () => {
    const input = Object.freeze(adrPolicyDefinitionInput());
    const snapshot = structuredClone(input);
    expect(validatePolicyDefinition(input).ok).toBe(true);
    expect(input).toEqual(snapshot);
  });

  it('rejects the development-seed v1 shape as an unsupported schema version', () => {
    expect(
      issuesOf({
        schemaVersion: 1,
        policyKey: 'patchpilot.builtin.v0',
        factorCatalog: [],
        weights: {},
      }),
    ).toEqual([{ path: 'schemaVersion', code: 'unsupported_schema_version' }]);
  });

  it.each([null, [], 'definition'])('rejects a non-plain definition', (input) => {
    expect(issuesOf(input)).toEqual([{ path: '$', code: 'not_plain_object' }]);
  });

  const W = ['weights'] as const;
  const N = ['normalization'] as const;

  it.each([
    ['weight sum 99', [...W, 'finding_age_days'], 1, 'weights', 'weight_sum_not_100'],
    ['weight sum 101', [...W, 'finding_age_days'], 3, 'weights', 'weight_sum_not_100'],
    ['negative weight', [...W, 'fix_available'], -1, 'weights.fix_available', 'out_of_range'],
    ['fractional weight', [...W, 'fix_available'], 2.5, 'weights.fix_available', 'not_integer'],
    ['missing weight', [...W, 'fix_available'], undefined, 'weights.fix_available', 'missing_key'],
    ['string weight', [...W, 'fix_available'], '2', 'weights.fix_available', 'invalid_type'],
    [
      'NaN weight',
      [...W, 'fix_available'],
      Number.NaN,
      'weights.fix_available',
      'non_finite_number',
    ],
    [
      'Infinity percent',
      [...N, 'internet_exposure', 'internet_facing'],
      Number.POSITIVE_INFINITY,
      'normalization.internet_exposure.internet_facing',
      'non_finite_number',
    ],
    ['extra weight factor', [...W, 'compensating_control'], 0, 'weights', 'unknown_factor'],
    [
      'withdrawn weight 1',
      [...W, 'advisory_withdrawn'],
      1,
      'weights.advisory_withdrawn',
      'withdrawn_weight_not_zero',
    ],
    [
      'missing normalization token',
      [...N, 'direct_dependency', 'transitive'],
      undefined,
      'normalization.direct_dependency.transitive',
      'missing_token',
    ],
    [
      'extra normalization token',
      [...N, 'direct_dependency', 'optional'],
      0,
      'normalization.direct_dependency',
      'unknown_token',
    ],
    [
      'favorable extreme not zero',
      [...N, 'internet_exposure', 'internal'],
      10,
      'normalization.internet_exposure',
      'favorable_extreme_not_zero',
    ],
    [
      'percent 101',
      [...N, 'source_severity', 'critical'],
      101,
      'normalization.source_severity.critical',
      'out_of_range',
    ],
    [
      'percent 33.3',
      [...N, 'source_severity', 'low'],
      33.3,
      'normalization.source_severity.low',
      'not_integer',
    ],
    [
      'high above critical',
      [...N, 'source_severity', 'critical'],
      70,
      'normalization.source_severity',
      'percent_order_violation',
    ],
    [
      'age buckets not starting at zero',
      [...N, 'finding_age_days', 0, 'minDays'],
      1,
      'normalization.finding_age_days',
      'age_bucket_start_not_zero',
    ],
    [
      'age buckets not increasing',
      [...N, 'finding_age_days', 2, 'minDays'],
      30,
      'normalization.finding_age_days',
      'age_bucket_order_violation',
    ],
    [
      'age percents decreasing',
      [...N, 'finding_age_days', 2, 'percent'],
      40,
      'normalization.finding_age_days',
      'percent_order_violation',
    ],
    [
      'P2 threshold at P1',
      ['bands', 1, 'minPriority'],
      80,
      'bands',
      'band_threshold_order_violation',
    ],
    [
      'P2 threshold above P1',
      ['bands', 1, 'minPriority'],
      81,
      'bands',
      'band_threshold_order_violation',
    ],
    [
      'P4 minimum not zero',
      ['bands', 3, 'minPriority'],
      1,
      'bands',
      'lowest_band_minimum_not_zero',
    ],
    [
      'due days decreasing',
      ['bands', 2, 'dueDateRecommendationDays'],
      20,
      'bands',
      'due_days_order_violation',
    ],
    [
      'due days zero',
      ['bands', 0, 'dueDateRecommendationDays'],
      0,
      'bands[0].dueDateRecommendationDays',
      'out_of_range',
    ],
    [
      'due days above 3650',
      ['bands', 3, 'dueDateRecommendationDays'],
      3651,
      'bands[3].dueDateRecommendationDays',
      'out_of_range',
    ],
    ['band P0', ['bands', 0, 'band'], 'P0', 'bands[0].band', 'band_order_mismatch'],
    [
      'kevMinimumBand P0',
      ['rules', 'kevMinimumBand'],
      'P0',
      'rules.kevMinimumBand',
      'invalid_rule',
    ],
    [
      'kevEscalation changed',
      ['rules', 'kevEscalation'],
      'always',
      'rules.kevEscalation',
      'invalid_rule',
    ],
    ['unexpected top-level key', ['version'], 1, '$', 'unexpected_key'],
    [
      'engineContract mismatch',
      ['engineContract'],
      'other/1',
      'engineContract',
      'engine_contract_mismatch',
    ],
    ['invalid policyKey', ['policyKey'], 'Has Spaces', 'policyKey', 'invalid_policy_key'],
    [
      'control character in description',
      ['factorCatalog', 0, 'description'],
      'line\nbreak',
      'factorCatalog[0].description',
      'invalid_description',
    ],
  ] as const)('rejects %s', (_name, path, value, issuePath, code) => {
    expect(issuesOf(withPath(adrPolicyDefinitionInput(), path, value))).toContainEqual({
      path: issuePath,
      code,
    });
  });

  it('rejects an extra catalog factor', () => {
    const input = adrPolicyDefinitionInput();
    const catalog = [
      ...input.factorCatalog,
      { factorId: 'compensating_control', description: 'x' },
    ];
    expect(issuesOf({ ...input, factorCatalog: catalog })).toContainEqual({
      path: 'factorCatalog',
      code: 'unknown_factor',
    });
  });

  it('rejects a reordered catalog', () => {
    const input = adrPolicyDefinitionInput();
    const [first, second, ...rest] = input.factorCatalog;
    expect(issuesOf({ ...input, factorCatalog: [second, first, ...rest] })).toEqual([
      { path: 'factorCatalog', code: 'catalog_order_mismatch' },
    ]);
  });

  it('rejects a duplicate catalog entry', () => {
    const input = adrPolicyDefinitionInput();
    const [first, ...rest] = input.factorCatalog;
    expect(issuesOf({ ...input, factorCatalog: [first, first, ...rest.slice(1)] })).toContainEqual({
      path: 'factorCatalog',
      code: 'duplicate_factor',
    });
  });

  it('bounds catalog scanning', () => {
    const input = adrPolicyDefinitionInput();
    const oversized = Array.from({ length: 1000 }, () => input.factorCatalog[0]);
    expect(issuesOf({ ...input, factorCatalog: oversized })).toEqual([
      { path: 'factorCatalog', code: 'count_out_of_range' },
    ]);
  });

  it('never echoes unknown keys or values', () => {
    const marker = 'tenant-secret-marker';
    const input = withPath(adrPolicyDefinitionInput(), [marker], marker);
    const issues = issuesOf(withPath(input, ['policyKey'], marker.toUpperCase()));
    expect(JSON.stringify(issues).toLowerCase()).not.toContain(marker);
  });
});
