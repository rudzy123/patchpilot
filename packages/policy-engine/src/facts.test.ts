import { describe, expect, it } from 'vitest';

import { FACTOR_IDS } from './catalog.js';
import { parseFactInput, type FactInputIssue } from './facts.js';
import { BASE_FACTS, factsWith, withPath } from './test-helper.js';

function issuesOf(input: unknown): readonly FactInputIssue[] {
  const result = parseFactInput(input);
  if (result.ok) {
    throw new Error('expected invalid_fact_input');
  }
  expect(result.error.kind).toBe('invalid_fact_input');
  return result.error.issues;
}

describe('parseFactInput', () => {
  it('accepts the all-unavailable base input as a deep-frozen canonical copy', () => {
    const result = parseFactInput(structuredClone(BASE_FACTS));
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    expect(result.value).toEqual(BASE_FACTS);
    expect(Object.keys(result.value)).toEqual([...FACTOR_IDS]);
    expect(Object.isFrozen(result.value)).toBe(true);
    expect(Object.isFrozen(result.value.kev_listed)).toBe(true);
  });

  it('accepts every observed and unknown shape', () => {
    const result = parseFactInput(
      factsWith({
        source_severity: { state: 'observed', values: ['low', 'critical'] },
        kev_listed: { state: 'unknown', value: 'absent_catalog_stale' },
        environment_sensitivity: { state: 'observed', value: 'production' },
        internet_exposure: { state: 'unknown', value: 'unknown' },
        business_criticality: { state: 'unknown', value: 'unspecified' },
        asset_data_classification: { state: 'observed', value: 'restricted' },
        direct_dependency: { state: 'observed', value: 'transitive' },
        fix_available: { state: 'unknown', value: 'undetermined' },
        finding_age_days: { state: 'observed', value: 36500 },
        advisory_withdrawn: { state: 'observed', value: 'withdrawn' },
      }),
    );
    expect(result.ok).toBe(true);
  });

  it('does not depend on input key order', () => {
    const reversed = Object.fromEntries(Object.entries(BASE_FACTS).reverse());
    const result = parseFactInput(reversed);
    expect(result.ok && Object.keys(result.value)).toEqual([...FACTOR_IDS]);
  });

  it('leaves a frozen input unchanged', () => {
    const input = Object.freeze(structuredClone(BASE_FACTS));
    const snapshot = structuredClone(input);
    expect(parseFactInput(input).ok).toBe(true);
    expect(input).toEqual(snapshot);
  });

  it.each([null, [], 'facts', 7, new Map(), Object.create({ inherited: true })])(
    'rejects a non-plain top-level input',
    (input) => {
      expect(issuesOf(input)).toEqual([{ factorId: null, code: 'facts_not_plain_object' }]);
    },
  );

  it('rejects a missing factor', () => {
    expect(issuesOf(withPath(BASE_FACTS, ['fix_available'], undefined))).toEqual([
      { factorId: 'fix_available', code: 'missing_factor' },
    ]);
  });

  it.each(['compensating_control', 'remediation_task_status'])(
    'rejects the extra factor %s without echoing its name',
    (key) => {
      const issues = issuesOf({ ...BASE_FACTS, [key]: { state: 'unavailable' } });
      expect(issues).toEqual([{ factorId: null, code: 'unknown_factor' }]);
      expect(JSON.stringify(issues)).not.toContain(key);
    },
  );

  it.each([
    ['bad state', { kev_listed: { state: 'maybe' } }, 'kev_listed', 'invalid_state'],
    ['missing state', { kev_listed: {} }, 'kev_listed', 'missing_state'],
    [
      'environment unknown',
      { environment_sensitivity: { state: 'unknown', value: 'unknown' } },
      'environment_sensitivity',
      'state_not_accepted',
    ],
    [
      'severity moderate',
      { source_severity: { state: 'observed', values: ['moderate'] } },
      'source_severity',
      'invalid_value',
    ],
    [
      'observed with no value',
      { internet_exposure: { state: 'observed' } },
      'internet_exposure',
      'missing_value',
    ],
    [
      'unavailable with a value',
      { internet_exposure: { state: 'unavailable', value: 'internal' } },
      'internet_exposure',
      'unexpected_property',
    ],
    [
      'exposure unknown maybe',
      { internet_exposure: { state: 'unknown', value: 'maybe' } },
      'internet_exposure',
      'invalid_value',
    ],
    [
      'bad KEV reason',
      { kev_listed: { state: 'unavailable', reason: 'feed_down' } },
      'kev_listed',
      'invalid_reason',
    ],
    [
      'missing KEV reason',
      { kev_listed: { state: 'unavailable' } },
      'kev_listed',
      'missing_reason',
    ],
    [
      'dependency as string true',
      { direct_dependency: { state: 'observed', value: 'true' } },
      'direct_dependency',
      'invalid_value',
    ],
    [
      'dependency as boolean',
      { direct_dependency: { state: 'observed', value: true } },
      'direct_dependency',
      'invalid_value',
    ],
    [
      'extra property inside a factor',
      { fix_available: { state: 'observed', value: 'available', note: 'x' } },
      'fix_available',
      'unexpected_property',
    ],
    [
      'empty severity values',
      { source_severity: { state: 'observed', values: [] } },
      'source_severity',
      'values_count_out_of_range',
    ],
    [
      'seventeen severity values',
      { source_severity: { state: 'observed', values: Array(17).fill('low') } },
      'source_severity',
      'values_count_out_of_range',
    ],
    [
      'severity value instead of values',
      { source_severity: { state: 'observed', value: 'critical' } },
      'source_severity',
      'missing_value',
    ],
    [
      'factor as null',
      { advisory_withdrawn: null },
      'advisory_withdrawn',
      'factor_not_plain_object',
    ],
    [
      'factor as array',
      { advisory_withdrawn: [] },
      'advisory_withdrawn',
      'factor_not_plain_object',
    ],
  ] as const)('rejects %s', (_name, overrides, factorId, code) => {
    expect(issuesOf({ ...BASE_FACTS, ...overrides })).toContainEqual({ factorId, code });
  });

  it.each([
    [-1, 'value_out_of_range'],
    [36501, 'value_out_of_range'],
    [1.5, 'value_not_integer'],
    [Number.NaN, 'value_not_integer'],
    [Number.POSITIVE_INFINITY, 'value_not_integer'],
    ['30', 'invalid_value'],
  ] as const)('rejects age %s', (value, code) => {
    expect(
      issuesOf(factsWith({ finding_age_days: { state: 'observed', value: value as number } })),
    ).toEqual([{ factorId: 'finding_age_days', code }]);
  });

  it('rejects accessor properties so validation cannot observe changing values', () => {
    const factor = {};
    Object.defineProperty(factor, 'state', { enumerable: true, get: () => 'unavailable' });
    expect(issuesOf({ ...BASE_FACTS, fix_available: factor })).toEqual([
      { factorId: 'fix_available', code: 'factor_not_plain_object' },
    ]);
  });

  it('orders issues by catalog ordinal then code, with unknown factors last', () => {
    const issues = issuesOf({
      ...BASE_FACTS,
      advisory_withdrawn: { state: 'bogus' },
      extra_factor: {},
      source_severity: { state: 'observed', values: ['nope'], value: 'x' },
    });
    expect(issues).toEqual([
      { factorId: 'source_severity', code: 'invalid_value' },
      { factorId: 'source_severity', code: 'unexpected_property' },
      { factorId: 'advisory_withdrawn', code: 'invalid_state' },
      { factorId: null, code: 'unknown_factor' },
    ]);
  });

  it('never echoes rejected values', () => {
    const marker = 'tenant-secret-marker';
    const issues = issuesOf({
      ...BASE_FACTS,
      internet_exposure: { state: 'observed', value: marker },
      [marker]: marker,
    });
    expect(JSON.stringify(issues)).not.toContain(marker);
  });
});
