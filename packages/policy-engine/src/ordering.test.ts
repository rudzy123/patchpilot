import { describe, expect, it } from 'vitest';

import type { PriorityFactInput } from './facts.js';
import { compareForRemediationQueue, rankFactorsByContribution } from './ordering.js';
import { adrPolicyDefinitionInput, evaluateWith, validatedDefinition } from './test-helper.js';

type Facts = Partial<PriorityFactInput>;

const CRITICAL: Facts = { source_severity: { state: 'observed', values: ['critical'] } };
const HIGH: Facts = { source_severity: { state: 'observed', values: ['high'] } };
const MEDIUM: Facts = { source_severity: { state: 'observed', values: ['medium'] } };
const LOW: Facts = { source_severity: { state: 'observed', values: ['low'] } };
const LISTED: Facts = { kev_listed: { state: 'observed', value: 'listed_catalog_current' } };
const NOT_LISTED: Facts = {
  kev_listed: { state: 'observed', value: 'not_listed_catalog_current' },
};
const PRODUCTION: Facts = { environment_sensitivity: { state: 'observed', value: 'production' } };
const NON_PRODUCTION: Facts = {
  environment_sensitivity: { state: 'observed', value: 'non_production' },
};
const INTERNET_FACING: Facts = {
  internet_exposure: { state: 'observed', value: 'internet_facing' },
};
const INTERNAL: Facts = { internet_exposure: { state: 'observed', value: 'internal' } };

/** B59 plus fix available: 61, P2, no KEV, no escalation, severity 100. */
const F5: Facts = {
  ...CRITICAL,
  ...PRODUCTION,
  ...NOT_LISTED,
  business_criticality: { state: 'observed', value: 'high' },
  asset_data_classification: { state: 'observed', value: 'restricted' },
  fix_available: { state: 'observed', value: 'available' },
};
/** 60, P2, escalated, KEV listed, severity 75. */
const E1: Facts = { ...HIGH, ...LISTED, ...NON_PRODUCTION, ...INTERNET_FACING };
/** 68, P2, KEV listed, context observed but not escalating. */
const KEV_NOT_ESCALATED_68: Facts = {
  ...CRITICAL,
  ...LISTED,
  ...NON_PRODUCTION,
  ...INTERNAL,
  business_criticality: { state: 'observed', value: 'critical' },
};
/** 60, P2, KEV listed only, not escalated, severity 0. */
const K10: Facts = LISTED;
/** 60, P2, not KEV listed, not escalated, severity 100. */
const P2_BOUNDARY: Facts = { ...CRITICAL, ...PRODUCTION, ...INTERNET_FACING, ...NOT_LISTED };
/** 60, P2, KEV listed, escalated, severity 0. */
const KEV_INTERNET_FACING_ONLY: Facts = { ...LISTED, ...INTERNET_FACING };
/** K9: 60, P2, KEV listed, not escalated, severity 25. */
const K9: Facts = { ...LOW, ...LISTED };

describe('compareForRemediationQueue', () => {
  it.each([
    ['Q1 priority outranks escalation', KEV_NOT_ESCALATED_68, E1],
    ['Q1 priority outranks KEV listing', F5, K10],
    ['Q1 priority outranks severity', { ...LOW, ...PRODUCTION, ...INTERNET_FACING }, MEDIUM],
    ['Q2 escalation outranks severity on equal priority', KEV_INTERNET_FACING_ONLY, K9],
    ['Q3 KEV listing outranks severity on equal priority', K10, P2_BOUNDARY],
    ['Q4 severity percent decides last', MEDIUM, { ...PRODUCTION, ...INTERNET_FACING }],
  ] as const)('%s', (_name, first, second) => {
    const a = evaluateWith(first);
    const b = evaluateWith(second);
    expect(compareForRemediationQueue(a, b)).toBe(-1);
    expect(compareForRemediationQueue(b, a)).toBe(1);
  });

  it('documents the equal-priority fixtures the tie-break cases rely on', () => {
    const priorities = [KEV_INTERNET_FACING_ONLY, K9, K10, P2_BOUNDARY].map(
      (facts) => evaluateWith(facts).priority,
    );
    expect(priorities).toEqual([60, 60, 60, 60]);
    expect(evaluateWith(MEDIUM).priority).toBe(
      evaluateWith({ ...PRODUCTION, ...INTERNET_FACING }).priority,
    );
  });

  it('Q5 returns 0 when every engine key is equal', () => {
    const a = evaluateWith({ ...MEDIUM, ...PRODUCTION });
    const b = evaluateWith({ ...MEDIUM, ...INTERNET_FACING });
    expect(a.priority).toBe(b.priority);
    expect(compareForRemediationQueue(a, b)).toBe(0);
    expect(compareForRemediationQueue(b, a)).toBe(0);
    expect(compareForRemediationQueue(a, a)).toBe(0);
  });

  it('Q6 returns incomparable across policy keys, even for identical facts', () => {
    const alternate = validatedDefinition({
      ...adrPolicyDefinitionInput(),
      policyKey: 'patchpilot.test.alternate',
    });
    const a = evaluateWith(E1);
    const b = evaluateWith(E1, alternate);
    expect(compareForRemediationQueue(a, b)).toBe('incomparable');
    expect(compareForRemediationQueue(b, a)).toBe('incomparable');
  });

  it('orders a queue deterministically regardless of input order', () => {
    const fixtures = [MEDIUM, K10, E1, F5, P2_BOUNDARY, K9, KEV_NOT_ESCALATED_68];
    const evaluations = fixtures.map((facts) => evaluateWith(facts));
    const sortQueue = (items: typeof evaluations): number[] =>
      [...items]
        .sort((left, right) => {
          const comparison = compareForRemediationQueue(left, right);
          if (comparison === 'incomparable') {
            throw new Error('fixtures share one policy');
          }
          return comparison;
        })
        .map((evaluation) => evaluations.indexOf(evaluation));
    const expected = [6, 3, 2, 5, 1, 4, 0];
    expect(sortQueue(evaluations)).toEqual(expected);
    expect(sortQueue([...evaluations].reverse())).toEqual(expected);
  });
});

describe('rankFactorsByContribution', () => {
  it('ranks by contribution descending, then catalog ordinal ascending', () => {
    const result = evaluateWith({
      ...CRITICAL,
      ...LISTED,
      ...PRODUCTION,
      business_criticality: { state: 'observed', value: 'high' },
      asset_data_classification: { state: 'observed', value: 'restricted' },
    });
    const ranked = rankFactorsByContribution(result.factors);
    expect(ranked.map((row) => [row.factorId, row.contributionCenti])).toEqual([
      ['source_severity', 4000],
      ['kev_listed', 2000],
      ['environment_sensitivity', 1000],
      ['asset_data_classification', 500],
      ['business_criticality', 400],
      ['internet_exposure', 0],
      ['direct_dependency', 0],
      ['fix_available', 0],
      ['finding_age_days', 0],
      ['advisory_withdrawn', 0],
    ]);
  });

  it('breaks equal contributions by catalog ordinal', () => {
    const ranked = rankFactorsByContribution(
      evaluateWith({ ...PRODUCTION, ...INTERNET_FACING }).factors,
    );
    expect(ranked.slice(0, 3).map((row) => row.factorId)).toEqual([
      'environment_sensitivity',
      'internet_exposure',
      'source_severity',
    ]);
  });

  it('returns a frozen view and leaves stored rows in catalog order', () => {
    const result = evaluateWith({ ...LISTED, ...PRODUCTION });
    const before = result.factors.map((row) => row.factorId);
    const ranked = rankFactorsByContribution(result.factors);
    expect(Object.isFrozen(ranked)).toBe(true);
    expect(ranked).not.toBe(result.factors);
    expect(result.factors.map((row) => row.factorId)).toEqual(before);
    expect(result.factors.map((row) => row.ordinal)).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    expect(ranked[0]).toBe(result.factors[1]);
    expect(ranked[1]).toBe(result.factors[2]);
  });
});
