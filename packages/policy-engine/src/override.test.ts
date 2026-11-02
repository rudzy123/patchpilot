import { describe, expect, it } from 'vitest';

import {
  validatePolicyDefinition,
  validatePolicyOverride,
  type ValidatedPriorityPolicyDefinition,
} from './definition.js';
import { adrPolicyDefinitionInput, OVERRIDE_OR_WEIGHTS, withPath } from './test-helper.js';

function parent(): ValidatedPriorityPolicyDefinition {
  const result = validatePolicyDefinition(adrPolicyDefinitionInput());
  if (!result.ok) {
    throw new Error('parent must validate');
  }
  return result.value;
}

function withWeights(weights: Record<string, number>): Record<string, unknown> {
  return { ...adrPolicyDefinitionInput(), weights };
}

const ZERO_WEIGHTS = Object.fromEntries(Object.keys(OVERRIDE_OR_WEIGHTS).map((key) => [key, 0]));

describe('validatePolicyOverride', () => {
  it('accepts override OR', () => {
    const result = validatePolicyOverride(parent(), withWeights({ ...OVERRIDE_OR_WEIGHTS }));
    expect(result.ok && result.value.weights).toEqual(OVERRIDE_OR_WEIGHTS);
  });

  it('accepts weights at the bounds', () => {
    const weights = {
      ...ZERO_WEIGHTS,
      source_severity: 50,
      kev_listed: 10,
      environment_sensitivity: 20,
      internet_exposure: 20,
    };
    expect(validatePolicyOverride(parent(), withWeights(weights)).ok).toBe(true);
  });

  it.each([
    [
      'severity 29',
      { source_severity: 29, environment_sensitivity: 16 },
      'weights.source_severity',
    ],
    [
      'severity 51',
      { source_severity: 51, kev_listed: 10, finding_age_days: 1 },
      'weights.source_severity',
    ],
    ['KEV 9', { kev_listed: 9, source_severity: 50, finding_age_days: 3 }, 'weights.kev_listed'],
    ['KEV 31', { kev_listed: 31, environment_sensitivity: 4 }, 'weights.kev_listed'],
  ] as const)('rejects %s', (_name, changes, path) => {
    const result = validatePolicyOverride(
      parent(),
      withWeights({ ...OVERRIDE_OR_WEIGHTS, ...changes }),
    );
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toEqual({
        kind: 'invalid_policy_override',
        issues: [{ path, code: 'weight_outside_override_bounds' }],
      });
    }
  });

  it.each([
    ['a sum of 101', ['weights', 'finding_age_days'], 3],
    ['withdrawn weight 1', ['weights', 'advisory_withdrawn'], 1],
  ] as const)('rejects %s as an invalid definition', (_name, path, value) => {
    const result = validatePolicyOverride(
      parent(),
      withPath(adrPolicyDefinitionInput(), path, value),
    );
    expect(!result.ok && result.error.kind).toBe('invalid_policy_definition');
  });

  it.each([
    ['a changed threshold', ['bands', 1, 'minPriority'], 65, 'bands'],
    ['a changed normalization', ['normalization', 'source_severity', 'high'], 70, 'normalization'],
    ['changed due days', ['bands', 0, 'dueDateRecommendationDays'], 14, 'bands'],
    ['kevMinimumBand P3', ['rules', 'kevMinimumBand'], 'P3', 'rules'],
    ['a changed description', ['factorCatalog', 2, 'description'], 'Tenant text', 'factorCatalog'],
    ['a changed policyKey', ['policyKey'], 'org.override', 'policyKey'],
  ] as const)('rejects %s', (_name, path, value, section) => {
    const result = validatePolicyOverride(
      parent(),
      withPath(adrPolicyDefinitionInput(), path, value),
    );
    expect(!result.ok && result.error).toEqual({
      kind: 'invalid_policy_override',
      issues: [{ path: section, code: 'differs_from_parent' }],
    });
  });

  it('rejects an unvalidated parent at runtime', () => {
    const forged = adrPolicyDefinitionInput() as ValidatedPriorityPolicyDefinition;
    const result = validatePolicyOverride(forged, adrPolicyDefinitionInput());
    expect(!result.ok && result.error).toEqual({
      kind: 'invalid_policy_override',
      issues: [{ path: '$', code: 'parent_not_validated' }],
    });
  });
});
