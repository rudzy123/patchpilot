import { describe, expect, it } from 'vitest';

import { BUILTIN_PRIORITY_POLICY_DEFINITION } from './builtin-definition.js';
import { FACTOR_IDS, PRIORITY_ENGINE_CONTRACT, WEIGHT_SUM } from './catalog.js';
import { canonicalJson } from './canonical-json.js';
import { evaluatePriority } from './evaluate.js';
import { parseFactInput } from './facts.js';
import { BASE_FACTS } from './test-helper.js';

describe('BUILTIN_PRIORITY_POLICY_DEFINITION', () => {
  const definition = BUILTIN_PRIORITY_POLICY_DEFINITION;

  it('carries the ADR 0045 built-in numbers and is deep-frozen', () => {
    expect(definition.schemaVersion).toBe(2);
    expect(definition.policyKey).toBe('patchpilot.builtin.v0');
    expect(definition.engineContract).toBe(PRIORITY_ENGINE_CONTRACT);
    expect(definition.factorCatalog.map((entry) => entry.factorId)).toEqual([...FACTOR_IDS]);
    expect(definition.weights).toEqual({
      source_severity: 40,
      kev_listed: 20,
      environment_sensitivity: 10,
      internet_exposure: 10,
      business_criticality: 8,
      asset_data_classification: 5,
      direct_dependency: 3,
      fix_available: 2,
      finding_age_days: 2,
      advisory_withdrawn: 0,
    });
    expect(FACTOR_IDS.reduce((sum, factorId) => sum + definition.weights[factorId], 0)).toBe(
      WEIGHT_SUM,
    );
    expect(definition.normalization.finding_age_days).toEqual([
      { minDays: 0, percent: 0 },
      { minDays: 30, percent: 50 },
      { minDays: 90, percent: 100 },
    ]);
    expect(definition.bands).toEqual([
      { band: 'P1', minPriority: 80, dueDateRecommendationDays: 7 },
      { band: 'P2', minPriority: 60, dueDateRecommendationDays: 30 },
      { band: 'P3', minPriority: 40, dueDateRecommendationDays: 90 },
      { band: 'P4', minPriority: 0, dueDateRecommendationDays: 180 },
    ]);
    expect(definition.rules).toEqual({
      kevMinimumBand: 'P2',
      kevEscalation: 'listed_and_production_or_internet_facing',
    });
    expect(Object.isFrozen(definition)).toBe(true);
    expect(Object.isFrozen(definition.weights)).toBe(true);
    expect(Object.isFrozen(definition.factorCatalog[0])).toBe(true);
    expect(Object.isFrozen(definition.normalization.finding_age_days[0])).toBe(true);
    expect(Object.isFrozen(definition.bands[0])).toBe(true);
    expect(Object.isFrozen(definition.rules)).toBe(true);
    expect(() => {
      (definition.weights as { source_severity: number }).source_severity = 0;
    }).toThrow(TypeError);
  });

  it('is a validated definition that evaluates all-unavailable facts to P4', () => {
    const facts = parseFactInput(BASE_FACTS);
    expect(facts.ok).toBe(true);
    if (!facts.ok) {
      return;
    }
    const result = evaluatePriority(definition, facts.value);
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    expect(result.value.policyKey).toBe('patchpilot.builtin.v0');
    expect(result.value).toMatchObject({
      weightedScoreCenti: 0,
      upliftCenti: 0,
      priority: 0,
      priorityBand: 'P4',
      dueDateRecommendationDays: 180,
      escalation: { recommended: false, reasons: [] },
    });
  });

  it('serializes to identical canonical JSON on repeat', () => {
    const first = canonicalJson(definition);
    const second = canonicalJson(definition);
    expect(first.ok && second.ok && first.value === second.value).toBe(true);
  });
});
