import type { FactorId } from './catalog.js';
import {
  validatePolicyDefinition,
  type PriorityPolicyDefinition,
  type ValidatedPriorityPolicyDefinition,
} from './definition.js';
import { evaluatePriority, type PriorityEvaluation } from './evaluate.js';
import { parseFactInput, type PriorityFactInput } from './facts.js';

/** A fresh, mutable copy of the ADR 0045 numbers for tests. */
export function adrPolicyDefinitionInput(): PriorityPolicyDefinition {
  return {
    schemaVersion: 2,
    policyKey: 'patchpilot.builtin.v0',
    engineContract: 'patchpilot.priority.p1p4/1',
    factorCatalog: [
      { factorId: 'source_severity', description: 'Highest source severity rating' },
      { factorId: 'kev_listed', description: 'CISA KEV catalog membership' },
      { factorId: 'environment_sensitivity', description: 'Environment sensitivity class' },
      { factorId: 'internet_exposure', description: 'Asset internet exposure' },
      { factorId: 'business_criticality', description: 'Asset business criticality' },
      { factorId: 'asset_data_classification', description: 'Asset data classification' },
      { factorId: 'direct_dependency', description: 'Direct or transitive dependency' },
      { factorId: 'fix_available', description: 'Fixed version availability' },
      { factorId: 'finding_age_days', description: 'Days since first observation' },
      { factorId: 'advisory_withdrawn', description: 'Advisory withdrawal flag' },
    ],
    weights: {
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
    },
    normalization: {
      source_severity: { critical: 100, high: 75, medium: 50, low: 25, none: 0 },
      kev_listed: {
        listed_catalog_current: 100,
        listed_catalog_stale: 100,
        listed_catalog_disabled_with_history: 100,
        not_listed_catalog_current: 0,
      },
      environment_sensitivity: { production: 100, non_production: 0 },
      internet_exposure: { internet_facing: 100, internal: 0 },
      business_criticality: { critical: 100, high: 50, medium: 25, low: 0 },
      asset_data_classification: { restricted: 100, confidential: 60, internal: 20, public: 0 },
      direct_dependency: { direct: 100, transitive: 0 },
      fix_available: { available: 100, not_available: 0 },
      finding_age_days: [
        { minDays: 0, percent: 0 },
        { minDays: 30, percent: 50 },
        { minDays: 90, percent: 100 },
      ],
    },
    bands: [
      { band: 'P1', minPriority: 80, dueDateRecommendationDays: 7 },
      { band: 'P2', minPriority: 60, dueDateRecommendationDays: 30 },
      { band: 'P3', minPriority: 40, dueDateRecommendationDays: 90 },
      { band: 'P4', minPriority: 0, dueDateRecommendationDays: 180 },
    ],
    rules: {
      kevMinimumBand: 'P2',
      kevEscalation: 'listed_and_production_or_internet_facing',
    },
  };
}

/** Override weights "OR" from the ADR 0045 rounding cases. */
export const OVERRIDE_OR_WEIGHTS: { readonly [K in FactorId]: number } = {
  source_severity: 35,
  kev_listed: 25,
  environment_sensitivity: 10,
  internet_exposure: 10,
  business_criticality: 7,
  asset_data_classification: 5,
  direct_dependency: 3,
  fix_available: 3,
  finding_age_days: 2,
  advisory_withdrawn: 0,
};

export const BASE_FACTS: PriorityFactInput = {
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

export function factsWith(overrides: Partial<PriorityFactInput>): PriorityFactInput {
  return { ...BASE_FACTS, ...overrides };
}

export function validatedDefinition(
  input: PriorityPolicyDefinition = adrPolicyDefinitionInput(),
): ValidatedPriorityPolicyDefinition {
  const result = validatePolicyDefinition(input);
  if (!result.ok) {
    throw new Error('test definition must validate');
  }
  return result.value;
}

/** Evaluates BASE facts with `overrides` applied; throws on any error. */
export function evaluateWith(
  overrides: Partial<PriorityFactInput>,
  definition: ValidatedPriorityPolicyDefinition = validatedDefinition(),
): PriorityEvaluation {
  const facts = parseFactInput(factsWith(overrides));
  if (!facts.ok) {
    throw new Error('test facts must parse');
  }
  const result = evaluatePriority(definition, facts.value);
  if (!result.ok) {
    throw new Error(`evaluation failed: ${result.error.kind}`);
  }
  return result.value;
}

type JsonPath = readonly (string | number)[];

/** Deep-clones `input` and sets (or, with `undefined`, deletes) the value at `path`. */
export function withPath(input: unknown, path: JsonPath, value: unknown): Record<string, unknown> {
  const clone = structuredClone(input) as Record<string, unknown>;
  let cursor: Record<string | number, unknown> = clone;
  for (const key of path.slice(0, -1)) {
    cursor = cursor[key] as Record<string | number, unknown>;
  }
  const last = path[path.length - 1];
  if (last === undefined) {
    throw new Error('path must not be empty');
  }
  if (value === undefined) {
    delete cursor[last];
  } else {
    cursor[last] = value;
  }
  return clone;
}
