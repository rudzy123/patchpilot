import { BUILTIN_PRIORITY_POLICY_DEFINITION } from './builtin-definition.js';
import type { FactorId } from './catalog.js';
import {
  validatePolicyDefinition,
  type PriorityPolicyDefinition,
  type ValidatedPriorityPolicyDefinition,
} from './definition.js';
import { evaluatePriority, type PriorityEvaluation } from './evaluate.js';
import { parseFactInput, type PriorityFactInput } from './facts.js';

/** A fresh, mutable copy of the built-in ADR 0045 definition for tests. */
export function adrPolicyDefinitionInput(): PriorityPolicyDefinition {
  return structuredClone(BUILTIN_PRIORITY_POLICY_DEFINITION);
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
