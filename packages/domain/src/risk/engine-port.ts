/**
 * Injected pure priority engine. Callers supply `parseFactInput`,
 * `evaluatePriority`, `validatePolicyDefinition`, `validatePolicyOverride`,
 * and `canonicalJson`. Validated definitions and parsed facts stay opaque
 * type parameters, so this package does not redeclare the engine's private
 * brands and does not import the engine package. `PriorityFactInput` is the
 * unbranded fact document. `evaluatePriority` accepts only facts the engine
 * has parsed, so callers parse through this port first. Fact-issue codes stay
 * strings. The result fields are readonly so those functions assign directly.
 */

import type { PriorityEvaluationDocument } from '../json-documents.js';

export type PriorityPolicyDefinitionIssue = {
  readonly path: string;
  readonly code: string;
};

export type PriorityPolicyDefinitionError = {
  readonly kind: 'invalid_policy_definition';
  readonly issues: readonly PriorityPolicyDefinitionIssue[];
};

export type PriorityPolicyOverrideIssue = {
  readonly path: string;
  readonly code: string;
};

export type PriorityPolicyOverrideError = {
  readonly kind: 'invalid_policy_override';
  readonly issues: readonly PriorityPolicyOverrideIssue[];
};

export type PriorityFactInputIssue = {
  readonly factorId: string | null;
  readonly code: string;
};

export type PriorityFactInputError = {
  readonly kind: 'invalid_fact_input';
  readonly issues: readonly PriorityFactInputIssue[];
};

export type PriorityEngineInvariantViolation = {
  readonly kind: 'engine_invariant_violation';
  readonly code: string;
};

export type PriorityCanonicalJsonError = {
  readonly kind: 'invalid_canonical_json_value';
  readonly code: string;
};

export type PriorityEvaluationError =
  PriorityPolicyDefinitionError | PriorityFactInputError | PriorityEngineInvariantViolation;

/** Same shape as the policy engine result: readonly success or readonly failure. */
export type PriorityEngineResult<T, E> =
  { readonly ok: true; readonly value: T } | { readonly ok: false; readonly error: E };

export type PriorityEnginePort<TValidatedDefinition, TParsedFacts> = {
  readonly parseFactInput: (
    input: unknown,
  ) => PriorityEngineResult<TParsedFacts, PriorityFactInputError>;
  readonly evaluatePriority: (
    definition: TValidatedDefinition,
    facts: TParsedFacts,
  ) => PriorityEngineResult<PriorityEvaluationDocument, PriorityEvaluationError>;
  readonly validatePolicyDefinition: (
    input: unknown,
  ) => PriorityEngineResult<TValidatedDefinition, PriorityPolicyDefinitionError>;
  readonly validatePolicyOverride: (
    parent: TValidatedDefinition,
    candidate: unknown,
  ) => PriorityEngineResult<
    TValidatedDefinition,
    PriorityPolicyDefinitionError | PriorityPolicyOverrideError
  >;
  readonly canonicalJson: (
    value: unknown,
  ) => PriorityEngineResult<string, PriorityCanonicalJsonError>;
};

export const PRIORITY_ENGINE_PORT_METHODS = [
  'parseFactInput',
  'evaluatePriority',
  'validatePolicyDefinition',
  'validatePolicyOverride',
  'canonicalJson',
] as const satisfies readonly (keyof PriorityEnginePort<unknown, unknown>)[];
