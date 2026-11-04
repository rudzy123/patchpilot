/**
 * The only API adapter for the pure priority engine.
 * Domain code does not import this module.
 */

import {
  BUILTIN_PRIORITY_POLICY_DEFINITION,
  canonicalJson,
  evaluatePriority,
  parseFactInput,
  validatePolicyDefinition,
  validatePolicyOverride,
} from '@patchpilot/policy-engine';

export { BUILTIN_PRIORITY_POLICY_DEFINITION };

export function createPriorityEnginePort() {
  return {
    parseFactInput,
    evaluatePriority,
    validatePolicyDefinition,
    validatePolicyOverride,
    canonicalJson,
  };
}
