import { describe, expect, it } from 'vitest';

import * as policyEngine from './index.js';

describe('@patchpilot/policy-engine', () => {
  it('exports the package boundary and the engine entry points', () => {
    expect(policyEngine.packageBoundary).toBe('@patchpilot/policy-engine');
    expect(policyEngine.POLICY_ENGINE_VERSION).toBe('@patchpilot/policy-engine@1');
    expect(policyEngine.PRIORITY_ENGINE_CONTRACT).toBe('patchpilot.priority.p1p4/1');
    expect(typeof policyEngine.validatePolicyDefinition).toBe('function');
    expect(typeof policyEngine.validatePolicyOverride).toBe('function');
    expect(typeof policyEngine.parseFactInput).toBe('function');
    expect(typeof policyEngine.evaluatePriority).toBe('function');
    expect(typeof policyEngine.compareForRemediationQueue).toBe('function');
    expect(typeof policyEngine.rankFactorsByContribution).toBe('function');
    expect(typeof policyEngine.canonicalJson).toBe('function');
    expect(Object.isFrozen(policyEngine.EXPLANATION_TEXT)).toBe(true);
  });

  it('keeps internal guards and helpers off the public surface', () => {
    const exported = Object.keys(policyEngine);
    for (const name of [
      'checkPriorityInvariants',
      'isValidatedPriorityPolicyDefinition',
      'isParsedPriorityFactInput',
      'deepFreeze',
      'readPlainRecord',
    ]) {
      expect(exported).not.toContain(name);
    }
  });
});
