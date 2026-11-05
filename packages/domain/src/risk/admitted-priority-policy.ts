/**
 * Production allowlist of (engine version, definition hash) pairs.
 * It mirrors docs/security/priority-weight-validation.md.
 * V-0001 is `validated_with_residuals`, so this list admits that one pair.
 * Any other pair fails closed. A signed entry alone does not publish a row.
 */

const SHA256_HEX = /^[a-f0-9]{64}$/;

export type AdmittedPriorityPolicyPair = {
  readonly engineVersion: string;
  readonly policyDefinitionSha256: string;
  /** Entry id in docs/security/priority-weight-validation.md. */
  readonly validationEntryId: string;
};

const ADMITTED_BUILTIN_PRIORITY_POLICY_PAIR: AdmittedPriorityPolicyPair = Object.freeze({
  engineVersion: '@patchpilot/policy-engine@1',
  policyDefinitionSha256: '7c1815d456ff6dcf9e19c218bcd5eaba73c265abc911027c3f50df41bb8504f7',
  validationEntryId: 'V-0001',
});

export const ADMITTED_PRIORITY_POLICY_PAIRS: readonly AdmittedPriorityPolicyPair[] = Object.freeze([
  ADMITTED_BUILTIN_PRIORITY_POLICY_PAIR,
]);

export function isAdmittedPriorityPolicyPair(
  pairs: readonly AdmittedPriorityPolicyPair[],
  engineVersion: string,
  policyDefinitionSha256: string,
): boolean {
  if (!Array.isArray(pairs)) {
    return false;
  }
  if (engineVersion.length === 0 || !SHA256_HEX.test(policyDefinitionSha256)) {
    return false;
  }
  return pairs.some(
    (pair) =>
      typeof pair === 'object' &&
      pair !== null &&
      pair.engineVersion === engineVersion &&
      pair.policyDefinitionSha256 === policyDefinitionSha256 &&
      typeof pair.validationEntryId === 'string' &&
      pair.validationEntryId.length > 0,
  );
}
