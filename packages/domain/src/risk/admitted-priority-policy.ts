/**
 * Production allowlist of (engine version, definition hash) pairs.
 * It mirrors docs/security/priority-weight-validation.md.
 * V-0001 is unsigned, so this list is empty. An empty list fails closed.
 * Only a later change that cites a signed `validated` or
 * `validated_with_residuals` entry may add a pair.
 */

const SHA256_HEX = /^[a-f0-9]{64}$/;

export type AdmittedPriorityPolicyPair = {
  readonly engineVersion: string;
  readonly policyDefinitionSha256: string;
  /** Entry id in docs/security/priority-weight-validation.md. */
  readonly validationEntryId: string;
};

export const ADMITTED_PRIORITY_POLICY_PAIRS: readonly AdmittedPriorityPolicyPair[] = Object.freeze(
  [],
);

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
