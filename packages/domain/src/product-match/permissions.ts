/**
 * Closed role mapping for one deliberate Product Match Evidence evaluation.
 * Caller-supplied permission strings are not an input.
 * This grant does not create a Finding or approve an advisory.
 */

import type { MembershipRole } from '../lifecycle.js';

export const PRODUCT_MATCH_EVALUATE_CONTROLLED_PERMISSION =
  'product_match:evaluate_controlled' as const;

export type ProductMatchEvaluationPermission = typeof PRODUCT_MATCH_EVALUATE_CONTROLLED_PERMISSION;

const NO_GRANTS: readonly ProductMatchEvaluationPermission[] = Object.freeze([]);

const OWNER_GRANTS: readonly ProductMatchEvaluationPermission[] = Object.freeze([
  PRODUCT_MATCH_EVALUATE_CONTROLLED_PERMISSION,
]);

export function productMatchEvaluationPermissionsForRole(
  role: MembershipRole,
): readonly ProductMatchEvaluationPermission[] {
  switch (role) {
    case 'owner':
      return OWNER_GRANTS;
    case 'admin':
    case 'member':
    case 'viewer':
      return NO_GRANTS;
    default: {
      const exhaustive: never = role;
      throw new Error(`Unexpected membership role: ${String(exhaustive)}`);
    }
  }
}

export function roleGrantsProductMatchEvaluation(role: MembershipRole): boolean {
  return productMatchEvaluationPermissionsForRole(role).length === 1;
}
