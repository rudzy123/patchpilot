/**
 * Closed role mapping for deliberate Product Match Evidence.
 * Evaluation and discovery are separate grants.
 * Caller-supplied permission strings are not an input.
 * Neither grant creates a Finding or approves an advisory.
 */

import type { MembershipRole } from '../lifecycle.js';

export const PRODUCT_MATCH_EVALUATE_CONTROLLED_PERMISSION =
  'product_match:evaluate_controlled' as const;

export const PRODUCT_MATCH_DISCOVER_CONTROLLED_PERMISSION =
  'product_match:discover_controlled' as const;

export type ProductMatchEvaluationPermission = typeof PRODUCT_MATCH_EVALUATE_CONTROLLED_PERMISSION;

export type ProductMatchDiscoveryPermission = typeof PRODUCT_MATCH_DISCOVER_CONTROLLED_PERMISSION;

const NO_EVALUATION_GRANTS: readonly ProductMatchEvaluationPermission[] = Object.freeze([]);

const OWNER_EVALUATION_GRANTS: readonly ProductMatchEvaluationPermission[] = Object.freeze([
  PRODUCT_MATCH_EVALUATE_CONTROLLED_PERMISSION,
]);

const NO_DISCOVERY_GRANTS: readonly ProductMatchDiscoveryPermission[] = Object.freeze([]);

const OWNER_DISCOVERY_GRANTS: readonly ProductMatchDiscoveryPermission[] = Object.freeze([
  PRODUCT_MATCH_DISCOVER_CONTROLLED_PERMISSION,
]);

export function productMatchEvaluationPermissionsForRole(
  role: MembershipRole,
): readonly ProductMatchEvaluationPermission[] {
  switch (role) {
    case 'owner':
      return OWNER_EVALUATION_GRANTS;
    case 'admin':
    case 'member':
    case 'viewer':
      return NO_EVALUATION_GRANTS;
    default: {
      const exhaustive: never = role;
      throw new Error(`Unexpected membership role: ${String(exhaustive)}`);
    }
  }
}

export function productMatchDiscoveryPermissionsForRole(
  role: MembershipRole,
): readonly ProductMatchDiscoveryPermission[] {
  switch (role) {
    case 'owner':
      return OWNER_DISCOVERY_GRANTS;
    case 'admin':
    case 'member':
    case 'viewer':
      return NO_DISCOVERY_GRANTS;
    default: {
      const exhaustive: never = role;
      throw new Error(`Unexpected membership role: ${String(exhaustive)}`);
    }
  }
}

export function roleGrantsProductMatchEvaluation(role: MembershipRole): boolean {
  return productMatchEvaluationPermissionsForRole(role).length === 1;
}

export function roleGrantsProductMatchDiscovery(role: MembershipRole): boolean {
  return productMatchDiscoveryPermissionsForRole(role).length === 1;
}
