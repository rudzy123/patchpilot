/**
 * Discovery permission for one read-only asset-scoped route.
 * Caller-supplied permission strings are not an input.
 * This grant does not include creation or inspection.
 */

import type { MembershipRole } from '../../lifecycle.js';

export const FINDING_DISCOVER_CONTROLLED_PERMISSION = 'finding:discover_controlled' as const;

const NO_GRANTS: readonly (typeof FINDING_DISCOVER_CONTROLLED_PERMISSION)[] = Object.freeze([]);

const DISCOVERY_GRANTS: readonly (typeof FINDING_DISCOVER_CONTROLLED_PERMISSION)[] = Object.freeze([
  FINDING_DISCOVER_CONTROLLED_PERMISSION,
]);

export function controlledFindingDiscoveryPermissionsForRole(
  role: MembershipRole,
): readonly (typeof FINDING_DISCOVER_CONTROLLED_PERMISSION)[] {
  switch (role) {
    case 'owner':
    case 'admin':
      return DISCOVERY_GRANTS;
    case 'member':
    case 'viewer':
      return NO_GRANTS;
    default: {
      const exhaustive: never = role;
      throw new Error(`Unexpected membership role: ${String(exhaustive)}`);
    }
  }
}

export function roleGrantsControlledFindingDiscovery(role: MembershipRole): boolean {
  return controlledFindingDiscoveryPermissionsForRole(role).length === 1;
}
