/**
 * Closed role mapping for the controlled Finding operator permissions.
 * Caller-supplied permission strings are not an input.
 * This module does not mint creation authority.
 */

import type { MembershipRole } from '../../lifecycle.js';

export const FINDING_CREATE_CONTROLLED_PERMISSION = 'finding:create_controlled' as const;

export const FINDING_INSPECT_PERMISSION = 'finding:inspect' as const;

export const CONTROLLED_FINDING_OPERATOR_PRODUCTION_REGISTRATION = 'absent' as const;

export const CONTROLLED_FINDING_OPERATOR_NEXT_REVIEW =
  'controlled_finding_operator_api_session_2' as const;

export type ControlledFindingOperatorPermission =
  typeof FINDING_CREATE_CONTROLLED_PERMISSION | typeof FINDING_INSPECT_PERMISSION;

const NO_GRANTS: readonly ControlledFindingOperatorPermission[] = Object.freeze([]);

const ADMIN_GRANTS: readonly ControlledFindingOperatorPermission[] = Object.freeze([
  FINDING_INSPECT_PERMISSION,
]);

const OWNER_GRANTS: readonly ControlledFindingOperatorPermission[] = Object.freeze([
  FINDING_CREATE_CONTROLLED_PERMISSION,
  FINDING_INSPECT_PERMISSION,
]);

export function controlledFindingOperatorPermissionsForRole(
  role: MembershipRole,
): readonly ControlledFindingOperatorPermission[] {
  switch (role) {
    case 'owner':
      return OWNER_GRANTS;
    case 'admin':
      return ADMIN_GRANTS;
    case 'member':
    case 'viewer':
      return NO_GRANTS;
    default: {
      const exhaustive: never = role;
      throw new Error(`Unexpected membership role: ${String(exhaustive)}`);
    }
  }
}

export function roleGrantsControlledFindingOperatorPermission(
  role: MembershipRole,
  permission: ControlledFindingOperatorPermission,
): boolean {
  return controlledFindingOperatorPermissionsForRole(role).some(
    (granted) => granted === permission,
  );
}
