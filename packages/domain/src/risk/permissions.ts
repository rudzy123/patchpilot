/**
 * Closed role mapping for priority calculation and inspection.
 * Caller-supplied permission strings are not an input.
 * These grants do not publish a policy or create a Finding.
 * Production registration is the API process.
 */

import type { MembershipRole } from '../lifecycle.js';

export const PRIORITY_CALCULATE_CONTROLLED_PERMISSION = 'priority:calculate_controlled' as const;

export const PRIORITY_INSPECT_PERMISSION = 'priority:inspect' as const;

export const PRIORITY_REVIEW_CONTROLLED_PERMISSION = 'priority:review_controlled' as const;

export const PRIORITY_CONTROLLED_PRODUCTION_REGISTRATION = 'api_process' as const;

export type PriorityPermission =
  | typeof PRIORITY_CALCULATE_CONTROLLED_PERMISSION
  | typeof PRIORITY_INSPECT_PERMISSION
  | typeof PRIORITY_REVIEW_CONTROLLED_PERMISSION;

const NO_GRANTS: readonly PriorityPermission[] = Object.freeze([]);

const ADMIN_GRANTS: readonly PriorityPermission[] = Object.freeze([PRIORITY_INSPECT_PERMISSION]);

const OWNER_GRANTS: readonly PriorityPermission[] = Object.freeze([
  PRIORITY_CALCULATE_CONTROLLED_PERMISSION,
  PRIORITY_INSPECT_PERMISSION,
  PRIORITY_REVIEW_CONTROLLED_PERMISSION,
]);

export function priorityPermissionsForRole(role: MembershipRole): readonly PriorityPermission[] {
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

export function roleGrantsPriorityPermission(
  role: MembershipRole,
  permission: PriorityPermission,
): boolean {
  return priorityPermissionsForRole(role).some((granted) => granted === permission);
}
