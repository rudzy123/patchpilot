/**
 * Closed role mapping for the remediation queue read.
 * Caller-supplied permission strings are not an input.
 * `finding:read` and `finding:inspect` do not grant this permission.
 */

import type { MembershipRole } from '../lifecycle.js';

export const REMEDIATION_QUEUE_READ_PERMISSION = 'remediation_queue:read' as const;

export type RemediationQueuePermission = typeof REMEDIATION_QUEUE_READ_PERMISSION;

const NO_GRANTS: readonly RemediationQueuePermission[] = Object.freeze([]);

const READ_GRANTS: readonly RemediationQueuePermission[] = Object.freeze([
  REMEDIATION_QUEUE_READ_PERMISSION,
]);

export function remediationQueuePermissionsForRole(
  role: MembershipRole,
): readonly RemediationQueuePermission[] {
  switch (role) {
    case 'owner':
    case 'admin':
      return READ_GRANTS;
    case 'member':
    case 'viewer':
      return NO_GRANTS;
    default: {
      const exhaustive: never = role;
      throw new Error(`Unexpected membership role: ${String(exhaustive)}`);
    }
  }
}

export function roleGrantsRemediationQueueRead(role: MembershipRole): boolean {
  return remediationQueuePermissionsForRole(role).some(
    (permission) => permission === REMEDIATION_QUEUE_READ_PERMISSION,
  );
}
