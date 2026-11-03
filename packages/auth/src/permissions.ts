import {
  controlledFindingDiscoveryPermissionsForRole,
  controlledFindingOperatorPermissionsForRole,
  err,
  FINDING_CREATE_CONTROLLED_PERMISSION,
  FINDING_DISCOVER_CONTROLLED_PERMISSION,
  FINDING_INSPECT_PERMISSION,
  ok,
  PRIORITY_CALCULATE_CONTROLLED_PERMISSION,
  PRIORITY_INSPECT_PERMISSION,
  priorityPermissionsForRole,
  PRODUCT_MATCH_EVALUATE_CONTROLLED_PERMISSION,
  productMatchEvaluationPermissionsForRole,
  type MembershipRole,
  type Result,
} from '@patchpilot/domain';

import { PERMISSION_DENIED } from './errors.js';
import type { TrustedActor } from './trusted-actor.js';

export const PERMISSIONS = {
  organizationRead: 'organization:read',
  organizationManage: 'organization:manage',
  membershipRead: 'membership:read',
  membershipManage: 'membership:manage',
  teamRead: 'team:read',
  teamManage: 'team:manage',
  assetRead: 'asset:read',
  assetManage: 'asset:manage',
  sbomRead: 'sbom:read',
  sbomUpload: 'sbom:upload',
  findingRead: 'finding:read',
  findingTriage: 'finding:triage',
  findingCreateControlled: FINDING_CREATE_CONTROLLED_PERMISSION,
  findingDiscoverControlled: FINDING_DISCOVER_CONTROLLED_PERMISSION,
  findingInspect: FINDING_INSPECT_PERMISSION,
  productMatchEvaluateControlled: PRODUCT_MATCH_EVALUATE_CONTROLLED_PERMISSION,
  priorityCalculateControlled: PRIORITY_CALCULATE_CONTROLLED_PERMISSION,
  priorityInspect: PRIORITY_INSPECT_PERMISSION,
  remediationManage: 'remediation:manage',
  riskAcceptanceRequest: 'risk_acceptance:request',
  riskAcceptanceApprove: 'risk_acceptance:approve',
  policyRead: 'policy:read',
  policyManage: 'policy:manage',
  integrationRead: 'integration:read',
  integrationManage: 'integration:manage',
  auditRead: 'audit:read',
  intelligenceRead: 'intelligence:read',
} as const;

export type Permission = (typeof PERMISSIONS)[keyof typeof PERMISSIONS];

export const permissionCatalog: readonly Permission[] = Object.freeze([
  PERMISSIONS.organizationRead,
  PERMISSIONS.organizationManage,
  PERMISSIONS.membershipRead,
  PERMISSIONS.membershipManage,
  PERMISSIONS.teamRead,
  PERMISSIONS.teamManage,
  PERMISSIONS.assetRead,
  PERMISSIONS.assetManage,
  PERMISSIONS.sbomRead,
  PERMISSIONS.sbomUpload,
  PERMISSIONS.findingRead,
  PERMISSIONS.findingTriage,
  PERMISSIONS.findingCreateControlled,
  PERMISSIONS.findingDiscoverControlled,
  PERMISSIONS.findingInspect,
  PERMISSIONS.productMatchEvaluateControlled,
  PERMISSIONS.priorityCalculateControlled,
  PERMISSIONS.priorityInspect,
  PERMISSIONS.remediationManage,
  PERMISSIONS.riskAcceptanceRequest,
  PERMISSIONS.riskAcceptanceApprove,
  PERMISSIONS.policyRead,
  PERMISSIONS.policyManage,
  PERMISSIONS.integrationRead,
  PERMISSIONS.integrationManage,
  PERMISSIONS.auditRead,
  PERMISSIONS.intelligenceRead,
]);

const VIEWER_PERMISSIONS: readonly Permission[] = [
  PERMISSIONS.organizationRead,
  PERMISSIONS.membershipRead,
  PERMISSIONS.teamRead,
  PERMISSIONS.assetRead,
  PERMISSIONS.sbomRead,
  PERMISSIONS.findingRead,
  PERMISSIONS.policyRead,
  PERMISSIONS.auditRead,
  PERMISSIONS.intelligenceRead,
  ...controlledFindingOperatorPermissionsForRole('viewer'),
  ...controlledFindingDiscoveryPermissionsForRole('viewer'),
  ...productMatchEvaluationPermissionsForRole('viewer'),
  ...priorityPermissionsForRole('viewer'),
];

const MEMBER_PERMISSIONS: readonly Permission[] = [
  ...VIEWER_PERMISSIONS,
  PERMISSIONS.sbomUpload,
  PERMISSIONS.findingTriage,
  PERMISSIONS.remediationManage,
  ...operatorGrantsBeyond('member', VIEWER_PERMISSIONS),
  ...discoveryGrantsBeyond('member', VIEWER_PERMISSIONS),
  ...productMatchGrantsBeyond('member', VIEWER_PERMISSIONS),
  ...priorityGrantsBeyond('member', VIEWER_PERMISSIONS),
];

const ADMIN_PERMISSIONS: readonly Permission[] = [
  ...MEMBER_PERMISSIONS,
  ...operatorGrantsBeyond('admin', MEMBER_PERMISSIONS),
  ...discoveryGrantsBeyond('admin', MEMBER_PERMISSIONS),
  ...productMatchGrantsBeyond('admin', MEMBER_PERMISSIONS),
  ...priorityGrantsBeyond('admin', MEMBER_PERMISSIONS),
  PERMISSIONS.membershipManage,
  PERMISSIONS.teamManage,
  PERMISSIONS.assetManage,
  PERMISSIONS.riskAcceptanceRequest,
  PERMISSIONS.policyManage,
  PERMISSIONS.integrationRead,
  PERMISSIONS.integrationManage,
];

const OWNER_PERMISSIONS: readonly Permission[] = [
  ...ADMIN_PERMISSIONS,
  ...operatorGrantsBeyond('owner', ADMIN_PERMISSIONS),
  ...discoveryGrantsBeyond('owner', ADMIN_PERMISSIONS),
  ...productMatchGrantsBeyond('owner', ADMIN_PERMISSIONS),
  ...priorityGrantsBeyond('owner', ADMIN_PERMISSIONS),
  PERMISSIONS.organizationManage,
  PERMISSIONS.riskAcceptanceApprove,
];

function discoveryGrantsBeyond(
  role: MembershipRole,
  already: readonly Permission[],
): readonly Permission[] {
  return controlledFindingDiscoveryPermissionsForRole(role).filter(
    (permission) => !already.includes(permission),
  );
}

function productMatchGrantsBeyond(
  role: MembershipRole,
  already: readonly Permission[],
): readonly Permission[] {
  return productMatchEvaluationPermissionsForRole(role).filter(
    (permission) => !already.includes(permission),
  );
}

function priorityGrantsBeyond(
  role: MembershipRole,
  already: readonly Permission[],
): readonly Permission[] {
  return priorityPermissionsForRole(role).filter((permission) => !already.includes(permission));
}

function operatorGrantsBeyond(
  role: MembershipRole,
  already: readonly Permission[],
): readonly Permission[] {
  return controlledFindingOperatorPermissionsForRole(role).filter(
    (permission) => !already.includes(permission),
  );
}

const ROLE_PERMISSIONS: Record<MembershipRole, ReadonlySet<Permission>> = {
  viewer: new Set(VIEWER_PERMISSIONS),
  member: new Set(MEMBER_PERMISSIONS),
  admin: new Set(ADMIN_PERMISSIONS),
  owner: new Set(OWNER_PERMISSIONS),
};

export function permissionsForRole(role: MembershipRole): readonly Permission[] {
  switch (role) {
    case 'viewer':
      return VIEWER_PERMISSIONS;
    case 'member':
      return MEMBER_PERMISSIONS;
    case 'admin':
      return ADMIN_PERMISSIONS;
    case 'owner':
      return OWNER_PERMISSIONS;
    default: {
      const exhaustive: never = role;
      throw new Error(`Unexpected membership role: ${String(exhaustive)}`);
    }
  }
}

export function hasPermission(role: MembershipRole, permission: Permission): boolean {
  return ROLE_PERMISSIONS[role].has(permission);
}

export function actorHasPermission(actor: TrustedActor, permission: Permission): boolean {
  if (actor.role === null) {
    return false;
  }

  return hasPermission(actor.role, permission);
}

export function requirePermission(actor: TrustedActor, permission: Permission): Result<void> {
  if (!actorHasPermission(actor, permission)) {
    return err(PERMISSION_DENIED);
  }

  return ok(undefined);
}

/**
 * ADR 0019: admin may manage member and viewer only; owner may manage all roles.
 * Role comparisons stay inside this mapping.
 */
export function canAdministerMembershipRole(
  actorRole: MembershipRole,
  targetRole: MembershipRole,
): boolean {
  if (!hasPermission(actorRole, PERMISSIONS.membershipManage)) {
    return false;
  }

  if (actorRole === 'owner') {
    return true;
  }

  return targetRole === 'member' || targetRole === 'viewer';
}
