import { describe, expect, it } from 'vitest';

import type { MembershipRole } from '@patchpilot/domain';

import {
  actorHasPermission,
  canAdministerMembershipRole,
  hasPermission,
  PERMISSIONS,
  permissionCatalog,
  requirePermission,
  type Permission,
} from './permissions.js';
import { createTrustedActor } from './trusted-actor.js';
import { PERMISSION_DENIED } from './errors.js';
import {
  createMembershipRecord,
  createOrganizationRecord,
  createUserRecord,
} from './test-helper.js';

const matrix: Record<Permission, Record<MembershipRole, boolean>> = {
  [PERMISSIONS.organizationRead]: { viewer: true, member: true, admin: true, owner: true },
  [PERMISSIONS.organizationManage]: { viewer: false, member: false, admin: false, owner: true },
  [PERMISSIONS.membershipRead]: { viewer: true, member: true, admin: true, owner: true },
  [PERMISSIONS.membershipManage]: { viewer: false, member: false, admin: true, owner: true },
  [PERMISSIONS.teamRead]: { viewer: true, member: true, admin: true, owner: true },
  [PERMISSIONS.teamManage]: { viewer: false, member: false, admin: true, owner: true },
  [PERMISSIONS.assetRead]: { viewer: true, member: true, admin: true, owner: true },
  [PERMISSIONS.assetManage]: { viewer: false, member: false, admin: true, owner: true },
  [PERMISSIONS.sbomRead]: { viewer: true, member: true, admin: true, owner: true },
  [PERMISSIONS.sbomUpload]: { viewer: false, member: true, admin: true, owner: true },
  [PERMISSIONS.findingRead]: { viewer: true, member: true, admin: true, owner: true },
  [PERMISSIONS.findingTriage]: { viewer: false, member: true, admin: true, owner: true },
  [PERMISSIONS.remediationManage]: { viewer: false, member: true, admin: true, owner: true },
  [PERMISSIONS.riskAcceptanceRequest]: { viewer: false, member: false, admin: true, owner: true },
  [PERMISSIONS.riskAcceptanceApprove]: { viewer: false, member: false, admin: false, owner: true },
  [PERMISSIONS.policyRead]: { viewer: true, member: true, admin: true, owner: true },
  [PERMISSIONS.policyManage]: { viewer: false, member: false, admin: true, owner: true },
  [PERMISSIONS.integrationRead]: { viewer: false, member: false, admin: true, owner: true },
  [PERMISSIONS.integrationManage]: { viewer: false, member: false, admin: true, owner: true },
  [PERMISSIONS.auditRead]: { viewer: true, member: true, admin: true, owner: true },
  [PERMISSIONS.intelligenceRead]: { viewer: true, member: true, admin: true, owner: true },
};

const roles: readonly MembershipRole[] = ['viewer', 'member', 'admin', 'owner'];

describe('permission catalog', () => {
  it('matches the ADR 0019 role matrix exactly', () => {
    expect(permissionCatalog).toEqual(Object.keys(matrix));
    for (const permission of permissionCatalog) {
      for (const role of roles) {
        expect(hasPermission(role, permission)).toBe(matrix[permission][role]);
      }
    }
  });

  it('grants intelligence:read to every role and does not reuse integration:read', () => {
    expect(hasPermission('viewer', PERMISSIONS.intelligenceRead)).toBe(true);
    expect(hasPermission('member', PERMISSIONS.intelligenceRead)).toBe(true);
    expect(hasPermission('admin', PERMISSIONS.intelligenceRead)).toBe(true);
    expect(hasPermission('owner', PERMISSIONS.intelligenceRead)).toBe(true);
    expect(hasPermission('viewer', PERMISSIONS.integrationRead)).toBe(false);
    expect(hasPermission('member', PERMISSIONS.integrationRead)).toBe(false);
    expect(PERMISSIONS.intelligenceRead).toBe('intelligence:read');
    expect(PERMISSIONS.intelligenceRead).not.toBe(PERMISSIONS.integrationRead);
  });

  it('denies by default when the actor has no Organization context', () => {
    const actor = createTrustedActor({ userId: 'user-1', sessionId: 'session-1' });
    expect(actor.permissions).toEqual([]);
    expect(actorHasPermission(actor, PERMISSIONS.organizationRead)).toBe(false);
    expect(requirePermission(actor, PERMISSIONS.organizationRead)).toEqual({
      ok: false,
      error: PERMISSION_DENIED,
    });
  });

  it('denies viewer organization:manage and allows owner', () => {
    const user = createUserRecord({});
    const organization = createOrganizationRecord({});
    const viewer = createTrustedActor({
      userId: user.id,
      sessionId: 'session-viewer',
      organization,
      membership: createMembershipRecord(organization, user, { role: 'viewer' }),
    });
    const owner = createTrustedActor({
      userId: user.id,
      sessionId: 'session-owner',
      organization,
      membership: createMembershipRecord(organization, user, { role: 'owner' }),
    });
    expect(requirePermission(viewer, PERMISSIONS.organizationManage)).toEqual({
      ok: false,
      error: PERMISSION_DENIED,
    });
    expect(requirePermission(owner, PERMISSIONS.organizationManage).ok).toBe(true);
  });

  it('maps membership:manage targeting inside the catalog', () => {
    expect(canAdministerMembershipRole('owner', 'owner')).toBe(true);
    expect(canAdministerMembershipRole('owner', 'admin')).toBe(true);
    expect(canAdministerMembershipRole('admin', 'member')).toBe(true);
    expect(canAdministerMembershipRole('admin', 'viewer')).toBe(true);
    expect(canAdministerMembershipRole('admin', 'admin')).toBe(false);
    expect(canAdministerMembershipRole('admin', 'owner')).toBe(false);
    expect(canAdministerMembershipRole('member', 'viewer')).toBe(false);
    expect(canAdministerMembershipRole('viewer', 'viewer')).toBe(false);
  });
});
