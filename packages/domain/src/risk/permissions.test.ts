/**
 * Priority permissions. Production registration is the API process.
 * Finding, policy, and product-match grants are not these grants.
 */

import { describe, expect, it } from 'vitest';

import type { MembershipRole } from '../lifecycle.js';
import {
  PRIORITY_CALCULATE_CONTROLLED_PERMISSION,
  PRIORITY_CONTROLLED_PRODUCTION_REGISTRATION,
  PRIORITY_INSPECT_PERMISSION,
  PRIORITY_REVIEW_CONTROLLED_PERMISSION,
  priorityPermissionsForRole,
  roleGrantsPriorityPermission,
} from './permissions.js';

const ROLES: readonly MembershipRole[] = ['owner', 'admin', 'member', 'viewer'];

const OTHER_PERMISSIONS = [
  'finding:create_controlled',
  'finding:inspect',
  'finding:discover_controlled',
  'finding:read',
  'finding:triage',
  'policy:read',
  'policy:manage',
  'product_match:evaluate_controlled',
  'asset:manage',
  'intelligence:read',
] as const;

describe('priority permissions', () => {
  it('grants priority:calculate_controlled to the owner only', () => {
    expect(PRIORITY_CALCULATE_CONTROLLED_PERMISSION).toBe('priority:calculate_controlled');
    expect(priorityPermissionsForRole('owner')).toEqual([
      PRIORITY_CALCULATE_CONTROLLED_PERMISSION,
      PRIORITY_INSPECT_PERMISSION,
      PRIORITY_REVIEW_CONTROLLED_PERMISSION,
    ]);
    expect(priorityPermissionsForRole('admin')).toEqual([PRIORITY_INSPECT_PERMISSION]);
    expect(priorityPermissionsForRole('member')).toEqual([]);
    expect(priorityPermissionsForRole('viewer')).toEqual([]);
    for (const role of ROLES) {
      expect(roleGrantsPriorityPermission(role, PRIORITY_CALCULATE_CONTROLLED_PERMISSION)).toBe(
        role === 'owner',
      );
    }
  });

  it('grants priority:inspect to the owner and the admin', () => {
    expect(PRIORITY_INSPECT_PERMISSION).toBe('priority:inspect');
    for (const role of ROLES) {
      expect(roleGrantsPriorityPermission(role, PRIORITY_INSPECT_PERMISSION)).toBe(
        role === 'owner' || role === 'admin',
      );
    }
  });

  it('grants priority:review_controlled to the owner only', () => {
    expect(PRIORITY_REVIEW_CONTROLLED_PERMISSION).toBe('priority:review_controlled');
    for (const role of ROLES) {
      expect(roleGrantsPriorityPermission(role, PRIORITY_REVIEW_CONTROLLED_PERMISSION)).toBe(
        role === 'owner',
      );
    }
  });

  it('does not reuse finding, policy, or product-match permissions', () => {
    expect(PRIORITY_CALCULATE_CONTROLLED_PERMISSION).not.toBe(PRIORITY_INSPECT_PERMISSION);
    expect(OTHER_PERMISSIONS).not.toContain(PRIORITY_CALCULATE_CONTROLLED_PERMISSION);
    expect(OTHER_PERMISSIONS).not.toContain(PRIORITY_INSPECT_PERMISSION);
  });

  it('registers production composition in the API process', () => {
    expect(PRIORITY_CONTROLLED_PRODUCTION_REGISTRATION).toBe('api_process');
  });

  it('rejects an unexpected membership role', () => {
    expect(() => priorityPermissionsForRole('guest' as MembershipRole)).toThrow(
      'Unexpected membership role: guest',
    );
  });
});
