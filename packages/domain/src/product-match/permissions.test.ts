/**
 * Owner-only product-match evaluation permission.
 * Finding permissions and instance advisory grants are not this grant.
 */

import { describe, expect, it } from 'vitest';

import type { MembershipRole } from '../lifecycle.js';
import {
  PRODUCT_MATCH_DISCOVER_CONTROLLED_PERMISSION,
  PRODUCT_MATCH_EVALUATE_CONTROLLED_PERMISSION,
  productMatchDiscoveryPermissionsForRole,
  productMatchEvaluationPermissionsForRole,
  roleGrantsProductMatchDiscovery,
  roleGrantsProductMatchEvaluation,
} from './permissions.js';

const ROLES: readonly MembershipRole[] = ['owner', 'admin', 'member', 'viewer'];

describe('product match evaluation permission', () => {
  it('grants product_match:evaluate_controlled to the owner only', () => {
    expect(PRODUCT_MATCH_EVALUATE_CONTROLLED_PERMISSION).toBe('product_match:evaluate_controlled');
    expect(productMatchEvaluationPermissionsForRole('owner')).toEqual([
      PRODUCT_MATCH_EVALUATE_CONTROLLED_PERMISSION,
    ]);
    expect(productMatchEvaluationPermissionsForRole('admin')).toEqual([]);
    expect(productMatchEvaluationPermissionsForRole('member')).toEqual([]);
    expect(productMatchEvaluationPermissionsForRole('viewer')).toEqual([]);
    for (const role of ROLES) {
      expect(roleGrantsProductMatchEvaluation(role)).toBe(role === 'owner');
    }
  });

  it('grants product_match:discover_controlled to the owner only', () => {
    expect(PRODUCT_MATCH_DISCOVER_CONTROLLED_PERMISSION).toBe('product_match:discover_controlled');
    expect(PRODUCT_MATCH_DISCOVER_CONTROLLED_PERMISSION).not.toBe(
      PRODUCT_MATCH_EVALUATE_CONTROLLED_PERMISSION,
    );
    expect(productMatchDiscoveryPermissionsForRole('owner')).toEqual([
      PRODUCT_MATCH_DISCOVER_CONTROLLED_PERMISSION,
    ]);
    expect(productMatchDiscoveryPermissionsForRole('admin')).toEqual([]);
    expect(productMatchDiscoveryPermissionsForRole('member')).toEqual([]);
    expect(productMatchDiscoveryPermissionsForRole('viewer')).toEqual([]);
    for (const role of ROLES) {
      expect(roleGrantsProductMatchDiscovery(role)).toBe(role === 'owner');
    }
    expect(productMatchDiscoveryPermissionsForRole('owner')).not.toContain(
      PRODUCT_MATCH_EVALUATE_CONTROLLED_PERMISSION,
    );
    expect(productMatchEvaluationPermissionsForRole('owner')).not.toContain(
      PRODUCT_MATCH_DISCOVER_CONTROLLED_PERMISSION,
    );
  });
});
