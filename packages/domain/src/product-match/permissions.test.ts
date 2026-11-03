/**
 * Owner-only product-match evaluation permission.
 * Finding permissions and instance advisory grants are not this grant.
 */

import { describe, expect, it } from 'vitest';

import type { MembershipRole } from '../lifecycle.js';
import {
  PRODUCT_MATCH_EVALUATE_CONTROLLED_PERMISSION,
  productMatchEvaluationPermissionsForRole,
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
});
