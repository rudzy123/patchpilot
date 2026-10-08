import { describe, expect, it } from 'vitest';

import {
  canPresentControlledFindingCreation,
  canPresentControlledFindingInspection,
  canPresentControlledFindingTargets,
} from './finding-permissions';

describe('controlled Finding presentation permissions', () => {
  it('lets owners and admins review targets and lets only owners create', () => {
    expect(canPresentControlledFindingTargets('owner')).toBe(true);
    expect(canPresentControlledFindingTargets('admin')).toBe(true);
    expect(canPresentControlledFindingCreation('owner')).toBe(true);
    expect(canPresentControlledFindingCreation('admin')).toBe(false);
    expect(canPresentControlledFindingInspection('owner')).toBe(true);
    expect(canPresentControlledFindingInspection('admin')).toBe(true);
  });

  it('withholds the workflow from member, viewer, and a missing role', () => {
    for (const role of ['member', 'viewer', null, undefined] as const) {
      expect(canPresentControlledFindingTargets(role)).toBe(false);
      expect(canPresentControlledFindingCreation(role)).toBe(false);
      expect(canPresentControlledFindingInspection(role)).toBe(false);
    }
  });
});
