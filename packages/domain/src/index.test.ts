import { describe, expect, it } from 'vitest';

import {
  boundPageSize,
  DEFAULT_PAGE_SIZE,
  err,
  errorCodes,
  evidenceKinds,
  findingStates,
  MAX_PAGE_SIZE,
  membershipRoles,
  MIN_PAGE_SIZE,
  ok,
  organizationStatuses,
  riskPolicyScopes,
  type FindingRepository,
  type OrganizationRepository,
} from './index.js';

describe('result boundary', () => {
  it('wraps success and failure without product entities', () => {
    expect(ok(1)).toEqual({ ok: true, value: 1 });
    expect(err({ code: 'internal', message: 'boom' }).ok).toBe(false);
  });

  it('exposes the API error taxonomy', () => {
    expect(errorCodes).toContain('validation');
    expect(errorCodes).not.toContain('organization');
  });
});

describe('lifecycle catalogs', () => {
  it('uses canonical organization and membership states', () => {
    expect(organizationStatuses).toEqual(['active', 'archived']);
    expect(membershipRoles).toEqual(['owner', 'admin', 'member', 'viewer']);
    expect(findingStates).not.toContain('reopened');
    expect(findingStates).not.toContain('assigned');
    expect(riskPolicyScopes).toEqual(['builtin', 'organization']);
    expect(evidenceKinds).toContain('export_snapshot');
  });
});

describe('page size bounds', () => {
  it('defaults and clamps page size', () => {
    expect(boundPageSize(undefined)).toBe(DEFAULT_PAGE_SIZE);
    expect(boundPageSize(0)).toBe(MIN_PAGE_SIZE);
    expect(boundPageSize(1000)).toBe(MAX_PAGE_SIZE);
    expect(boundPageSize(37)).toBe(37);
  });
});

describe('tenant repository ports', () => {
  it('require organizationId as the first argument on tenant-owned lookups', () => {
    const organizationRepo: Pick<OrganizationRepository, 'findById'> = {
      findById: async (organizationId: string, id: string) => {
        expect(organizationId.length).toBeGreaterThan(0);
        expect(id.length).toBeGreaterThan(0);
        return undefined;
      },
    };
    const findingRepo: Pick<FindingRepository, 'findById'> = {
      findById: async (organizationId: string, id: string) => {
        expect(organizationId.length).toBeGreaterThan(0);
        expect(id.length).toBeGreaterThan(0);
        return undefined;
      },
    };

    void organizationRepo.findById('org', 'id');
    void findingRepo.findById('org', 'id');
    expect(organizationRepo.findById.length).toBe(2);
    expect(findingRepo.findById.length).toBe(2);
  });
});
