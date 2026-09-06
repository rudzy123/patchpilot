import { describe, expect, it } from 'vitest';

import {
  createOsvAdvisoryWithdrawal,
  osvPresenceKinds,
} from '@patchpilot/vulnerability-intelligence';

describe('OSV provider presence and absence semantics', () => {
  it('keeps every presence kind pairwise distinct', () => {
    for (let i = 0; i < osvPresenceKinds.length; i += 1) {
      for (let j = 0; j < osvPresenceKinds.length; j += 1) {
        const left = osvPresenceKinds[i];
        const right = osvPresenceKinds[j];
        expect(left === right, `${left} vs ${right}`).toBe(i === j);
      }
    }
    expect(osvPresenceKinds).toContain('provider_absent_observed');
    expect(osvPresenceKinds).not.toContain('withdrawn');
    expect(osvPresenceKinds).not.toContain('provider_present_observed');
  });

  it('treats withdrawal as distinct from absence, revocation, retrieval miss, parser failure, and exclusion', () => {
    const withdrawn = createOsvAdvisoryWithdrawal({
      revisionId: '55555555-5555-4555-8555-555555555555',
      withdrawnAt: '2026-09-04T18:00:00.000Z',
    });
    expect(withdrawn.ok).toBe(true);
    if (!withdrawn.ok) {
      return;
    }
    expect(withdrawn.value.distinctFromProviderAbsence).toBe(true);
    expect(withdrawn.value.distinctFromSourceRevocation).toBe(true);
    expect(withdrawn.value.closesFinding).toBe(false);
    expect(osvPresenceKinds.includes('provider_absent_observed')).toBe(true);
    expect(osvPresenceKinds.includes('source_license_eligibility_revoked')).toBe(true);
    expect(osvPresenceKinds.includes('generation_not_found')).toBe(true);
    expect(osvPresenceKinds.includes('parser_failure')).toBe(true);
    expect(osvPresenceKinds.includes('catalog_exclusion')).toBe(true);
  });
});
