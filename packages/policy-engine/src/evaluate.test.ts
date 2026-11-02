import { describe, expect, it } from 'vitest';

import { checkPriorityInvariants } from './evaluate.js';

describe('checkPriorityInvariants', () => {
  const valid = {
    contributions: [4000, 2000],
    weightedScoreCenti: 6000,
    upliftCenti: 0,
    priority: 60,
    band: { band: 'P2' },
  };

  it('DT8 accepts in-range arithmetic', () => {
    expect(checkPriorityInvariants(valid)).toBeNull();
  });

  it.each([
    [{ contributions: [-1] }, 'contribution_out_of_range'],
    [{ contributions: [10001] }, 'contribution_out_of_range'],
    [{ weightedScoreCenti: 10001 }, 'weighted_score_out_of_range'],
    [{ weightedScoreCenti: 0.5 }, 'weighted_score_out_of_range'],
    [{ upliftCenti: 4001 }, 'uplift_out_of_range'],
    [{ priority: 101 }, 'priority_out_of_range'],
    [{ priority: -1 }, 'priority_out_of_range'],
    [{ priority: Number.NaN }, 'priority_out_of_range'],
    [{ band: null }, 'band_unresolved'],
  ] as const)('DT8 rejects %o', (change, code) => {
    expect(checkPriorityInvariants({ ...valid, ...change })).toBe(code);
  });
});
