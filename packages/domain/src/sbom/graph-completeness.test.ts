import { describe, expect, it } from 'vitest';

import { deriveGraphCompleteness, graphCompletenessMatchesCounts } from './graph-completeness.js';

describe('graph completeness', () => {
  it('treats an empty validated document as empty, not as an asset without software', () => {
    expect(
      deriveGraphCompleteness({
        componentCount: 0,
        dependencyEdgeCount: 0,
        skippedListedEdgeCount: 0,
      }),
    ).toEqual({
      ok: true,
      value: 'empty',
    });
    expect(
      graphCompletenessMatchesCounts('empty', { componentCount: 0, dependencyEdgeCount: 0 }),
    ).toBe(true);
    expect(
      graphCompletenessMatchesCounts('empty', { componentCount: 1, dependencyEdgeCount: 0 }),
    ).toBe(false);
  });

  it('treats components without usable edges as no_dependencies, not as proof of no dependencies', () => {
    expect(
      deriveGraphCompleteness({
        componentCount: 3,
        dependencyEdgeCount: 0,
        skippedListedEdgeCount: 2,
      }),
    ).toEqual({ ok: true, value: 'no_dependencies' });
    expect(
      graphCompletenessMatchesCounts('no_dependencies', {
        componentCount: 3,
        dependencyEdgeCount: 0,
      }),
    ).toBe(true);
  });

  it('marks a fully represented validated graph complete without claiming exhaustive inventory', () => {
    expect(
      deriveGraphCompleteness({
        componentCount: 4,
        dependencyEdgeCount: 5,
        skippedListedEdgeCount: 0,
      }),
    ).toEqual({ ok: true, value: 'complete' });
    expect(
      graphCompletenessMatchesCounts('complete', { componentCount: 4, dependencyEdgeCount: 5 }),
    ).toBe(true);
  });

  it('marks stored edges with skipped listed refs as partial', () => {
    expect(
      deriveGraphCompleteness({
        componentCount: 4,
        dependencyEdgeCount: 2,
        skippedListedEdgeCount: 1,
      }),
    ).toEqual({ ok: true, value: 'partial' });
    expect(
      graphCompletenessMatchesCounts('partial', { componentCount: 4, dependencyEdgeCount: 2 }),
    ).toBe(true);
  });

  it('rejects impossible empty graphs that still include edges', () => {
    expect(
      deriveGraphCompleteness({
        componentCount: 0,
        dependencyEdgeCount: 1,
        skippedListedEdgeCount: 0,
      }).ok,
    ).toBe(false);
  });
});
