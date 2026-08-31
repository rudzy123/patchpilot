import type { GraphCompleteness } from '../lifecycle.js';
import { err, ok, type Result } from '../result.js';
import { sbomValidationError } from './errors.js';

export type GraphCompletenessInputs = {
  componentCount: number;
  dependencyEdgeCount: number;
  skippedListedEdgeCount: number;
};

function isNonNegativeInt(value: number): boolean {
  return Number.isInteger(value) && value >= 0;
}

/**
 * Derive Session 8 graphCompleteness.
 *
 * - empty: no components after validation. This does not mean the Asset contains no software.
 * - no_dependencies: components stored and no usable dependency edges. This does not prove
 *   the software has no dependencies.
 * - partial: some edges stored, but listed refs were not a full closed stored set (skipped edges).
 * - complete: the document's validated dependency graph was fully represented. This is not
 *   exhaustive product inventory.
 */
export function deriveGraphCompleteness(input: GraphCompletenessInputs): Result<GraphCompleteness> {
  if (
    !isNonNegativeInt(input.componentCount) ||
    !isNonNegativeInt(input.dependencyEdgeCount) ||
    !isNonNegativeInt(input.skippedListedEdgeCount)
  ) {
    return err(sbomValidationError('Graph completeness counts must be non-negative integers.'));
  }

  if (input.componentCount === 0) {
    if (input.dependencyEdgeCount !== 0 || input.skippedListedEdgeCount !== 0) {
      return err(sbomValidationError('An empty graph cannot include dependency edges.'));
    }
    return ok('empty');
  }

  if (input.dependencyEdgeCount === 0) {
    return ok('no_dependencies');
  }

  if (input.skippedListedEdgeCount > 0) {
    return ok('partial');
  }

  return ok('complete');
}

export function graphCompletenessMatchesCounts(
  completeness: GraphCompleteness,
  input: Pick<GraphCompletenessInputs, 'componentCount' | 'dependencyEdgeCount'>,
): boolean {
  switch (completeness) {
    case 'empty':
      return input.componentCount === 0 && input.dependencyEdgeCount === 0;
    case 'no_dependencies':
      return input.componentCount > 0 && input.dependencyEdgeCount === 0;
    case 'partial':
    case 'complete':
      return input.componentCount > 0 && input.dependencyEdgeCount > 0;
  }
}
