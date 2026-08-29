import type { GraphCompleteness, SbomSpecificationVersion } from '../lifecycle.js';
import { dependencyRelationshipTypes } from '../lifecycle.js';
import { err, ok, type Result } from '../result.js';
import { validateNormalizedComponent, type NormalizedComponent } from './component.js';
import { SBOM_INVALID_GRAPH, sbomValidationError } from './errors.js';
import { graphCompletenessMatchesCounts } from './graph-completeness.js';

export const parseWarningCodes = [
  'self_dependency_skipped',
  'duplicate_identity_collapsed',
] as const;
export type ParseWarningCode = (typeof parseWarningCodes)[number];

export type CountOnlyWarningSummary = {
  code: ParseWarningCode;
  count: number;
};

export type NormalizedDependencyEdge = {
  fromBomRef: string;
  toBomRef: string;
  relationshipType: (typeof dependencyRelationshipTypes)[number];
};

export type NormalizedComponentGraph = {
  specificationVersion: SbomSpecificationVersion;
  graphCompleteness: GraphCompleteness;
  components: readonly NormalizedComponent[];
  edges: readonly NormalizedDependencyEdge[];
  warnings: readonly CountOnlyWarningSummary[];
  componentCount: number;
  dependencyEdgeCount: number;
  warningCount: number;
  capturedAt: Date | null;
  parserVersion: string;
  normalizationVersion: string;
};

function isNonNegativeInt(value: number): boolean {
  return Number.isInteger(value) && value >= 0;
}

export function validateNormalizedComponentGraph(
  graph: NormalizedComponentGraph,
): Result<NormalizedComponentGraph> {
  if (
    graph.componentCount !== graph.components.length ||
    graph.dependencyEdgeCount !== graph.edges.length
  ) {
    return err(sbomValidationError('Graph counts must match component and edge array lengths.'));
  }

  const warningSum = graph.warnings.reduce((sum, warning) => sum + warning.count, 0);
  if (graph.warningCount !== warningSum) {
    return err(
      sbomValidationError('Warning count must equal the sum of count-only warning summaries.'),
    );
  }

  if (
    !isNonNegativeInt(graph.componentCount) ||
    !isNonNegativeInt(graph.dependencyEdgeCount) ||
    !isNonNegativeInt(graph.warningCount)
  ) {
    return err(SBOM_INVALID_GRAPH);
  }

  if (!graphCompletenessMatchesCounts(graph.graphCompleteness, graph)) {
    return err(
      sbomValidationError('graphCompleteness does not match stored component and edge counts.'),
    );
  }

  const components: NormalizedComponent[] = [];
  const bomRefs = new Set<string>();
  const identityKeys = new Set<string>();

  for (const component of graph.components) {
    const validated = validateNormalizedComponent(component);
    if (!validated.ok) {
      return validated;
    }
    if (identityKeys.has(validated.value.identityKey)) {
      return err(sbomValidationError('Normalized components must not repeat identityKey values.'));
    }
    identityKeys.add(validated.value.identityKey);
    if (validated.value.bomRef !== null) {
      if (validated.value.bomRef.length === 0) {
        return err(sbomValidationError('bomRef must be null or non-empty.'));
      }
      if (bomRefs.has(validated.value.bomRef)) {
        return err(sbomValidationError('Normalized components must not repeat bomRef values.'));
      }
      bomRefs.add(validated.value.bomRef);
    }
    components.push(validated.value);
  }

  for (const edge of graph.edges) {
    if (edge.relationshipType !== 'depends_on') {
      return err(sbomValidationError('Session 8 stores depends_on edges only.'));
    }
    if (edge.fromBomRef.length === 0 || edge.toBomRef.length === 0) {
      return err(sbomValidationError('Dependency edges require non-empty bom-ref endpoints.'));
    }
    if (edge.fromBomRef === edge.toBomRef) {
      return err(
        sbomValidationError('Self-dependency edges must be skipped as warnings, not stored.'),
      );
    }
    if (!bomRefs.has(edge.fromBomRef) || !bomRefs.has(edge.toBomRef)) {
      return err(
        sbomValidationError('Dependency edges must resolve to normalized component bom-refs.'),
      );
    }
  }

  for (const warning of graph.warnings) {
    if (!isNonNegativeInt(warning.count) || warning.count === 0) {
      return err(sbomValidationError('Warning summaries must use a positive count.'));
    }
  }

  return ok({
    ...graph,
    components,
  });
}
