/**
 * Session 11 Batch 5D explicit finite graphs for OSV acquisition adapters.
 *
 * These are adjacency predicates over committed Batch 5B states. They do not
 * execute matching, Findings, object storage, or provider retrieval.
 */

import {
  osvAttachmentStates,
  osvCatalogLifecycleStates,
  type OsvAttachmentState,
  type OsvCatalogLifecycleState,
} from '@patchpilot/vulnerability-intelligence';

export const OSV_CATALOG_GENERATION_EDGES: Readonly<
  Record<OsvCatalogLifecycleState, readonly OsvCatalogLifecycleState[]>
> = Object.freeze({
  planned: Object.freeze(['acquiring', 'failed', 'quarantined', 'cancelled'] as const),
  acquiring: Object.freeze(['ready_for_activation', 'failed', 'quarantined', 'cancelled'] as const),
  ready_for_activation: Object.freeze(['active', 'failed', 'quarantined', 'cancelled'] as const),
  active: Object.freeze(['superseded'] as const),
  superseded: Object.freeze([] as const),
  failed: Object.freeze([] as const),
  quarantined: Object.freeze([] as const),
  cancelled: Object.freeze([] as const),
});

export const OSV_ATTACHMENT_EDGES: Readonly<
  Record<OsvAttachmentState, readonly OsvAttachmentState[]>
> = Object.freeze({
  staged: Object.freeze(['attached', 'orphaned', 'rejected'] as const),
  attached: Object.freeze([] as const),
  orphaned: Object.freeze([] as const),
  rejected: Object.freeze([] as const),
});

export const OSV_ACTIVATION_PREREQUISITE_NODES = [
  'inventory_complete',
  'eligible_bodies_complete',
  'parser_complete',
  'parsed_catalog_complete',
  'accepted_reconciliation',
  'no_blocking_quarantine',
  'no_immutable_conflict',
  'version_set_consistent',
  'candidate_ready_for_activation',
] as const;

export type OsvActivationPrerequisiteNode = (typeof OSV_ACTIVATION_PREREQUISITE_NODES)[number];

/**
 * Directed prerequisite edges. Matching completeness, tenant state, Finding
 * state, and MAL matching eligibility are intentionally absent.
 */
export const OSV_ACTIVATION_PREREQUISITE_EDGES: ReadonlyArray<
  readonly [OsvActivationPrerequisiteNode, OsvActivationPrerequisiteNode]
> = Object.freeze([
  ['inventory_complete', 'eligible_bodies_complete'],
  ['eligible_bodies_complete', 'parser_complete'],
  ['parser_complete', 'parsed_catalog_complete'],
  ['parsed_catalog_complete', 'accepted_reconciliation'],
  ['accepted_reconciliation', 'no_blocking_quarantine'],
  ['no_blocking_quarantine', 'no_immutable_conflict'],
  ['no_immutable_conflict', 'version_set_consistent'],
  ['version_set_consistent', 'candidate_ready_for_activation'],
]);

const CATALOG_EDGE_SET: ReadonlySet<string> = new Set(
  osvCatalogLifecycleStates.flatMap((from) =>
    OSV_CATALOG_GENERATION_EDGES[from].map((to) => `${from}->${to}`),
  ),
);

const ATTACHMENT_EDGE_SET: ReadonlySet<string> = new Set(
  osvAttachmentStates.flatMap((from) => OSV_ATTACHMENT_EDGES[from].map((to) => `${from}->${to}`)),
);

export function catalogGenerationTransitionAllowed(
  from: OsvCatalogLifecycleState,
  to: OsvCatalogLifecycleState,
): boolean {
  return CATALOG_EDGE_SET.has(`${from}->${to}`);
}

export function attachmentTransitionAllowed(
  from: OsvAttachmentState,
  to: OsvAttachmentState,
): boolean {
  return ATTACHMENT_EDGE_SET.has(`${from}->${to}`);
}

export function catalogGenerationHasOutgoing(state: OsvCatalogLifecycleState): boolean {
  return OSV_CATALOG_GENERATION_EDGES[state].length > 0;
}

export function attachmentHasOutgoing(state: OsvAttachmentState): boolean {
  return OSV_ATTACHMENT_EDGES[state].length > 0;
}

export function catalogGenerationGraphIsAcyclic(): boolean {
  return !hasCycle(osvCatalogLifecycleStates, (node) => {
    const state = node as OsvCatalogLifecycleState;
    return OSV_CATALOG_GENERATION_EDGES[state];
  });
}

export function attachmentGraphIsAcyclic(): boolean {
  return !hasCycle(osvAttachmentStates, (node) => {
    const state = node as OsvAttachmentState;
    return OSV_ATTACHMENT_EDGES[state];
  });
}

export function activationPrerequisiteGraphIsAcyclic(): boolean {
  const outgoing = new Map<string, string[]>();
  for (const node of OSV_ACTIVATION_PREREQUISITE_NODES) {
    outgoing.set(node, []);
  }
  for (const [from, to] of OSV_ACTIVATION_PREREQUISITE_EDGES) {
    const next = outgoing.get(from);
    if (next === undefined) {
      return false;
    }
    next.push(to);
  }
  return !hasCycle(OSV_ACTIVATION_PREREQUISITE_NODES, (node) => outgoing.get(node) ?? []);
}

export type OsvActivationPrerequisiteSnapshot = {
  readonly inventoryComplete: boolean;
  readonly eligibleBodiesComplete: boolean;
  readonly parserComplete: boolean;
  readonly parsedCatalogComplete: boolean;
  readonly acceptedReconciliation: boolean;
  readonly noBlockingQuarantine: boolean;
  readonly noImmutableConflict: boolean;
  readonly versionSetConsistent: boolean;
  readonly candidateReadyForActivation: boolean;
};

export function activationPrerequisitesSatisfied(
  snapshot: OsvActivationPrerequisiteSnapshot,
): boolean {
  return (
    snapshot.inventoryComplete &&
    snapshot.eligibleBodiesComplete &&
    snapshot.parserComplete &&
    snapshot.parsedCatalogComplete &&
    snapshot.acceptedReconciliation &&
    snapshot.noBlockingQuarantine &&
    snapshot.noImmutableConflict &&
    snapshot.versionSetConsistent &&
    snapshot.candidateReadyForActivation
  );
}

function hasCycle(
  nodes: readonly string[],
  outgoing: (node: string) => readonly string[],
): boolean {
  const visiting = new Set<string>();
  const visited = new Set<string>();

  const visit = (node: string): boolean => {
    if (visiting.has(node)) {
      return true;
    }
    if (visited.has(node)) {
      return false;
    }
    visiting.add(node);
    for (const next of outgoing(node)) {
      if (visit(next)) {
        return true;
      }
    }
    visiting.delete(node);
    visited.add(node);
    return false;
  };

  for (const node of nodes) {
    if (visit(node)) {
      return true;
    }
  }
  return false;
}
