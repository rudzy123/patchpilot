import { describe, expect, it } from 'vitest';

import {
  OSV_ACTIVATION_PREREQUISITE_EDGES,
  OSV_ACTIVATION_PREREQUISITE_NODES,
  OSV_ATTACHMENT_EDGES,
  OSV_CATALOG_GENERATION_EDGES,
  activationPrerequisiteGraphIsAcyclic,
  activationPrerequisitesSatisfied,
  attachmentGraphIsAcyclic,
  attachmentHasOutgoing,
  attachmentTransitionAllowed,
  catalogGenerationGraphIsAcyclic,
  catalogGenerationHasOutgoing,
  catalogGenerationTransitionAllowed,
} from './osv-acquisition-graphs.js';
import {
  osvAttachmentStates,
  osvCatalogLifecycleStates,
} from '@patchpilot/vulnerability-intelligence';

describe('OSV catalog-generation state graph', () => {
  it('is acyclic and lists every committed state', () => {
    expect(Object.keys(OSV_CATALOG_GENERATION_EDGES).sort()).toEqual(
      [...osvCatalogLifecycleStates].sort(),
    );
    expect(catalogGenerationGraphIsAcyclic()).toBe(true);
    expect(catalogGenerationHasOutgoing('active')).toBe(true);
    expect(catalogGenerationHasOutgoing('superseded')).toBe(false);
    expect(catalogGenerationHasOutgoing('failed')).toBe(false);
    expect(catalogGenerationHasOutgoing('cancelled')).toBe(false);
    expect(catalogGenerationHasOutgoing('quarantined')).toBe(false);
  });

  it('accepts only committed edges over every ordered state pair', () => {
    for (const from of osvCatalogLifecycleStates) {
      for (const to of osvCatalogLifecycleStates) {
        const allowed = catalogGenerationTransitionAllowed(from, to);
        const listed = OSV_CATALOG_GENERATION_EDGES[from].includes(to);
        expect(allowed, `${from}->${to}`).toBe(listed);
      }
    }
    expect(catalogGenerationTransitionAllowed('planned', 'acquiring')).toBe(true);
    expect(catalogGenerationTransitionAllowed('acquiring', 'ready_for_activation')).toBe(true);
    expect(catalogGenerationTransitionAllowed('ready_for_activation', 'active')).toBe(true);
    expect(catalogGenerationTransitionAllowed('active', 'superseded')).toBe(true);
    expect(catalogGenerationTransitionAllowed('planned', 'active')).toBe(false);
    expect(catalogGenerationTransitionAllowed('acquiring', 'active')).toBe(false);
    expect(catalogGenerationTransitionAllowed('failed', 'active')).toBe(false);
    expect(catalogGenerationTransitionAllowed('cancelled', 'active')).toBe(false);
    expect(catalogGenerationTransitionAllowed('quarantined', 'active')).toBe(false);
    expect(catalogGenerationTransitionAllowed('superseded', 'active')).toBe(false);
    expect(catalogGenerationTransitionAllowed('cancelled', 'acquiring')).toBe(false);
  });
});

describe('OSV attachment lifecycle graph', () => {
  it('is acyclic and forbids terminal mutation', () => {
    expect(Object.keys(OSV_ATTACHMENT_EDGES).sort()).toEqual([...osvAttachmentStates].sort());
    expect(attachmentGraphIsAcyclic()).toBe(true);
    expect(attachmentHasOutgoing('attached')).toBe(false);
    expect(attachmentHasOutgoing('orphaned')).toBe(false);
    expect(attachmentHasOutgoing('rejected')).toBe(false);
  });

  it('accepts only committed edges over every ordered state pair', () => {
    for (const from of osvAttachmentStates) {
      for (const to of osvAttachmentStates) {
        const allowed = attachmentTransitionAllowed(from, to);
        const listed = OSV_ATTACHMENT_EDGES[from].includes(to);
        expect(allowed, `${from}->${to}`).toBe(listed);
      }
    }
    expect(attachmentTransitionAllowed('staged', 'attached')).toBe(true);
    expect(attachmentTransitionAllowed('attached', 'staged')).toBe(false);
    expect(attachmentTransitionAllowed('attached', 'orphaned')).toBe(false);
    expect(attachmentTransitionAllowed('orphaned', 'attached')).toBe(false);
    expect(attachmentTransitionAllowed('rejected', 'attached')).toBe(false);
  });
});

describe('OSV activation prerequisite graph', () => {
  it('is acyclic and requires every mandatory predecessor', () => {
    expect(activationPrerequisiteGraphIsAcyclic()).toBe(true);
    expect(OSV_ACTIVATION_PREREQUISITE_NODES).not.toContain('matching_complete');
    expect(OSV_ACTIVATION_PREREQUISITE_NODES.join(' ')).not.toMatch(/tenant|finding|mal/i);
    const fromNodes = new Set(OSV_ACTIVATION_PREREQUISITE_EDGES.map(([from]) => from));
    const toNodes = new Set(OSV_ACTIVATION_PREREQUISITE_EDGES.map(([, to]) => to));
    expect(fromNodes.has('inventory_complete')).toBe(true);
    expect(toNodes.has('candidate_ready_for_activation')).toBe(true);
    expect(
      activationPrerequisitesSatisfied({
        inventoryComplete: true,
        eligibleBodiesComplete: true,
        parserComplete: true,
        parsedCatalogComplete: true,
        acceptedReconciliation: true,
        noBlockingQuarantine: true,
        noImmutableConflict: true,
        versionSetConsistent: true,
        candidateReadyForActivation: true,
      }),
    ).toBe(true);
    for (const key of [
      'inventoryComplete',
      'eligibleBodiesComplete',
      'parserComplete',
      'parsedCatalogComplete',
      'acceptedReconciliation',
      'noBlockingQuarantine',
      'noImmutableConflict',
      'versionSetConsistent',
      'candidateReadyForActivation',
    ] as const) {
      const snapshot = {
        inventoryComplete: true,
        eligibleBodiesComplete: true,
        parserComplete: true,
        parsedCatalogComplete: true,
        acceptedReconciliation: true,
        noBlockingQuarantine: true,
        noImmutableConflict: true,
        versionSetConsistent: true,
        candidateReadyForActivation: true,
        [key]: false,
      };
      expect(activationPrerequisitesSatisfied(snapshot), key).toBe(false);
    }
  });
});
