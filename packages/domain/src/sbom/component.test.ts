import { describe, expect, it } from 'vitest';

import { componentIdentityStates } from '../lifecycle.js';
import {
  buildComponentIdentityKey,
  componentOccurrenceNormalizationKey,
  isMatchableComponentIdentity,
  occurrenceAliasConflict,
  validateNormalizedComponent,
  type NormalizedComponent,
} from './component.js';
import { validateNormalizedComponentGraph } from './graph.js';
import { unknownComponentVersion } from './version.js';

const identity = buildComponentIdentityKey({
  identityState: 'resolved',
  versionlessPurl: 'pkg:npm/left-pad',
  ecosystem: 'npm',
  namespace: null,
  name: 'left-pad',
  bomRef: 'pkg:npm/left-pad',
});

function resolvedComponent(): NormalizedComponent {
  if (!identity.ok) {
    throw new Error('expected identity key');
  }
  return {
    bomRef: 'pkg:npm/left-pad',
    name: 'left-pad',
    namespace: null,
    ecosystem: 'npm',
    identityState: 'resolved',
    versionlessPurl: 'pkg:npm/left-pad',
    versionedPurl: 'pkg:npm/left-pad@1.3.0',
    version: { kind: 'known', value: '1.3.0' },
    isDirect: true,
    identityKey: identity.value,
  };
}

describe('normalized component', () => {
  it('expresses nullable bom-ref, namespace, ecosystem, PURL, and directness', () => {
    const component = resolvedComponent();
    expect(validateNormalizedComponent(component).ok).toBe(true);
    expect(isMatchableComponentIdentity(component)).toBe(true);
    expect(componentIdentityStates).toContain(component.identityState);
  });

  it('ignores unresolved identities for future matching', () => {
    const key = buildComponentIdentityKey({
      identityState: 'unsupported',
      versionlessPurl: null,
      ecosystem: null,
      namespace: null,
      name: 'blob',
      bomRef: null,
    });
    expect(key.ok).toBe(true);
    if (!key.ok) {
      return;
    }
    const unresolved: NormalizedComponent = {
      bomRef: null,
      name: 'blob',
      namespace: null,
      ecosystem: null,
      identityState: 'unsupported',
      versionlessPurl: null,
      versionedPurl: null,
      version: unknownComponentVersion(),
      isDirect: null,
      identityKey: key.value,
    };
    expect(isMatchableComponentIdentity(unresolved)).toBe(false);
    expect(validateNormalizedComponent(unresolved).ok).toBe(true);
  });

  it('rejects identityKey drift', () => {
    expect(
      validateNormalizedComponent({
        ...resolvedComponent(),
        identityKey: 'other',
      }).ok,
    ).toBe(false);
  });
});

describe('normalized graph', () => {
  it('accepts a bounded graph without raw document fields', () => {
    const parent = resolvedComponent();
    const childKey = buildComponentIdentityKey({
      identityState: 'resolved',
      versionlessPurl: 'pkg:npm/dep',
      ecosystem: 'npm',
      namespace: null,
      name: 'dep',
      bomRef: 'pkg:npm/dep',
    });
    if (!childKey.ok) {
      throw new Error('expected child key');
    }
    const child: NormalizedComponent = {
      bomRef: 'pkg:npm/dep',
      name: 'dep',
      namespace: null,
      ecosystem: 'npm',
      identityState: 'resolved',
      versionlessPurl: 'pkg:npm/dep',
      versionedPurl: null,
      version: { kind: 'known', value: '2.0.0' },
      isDirect: false,
      identityKey: childKey.value,
    };

    const graph = validateNormalizedComponentGraph({
      specificationVersion: '1.6',
      graphCompleteness: 'complete',
      components: [parent, child],
      edges: [
        {
          fromBomRef: parent.bomRef ?? '',
          toBomRef: child.bomRef ?? '',
          relationshipType: 'depends_on',
        },
      ],
      warnings: [{ code: 'self_dependency_skipped', count: 1 }],
      componentCount: 2,
      dependencyEdgeCount: 1,
      warningCount: 1,
      capturedAt: new Date('2026-08-29T12:00:00.000Z'),
      parserVersion: '0.1.0',
      normalizationVersion: '1',
    });
    expect(graph.ok).toBe(true);
    if (graph.ok) {
      expect(graph.value).not.toHaveProperty('externalReferences');
      expect(graph.value).not.toHaveProperty('componentsJson');
    }
  });

  it('rejects unresolved dependency refs and self-edges', () => {
    const parent = resolvedComponent();
    expect(
      validateNormalizedComponentGraph({
        specificationVersion: '1.5',
        graphCompleteness: 'complete',
        components: [parent],
        edges: [
          { fromBomRef: parent.bomRef ?? '', toBomRef: 'missing', relationshipType: 'depends_on' },
        ],
        warnings: [],
        componentCount: 1,
        dependencyEdgeCount: 1,
        warningCount: 0,
        capturedAt: null,
        parserVersion: '0.1.0',
        normalizationVersion: '1',
      }).ok,
    ).toBe(false);
    expect(
      validateNormalizedComponentGraph({
        specificationVersion: '1.5',
        graphCompleteness: 'no_dependencies',
        components: [parent],
        edges: [
          {
            fromBomRef: parent.bomRef ?? '',
            toBomRef: parent.bomRef ?? '',
            relationshipType: 'depends_on',
          },
        ],
        warnings: [],
        componentCount: 1,
        dependencyEdgeCount: 1,
        warningCount: 0,
        capturedAt: null,
        parserVersion: '0.1.0',
        normalizationVersion: '1',
      }).ok,
    ).toBe(false);
  });

  it('accepts two observed versions of one versionless component and rejects a repeated version', () => {
    const first = resolvedComponent();
    const second: NormalizedComponent = {
      ...first,
      bomRef: 'pkg:npm/left-pad@2.0.0',
      version: { kind: 'known', value: '2.0.0' },
      versionedPurl: 'pkg:npm/left-pad@2.0.0',
      isDirect: false,
    };
    expect(second.identityKey).toBe(first.identityKey);
    expect(componentOccurrenceNormalizationKey(first)).not.toBe(
      componentOccurrenceNormalizationKey(second),
    );

    const distinct = validateNormalizedComponentGraph({
      specificationVersion: '1.6',
      graphCompleteness: 'complete',
      components: [first, second],
      edges: [
        {
          fromBomRef: first.bomRef ?? '',
          toBomRef: second.bomRef ?? '',
          relationshipType: 'depends_on',
        },
      ],
      warnings: [],
      componentCount: 2,
      dependencyEdgeCount: 1,
      warningCount: 0,
      capturedAt: null,
      parserVersion: '0.1.0',
      normalizationVersion: '2',
    });
    expect(distinct.ok).toBe(true);

    const repeated = validateNormalizedComponentGraph({
      specificationVersion: '1.6',
      graphCompleteness: 'complete',
      components: [first, { ...first, bomRef: 'alias-ref' }],
      edges: [
        {
          fromBomRef: first.bomRef ?? '',
          toBomRef: 'alias-ref',
          relationshipType: 'depends_on',
        },
      ],
      warnings: [],
      componentCount: 2,
      dependencyEdgeCount: 1,
      warningCount: 0,
      capturedAt: null,
      parserVersion: '0.1.0',
      normalizationVersion: '2',
    });
    expect(repeated.ok).toBe(false);
  });
});

describe('occurrence alias facts', () => {
  const known = { kind: 'known' as const, value: '1.0.0' };
  const hashA = new Set(['a'.repeat(64)]);
  const hashB = new Set(['b'.repeat(64)]);

  it('allows a missing hash or versioned PURL and rejects present contradictions', () => {
    expect(
      occurrenceAliasConflict(
        { version: known, versionedPurl: 'pkg:npm/left-pad@1.0.0', sha256Hex: hashA },
        { version: known, versionedPurl: 'pkg:npm/left-pad@1.0.0', sha256Hex: null },
      ),
    ).toBeNull();
    expect(
      occurrenceAliasConflict(
        { version: known, versionedPurl: null, sha256Hex: null },
        { version: known, versionedPurl: 'pkg:npm/left-pad@1.0.0', sha256Hex: hashA },
      ),
    ).toBeNull();
    expect(
      occurrenceAliasConflict(
        { version: known, versionedPurl: 'pkg:npm/left-pad@1.0.0', sha256Hex: hashA },
        { version: known, versionedPurl: 'pkg:npm/left-pad@1.0.0', sha256Hex: hashB },
      ),
    ).toBe('sha256');
    expect(
      occurrenceAliasConflict(
        { version: known, versionedPurl: 'pkg:npm/left-pad@1.0.0', sha256Hex: null },
        { version: known, versionedPurl: 'pkg:npm/left-pad@9.9.9', sha256Hex: null },
      ),
    ).toBe('versioned_purl');
    expect(
      occurrenceAliasConflict(
        { version: known, versionedPurl: null, sha256Hex: null },
        { version: { kind: 'unknown' }, versionedPurl: null, sha256Hex: null },
      ),
    ).toBe('version');
  });
});
