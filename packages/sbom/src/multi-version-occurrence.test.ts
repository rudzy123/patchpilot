import { createHash } from 'node:crypto';

import { SBOM_NORMALIZATION_VERSION_DEFAULT } from '@patchpilot/config';
import {
  CURRENT_SBOM_NORMALIZATION_VERSION,
  HISTORICAL_SBOM_NORMALIZATION_VERSION,
} from '@patchpilot/domain';
import { describe, expect, it } from 'vitest';

import { normalizeCycloneDxDocument } from './normalize-cyclonedx.js';
import { parseSbomParserRequest } from './parse-document.js';
import { defaultSbomParserLimits } from './parser-limits.js';
import type { ParserWorkerRequest, ParserWorkerSuccess } from './parser-thread.js';

const REQUEST_ID = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const HASH_A = 'ab'.repeat(32);
const HASH_B = 'cd'.repeat(32);

function bufferWithHash(text: string): { bytes: ArrayBuffer; sha256: string; byteLength: number } {
  const view = Uint8Array.from(Buffer.from(text, 'utf8'));
  const bytes = view.buffer.slice(view.byteOffset, view.byteOffset + view.byteLength);
  const sha256 = createHash('sha256').update(Buffer.from(bytes)).digest('hex');
  return { bytes, sha256, byteLength: bytes.byteLength };
}

function requestFromDocument(
  document: unknown,
  normalizationVersion: string = CURRENT_SBOM_NORMALIZATION_VERSION,
): ParserWorkerRequest {
  const payload = bufferWithHash(JSON.stringify(document));
  return {
    requestId: REQUEST_ID,
    bytes: payload.bytes,
    expectedSha256: payload.sha256,
    byteLength: payload.byteLength,
    limits: defaultSbomParserLimits(),
    parserVersion: '0.1.0',
    normalizationVersion,
  };
}

function library(
  bomRef: string,
  name: string,
  version: string | undefined,
  purl: string,
  hashes?: Array<{ alg: string; content: string }>,
): Record<string, unknown> {
  return {
    type: 'library',
    'bom-ref': bomRef,
    name,
    ...(version === undefined ? {} : { version }),
    purl,
    ...(hashes === undefined ? {} : { hashes }),
  };
}

function document(input: {
  components: Record<string, unknown>[];
  dependencies: Array<{ ref: string; dependsOn?: string[] }>;
}): Record<string, unknown> {
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    version: 1,
    metadata: {
      timestamp: '2026-10-05T12:00:00Z',
      component: library('app', 'app', '1.0.0', 'pkg:npm/app@1.0.0'),
    },
    components: input.components,
    dependencies: input.dependencies,
  };
}

function succeed(documentBody: Record<string, unknown>): ParserWorkerSuccess {
  const result = parseSbomParserRequest(requestFromDocument(documentBody));
  expect(result.ok).toBe(true);
  if (!result.ok) {
    throw new Error('expected a normalized graph');
  }
  return result;
}

function versionsOf(result: ParserWorkerSuccess, name: string): string[] {
  return result.components
    .filter((component) => component.name === name)
    .map((component) => (component.version.kind === 'known' ? component.version.value : 'unknown'))
    .sort();
}

describe('multi-version component occurrences', () => {
  it('uses normalization version 2 for new graphs and rejects the historical label', () => {
    expect(CURRENT_SBOM_NORMALIZATION_VERSION).toBe('2');
    expect(HISTORICAL_SBOM_NORMALIZATION_VERSION).toBe('1');
    expect(SBOM_NORMALIZATION_VERSION_DEFAULT).toBe(CURRENT_SBOM_NORMALIZATION_VERSION);

    const body = document({
      components: [library('dep', 'dep', '1.0.0', 'pkg:npm/dep@1.0.0')],
      dependencies: [{ ref: 'app', dependsOn: ['dep'] }],
    });
    const current = succeed(body);
    expect(current.normalizationVersion).toBe(CURRENT_SBOM_NORMALIZATION_VERSION);
    expect(
      parseSbomParserRequest(requestFromDocument(body, HISTORICAL_SBOM_NORMALIZATION_VERSION)),
    ).toEqual({
      ok: false,
      disposition: 'rejected',
      code: 'unsupported_normalization_version',
    });
  });

  it('preserves two known versions, bom-refs, and the edges that address them', () => {
    const result = succeed(
      document({
        components: [
          library('pad-1', 'left-pad', '1.0.0', 'pkg:npm/left-pad@1.0.0'),
          library('pad-2', 'left-pad', '2.0.0', 'pkg:npm/left-pad@2.0.0'),
        ],
        dependencies: [{ ref: 'app', dependsOn: ['pad-1', 'pad-2'] }],
      }),
    );

    const pads = result.components.filter((component) => component.name === 'left-pad');
    expect(pads).toHaveLength(2);
    expect(new Set(pads.map((component) => component.identityKey)).size).toBe(1);
    expect(pads.every((component) => component.identityKey === 'purl:pkg:npm/left-pad')).toBe(true);
    expect(versionsOf(result, 'left-pad')).toEqual(['1.0.0', '2.0.0']);
    expect(pads.map((component) => component.bomRef).sort()).toEqual(['pad-1', 'pad-2']);
    expect(result.edges).toEqual([
      { fromBomRef: 'app', toBomRef: 'pad-1', relationshipType: 'depends_on' },
      { fromBomRef: 'app', toBomRef: 'pad-2', relationshipType: 'depends_on' },
    ]);
    expect(result.warnings).toEqual([]);
    expect(JSON.stringify(result)).not.toContain('unaffected');
  });

  it('keeps a direct version and a transitive version on separate occurrences', () => {
    const result = succeed(
      document({
        components: [
          library('pad-2', 'left-pad', '2.0.0', 'pkg:npm/left-pad@2.0.0'),
          library('mid', 'mid', '3.0.0', 'pkg:npm/mid@3.0.0'),
          library('pad-1', 'left-pad', '1.0.0', 'pkg:npm/left-pad@1.0.0'),
        ],
        dependencies: [
          { ref: 'app', dependsOn: ['pad-2', 'mid'] },
          { ref: 'mid', dependsOn: ['pad-1'] },
          { ref: 'pad-2', dependsOn: ['pad-1'] },
          { ref: 'pad-1', dependsOn: ['pad-2'] },
        ],
      }),
    );

    const pad1 = result.components.find((component) => component.bomRef === 'pad-1');
    const pad2 = result.components.find((component) => component.bomRef === 'pad-2');
    const mid = result.components.find((component) => component.bomRef === 'mid');
    expect(pad1?.version).toEqual({ kind: 'known', value: '1.0.0' });
    expect(pad2?.version).toEqual({ kind: 'known', value: '2.0.0' });
    expect(pad1?.identityKey).toBe(pad2?.identityKey);
    expect(pad1?.isDirect).toBe(false);
    expect(pad2?.isDirect).toBe(true);
    expect(mid?.isDirect).toBe(true);
    expect(result.edges).toEqual([
      { fromBomRef: 'app', toBomRef: 'pad-2', relationshipType: 'depends_on' },
      { fromBomRef: 'app', toBomRef: 'mid', relationshipType: 'depends_on' },
      { fromBomRef: 'mid', toBomRef: 'pad-1', relationshipType: 'depends_on' },
      { fromBomRef: 'pad-2', toBomRef: 'pad-1', relationshipType: 'depends_on' },
      { fromBomRef: 'pad-1', toBomRef: 'pad-2', relationshipType: 'depends_on' },
    ]);
    expect(result.edges.some((edge) => edge.fromBomRef === edge.toBomRef)).toBe(false);
    expect(result.components.filter((component) => component.name === 'left-pad')).toHaveLength(2);
  });

  it('aliases agreeing same-version representations and repeated paths without a second occurrence', () => {
    const result = succeed(
      document({
        components: [
          library('pad-a', 'left-pad', '1.0.0', 'pkg:npm/left-pad@1.0.0', [
            { alg: 'SHA-256', content: HASH_A },
          ]),
          library('pad-b', 'left-pad', '1.0.0', 'pkg:npm/left-pad@1.0.0?os=linux#lib/index.js', [
            { alg: 'SHA-256', content: HASH_A.toUpperCase() },
            { alg: 'SHA-1', content: 'a'.repeat(40) },
          ]),
          library('mid', 'mid', '3.0.0', 'pkg:npm/mid@3.0.0'),
        ],
        dependencies: [
          { ref: 'app', dependsOn: ['pad-a', 'pad-b', 'mid'] },
          { ref: 'mid', dependsOn: ['pad-b'] },
          { ref: 'pad-a', dependsOn: ['pad-b'] },
        ],
      }),
    );

    const pads = result.components.filter((component) => component.name === 'left-pad');
    expect(pads).toHaveLength(1);
    expect(pads[0]?.bomRef).toBe('pad-a');
    expect(pads[0]?.versionedPurl).toBe('pkg:npm/left-pad@1.0.0');
    expect(pads[0]?.isDirect).toBe(true);
    expect(result.edges).toEqual([
      { fromBomRef: 'app', toBomRef: 'pad-a', relationshipType: 'depends_on' },
      { fromBomRef: 'app', toBomRef: 'mid', relationshipType: 'depends_on' },
      { fromBomRef: 'mid', toBomRef: 'pad-a', relationshipType: 'depends_on' },
    ]);
    expect(result.warnings).toEqual(
      expect.arrayContaining([
        { code: 'duplicate_identity_collapsed', count: 1 },
        { code: 'self_dependency_skipped', count: 1 },
      ]),
    );
    expect(result.components).toHaveLength(3);
  });

  it('keeps a known version distinct from an explicit unknown version', () => {
    const result = succeed(
      document({
        components: [
          library('known', 'left-pad', '1.2.3', 'pkg:npm/left-pad@1.2.3'),
          library('unknown', 'left-pad', undefined, 'pkg:npm/left-pad'),
        ],
        dependencies: [{ ref: 'app', dependsOn: ['known', 'unknown'] }],
      }),
    );

    const known = result.components.find((component) => component.bomRef === 'known');
    const unknown = result.components.find((component) => component.bomRef === 'unknown');
    expect(known?.version).toEqual({ kind: 'known', value: '1.2.3' });
    expect(known?.versionedPurl).toBe('pkg:npm/left-pad@1.2.3');
    expect(unknown?.version).toEqual({ kind: 'unknown' });
    expect(unknown?.versionedPurl).toBeNull();
    expect(known?.identityKey).toBe(unknown?.identityKey);
    expect(versionsOf(result, 'left-pad')).toEqual(['1.2.3', 'unknown']);
    expect(JSON.stringify(result)).not.toContain('unaffected');
  });

  it('rejects a CycloneDX version that disagrees with the PURL version and returns no graph', () => {
    const result = parseSbomParserRequest(
      requestFromDocument(
        document({
          components: [library('pad', 'left-pad', '1.0.0', 'pkg:npm/left-pad@2.0.0')],
          dependencies: [{ ref: 'app', dependsOn: ['pad'] }],
        }),
      ),
    );
    expect(result).toEqual({
      ok: false,
      disposition: 'rejected',
      code: 'component_version_conflict',
    });
    expect(result).not.toHaveProperty('components');
    expect(result).not.toHaveProperty('edges');
  });

  it('rejects contradictory SHA-256 evidence for one component and version', () => {
    const oneComponent = parseSbomParserRequest(
      requestFromDocument(
        document({
          components: [
            library('pad', 'left-pad', '1.0.0', 'pkg:npm/left-pad@1.0.0', [
              { alg: 'SHA-256', content: HASH_A },
              { alg: 'SHA-256', content: HASH_B },
            ]),
          ],
          dependencies: [],
        }),
      ),
    );
    expect(oneComponent).toEqual({
      ok: false,
      disposition: 'rejected',
      code: 'component_hash_conflict',
    });

    const acrossRepresentations = parseSbomParserRequest(
      requestFromDocument(
        document({
          components: [
            library('pad-a', 'left-pad', '1.0.0', 'pkg:npm/left-pad@1.0.0'),
            library('pad-b', 'left-pad', '1.0.0', 'pkg:npm/left-pad@1.0.0', [
              { alg: 'SHA-256', content: HASH_A },
            ]),
            library('pad-c', 'left-pad', '1.0.0', 'pkg:npm/left-pad@1.0.0', [
              { alg: 'SHA-256', content: HASH_B },
            ]),
          ],
          dependencies: [{ ref: 'app', dependsOn: ['pad-a', 'pad-b', 'pad-c'] }],
        }),
      ),
    );
    expect(acrossRepresentations).toEqual({
      ok: false,
      disposition: 'rejected',
      code: 'component_hash_conflict',
    });
    expect(acrossRepresentations).not.toHaveProperty('components');
  });

  it('does not treat a missing SHA-256 as a conflict with a present SHA-256', () => {
    const result = succeed(
      document({
        components: [
          library('pad-a', 'left-pad', '1.0.0', 'pkg:npm/left-pad@1.0.0', [
            { alg: 'SHA-256', content: HASH_A },
          ]),
          library('pad-b', 'left-pad', '1.0.0', 'pkg:npm/left-pad@1.0.0'),
        ],
        dependencies: [{ ref: 'app', dependsOn: ['pad-a', 'pad-b'] }],
      }),
    );
    expect(result.components.filter((component) => component.name === 'left-pad')).toHaveLength(1);
    expect(result.edges).toEqual([
      { fromBomRef: 'app', toBomRef: 'pad-a', relationshipType: 'depends_on' },
    ]);
    expect(result.warnings).toEqual([{ code: 'duplicate_identity_collapsed', count: 1 }]);
  });
});

function permutations<T>(values: readonly T[]): T[][] {
  if (values.length <= 1) {
    return [Array.from(values)];
  }
  const results: T[][] = [];
  for (let index = 0; index < values.length; index += 1) {
    const head = values[index];
    if (head === undefined) {
      continue;
    }
    const rest = values.filter((_, itemIndex) => itemIndex !== index);
    for (const tail of permutations(rest)) {
      results.push([head, ...tail]);
    }
  }
  return results;
}

function failureCode(documentBody: Record<string, unknown>): string | undefined {
  const result = parseSbomParserRequest(requestFromDocument(documentBody));
  return result.ok ? undefined : result.code;
}

function occurrenceProjection(result: ParserWorkerSuccess): unknown {
  return {
    normalizationVersion: result.normalizationVersion,
    components: result.components
      .map((component) => ({
        bomRef: component.bomRef,
        name: component.name,
        identityKey: component.identityKey,
        version: component.version,
        versionedPurl: component.versionedPurl,
        isDirect: component.isDirect,
      }))
      .sort((left, right) => JSON.stringify(left).localeCompare(JSON.stringify(right))),
    edges: result.edges.map((edge) => `${edge.fromBomRef}\u0000${edge.toBomRef}`).sort(),
    warnings: result.warnings,
  };
}

describe('multi-version occurrence adversarial normalization', () => {
  it('keeps three known versions and does not fold ecosystem-equivalent names into one version', () => {
    const result = succeed(
      document({
        components: [
          library('pad-3', 'Left-Pad', '3.0.0', 'pkg:npm/Left-Pad@3.0.0'),
          library('pad-1', 'left-pad', '1.0.0', 'pkg:npm/left-pad@1.0.0'),
          library('pad-2', 'LEFT-PAD', '2.0.0', 'pkg:npm/LEFT-PAD@2.0.0'),
          library('py-1', 'Left_Pad', '1.0.0', 'pkg:pypi/Left_Pad@1.0.0'),
          library('py-2', 'left-pad', '2.0.0', 'pkg:pypi/left-pad@2.0.0'),
        ],
        dependencies: [{ ref: 'app', dependsOn: ['pad-1', 'pad-2', 'pad-3', 'py-1', 'py-2'] }],
      }),
    );

    const npm = result.components.filter(
      (component) => component.identityKey === 'purl:pkg:npm/left-pad',
    );
    expect(npm).toHaveLength(3);
    expect(
      npm
        .map((component) =>
          component.version.kind === 'known' ? component.version.value : 'unknown',
        )
        .sort(),
    ).toEqual(['1.0.0', '2.0.0', '3.0.0']);
    expect(new Set(npm.map((component) => component.bomRef)).size).toBe(3);
    const pypi = result.components.filter(
      (component) => component.identityKey === 'purl:pkg:pypi/left-pad',
    );
    expect(pypi).toHaveLength(2);
    expect(result.edges.some((edge) => edge.fromBomRef === edge.toBomRef)).toBe(false);
  });

  it('keeps known and unknown versions distinct in either document order', () => {
    const known = library('known', 'left-pad', '1.2.3', 'pkg:npm/left-pad@1.2.3');
    const unknown = library('unknown', 'left-pad', 'unknown', 'pkg:npm/left-pad@unknown');
    const blank = library('blank', 'left-pad', undefined, 'pkg:npm/left-pad');
    for (const components of permutations([known, unknown, blank])) {
      const result = succeed(
        document({
          components,
          dependencies: [{ ref: 'app', dependsOn: ['known', 'unknown', 'blank'] }],
        }),
      );
      expect(versionsOf(result, 'left-pad')).toEqual(['1.2.3', 'unknown']);
      expect(
        result.components.filter((component) => component.identityKey === 'purl:pkg:npm/left-pad'),
      ).toHaveLength(2);
      expect(JSON.stringify(result)).not.toContain('unaffected');
      expect(result.edges).toHaveLength(2);
      expect(result.edges.some((edge) => edge.fromBomRef === edge.toBomRef)).toBe(false);
    }
  });

  it('aliases same-version representations independently of hash, purl, name, and bom-ref order', () => {
    const noHash = library('pad-z', 'Zed', '1.0.0', 'pkg:npm/left-pad');
    const withHash = library('pad-a', 'alpha', '1.0.0', 'pkg:npm/left-pad@1.0.0', [
      { alg: 'SHA-256', content: HASH_A.toUpperCase() },
      { alg: 'SHA-256', content: HASH_A },
      { alg: 'SHA-1', content: 'ab'.repeat(20) },
    ]);
    const projections = permutations([noHash, withHash]).map((components) =>
      occurrenceProjection(
        succeed(
          document({
            components,
            dependencies: [
              { ref: 'app', dependsOn: ['pad-z', 'pad-a'] },
              { ref: 'pad-z', dependsOn: ['pad-a'] },
            ],
          }),
        ),
      ),
    );
    expect(new Set(projections.map((projection) => JSON.stringify(projection))).size).toBe(1);
    const canonical = projections[0] as {
      components: Array<{
        bomRef: string;
        name: string;
        identityKey: string;
        versionedPurl: string;
      }>;
      edges: string[];
    };
    const pads = canonical.components.filter(
      (component) => component.identityKey === 'purl:pkg:npm/left-pad',
    );
    expect(pads).toHaveLength(1);
    expect(pads[0]?.bomRef).toBe('pad-a');
    expect(pads[0]?.name).toBe('Zed');
    expect(pads[0]?.versionedPurl).toBe('pkg:npm/left-pad@1.0.0');
    expect(canonical.edges).toEqual(['app\u0000pad-a']);
  });

  it('rejects a later contradictory hash or versioned PURL after adopting earlier evidence', () => {
    const bare = library('pad-a', 'left-pad', '1.0.0', 'pkg:npm/left-pad');
    const hashA = library('pad-b', 'left-pad', '1.0.0', 'pkg:npm/left-pad@1.0.0', [
      { alg: 'SHA-256', content: HASH_A },
    ]);
    const hashB = library('pad-c', 'left-pad', '1.0.0', 'pkg:npm/left-pad@1.0.0', [
      { alg: 'SHA-256', content: HASH_B },
    ]);
    for (const components of permutations([bare, hashA, hashB])) {
      expect(
        failureCode(
          document({
            components,
            dependencies: [{ ref: 'app', dependsOn: ['pad-a', 'pad-b', 'pad-c'] }],
          }),
        ),
      ).toBe('component_hash_conflict');
    }

    const versionless = library('pad-a', 'left-pad', '1.0.0', 'pkg:npm/left-pad');
    const versioned = library('pad-b', 'left-pad', undefined, 'pkg:npm/left-pad@1.0.0');
    const purlProjections = permutations([versionless, versioned]).map((components) =>
      occurrenceProjection(
        succeed(
          document({
            components,
            dependencies: [{ ref: 'app', dependsOn: ['pad-a', 'pad-b'] }],
          }),
        ),
      ),
    );
    expect(new Set(purlProjections.map((projection) => JSON.stringify(projection))).size).toBe(1);

    const distinctPurlVersions = succeed(
      document({
        components: [
          library('plain', 'left-pad', '1.0.0', 'pkg:npm/left-pad@1.0.0'),
          library('debian', 'left-pad', '1.0.0+debian', 'pkg:npm/left-pad@1.0.0%2Bdebian'),
        ],
        dependencies: [{ ref: 'app', dependsOn: ['plain', 'debian'] }],
      }),
    );
    expect(versionsOf(distinctPurlVersions, 'left-pad')).toEqual(['1.0.0', '1.0.0+debian']);
    expect(distinctPurlVersions.edges).toHaveLength(2);
  });

  it('rejects version and hash contradictions without returning a graph', () => {
    expect(
      failureCode(
        document({
          components: [library('pad', 'left-pad', 'unknown', 'pkg:npm/left-pad@1.2.3')],
          dependencies: [],
        }),
      ),
    ).toBe('component_version_conflict');
    expect(
      failureCode(
        document({
          components: [library('pad', 'left-pad', '1.0.0 ', 'pkg:npm/left-pad@1.0.0')],
          dependencies: [],
        }),
      ),
    ).toBe('component_version_conflict');
    expect(
      failureCode(
        document({
          components: [library('pad', 'left-pad', '1.0.0', 'pkg:npm/left-pad@1.0.0%2Bdebian')],
          dependencies: [],
        }),
      ),
    ).toBe('component_version_conflict');
    const malformed = document({
      components: [
        library('pad', 'left-pad', '1.0.0', 'pkg:npm/left-pad@1.0.0', [
          { alg: 'SHA-256', content: 'zz'.repeat(32) },
        ]),
      ],
      dependencies: [],
    });
    expect(failureCode(malformed)).toBe('schema_invalid');
    expect(
      normalizeCycloneDxDocument(
        malformed,
        defaultSbomParserLimits(),
        '0.1.0',
        CURRENT_SBOM_NORMALIZATION_VERSION,
        '1.6',
      ),
    ).toEqual({
      ok: false,
      disposition: 'rejected',
      code: 'component_hash_conflict',
    });
    const preserved = succeed(
      document({
        components: [library('pad', 'left-pad', '1.2.3-rc.1', 'pkg:npm/left-pad@1.2.3-rc.1')],
        dependencies: [],
      }),
    );
    expect(versionsOf(preserved, 'left-pad')).toEqual(['1.2.3-rc.1']);
  });

  it('rejects every normalization label other than version 2 and returns no graph', () => {
    const body = document({
      components: [library('pad', 'left-pad', '1.0.0', 'pkg:npm/left-pad@1.0.0')],
      dependencies: [],
    });
    for (const label of [HISTORICAL_SBOM_NORMALIZATION_VERSION, '3', '2.0']) {
      const result = parseSbomParserRequest(requestFromDocument(body, label));
      expect(result).toEqual({
        ok: false,
        disposition: 'rejected',
        code: 'unsupported_normalization_version',
      });
      expect(result).not.toHaveProperty('components');
    }
  });
});
