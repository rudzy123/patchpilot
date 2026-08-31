import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { validateNormalizedComponentGraph } from '@patchpilot/domain';
import { describe, expect, it } from 'vitest';

import { parseSbomParserRequest } from './parse-document.js';
import { defaultSbomParserLimits } from './parser-limits.js';
import type { ParserWorkerRequest } from './parser-thread.js';

const REQUEST_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const fixtureDirectory = join(dirname(fileURLToPath(import.meta.url)), 'fixtures');

function bufferWithHash(text: string): { bytes: ArrayBuffer; sha256: string; byteLength: number } {
  const view = Uint8Array.from(Buffer.from(text, 'utf8'));
  const bytes = view.buffer.slice(view.byteOffset, view.byteOffset + view.byteLength);
  const sha256 = createHash('sha256').update(Buffer.from(bytes)).digest('hex');
  return { bytes, sha256, byteLength: bytes.byteLength };
}

function requestFromText(
  text: string,
  overrides: Partial<ParserWorkerRequest> = {},
): ParserWorkerRequest {
  const payload = bufferWithHash(text);
  return {
    requestId: REQUEST_ID,
    bytes: payload.bytes,
    expectedSha256: payload.sha256,
    byteLength: payload.byteLength,
    limits: defaultSbomParserLimits(),
    parserVersion: '0.1.0',
    normalizationVersion: '1',
    ...overrides,
  };
}

function requestFromJson(
  document: unknown,
  overrides: Partial<ParserWorkerRequest> = {},
): ParserWorkerRequest {
  return requestFromText(JSON.stringify(document), overrides);
}

function cycloneDx(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    version: 1,
    metadata: {
      timestamp: '2026-08-31T12:00:00Z',
      component: {
        type: 'application',
        'bom-ref': 'app',
        name: 'app',
        version: '1.0.0',
        purl: 'pkg:npm/app@1.0.0',
      },
    },
    components: [
      {
        type: 'library',
        'bom-ref': 'dep',
        name: 'dep',
        version: '2.0.0',
        purl: 'pkg:npm/dep@2.0.0',
      },
    ],
    dependencies: [{ ref: 'app', dependsOn: ['dep'] }],
    ...overrides,
  };
}

describe('parseSbomParserRequest', () => {
  it('parses allowlisted CycloneDX 1.4, 1.5, and 1.6 fixtures offline', () => {
    for (const fileName of ['valid-1.4.json', 'valid-1.5.json', 'valid-1.6.json'] as const) {
      const text = readFileSync(join(fixtureDirectory, fileName), 'utf8');
      const result = parseSbomParserRequest(requestFromText(text));
      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.specificationVersion).toBe(fileName.replace('valid-', '').replace('.json', ''));
        expect(result.graphCompleteness).toBe('no_dependencies');
        expect(result.stats.componentCount).toBe(1);
      }
    }
  });

  it('rejects prototype keys as poison', () => {
    expect(parseSbomParserRequest(requestFromText('{"__proto__":{"x":1}}'))).toEqual({
      ok: false,
      disposition: 'quarantined',
      code: 'prototype_pollution',
    });
    expect(parseSbomParserRequest(requestFromText('{"constructor":{"prototype":{}}}'))).toEqual({
      ok: false,
      disposition: 'quarantined',
      code: 'prototype_pollution',
    });
    expect(parseSbomParserRequest(requestFromText('{"prototype":{"x":1}}'))).toEqual({
      ok: false,
      disposition: 'quarantined',
      code: 'prototype_pollution',
    });
  });

  it('rejects JSON that exceeds depth, node, and string-byte limits', () => {
    let nested: unknown = { leaf: true };
    for (let depth = 0; depth < 33; depth += 1) {
      nested = { n: nested };
    }
    expect(
      parseSbomParserRequest(
        requestFromJson(nested, { limits: { ...defaultSbomParserLimits(), jsonMaxDepth: 8 } }),
      ),
    ).toEqual({ ok: false, disposition: 'rejected', code: 'json_depth' });

    expect(
      parseSbomParserRequest(
        requestFromJson([1, 2, 3, 4, 5], {
          limits: { ...defaultSbomParserLimits(), jsonMaxNodes: 4 },
        }),
      ),
    ).toEqual({ ok: false, disposition: 'rejected', code: 'json_nodes' });

    expect(
      parseSbomParserRequest(
        requestFromJson(
          { name: 'n'.repeat(32) },
          { limits: { ...defaultSbomParserLimits(), jsonMaxStringBytes: 16 } },
        ),
      ),
    ).toEqual({ ok: false, disposition: 'rejected', code: 'json_string_length' });
  });

  it('rejects invalid UTF-8 and malformed JSON', () => {
    const invalidUtf8 = new Uint8Array([0xff, 0xfe, 0xfd]);
    const bytes = invalidUtf8.buffer.slice(
      invalidUtf8.byteOffset,
      invalidUtf8.byteOffset + invalidUtf8.byteLength,
    );
    const sha256 = createHash('sha256').update(Buffer.from(bytes)).digest('hex');
    expect(
      parseSbomParserRequest({
        requestId: REQUEST_ID,
        bytes,
        expectedSha256: sha256,
        byteLength: bytes.byteLength,
        limits: defaultSbomParserLimits(),
        parserVersion: '0.1.0',
        normalizationVersion: '1',
      }),
    ).toEqual({ ok: false, disposition: 'rejected', code: 'utf8' });

    expect(parseSbomParserRequest(requestFromText('{'))).toEqual({
      ok: false,
      disposition: 'rejected',
      code: 'json_syntax',
    });
  });

  it('rejects documents that are not allowlisted CycloneDX JSON', () => {
    expect(parseSbomParserRequest(requestFromJson({ bomFormat: 'SPDX' }))).toEqual({
      ok: false,
      disposition: 'rejected',
      code: 'not_cyclonedx',
    });
    expect(
      parseSbomParserRequest(requestFromText(readFileSync(join(fixtureDirectory, 'unsupported-1.7.json'), 'utf8'))),
    ).toEqual({ ok: false, disposition: 'rejected', code: 'unsupported_spec_version' });
    expect(
      parseSbomParserRequest(
        requestFromText(readFileSync(join(fixtureDirectory, 'schema-invalid-1.4.json'), 'utf8')),
      ),
    ).toEqual({ ok: false, disposition: 'rejected', code: 'schema_invalid' });
  });

  it('enforces semantic component, edge, identifier, and tool limits', () => {
    expect(
      parseSbomParserRequest(
        requestFromJson(cycloneDx(), { limits: { ...defaultSbomParserLimits(), maxComponents: 1 } }),
      ),
    ).toEqual({ ok: false, disposition: 'rejected', code: 'component_limit' });

    expect(
      parseSbomParserRequest(
        requestFromJson(cycloneDx(), {
          limits: { ...defaultSbomParserLimits(), maxDependencyEdges: 0 },
        }),
      ),
    ).toEqual({ ok: false, disposition: 'rejected', code: 'edge_limit' });

    expect(
      parseSbomParserRequest(
        requestFromJson(
          cycloneDx({
            metadata: {
              component: {
                type: 'application',
                'bom-ref': 'b'.repeat(100),
                name: 'app',
                version: '1.0.0',
              },
            },
            components: [],
            dependencies: [],
          }),
          { limits: { ...defaultSbomParserLimits(), maxBomRefBytes: 64 } },
        ),
      ),
    ).toEqual({ ok: false, disposition: 'rejected', code: 'identifier_length' });

    expect(
      parseSbomParserRequest(
        requestFromJson(
          cycloneDx({
            metadata: {
              tools: {
                components: [
                  { type: 'application', name: 'tool-0' },
                  { type: 'application', name: 'tool-1' },
                  { type: 'application', name: 'tool-2' },
                ],
              },
              component: {
                type: 'application',
                'bom-ref': 'app',
                name: 'app',
                version: '1.0.0',
              },
            },
            components: [],
            dependencies: [],
          }),
          { limits: { ...defaultSbomParserLimits(), maxMetadataTools: 2 } },
        ),
      ),
    ).toEqual({ ok: false, disposition: 'rejected', code: 'tool_limit' });
  });

  it('normalizes PURLs and treats missing versions as explicit unknown', () => {
    const result = parseSbomParserRequest(
      requestFromJson(
        cycloneDx({
          components: [
            {
              type: 'library',
              'bom-ref': 'dep',
              name: 'dep',
              purl: 'pkg:npm/dep',
            },
          ],
        }),
      ),
    );
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    const dep = result.components.find((component) => component.bomRef === 'dep');
    expect(dep?.version).toEqual({ kind: 'unknown' });
    expect(dep?.versionlessPurl).toBe('pkg:npm/dep');
    expect(dep?.versionedPurl).toBeNull();
    expect(dep?.identityState).toBe('resolved');
    expect(dep?.ecosystem).toBe('npm');
  });

  it('rejects duplicate bom-ref values', () => {
    expect(
      parseSbomParserRequest(
        requestFromJson(
          cycloneDx({
            components: [
              {
                type: 'library',
                'bom-ref': 'app',
                name: 'other',
                version: '9.0.0',
                purl: 'pkg:npm/other@9.0.0',
              },
            ],
            dependencies: [],
          }),
        ),
      ),
    ).toEqual({ ok: false, disposition: 'rejected', code: 'duplicate_bom_ref' });
  });

  it('rejects unknown dependency references', () => {
    expect(
      parseSbomParserRequest(
        requestFromJson(cycloneDx({ dependencies: [{ ref: 'app', dependsOn: ['missing'] }] })),
      ),
    ).toEqual({ ok: false, disposition: 'rejected', code: 'unresolved_dependency_ref' });
  });

  it('omits self-edges, counts self_dependency_skipped, and yields a persistable graph', () => {
    const result = parseSbomParserRequest(
      requestFromJson(
        cycloneDx({
          dependencies: [{ ref: 'app', dependsOn: ['app', 'dep'] }],
        }),
      ),
    );
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    expect(result.edges).toEqual([
      { fromBomRef: 'app', toBomRef: 'dep', relationshipType: 'depends_on' },
    ]);
    expect(result.warnings).toEqual([{ code: 'self_dependency_skipped', count: 1 }]);
    expect(result.stats.warningCount).toBe(1);
    expect(result.graphCompleteness).toBe('partial');

    const persistable = validateNormalizedComponentGraph({
      specificationVersion: result.specificationVersion,
      graphCompleteness: result.graphCompleteness,
      components: result.components,
      edges: result.edges,
      warnings: result.warnings,
      componentCount: result.stats.componentCount,
      dependencyEdgeCount: result.stats.dependencyEdgeCount,
      warningCount: result.stats.warningCount,
      capturedAt: result.capturedAt === null ? null : new Date(result.capturedAt),
      parserVersion: result.parserVersion,
      normalizationVersion: result.normalizationVersion,
    });
    expect(persistable.ok).toBe(true);
    if (persistable.ok) {
      expect(persistable.value.edges.some((edge) => edge.fromBomRef === edge.toBomRef)).toBe(false);
    }
  });

  it('retains cycles in the normalized graph', () => {
    const result = parseSbomParserRequest(
      requestFromJson(
        cycloneDx({
          dependencies: [
            { ref: 'app', dependsOn: ['dep'] },
            { ref: 'dep', dependsOn: ['app'] },
          ],
        }),
      ),
    );
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    expect(result.graphCompleteness).toBe('complete');
    expect(result.edges).toEqual([
      { fromBomRef: 'app', toBomRef: 'dep', relationshipType: 'depends_on' },
      { fromBomRef: 'dep', toBomRef: 'app', relationshipType: 'depends_on' },
    ]);
    expect(result.warnings).toEqual([]);
  });

  it('marks an empty validated document empty and a component-only document no_dependencies', () => {
    const empty = parseSbomParserRequest(
      requestFromJson({
        bomFormat: 'CycloneDX',
        specVersion: '1.6',
        version: 1,
      }),
    );
    expect(empty.ok).toBe(true);
    if (empty.ok) {
      expect(empty.graphCompleteness).toBe('empty');
      expect(empty.stats.componentCount).toBe(0);
    }

    const noDeps = parseSbomParserRequest(
      requestFromJson(
        cycloneDx({
          dependencies: [],
        }),
      ),
    );
    expect(noDeps.ok).toBe(true);
    if (noDeps.ok) {
      expect(noDeps.graphCompleteness).toBe('no_dependencies');
    }
  });

  it('returns a bounded success DTO without parser internals', () => {
    const result = parseSbomParserRequest(requestFromJson(cycloneDx()));
    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    expect(result.capturedAt).toBe('2026-08-31T12:00:00Z');
    expect(result).not.toHaveProperty('ajvErrors');
    expect(result).not.toHaveProperty('stack');
    expect(JSON.stringify(result).length).toBeLessThan(16_777_216);
  });

  it('rejects an invalid PURL', () => {
    expect(
      parseSbomParserRequest(
        requestFromJson(
          cycloneDx({
            components: [
              {
                type: 'library',
                'bom-ref': 'dep',
                name: 'dep',
                purl: 'not-a-purl',
              },
            ],
            dependencies: [],
          }),
        ),
      ),
    ).toEqual({ ok: false, disposition: 'rejected', code: 'invalid_purl' });
  });
});
