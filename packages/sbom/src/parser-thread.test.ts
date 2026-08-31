import { createHash } from 'node:crypto';

import {
  SBOM_JSON_MAX_DEPTH_DEFAULT,
  SBOM_JSON_MAX_NODES_DEFAULT,
  SBOM_JSON_MAX_STRING_BYTES_DEFAULT,
  SBOM_MAX_BOM_REF_BYTES_DEFAULT,
  SBOM_MAX_COMPONENTS_DEFAULT,
  SBOM_MAX_COMPONENT_NAME_CHARS_DEFAULT,
  SBOM_MAX_DEPENDENCY_EDGES_DEFAULT,
  SBOM_MAX_EXTERNAL_REFS_PER_COMPONENT_DEFAULT,
  SBOM_MAX_METADATA_TOOLS_DEFAULT,
  SBOM_MAX_PROPERTIES_PER_COMPONENT_DEFAULT,
  SBOM_MAX_PURL_BYTES_DEFAULT,
  SBOM_MAX_VERSION_CHARS_DEFAULT,
  SBOM_UPLOAD_MAX_BYTES_DEFAULT,
} from '@patchpilot/config';
import { buildComponentIdentityKey, type SbomParserLimits } from '@patchpilot/domain';
import { describe, expect, it } from 'vitest';

import {
  hashParserWorkerBytes,
  validateParserWorkerFailure,
  validateParserWorkerRequest,
  validateParserWorkerSuccess,
} from './parser-thread.js';

const REQUEST_ID = '77777777-7777-4777-8777-777777777777';

const limits: SbomParserLimits = {
  maxBytes: SBOM_UPLOAD_MAX_BYTES_DEFAULT,
  jsonMaxDepth: SBOM_JSON_MAX_DEPTH_DEFAULT,
  jsonMaxNodes: SBOM_JSON_MAX_NODES_DEFAULT,
  jsonMaxStringBytes: SBOM_JSON_MAX_STRING_BYTES_DEFAULT,
  maxComponents: SBOM_MAX_COMPONENTS_DEFAULT,
  maxDependencyEdges: SBOM_MAX_DEPENDENCY_EDGES_DEFAULT,
  maxBomRefBytes: SBOM_MAX_BOM_REF_BYTES_DEFAULT,
  maxPurlBytes: SBOM_MAX_PURL_BYTES_DEFAULT,
  maxComponentNameChars: SBOM_MAX_COMPONENT_NAME_CHARS_DEFAULT,
  maxVersionChars: SBOM_MAX_VERSION_CHARS_DEFAULT,
  maxMetadataTools: SBOM_MAX_METADATA_TOOLS_DEFAULT,
  maxExternalRefsPerComponent: SBOM_MAX_EXTERNAL_REFS_PER_COMPONENT_DEFAULT,
  maxPropertiesPerComponent: SBOM_MAX_PROPERTIES_PER_COMPONENT_DEFAULT,
};

function bufferWithHash(text: string): { bytes: ArrayBuffer; sha256: string; byteLength: number } {
  const view = Uint8Array.from(Buffer.from(text, 'utf8'));
  const bytes = view.buffer.slice(view.byteOffset, view.byteOffset + view.byteLength);
  const sha256 = createHash('sha256').update(Buffer.from(bytes)).digest('hex');
  return { bytes, sha256, byteLength: bytes.byteLength };
}

const parentKey = buildComponentIdentityKey({
  identityState: 'resolved',
  versionlessPurl: 'pkg:npm/root',
  ecosystem: 'npm',
  namespace: null,
  name: 'root',
  bomRef: 'root',
});
const childKey = buildComponentIdentityKey({
  identityState: 'resolved',
  versionlessPurl: 'pkg:npm/child',
  ecosystem: 'npm',
  namespace: null,
  name: 'child',
  bomRef: 'child',
});

function successPayload(overrides: Record<string, unknown> = {}) {
  if (!parentKey.ok || !childKey.ok) {
    throw new Error('expected identity keys');
  }
  return {
    ok: true,
    specificationVersion: '1.6',
    graphCompleteness: 'complete',
    components: [
      {
        bomRef: 'root',
        name: 'root',
        namespace: null,
        ecosystem: 'npm',
        identityState: 'resolved',
        versionlessPurl: 'pkg:npm/root',
        versionedPurl: 'pkg:npm/root@1.0.0',
        version: { kind: 'known', value: '1.0.0' },
        isDirect: true,
        identityKey: parentKey.value,
      },
      {
        bomRef: 'child',
        name: 'child',
        namespace: null,
        ecosystem: 'npm',
        identityState: 'resolved',
        versionlessPurl: 'pkg:npm/child',
        versionedPurl: null,
        version: { kind: 'unknown' },
        isDirect: false,
        identityKey: childKey.value,
      },
    ],
    edges: [{ fromBomRef: 'root', toBomRef: 'child', relationshipType: 'depends_on' }],
    warnings: [],
    stats: { componentCount: 2, dependencyEdgeCount: 1, warningCount: 0 },
    capturedAt: '2026-08-29T12:00:00.000Z',
    parserVersion: '0.1.0',
    normalizationVersion: '1',
    ...overrides,
  };
}

describe('parser worker request', () => {
  it('accepts a transferable buffer with matching SHA-256 and typed limits', () => {
    const payload = bufferWithHash('{"bomFormat":"CycloneDX"}');
    const parsed = validateParserWorkerRequest({
      requestId: REQUEST_ID,
      bytes: payload.bytes,
      expectedSha256: payload.sha256,
      byteLength: payload.byteLength,
      limits,
      parserVersion: '0.1.0',
      normalizationVersion: '1',
    });
    expect(parsed.ok).toBe(true);
    expect(hashParserWorkerBytes(payload.bytes)).toBe(payload.sha256);
  });

  it('rejects tenant identifiers, object keys, filenames, and credentials', () => {
    const payload = bufferWithHash('{}');
    const base = {
      requestId: REQUEST_ID,
      bytes: payload.bytes,
      expectedSha256: payload.sha256,
      byteLength: payload.byteLength,
      limits,
      parserVersion: '0.1.0',
      normalizationVersion: '1',
    };
    for (const extra of [
      { organizationId: REQUEST_ID },
      { assetId: REQUEST_ID },
      { sbomId: REQUEST_ID },
      { objectKey: 'org/x/assets/y/sboms/sha256/' + payload.sha256 },
      { filename: 'bom.json' },
      { headers: { 'content-type': 'application/json' } },
      { credentials: { secretAccessKey: 'x' } },
      { endpoint: 'http://127.0.0.1:9000' },
    ]) {
      expect(validateParserWorkerRequest({ ...base, ...extra }).ok).toBe(false);
    }
  });

  it('rejects byte-length, SHA-256, and version-shape failures', () => {
    const payload = bufferWithHash('{}');
    expect(
      validateParserWorkerRequest({
        requestId: REQUEST_ID,
        bytes: payload.bytes,
        expectedSha256: payload.sha256,
        byteLength: payload.byteLength + 1,
        limits,
        parserVersion: '0.1.0',
        normalizationVersion: '1',
      }).ok,
    ).toBe(false);
    expect(
      validateParserWorkerRequest({
        requestId: REQUEST_ID,
        bytes: payload.bytes,
        expectedSha256: 'b'.repeat(64),
        byteLength: payload.byteLength,
        limits,
        parserVersion: '0.1.0',
        normalizationVersion: '1',
      }).ok,
    ).toBe(false);
    expect(
      validateParserWorkerRequest({
        requestId: REQUEST_ID,
        bytes: payload.bytes,
        expectedSha256: payload.sha256,
        byteLength: payload.byteLength,
        limits,
        parserVersion: '../evil',
        normalizationVersion: '1',
      }).ok,
    ).toBe(false);
  });
});

describe('parser worker success', () => {
  it('accepts a bounded normalized graph', () => {
    const parsed = validateParserWorkerSuccess(successPayload(), limits);
    expect(parsed.ok).toBe(true);
  });

  it('rejects CycloneDX 1.7, count mismatches, and over-limit arrays', () => {
    expect(
      validateParserWorkerSuccess(successPayload({ specificationVersion: '1.7' }), limits).ok,
    ).toBe(false);
    expect(
      validateParserWorkerSuccess(
        successPayload({ stats: { componentCount: 99, dependencyEdgeCount: 1, warningCount: 0 } }),
        limits,
      ).ok,
    ).toBe(false);
    expect(validateParserWorkerSuccess(successPayload(), { ...limits, maxComponents: 1 }).ok).toBe(
      false,
    );
    expect(
      validateParserWorkerSuccess(successPayload(), { ...limits, maxDependencyEdges: 0 }).ok,
    ).toBe(false);
  });

  it('rejects oversized serialized results', () => {
    expect(validateParserWorkerSuccess(successPayload(), limits, 32).ok).toBe(false);
  });

  it('rejects unknown fields and raw parser details', () => {
    expect(validateParserWorkerSuccess(successPayload({ ajvErrors: [] }), limits).ok).toBe(false);
    expect(validateParserWorkerSuccess(successPayload({ stack: 'Error' }), limits).ok).toBe(false);
    expect(validateParserWorkerSuccess(successPayload({ rawJson: '{}' }), limits).ok).toBe(false);
  });
});

describe('parser worker failure', () => {
  it('accepts closed rejected and quarantined codes', () => {
    expect(
      validateParserWorkerFailure({ ok: false, disposition: 'rejected', code: 'schema_invalid' })
        .ok,
    ).toBe(true);
    expect(
      validateParserWorkerFailure({ ok: false, disposition: 'quarantined', code: 'parser_crash' })
        .ok,
    ).toBe(true);
  });

  it('rejects retryable infrastructure, terminal internal, and mismatched dispositions', () => {
    expect(
      validateParserWorkerFailure({ ok: false, disposition: 'rejected', code: 'storage_timeout' })
        .ok,
    ).toBe(false);
    expect(
      validateParserWorkerFailure({
        ok: false,
        disposition: 'quarantined',
        code: 'processing_failed',
      }).ok,
    ).toBe(false);
    expect(
      validateParserWorkerFailure({ ok: false, disposition: 'quarantined', code: 'schema_invalid' })
        .ok,
    ).toBe(false);
    expect(
      validateParserWorkerFailure({
        ok: false,
        disposition: 'rejected',
        code: 'schema_invalid',
        message: 'instancePath /components',
      }).ok,
    ).toBe(false);
  });
});
