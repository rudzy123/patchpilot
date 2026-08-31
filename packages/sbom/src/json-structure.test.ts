import { describe, expect, it } from 'vitest';

import { inspectJsonStructure } from './json-structure.js';

const limits = {
  jsonMaxDepth: 4,
  jsonMaxNodes: 8,
  jsonMaxStringBytes: 16,
};

describe('JSON structure inspection', () => {
  it('accepts a shallow object under the node and string-byte limits', () => {
    expect(inspectJsonStructure({ bomFormat: 'CycloneDX' }, limits)).toEqual({ ok: true });
  });

  it('rejects nesting deeper than the typed depth limit', () => {
    const nested = { a: { b: { c: { d: { e: 1 } } } } };
    expect(inspectJsonStructure(nested, limits)).toEqual({ ok: false, code: 'json_depth' });
  });

  it('rejects graphs that exceed the JSON node count', () => {
    expect(inspectJsonStructure([1, 2, 3, 4, 5, 6, 7, 8], limits)).toEqual({
      ok: false,
      code: 'json_nodes',
    });
  });

  it('rejects strings that exceed the per-string byte limit', () => {
    expect(inspectJsonStructure({ name: 'a'.repeat(17) }, limits)).toEqual({
      ok: false,
      code: 'json_string_length',
    });
  });

  it('rejects prototype as an object key', () => {
    expect(inspectJsonStructure({ prototype: { polluted: true } }, limits)).toEqual({
      ok: false,
      code: 'prototype_pollution',
    });
  });
});
