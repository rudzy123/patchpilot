import { describe, expect, it } from 'vitest';

import { parserThreadMessageToParseResult } from './document-parser-adapter.js';
import { parserSuccessToNormalizedGraph } from './parser-thread.js';

describe('parser thread adapter', () => {
  it('maps parser-thread failures to the domain parser port', () => {
    expect(
      parserThreadMessageToParseResult({
        ok: false,
        disposition: 'rejected',
        code: 'schema_invalid',
      }),
    ).toEqual({ ok: false, code: 'schema_invalid' });
    expect(
      parserThreadMessageToParseResult({
        ok: false,
        disposition: 'quarantined',
        code: 'parser_timeout',
      }),
    ).toEqual({ ok: false, code: 'parser_timeout' });
  });

  it('converts capturedAt strings to Date values', () => {
    const success = {
      ok: true as const,
      specificationVersion: '1.6' as const,
      graphCompleteness: 'empty' as const,
      components: [],
      edges: [],
      warnings: [],
      stats: { componentCount: 0, dependencyEdgeCount: 0, warningCount: 0 },
      capturedAt: '2026-08-31T12:00:00.000Z',
      parserVersion: '0.1.0',
      normalizationVersion: '1',
    };
    const graph = parserSuccessToNormalizedGraph(success);
    expect(graph.ok).toBe(true);
    if (!graph.ok) {
      return;
    }
    expect(graph.value.capturedAt).toEqual(new Date('2026-08-31T12:00:00.000Z'));
    expect(parserThreadMessageToParseResult(success)).toEqual({ ok: true, graph: graph.value });
  });
});
