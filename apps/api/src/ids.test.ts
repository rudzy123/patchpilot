import { describe, expect, it } from 'vitest';

import { isSafeId, resolveRequestIdentifiers } from './ids.js';

describe('request identifier policy', () => {
  it('accepts a strict safe format', () => {
    expect(isSafeId('req-123_ABC')).toBe(true);
    expect(isSafeId('not valid')).toBe(false);
    expect(isSafeId('x'.repeat(129))).toBe(false);
  });

  it('uses one generated value for both ids when neither header is valid', () => {
    const resolved = resolveRequestIdentifiers({
      requestIdHeader: 'bad id',
      correlationIdHeader: undefined,
      generateId: () => 'generated-1',
    });
    expect(resolved.requestId).toBe('generated-1');
    expect(resolved.correlationId).toBe('generated-1');
    expect(resolved.requestIdGenerated).toBe(true);
  });

  it('propagates valid ids independently', () => {
    const resolved = resolveRequestIdentifiers({
      requestIdHeader: 'req-1',
      correlationIdHeader: 'corr-1',
      generateId: () => 'generated',
    });
    expect(resolved.requestId).toBe('req-1');
    expect(resolved.correlationId).toBe('corr-1');
  });
});
