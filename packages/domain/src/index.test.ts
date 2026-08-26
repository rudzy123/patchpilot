import { describe, expect, it } from 'vitest';

import { err, errorCodes, ok } from './index.js';

describe('result boundary', () => {
  it('wraps success and failure without product entities', () => {
    expect(ok(1)).toEqual({ ok: true, value: 1 });
    expect(err({ code: 'internal', message: 'boom' }).ok).toBe(false);
  });

  it('exposes the API error taxonomy', () => {
    expect(errorCodes).toContain('validation');
    expect(errorCodes).not.toContain('organization');
  });
});
