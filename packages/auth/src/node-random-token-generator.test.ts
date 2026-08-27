import { describe, expect, it } from 'vitest';

import { createNodeRandomTokenGenerator } from './node-random-token-generator.js';
import { SESSION_TOKEN_BYTES } from './random-token-generator.js';

describe('Node random token generator', () => {
  it('returns independent 32-byte base64url tokens', () => {
    const generator = createNodeRandomTokenGenerator();
    const first = generator.generate(SESSION_TOKEN_BYTES);
    const second = generator.generate(SESSION_TOKEN_BYTES);
    expect(first).not.toBe(second);
    expect(Buffer.from(first, 'base64url').length).toBe(32);
    expect(Buffer.from(second, 'base64url').length).toBe(32);
    expect(first).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(first).not.toContain('+');
    expect(first).not.toContain('/');
    expect(first).not.toContain('=');
  });
});
