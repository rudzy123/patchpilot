import { describe, expect, it } from 'vitest';

import { parseUntrustedJson } from './untrusted-json.js';

describe('untrusted JSON parse', () => {
  it('rejects prototype-related keys', () => {
    expect(() => parseUntrustedJson('{"__proto__":{"polluted":true}}')).toThrow(/prototype/i);
    expect(() => parseUntrustedJson('{"constructor":{"prototype":{"polluted":true}}}')).toThrow(
      /prototype/i,
    );
  });

  it('parses ordinary objects', () => {
    expect(parseUntrustedJson('{"bomFormat":"CycloneDX"}')).toEqual({ bomFormat: 'CycloneDX' });
  });
});
