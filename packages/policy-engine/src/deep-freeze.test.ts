import { describe, expect, it } from 'vitest';

import { deepFreeze } from './deep-freeze.js';

describe('deepFreeze', () => {
  it('freezes nested objects and arrays and returns the same reference', () => {
    const value = { a: { b: [1, { c: 2 }] } };
    const frozen = deepFreeze(value);
    expect(frozen).toBe(value);
    expect(Object.isFrozen(value)).toBe(true);
    expect(Object.isFrozen(value.a)).toBe(true);
    expect(Object.isFrozen(value.a.b)).toBe(true);
    expect(Object.isFrozen(value.a.b[1])).toBe(true);
  });

  it('descends into an already-frozen shell that holds mutable children', () => {
    const child = { mutable: true };
    const shell = Object.freeze({ child, list: Object.freeze([child]) });
    deepFreeze(shell);
    expect(Object.isFrozen(child)).toBe(true);
  });

  it('terminates on cycles and freezes every node in them', () => {
    const first: Record<string, unknown> = {};
    const second: Record<string, unknown> = { first };
    first['second'] = second;
    deepFreeze(first);
    expect(Object.isFrozen(first)).toBe(true);
    expect(Object.isFrozen(second)).toBe(true);
  });

  it('rejects later mutation in strict mode', () => {
    const value = deepFreeze({ nested: { count: 1 } });
    expect(() => {
      (value.nested as { count: number }).count = 2;
    }).toThrow(TypeError);
  });

  it('does not invoke getters', () => {
    let reads = 0;
    const value = Object.defineProperty({}, 'lazy', {
      enumerable: true,
      get: () => {
        reads += 1;
        return { inner: true };
      },
    });
    deepFreeze(value);
    expect(reads).toBe(0);
    expect(Object.isFrozen(value)).toBe(true);
  });

  it.each([null, undefined, 0, 'text', true, 1n])('returns the primitive %s unchanged', (value) => {
    expect(deepFreeze(value)).toBe(value);
  });
});
