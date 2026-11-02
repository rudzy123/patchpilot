import { describe, expect, it } from 'vitest';

import { canonicalJson, CANONICAL_JSON_MAX_DEPTH } from './canonical-json.js';
import { adrPolicyDefinitionInput, evaluateWith, validatedDefinition } from './test-helper.js';

function serialized(value: unknown): string {
  const result = canonicalJson(value);
  if (!result.ok) {
    throw new Error(`canonicalJson failed: ${result.error.code}`);
  }
  return result.value;
}

function nestedArrays(levels: number): unknown {
  let value: unknown = 0;
  for (let level = 0; level < levels; level += 1) {
    value = [value];
  }
  return value;
}

function reverseKeys(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(reverseKeys);
  }
  if (typeof value === 'object' && value !== null) {
    return Object.fromEntries(
      Object.entries(value)
        .reverse()
        .map(([key, child]) => [key, reverseKeys(child)]),
    );
  }
  return value;
}

describe('canonicalJson', () => {
  it('sorts object keys at every depth and emits no whitespace', () => {
    expect(serialized({ b: 1, a: { d: [3, { z: true, y: null }], c: 'x' } })).toBe(
      '{"a":{"c":"x","d":[3,{"y":null,"z":true}]},"b":1}',
    );
  });

  it('preserves array order', () => {
    expect(serialized([3, 1, 2])).toBe('[3,1,2]');
  });

  it('sorts keys by UTF-16 code unit', () => {
    expect(serialized({ '\uFF21': 1, '\u{1F600}': 2, a: 3, B: 4 })).toBe(
      '{"B":4,"a":3,"\u{1F600}":2,"\uFF21":1}',
    );
  });

  it('escapes strings as JSON, including lone surrogates', () => {
    expect(serialized({ text: 'quote " slash \\ newline \n', lone: '\uD800' })).toBe(
      '{"lone":"\\ud800","text":"quote \\" slash \\\\ newline \\n"}',
    );
  });

  it('serializes numbers with the ECMAScript shortest form and folds negative zero', () => {
    expect(serialized([0, -0, 1.5, 1e21, -7])).toBe('[0,0,1.5,1e+21,-7]');
  });

  it('accepts null-prototype records and shared non-cyclic references', () => {
    const shared = { k: 1 };
    const bare = Object.assign(Object.create(null) as Record<string, unknown>, { b: 2, a: 1 });
    expect(serialized({ left: shared, right: shared, bare })).toBe(
      '{"bare":{"a":1,"b":2},"left":{"k":1},"right":{"k":1}}',
    );
  });

  it('is independent of key insertion order', () => {
    const definition = adrPolicyDefinitionInput();
    expect(serialized(reverseKeys(definition))).toBe(serialized(definition));
  });

  it('pins the canonical form of a validated definition', () => {
    expect(serialized(validatedDefinition())).toMatch(
      /^\{"bands":\[\{"band":"P1","dueDateRecommendationDays":7,"minPriority":80\},/,
    );
  });

  it('produces byte-identical output for repeated evaluations', () => {
    const first = serialized(evaluateWith({}));
    for (let run = 0; run < 100; run += 1) {
      expect(serialized(evaluateWith({}))).toBe(first);
    }
  });

  it(`accepts ${CANONICAL_JSON_MAX_DEPTH} nested containers and rejects one more`, () => {
    expect(canonicalJson(nestedArrays(CANONICAL_JSON_MAX_DEPTH)).ok).toBe(true);
    expect(canonicalJson(nestedArrays(CANONICAL_JSON_MAX_DEPTH + 1))).toEqual({
      ok: false,
      error: { kind: 'invalid_canonical_json_value', code: 'depth_exceeded' },
    });
  });

  const cyclic: Record<string, unknown> = { a: 1 };
  cyclic['self'] = cyclic;
  const sparse: unknown[] = [1];
  sparse[2] = 3;
  const decorated = Object.assign([1, 2], { extra: true });
  const withGetter = Object.defineProperty({}, 'value', { enumerable: true, get: () => 1 });
  const withSymbol = { [Symbol('key')]: 1 };
  const hidden = Object.defineProperty({}, 'value', { enumerable: false, value: 1 });
  class Instance {
    readonly value = 1;
  }

  it.each([
    ['undefined', undefined, 'unsupported_value'],
    ['an undefined property', { a: undefined }, 'unsupported_value'],
    ['an undefined element', [undefined], 'unsupported_value'],
    ['a function', () => 1, 'unsupported_value'],
    ['a symbol', Symbol('value'), 'unsupported_value'],
    ['a bigint', 1n, 'unsupported_value'],
    ['NaN', Number.NaN, 'non_finite_number'],
    ['Infinity', { a: Number.POSITIVE_INFINITY }, 'non_finite_number'],
    ['-Infinity', [Number.NEGATIVE_INFINITY], 'non_finite_number'],
    ['a Date', new Date(0), 'non_plain_object'],
    ['a Map', new Map(), 'non_plain_object'],
    ['a class instance', new Instance(), 'non_plain_object'],
    ['a getter', withGetter, 'non_plain_object'],
    ['a symbol key', withSymbol, 'non_plain_object'],
    ['a non-enumerable property', hidden, 'non_plain_object'],
    ['a sparse array', sparse, 'non_plain_array'],
    ['a decorated array', decorated, 'non_plain_array'],
    ['a cycle', cyclic, 'cycle'],
  ] as const)('rejects %s without echoing the value', (_name, value, code) => {
    const result = canonicalJson(value);
    expect(result).toEqual({ ok: false, error: { kind: 'invalid_canonical_json_value', code } });
    expect(Object.isFrozen(result)).toBe(true);
    expect(!result.ok && Object.isFrozen(result.error)).toBe(true);
  });

  it('does not invoke getters while rejecting them', () => {
    let reads = 0;
    const value = Object.defineProperty({}, 'value', {
      enumerable: true,
      get: () => {
        reads += 1;
        return 1;
      },
    });
    expect(canonicalJson(value).ok).toBe(false);
    expect(reads).toBe(0);
  });
});
