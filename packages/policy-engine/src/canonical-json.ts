import { deepFreeze } from './deep-freeze.js';
import { readPlainArray, readPlainRecord } from './plain-data.js';
import { err, ok, type Result } from './result.js';

export const CANONICAL_JSON_MAX_DEPTH = 32;
export const CANONICAL_JSON_MAX_ARRAY_LENGTH = 100_000;

export const CANONICAL_JSON_ISSUE_CODES = [
  'unsupported_value',
  'non_finite_number',
  'non_plain_object',
  'non_plain_array',
  'cycle',
  'depth_exceeded',
] as const;
export type CanonicalJsonIssueCode = (typeof CANONICAL_JSON_ISSUE_CODES)[number];

export type CanonicalJsonError = {
  readonly kind: 'invalid_canonical_json_value';
  readonly code: CanonicalJsonIssueCode;
};

class CanonicalJsonFailure {
  readonly code: CanonicalJsonIssueCode;

  constructor(code: CanonicalJsonIssueCode) {
    this.code = code;
  }
}

function compareKeys(left: string, right: string): number {
  if (left === right) {
    return 0;
  }
  return left < right ? -1 : 1;
}

function serialize(value: unknown, ancestors: Set<object>, depth: number): string {
  if (value === null) {
    return 'null';
  }
  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'string':
      return JSON.stringify(value);
    case 'number':
      if (!Number.isFinite(value)) {
        throw new CanonicalJsonFailure('non_finite_number');
      }
      return JSON.stringify(value);
    case 'object':
      break;
    default:
      throw new CanonicalJsonFailure('unsupported_value');
  }
  if (depth >= CANONICAL_JSON_MAX_DEPTH) {
    throw new CanonicalJsonFailure('depth_exceeded');
  }
  if (ancestors.has(value)) {
    throw new CanonicalJsonFailure('cycle');
  }
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      const elements = readPlainArray(value, CANONICAL_JSON_MAX_ARRAY_LENGTH);
      if (typeof elements === 'string') {
        throw new CanonicalJsonFailure('non_plain_array');
      }
      return `[${elements.map((element) => serialize(element, ancestors, depth + 1)).join(',')}]`;
    }
    const record = readPlainRecord(value);
    if (record === null) {
      throw new CanonicalJsonFailure('non_plain_object');
    }
    const members = [...record.keys()]
      .sort(compareKeys)
      .map((key) => `${JSON.stringify(key)}:${serialize(record.get(key), ancestors, depth + 1)}`);
    return `{${members.join(',')}}`;
  } finally {
    ancestors.delete(value);
  }
}

/**
 * Serializes plain JSON data with object keys sorted by UTF-16 code unit and
 * no insignificant whitespace, so equal data always yields identical bytes
 * for hashing. Values that JSON would drop or distort are rejected, never
 * omitted: `undefined`, functions, symbols, bigints, non-finite numbers,
 * non-plain objects, sparse or decorated arrays, and cycles.
 */
export function canonicalJson(value: unknown): Result<string, CanonicalJsonError> {
  try {
    return ok(serialize(value, new Set<object>(), 0));
  } catch (failure) {
    if (failure instanceof CanonicalJsonFailure) {
      return err(deepFreeze({ kind: 'invalid_canonical_json_value', code: failure.code }));
    }
    throw failure;
  }
}
