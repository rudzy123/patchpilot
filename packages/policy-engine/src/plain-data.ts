/**
 * Untrusted structural reads. Only own, enumerable, string-keyed data
 * properties are accepted, so getters, symbols, and exotic prototypes cannot
 * change what validation observes.
 */

export function readPlainRecord(value: unknown): ReadonlyMap<string, unknown> | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    return null;
  }
  const proto: unknown = Object.getPrototypeOf(value);
  if (proto !== Object.prototype && proto !== null) {
    return null;
  }
  const entries = new Map<string, unknown>();
  for (const key of Reflect.ownKeys(value)) {
    if (typeof key !== 'string') {
      return null;
    }
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor === undefined || !('value' in descriptor) || descriptor.enumerable !== true) {
      return null;
    }
    entries.set(key, descriptor.value);
  }
  return entries;
}

/**
 * Reads a dense array of at most `maxLength` elements. Returns `too_long`
 * without reading elements when the bound is exceeded.
 */
export function readPlainArray(
  value: unknown,
  maxLength: number,
): readonly unknown[] | 'not_array' | 'too_long' {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) {
    return 'not_array';
  }
  const length = value.length;
  if (length > maxLength) {
    return 'too_long';
  }
  const elements: unknown[] = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, index);
    if (descriptor === undefined || !('value' in descriptor)) {
      return 'not_array';
    }
    elements.push(descriptor.value);
  }
  for (const key of Reflect.ownKeys(value)) {
    if (key !== 'length' && !(typeof key === 'string' && /^(0|[1-9][0-9]*)$/.test(key))) {
      return 'not_array';
    }
  }
  return elements;
}

export function isOneOf<T extends string>(value: unknown, allowed: readonly T[]): value is T {
  return typeof value === 'string' && (allowed as readonly string[]).includes(value);
}
