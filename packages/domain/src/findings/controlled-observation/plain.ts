/**
 * Hostile-input guards for repeated-observation contracts.
 * Getters are not invoked. Proxies and foreign prototypes are rejected.
 */

import { types as nodeUtilTypes } from 'node:util';

export function isHostileProxy(value: unknown): boolean {
  return nodeUtilTypes.isProxy(value);
}

export function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== 'object' || value === null || isHostileProxy(value)) {
    return false;
  }
  if (Array.isArray(value)) {
    return false;
  }
  const prototype: unknown = Object.getPrototypeOf(value);
  return prototype === Object.prototype;
}

export function ownDataProperties(
  record: Record<string, unknown>,
): { readonly ok: true; readonly keys: readonly string[] } | { readonly ok: false } {
  const symbols = Object.getOwnPropertySymbols(record);
  if (symbols.length > 0) {
    return { ok: false };
  }
  const keys: string[] = [];
  for (const key of Object.getOwnPropertyNames(record)) {
    const descriptor = Object.getOwnPropertyDescriptor(record, key);
    if (
      descriptor === undefined ||
      descriptor.get !== undefined ||
      descriptor.set !== undefined ||
      !Object.hasOwn(record, key)
    ) {
      return { ok: false };
    }
    keys.push(key);
  }
  return { ok: true, keys };
}

export function readOwnData(record: Record<string, unknown>, key: string): unknown {
  const descriptor = Object.getOwnPropertyDescriptor(record, key);
  if (descriptor === undefined || descriptor.get !== undefined || descriptor.set !== undefined) {
    return undefined;
  }
  return descriptor.value;
}

export function closedRecord(
  input: unknown,
  keys: readonly string[],
): ReadonlyMap<string, unknown> | null {
  if (!isPlainObject(input)) {
    return null;
  }
  const owned = ownDataProperties(input);
  if (!owned.ok || owned.keys.length !== keys.length) {
    return null;
  }
  for (const key of owned.keys) {
    if (!keys.includes(key)) {
      return null;
    }
  }
  const values = new Map<string, unknown>();
  for (const key of keys) {
    values.set(key, readOwnData(input, key));
  }
  return values;
}

export function recordHasAmbientKey(input: unknown, ambient: readonly string[]): boolean {
  if (typeof input !== 'object' || input === null || isHostileProxy(input)) {
    return false;
  }
  const names = Object.getOwnPropertyNames(input);
  const blocked = new Set<string>(ambient);
  for (const name of names) {
    if (blocked.has(name)) {
      return true;
    }
  }
  return false;
}

export function ownNames(input: unknown): readonly string[] | null {
  if (typeof input !== 'object' || input === null || isHostileProxy(input)) {
    return null;
  }
  return Object.getOwnPropertyNames(input);
}
