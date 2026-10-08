const CANONICAL_UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

/** Lowercase canonical UUID. Route selectors are not tenancy authority. */
export function isCanonicalUuid(value: string): boolean {
  return CANONICAL_UUID.test(value);
}
