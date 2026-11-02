/**
 * Freezes `value` and everything reachable through its own properties. An
 * already-frozen object is still descended into, because a frozen shell may
 * hold mutable children.
 */
export function deepFreeze<T>(value: T): T {
  freezeReachable(value, new WeakSet<object>());
  return value;
}

function freezeReachable(value: unknown, visited: WeakSet<object>): void {
  if ((typeof value !== 'object' && typeof value !== 'function') || value === null) {
    return;
  }
  if (visited.has(value)) {
    return;
  }
  visited.add(value);
  for (const key of Reflect.ownKeys(value)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (descriptor !== undefined && 'value' in descriptor) {
      freezeReachable(descriptor.value, visited);
    }
  }
  Object.freeze(value);
}
