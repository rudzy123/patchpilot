/**
 * The injected engine port names the pure functions and nothing else.
 * `parseFactInput` is required because `evaluatePriority` accepts parsed facts.
 */

import { describe, expect, it } from 'vitest';

import { PRIORITY_ENGINE_PORT_METHODS, type PriorityEnginePort } from './engine-port.js';

type PortMethod = keyof PriorityEnginePort<unknown, unknown>;
type ListedMethod = (typeof PRIORITY_ENGINE_PORT_METHODS)[number];
const portMethodsAreExact: [PortMethod] extends [ListedMethod]
  ? [ListedMethod] extends [PortMethod]
    ? true
    : never
  : never = true;

describe('priority engine port', () => {
  it('injects fact parsing, evaluate, both validators, and canonical JSON', () => {
    expect(portMethodsAreExact).toBe(true);
    expect([...PRIORITY_ENGINE_PORT_METHODS]).toEqual([
      'parseFactInput',
      'evaluatePriority',
      'validatePolicyDefinition',
      'validatePolicyOverride',
      'canonicalJson',
    ]);
  });
});
