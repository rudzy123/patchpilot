/**
 * The production allowlist admits one validated pair. Every other pair fails closed.
 */

import { readFileSync } from 'node:fs';

import { describe, expect, it } from 'vitest';

import {
  ADMITTED_PRIORITY_POLICY_PAIRS,
  isAdmittedPriorityPolicyPair,
  type AdmittedPriorityPolicyPair,
} from './admitted-priority-policy.js';

const ENGINE_VERSION = '@patchpilot/policy-engine@1';
const DEFINITION_SHA256 = '7c1815d456ff6dcf9e19c218bcd5eaba73c265abc911027c3f50df41bb8504f7';
const OTHER_SHA256 = '0000000000000000000000000000000000000000000000000000000000000000';

const ADMITTED_PAIR = {
  engineVersion: ENGINE_VERSION,
  policyDefinitionSha256: DEFINITION_SHA256,
  validationEntryId: 'V-0001',
} as const satisfies AdmittedPriorityPolicyPair;

describe('admitted priority policy pair', () => {
  it('freezes exactly the V-0001 builtin pair', () => {
    const source = readFileSync(new URL('./admitted-priority-policy.ts', import.meta.url), 'utf8');
    expect(source.match(/'@patchpilot\/policy-engine@1'/g)).toEqual([
      "'@patchpilot/policy-engine@1'",
    ]);
    expect(source).not.toContain('PRIORITY_CALCULATION_ENGINE_VERSION');
    expect(source).not.toContain('POLICY_ENGINE_VERSION');
    expect(source).toContain(`policyDefinitionSha256: '${DEFINITION_SHA256}'`);
    expect(source).toContain("validationEntryId: 'V-0001'");

    expect(ADMITTED_PRIORITY_POLICY_PAIRS).toEqual([ADMITTED_PAIR]);
    expect(Object.isFrozen(ADMITTED_PRIORITY_POLICY_PAIRS)).toBe(true);
    expect(Object.getOwnPropertyDescriptor(ADMITTED_PRIORITY_POLICY_PAIRS, '0')?.writable).toBe(
      false,
    );

    const pair = ADMITTED_PRIORITY_POLICY_PAIRS[0];
    if (pair === undefined) {
      throw new Error('expected one admitted pair');
    }
    expect(Object.isFrozen(pair)).toBe(true);
    expect(Object.getOwnPropertyDescriptor(pair, 'engineVersion')?.writable).toBe(false);
    expect(Object.getOwnPropertyDescriptor(pair, 'policyDefinitionSha256')?.writable).toBe(false);
    expect(Object.getOwnPropertyDescriptor(pair, 'validationEntryId')?.writable).toBe(false);

    expect(() => {
      (ADMITTED_PRIORITY_POLICY_PAIRS as unknown as AdmittedPriorityPolicyPair[]).push(pair);
    }).toThrow(TypeError);
    expect(() => {
      Object.assign(pair, { engineVersion: '@patchpilot/policy-engine@2' });
    }).toThrow(TypeError);
    expect(ADMITTED_PRIORITY_POLICY_PAIRS).toEqual([ADMITTED_PAIR]);
    expect(
      isAdmittedPriorityPolicyPair(
        ADMITTED_PRIORITY_POLICY_PAIRS,
        ENGINE_VERSION,
        DEFINITION_SHA256,
      ),
    ).toBe(true);
  });

  it('rejects a different engine version, hash, or empty validation id', () => {
    expect(
      isAdmittedPriorityPolicyPair(
        ADMITTED_PRIORITY_POLICY_PAIRS,
        '@patchpilot/policy-engine@2',
        DEFINITION_SHA256,
      ),
    ).toBe(false);
    expect(
      isAdmittedPriorityPolicyPair(ADMITTED_PRIORITY_POLICY_PAIRS, ENGINE_VERSION, OTHER_SHA256),
    ).toBe(false);
    expect(
      isAdmittedPriorityPolicyPair(ADMITTED_PRIORITY_POLICY_PAIRS, ENGINE_VERSION, 'abc'),
    ).toBe(false);
    expect(
      isAdmittedPriorityPolicyPair(
        [
          {
            engineVersion: ENGINE_VERSION,
            policyDefinitionSha256: DEFINITION_SHA256,
            validationEntryId: '',
          },
        ],
        ENGINE_VERSION,
        DEFINITION_SHA256,
      ),
    ).toBe(false);
  });

  it('fails closed when the pair is not admitted', () => {
    expect(isAdmittedPriorityPolicyPair([], ENGINE_VERSION, DEFINITION_SHA256)).toBe(false);
    expect(
      isAdmittedPriorityPolicyPair(
        [
          {
            engineVersion: '@patchpilot/policy-engine@2',
            policyDefinitionSha256: DEFINITION_SHA256,
            validationEntryId: 'V-0001',
          },
        ],
        ENGINE_VERSION,
        DEFINITION_SHA256,
      ),
    ).toBe(false);
    expect(
      isAdmittedPriorityPolicyPair(
        [
          {
            engineVersion: ENGINE_VERSION,
            policyDefinitionSha256: OTHER_SHA256,
            validationEntryId: 'V-0001',
          },
        ],
        ENGINE_VERSION,
        DEFINITION_SHA256,
      ),
    ).toBe(false);
    expect(
      isAdmittedPriorityPolicyPair(
        undefined as unknown as readonly AdmittedPriorityPolicyPair[],
        ENGINE_VERSION,
        DEFINITION_SHA256,
      ),
    ).toBe(false);
  });
});
