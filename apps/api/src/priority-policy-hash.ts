/**
 * Hashes a published policy definition for the current-priority read.
 * The read use case receives this function. It does not receive the engine port.
 */

import { createHash } from 'node:crypto';

import { canonicalJson } from '@patchpilot/policy-engine';

export function hashPriorityPolicyDefinition(definition: unknown): string | null {
  const encoded = canonicalJson(definition);
  if (!encoded.ok) {
    return null;
  }
  return createHash('sha256').update(encoded.value, 'utf8').digest('hex');
}
