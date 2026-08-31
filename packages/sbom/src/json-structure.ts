import type { SafeFailureCode, SbomParserLimits } from '@patchpilot/domain';

const FORBIDDEN_OBJECT_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

export type JsonStructureInspection = { ok: true } | { ok: false; code: SafeFailureCode };

function isObjectRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function inspectNode(
  value: unknown,
  depth: number,
  state: { nodes: number },
  limits: Pick<SbomParserLimits, 'jsonMaxDepth' | 'jsonMaxNodes' | 'jsonMaxStringBytes'>,
): JsonStructureInspection {
  if (depth > limits.jsonMaxDepth) {
    return { ok: false, code: 'json_depth' };
  }

  state.nodes += 1;
  if (state.nodes > limits.jsonMaxNodes) {
    return { ok: false, code: 'json_nodes' };
  }

  if (typeof value === 'string') {
    if (Buffer.byteLength(value, 'utf8') > limits.jsonMaxStringBytes) {
      return { ok: false, code: 'json_string_length' };
    }
    return { ok: true };
  }

  if (value === null || typeof value === 'number' || typeof value === 'boolean') {
    return { ok: true };
  }

  if (Array.isArray(value)) {
    for (const item of value) {
      const nested = inspectNode(item, depth + 1, state, limits);
      if (!nested.ok) {
        return nested;
      }
    }
    return { ok: true };
  }

  if (!isObjectRecord(value)) {
    return { ok: false, code: 'json_syntax' };
  }

  for (const key of Object.getOwnPropertyNames(value)) {
    if (FORBIDDEN_OBJECT_KEYS.has(key)) {
      return { ok: false, code: 'prototype_pollution' };
    }
    const nested = inspectNode(value[key], depth + 1, state, limits);
    if (!nested.ok) {
      return nested;
    }
  }

  return { ok: true };
}

/**
 * Enforce JSON depth, node, and string-byte limits, and reject prototype-related
 * object keys. The document root is depth 1.
 */
export function inspectJsonStructure(
  value: unknown,
  limits: Pick<SbomParserLimits, 'jsonMaxDepth' | 'jsonMaxNodes' | 'jsonMaxStringBytes'>,
): JsonStructureInspection {
  return inspectNode(value, 1, { nodes: 0 }, limits);
}

export function isPrototypePollutionParseError(error: unknown): boolean {
  return error instanceof SyntaxError && /forbidden prototype/i.test(error.message);
}
