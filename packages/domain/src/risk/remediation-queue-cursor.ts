/**
 * Opaque remediation-queue cursor.
 * It binds a page to the section, the reference definition hash, the engine
 * version, and the last key tuple. The client does not build it.
 */

export const REMEDIATION_QUEUE_CURSOR_VERSION = 1 as const;

export const REMEDIATION_QUEUE_MAX_CURSOR_LENGTH = 2048;

const UUID_LOWER = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const SHA256_HEX = /^[a-f0-9]{64}$/;
const DECIMAL_TEXT = /^(?:0|[1-9][0-9]{0,8})(?:\.[0-9]{1,6})?$/;
const OBSERVED_AT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const ENGINE_TEXT = /^[\u0020-\u007e]{1,64}$/;

export type RemediationQueueCursor =
  | {
      readonly section: 'ranked';
      readonly policyDefinitionSha256: string;
      readonly engineVersion: string;
      readonly priorityText: string;
      readonly escalationRecommended: boolean;
      readonly kevListed: boolean;
      readonly severityText: string;
      readonly firstObservedAt: string;
      readonly findingId: string;
    }
  | {
      readonly section: 'incomparable';
      readonly policyDefinitionSha256: string;
      readonly engineVersion: string;
      readonly calculatedAt: string;
      readonly findingId: string;
    }
  | {
      readonly section: 'not_calculated';
      readonly policyDefinitionSha256: string;
      readonly engineVersion: string;
      readonly firstObservedAt: string;
      readonly findingId: string;
    };

export function encodeRemediationQueueCursor(cursor: RemediationQueueCursor): string {
  const payload =
    cursor.section === 'ranked'
      ? {
          v: REMEDIATION_QUEUE_CURSOR_VERSION,
          s: cursor.section,
          h: cursor.policyDefinitionSha256,
          e: cursor.engineVersion,
          p: cursor.priorityText,
          es: cursor.escalationRecommended,
          k: cursor.kevListed,
          sv: cursor.severityText,
          t: cursor.firstObservedAt,
          i: cursor.findingId,
        }
      : cursor.section === 'incomparable'
        ? {
            v: REMEDIATION_QUEUE_CURSOR_VERSION,
            s: cursor.section,
            h: cursor.policyDefinitionSha256,
            e: cursor.engineVersion,
            t: cursor.calculatedAt,
            i: cursor.findingId,
          }
        : {
            v: REMEDIATION_QUEUE_CURSOR_VERSION,
            s: cursor.section,
            h: cursor.policyDefinitionSha256,
            e: cursor.engineVersion,
            t: cursor.firstObservedAt,
            i: cursor.findingId,
          };
  return Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
}

export function decodeRemediationQueueCursor(
  value: string,
): { readonly ok: true; readonly cursor: RemediationQueueCursor } | { readonly ok: false } {
  if (value.length === 0 || value.length > REMEDIATION_QUEUE_MAX_CURSOR_LENGTH) {
    return { ok: false };
  }
  if (!/^[A-Za-z0-9_-]+$/.test(value)) {
    return { ok: false };
  }
  let parsed: unknown;
  try {
    const decoded = Buffer.from(value, 'base64url').toString('utf8');
    if (decoded.length === 0 || decoded.includes('\u0000')) {
      return { ok: false };
    }
    parsed = JSON.parse(decoded) as unknown;
  } catch {
    return { ok: false };
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { ok: false };
  }
  const record = parsed as Record<string, unknown>;
  if (record['v'] !== REMEDIATION_QUEUE_CURSOR_VERSION) {
    return { ok: false };
  }
  const section = record['s'];
  if (section === 'ranked') {
    return decodeRanked(record);
  }
  if (section === 'incomparable') {
    return decodeIncomparable(record);
  }
  if (section === 'not_calculated') {
    return decodeNotCalculated(record);
  }
  return { ok: false };
}

function decodeRanked(
  record: Record<string, unknown>,
): { readonly ok: true; readonly cursor: RemediationQueueCursor } | { readonly ok: false } {
  if (!exactKeys(record, ['v', 's', 'h', 'e', 'p', 'es', 'k', 'sv', 't', 'i'])) {
    return { ok: false };
  }
  const shared = readShared(record);
  const priorityText = record['p'];
  const severityText = record['sv'];
  const firstObservedAt = record['t'];
  const escalationRecommended = record['es'];
  const kevListed = record['k'];
  if (
    shared === null ||
    typeof priorityText !== 'string' ||
    !DECIMAL_TEXT.test(priorityText) ||
    typeof severityText !== 'string' ||
    !DECIMAL_TEXT.test(severityText) ||
    typeof firstObservedAt !== 'string' ||
    !OBSERVED_AT.test(firstObservedAt) ||
    typeof escalationRecommended !== 'boolean' ||
    typeof kevListed !== 'boolean'
  ) {
    return { ok: false };
  }
  return {
    ok: true,
    cursor: {
      section: 'ranked',
      policyDefinitionSha256: shared.hash,
      engineVersion: shared.engine,
      priorityText,
      escalationRecommended,
      kevListed,
      severityText,
      firstObservedAt,
      findingId: shared.findingId,
    },
  };
}

function decodeIncomparable(
  record: Record<string, unknown>,
): { readonly ok: true; readonly cursor: RemediationQueueCursor } | { readonly ok: false } {
  if (!exactKeys(record, ['v', 's', 'h', 'e', 't', 'i'])) {
    return { ok: false };
  }
  const shared = readShared(record);
  const calculatedAt = record['t'];
  if (shared === null || typeof calculatedAt !== 'string' || !OBSERVED_AT.test(calculatedAt)) {
    return { ok: false };
  }
  return {
    ok: true,
    cursor: {
      section: 'incomparable',
      policyDefinitionSha256: shared.hash,
      engineVersion: shared.engine,
      calculatedAt,
      findingId: shared.findingId,
    },
  };
}

function decodeNotCalculated(
  record: Record<string, unknown>,
): { readonly ok: true; readonly cursor: RemediationQueueCursor } | { readonly ok: false } {
  if (!exactKeys(record, ['v', 's', 'h', 'e', 't', 'i'])) {
    return { ok: false };
  }
  const shared = readShared(record);
  const firstObservedAt = record['t'];
  if (
    shared === null ||
    typeof firstObservedAt !== 'string' ||
    !OBSERVED_AT.test(firstObservedAt)
  ) {
    return { ok: false };
  }
  return {
    ok: true,
    cursor: {
      section: 'not_calculated',
      policyDefinitionSha256: shared.hash,
      engineVersion: shared.engine,
      firstObservedAt,
      findingId: shared.findingId,
    },
  };
}

function readShared(
  record: Record<string, unknown>,
): { readonly hash: string; readonly engine: string; readonly findingId: string } | null {
  const hash = record['h'];
  const engine = record['e'];
  const findingId = record['i'];
  if (
    typeof hash !== 'string' ||
    !SHA256_HEX.test(hash) ||
    typeof engine !== 'string' ||
    !ENGINE_TEXT.test(engine) ||
    typeof findingId !== 'string' ||
    !UUID_LOWER.test(findingId)
  ) {
    return null;
  }
  return { hash, engine, findingId };
}

function exactKeys(record: Record<string, unknown>, keys: readonly string[]): boolean {
  const owned = Object.keys(record);
  if (owned.length !== keys.length) {
    return false;
  }
  return keys.every((key) => Object.hasOwn(record, key));
}
