import { err, ok, type Result } from '../result.js';
import { isFinalSbomObjectKey, isTemporarySbomObjectKey } from '../sbom/object-keys.js';
import {
  INTELLIGENCE_SNAPSHOT_OBJECT_KEY_MAX_LENGTH,
  INTELLIGENCE_SNAPSHOT_OBJECT_KEY_PATTERN,
  SHA256_HEX_PATTERN,
} from './constants.js';
import { INTELLIGENCE_INVALID_OBJECT_KEY } from './errors.js';

export type IntelligenceSnapshotObjectKey = string & {
  readonly __intelligenceSnapshotObjectKey: unique symbol;
};

function looksLikeUrl(value: string): boolean {
  return (
    value.includes('://') ||
    value.startsWith('http:') ||
    value.startsWith('https:') ||
    value.startsWith('//')
  );
}

/**
 * Opaque internal snapshot object key. Exact production key layout remains
 * deferred by ADR 0021. This validator only rejects URLs, SBOM keys, and
 * unsafe characters. It does not approve a final prefix scheme.
 */
export function parseIntelligenceSnapshotObjectKey(
  value: string,
): Result<IntelligenceSnapshotObjectKey> {
  if (
    value.length === 0 ||
    value.length > INTELLIGENCE_SNAPSHOT_OBJECT_KEY_MAX_LENGTH ||
    !INTELLIGENCE_SNAPSHOT_OBJECT_KEY_PATTERN.test(value) ||
    value.includes('..') ||
    value.includes('\\') ||
    looksLikeUrl(value) ||
    value.includes('sboms/') ||
    isFinalSbomObjectKey(value) ||
    isTemporarySbomObjectKey(value)
  ) {
    return err(INTELLIGENCE_INVALID_OBJECT_KEY);
  }
  return ok(value as IntelligenceSnapshotObjectKey);
}

export function isIntelligenceSnapshotObjectKey(
  value: string,
): value is IntelligenceSnapshotObjectKey {
  return parseIntelligenceSnapshotObjectKey(value).ok;
}

export type IntelligenceSnapshotObjectKeyKind = 'temporary' | 'final';

export type IntelligenceSnapshotObjectKeyPlan = {
  kind: IntelligenceSnapshotObjectKeyKind;
  provider: 'cisa_kev';
  sourceIdentifier: 'cisa_kev_json_catalog';
  syncRunId?: string;
  responseSha256?: string;
};

export type IntelligenceSnapshotObjectKeyBuilderPort = {
  build(plan: IntelligenceSnapshotObjectKeyPlan): Result<IntelligenceSnapshotObjectKey>;
};

export function assertSnapshotIdentitySha256(value: string): boolean {
  return SHA256_HEX_PATTERN.test(value);
}
