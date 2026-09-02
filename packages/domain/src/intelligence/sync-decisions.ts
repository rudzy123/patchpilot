import type { IntelligenceNotModifiedReason } from './constants.js';
import type { IntelligenceSafeFailureCode } from './failures.js';
import type { IntelligenceKevParserWarningSummary } from './ports.js';
import type { IntelligenceSnapshotRecord, KevGenerationRecord } from './records.js';

export type CatalogRegressionDecision =
  | { kind: 'stage' }
  | { kind: 'not_modified'; reason: 'content_sha256_unchanged' }
  | { kind: 'quarantine'; code: 'catalog_regression' };

export type ContentHashNotModifiedDecision =
  | { kind: 'not_modified'; reason: 'content_sha256_unchanged'; priorAcceptedGenerationId: string }
  | { kind: 'reprocess' };

export type IntelligenceRetryWaitBounds = {
  floorMs: number;
  ceilingMs: number;
};

export function decideContentHashNotModified(input: {
  activeGeneration: KevGenerationRecord | undefined;
  activeSnapshot: IntelligenceSnapshotRecord | undefined;
  fetchedSnapshotSha256: string;
  syncRunParserVersion: string;
  syncRunNormalizationVersion: string;
}): ContentHashNotModifiedDecision {
  const active = input.activeGeneration;
  if (active === undefined || input.activeSnapshot === undefined) {
    return { kind: 'reprocess' };
  }
  if (input.activeSnapshot.responseSha256 !== input.fetchedSnapshotSha256) {
    return { kind: 'reprocess' };
  }
  if (
    active.parserVersion !== input.syncRunParserVersion ||
    active.normalizationVersion !== input.syncRunNormalizationVersion
  ) {
    return { kind: 'reprocess' };
  }
  return {
    kind: 'not_modified',
    reason: 'content_sha256_unchanged',
    priorAcceptedGenerationId: active.id,
  };
}

export function decideCatalogRegression(input: {
  activeGeneration: KevGenerationRecord | undefined;
  catalogReleasedAt: Date;
  snapshotSha256: string;
  activeSnapshotSha256: string | undefined;
  syncRunParserVersion: string;
  syncRunNormalizationVersion: string;
}): CatalogRegressionDecision {
  const active = input.activeGeneration;
  if (active === undefined || active.catalogReleasedAt === null) {
    return { kind: 'stage' };
  }

  const incoming = input.catalogReleasedAt.getTime();
  const current = active.catalogReleasedAt.getTime();
  if (!Number.isSafeInteger(incoming) || !Number.isSafeInteger(current)) {
    return { kind: 'quarantine', code: 'catalog_regression' };
  }

  if (incoming > current) {
    return { kind: 'stage' };
  }
  if (incoming < current) {
    return { kind: 'quarantine', code: 'catalog_regression' };
  }

  if (
    input.activeSnapshotSha256 === input.snapshotSha256 &&
    active.parserVersion === input.syncRunParserVersion &&
    active.normalizationVersion === input.syncRunNormalizationVersion
  ) {
    return { kind: 'not_modified', reason: 'content_sha256_unchanged' };
  }

  return { kind: 'stage' };
}

export function intelligenceRetryWaitDelayMs(
  executionAttempt: number,
  bounds: IntelligenceRetryWaitBounds,
): number {
  const exponent = Math.max(0, executionAttempt - 1);
  let delay = bounds.floorMs;
  for (let index = 0; index < exponent; index += 1) {
    const doubled = delay * 2;
    delay = doubled > bounds.ceilingMs ? bounds.ceilingMs : doubled;
    if (!Number.isSafeInteger(delay)) {
      return bounds.ceilingMs;
    }
  }
  if (delay < bounds.floorMs) {
    return bounds.floorMs;
  }
  if (delay > bounds.ceilingMs) {
    return bounds.ceilingMs;
  }
  return delay;
}

export function sumParserWarningCounts(
  warnings: readonly IntelligenceKevParserWarningSummary[],
): { ok: true; count: number } | { ok: false; code: IntelligenceSafeFailureCode } {
  let total = 0;
  const seen = new Set<string>();
  for (const warning of warnings) {
    if (typeof warning.code !== 'string' || warning.code.length === 0) {
      return { ok: false, code: 'processing_failed' };
    }
    if (seen.has(warning.code)) {
      return { ok: false, code: 'processing_failed' };
    }
    seen.add(warning.code);
    if (!Number.isSafeInteger(warning.count) || warning.count < 1) {
      return { ok: false, code: 'processing_failed' };
    }
    const next = total + warning.count;
    if (!Number.isSafeInteger(next)) {
      return { ok: false, code: 'processing_failed' };
    }
    total = next;
  }
  return { ok: true, count: total };
}

export function notModifiedReason(): IntelligenceNotModifiedReason {
  return 'content_sha256_unchanged';
}
