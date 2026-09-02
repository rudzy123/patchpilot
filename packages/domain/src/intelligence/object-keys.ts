import { err, ok, type Result } from '../result.js';
import { isFinalSbomObjectKey, isTemporarySbomObjectKey } from '../sbom/object-keys.js';
import {
  CISA_KEV_SOURCE_IDENTIFIER,
  INTELLIGENCE_FINAL_SNAPSHOT_OBJECT_KEY_PATTERN,
  INTELLIGENCE_SNAPSHOT_KEY_PREFIX,
  INTELLIGENCE_SNAPSHOT_OBJECT_KEY_MAX_LENGTH,
  INTELLIGENCE_TEMPORARY_SNAPSHOT_OBJECT_KEY_PATTERN,
  INTELLIGENCE_UPLOAD_ID_PATTERN,
  SHA256_HEX_PATTERN,
} from './constants.js';
import { INTELLIGENCE_INVALID_OBJECT_KEY } from './errors.js';

export type TemporaryIntelligenceSnapshotObjectKey = string & {
  readonly __temporaryIntelligenceSnapshotObjectKey: unique symbol;
};

export type FinalIntelligenceSnapshotObjectKey = string & {
  readonly __finalIntelligenceSnapshotObjectKey: unique symbol;
};

export type IntelligenceSnapshotObjectKey =
  TemporaryIntelligenceSnapshotObjectKey | FinalIntelligenceSnapshotObjectKey;

const TEMPORARY_PREFIX = `${INTELLIGENCE_SNAPSHOT_KEY_PREFIX}/tmp/` as const;
const FINAL_PREFIX = `${INTELLIGENCE_SNAPSHOT_KEY_PREFIX}/sha256/` as const;

function looksLikeUrl(value: string): boolean {
  return (
    value.includes('://') ||
    value.startsWith('http:') ||
    value.startsWith('https:') ||
    value.startsWith('//')
  );
}

function hasUnsafeKeyShape(value: string): boolean {
  return (
    value.length === 0 ||
    value.length > INTELLIGENCE_SNAPSHOT_OBJECT_KEY_MAX_LENGTH ||
    value.includes('.') ||
    value.includes('\\') ||
    value.includes('//') ||
    looksLikeUrl(value) ||
    value.includes('sboms/') ||
    isFinalSbomObjectKey(value) ||
    isTemporarySbomObjectKey(value)
  );
}

export function buildTemporaryIntelligenceSnapshotObjectKey(
  uploadId: string,
): Result<TemporaryIntelligenceSnapshotObjectKey> {
  if (!INTELLIGENCE_UPLOAD_ID_PATTERN.test(uploadId)) {
    return err(INTELLIGENCE_INVALID_OBJECT_KEY);
  }

  const value = `${TEMPORARY_PREFIX}${uploadId}`;
  return parseTemporaryIntelligenceSnapshotObjectKey(value);
}

export function buildFinalIntelligenceSnapshotObjectKey(
  responseSha256: string,
): Result<FinalIntelligenceSnapshotObjectKey> {
  if (!SHA256_HEX_PATTERN.test(responseSha256)) {
    return err(INTELLIGENCE_INVALID_OBJECT_KEY);
  }

  const value = `${FINAL_PREFIX}${responseSha256}`;
  return parseFinalIntelligenceSnapshotObjectKey(value);
}

export function parseTemporaryIntelligenceSnapshotObjectKey(
  value: string,
): Result<TemporaryIntelligenceSnapshotObjectKey> {
  if (hasUnsafeKeyShape(value) || !INTELLIGENCE_TEMPORARY_SNAPSHOT_OBJECT_KEY_PATTERN.test(value)) {
    return err(INTELLIGENCE_INVALID_OBJECT_KEY);
  }

  return ok(value as TemporaryIntelligenceSnapshotObjectKey);
}

export function parseFinalIntelligenceSnapshotObjectKey(
  value: string,
): Result<FinalIntelligenceSnapshotObjectKey> {
  if (hasUnsafeKeyShape(value) || !INTELLIGENCE_FINAL_SNAPSHOT_OBJECT_KEY_PATTERN.test(value)) {
    return err(INTELLIGENCE_INVALID_OBJECT_KEY);
  }

  return ok(value as FinalIntelligenceSnapshotObjectKey);
}

export function parseIntelligenceSnapshotObjectKey(
  value: string,
): Result<IntelligenceSnapshotObjectKey> {
  const temporary = parseTemporaryIntelligenceSnapshotObjectKey(value);
  if (temporary.ok) {
    return temporary;
  }

  return parseFinalIntelligenceSnapshotObjectKey(value);
}

export function isTemporaryIntelligenceSnapshotObjectKey(
  value: string,
): value is TemporaryIntelligenceSnapshotObjectKey {
  return parseTemporaryIntelligenceSnapshotObjectKey(value).ok;
}

export function isFinalIntelligenceSnapshotObjectKey(
  value: string,
): value is FinalIntelligenceSnapshotObjectKey {
  return parseFinalIntelligenceSnapshotObjectKey(value).ok;
}

export function isIntelligenceSnapshotObjectKey(
  value: string,
): value is IntelligenceSnapshotObjectKey {
  return parseIntelligenceSnapshotObjectKey(value).ok;
}

export function intelligenceSnapshotKeyProvider(_key: IntelligenceSnapshotObjectKey): 'cisa_kev' {
  return 'cisa_kev';
}

export function intelligenceSnapshotKeySourceIdentifier(
  _key: IntelligenceSnapshotObjectKey,
): typeof CISA_KEV_SOURCE_IDENTIFIER {
  return CISA_KEV_SOURCE_IDENTIFIER;
}

export function uploadIdFromTemporaryIntelligenceSnapshotObjectKey(
  key: TemporaryIntelligenceSnapshotObjectKey,
): string {
  return key.slice(TEMPORARY_PREFIX.length);
}

export function sha256FromFinalIntelligenceSnapshotObjectKey(
  key: FinalIntelligenceSnapshotObjectKey,
): string {
  return key.slice(FINAL_PREFIX.length);
}

export function intelligenceObjectKeysShareScope(
  left: IntelligenceSnapshotObjectKey,
  right: IntelligenceSnapshotObjectKey,
): boolean {
  return (
    intelligenceSnapshotKeyProvider(left) === intelligenceSnapshotKeyProvider(right) &&
    intelligenceSnapshotKeySourceIdentifier(left) === intelligenceSnapshotKeySourceIdentifier(right)
  );
}

export type IntelligenceSnapshotObjectKeyKind = 'temporary' | 'final';

export type IntelligenceSnapshotObjectKeyPlan =
  | {
      kind: 'temporary';
      provider: 'cisa_kev';
      sourceIdentifier: typeof CISA_KEV_SOURCE_IDENTIFIER;
      uploadId: string;
    }
  | {
      kind: 'final';
      provider: 'cisa_kev';
      sourceIdentifier: typeof CISA_KEV_SOURCE_IDENTIFIER;
      responseSha256: string;
    };

export type IntelligenceSnapshotObjectKeyBuilderPort = {
  buildTemporary(uploadId: string): Result<TemporaryIntelligenceSnapshotObjectKey>;
  buildFinal(responseSha256: string): Result<FinalIntelligenceSnapshotObjectKey>;
  build(plan: IntelligenceSnapshotObjectKeyPlan): Result<IntelligenceSnapshotObjectKey>;
};

export function createIntelligenceSnapshotObjectKeyBuilder(): IntelligenceSnapshotObjectKeyBuilderPort {
  return {
    buildTemporary: buildTemporaryIntelligenceSnapshotObjectKey,
    buildFinal: buildFinalIntelligenceSnapshotObjectKey,
    build(plan) {
      if (plan.kind === 'temporary') {
        return buildTemporaryIntelligenceSnapshotObjectKey(plan.uploadId);
      }

      return buildFinalIntelligenceSnapshotObjectKey(plan.responseSha256);
    },
  };
}

export function assertSnapshotIdentitySha256(value: string): boolean {
  return SHA256_HEX_PATTERN.test(value);
}
