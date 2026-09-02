import { describe, expect, it } from 'vitest';

import { buildFinalSbomObjectKey, buildTemporarySbomObjectKey } from '../sbom/object-keys.js';
import { INTELLIGENCE_SNAPSHOT_OBJECT_KEY_MAX_LENGTH } from './constants.js';
import {
  buildFinalIntelligenceSnapshotObjectKey,
  buildTemporaryIntelligenceSnapshotObjectKey,
  createIntelligenceSnapshotObjectKeyBuilder,
  intelligenceObjectKeysShareScope,
  intelligenceSnapshotKeyProvider,
  intelligenceSnapshotKeySourceIdentifier,
  isFinalIntelligenceSnapshotObjectKey,
  isTemporaryIntelligenceSnapshotObjectKey,
  parseFinalIntelligenceSnapshotObjectKey,
  parseIntelligenceSnapshotObjectKey,
  parseTemporaryIntelligenceSnapshotObjectKey,
  sha256FromFinalIntelligenceSnapshotObjectKey,
  uploadIdFromTemporaryIntelligenceSnapshotObjectKey,
} from './object-keys.js';

const UPLOAD_ID = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const SHA = 'b'.repeat(64);
const TEMPORARY = `intelligence/cisa_kev/cisa_kev_json_catalog/tmp/${UPLOAD_ID}`;
const FINAL = `intelligence/cisa_kev/cisa_kev_json_catalog/sha256/${SHA}`;

describe('intelligence snapshot object keys', () => {
  it('builds deterministic temporary and final keys below the database ceiling', () => {
    const temporary = buildTemporaryIntelligenceSnapshotObjectKey(UPLOAD_ID);
    const firstFinal = buildFinalIntelligenceSnapshotObjectKey(SHA);
    const secondFinal = buildFinalIntelligenceSnapshotObjectKey(SHA);
    expect(temporary.ok).toBe(true);
    expect(firstFinal.ok).toBe(true);
    expect(secondFinal.ok).toBe(true);
    if (!temporary.ok || !firstFinal.ok || !secondFinal.ok) {
      return;
    }

    expect(temporary.value).toBe(TEMPORARY);
    expect(firstFinal.value).toBe(FINAL);
    expect(secondFinal.value).toBe(firstFinal.value);
    expect(temporary.value.length).toBeLessThan(INTELLIGENCE_SNAPSHOT_OBJECT_KEY_MAX_LENGTH);
    expect(firstFinal.value.length).toBeLessThan(INTELLIGENCE_SNAPSHOT_OBJECT_KEY_MAX_LENGTH);
    expect(INTELLIGENCE_SNAPSHOT_OBJECT_KEY_MAX_LENGTH).toBe(512);
  });

  it('extracts closed provider, source, upload id, and digest from trusted keys', () => {
    const temporary = parseTemporaryIntelligenceSnapshotObjectKey(TEMPORARY);
    const finalKey = parseFinalIntelligenceSnapshotObjectKey(FINAL);
    expect(temporary.ok && finalKey.ok).toBe(true);
    if (!temporary.ok || !finalKey.ok) {
      return;
    }

    expect(intelligenceSnapshotKeyProvider(temporary.value)).toBe('cisa_kev');
    expect(intelligenceSnapshotKeySourceIdentifier(finalKey.value)).toBe('cisa_kev_json_catalog');
    expect(uploadIdFromTemporaryIntelligenceSnapshotObjectKey(temporary.value)).toBe(UPLOAD_ID);
    expect(sha256FromFinalIntelligenceSnapshotObjectKey(finalKey.value)).toBe(SHA);
    expect(intelligenceObjectKeysShareScope(temporary.value, finalKey.value)).toBe(true);
  });

  it('rejects uppercase, malformed ids, URLs, SBOM keys, and unsafe path forms', () => {
    expect(buildTemporaryIntelligenceSnapshotObjectKey(UPLOAD_ID.toUpperCase()).ok).toBe(false);
    expect(buildFinalIntelligenceSnapshotObjectKey('A'.repeat(64)).ok).toBe(false);
    expect(buildTemporaryIntelligenceSnapshotObjectKey('not-a-uuid').ok).toBe(false);
    expect(buildFinalIntelligenceSnapshotObjectKey('abc').ok).toBe(false);
    expect(parseIntelligenceSnapshotObjectKey('https://example.invalid/object').ok).toBe(false);
    expect(
      parseIntelligenceSnapshotObjectKey('intelligence/cisa_kev/cisa_kev_json_catalog/tmp/../x').ok,
    ).toBe(false);
    expect(
      parseIntelligenceSnapshotObjectKey(
        `intelligence/cisa_kev/cisa_kev_json_catalog//sha256/${SHA}`,
      ).ok,
    ).toBe(false);
    expect(
      parseIntelligenceSnapshotObjectKey(
        `intelligence\\cisa_kev\\cisa_kev_json_catalog\\sha256\\${SHA}`,
      ).ok,
    ).toBe(false);
    expect(
      parseIntelligenceSnapshotObjectKey(
        'intelligence/cisa_kev/cisa_kev_json_catalog/sha256/catalog.json',
      ).ok,
    ).toBe(false);
    expect(
      parseIntelligenceSnapshotObjectKey(
        'intelligence/cisa_kev/cisa_kev_json_catalog/sha256/known_exploited_vulnerabilities.json',
      ).ok,
    ).toBe(false);
    expect(
      parseIntelligenceSnapshotObjectKey(`osv/cisa_kev/cisa_kev_json_catalog/sha256/${SHA}`).ok,
    ).toBe(false);
    expect(
      parseIntelligenceSnapshotObjectKey(`intelligence/osv/cisa_kev_json_catalog/sha256/${SHA}`).ok,
    ).toBe(false);
    expect(
      parseIntelligenceSnapshotObjectKey(`intelligence/cisa_kev/osv_all_zip/sha256/${SHA}`).ok,
    ).toBe(false);
    const sbomTemporary = buildTemporarySbomObjectKey({
      organizationId: UPLOAD_ID,
      assetId: UPLOAD_ID,
      uploadId: UPLOAD_ID,
    });
    const sbomFinal = buildFinalSbomObjectKey({
      organizationId: UPLOAD_ID,
      assetId: UPLOAD_ID,
      sha256: SHA,
    });
    expect(parseIntelligenceSnapshotObjectKey(sbomTemporary).ok).toBe(false);
    expect(parseIntelligenceSnapshotObjectKey(sbomFinal).ok).toBe(false);
    expect(isTemporaryIntelligenceSnapshotObjectKey(sbomTemporary)).toBe(false);
    expect(isFinalIntelligenceSnapshotObjectKey(sbomFinal)).toBe(false);
  });

  it('parses trusted keys and rejects cross-type extraction', () => {
    expect(parseTemporaryIntelligenceSnapshotObjectKey(TEMPORARY).ok).toBe(true);
    expect(parseFinalIntelligenceSnapshotObjectKey(FINAL).ok).toBe(true);
    expect(parseTemporaryIntelligenceSnapshotObjectKey(FINAL).ok).toBe(false);
    expect(parseFinalIntelligenceSnapshotObjectKey(TEMPORARY).ok).toBe(false);
    const builder = createIntelligenceSnapshotObjectKeyBuilder();
    expect(builder.buildTemporary(UPLOAD_ID).ok).toBe(true);
    expect(builder.buildFinal(SHA).ok).toBe(true);
    expect(
      builder.build({
        kind: 'final',
        provider: 'cisa_kev',
        sourceIdentifier: 'cisa_kev_json_catalog',
        responseSha256: SHA,
      }).ok,
    ).toBe(true);
  });
});
