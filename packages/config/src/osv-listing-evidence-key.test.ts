/**
 * Session 13 Batch 3D-C listing-evidence key provisioning.
 * Ephemeral synthetic material only. No production key. Not loaded by
 * loadServerConfig.
 */

import { inspect } from 'node:util';
import { randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import {
  INTELLIGENCE_OSV_LISTING_EVIDENCE_KEY_ALIAS_NAME,
  INTELLIGENCE_OSV_LISTING_EVIDENCE_KEY_MATERIAL_NAME,
  INTELLIGENCE_OSV_LISTING_EVIDENCE_KEY_STATE_NAME,
  loadOsvProtectedListingEvidenceKeyProvisioningFrom,
  releaseOsvProtectedListingEvidenceKeyMaterialToInfrastructure,
} from './osv-listing-evidence-key.js';

const here = dirname(fileURLToPath(import.meta.url));

function randomHexKey(): string {
  return Buffer.from(randomBytes(32)).toString('hex');
}

describe('Session 13 Batch 3D-C listing-evidence key provisioning', () => {
  it('loads a current operator-supplied hex key into an opaque handle', () => {
    const material = randomHexKey();
    const loaded = loadOsvProtectedListingEvidenceKeyProvisioningFrom({
      [INTELLIGENCE_OSV_LISTING_EVIDENCE_KEY_MATERIAL_NAME]: material,
      [INTELLIGENCE_OSV_LISTING_EVIDENCE_KEY_ALIAS_NAME]: 'osv.listing.evidence.k1',
      [INTELLIGENCE_OSV_LISTING_EVIDENCE_KEY_STATE_NAME]: 'current',
    });
    expect(loaded.ok).toBe(true);
    if (!loaded.ok) {
      return;
    }
    expect(loaded.value.returnsRawKeyMaterial).toBe(false);
    expect(loaded.value.byteLength).toBe(32);
    expect(loaded.value.alias).toBe('osv.listing.evidence.k1');
    expect(JSON.stringify(loaded.value)).not.toContain(material);
    expect(inspect(loaded.value)).not.toContain(material);
    expect(String(loaded.value)).not.toContain(material);
    const released = releaseOsvProtectedListingEvidenceKeyMaterialToInfrastructure(loaded.value);
    expect(released.ok).toBe(true);
    if (released.ok) {
      released.value.keyMaterial.fill(0);
    }
  });

  it('rejects missing, malformed, wrong-size, all-zero, and endpoint-shaped aliases', () => {
    const missing = loadOsvProtectedListingEvidenceKeyProvisioningFrom({});
    expect(missing.ok).toBe(false);
    if (!missing.ok) {
      expect(missing.code).toBe('key_unavailable');
    }
    const alias = 'osv.listing.evidence.k1';
    expect(
      loadOsvProtectedListingEvidenceKeyProvisioningFrom({
        [INTELLIGENCE_OSV_LISTING_EVIDENCE_KEY_MATERIAL_NAME]: 'aa',
        [INTELLIGENCE_OSV_LISTING_EVIDENCE_KEY_ALIAS_NAME]: alias,
        [INTELLIGENCE_OSV_LISTING_EVIDENCE_KEY_STATE_NAME]: 'current',
      }).ok,
    ).toBe(false);
    expect(
      loadOsvProtectedListingEvidenceKeyProvisioningFrom({
        [INTELLIGENCE_OSV_LISTING_EVIDENCE_KEY_MATERIAL_NAME]: `${randomHexKey()}aa`,
        [INTELLIGENCE_OSV_LISTING_EVIDENCE_KEY_ALIAS_NAME]: alias,
        [INTELLIGENCE_OSV_LISTING_EVIDENCE_KEY_STATE_NAME]: 'current',
      }).ok,
    ).toBe(false);
    expect(
      loadOsvProtectedListingEvidenceKeyProvisioningFrom({
        [INTELLIGENCE_OSV_LISTING_EVIDENCE_KEY_MATERIAL_NAME]: '0'.repeat(64),
        [INTELLIGENCE_OSV_LISTING_EVIDENCE_KEY_ALIAS_NAME]: alias,
        [INTELLIGENCE_OSV_LISTING_EVIDENCE_KEY_STATE_NAME]: 'current',
      }).ok,
    ).toBe(false);
    expect(
      loadOsvProtectedListingEvidenceKeyProvisioningFrom({
        [INTELLIGENCE_OSV_LISTING_EVIDENCE_KEY_MATERIAL_NAME]: 'A'.repeat(64),
        [INTELLIGENCE_OSV_LISTING_EVIDENCE_KEY_ALIAS_NAME]: alias,
        [INTELLIGENCE_OSV_LISTING_EVIDENCE_KEY_STATE_NAME]: 'current',
      }).ok,
    ).toBe(false);
    expect(
      loadOsvProtectedListingEvidenceKeyProvisioningFrom({
        [INTELLIGENCE_OSV_LISTING_EVIDENCE_KEY_MATERIAL_NAME]: randomHexKey(),
        [INTELLIGENCE_OSV_LISTING_EVIDENCE_KEY_ALIAS_NAME]: 'https://kms.example',
        [INTELLIGENCE_OSV_LISTING_EVIDENCE_KEY_STATE_NAME]: 'current',
      }).ok,
    ).toBe(false);
    expect(
      loadOsvProtectedListingEvidenceKeyProvisioningFrom({
        [INTELLIGENCE_OSV_LISTING_EVIDENCE_KEY_MATERIAL_NAME]: randomHexKey(),
        [INTELLIGENCE_OSV_LISTING_EVIDENCE_KEY_ALIAS_NAME]: alias,
        [INTELLIGENCE_OSV_LISTING_EVIDENCE_KEY_STATE_NAME]: 'current_please',
      }).ok,
    ).toBe(false);
  });

  it('is not imported by loadServerConfig or intelligence configuration', () => {
    const server = readFileSync(join(here, 'server.ts'), 'utf8');
    const intelligence = readFileSync(join(here, 'intelligence.ts'), 'utf8');
    expect(server).not.toContain('INTELLIGENCE_OSV_LISTING_EVIDENCE');
    expect(intelligence).not.toContain('INTELLIGENCE_OSV_LISTING_EVIDENCE');
    expect(intelligence).toContain('INTELLIGENCE_OSV_ENABLED must be false');
    const publicIndex = readFileSync(join(here, 'index.ts'), 'utf8');
    expect(publicIndex).not.toContain(
      'releaseOsvProtectedListingEvidenceKeyMaterialToInfrastructure',
    );
  });
});
