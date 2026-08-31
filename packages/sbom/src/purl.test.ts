import { describe, expect, it } from 'vitest';

import { normalizePackageUrl, parsePackageUrl } from './purl.js';

describe('package URL parsing', () => {
  it('parses a synthetic PatchPilot PURL', () => {
    const parsed = parsePackageUrl('pkg:npm/%40patchpilot/sbom@0.0.0');
    expect(parsed.type).toBe('npm');
    expect(parsed.namespace).toBe('@patchpilot');
    expect(parsed.name).toBe('sbom');
    expect(parsed.version).toBe('0.0.0');
  });

  it('canonicalizes versionless identity without version, qualifiers, or subpath', () => {
    const normalized = normalizePackageUrl('pkg:npm/%40patchpilot/sbom@1.2.3?arch=x64#src');
    expect(normalized.ok).toBe(true);
    if (!normalized.ok) {
      return;
    }
    expect(normalized.value.versionless).toBe('pkg:npm/%40patchpilot/sbom');
    expect(normalized.value.versioned).toBe('pkg:npm/%40patchpilot/sbom@1.2.3');
    expect(normalized.value.namespace).toBe('@patchpilot');
  });
});
