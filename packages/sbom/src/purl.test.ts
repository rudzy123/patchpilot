import { describe, expect, it } from 'vitest';

import { parsePackageUrl } from './purl.js';

describe('package URL parsing', () => {
  it('parses a synthetic PatchPilot PURL', () => {
    const parsed = parsePackageUrl('pkg:npm/%40patchpilot/sbom@0.0.0');
    expect(parsed.type).toBe('npm');
    expect(parsed.namespace).toBe('@patchpilot');
    expect(parsed.name).toBe('sbom');
    expect(parsed.version).toBe('0.0.0');
  });
});
