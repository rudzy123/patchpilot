import { describe, expect, it } from 'vitest';

import { packageBoundary } from './index.js';

describe('@patchpilot/sbom', () => {
  it('exports a package boundary without product types', () => {
    expect(packageBoundary).toBe('@patchpilot/sbom');
  });
});
