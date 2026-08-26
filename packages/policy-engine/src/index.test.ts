import { describe, expect, it } from 'vitest';

import { packageBoundary } from './index.js';

describe('@patchpilot/policy-engine', () => {
  it('exports a package boundary without product types', () => {
    expect(packageBoundary).toBe('@patchpilot/policy-engine');
  });
});
