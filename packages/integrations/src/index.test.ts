import { describe, expect, it } from 'vitest';

import { createEmptyJobRegistry, deferredIntegrationNotes } from './index.js';

describe('integration ports', () => {
  it('exposes an empty job registry with no product handlers', () => {
    expect(createEmptyJobRegistry()).toEqual([]);
  });

  it('documents the streaming S3-compatible adapter', () => {
    expect(deferredIntegrationNotes.minioAdapter).toBe('s3-compatible-streaming-adapter');
    expect(deferredIntegrationNotes.s3Client).toBe('wired-static-credentials');
    expect(deferredIntegrationNotes.objectKeyConvention).toBe('org-asset-sha256');
    expect(deferredIntegrationNotes.intelligenceObjectKeyConvention).toBe(
      'intelligence-cisa-kev-sha256',
    );
    expect(deferredIntegrationNotes.osvObjectKeyConvention).toBe('intelligence-osv-sha256');
  });
});
