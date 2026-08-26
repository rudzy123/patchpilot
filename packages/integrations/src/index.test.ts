import { describe, expect, it } from 'vitest';

import { createEmptyJobRegistry, deferredIntegrationNotes } from './index.js';

describe('integration ports', () => {
  it('exposes an empty job registry with no product handlers', () => {
    expect(createEmptyJobRegistry()).toEqual([]);
  });

  it('documents deferred MinIO adapter and tenant keys', () => {
    expect(deferredIntegrationNotes.minioAdapter).toContain('deferred');
  });
});
