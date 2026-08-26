import { describe, expect, it } from 'vitest';

import { startTelemetry } from './index.js';

describe('telemetry lifecycle', () => {
  it('starts as a no-op when disabled', async () => {
    const handle = await startTelemetry({
      serviceName: 'test',
      enabled: false,
    });
    await expect(handle.shutdown()).resolves.toBeUndefined();
  });
});
