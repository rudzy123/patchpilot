import { loadServerConfigFrom } from '@patchpilot/config';
import { createFoundationTestEnv } from '@patchpilot/test-utils';
import { describe, expect, it } from 'vitest';

describe('minio integration', () => {
  it('reports live against local Compose MinIO without embedding credentials in the health URL', async () => {
    const config = loadServerConfigFrom(createFoundationTestEnv());
    const healthUrl = `${config.objectStorage.endpoint}/minio/health/live`;
    expect(healthUrl).not.toContain(config.objectStorage.accessKey);
    expect(healthUrl).not.toContain(config.objectStorage.secretKey);

    const controller = new AbortController();
    const timer = setTimeout(() => {
      controller.abort();
    }, config.readinessTimeoutMs);
    try {
      const response = await fetch(healthUrl, { signal: controller.signal });
      expect(response.ok).toBe(true);
    } finally {
      clearTimeout(timer);
    }
  });
});
