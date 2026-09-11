/**
 * Session 13 Batch 2F worker-side preflight rehearsal.
 * Confirms production exclusion and local MinIO HeadBucket readiness.
 * PostgreSQL preflight composition lives in the database package
 * ephemeral rehearsal. No provider DNS, HTTPS, lease acquisition, timers,
 * activation, matching, Finding writes, or persistent-database mutation.
 */

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { loadServerConfigFrom } from '@patchpilot/config';
import { createS3OsvAdvisoryObjectStorage } from '@patchpilot/integrations';
import { createFoundationTestEnv } from '@patchpilot/test-utils';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

const workspaceRoot = join(dirname(fileURLToPath(import.meta.url)), '../../..');

describe('session 13 Batch 2F worker preflight rehearsal', { timeout: 60_000 }, () => {
  const config = loadServerConfigFrom(createFoundationTestEnv());
  let storage: ReturnType<typeof createS3OsvAdvisoryObjectStorage> | undefined;

  beforeAll(async () => {
    storage = createS3OsvAdvisoryObjectStorage({
      endpoint: config.objectStorage.endpoint,
      region: config.objectStorage.region,
      accessKey: config.objectStorage.accessKey,
      secretKey: config.objectStorage.secretKey,
      bucket: config.objectStorage.bucket,
      useSsl: config.objectStorage.useSsl,
      connectionTimeoutMs: config.objectStorage.connectionTimeoutMs,
      operationTimeoutMs: config.intelligence.objectStorageTimeoutMs,
      deploymentEnvironment: config.deploymentEnvironment,
      allowDevelopmentAdapters: config.allowDevelopmentAdapters,
    });
    const initialized = await storage.initializeDevelopmentBucket({
      explicitlyAllowed: true,
      bucket: config.objectStorage.bucket,
    });
    expect(initialized.ok).toBe(true);
  });

  afterAll(() => {
    storage?.destroy();
  });

  it('does not register preflight in worker production sources', () => {
    const production = [
      'main.ts',
      'app.ts',
      'intelligence-composition.ts',
      'intelligence-runtime.ts',
      'intelligence-scheduler.ts',
      'intelligence-sync-processor.ts',
      'queue-job-router.ts',
    ];
    for (const relative of production) {
      const source = readFileSync(join(dirname(fileURLToPath(import.meta.url)), relative), 'utf8');
      expect(source, relative).not.toContain('createOsvCanaryPreflightService');
      expect(source, relative).not.toContain('createOsvCanaryPreflightReadiness');
      expect(source, relative).not.toContain('createOsvGcsListingHttpsAdapter');
    }
    expect(readFileSync(join(workspaceRoot, 'AGENTS.md'), 'utf8')).toContain('Session 13 Batch 2F');
  });

  it('checks local object storage with HeadBucket only', async () => {
    expect(storage).toBeDefined();
    const inspected = await storage?.inspectBucketReadiness();
    expect(inspected?.ready).toBe(true);
    expect(inspected?.mutated).toBe(false);
  });
});
