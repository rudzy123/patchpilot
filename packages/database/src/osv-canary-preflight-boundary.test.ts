/**
 * Session 13 Batch 2F database source-boundary tests.
 */

import { existsSync, readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import * as databasePublic from './index.js';

const srcDir = path.dirname(fileURLToPath(import.meta.url));
const workspaceRoot = path.join(srcDir, '..', '..', '..');

describe('OSV canary preflight readiness source boundary', () => {
  it('exports the read-only preflight factory and does not export mutation helpers', () => {
    expect(existsSync(path.join(srcDir, 'osv-canary-preflight-readiness.ts'))).toBe(true);
    expect('createOsvCanaryPreflightReadiness' in databasePublic).toBe(true);
    expect('acquireOsvCanaryPreflightLease' in databasePublic).toBe(false);
    expect('startOsvCanaryPreflightHeartbeat' in databasePublic).toBe(false);
  });

  it('keeps preflight readiness free of provider, queue, and Finding mutation', () => {
    const source = readFileSync(path.join(srcDir, 'osv-canary-preflight-readiness.ts'), 'utf8');
    expect(source).not.toMatch(
      /from 'ioredis'|from 'bullmq'|from '@aws-sdk'|from 'fastify'|from 'next'|from 'node:https'|storage\.googleapis\.com|osv\.dev|leases\.acquire|leases\.heartbeat|leases\.release|createFinding|finding\.recalculate|activateReadyGeneration/,
    );
    expect(source).toContain("Object.hasOwn(raw, 'holder_token_digest')");
    expect(source).not.toMatch(
      /SELECT[\s\S]*holder_token_digest[\s\S]*FROM "osv_runtime_lease_projection"/,
    );
    expect(source).toContain('RepeatableRead');
    expect(source).toContain('globalFindingAbsenceNotRequired');
    expect(source).toContain('$transaction');
  });

  it('does not register preflight in production composition', () => {
    const production = [
      'apps/worker/src/main.ts',
      'apps/worker/src/app.ts',
      'apps/worker/src/intelligence-composition.ts',
      'apps/worker/src/intelligence-runtime.ts',
      'apps/worker/src/intelligence-scheduler.ts',
      'apps/worker/src/intelligence-sync-processor.ts',
      'apps/worker/src/queue-job-router.ts',
      'apps/api/src/app.ts',
      'apps/api/src/server.ts',
      'apps/api/src/intelligence-runtime.ts',
      'apps/api/src/intelligence-routes.ts',
      'packages/database/src/seed/development.ts',
    ] as const;
    for (const relative of production) {
      const source = readFileSync(path.join(workspaceRoot, relative), 'utf8');
      expect(source, relative).not.toContain('createOsvCanaryPreflightReadiness');
      expect(source, relative).not.toContain('createOsvCanaryPreflightService');
    }
    expect(readdirSync(srcDir).some((name) => name.includes('preflight'))).toBe(true);
  });
});
