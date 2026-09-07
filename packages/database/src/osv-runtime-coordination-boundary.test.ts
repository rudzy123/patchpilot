import { existsSync, readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import * as databasePublic from './index.js';

const srcDir = path.dirname(fileURLToPath(import.meta.url));
const packageRoot = path.join(srcDir, '..');
const workspaceRoot = path.join(packageRoot, '..', '..');

const BANNED_ADAPTER_EXPORTS = [
  'createOsvRuntimeLeasePersistence',
  'createOsvRuntimeRetryPersistence',
  'acquireOsvRuntimeLease',
  'heartbeatOsvRuntimeLease',
  'releaseOsvRuntimeLease',
  'takeoverOsvRuntimeLease',
  'claimRetry',
  'executeRetry',
] as const;

function walkTs(directory: string, files: string[] = []): string[] {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const fullPath = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      walkTs(fullPath, files);
      continue;
    }
    if (entry.name.endsWith('.ts')) {
      files.push(fullPath);
    }
  }
  return files;
}

describe('OSV runtime coordination schema source boundary', () => {
  it('exports the Batch 7 coordination factory and does not export retry execution', () => {
    expect(existsSync(path.join(srcDir, 'osv-runtime-coordination-persistence.ts'))).toBe(true);
    expect(existsSync(path.join(srcDir, 'osv-runtime-lease-persistence.ts'))).toBe(false);
    expect(existsSync(path.join(srcDir, 'osv-runtime-retry-persistence.ts'))).toBe(false);
    expect('createOsvRuntimeCoordinationPersistence' in databasePublic).toBe(true);
    expect('createOsvRuntimeCoordinationPersistenceForClient' in databasePublic).toBe(false);
    for (const name of BANNED_ADAPTER_EXPORTS) {
      expect(name in databasePublic, name).toBe(false);
    }
    expect('createOsvAcquisitionPersistence' in databasePublic).toBe(true);
  });

  it('keeps Batch 7 database sources free of scheduler, provider, and Finding coupling', () => {
    const productionFiles = walkTs(srcDir).filter((filePath) => {
      const name = path.basename(filePath);
      return name.startsWith('osv-runtime-coordination') && !name.includes('.test.');
    });
    expect(productionFiles.length).toBeGreaterThan(0);
    for (const filePath of productionFiles) {
      const source = readFileSync(filePath, 'utf8');
      expect(source, filePath).not.toMatch(
        /from 'ioredis'|from 'bullmq'|from '@aws-sdk|from 'fastify'|from 'next'|from 'node:https'|storage\.googleapis\.com|osv\.dev|setTimeout\(|executeRetry|createFinding/,
      );
    }
    expect(
      existsSync(path.join(srcDir, 'osv-runtime-coordination-constraints.integration.test.ts')),
    ).toBe(true);
  });

  it('keeps runtime coordination models free of tenant and Finding columns', () => {
    const schema = readFileSync(path.join(packageRoot, 'prisma/schema.prisma'), 'utf8');
    const start = schema.indexOf('model OsvRuntimeSynchronizationRequest');
    const end = schema.indexOf('\nmodel Integration {');
    expect(start).toBeGreaterThan(0);
    expect(end).toBeGreaterThan(start);
    const block = schema.slice(start, end);
    expect(block).not.toContain('organizationId');
    expect(block).not.toContain('tenantId');
    expect(block).not.toContain('userId');
    expect(block).not.toContain('assetId');
    expect(block).not.toContain('componentId');
    expect(block).not.toContain('findingId');
    expect(block).not.toContain('findingObservationId');
    expect(block).not.toContain('evidenceId');
    expect(block).not.toContain('riskCalculationId');
    expect(block).not.toContain('holderToken ');
    expect(block).not.toContain('pageToken');
    expect(block).not.toContain('@db.Json');
    expect(block).toContain('holderTokenDigest');
    expect(block).toContain('rowRevision');
    expect(block).toContain('fencingToken');
    expect(block).toContain('BigInt');
  });

  it('does not register the OSV job in production composition', () => {
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
    ] as const;
    for (const relative of production) {
      const source = readFileSync(path.join(workspaceRoot, relative), 'utf8');
      expect(source, relative).not.toContain('intelligence.osv.sync');
      expect(source, relative).not.toContain('OsvRuntimeSynchronization');
      expect(source, relative).not.toContain('osv_runtime_lease');
    }
  });
});
