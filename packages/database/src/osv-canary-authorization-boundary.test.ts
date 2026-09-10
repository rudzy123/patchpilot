import { existsSync, readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import * as databasePublic from './index.js';

const srcDir = path.dirname(fileURLToPath(import.meta.url));
const packageRoot = path.join(srcDir, '..');
const workspaceRoot = path.join(packageRoot, '..', '..');

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

describe('OSV canary authorization schema source boundary', () => {
  it('exports the Batch 2C authorization factory and does not export execution helpers', () => {
    expect(existsSync(path.join(srcDir, 'osv-canary-authorization-persistence.ts'))).toBe(true);
    expect('createOsvCanaryAuthorizationPersistence' in databasePublic).toBe(true);
    expect('createOsvCanaryAuthorizationPersistenceForClient' in databasePublic).toBe(false);
    expect('issueOsvCanaryAuthorization' in databasePublic).toBe(false);
    expect('consumeOsvCanaryAuthorization' in databasePublic).toBe(false);
    expect('revokeOsvCanaryAuthorization' in databasePublic).toBe(false);
  });

  it('keeps Batch 2C database sources free of scheduler, provider, and Finding coupling', () => {
    const productionFiles = walkTs(srcDir).filter((filePath) => {
      const name = path.basename(filePath);
      return name.startsWith('osv-canary-authorization') && !name.includes('.test.');
    });
    expect(productionFiles.length).toBeGreaterThan(0);
    for (const filePath of productionFiles) {
      const source = readFileSync(filePath, 'utf8');
      expect(source, filePath).not.toMatch(
        /from 'ioredis'|from 'bullmq'|from '@aws-sdk|from 'fastify'|from 'next'|from 'node:https'|storage\.googleapis\.com|osv\.dev|setTimeout\(|executeRetry|createFinding/,
      );
    }
  });

  it('keeps canary models free of tenant and Finding columns', () => {
    const schema = readFileSync(path.join(packageRoot, 'prisma/schema.prisma'), 'utf8');
    const start = schema.indexOf('model OsvCanaryInstanceOperatorIdentity');
    const end = schema.indexOf('\nmodel OsvListingObservationEvidenceSet {');
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
    expect(block).not.toContain('holderToken');
    expect(block).not.toContain('pageToken');
    expect(block).not.toContain('@db.Json');
    expect(block).not.toContain('password');
    expect(block).toContain('operatorIdentityId');
    expect(block).toContain('listingAuthorizationId');
  });

  it('does not register canary authorization in production composition', () => {
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
      expect(source, relative).not.toContain('OsvCanaryAuthorization');
      expect(source, relative).not.toContain('OsvCanaryInstanceOperatorIdentity');
      expect(source, relative).not.toContain('osv_canary_authorization');
      expect(source, relative).not.toContain('storage.googleapis.com');
      expect(source, relative).not.toContain('osv.dev');
    }
  });
});
