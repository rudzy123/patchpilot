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

describe('OSV protected listing-observation evidence adapter source boundary', () => {
  it('exports the Batch 3D-A factory and does not export the ForClient helper', () => {
    expect(existsSync(path.join(srcDir, 'osv-listing-observation-evidence-persistence.ts'))).toBe(
      true,
    );
    expect('createOsvListingObservationEvidencePersistence' in databasePublic).toBe(true);
    expect('createOsvListingObservationEvidencePersistenceForClient' in databasePublic).toBe(false);
    expect('createOsvProtectedListingEvidenceKeyProvider' in databasePublic).toBe(false);
    expect('createCipheriv' in databasePublic).toBe(false);
    expect('createDecipheriv' in databasePublic).toBe(false);
    expect(existsSync(path.join(srcDir, 'osv-listing-observation-evidence-encryption.ts'))).toBe(
      false,
    );
  });

  it('keeps adapter sources free of scheduler, provider, and Finding coupling', () => {
    const productionFiles = walkTs(srcDir).filter((filePath) => {
      const name = path.basename(filePath);
      return name.startsWith('osv-listing-observation-evidence') && !name.includes('.test.');
    });
    expect(productionFiles.length).toBeGreaterThan(0);
    for (const filePath of productionFiles) {
      const source = readFileSync(filePath, 'utf8');
      expect(source, filePath).not.toMatch(
        /from 'ioredis'|from 'bullmq'|from '@aws-sdk|from 'fastify'|from 'next'|from 'node:https'|from 'node:http'|storage\.googleapis\.com|osv\.dev|setTimeout\(|executeRetry|createFinding|dns\.lookup|process\.env/,
      );
    }
  });

  it('does not register protected evidence in production composition', () => {
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
      expect(source, relative).not.toContain('createOsvListingObservationEvidencePersistence');
      expect(source, relative).not.toContain('osv-listing-evidence-envelope-persistence');
      expect(source, relative).not.toContain('storage.googleapis.com');
      expect(source, relative).not.toContain('osv.dev');
    }
    const repositories = readFileSync(path.join(srcDir, 'repositories.ts'), 'utf8');
    expect(repositories).not.toContain('osvListingObservationEvidence');
    expect(repositories).not.toContain('protectedIdentityEnvelope');
    expect(repositories).not.toContain('opaqueKeyAlias');
    const productionFiles = walkTs(path.join(workspaceRoot, 'apps')).filter((filePath) => {
      const name = path.basename(filePath);
      return !name.includes('.test.') && !name.includes('.spec.');
    });
    for (const filePath of productionFiles) {
      const source = readFileSync(filePath, 'utf8');
      expect(source, filePath).not.toContain('createOsvListingObservationEvidencePersistence');
    }
  });
});
