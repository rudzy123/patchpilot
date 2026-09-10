import { existsSync, readFileSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import * as databasePublic from './index.js';

const srcDir = path.dirname(fileURLToPath(import.meta.url));
const packageRoot = path.join(srcDir, '..');
const workspaceRoot = path.join(packageRoot, '..', '..');

const PRODUCTION = [
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
  'packages/database/src/index.ts',
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

describe('OSV protected listing-observation evidence schema source boundary', () => {
  it('does not export a persistence adapter or encryption helper', () => {
    expect(existsSync(path.join(srcDir, 'osv-listing-observation-evidence-persistence.ts'))).toBe(
      false,
    );
    expect(existsSync(path.join(srcDir, 'osv-listing-observation-evidence-encryption.ts'))).toBe(
      false,
    );
    expect('createOsvListingObservationEvidencePersistence' in databasePublic).toBe(false);
    expect('createOsvProtectedListingEvidenceKeyProvider' in databasePublic).toBe(false);
    expect('createCipheriv' in databasePublic).toBe(false);
    expect('createDecipheriv' in databasePublic).toBe(false);
    expect(
      existsSync(
        path.join(srcDir, 'osv-listing-observation-evidence-constraints.integration.test.ts'),
      ),
    ).toBe(true);
  });

  it('keeps schema-only database sources free of encryption execution and provider contact', () => {
    const schema = readFileSync(path.join(packageRoot, 'prisma/schema.prisma'), 'utf8');
    const start = schema.indexOf(
      '/// Session 13 Batch 3D-S protected listing-observation evidence set.',
    );
    const end = schema.indexOf('\nmodel Integration {');
    expect(start).toBeGreaterThan(0);
    expect(end).toBeGreaterThan(start);
    const block = schema.slice(start, end);
    expect(block).toContain('protectedIdentityEnvelope');
    expect(block).toContain('opaqueKeyAlias');
    expect(block).not.toContain('providerObjectKey');
    expect(block).not.toContain('plaintextIdentity');
    expect(block).not.toContain('organizationId');
    expect(block).not.toContain('tenantId');
    expect(block).not.toContain('findingId');
    expect(block).not.toContain('pageToken');
    expect(block).not.toContain('@db.Json');
    expect(block).toContain('Public queries must omit');
    expect(block).toContain('Database access is not decryption authority');
    expect(block).toContain('exactly-one-current');
    expect(block).toContain('successor-only');
    const sql = readFileSync(
      path.join(
        packageRoot,
        'prisma/migrations/20260910120000_osv_listing_observation_evidence_persistence/migration.sql',
      ),
      'utf8',
    );
    expect(sql).not.toMatch(/createCipheriv|createDecipheriv|randomBytes|generateKey/i);
    expect(sql).not.toMatch(/storage\.googleapis\.com|osv\.dev/i);
    expect(sql).toContain('cannot erase under legal hold');
    expect(sql).toContain('exactly one current envelope unless erased');
    expect(sql).toContain('cannot insert a successor-only state');
    expect(sql).toContain('osv_listing_observation_evidence_envelope_current_required');
  });

  it('does not register protected evidence in production composition', () => {
    for (const relative of PRODUCTION) {
      const source = readFileSync(path.join(workspaceRoot, relative), 'utf8');
      expect(source, relative).not.toContain('OsvListingObservationEvidenceSet');
      expect(source, relative).not.toContain('createOsvListingObservationEvidencePersistence');
      expect(source, relative).not.toContain('protectedIdentityEnvelope');
      expect(source, relative).not.toContain('storage.googleapis.com');
    }
    const index = readFileSync(path.join(srcDir, 'index.ts'), 'utf8');
    expect(index).not.toContain('osv-listing-observation-evidence-persistence');
    const repositories = readFileSync(path.join(srcDir, 'repositories.ts'), 'utf8');
    expect(repositories).not.toContain('osvListingObservationEvidence');
    expect(repositories).not.toContain('protectedIdentityEnvelope');
    expect(repositories).not.toContain('opaqueKeyAlias');
    expect(repositories).not.toContain('OsvListingObservationEvidenceSet');
    const productionFiles = walkTs(path.join(workspaceRoot, 'apps')).filter((filePath) => {
      const name = path.basename(filePath);
      return !name.includes('.test.') && !name.includes('.spec.');
    });
    for (const filePath of productionFiles) {
      const source = readFileSync(filePath, 'utf8');
      expect(source, filePath).not.toContain('osv_listing_observation_evidence');
    }
  });
});
