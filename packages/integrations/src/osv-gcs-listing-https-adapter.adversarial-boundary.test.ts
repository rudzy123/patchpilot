/**
 * Session 12 Batch 2 production-runtime, source-boundary, export, and
 * zero-Finding proofs for the listing-page HTTPS executor.
 */

import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { createOsvGcsListingHttpsAdapter } from './osv-gcs-listing-https-adapter.js';

const here = dirname(fileURLToPath(import.meta.url));
const workspaceRoot = join(here, '..', '..', '..');

const PRODUCTION_COMPOSITION_FILES = [
  'apps/worker/src/main.ts',
  'apps/worker/src/app.ts',
  'apps/worker/src/intelligence-composition.ts',
  'apps/worker/src/intelligence-runtime.ts',
  'apps/worker/src/intelligence-scheduler.ts',
  'apps/worker/src/intelligence-sync-processor.ts',
  'apps/worker/src/queue-job-router.ts',
  'apps/worker/src/sbom-ingest-processor.ts',
  'apps/worker/src/outbox-relay-runtime.ts',
  'apps/api/src/app.ts',
  'apps/api/src/server.ts',
  'apps/api/src/intelligence-runtime.ts',
  'apps/api/src/intelligence-routes.ts',
  'apps/api/src/auth-runtime.ts',
  'packages/database/src/index.ts',
  'packages/config/src/intelligence.ts',
] as const;

function readWorkspace(relativePath: string): string {
  return readFileSync(join(workspaceRoot, relativePath), 'utf8');
}

describe('OSV GCS listing adversarial production exclusion', () => {
  it('does not construct or invoke the listing executor from production roots', () => {
    for (const relative of PRODUCTION_COMPOSITION_FILES) {
      const source = readWorkspace(relative);
      expect(source, relative).not.toContain('createOsvGcsListingHttpsAdapter');
      expect(source, relative).not.toContain('osv-gcs-listing-https-adapter');
      expect(source, relative).not.toContain('createOsvGcsListingHttpsAdapterForTests');
      expect(source, relative).not.toContain('intelligence.osv.sync');
    }
  });

  it('does not export the test factory or HTTPS seam from the package index', () => {
    const index = readFileSync(join(here, 'index.ts'), 'utf8');
    expect(index).toContain('createOsvGcsListingHttpsAdapter');
    expect(index).not.toContain('createOsvGcsListingHttpsAdapterForTests');
    expect(index).not.toContain('OsvGcsListingHttpsTestDependencies');
    const pkg = JSON.parse(readFileSync(join(here, '..', 'package.json'), 'utf8')) as {
      exports: { '.': { import: string } };
    };
    expect(pkg.exports['.']).toEqual({
      types: './dist/index.d.ts',
      import: './dist/index.js',
    });
  });

  it('keeps the production factory free of injectable destination or TLS overrides', () => {
    const adapter = createOsvGcsListingHttpsAdapter();
    expect(typeof adapter.listPage).toBe('function');
    expect(adapter.listPage.length).toBe(1);
    expect(createOsvGcsListingHttpsAdapter.length).toBe(0);
  });
});

describe('OSV GCS listing adversarial source and Finding boundaries', () => {
  it('imports no persistence, retrieval execution, parser worker, or application runtime', () => {
    const source = readFileSync(join(here, 'osv-gcs-listing-https-adapter.ts'), 'utf8');
    const forbidden = [
      '@aws-sdk/client-s3',
      '@patchpilot/database',
      '@prisma/client',
      'osv-generation-bound-retrieval-https',
      'advisory-parser-worker',
      'advisory-parser-host',
      'createOsvDisabledAcquisitionOrchestrator',
      'bullmq',
      'ioredis',
      'fastify',
      'next/server',
      'process.env',
      'eval(',
      'new Function',
      'organizationId',
      'tenantId',
      'assetId',
      'componentId',
      'findingId',
      'finding.recalculate',
      'createFinding',
      'FindingObservation',
      'RiskCalculation',
      'activateReadyGeneration',
    ];
    for (const token of forbidden) {
      expect(source, token).not.toContain(token);
    }
    expect(source).not.toContain('setInterval');
    expect(source).not.toContain('alt=media');
    expect(source).not.toContain('repeated_page_token');
    expect(source).not.toContain('tokenDigestSet');
  });

  it('does not enable OSV or create a completion-report artifact', () => {
    const intelligence = readWorkspace('packages/config/src/intelligence.ts');
    expect(intelligence).toContain('INTELLIGENCE_OSV_ENABLED must be false');
    expect(existsSync(join(workspaceRoot, 'SESSION_12_BATCH_2_COMPLETION.md'))).toBe(false);
    expect(existsSync(join(workspaceRoot, 'R2_COMPLETION_REPORT.md'))).toBe(false);
    const migrationsRoot = join(workspaceRoot, 'packages/database/prisma/migrations');
    const directories = readdirSync(migrationsRoot, { withFileTypes: true })
      .filter((entry) => entry.isDirectory())
      .map((entry) => entry.name);
    expect(directories).toHaveLength(13);
  });
});
