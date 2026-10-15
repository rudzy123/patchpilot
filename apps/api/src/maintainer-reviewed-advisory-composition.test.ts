import { readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');

function source(relative: string): string {
  return readFileSync(path.join(repoRoot, relative), 'utf8');
}

function walk(directory: string, files: string[] = []): string[] {
  for (const entry of readdirSync(directory)) {
    if (entry === 'node_modules' || entry === 'dist' || entry === '.next') {
      continue;
    }
    const fullPath = path.join(directory, entry);
    if (statSync(fullPath).isDirectory()) {
      walk(fullPath, files);
    } else if (/\.(ts|tsx|mjs)$/.test(entry) && !/\.test\.(ts|tsx)$/.test(entry)) {
      files.push(fullPath);
    }
  }
  return files;
}

describe('maintainer-reviewed advisory API composition', () => {
  it('constructs both services only from API startup', () => {
    const server = source('apps/api/src/server.ts');
    const app = source('apps/api/src/app.ts');
    const runtime = source('apps/api/src/maintainer-reviewed-advisory-runtime.ts');
    const routes = source('apps/api/src/maintainer-reviewed-advisory-routes.ts');
    const http = source('apps/api/src/maintainer-reviewed-advisory-http.ts');
    expect(server).toContain('composeMaintainerReviewedAdvisoryRuntime');
    expect(app).toContain('registerMaintainerReviewedAdvisoryRoutes');
    expect(app).not.toContain('composeMaintainerReviewedAdvisoryRuntime');
    expect(runtime).toContain('createMaintainerReviewedAdvisoryMutationApplication');
    expect(routes).not.toContain('@patchpilot/database');
    expect(routes).not.toContain('@prisma/client');
    expect(routes).not.toContain('vulnerability-intelligence');
    expect(http).not.toContain('@patchpilot/database');
    expect(http).not.toContain('vulnerability-intelligence');
    for (const text of [server, app, runtime, routes, http]) {
      expect(text).not.toContain(['sealMaintainerReviewedAdvisoryApproval', 'Capability'].join(''));
      expect(text).not.toContain(['createReviewer', 'CapabilityIssuer'].join(''));
      expect(text).not.toContain('createMaintainerReviewedAdvisorySubmissionPersistence');
      expect(text).not.toContain('createMaintainerReviewedAdvisoryApprovalApplicationPersistence');
      expect(text).not.toContain('bullmq');
      expect(text).not.toContain('osv.dev');
    }

    const allowedCreate = new Set([
      path.join(
        repoRoot,
        'packages/database/src/maintainer-reviewed-advisory-mutation-application.ts',
      ),
      path.join(repoRoot, 'apps/api/src/maintainer-reviewed-advisory-runtime.ts'),
    ]);
    const roots = ['apps', 'packages/database/src', 'packages/auth/src'].map((root) =>
      path.join(repoRoot, root),
    );
    const createOffenders: string[] = [];
    const composeOffenders: string[] = [];
    for (const root of roots) {
      for (const filePath of walk(root)) {
        const text = readFileSync(filePath, 'utf8');
        if (
          text.includes('createMaintainerReviewedAdvisoryMutationApplication') &&
          !allowedCreate.has(filePath)
        ) {
          createOffenders.push(path.relative(repoRoot, filePath));
        }
        if (
          text.includes('composeMaintainerReviewedAdvisoryRuntime') &&
          !filePath.endsWith(`${path.sep}server.ts`) &&
          !filePath.endsWith(`${path.sep}maintainer-reviewed-advisory-runtime.ts`)
        ) {
          composeOffenders.push(path.relative(repoRoot, filePath));
        }
      }
    }
    expect(createOffenders).toEqual([]);
    expect(composeOffenders).toEqual([]);

    for (const relative of [
      'apps/web/app/layout.tsx',
      'apps/worker/src/main.ts',
      'apps/worker/src/queue-job-router.ts',
      'apps/worker/src/intelligence-scheduler.ts',
      'apps/worker/src/bullmq-outbox-publisher.ts',
      'packages/database/src/seed/run.ts',
      'packages/database/src/seed/development.ts',
      'packages/database/src/index.ts',
      `packages/database/src/${['instance', 'advisory', 'authority', 'command', 'main'].join('-')}.ts`,
      'packages/auth/src/permissions.ts',
    ]) {
      const text = source(relative);
      expect(text, relative).not.toContain('composeMaintainerReviewedAdvisoryRuntime');
      expect(text, relative).not.toContain('createMaintainerReviewedAdvisoryMutationApplication');
      expect(text, relative).not.toContain('registerMaintainerReviewedAdvisoryRoutes');
      expect(text, relative).not.toContain('/intelligence/maintainer-reviewed-advisories');
    }
  });
});
