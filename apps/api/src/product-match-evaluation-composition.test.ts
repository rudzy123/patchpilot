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
    if (entry === 'node_modules' || entry === 'dist' || entry === '.next' || entry === 'coverage') {
      continue;
    }
    const fullPath = path.join(directory, entry);
    if (statSync(fullPath).isDirectory()) {
      walk(fullPath, files);
      continue;
    }
    if (!/\.(ts|tsx|mjs)$/.test(entry) || entry.includes('.test.')) {
      continue;
    }
    files.push(fullPath);
  }
  return files;
}

describe('deliberate product match evaluation API composition', () => {
  it('constructs the service only from the API runtime and wires it at startup', () => {
    const server = source('apps/api/src/server.ts');
    const app = source('apps/api/src/app.ts');
    const runtime = source('apps/api/src/product-match-evaluation-runtime.ts');
    const routes = source('apps/api/src/product-match-evaluation-routes.ts');
    const http = source('apps/api/src/product-match-evaluation-http.ts');
    expect(server).toContain('composeProductMatchEvaluationRuntime');
    expect(server).not.toContain('createDeliberateProductMatchEvaluation');
    expect(app).toContain('registerProductMatchEvaluationRoutes');
    expect(app).not.toContain('composeProductMatchEvaluationRuntime');
    expect(runtime).toContain('createDeliberateProductMatchEvaluationPersistence');
    expect(runtime).toContain('createDeliberateProductMatchEvaluation(');
    expect(runtime).not.toContain('evaluateReviewedNpmRange');
    expect(runtime).not.toContain('createProductMatchEvaluationComposition');
    expect(runtime).not.toContain('createProductMatchEvaluationPersistence');
    expect(runtime).not.toContain('createControlledFindingCreation');
    expect(runtime).not.toContain('bullmq');
    expect(runtime).not.toContain('osv.dev');
    expect(runtime).not.toContain('process.env');
    expect(routes).toContain("'/assets/:assetId/product-match-evaluations'");
    expect(routes).not.toContain('@patchpilot/database');
    expect(routes).not.toContain('vulnerability-intelligence');
    expect(routes).not.toContain('@prisma/client');
    expect(routes).not.toContain('createDeliberateProductMatchEvaluation');
    expect(http).not.toContain('@patchpilot/database');
    expect(http).not.toContain('vulnerability-intelligence');
    expect(http).not.toContain('@prisma/client');

    const composeAllowed = new Set([
      'apps/api/src/server.ts',
      'apps/api/src/product-match-evaluation-runtime.ts',
    ]);
    const registerAllowed = new Set([
      'apps/api/src/app.ts',
      'apps/api/src/product-match-evaluation-routes.ts',
    ]);
    const serviceAllowed = new Set(['apps/api/src/product-match-evaluation-runtime.ts']);
    const composeOffenders: string[] = [];
    const registerOffenders: string[] = [];
    const serviceOffenders: string[] = [];
    for (const filePath of walk(path.join(repoRoot, 'apps'))) {
      const text = readFileSync(filePath, 'utf8');
      const relative = path.relative(repoRoot, filePath).split(path.sep).join('/');
      if (text.includes('composeProductMatchEvaluationRuntime') && !composeAllowed.has(relative)) {
        composeOffenders.push(relative);
      }
      if (text.includes('registerProductMatchEvaluationRoutes') && !registerAllowed.has(relative)) {
        registerOffenders.push(relative);
      }
      if (
        /createDeliberateProductMatchEvaluation(?!Persistence)/.test(text) &&
        !serviceAllowed.has(relative)
      ) {
        serviceOffenders.push(relative);
      }
      if (
        text.includes('createDeliberateProductMatchEvaluationPersistence') &&
        !serviceAllowed.has(relative)
      ) {
        serviceOffenders.push(relative);
      }
    }
    expect(composeOffenders).toEqual([]);
    expect(registerOffenders).toEqual([]);
    expect(serviceOffenders).toEqual([]);

    for (const relative of [
      'apps/web/app/layout.tsx',
      'apps/worker/src/main.ts',
      'apps/worker/src/app.ts',
      'apps/worker/src/queue-job-router.ts',
      'apps/worker/src/intelligence-scheduler.ts',
      'packages/database/src/seed/development.ts',
    ]) {
      const text = source(relative);
      expect(text, relative).not.toContain('composeProductMatchEvaluationRuntime');
      expect(text, relative).not.toContain('registerProductMatchEvaluationRoutes');
      expect(text, relative).not.toContain('createDeliberateProductMatchEvaluation');
      expect(text, relative).not.toContain('/product-match-evaluations');
    }
  });
});
