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

describe('product match candidate API composition', () => {
  it('constructs discovery only from the API runtime and wires it at startup', () => {
    const server = source('apps/api/src/server.ts');
    const app = source('apps/api/src/app.ts');
    const runtime = source('apps/api/src/product-match-candidate-runtime.ts');
    const routes = source('apps/api/src/product-match-candidate-routes.ts');
    expect(server).toContain('composeProductMatchCandidateRuntime');
    expect(server).not.toContain('createProductMatchCandidateDiscovery');
    expect(server).not.toContain('deliberate-product-match-evaluation');
    expect(app).toContain('registerProductMatchCandidateRoutes');
    expect(app).not.toContain('composeProductMatchCandidateRuntime');
    expect(runtime).toContain('createProductMatchCandidatePersistence');
    expect(runtime).toContain('createProductMatchCandidateDiscovery');
    expect(runtime).not.toContain('createControlledFinding');
    expect(runtime).not.toContain('process.env');
    expect(source('apps/api/src/product-match-candidate-http.ts')).toContain(
      "export const PRODUCT_MATCH_CANDIDATE_ROUTE = '/assets/:assetId/product-match-candidates'",
    );
    expect(routes).toContain('PRODUCT_MATCH_CANDIDATE_ROUTE');
    expect(routes).not.toContain('@patchpilot/database');
    expect(routes).not.toContain('vulnerability-intelligence');
    expect(routes).not.toContain('@prisma/client');

    const composeAllowed = new Set([
      'apps/api/src/server.ts',
      'apps/api/src/product-match-candidate-runtime.ts',
    ]);
    const registerAllowed = new Set([
      'apps/api/src/app.ts',
      'apps/api/src/product-match-candidate-routes.ts',
    ]);
    const composeOffenders: string[] = [];
    const registerOffenders: string[] = [];
    for (const filePath of walk(path.join(repoRoot, 'apps'))) {
      const text = readFileSync(filePath, 'utf8');
      const relative = path.relative(repoRoot, filePath).split(path.sep).join('/');
      if (text.includes('composeProductMatchCandidateRuntime') && !composeAllowed.has(relative)) {
        composeOffenders.push(relative);
      }
      if (text.includes('registerProductMatchCandidateRoutes') && !registerAllowed.has(relative)) {
        registerOffenders.push(relative);
      }
      if (
        text.includes('createProductMatchCandidatePersistence') &&
        relative !== 'apps/api/src/product-match-candidate-runtime.ts'
      ) {
        composeOffenders.push(relative);
      }
    }
    expect(composeOffenders).toEqual([]);
    expect(registerOffenders).toEqual([]);

    for (const relative of [
      'apps/web/app/layout.tsx',
      'apps/worker/src/main.ts',
      'apps/worker/src/app.ts',
      'packages/database/src/seed/development.ts',
    ]) {
      const text = source(relative);
      expect(text, relative).not.toContain('composeProductMatchCandidateRuntime');
      expect(text, relative).not.toContain('createProductMatchCandidateDiscovery');
    }
  });
});
