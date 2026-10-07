/**
 * Public surface and production exclusion for Finding inspection.
 */

import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import * as domainPublic from '../../index.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '../../../../..');

const SKIPPED = new Set([
  'node_modules',
  'dist',
  '.next',
  'coverage',
  'generated',
  '.git',
  '.turbo',
]);

function walk(directory: string, files: string[] = []): string[] {
  for (const entry of readdirSync(directory)) {
    if (SKIPPED.has(entry)) {
      continue;
    }
    const fullPath = path.join(directory, entry);
    if (statSync(fullPath).isDirectory()) {
      walk(fullPath, files);
    } else {
      files.push(fullPath);
    }
  }
  return files;
}

function isProductionSource(filePath: string): boolean {
  const name = path.basename(filePath);
  if (/-fixture\.ts$/.test(name) || /-harness\.ts$/.test(name) || /-test-seam\.ts$/.test(name)) {
    return false;
  }
  return /\.(ts|tsx|mjs)$/.test(filePath) && !/\.test\.(ts|tsx|mjs)$/.test(filePath);
}

describe('controlled finding inspection public surface', () => {
  it('exports the inspection contract and withholds writer and seal details', () => {
    expect(domainPublic.openFindingInspection).toEqual(expect.any(Function));
    expect(domainPublic.FINDING_INSPECTION_PRODUCTION_REGISTRATION).toBe('absent');
    const names = Object.keys(domainPublic);
    expect(names).not.toContain('createControlledFindingInspectionPersistence');
    expect(names).not.toContain('projectFindingInspection');
    expect(names).not.toContain('issueFindingCreationAuthorization');
    expect(
      names.filter((name) => /replayFingerprint|reviewerIdentity|PrismaClient|sql/i.test(name)),
    ).toEqual([]);
    const source = readFileSync(path.join(here, 'index.ts'), 'utf8');
    expect(source).not.toContain('issueFindingCreationAuthorization');
    expect(source).not.toContain('@prisma/client');
    expect(source).not.toContain('createControlledFindingInspectionPersistence');
  });

  it('keeps the contract sources free of frameworks and writers', () => {
    const files = readdirSync(here).filter(
      (name) => name.endsWith('.ts') && !name.endsWith('.test.ts'),
    );
    expect(files.length).toBeGreaterThan(0);
    for (const name of files) {
      const source = readFileSync(path.join(here, name), 'utf8');
      expect(source, name).not.toMatch(
        /@prisma\/client|from 'fastify'|from 'next'|process\.env|\bfetch\s*\(|createFinding/,
      );
      expect(source, name).not.toContain('.update(');
      expect(source, name).not.toContain('.delete(');
    }
  });
});

describe('controlled finding inspection production exclusion', () => {
  it('is not constructed by API, web, worker, or seed sources except the API runtime', () => {
    const roots = ['apps/api', 'apps/web', 'apps/worker', 'packages/database/src/seed'].map(
      (root) => path.join(repoRoot, root),
    );
    const persistence = 'createControlledFindingInspectionPersistence';
    const allowedPersistence = new Set(['apps/api/src/finding-runtime.ts']);
    const forbidden = ['openFindingInspection', 'findings/controlled-inspection'];
    const offenders: string[] = [];
    for (const root of roots) {
      for (const filePath of walk(root).filter(isProductionSource)) {
        const relative = path.relative(repoRoot, filePath);
        const source = readFileSync(filePath, 'utf8');
        if (forbidden.some((needle) => source.includes(needle))) {
          offenders.push(relative);
        }
        if (source.includes(persistence) && !allowedPersistence.has(relative)) {
          offenders.push(relative);
        }
      }
    }
    expect(offenders).toEqual([]);
    const runtime = readFileSync(path.join(repoRoot, 'apps/api/src/finding-runtime.ts'), 'utf8');
    expect(runtime).toContain(persistence);
    expect(runtime).not.toContain('openFindingInspection');
  });

  it('is not registered on the repository, outbox, queue, or startup roots', () => {
    const files = [
      'packages/database/src/index.ts',
      'packages/database/src/repositories.ts',
      'packages/database/src/outbox-relay-persistence.ts',
      'apps/api/src/server.ts',
      'apps/worker/src/main.ts',
      'apps/worker/src/queue-job-router.ts',
      'apps/worker/src/bullmq-outbox-publisher.ts',
      'apps/worker/src/intelligence-scheduler.ts',
      'apps/web/app/layout.tsx',
    ];
    const forbidden = [
      'openFindingInspection',
      'createControlledFindingInspectionPersistence',
      'findings/controlled-inspection',
    ];
    for (const relative of files) {
      const source = readFileSync(path.join(repoRoot, relative), 'utf8');
      for (const needle of forbidden) {
        expect(source, `${relative} ${needle}`).not.toContain(needle);
      }
    }
  });
});
