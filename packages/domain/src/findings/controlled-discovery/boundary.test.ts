/**
 * Discovery stays off the creation issuer and off non-API composition.
 */

import { readFileSync, readdirSync, statSync } from 'node:fs';
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

describe('controlled finding discovery boundary', () => {
  it('keeps the factory off the package barrel and out of creation', () => {
    expect(domainPublic.FINDING_DISCOVER_CONTROLLED_PERMISSION).toBe('finding:discover_controlled');
    expect(Object.keys(domainPublic)).not.toContain('createControlledFindingDiscoveryApplication');
    expect(Object.keys(domainPublic)).not.toContain('issueFindingCreationAuthorization');
    const barrel = readFileSync(path.join(repoRoot, 'packages/domain/src/index.ts'), 'utf8');
    expect(barrel).not.toContain('createControlledFindingDiscoveryApplication');
    expect(barrel).not.toContain('findings/controlled-discovery/service');
    expect(barrel).not.toContain('findings/controlled-discovery/page');
    const sources = readdirSync(here).filter(
      (name) => name.endsWith('.ts') && !name.endsWith('.test.ts'),
    );
    for (const name of sources) {
      const source = readFileSync(path.join(here, name), 'utf8');
      expect(source, name).not.toContain('issueFindingCreationAuthorization');
      expect(source, name).not.toContain('createControlledFindingCreationApplication');
      expect(source, name).not.toContain('openFindingCreationCommand');
      expect(source, name).not.toContain('@prisma/client');
      expect(source, name).not.toContain('process.env');
    }
  });

  it('is composed only by the API discovery runtime', () => {
    const allowed = new Map<string, readonly string[]>([
      [
        'createControlledFindingDiscoveryApplication',
        [
          'packages/domain/src/findings/controlled-discovery/service.ts',
          'packages/domain/src/findings/controlled-discovery/index.ts',
          'apps/api/src/finding-discovery-runtime.ts',
        ],
      ],
      [
        'createControlledFindingDiscoveryPersistence',
        [
          'packages/database/src/controlled-finding-discovery-persistence.ts',
          'apps/api/src/finding-discovery-runtime.ts',
        ],
      ],
      [
        'composeControlledFindingDiscoveryRuntime',
        ['apps/api/src/finding-discovery-runtime.ts', 'apps/api/src/server.ts'],
      ],
    ]);
    const offenders: string[] = [];
    for (const root of ['apps', 'packages']) {
      for (const filePath of walk(path.join(repoRoot, root))) {
        if (!/\.(ts|tsx|mjs)$/.test(filePath) || /\.test\.(ts|tsx|mjs)$/.test(filePath)) {
          continue;
        }
        const relative = path.relative(repoRoot, filePath);
        const source = readFileSync(filePath, 'utf8');
        for (const [needle, files] of allowed) {
          if (source.includes(needle) && !files.includes(relative)) {
            offenders.push(`${relative}:${needle}`);
          }
        }
        if (
          source.includes('issueFindingCreationAuthorization') &&
          relative.startsWith('packages/domain/src/findings/controlled-discovery/')
        ) {
          offenders.push(relative);
        }
      }
    }
    expect(offenders).toEqual([]);
    const runtime = readFileSync(
      path.join(repoRoot, 'apps/api/src/finding-discovery-runtime.ts'),
      'utf8',
    );
    expect(runtime).not.toContain('issueFindingCreationAuthorization');
    expect(runtime).not.toContain('createControlledFindingCreationApplication');
    expect(runtime).not.toContain('createControlledFindingCreationPersistence');
    expect(runtime).not.toContain('bullmq');
  });
});
