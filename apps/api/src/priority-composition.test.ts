import { readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '../../..');

describe('controlled priority composition', () => {
  it('constructs the calculation and queue use cases only in the API priority runtime', () => {
    const needles = ['createCalculateFindingRiskUseCase', 'createReadRemediationQueueUseCase'];
    const allowed = new Set([path.join(here, 'priority-runtime.ts')]);
    const roots = [
      path.join(repoRoot, 'apps/api/src'),
      path.join(repoRoot, 'apps/web'),
      path.join(repoRoot, 'apps/worker/src'),
      path.join(repoRoot, 'packages/database/src/seed'),
    ];
    const offenders: string[] = [];
    for (const root of roots) {
      for (const filePath of walk(root)) {
        if (!/\.(ts|tsx)$/.test(filePath) || filePath.endsWith('.test.ts')) {
          continue;
        }
        if (allowed.has(filePath)) {
          continue;
        }
        const source = readFileSync(filePath, 'utf8');
        if (needles.some((needle) => source.includes(needle))) {
          offenders.push(path.relative(repoRoot, filePath));
        }
      }
    }
    expect(offenders).toEqual([]);
    const runtime = readFileSync(path.join(here, 'priority-runtime.ts'), 'utf8');
    const server = readFileSync(path.join(here, 'server.ts'), 'utf8');
    expect(runtime).toContain('createReadControlledFindingPriorityUseCase');
    expect(runtime).toContain('createReadRemediationQueueUseCase');
    expect(server).toContain('composeControlledPriorityRuntime');
    expect(server).not.toContain('createCalculateFindingRiskUseCase');
    expect(server).not.toContain('createReadRemediationQueueUseCase');
    expect(server).not.toContain('@patchpilot/policy-engine');
  });
});

function walk(directory: string): string[] {
  if (!statSync(directory, { throwIfNoEntry: false })?.isDirectory()) {
    return [];
  }
  const files: string[] = [];
  for (const entry of readdirSync(directory)) {
    if (entry === 'node_modules' || entry === 'dist' || entry === '.next') {
      continue;
    }
    const filePath = path.join(directory, entry);
    if (statSync(filePath).isDirectory()) {
      files.push(...walk(filePath));
      continue;
    }
    files.push(filePath);
  }
  return files;
}
