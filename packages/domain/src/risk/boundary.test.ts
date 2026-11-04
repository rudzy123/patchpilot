/**
 * Domain owns the priority port. It does not import the policy engine.
 * The API composition files and the builtin publication command may import it.
 * The web, the worker, and the database barrel do not.
 */

import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import * as domainPublic from '../index.js';
import * as riskPublic from './index.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '../../../..');

const SKIPPED = new Set(['node_modules', 'dist', '.next', 'coverage', 'generated', '.git']);

function walk(directory: string, files: string[] = []): string[] {
  for (const entry of readdirSync(directory)) {
    if (SKIPPED.has(entry)) {
      continue;
    }
    const fullPath = path.join(directory, entry);
    if (statSync(fullPath).isDirectory()) {
      walk(fullPath, files);
    } else if (/\.(ts|tsx|mjs|js)$/.test(entry)) {
      files.push(fullPath);
    }
  }
  return files;
}

function importSpecifiers(source: string): string[] {
  const withoutComments = source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
  const specifiers: string[] = [];
  const patterns = [
    /\bfrom\s+['"]([^'"]+)['"]/g,
    /\bimport\s+['"]([^'"]+)['"]/g,
    /\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
    /\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
  ];
  for (const pattern of patterns) {
    for (const match of withoutComments.matchAll(pattern)) {
      const specifier = match[1];
      if (specifier !== undefined) {
        specifiers.push(specifier);
      }
    }
  }
  return specifiers;
}

function importsPolicyEngine(specifier: string): boolean {
  return specifier === '@patchpilot/policy-engine' || specifier.includes('policy-engine');
}

const NUMERICAL_POLICY = [
  /source_severity\s*:\s*40\b/,
  /kev_listed\s*:\s*20\b/,
  /environment_sensitivity\s*:\s*10\b/,
  /minPriority\s*:\s*80\b/,
  /dueDateRecommendationDays\s*:\s*7\b/,
  /OVERRIDE_WEIGHT_BOUNDS/,
  /\[\s*30\s*,\s*50\s*\]/,
  /critical\s*:\s*100\b/,
];

function productionSources(directory: string): string[] {
  return walk(directory).filter((filePath) => !filePath.endsWith('.test.ts'));
}

describe('priority contract boundary', () => {
  it('re-exports the risk contract from the domain barrel', () => {
    for (const key of Object.keys(riskPublic)) {
      expect(domainPublic).toHaveProperty(key);
    }
    expect(domainPublic.PRIORITY_CALCULATE_CONTROLLED_PERMISSION).toBe(
      'priority:calculate_controlled',
    );
    expect(domainPublic.PRIORITY_INSPECT_PERMISSION).toBe('priority:inspect');
    expect(domainPublic.PRIORITY_CONTROLLED_PRODUCTION_REGISTRATION).toBe('api_process');
  });

  it('does not depend on the policy engine', () => {
    const manifest = JSON.parse(
      readFileSync(path.join(repoRoot, 'packages/domain/package.json'), 'utf8'),
    ) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
      peerDependencies?: Record<string, string>;
      optionalDependencies?: Record<string, string>;
    };
    const declared = [
      ...Object.keys(manifest.dependencies ?? {}),
      ...Object.keys(manifest.devDependencies ?? {}),
      ...Object.keys(manifest.peerDependencies ?? {}),
      ...Object.keys(manifest.optionalDependencies ?? {}),
    ];
    expect(declared).not.toContain('@patchpilot/policy-engine');
  });

  it('keeps the engine import out of domain, the web, the worker, and the database barrel', () => {
    const allowed = new Set([
      path.join(repoRoot, 'apps/api/src/priority-engine.ts'),
      path.join(repoRoot, 'apps/api/src/priority-policy-hash.ts'),
      path.join(
        repoRoot,
        'packages/database/src/builtin-priority-policy-publication-command-main.ts',
      ),
      path.join(repoRoot, 'packages/database/src/seed/run.ts'),
    ]);
    const files = [
      ...walk(path.join(repoRoot, 'packages/domain/src')),
      ...walk(path.join(repoRoot, 'apps/api')),
      ...walk(path.join(repoRoot, 'apps/web')),
      ...walk(path.join(repoRoot, 'apps/worker')),
      ...walk(path.join(repoRoot, 'packages/database/src')),
    ];
    const offenders: string[] = [];
    for (const filePath of files) {
      if (allowed.has(filePath) || filePath.endsWith('.test.ts')) {
        continue;
      }
      const specifiers = importSpecifiers(readFileSync(filePath, 'utf8'));
      if (specifiers.some(importsPolicyEngine)) {
        offenders.push(path.relative(repoRoot, filePath));
      }
    }
    expect(offenders).toEqual([]);
  });

  it('does not copy weights, band thresholds, or normalization percents', () => {
    const files = [
      ...productionSources(path.join(repoRoot, 'packages/domain/src/risk')),
      path.join(repoRoot, 'packages/domain/src/json-documents.ts'),
    ];
    const offenders: string[] = [];
    for (const filePath of files) {
      const source = readFileSync(filePath, 'utf8');
      if (NUMERICAL_POLICY.some((pattern) => pattern.test(source))) {
        offenders.push(path.relative(repoRoot, filePath));
      }
    }
    expect(offenders).toEqual([]);
  });
});
