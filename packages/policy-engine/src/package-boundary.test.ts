import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), '..');
const srcRoot = join(packageRoot, 'src');

function productionSources(directory: string): string[] {
  const files: string[] = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const fullPath = join(directory, entry.name);
    if (entry.isDirectory()) {
      files.push(...productionSources(fullPath));
      continue;
    }
    if (entry.name.endsWith('.test.ts')) {
      continue;
    }
    if (entry.name.endsWith('.ts')) {
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

describe('policy-engine package boundary', () => {
  it('DT9 declares zero runtime dependencies', () => {
    const manifest = JSON.parse(readFileSync(join(packageRoot, 'package.json'), 'utf8')) as {
      dependencies?: Record<string, string>;
      optionalDependencies?: Record<string, string>;
      peerDependencies?: Record<string, string>;
    };
    expect(Object.keys(manifest.dependencies ?? {})).toEqual([]);
    expect(Object.keys(manifest.optionalDependencies ?? {})).toEqual([]);
    expect(Object.keys(manifest.peerDependencies ?? {})).toEqual([]);
  });

  it('DT9 source imports exclude @patchpilot packages and node builtins', () => {
    const files = productionSources(srcRoot);
    expect(files.length).toBeGreaterThan(0);
    const specifiers = files.flatMap((file) =>
      importSpecifiers(readFileSync(file, 'utf8')).map((specifier) => ({ file, specifier })),
    );
    expect(specifiers.length).toBeGreaterThan(0);
    for (const { file, specifier } of specifiers) {
      expect(specifier, file).not.toMatch(/^@patchpilot\//);
      expect(specifier, file).not.toMatch(/^node:/);
      expect(
        specifier.startsWith('./') || specifier.startsWith('../'),
        `${file} ${specifier}`,
      ).toBe(true);
    }
  });
});

const SKIPPED_DIRECTORIES = new Set(['node_modules', 'dist', '.next', 'coverage', 'generated']);

function repoSources(directory: string): string[] {
  const files: string[] = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (SKIPPED_DIRECTORIES.has(entry.name)) {
      continue;
    }
    const fullPath = join(directory, entry.name);
    if (entry.isDirectory()) {
      files.push(...repoSources(fullPath));
      continue;
    }
    if (!entry.isFile()) {
      continue;
    }
    if (
      entry.name.endsWith('.d.ts') ||
      entry.name.includes('.test.') ||
      entry.name.includes('.spec.')
    ) {
      continue;
    }
    if (entry.name.endsWith('.ts') || entry.name.endsWith('.tsx')) {
      files.push(fullPath);
    }
  }
  return files;
}

describe('policy engine source boundary', () => {
  it('rejects policy-engine imports outside the API composition and the publication command', () => {
    const repoRoot = join(packageRoot, '..', '..');
    const allowed = new Set([
      join(repoRoot, 'packages/database/src/seed/run.ts'),
      join(repoRoot, 'apps/api/src/priority-engine.ts'),
      join(repoRoot, 'apps/api/src/priority-policy-hash.ts'),
      join(repoRoot, 'packages/database/src/builtin-priority-policy-publication-command-main.ts'),
    ]);
    const roots = [
      join(repoRoot, 'apps/api'),
      join(repoRoot, 'apps/web'),
      join(repoRoot, 'apps/worker'),
      join(repoRoot, 'packages/domain/src'),
      join(repoRoot, 'packages/database/src'),
    ];
    const offenders: string[] = [];
    for (const root of roots) {
      const files = repoSources(root);
      expect(files.length, root).toBeGreaterThan(0);
      for (const file of files) {
        if (allowed.has(file)) {
          continue;
        }
        const specifiers = importSpecifiers(readFileSync(file, 'utf8'));
        if (
          specifiers.some(
            (specifier) =>
              specifier === '@patchpilot/policy-engine' ||
              specifier.startsWith('@patchpilot/policy-engine/'),
          )
        ) {
          offenders.push(file);
        }
      }
    }
    expect(offenders).toEqual([]);
  });
});
