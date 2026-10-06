import { spawnSync } from 'node:child_process';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import * as domainPublic from '../../index.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '../../../../..');
const domainIndex = path.join(here, '../../index.ts');
const featureIndex = path.join(here, 'index.ts');

const SKIPPED = new Set([
  'node_modules',
  'dist',
  '.next',
  'coverage',
  'generated',
  '.git',
  '.turbo',
]);

const BANNED_SOURCE =
  /@prisma\/client|\bPrisma\b|from 'fastify'|from "fastify"|from 'next'|from "next"|from 'ioredis'|from "ioredis"|from 'bullmq'|from "bullmq"|@aws-sdk|process\.env|\beval\s*\(|new Function|import\s*\(|from 'node:fs'|from 'node:https'|from 'node:http'|from 'node:net'/;

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
  return /\.(ts|tsx|mjs)$/.test(filePath) && !/\.test\.(ts|tsx|mjs)$/.test(filePath);
}

describe('controlled finding creation public surface', () => {
  it('does not export the issuer, fingerprint, or a test reset helper', () => {
    const names = Object.keys(domainPublic);
    expect(names).not.toContain('issueFindingCreationAuthorization');
    expect(names).toContain('FINDING_CREATION_EVIDENCE_SET_LIMIT');
    expect(names).not.toContain('parseFindingCreationEvidenceSet');
    expect(names).not.toContain('fingerprintEvidenceIds');
    expect(names.filter((name) => /clear.*[Ff]inding|testIssuer|resetFinding/.test(name))).toEqual(
      [],
    );
    const domainSource = readFileSync(domainIndex, 'utf8');
    const featureSource = readFileSync(featureIndex, 'utf8');
    for (const source of [domainSource, featureSource]) {
      expect(source).not.toContain('issueFindingCreationAuthorization');
      expect(source).not.toContain('parseFindingCreationEvidenceSet');
      expect(source).not.toContain('authorizationSeals');
      expect(source).not.toContain('fingerprintEvidenceIds');
    }
    const packageJson = JSON.parse(
      readFileSync(path.join(repoRoot, 'packages/domain/package.json'), 'utf8'),
    ) as { exports: Record<string, unknown> };
    expect(Object.keys(packageJson.exports)).toEqual(['.']);
  });
});

describe('controlled finding creation source boundary', () => {
  it('keeps the contract sources free of frameworks, I/O, and writers', () => {
    const files = readdirSync(here).filter(
      (name) => name.endsWith('.ts') && !name.endsWith('.test.ts'),
    );
    expect(files.length).toBeGreaterThan(0);
    for (const name of files) {
      const source = readFileSync(path.join(here, name), 'utf8');
      expect(source, name).not.toMatch(BANNED_SOURCE);
      expect(source, name).not.toContain('createFinding');
      expect(source, name).not.toContain('finding.create');
      expect(source, name).not.toContain('@patchpilot/database');
    }
  });
});

describe('controlled finding creation production exclusion', () => {
  it('is not constructed by API, web, worker, or database production sources', () => {
    const roots = ['apps/api', 'apps/web', 'apps/worker', 'packages/database/src'].map((root) =>
      path.join(repoRoot, root),
    );
    const offenders: string[] = [];
    const forbidden = [
      'issueFindingCreationAuthorization',
      'findings/controlled-creation',
      'openFindingCreationCommand',
      'presentFindingCreationAuthorization',
    ];
    for (const root of roots) {
      for (const filePath of walk(root).filter(isProductionSource)) {
        const source = readFileSync(filePath, 'utf8');
        if (forbidden.some((needle) => source.includes(needle))) {
          offenders.push(path.relative(repoRoot, filePath));
        }
      }
    }
    expect(offenders).toEqual([]);
  });
});

describe('controlled finding creation issuer containment', () => {
  it('keeps the issuer out of production sources except its module', () => {
    const allowed = 'packages/domain/src/findings/controlled-creation/authorization.ts';
    const offenders: string[] = [];
    for (const filePath of walk(repoRoot).filter(isProductionSource)) {
      const relative = path.relative(repoRoot, filePath);
      if (relative === allowed) {
        continue;
      }
      const source = readFileSync(filePath, 'utf8');
      if (source.includes('issueFindingCreationAuthorization')) {
        offenders.push(relative);
      }
    }
    expect(offenders).toEqual([]);
  });

  it('rejects package subpath imports of the issuer module', () => {
    const specifiers = [
      '@patchpilot/domain/src/findings/controlled-creation/authorization.js',
      '@patchpilot/domain/findings/controlled-creation',
    ];
    for (const specifier of specifiers) {
      const result = spawnSync(
        process.execPath,
        ['--input-type=module', '-e', `import('${specifier}')`],
        { cwd: path.join(repoRoot, 'apps/api'), encoding: 'utf8' },
      );
      expect(result.status, specifier).not.toBe(0);
      expect(`${result.stderr}`, specifier).toContain('ERR_PACKAGE_PATH_NOT_EXPORTED');
    }
  });
});

describe('controlled finding creation checkpoint', () => {
  it('records contracts without persistence or production composition', () => {
    const checkpoint = readFileSync(path.join(repoRoot, 'docs/project/current-state.md'), 'utf8');
    expect(checkpoint).toContain('process-local creation authorization are implemented');
    expect(checkpoint).toContain('Persistence is not implemented.');
    expect(checkpoint).toContain('The evidence-link migration is not implemented.');
    expect(checkpoint).toContain('No Finding can be created.');
    expect(checkpoint).toContain('Production composition is absent.');
    expect(checkpoint).toContain('Session 1-R reviewed the process-local creation authorization.');
    expect(checkpoint).toContain('The issuer function is not a package export.');
    expect(checkpoint).toContain('Session 2 is next.');
    expect(checkpoint).not.toContain('Session 1-R is next.');
    expect(checkpoint).toContain('All lifecycle powers remain unavailable.');
    expect(checkpoint).toContain('The controlled product slice is not complete.');
  });
});
