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
  const name = path.basename(filePath);
  if (/-fixture\.ts$/.test(name) || /-harness\.ts$/.test(name) || /-test-seam\.ts$/.test(name)) {
    return false;
  }
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
  it('is not constructed by API, web, or worker sources', () => {
    const roots = ['apps/api', 'apps/web', 'apps/worker'].map((root) => path.join(repoRoot, root));
    const offenders: string[] = [];
    const forbidden = [
      'issueFindingCreationAuthorization',
      'findings/controlled-creation',
      'openFindingCreationCommand',
      'presentFindingCreationAuthorization',
      'createControlledFindingCreationPersistence',
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

  it('lets only the uncomposed persistence adapter verify a sealed authorization', () => {
    const allowed = 'packages/database/src/controlled-finding-creation-persistence.ts';
    const offenders: string[] = [];
    const databaseRoot = path.join(repoRoot, 'packages/database/src');
    for (const filePath of walk(databaseRoot).filter(isProductionSource)) {
      const relative = path.relative(repoRoot, filePath);
      const source = readFileSync(filePath, 'utf8');
      if (
        source.includes('issueFindingCreationAuthorization') ||
        source.includes('findings/controlled-creation')
      ) {
        offenders.push(relative);
      }
      const verifies =
        source.includes('presentFindingCreationAuthorization') ||
        source.includes('openFindingCreationCommand');
      if (verifies && relative !== allowed) {
        offenders.push(relative);
      }
    }
    const adapter = readFileSync(path.join(repoRoot, allowed), 'utf8');
    expect(adapter).toContain('presentFindingCreationAuthorization');
    expect(adapter).not.toContain('issueFindingCreationAuthorization');
    expect(offenders).toEqual([]);
    const barrel = readFileSync(path.join(databaseRoot, 'index.ts'), 'utf8');
    expect(barrel).not.toContain('createControlledFindingCreationPersistence');
  });
});

describe('controlled finding creation issuer containment', () => {
  it('keeps the issuer out of production sources except its module and the creation application', () => {
    const allowed = new Set([
      'packages/domain/src/findings/controlled-creation/authorization.ts',
      'packages/domain/src/findings/controlled-operator/creation.ts',
    ]);
    const offenders: string[] = [];
    for (const filePath of walk(repoRoot).filter(isProductionSource)) {
      const relative = path.relative(repoRoot, filePath);
      if (allowed.has(relative)) {
        continue;
      }
      const source = readFileSync(filePath, 'utf8');
      if (source.includes('issueFindingCreationAuthorization')) {
        offenders.push(relative);
      }
    }
    expect(offenders).toEqual([]);
    const application = readFileSync(
      path.join(repoRoot, 'packages/domain/src/findings/controlled-operator/creation.ts'),
      'utf8',
    );
    expect(application).toContain('issueFindingCreationAuthorization');
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
  it('records the uncomposed creation transaction without a user-facing Finding product', () => {
    const checkpoint = readFileSync(path.join(repoRoot, 'docs/project/current-state.md'), 'utf8');
    expect(checkpoint).toContain('process-local creation authorization are implemented');
    expect(checkpoint).toContain(
      'The atomic creation transaction and evidence-link model are implemented and production uncomposed.',
    );
    expect(checkpoint).toContain(
      'Safe inspection and explanation are implemented and production uncomposed.',
    );
    expect(checkpoint).toContain('Lifecycle transitions remain unavailable.');
    expect(checkpoint).toContain('Production composition is absent.');
    expect(checkpoint).toContain('A user-facing Finding product is not operational.');
    expect(checkpoint).toContain('Session 1-R reviewed the process-local creation authorization.');
    expect(checkpoint).toContain('Session 2-R reviewed the creation transaction.');
    expect(checkpoint).toContain('The issuer function is not a package export.');
    expect(checkpoint).toContain('Session 3-R reviewed safe inspection and explanation.');
    expect(checkpoint).toContain('publicly indistinguishable');
    expect(checkpoint).toContain('Explanation is derived from immutable evidence.');
    expect(checkpoint).toContain('Applicability is read time only.');
    expect(checkpoint).toContain('The Controlled Finding vertical slice is merged.');
    expect(checkpoint).toContain('The protected operator API is the approved next implementation.');
    expect(checkpoint).toContain('Those routes are not implemented.');
    expect(checkpoint).not.toContain('Branch-closure review is next.');
    expect(checkpoint).not.toContain('Session 3-R is next.');
    expect(checkpoint).not.toContain('Session 2-R is next.');
    expect(checkpoint).toContain(
      'Controlled Finding Operator API Session 1-R reviewed the application authorization boundary.',
    );
    expect(checkpoint).not.toContain('Controlled Finding Operator API Session 1-R is next.');
    expect(checkpoint).toContain('The operator permissions are implemented.');
    expect(checkpoint).toContain(
      'The application creation and inspection boundaries are implemented.',
    );
    expect(checkpoint).toContain('Private creation issuance remains contained.');
    expect(checkpoint).toContain('HTTP routes are not yet implemented.');
    expect(checkpoint).toContain('Production composition remains absent.');
    expect(checkpoint).toContain('Automatic and lifecycle capabilities remain unavailable.');
    expect(checkpoint).toContain('All lifecycle powers remain unavailable.');
    expect(checkpoint).toContain('The controlled product slice is not complete.');
  });
});
