/**
 * Public surface, issuer containment, and production exclusion for the
 * controlled Finding operator application.
 */

import { spawnSync } from 'node:child_process';
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

const BANNED_SOURCE =
  /@prisma\/client|\bPrisma\b|from 'fastify'|from "fastify"|from 'next'|from "next"|from 'ioredis'|from "ioredis"|from 'bullmq'|from "bullmq"|@aws-sdk|process\.env|\beval\s*\(|new Function|import\s*\(|from 'node:fs'|from 'node:https'|from 'node:http'|from 'node:net'|from 'node:timers'|setTimeout\(|setInterval\(|@patchpilot\/database|@patchpilot\/vulnerability-intelligence/;

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

describe('controlled finding operator public surface', () => {
  it('exports the permission catalog and withholds the factories and issuer', () => {
    expect(domainPublic.FINDING_CREATE_CONTROLLED_PERMISSION).toBe('finding:create_controlled');
    expect(domainPublic.FINDING_INSPECT_PERMISSION).toBe('finding:inspect');
    expect(domainPublic.CONTROLLED_FINDING_OPERATOR_PRODUCTION_REGISTRATION).toBe('absent');
    expect(domainPublic.controlledFindingOperatorPermissionsForRole('owner')).toEqual([
      'finding:create_controlled',
      'finding:inspect',
    ]);
    const names = Object.keys(domainPublic);
    expect(names).not.toContain('createControlledFindingCreationApplication');
    expect(names).not.toContain('createControlledFindingInspectionApplication');
    expect(names).not.toContain('issueFindingCreationAuthorization');
    expect(names).not.toContain('authorizationSeals');
    expect(names).not.toContain('commandSeals');
    expect(names).not.toContain('parseFindingCreationEvidenceSet');
    expect(names).not.toContain('fingerprintEvidenceIds');
    expect(names).not.toContain('roleGrantsControlledFindingOperatorPermission');
    expect(names).not.toContain('parseControlledFindingOperatorActor');
    expect(names.filter((name) => /clear.*[Ff]inding|testIssuer|resetFinding/.test(name))).toEqual(
      [],
    );
    const packageJson = JSON.parse(
      readFileSync(path.join(repoRoot, 'packages/domain/package.json'), 'utf8'),
    ) as { exports: Record<string, unknown> };
    expect(Object.keys(packageJson.exports)).toEqual(['.']);
    const barrel = readFileSync(path.join(repoRoot, 'packages/domain/src/index.ts'), 'utf8');
    expect(barrel).not.toContain('issueFindingCreationAuthorization');
    expect(barrel).not.toContain('createControlledFindingCreationApplication');
    expect(barrel).not.toContain('createControlledFindingInspectionApplication');
    expect(barrel).not.toContain('findings/controlled-operator/creation');
    expect(barrel).not.toContain('findings/controlled-operator/inspection');
    expect(barrel).not.toContain('findings/controlled-operator/index');
    const feature = readFileSync(path.join(here, 'index.ts'), 'utf8');
    expect(feature).toContain('createControlledFindingCreationApplication');
    expect(feature).toContain('createControlledFindingInspectionApplication');
    expect(feature).not.toContain('issueFindingCreationAuthorization');
    const databaseBarrel = readFileSync(
      path.join(repoRoot, 'packages/database/src/index.ts'),
      'utf8',
    );
    expect(databaseBarrel).not.toContain('createControlledFindingCreationApplication');
    expect(databaseBarrel).not.toContain('createControlledFindingInspectionApplication');
    expect(databaseBarrel).not.toContain('issueFindingCreationAuthorization');
  });

  it('rejects package subpath imports of the operator and issuer modules', () => {
    const specifiers = [
      '@patchpilot/domain/findings/controlled-operator',
      '@patchpilot/domain/src/findings/controlled-operator/creation.js',
      '@patchpilot/domain/src/findings/controlled-creation/authorization.js',
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

describe('controlled finding operator source boundary', () => {
  it('keeps application sources free of frameworks, I/O, and lifecycle writers', () => {
    const files = readdirSync(here).filter(
      (name) => name.endsWith('.ts') && !name.endsWith('.test.ts'),
    );
    expect(files.length).toBeGreaterThan(0);
    for (const name of files) {
      const source = readFileSync(path.join(here, name), 'utf8');
      expect(source, name).not.toMatch(BANNED_SOURCE);
      expect(source, name).not.toContain('createFinding');
      expect(source, name).not.toContain('finding.create');
      expect(source, name).not.toContain('transitionFinding');
    }
    const creation = readFileSync(path.join(here, 'creation.ts'), 'utf8');
    const inspection = readFileSync(path.join(here, 'inspection.ts'), 'utf8');
    expect(creation).toContain('FINDING_CREATE_CONTROLLED_PERMISSION');
    expect(creation).not.toContain('FINDING_INSPECT_PERMISSION');
    expect(creation).not.toContain('openFindingInspection');
    expect(inspection).toContain('FINDING_INSPECT_PERMISSION');
    expect(inspection).not.toContain('FINDING_CREATE_CONTROLLED_PERMISSION');
    expect(inspection).not.toContain('issueFindingCreationAuthorization');
    expect(inspection).not.toContain('openFindingCreationCommand');
    const execute = creation.slice(creation.indexOf('async function executeCreation'));
    const markers = [
      'roleGrantsControlledFindingOperatorPermission(',
      'parseCreationRequest(',
      'readCorrelationId(',
      'issueFindingCreationAuthorization(',
      'openFindingCreationCommand(',
      'persistence.apply(',
    ];
    let cursor = -1;
    for (const marker of markers) {
      const index = execute.indexOf(marker);
      expect(index, marker).toBeGreaterThan(cursor);
      cursor = index;
    }
  });

  it('lets only the creation application invoke the issuer', () => {
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
    const operatorTest = readFileSync(path.join(here, 'operator.test.ts'), 'utf8');
    expect(operatorTest).not.toContain('issueFindingCreationAuthorization');
  });
});

describe('controlled finding operator production exclusion', () => {
  it('is not constructed by API, web, worker, seed, queue, or database startup', () => {
    const roots = [
      'apps/api',
      'apps/web',
      'apps/worker',
      'packages/auth/src',
      'packages/database/src',
    ].map((root) => path.join(repoRoot, root));
    const forbidden = [
      'createControlledFindingCreationApplication',
      'createControlledFindingInspectionApplication',
      'issueFindingCreationAuthorization',
      'findings/controlled-operator',
    ];
    const offenders: string[] = [];
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
