import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import * as databasePublic from './index.js';
import { createRepositories } from './repositories.js';

const srcDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(srcDir, '..', '..', '..');

const SKIPPED_DIRECTORIES = new Set(['node_modules', 'dist', '.next', 'coverage', 'generated']);

function walk(directory: string, files: string[] = []): string[] {
  for (const entry of readdirSync(directory)) {
    if (SKIPPED_DIRECTORIES.has(entry)) {
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

function isTestOrFixture(filePath: string): boolean {
  const name = path.basename(filePath);
  return /\.test\.(ts|tsx|mjs)$/.test(name) || /-fixture\.ts$/.test(name);
}

function productionSources(): string[] {
  return ['apps', 'packages']
    .flatMap((root) => walk(path.join(repoRoot, root)))
    .filter((filePath) => /\.(ts|tsx|mjs)$/.test(filePath) && !isTestOrFixture(filePath));
}

const FINDING_WRITE =
  /\.(finding|findingObservation)\s*\.\s*(create|createMany|createManyAndReturn|update|updateMany|upsert|delete|deleteMany)\b/;
const FINDING_RAW_SQL = /(INSERT\s+INTO|UPDATE|DELETE\s+FROM)\s+"?finding(_observation)?"?\b/i;

describe('Finding generic-write containment', () => {
  it('exposes only read operations on the composed Finding repository', async () => {
    const calls: string[] = [];
    const client = {
      finding: {
        findFirst: async () => {
          calls.push('findFirst');
          return null;
        },
        findMany: async () => {
          calls.push('findMany');
          return [];
        },
      },
    };
    const repos = createRepositories(client as never);
    const findings = repos.findings as unknown as Record<string, unknown>;

    const members = new Set<string>([
      ...Object.keys(findings),
      ...Object.getOwnPropertyNames(Object.getPrototypeOf(findings)),
    ]);
    members.delete('constructor');
    const callable = [...members].filter((name) => typeof findings[name] === 'function');
    expect(callable.sort()).toEqual(['findById', 'listForOrganization']);
    expect('create' in findings).toBe(false);

    await repos.findings.findById('org', 'id');
    await repos.findings.listForOrganization('org');
    expect(calls.sort()).toEqual(['findFirst', 'findMany']);

    // @ts-expect-error The Finding port has no generic create operation.
    expect(repos.findings.create).toBeUndefined();
  });

  it('does not export a Finding writer or repository class from the database package', () => {
    const names = Object.keys(databasePublic);
    expect(names.filter((name) => /finding/i.test(name))).toEqual([]);
    expect('PrismaFindingRepository' in databasePublic).toBe(false);
  });

  it('keeps Finding creation out of the domain port source', () => {
    const ports = readFileSync(path.join(repoRoot, 'packages/domain/src/ports.ts'), 'utf8');
    expect(ports).not.toContain('CreateFindingInput');
    const start = ports.indexOf('export type FindingRepository');
    expect(start).toBeGreaterThan(-1);
    const block = ports.slice(start, ports.indexOf('};', start));
    expect(block).not.toMatch(/\bcreate\w*\s*\(/);
    expect(block).not.toMatch(/\b(update|upsert|delete|assign|suppress|transition)\w*\s*\(/);
    const domainIndex = readFileSync(path.join(repoRoot, 'packages/domain/src/index.ts'), 'utf8');
    expect(domainIndex).not.toContain('CreateFindingInput');
  });

  it('keeps direct Prisma Finding writes out of production sources', () => {
    const offenders: string[] = [];
    for (const filePath of productionSources()) {
      const source = readFileSync(filePath, 'utf8');
      if (FINDING_WRITE.test(source) || FINDING_RAW_SQL.test(source)) {
        offenders.push(path.relative(repoRoot, filePath));
      }
    }
    expect(offenders).toEqual([]);
  });

  it('keeps the Finding-writing intelligence fixture out of the production build', () => {
    const buildConfig = readFileSync(path.join(srcDir, '..', 'tsconfig.build.json'), 'utf8');
    expect(buildConfig).toContain('src/intelligence-test-fixture.ts');
    expect(buildConfig).toContain('src/**/*.test.ts');
  });
});
