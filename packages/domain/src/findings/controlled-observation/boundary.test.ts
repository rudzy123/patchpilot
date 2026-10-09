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
  /@prisma\/client|\bPrisma\b|from 'fastify'|from "fastify"|from 'next'|from "next"|from 'ioredis'|from "ioredis"|from 'bullmq'|from "bullmq"|@aws-sdk|process\.env|\beval\s*\(|new Function|import\s*\(|from 'node:fs'|from 'node:https'|from 'node:http'|from 'node:net'|setTimeout|setInterval/;

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

describe('repeated observation public surface', () => {
  it('does not export the issuer, fingerprint parser, or a reset helper', () => {
    const names = Object.keys(domainPublic);
    expect(names).not.toContain('issueFindingRepeatedObservationAuthorization');
    expect(names).not.toContain('parseFindingRepeatedObservationSupport');
    expect(names).not.toContain('fingerprintEvidenceSupport');
    expect(names).not.toContain('authorizationSeals');
    expect(names).toContain('FINDING_REPEATED_OBSERVATION_PURPOSE');
    expect(names).toContain('openFindingRepeatedObservationCommand');
    expect(names).toContain('presentFindingRepeatedObservationAuthorization');
    expect(names.filter((name) => /testIssuer|resetFinding|clear.*Observation/.test(name))).toEqual(
      [],
    );
    const domainSource = readFileSync(domainIndex, 'utf8');
    const featureSource = readFileSync(featureIndex, 'utf8');
    for (const source of [domainSource, featureSource]) {
      expect(source).not.toContain('issueFindingRepeatedObservationAuthorization');
      expect(source).not.toContain('parseFindingRepeatedObservationSupport');
      expect(source).not.toContain('authorizationSeals');
      expect(source).not.toContain('fingerprintEvidenceSupport');
    }
    const packageJson = JSON.parse(
      readFileSync(path.join(repoRoot, 'packages/domain/package.json'), 'utf8'),
    ) as { exports: Record<string, unknown> };
    expect(Object.keys(packageJson.exports).sort()).toEqual([
      '.',
      './controlled-finding-discovery',
      './controlled-finding-operator',
    ]);
  });
});

describe('repeated observation source boundary', () => {
  it('keeps the contract sources free of frameworks, I/O, timers, and writers', () => {
    const files = readdirSync(here).filter(
      (name) => name.endsWith('.ts') && !name.endsWith('.test.ts'),
    );
    expect(files.length).toBeGreaterThan(0);
    for (const name of files) {
      const source = readFileSync(path.join(here, name), 'utf8');
      expect(source, name).not.toMatch(BANNED_SOURCE);
      expect(source, name).not.toContain('@patchpilot/database');
      expect(source, name).not.toContain('prisma.');
    }
  });
});

describe('repeated observation production exclusion', () => {
  it('is not constructed by API, web, worker, or database sources', () => {
    const roots = ['apps/api', 'apps/web', 'apps/worker', 'packages/database/src'].map((root) =>
      path.join(repoRoot, root),
    );
    const forbidden = [
      'issueFindingRepeatedObservationAuthorization',
      'findings/controlled-observation',
      'openFindingRepeatedObservationCommand',
      'presentFindingRepeatedObservationAuthorization',
      'record_finding_repeated_observation',
    ];
    const allowedDatabase = new Set([
      'packages/database/src/controlled-finding-repeated-observation-persistence.ts',
      'packages/database/src/controlled-finding-inspection-repeated-validation.ts',
    ]);
    const offenders: string[] = [];
    for (const root of roots) {
      for (const filePath of walk(root).filter(isProductionSource)) {
        const relative = path.relative(repoRoot, filePath);
        if (allowedDatabase.has(relative)) {
          continue;
        }
        const source = readFileSync(filePath, 'utf8');
        if (forbidden.some((needle) => source.includes(needle))) {
          offenders.push(relative);
        }
      }
    }
    expect(offenders).toEqual([]);
  });

  it('is absent from startup, health, seed, queue, and migration entrypoints', () => {
    const files = [
      'apps/api/src/server.ts',
      'apps/api/src/app.ts',
      'apps/web/app/layout.tsx',
      'apps/web/app/health/route.ts',
      'apps/worker/src/main.ts',
      'apps/worker/src/app.ts',
      'apps/worker/src/queue-job-router.ts',
      'apps/worker/src/bullmq-outbox-publisher.ts',
      'apps/worker/src/outbox-relay-runtime.ts',
      'apps/worker/src/sbom-ingest-processor.ts',
      'apps/worker/src/intelligence-sync-processor.ts',
      'apps/worker/src/intelligence-scheduler.ts',
      'apps/worker/src/intelligence-composition.ts',
      'packages/database/src/seed/run.ts',
      'packages/database/src/seed/development.ts',
      'scripts/run-database-command.mjs',
    ];
    const forbidden = [
      'issueFindingRepeatedObservationAuthorization',
      'findings/controlled-observation',
      'openFindingRepeatedObservationCommand',
      'presentFindingRepeatedObservationAuthorization',
      'record_finding_repeated_observation',
    ];
    for (const relative of files) {
      const source = readFileSync(path.join(repoRoot, relative), 'utf8');
      expect(
        forbidden.some((needle) => source.includes(needle)),
        relative,
      ).toBe(false);
    }
    const migrationRoot = path.join(repoRoot, 'packages/database/prisma/migrations');
    const migrations = readdirSync(migrationRoot).filter((name) => name !== 'migration_lock.toml');
    expect(migrations).toHaveLength(25);
    const schema = readFileSync(
      path.join(repoRoot, 'packages/database/prisma/schema.prisma'),
      'utf8',
    );
    expect(schema).toContain('finding_repeated_observation_evidence_link');
    expect(schema).toContain('finding_repeated_observation_aggregate');
  });

  it('keeps the issuer inside its module', () => {
    const allowed = new Set([
      'packages/domain/src/findings/controlled-observation/authorization.ts',
    ]);
    const offenders: string[] = [];
    for (const filePath of walk(repoRoot).filter(isProductionSource)) {
      const relative = path.relative(repoRoot, filePath);
      if (allowed.has(relative)) {
        continue;
      }
      const source = readFileSync(filePath, 'utf8');
      if (source.includes('issueFindingRepeatedObservationAuthorization')) {
        offenders.push(relative);
      }
    }
    expect(offenders).toEqual([]);
  });

  it('rejects package subpath imports of the issuer module', () => {
    const specifiers = [
      '@patchpilot/domain/src/findings/controlled-observation/authorization.js',
      '@patchpilot/domain/findings/controlled-observation',
    ];
    for (const specifier of specifiers) {
      const result = spawnSync(
        process.execPath,
        ['--input-type=module', '-e', `import('${specifier}')`],
        {
          cwd: path.join(repoRoot, 'apps/api'),
          encoding: 'utf8',
        },
      );
      expect(result.status, specifier).not.toBe(0);
      expect(`${result.stderr}`, specifier).toContain('ERR_PACKAGE_PATH_NOT_EXPORTED');
    }
  });
});

describe('repeated observation inspection and checkpoint', () => {
  it('leaves the creation inspection length check in place', () => {
    const projection = readFileSync(
      path.join(repoRoot, 'packages/domain/src/findings/controlled-inspection/projection.ts'),
      'utf8',
    );
    expect(projection).toContain('creationObservations.length !== 1');
    expect(projection).not.toContain('record_finding_repeated_observation');
  });

  it('records contracts without a completed repeated-observation slice', () => {
    const checkpoint = readFileSync(path.join(repoRoot, 'docs/project/current-state.md'), 'utf8');
    expect(checkpoint).toContain('Repeated-observation contracts are implemented.');
    expect(checkpoint).toContain('Process-local observation authority is implemented.');
    expect(checkpoint).toContain('The additive migration is implemented.');
    expect(checkpoint).toContain('The atomic repeated-observation transaction is implemented.');
    expect(checkpoint).toContain('Persistence remains production uncomposed.');
    expect(checkpoint).toContain('Only last_observed_at and updated_at may change.');
    expect(checkpoint).toContain('Creation inspection remains creation based.');
    expect(checkpoint).toContain('Later history is not publicly exposed.');
    expect(checkpoint).toContain('Production composition is absent.');
    expect(checkpoint).toContain(
      'Controlled Finding Repeated Observation Session 1-R reviewed the process-local observation authority.',
    );
    expect(checkpoint).toContain(
      'Controlled Finding Repeated Observation Session 2-R reviewed the uncomposed PostgreSQL transaction.',
    );
    expect(checkpoint).toContain('Current inspection tolerates legal repeated observations.');
    expect(checkpoint).toContain('Public inspection remains creation based.');
    expect(checkpoint).toContain('Repeated-observation history is not publicly exposed.');
    expect(checkpoint).toContain('The writer remains production uncomposed.');
    expect(checkpoint).toContain('Inspection performs no mutation.');
    expect(checkpoint).toContain(
      'Controlled Finding Repeated Observation Session 3-R reviewed the creation-based read path.',
    );
    expect(checkpoint).toContain('Repeated-observation branch closure remains the open review.');
    expect(checkpoint).not.toContain('Repeated Observation Session 3-R read-path review is next.');
    expect(checkpoint).not.toContain('Session 3 inspection compatibility is next.');
    expect(checkpoint).toContain('All lifecycle powers remain unavailable.');
    expect(checkpoint).toContain('Frozen migrations: 25.');
    expect(checkpoint).not.toContain('repeated-observation slice is complete');
    expect(checkpoint).not.toContain('repeated observation is production composed');
  });
});
