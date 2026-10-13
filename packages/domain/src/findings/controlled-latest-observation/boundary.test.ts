/**
 * Public surface and production exclusion for the latest-observation
 * application service.
 */

import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import * as domainPublic from '../../index.js';
import { createControlledFindingLatestObservationApplication } from './service.js';

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
  /@prisma\/client|\bPrisma\b|from 'fastify'|from "fastify"|from 'next'|from "next"|from 'ioredis'|from "ioredis"|from 'bullmq'|from "bullmq"|@aws-sdk|process\.env|\beval\s*\(|new Function|import\s*\(|from 'node:fs'|from 'node:https'|from 'node:http'|from 'node:net'|from 'node:timers'|setTimeout\(|setInterval\(|@patchpilot\/database|@patchpilot\/vulnerability-intelligence|selectFindingLatestObservation|createControlledFindingLatestObservationRead|controlled-finding-latest-observation-read/;

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

describe('controlled finding latest-observation application surface', () => {
  it('keeps the service off the domain barrel and package exports', () => {
    const names = Object.keys(domainPublic);
    expect(names).not.toContain('createControlledFindingLatestObservationApplication');
    expect(names).not.toContain('selectFindingLatestObservation');
    expect(names).not.toContain('mapFindingLatestObservationInspectionResult');
    const packageJson = JSON.parse(
      readFileSync(path.join(repoRoot, 'packages/domain/package.json'), 'utf8'),
    ) as { exports: Record<string, unknown> };
    expect(Object.keys(packageJson.exports).sort()).toEqual([
      '.',
      './controlled-finding-discovery',
      './controlled-finding-operator',
    ]);
    const encoded = JSON.stringify(packageJson.exports);
    expect(encoded).not.toContain('controlled-latest-observation');
    expect(encoded).not.toContain('createControlledFindingLatestObservationApplication');
    const barrels = [
      'packages/domain/src/index.ts',
      'packages/domain/src/findings/controlled-inspection/index.ts',
      'packages/domain/src/findings/controlled-inspection/service.ts',
      'packages/domain/src/findings/controlled-operator/index.ts',
      'packages/domain/src/findings/controlled-operator/inspection.ts',
      'packages/database/src/index.ts',
      'packages/database/src/controlled-finding-persistence.ts',
    ];
    for (const relative of barrels) {
      const source = readFileSync(path.join(repoRoot, relative), 'utf8');
      expect(source, relative).not.toContain('createControlledFindingLatestObservationApplication');
      expect(source, relative).not.toContain('controlled-latest-observation');
    }
    expect(createControlledFindingLatestObservationApplication).toEqual(expect.any(Function));
  });

  it('keeps the application sources free of frameworks, persistence, and writers', () => {
    const files = readdirSync(here).filter(
      (name) => name.endsWith('.ts') && !name.endsWith('.test.ts'),
    );
    expect(files.length).toBeGreaterThan(0);
    for (const name of files) {
      const source = readFileSync(path.join(here, name), 'utf8');
      expect(source, name).not.toMatch(BANNED_SOURCE);
      expect(source, name).not.toContain('.update(');
      expect(source, name).not.toContain('.delete(');
      expect(source, name).not.toContain('issueFindingRepeatedObservationAuthorization');
      expect(source, name).not.toContain('recordFindingRepeatedObservation');
      expect(source, name).not.toContain('auditEvent');
    }
    const service = readFileSync(path.join(here, 'service.ts'), 'utf8');
    const execute = service.slice(service.indexOf('async function executeLatestObservation'));
    const markers = [
      'parseControlledFindingOperatorActor(',
      'roleGrantsControlledFindingOperatorPermission(',
      'FINDING_INSPECT_PERMISSION',
      'parseInspectControlledFindingLatestObservationCommand(',
      'read.read(',
    ];
    let cursor = -1;
    for (const marker of markers) {
      const index = execute.indexOf(marker);
      expect(index, marker).toBeGreaterThan(cursor);
      cursor = index;
    }
    expect(service).not.toContain('selectFindingLatestObservation');
    expect(service).not.toContain('projectFindingInspection');
  });
});

describe('controlled finding latest-observation production exclusion', () => {
  it('is not constructed by API, web, worker, seed, or startup sources', () => {
    const roots = ['apps/api', 'apps/web', 'apps/worker', 'packages/database/src/seed'].map(
      (root) => path.join(repoRoot, root),
    );
    const forbidden = [
      'createControlledFindingLatestObservationApplication',
      'controlled-latest-observation',
      'createControlledFindingLatestObservationRead',
      'loadControlledFindingLatestObservationSnapshot',
      'selectFindingLatestObservation',
      'latest-observation-selection',
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
    const closed = [
      'apps/api/src/server.ts',
      'apps/api/src/finding-runtime.ts',
      'apps/api/src/finding-routes.ts',
      'apps/worker/src/main.ts',
      'apps/worker/src/queue-job-router.ts',
      'apps/worker/src/bullmq-outbox-publisher.ts',
      'apps/worker/src/intelligence-scheduler.ts',
      'apps/web/app/layout.tsx',
      'apps/web/app/findings/[findingId]/page.tsx',
      'apps/web/app/findings/[findingId]/finding-inspection-page-client.tsx',
      'packages/database/src/index.ts',
      'packages/database/src/repositories.ts',
      'packages/database/src/outbox-relay-persistence.ts',
    ];
    for (const relative of closed) {
      const source = readFileSync(path.join(repoRoot, relative), 'utf8');
      for (const needle of forbidden) {
        expect(source, `${relative} ${needle}`).not.toContain(needle);
      }
    }
    const routes = readFileSync(path.join(repoRoot, 'apps/api/src/finding-routes.ts'), 'utf8');
    expect(routes).toContain("const INSPECTION_ROUTE = '/findings/:findingId'");
    const inspection = readFileSync(
      path.join(repoRoot, 'packages/domain/src/findings/controlled-inspection/service.ts'),
      'utf8',
    );
    expect(inspection).toContain('projectFindingInspection');
    expect(inspection).not.toContain('latest_repeated');
    const webClient = readFileSync(
      path.join(repoRoot, 'apps/web/app/findings/[findingId]/finding-inspection-page-client.tsx'),
      'utf8',
    );
    expect(webClient).toContain('inspectControlledFinding');
    expect(webClient).toContain('creationEvidenceApplicability');
  });
});
