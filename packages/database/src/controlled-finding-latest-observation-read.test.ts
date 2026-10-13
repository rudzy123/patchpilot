/**
 * Query boundary for the internal latest-observation read.
 * No database is opened. Synthetic identifiers only.
 */

import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { Prisma, type PrismaClient } from '@prisma/client';
import { describe, expect, it } from 'vitest';

import * as databasePublic from './index.js';
import * as findingPersistence from './controlled-finding-persistence.js';
import { createControlledFindingLatestObservationRead } from './controlled-finding-latest-observation-read.js';

const ORG = '11111111-1111-4111-8111-111111111111';
const FINDING = '22222222-2222-4222-8222-222222222222';
const srcDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(srcDir, '..', '..', '..');
const adapterPath = path.join(srcDir, 'controlled-finding-latest-observation-read.ts');

const SKIPPED = new Set(['node_modules', 'dist', '.next', 'coverage', 'generated', '.git']);

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

describe('controlled finding latest-observation read boundary', () => {
  it('does not export the adapter from the database package or the API persistence barrel', () => {
    expect(Object.keys(databasePublic).filter((name) => /finding/i.test(name))).toEqual([]);
    expect('createControlledFindingLatestObservationRead' in databasePublic).toBe(false);
    expect('createControlledFindingLatestObservationRead' in findingPersistence).toBe(false);
    expect('createControlledFindingRepeatedObservationPersistence' in databasePublic).toBe(false);
  });

  it('scopes a missing finding to the organization and returns not_found', async () => {
    const queries: { text: string; values: unknown[] }[] = [];
    const prisma = {
      $transaction: async (callback: (tx: unknown) => Promise<unknown>) =>
        callback({
          $queryRaw: async (strings: TemplateStringsArray, ...values: unknown[]) => {
            queries.push({ text: strings.join(' '), values });
            return [];
          },
        }),
    } as unknown as PrismaClient;
    const outcome = await createControlledFindingLatestObservationRead(prisma).read({
      organizationId: ORG,
      findingId: FINDING,
    });
    expect(outcome.diagnostic).toBe('not_found');
    expect(outcome.safe).toEqual({
      schemaVersion: 'finding_latest_observation_external_result_v1',
      status: 'not_found',
    });
    const findingQuery = queries.find((query) => query.text.includes('FROM "finding"'));
    const parameters = (findingQuery?.values ?? []).filter(
      (value): value is string => typeof value === 'string',
    );
    expect(parameters).toEqual([ORG, FINDING]);
    expect(findingQuery?.text).toContain('organization_id');
    expect(findingQuery?.text).not.toContain(ORG);
    expect(findingQuery?.text).not.toContain(FINDING);
    expect(JSON.stringify(outcome.safe)).not.toContain(FINDING);
  });

  it('translates database and internal failures without echoing the driver message', async () => {
    const secret = 'postgres://user:secret@database.internal/patchpilot';
    const unavailable = {
      $transaction: async () => {
        throw new Prisma.PrismaClientKnownRequestError(secret, {
          code: 'P1001',
          clientVersion: 'test',
        });
      },
    } as unknown as PrismaClient;
    const internal = {
      $transaction: async () => {
        throw new Error(secret);
      },
    } as unknown as PrismaClient;
    const down = await createControlledFindingLatestObservationRead(unavailable).read({
      organizationId: ORG,
      findingId: FINDING,
    });
    const failed = await createControlledFindingLatestObservationRead(internal).read({
      organizationId: ORG,
      findingId: FINDING,
    });
    expect(down.diagnostic).toBe('database_unavailable');
    expect(failed.diagnostic).toBe('internal_failure');
    expect(down.safe.status).toBe('unavailable');
    expect(failed.safe.status).toBe('unavailable');
    expect(down.safe.status).not.toBe('not_found');
    expect(JSON.stringify(down.safe)).not.toContain('secret');
    expect(JSON.stringify(failed.safe)).not.toContain('postgres://');
    expect(JSON.stringify(down)).not.toContain('finding_observation');
  });

  it('rejects a malformed identifier before opening a transaction', async () => {
    let transactions = 0;
    const prisma = {
      $transaction: async () => {
        transactions += 1;
        return { diagnostic: 'not_found' };
      },
    } as unknown as PrismaClient;
    const result = await createControlledFindingLatestObservationRead(prisma).read({
      organizationId: ORG,
      findingId: 'not-a-uuid',
    });
    expect(result.diagnostic).toBe('internal_failure');
    expect(result.safe.status).toBe('unavailable');
    expect(transactions).toBe(0);
  });

  it('keeps the SQL read-only, parameterized, and selector-driven', () => {
    const source = readFileSync(adapterPath, 'utf8');
    expect(source).toContain('selectFindingLatestObservation');
    expect(source).toContain('mapFindingLatestObservationInspectionResult');
    expect(source).toContain('RepeatableRead');
    expect(source).toContain("set_config('transaction_read_only', 'on', true)");
    expect(source).toContain("AT TIME ZONE 'UTC'");
    expect(source).toContain('HH24:MI:SS.US');
    expect(source).toContain('lower(');
    expect(source).not.toContain('SELECT *');
    expect(source).not.toMatch(/LIMIT\s+1/i);
    expect(source).not.toMatch(/\bLIMIT\b/);
    expect(source).not.toMatch(/\bINSERT\b/);
    expect(source).not.toMatch(/\bUPDATE\b/);
    expect(source).not.toMatch(/\bDELETE\b/);
    expect(source).not.toContain('$executeRaw');
    expect(source).not.toContain('createControlledFindingRepeatedObservationPersistence');
    expect(source).not.toContain('issueFindingRepeatedObservationAuthorization');
    expect(source).not.toContain('ORDER BY');
    expect(source).not.toContain('new Date');
    expect(source).not.toContain('process.env');
    expect(source).not.toContain('fetch(');
  });

  it('is not imported by production inspection, startup, web, or worker code', () => {
    const everywhere = [
      'loadControlledFindingLatestObservationSnapshot',
      'controlled-finding-latest-observation-read',
    ];
    const factory = 'createControlledFindingLatestObservationRead';
    const allowedFactory = 'apps/api/src/finding-runtime.ts';
    const roots = ['apps/api', 'apps/web', 'apps/worker', 'packages/database/src/seed'].map(
      (root) => path.join(repoRoot, root),
    );
    const offenders: string[] = [];
    for (const root of roots) {
      for (const filePath of walk(root)) {
        if (!filePath.endsWith('.ts') && !filePath.endsWith('.tsx')) {
          continue;
        }
        const relative = path.relative(repoRoot, filePath);
        const source = readFileSync(filePath, 'utf8');
        if (everywhere.some((needle) => source.includes(needle))) {
          offenders.push(relative);
        }
        if (source.includes(factory) && relative !== allowedFactory) {
          offenders.push(relative);
        }
      }
    }
    expect(offenders).toEqual([]);
    const runtime = readFileSync(path.join(repoRoot, allowedFactory), 'utf8');
    expect(runtime).toContain(factory);
    expect(runtime).toContain(
      '@patchpilot/database/controlled-finding-latest-observation-persistence',
    );
    expect(runtime).not.toContain('controlled-finding-latest-observation-read');
    expect(runtime).not.toContain('loadControlledFindingLatestObservationSnapshot');
    const closed = [
      'packages/database/src/index.ts',
      'packages/database/src/controlled-finding-persistence.ts',
      'packages/database/src/controlled-finding-inspection-persistence.ts',
      'packages/database/src/repositories.ts',
      'apps/api/src/server.ts',
      'apps/api/src/finding-routes.ts',
      'apps/api/src/finding-latest-observation-routes.ts',
      'packages/domain/src/index.ts',
      'packages/domain/src/findings/controlled-inspection/index.ts',
      'packages/domain/src/findings/controlled-inspection/service.ts',
      'packages/domain/src/findings/controlled-operator/permissions.ts',
    ];
    for (const relative of closed) {
      const source = readFileSync(path.join(repoRoot, relative), 'utf8');
      for (const needle of [...everywhere, factory]) {
        expect(source, `${relative} ${needle}`).not.toContain(needle);
      }
    }
    const permissions = readFileSync(
      path.join(repoRoot, 'packages/domain/src/findings/controlled-operator/permissions.ts'),
      'utf8',
    );
    expect(permissions).not.toContain('latest_observation');
    const writer = readFileSync(path.join(repoRoot, 'packages/database/src/index.ts'), 'utf8');
    expect(writer).not.toContain('createControlledFindingRepeatedObservationPersistence');
    expect(writer).not.toContain('issueFindingRepeatedObservationAuthorization');
  });
});
