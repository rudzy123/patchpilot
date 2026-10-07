/**
 * Query boundary for controlled Finding inspection.
 * No database is opened. Synthetic identifiers only.
 */

import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { Prisma, type PrismaClient } from '@prisma/client';
import { describe, expect, it } from 'vitest';

import * as databasePublic from './index.js';
import { createControlledFindingInspectionPersistence } from './controlled-finding-inspection-persistence.js';

const ORG = '11111111-1111-4111-8111-111111111111';
const FINDING = '22222222-2222-4222-8222-222222222222';

describe('controlled finding inspection query boundary', () => {
  it('does not export the adapter from the database package', () => {
    expect(Object.keys(databasePublic).filter((name) => /finding/i.test(name))).toEqual([]);
    expect('createControlledFindingInspectionPersistence' in databasePublic).toBe(false);
  });

  it('scopes the lookup to the organization and hides absent rows', async () => {
    const queries: unknown[] = [];
    const writes: string[] = [];
    const prisma = {
      $transaction: async (callback: (tx: unknown) => Promise<unknown>) =>
        callback({
          $queryRaw: async () => [{ set_config: 'on' }],
          finding: {
            findFirst: async (args: unknown) => {
              queries.push(args);
              return null;
            },
            update: async () => {
              writes.push('update');
              return null;
            },
            create: async () => {
              writes.push('create');
              return null;
            },
          },
        }),
    } as unknown as PrismaClient;
    const reader = createControlledFindingInspectionPersistence(prisma);
    const absent = await reader.load({ organizationId: ORG, findingId: FINDING });
    expect(absent).toEqual({ status: 'not_found' });
    expect(queries).toEqual([
      expect.objectContaining({
        where: { organizationId: ORG, id: FINDING },
      }),
    ]);
    expect(writes).toEqual([]);
    expect(JSON.stringify(absent)).not.toContain(FINDING);
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
    const down = await createControlledFindingInspectionPersistence(unavailable).load({
      organizationId: ORG,
      findingId: FINDING,
    });
    const failed = await createControlledFindingInspectionPersistence(internal).load({
      organizationId: ORG,
      findingId: FINDING,
    });
    expect(down).toEqual({ status: 'database_unavailable' });
    expect(failed).toEqual({ status: 'internal_failure' });
    expect(JSON.stringify(down)).not.toContain('secret');
    expect(JSON.stringify(failed)).not.toContain('postgres://');
  });

  it('rejects a malformed identifier before opening a transaction', async () => {
    let transactions = 0;
    const prisma = {
      $transaction: async () => {
        transactions += 1;
        return { status: 'not_found' };
      },
    } as unknown as PrismaClient;
    const result = await createControlledFindingInspectionPersistence(prisma).load({
      organizationId: ORG,
      findingId: 'not-a-uuid',
    });
    expect(result).toEqual({ status: 'internal_failure' });
    expect(transactions).toBe(0);
  });

  it('does not write, call a provider, or call an evaluator', () => {
    const source = readFileSync(
      fileURLToPath(import.meta.url).replace(/\.test\.ts$/, '.ts'),
      'utf8',
    );
    expect(source).not.toContain('@patchpilot/vulnerability-intelligence');
    expect(source).not.toContain('fetch(');
    expect(source).not.toContain('evaluateReviewed');
    expect(source).not.toMatch(
      /\.(finding|findingObservation|findingCreationEvidenceLink|productMatchEvaluationEvidence)\s*\.\s*(create|update|delete|upsert)\(/,
    );
    expect(source).not.toContain('INSERT');
    expect(source).not.toContain('$executeRaw');
    expect(source).toContain("set_config('transaction_read_only', 'on', true)");
    expect(source).not.toContain('reviewerIdentity');
    expect(source).not.toContain('actorMembershipId');
    expect(source).not.toContain('sourceIdentity');
    expect(path.basename(fileURLToPath(import.meta.url))).toContain('inspection');
  });
});
