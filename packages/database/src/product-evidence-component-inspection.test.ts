/**
 * Session 15 Batch 3-R component-inspection query boundary.
 * No database is opened. Synthetic identifiers only.
 */

import type { PrismaClient } from '@prisma/client';
import { describe, expect, it } from 'vitest';

import { createProductEvidenceComponentInspection } from './product-evidence-component-inspection.js';

const ORG = '11111111-1111-4111-8111-111111111111';
const OCC = '22222222-2222-4222-8222-222222222222';

describe('product-evidence component inspection query boundary', () => {
  it('rejects a non-v4 identifier and a getter before any query', async () => {
    let transactions = 0;
    const prisma = {
      $transaction: async () => {
        transactions += 1;
        throw new Error('postgres://secret');
      },
    } as unknown as PrismaClient;
    const reader = createProductEvidenceComponentInspection(prisma);
    const malformed = await reader.inspectTenantOccurrence({
      organizationId: 'not-a-uuid',
      componentOccurrenceId: OCC,
    });
    expect(malformed).toEqual({ kind: 'rejected', code: 'malformed_persisted_state' });
    const host = { organizationId: ORG, componentOccurrenceId: OCC };
    Object.defineProperty(host, 'organizationId', { get: () => ORG });
    const getter = await reader.inspectTenantOccurrence(host);
    expect(getter).toEqual({ kind: 'rejected', code: 'malformed_persisted_state' });
    expect(transactions).toBe(0);
    expect(JSON.stringify(malformed)).not.toContain('postgres://');
  });

  it('scopes the occurrence read to the supplied organization and hides query failures', async () => {
    const queries: unknown[] = [];
    const prisma = {
      $transaction: async (callback: (tx: unknown) => Promise<unknown>) =>
        callback({
          componentOccurrence: {
            findFirst: async (args: unknown) => {
              queries.push(args);
              throw new Error('postgres://secret SELECT left-pad');
            },
          },
        }),
    } as unknown as PrismaClient;
    const reader = createProductEvidenceComponentInspection(prisma);
    const result = await reader.inspectTenantOccurrence({
      organizationId: ORG,
      componentOccurrenceId: OCC,
    });
    expect(result).toEqual({ kind: 'rejected', code: 'database_unavailable' });
    expect(JSON.stringify(result)).not.toContain('postgres://');
    expect(JSON.stringify(result)).not.toContain('left-pad');
    expect(queries).toEqual([
      {
        where: { organizationId: ORG, id: OCC },
        select: {
          id: true,
          organizationId: true,
          assetId: true,
          sbomId: true,
          sbomIngestionId: true,
          componentId: true,
          version: true,
          versionKnown: true,
        },
      },
    ]);
  });
});
