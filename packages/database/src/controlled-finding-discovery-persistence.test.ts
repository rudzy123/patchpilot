/**
 * Source boundary for the read-only discovery adapter.
 */

import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { Prisma, type PrismaClient } from '@prisma/client';
import { describe, expect, it } from 'vitest';

import { createControlledFindingDiscoveryPersistence } from './controlled-finding-discovery-persistence.js';

const source = readFileSync(
  path.join(
    path.dirname(fileURLToPath(import.meta.url)),
    'controlled-finding-discovery-persistence.ts',
  ),
  'utf8',
);

describe('controlled finding discovery persistence source', () => {
  it('is a repeatable read-only query and does not write or lock creation', () => {
    expect(source).toContain("set_config('transaction_read_only', 'on', true)");
    expect(source).toContain("set_config('statement_timeout', '2000', true)");
    expect(source).toContain('RepeatableRead');
    expect(source).toContain('patchpilot_finding_creation_qualifying_evidence');
    expect(source).not.toMatch(/INSERT\s+INTO/i);
    expect(source).not.toMatch(/UPDATE\s+"/i);
    expect(source).not.toMatch(/DELETE\s+FROM/i);
    expect(source).not.toContain('FOR UPDATE');
    expect(source).not.toContain('pg_advisory');
    expect(source).not.toContain("set_config('patchpilot.controlled_finding_creation'");
    expect(source).not.toContain('issueFindingCreationAuthorization');
    expect(source).not.toContain('createControlledFindingCreationApplication');
    expect(source).toContain('organization."status"::text AS organization_status');
    expect(source).toContain("role === 'owner' || role === 'admin'");
    expect(source).toContain('P1001');
  });

  it('translates database outages without echoing the driver target', async () => {
    const secret = 'postgres://user:secret@database.internal/patchpilot';
    const organizationId = '11111111-1111-4111-8111-111111111111';
    const membershipId = '22222222-2222-4222-8222-222222222222';
    const actorId = '33333333-3333-4333-8333-333333333333';
    const assetId = '44444444-4444-4444-8444-444444444444';
    const query = {
      organizationId,
      membershipId,
      actorId,
      assetId,
      cursor: null,
    };
    const unavailable = createControlledFindingDiscoveryPersistence({
      $transaction: async () => {
        throw new Prisma.PrismaClientKnownRequestError(secret, {
          code: 'P1001',
          clientVersion: 'test',
        });
      },
    } as unknown as PrismaClient);
    const timedOut = createControlledFindingDiscoveryPersistence({
      $transaction: async () => {
        throw new Error(`${secret} canceling statement due to statement timeout`);
      },
    } as unknown as PrismaClient);
    const internal = createControlledFindingDiscoveryPersistence({
      $transaction: async () => {
        throw new Error(secret);
      },
    } as unknown as PrismaClient);
    const down = await unavailable.read(query);
    const timeout = await timedOut.read(query);
    const failed = await internal.read(query);
    expect(down).toEqual({ status: 'database_unavailable' });
    expect(timeout).toEqual({ status: 'database_unavailable' });
    expect(failed).toEqual({ status: 'internal_failure' });
    expect(JSON.stringify(down)).not.toContain('secret');
    expect(JSON.stringify(down)).not.toContain('postgres://');
    expect(JSON.stringify(timeout)).not.toContain(secret);
    expect(JSON.stringify(failed)).not.toContain(secret);
  });
});
