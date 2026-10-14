import { readFileSync } from 'node:fs';

import { Prisma } from '@prisma/client';
import { describe, expect, it } from 'vitest';

import { classifyInstanceAdvisoryPersistenceFailure } from './instance-advisory-authority-persistence.js';

const PERSISTENCE_SOURCE = readFileSync(
  new URL('./instance-advisory-authority-persistence.ts', import.meta.url),
  'utf8',
);

describe('instance advisory persistence error translation', () => {
  it('does not treat every unique violation as replay', () => {
    expect(
      classifyInstanceAdvisoryPersistenceFailure(
        new Error(
          'Raw query failed. Code: `23505`. Message: duplicate key value violates unique constraint "instance_advisory_authority_grant_one_active_user_idx"',
        ),
      ),
    ).toBe('active_grant_unique');
    expect(
      classifyInstanceAdvisoryPersistenceFailure(
        new Error(
          'Raw query failed. Code: `23505`. Message: duplicate key value violates unique constraint "audit_event_system_replay_idx"',
        ),
      ),
    ).toBe('transaction_aborted');
  });

  it('keeps database unavailability distinct from a missing row', () => {
    expect(
      classifyInstanceAdvisoryPersistenceFailure(new Error("Can't reach database server")),
    ).toBe('database_unavailable');
    expect(
      classifyInstanceAdvisoryPersistenceFailure(new Error('Raw query failed. Code: `23503`')),
    ).toBe('transaction_aborted');
    expect(
      classifyInstanceAdvisoryPersistenceFailure(new Error('Raw query failed. Code: `40P01`')),
    ).toBe('concurrency_conflict');
    expect(classifyInstanceAdvisoryPersistenceFailure(new Error('unexpected'))).toBe(
      'internal_failure',
    );
    const known = new Prisma.PrismaClientKnownRequestError('closed', {
      code: 'P1001',
      clientVersion: 'test',
    });
    expect(classifyInstanceAdvisoryPersistenceFailure(known)).toBe('database_unavailable');
    const connector = new Prisma.PrismaClientUnknownRequestError(
      'Error in connector: Error querying the database: ERROR: instance advisory authority audit is incomplete',
      { clientVersion: 'test' },
    );
    expect(classifyInstanceAdvisoryPersistenceFailure(connector)).toBe('transaction_aborted');
  });

  it('keeps authorization snapshots atomic and collateral checks inside this transaction', () => {
    expect(PERSISTENCE_SOURCE).toContain('loadAuthorizationFactsInOneSnapshot');
    expect(PERSISTENCE_SOURCE).toContain('LEFT JOIN "instance_advisory_authority_grant"');
    expect(PERSISTENCE_SOURCE).toContain('xmin = pg_current_xact_id()::xid');
    expect(PERSISTENCE_SOURCE).not.toContain('function blankGrant');
    expect(PERSISTENCE_SOURCE).not.toContain('COUNT(*) FROM "organization")');
    expect(PERSISTENCE_SOURCE).not.toContain("set_config(${setting}, 'on', false)");
  });
});
