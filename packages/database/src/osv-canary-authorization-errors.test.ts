import { describe, expect, it } from 'vitest';

import { Prisma } from '@prisma/client';

import {
  classifyCanaryUniqueConflict,
  isUniqueViolation,
  translateCanaryAuthorizationFailure,
} from './osv-canary-authorization-errors.js';

function known(code: string, meta?: Record<string, unknown>): Prisma.PrismaClientKnownRequestError {
  if (meta === undefined) {
    return new Prisma.PrismaClientKnownRequestError('bounded', {
      code,
      clientVersion: 'test',
    });
  }
  return new Prisma.PrismaClientKnownRequestError('bounded', {
    code,
    clientVersion: 'test',
    meta,
  });
}

describe('OSV canary authorization error translation', () => {
  it('does not classify unique conflicts as already_applied', () => {
    const error = known('P2002', { target: ['id'] });
    expect(isUniqueViolation(error)).toBe(true);
    expect(translateCanaryAuthorizationFailure(error)).toBe('immutable_conflict');
  });

  it('classifies listing-review and consume-binding unique conflicts without leaking SQL', () => {
    const listing = known('P2010', {
      code: '23505',
      message:
        'duplicate key value violates unique constraint "osv_canary_authorization_listing_auth_uidx"',
    });
    expect(classifyCanaryUniqueConflict(listing)).toBe('listing_review');
    expect(JSON.stringify(listing.meta)).not.toEqual(classifyCanaryUniqueConflict(listing));
    const consume = known('P2010', {
      code: '23505',
      constraint: 'osv_canary_authorization_consumed_run_uidx',
    });
    expect(classifyCanaryUniqueConflict(consume)).toBe('consume_binding');
    expect(classifyCanaryUniqueConflict(known('P2002', { target: ['id'] }))).toBe('unclassified');
  });

  it('maps bounded failure classes without leaking SQL or secrets', () => {
    expect(translateCanaryAuthorizationFailure(known('P2003'))).toBe('foreign_key_conflict');
    expect(translateCanaryAuthorizationFailure(known('P2004'))).toBe('check_constraint_failure');
    expect(translateCanaryAuthorizationFailure(known('P2025'))).toBe('not_found');
    expect(translateCanaryAuthorizationFailure(known('P2010', { code: '23505' }))).toBe(
      'immutable_conflict',
    );
    expect(translateCanaryAuthorizationFailure(known('P2010', { code: '23514' }))).toBe(
      'check_constraint_failure',
    );
    expect(translateCanaryAuthorizationFailure(known('P2010', { code: '23503' }))).toBe(
      'foreign_key_conflict',
    );
    expect(translateCanaryAuthorizationFailure(known('P2010', { code: '40001' }))).toBe(
      'serialization_failure',
    );
    expect(translateCanaryAuthorizationFailure(known('P1001'))).toBe('database_unavailable');
    const leaked = new Error(
      'SELECT password FROM secret WHERE token=aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    );
    const mapped = translateCanaryAuthorizationFailure(leaked);
    expect(mapped).toBe('database_unavailable');
    expect(mapped).not.toContain('password');
    expect(JSON.stringify(mapped)).not.toContain('SELECT');
  });
});
