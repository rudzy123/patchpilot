import { describe, expect, it } from 'vitest';

import { Prisma } from '@prisma/client';

import {
  classifyUniqueConflict,
  isUniqueViolation,
  translateRuntimeCoordinationFailure,
  uniqueTargetTokens,
} from './osv-runtime-coordination-errors.js';

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

describe('OSV runtime coordination error translation', () => {
  it('does not classify unique conflicts as already_applied', () => {
    const error = known('P2002', { target: ['operator_request_id'] });
    expect(isUniqueViolation(error)).toBe(true);
    expect(translateRuntimeCoordinationFailure(error)).toBe('immutable_conflict');
    expect(uniqueTargetTokens(error)).toEqual(['operator_request_id']);
    expect(classifyUniqueConflict(error, (tokens) => tokens.includes('operator_request_id'))).toBe(
      'natural_key',
    );
  });

  it('maps bounded failure classes without leaking SQL or holder tokens', () => {
    expect(translateRuntimeCoordinationFailure(known('P2003'))).toBe('foreign_key_conflict');
    expect(translateRuntimeCoordinationFailure(known('P2004'))).toBe('check_constraint_failure');
    expect(translateRuntimeCoordinationFailure(known('P2025'))).toBe('not_found');
    expect(translateRuntimeCoordinationFailure(known('P2034'))).toBe('serialization_failure');
    expect(translateRuntimeCoordinationFailure(known('P1001'))).toBe('database_unavailable');
    expect(
      translateRuntimeCoordinationFailure(
        known('P2010', { code: 'restrict_violation', message: 'osv runtime lease fencing token' }),
      ),
    ).toBe('state_conflict');
    const overflow = new Error('integer out of range 22003');
    expect(translateRuntimeCoordinationFailure(overflow)).toBe('lease_integer_overflow');
    const leaked = new Error(
      'SELECT holder_token FROM secret WHERE token=44444444-4444-4444-8444-444444444444',
    );
    const mapped = translateRuntimeCoordinationFailure(leaked);
    expect(mapped).toBe('database_unavailable');
    expect(mapped).not.toContain('holder');
    expect(mapped).not.toContain('44444444');
    expect(JSON.stringify(mapped)).not.toContain('SELECT');
  });
});
