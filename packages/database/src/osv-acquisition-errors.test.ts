import { describe, expect, it } from 'vitest';

import { Prisma } from '@prisma/client';

import {
  classifyUniqueConflict,
  isUniqueViolation,
  translateDatabaseFailure,
  uniqueTargetTokens,
} from './osv-acquisition-errors.js';

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

describe('OSV database error translation', () => {
  it('does not classify unique conflicts as already_applied', () => {
    const error = known('P2002', { target: ['provider_object_id', 'provider_generation'] });
    expect(isUniqueViolation(error)).toBe(true);
    expect(translateDatabaseFailure(error)).toBe('immutable_conflict');
    expect(uniqueTargetTokens(error)).toEqual(['provider_object_id', 'provider_generation']);
    expect(classifyUniqueConflict(error, (tokens) => tokens.includes('provider_generation'))).toBe(
      'natural_key',
    );
    expect(classifyUniqueConflict(known('P2002', {}), () => false)).toBe('absent_or_unusable_meta');
    expect(classifyUniqueConflict(known('P2002', { target: ['id'] }), () => false)).toBe(
      'unrelated',
    );
  });

  it('maps bounded failure classes without leaking SQL', () => {
    expect(translateDatabaseFailure(known('P2003'))).toBe('scope_mismatch');
    expect(translateDatabaseFailure(known('P2004'))).toBe('invalid_field');
    expect(translateDatabaseFailure(known('P2025'))).toBe('invalid_state');
    expect(translateDatabaseFailure(known('P2034'))).toBe('stale_pointer');
    expect(translateDatabaseFailure(known('P1001'))).toBe('invalid_state');
    expect(translateDatabaseFailure(new Error('SELECT * FROM secret'))).toBe('invalid_state');
    expect(
      translateDatabaseFailure(
        new Prisma.PrismaClientUnknownRequestError(
          'ConnectorError code: 2201B invalid regular expression',
          { clientVersion: 'test' },
        ),
      ),
    ).toBe('invalid_field');
    expect(
      String(translateDatabaseFailure(known('P2002', { target: 'osv_provider_object_key_uidx' }))),
    ).not.toContain('osv_provider_object');
  });
});
