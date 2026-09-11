import { describe, expect, it } from 'vitest';

import { Prisma } from '@prisma/client';

import {
  classifyProviderContactUniqueConflict,
  isUniqueViolation,
  translateProviderContactAuthorizationFailure,
} from './osv-listing-provider-contact-authorization-errors.js';

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

describe('OSV listing provider-contact authorization error translation', () => {
  it('does not classify unique conflicts as already_applied', () => {
    const error = known('P2002', { target: ['id'] });
    expect(isUniqueViolation(error)).toBe(true);
    expect(translateProviderContactAuthorizationFailure(error)).toBe('immutable_conflict');
    expect(classifyProviderContactUniqueConflict(error)).toBe('identity');
  });

  it('classifies source, request, run, preflight, and consume-binding uniqueness', () => {
    expect(
      classifyProviderContactUniqueConflict(
        known('P2010', {
          code: '23505',
          constraint: 'osv_listing_provider_contact_source_uidx',
        }),
      ),
    ).toBe('source');
    expect(
      classifyProviderContactUniqueConflict(
        known('P2010', {
          code: '23505',
          constraint: 'osv_listing_provider_contact_consumed_run_uidx',
        }),
      ),
    ).toBe('consume_binding');
    expect(
      classifyProviderContactUniqueConflict(known('P2002', { target: ['preflight_evidence_id'] })),
    ).toBe('preflight');
    expect(
      classifyProviderContactUniqueConflict(
        new Prisma.PrismaClientKnownRequestError(
          'Raw query failed. Code: `23505`. Message: `duplicate key value violates unique constraint "osv_listing_provider_contact_request_uidx"`',
          {
            code: 'P2010',
            clientVersion: 'test',
            meta: { code: '23505' },
          },
        ),
      ),
    ).toBe('request');
  });

  it('maps bounded failure classes without leaking SQL or secrets', () => {
    expect(translateProviderContactAuthorizationFailure(known('P2003'))).toBe(
      'foreign_key_conflict',
    );
    expect(translateProviderContactAuthorizationFailure(known('P2004'))).toBe(
      'check_constraint_failure',
    );
    expect(translateProviderContactAuthorizationFailure(known('P2025'))).toBe(
      'authorization_not_found',
    );
    expect(translateProviderContactAuthorizationFailure(known('P2010', { code: '23514' }))).toBe(
      'check_constraint_failure',
    );
    expect(translateProviderContactAuthorizationFailure(known('P2010', { code: '40001' }))).toBe(
      'serialization_failure',
    );
    expect(translateProviderContactAuthorizationFailure(known('P1001'))).toBe(
      'database_unavailable',
    );
    const leaked = new Error(
      'SELECT password FROM secret WHERE token=aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
    );
    const mapped = translateProviderContactAuthorizationFailure(leaked);
    expect(mapped).toBe('database_unavailable');
    expect(mapped).not.toContain('password');
    expect(JSON.stringify(mapped)).not.toContain('SELECT');
  });
});
