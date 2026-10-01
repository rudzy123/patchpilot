import { Prisma } from '@prisma/client';
import { describe, expect, it } from 'vitest';

import {
  isAdvisoryRevisionUniqueViolation,
  translateAdvisoryRevisionPersistenceFailure,
} from './advisory-revision-persistence-errors.js';

describe('advisory revision persistence error translation', () => {
  it('maps database failures to closed codes without echoing SQL or constraint names', () => {
    const secret =
      'postgres://user:secret@database.internal/patchpilot constraint advisory_revision_digest_uidx';
    const unique = new Prisma.PrismaClientKnownRequestError(secret, {
      code: 'P2002',
      clientVersion: 'test',
    });
    const foreignKey = new Prisma.PrismaClientKnownRequestError(secret, {
      code: 'P2003',
      clientVersion: 'test',
    });
    const unavailable = new Prisma.PrismaClientKnownRequestError(secret, {
      code: 'P1001',
      clientVersion: 'test',
    });
    const timeout = new Prisma.PrismaClientKnownRequestError(secret, {
      code: 'P2024',
      clientVersion: 'test',
    });
    const aborted = new Prisma.PrismaClientKnownRequestError(secret, {
      code: 'P2034',
      clientVersion: 'test',
    });
    expect(isAdvisoryRevisionUniqueViolation(unique)).toBe(true);
    expect(translateAdvisoryRevisionPersistenceFailure(unique)).toBe('unique_violation');
    expect(translateAdvisoryRevisionPersistenceFailure(foreignKey)).toBe('foreign_key_violation');
    expect(translateAdvisoryRevisionPersistenceFailure(unavailable)).toBe('database_unavailable');
    expect(translateAdvisoryRevisionPersistenceFailure(timeout)).toBe('timeout');
    expect(translateAdvisoryRevisionPersistenceFailure(aborted)).toBe('transaction_aborted');
    const appendOnly = new Prisma.PrismaClientUnknownRequestError(
      `ConnectorError(PostgresError { code: "23001", message: "${secret}" })`,
      { clientVersion: 'test' },
    );
    const check = new Prisma.PrismaClientKnownRequestError(secret, {
      code: 'P2010',
      clientVersion: 'test',
      meta: { code: '23514' },
    });
    expect(translateAdvisoryRevisionPersistenceFailure(appendOnly)).toBe('append_only_rejected');
    expect(translateAdvisoryRevisionPersistenceFailure(check)).toBe('check_constraint_violation');
    expect(translateAdvisoryRevisionPersistenceFailure(new Error(secret))).toBe('internal_failure');
    const encoded = JSON.stringify({
      unique: translateAdvisoryRevisionPersistenceFailure(unique),
      appendOnly: translateAdvisoryRevisionPersistenceFailure(appendOnly),
    });
    expect(encoded).not.toContain('secret');
    expect(encoded).not.toContain('advisory_revision');
    expect(encoded).not.toContain('postgres://');
    expect(encoded).not.toBe('already_applied');
  });
});
