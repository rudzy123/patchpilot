import { Prisma } from '@prisma/client';
import { describe, expect, it } from 'vitest';

import { translateMatchEvaluationPersistenceFailure } from './match-evaluation-evidence-errors.js';

describe('match evaluation persistence error translation', () => {
  it('maps database failures to closed codes without echoing the driver message', () => {
    const secret =
      'postgres://user:secret@database.internal/patchpilot constraint match_evaluation_evidence';
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
      code: 'P2028',
      clientVersion: 'test',
    });
    expect(translateMatchEvaluationPersistenceFailure(foreignKey)).toBe('foreign_key_failure');
    expect(translateMatchEvaluationPersistenceFailure(unavailable)).toBe('database_unavailable');
    expect(translateMatchEvaluationPersistenceFailure(timeout)).toBe('timeout');
    expect(translateMatchEvaluationPersistenceFailure(aborted)).toBe('transaction_aborted');
    const check = new Prisma.PrismaClientKnownRequestError(secret, {
      code: 'P2010',
      clientVersion: 'test',
      meta: { code: '23514' },
    });
    const disagreement = new Prisma.PrismaClientKnownRequestError(secret, {
      code: 'P2010',
      clientVersion: 'test',
      meta: { code: '23P01' },
    });
    expect(translateMatchEvaluationPersistenceFailure(check)).toBe('check_constraint_failure');
    expect(translateMatchEvaluationPersistenceFailure(disagreement)).toBe('immutable_conflict');
    const unknownCheck = new Prisma.PrismaClientUnknownRequestError(
      `ConnectorError(PostgresError { code: "23514", message: "${secret}" })`,
      { clientVersion: 'test' },
    );
    expect(translateMatchEvaluationPersistenceFailure(unknownCheck)).toBe(
      'check_constraint_failure',
    );
    expect(translateMatchEvaluationPersistenceFailure(new Error(secret))).toBe('internal_failure');
    const encoded = JSON.stringify({
      foreignKey: translateMatchEvaluationPersistenceFailure(foreignKey),
      unavailable: translateMatchEvaluationPersistenceFailure(unavailable),
    });
    expect(encoded).not.toContain('secret');
    expect(encoded).not.toContain('match_evaluation_evidence');
    expect(encoded).not.toContain('postgres://');
  });
});
