import { Prisma } from '@prisma/client';
import { describe, expect, it } from 'vitest';

import {
  isMaintainerReviewedApprovalUniqueViolation,
  translateMaintainerReviewedApprovalFailure,
} from './maintainer-reviewed-advisory-approval-persistence-errors.js';

describe('maintainer-reviewed approval error translation', () => {
  it('does not treat every unique violation as exact replay and omits database text', () => {
    const secret =
      'postgres://user:secret@database.internal/patchpilot constraint maintainer_reviewed_advisory_approval_replay_uidx';
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
    const appendOnly = new Prisma.PrismaClientUnknownRequestError(
      `ConnectorError(PostgresError { code: "23001", message: "${secret}" })`,
      { clientVersion: 'test' },
    );
    const check = new Prisma.PrismaClientKnownRequestError(secret, {
      code: 'P2010',
      clientVersion: 'test',
      meta: { code: '23514' },
    });
    expect(isMaintainerReviewedApprovalUniqueViolation(unique)).toBe(true);
    expect(translateMaintainerReviewedApprovalFailure(unique)).toBe('unique_violation');
    expect(translateMaintainerReviewedApprovalFailure(unique)).not.toBe('already_applied');
    expect(translateMaintainerReviewedApprovalFailure(foreignKey)).toBe('foreign_key_violation');
    expect(translateMaintainerReviewedApprovalFailure(unavailable)).toBe('database_unavailable');
    expect(translateMaintainerReviewedApprovalFailure(timeout)).toBe('timeout');
    expect(translateMaintainerReviewedApprovalFailure(aborted)).toBe('transaction_aborted');
    expect(translateMaintainerReviewedApprovalFailure(appendOnly)).toBe('append_only_rejected');
    expect(translateMaintainerReviewedApprovalFailure(check)).toBe('check_constraint_violation');
    expect(translateMaintainerReviewedApprovalFailure(new Error(secret))).toBe('internal_failure');
    expect(
      JSON.stringify({
        unique: translateMaintainerReviewedApprovalFailure(unique),
        appendOnly: translateMaintainerReviewedApprovalFailure(appendOnly),
      }),
    ).not.toContain('secret');
  });
});
