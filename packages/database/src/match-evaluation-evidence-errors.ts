/**
 * Bounded Prisma error translation for match-evaluation evidence.
 * Public results never include SQL, constraint names, Prisma objects, or stacks.
 */

import { Prisma } from '@prisma/client';
import type { MatchEvaluationPersistenceRejectionCode } from '@patchpilot/vulnerability-intelligence';

const UNAVAILABLE_CODES = new Set(['P1000', 'P1001', 'P1002', 'P1003', 'P1017']);
const TIMEOUT_CODES = new Set(['P1008', 'P2024']);
const FOREIGN_KEY_CODES = new Set(['P2003']);
const CHECK_CODES = new Set(['P2004', 'P2011']);
const RAW_QUERY_FAILED = 'P2010';

function postgresSqlState(error: Prisma.PrismaClientKnownRequestError): string | undefined {
  const metaCode = error.meta?.['code'];
  return typeof metaCode === 'string' ? metaCode : undefined;
}

function unknownRequestSqlState(error: unknown): string | undefined {
  if (!(error instanceof Prisma.PrismaClientUnknownRequestError)) {
    return undefined;
  }
  const match = /code: "([0-9A-Z]{5})"/.exec(error.message);
  return match?.[1];
}

function sqlState(error: unknown): string | undefined {
  if (error instanceof Prisma.PrismaClientKnownRequestError) {
    return postgresSqlState(error);
  }
  return unknownRequestSqlState(error);
}

export function isMatchEvaluationUniqueViolation(
  error: unknown,
): error is Prisma.PrismaClientKnownRequestError {
  if (!(error instanceof Prisma.PrismaClientKnownRequestError)) {
    return false;
  }
  if (error.code === 'P2002') {
    return true;
  }
  return error.code === RAW_QUERY_FAILED && postgresSqlState(error) === '23505';
}

export function translateMatchEvaluationPersistenceFailure(
  error: unknown,
): MatchEvaluationPersistenceRejectionCode {
  const state = sqlState(error);
  if (state === '23P01') {
    return 'immutable_conflict';
  }
  if (state === '23503') {
    return 'foreign_key_failure';
  }
  if (state === '23514' || state === '23001') {
    return 'check_constraint_failure';
  }
  if (state === '40001') {
    return 'transaction_aborted';
  }
  if (!(error instanceof Prisma.PrismaClientKnownRequestError)) {
    if (
      error instanceof Prisma.PrismaClientInitializationError ||
      error instanceof Prisma.PrismaClientRustPanicError
    ) {
      return 'database_unavailable';
    }
    return 'internal_failure';
  }
  if (UNAVAILABLE_CODES.has(error.code)) {
    return 'database_unavailable';
  }
  if (TIMEOUT_CODES.has(error.code)) {
    return 'timeout';
  }
  if (FOREIGN_KEY_CODES.has(error.code) || postgresSqlState(error) === '23503') {
    return 'foreign_key_failure';
  }
  if (
    CHECK_CODES.has(error.code) ||
    postgresSqlState(error) === '23514' ||
    postgresSqlState(error) === '23001' ||
    error.code === 'P2010'
  ) {
    return 'check_constraint_failure';
  }
  if (error.code === 'P2028' || error.code === 'P2034' || postgresSqlState(error) === '40001') {
    return 'transaction_aborted';
  }
  return 'internal_failure';
}
