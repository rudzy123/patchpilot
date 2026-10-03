/**
 * Bounded Prisma error translation for product-match evaluation.
 * Results omit SQL, constraint names, trigger names, and stacks.
 */

import { Prisma } from '@prisma/client';
import type { ProductMatchEvaluationRejectionCode } from '@patchpilot/vulnerability-intelligence';

const UNAVAILABLE_CODES = new Set(['P1000', 'P1001', 'P1002', 'P1003', 'P1017']);
const TIMEOUT_CODES = new Set(['P1008', 'P2024']);
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

export function isProductMatchUniqueViolation(error: unknown): boolean {
  if (error instanceof Prisma.PrismaClientKnownRequestError) {
    if (error.code === 'P2002') {
      return true;
    }
    return error.code === RAW_QUERY_FAILED && postgresSqlState(error) === '23505';
  }
  return sqlState(error) === '23505';
}

export function translateProductMatchFailure(error: unknown): ProductMatchEvaluationRejectionCode {
  const state = sqlState(error);
  if (state === '23505') {
    return 'immutable_conflict';
  }
  if (state === '23503') {
    return 'foreign_key_failure';
  }
  if (state === '23514' || state === '23P01' || state === '23001') {
    return 'check_constraint_failure';
  }
  if (state === '40001' || state === '40P01') {
    return 'transaction_aborted';
  }
  if (
    error instanceof Prisma.PrismaClientInitializationError ||
    error instanceof Prisma.PrismaClientRustPanicError
  ) {
    return 'database_unavailable';
  }
  if (!(error instanceof Prisma.PrismaClientKnownRequestError)) {
    return 'internal_failure';
  }
  if (error.code === 'P2002') {
    return 'immutable_conflict';
  }
  if (UNAVAILABLE_CODES.has(error.code)) {
    return 'database_unavailable';
  }
  if (TIMEOUT_CODES.has(error.code)) {
    return 'timeout';
  }
  if (error.code === 'P2003') {
    return 'foreign_key_failure';
  }
  if (error.code === 'P2028') {
    return 'transaction_aborted';
  }
  return 'internal_failure';
}
