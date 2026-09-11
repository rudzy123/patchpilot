/**
 * Session 13 Batch 3D-A bounded Prisma/PostgreSQL error translation for
 * protected listing-observation evidence adapters. Unique conflicts are
 * never already_applied here. Public results never include Prisma objects,
 * SQL, constraint names, credentials, tokens, ciphertext, or stacks.
 */

import { Prisma } from '@prisma/client';
import type { OsvListingObservationEvidencePersistenceRejectionCode } from '@patchpilot/vulnerability-intelligence';

const UNAVAILABLE_CODES = new Set(['P1000', 'P1001', 'P1017']);
const SERIALIZATION_CODES = new Set(['P2034']);
const NOT_FOUND_CODES = new Set(['P2025']);
const FOREIGN_KEY_CODES = new Set(['P2003']);
const CHECK_CODES = new Set(['P2004', 'P2011']);
const RAW_QUERY_FAILED = 'P2010';

function postgresSqlState(error: unknown): string | undefined {
  if (!(error instanceof Prisma.PrismaClientKnownRequestError)) {
    return undefined;
  }
  const metaCode = error.meta?.['code'];
  if (typeof metaCode === 'string' && metaCode.length > 0) {
    return metaCode;
  }
  const match = /Code:\s*`([A-Z0-9]+)`/.exec(error.message);
  return match?.[1];
}

export function isUniqueViolation(error: unknown): boolean {
  if (!(error instanceof Prisma.PrismaClientKnownRequestError) || error.code !== 'P2002') {
    const sqlState = postgresSqlState(error);
    return sqlState === '23505';
  }
  return true;
}

export function isForeignKeyViolation(error: unknown): boolean {
  if (error instanceof Prisma.PrismaClientKnownRequestError && FOREIGN_KEY_CODES.has(error.code)) {
    return true;
  }
  return postgresSqlState(error) === '23503';
}

export function isCheckConstraintViolation(error: unknown): boolean {
  if (error instanceof Prisma.PrismaClientKnownRequestError && CHECK_CODES.has(error.code)) {
    return true;
  }
  const sqlState = postgresSqlState(error);
  return sqlState === '23514';
}

export function isRestrictViolation(error: unknown): boolean {
  if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === RAW_QUERY_FAILED) {
    const metaCode = error.meta?.['code'];
    if (metaCode === 'restrict_violation' || metaCode === '23001') {
      return true;
    }
  }
  const sqlState = postgresSqlState(error);
  return sqlState === '23001' || sqlState === 'P0001';
}

export function isSerializationConflict(error: unknown): boolean {
  if (
    error instanceof Prisma.PrismaClientKnownRequestError &&
    SERIALIZATION_CODES.has(error.code)
  ) {
    return true;
  }
  const sqlState = postgresSqlState(error);
  return sqlState === '40001' || sqlState === '40P01';
}

export function isDatabaseUnavailable(error: unknown): boolean {
  if (error instanceof Prisma.PrismaClientInitializationError) {
    return true;
  }
  if (error instanceof Prisma.PrismaClientRustPanicError) {
    return true;
  }
  return error instanceof Prisma.PrismaClientKnownRequestError && UNAVAILABLE_CODES.has(error.code);
}

export function isTransactionAborted(error: unknown): boolean {
  if (!(error instanceof Prisma.PrismaClientKnownRequestError)) {
    return false;
  }
  return error.code === 'P2028' || error.code === 'P2034' || error.message.includes('aborted');
}

export function isRowNotFound(error: unknown): boolean {
  return error instanceof Prisma.PrismaClientKnownRequestError && NOT_FOUND_CODES.has(error.code);
}

export function translateListingObservationEvidenceFailure(
  error: unknown,
): OsvListingObservationEvidencePersistenceRejectionCode {
  if (isUniqueViolation(error)) {
    return 'immutable_conflict';
  }
  if (isForeignKeyViolation(error)) {
    return 'foreign_key_conflict';
  }
  if (isCheckConstraintViolation(error)) {
    return 'check_constraint_failure';
  }
  if (isRowNotFound(error)) {
    return 'authorization_not_found';
  }
  if (isSerializationConflict(error) || isTransactionAborted(error)) {
    return 'serialization_failure';
  }
  if (isRestrictViolation(error)) {
    return 'state_conflict';
  }
  if (isDatabaseUnavailable(error)) {
    return 'database_unavailable';
  }
  return 'database_unavailable';
}
