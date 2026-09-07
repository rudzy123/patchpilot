/**
 * Session 12 Batch 7 bounded Prisma/PostgreSQL error translation for OSV
 * runtime coordination adapters.
 *
 * Unique conflicts are never already_applied here. Callers reload the natural
 * key and compare immutable fields. Public results never include Prisma
 * objects, SQL, constraint names, holder tokens, digests, or stacks.
 */

import { Prisma } from '@prisma/client';
import type { OsvRuntimeCoordinationRejectionCode } from '@patchpilot/vulnerability-intelligence';

export type RuntimeUniqueConflictClass = 'natural_key' | 'absent_or_unusable_meta' | 'unrelated';

const UNAVAILABLE_CODES = new Set(['P1000', 'P1001', 'P1017']);
const SERIALIZATION_CODES = new Set(['P2034']);
const NOT_FOUND_CODES = new Set(['P2025']);
const FOREIGN_KEY_CODES = new Set(['P2003']);
const CHECK_CODES = new Set(['P2004', 'P2011']);
const RAW_QUERY_FAILED = 'P2010';

export function uniqueTargetTokens(error: Prisma.PrismaClientKnownRequestError): readonly string[] {
  const target = error.meta?.['target'];
  if (typeof target === 'string') {
    return target.length === 0 ? [] : [target];
  }
  if (Array.isArray(target)) {
    return target.map(String).filter((token) => token.length > 0);
  }
  return [];
}

export function classifyUniqueConflict(
  error: Prisma.PrismaClientKnownRequestError,
  isNaturalKey: (tokens: readonly string[]) => boolean,
): RuntimeUniqueConflictClass {
  const tokens = uniqueTargetTokens(error);
  if (isNaturalKey(tokens)) {
    return 'natural_key';
  }
  if (tokens.length === 0) {
    return 'absent_or_unusable_meta';
  }
  return 'unrelated';
}

export function isUniqueViolation(error: unknown): error is Prisma.PrismaClientKnownRequestError {
  return error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002';
}

export function isForeignKeyViolation(error: unknown): boolean {
  return error instanceof Prisma.PrismaClientKnownRequestError && FOREIGN_KEY_CODES.has(error.code);
}

export function isCheckConstraintViolation(error: unknown): boolean {
  return error instanceof Prisma.PrismaClientKnownRequestError && CHECK_CODES.has(error.code);
}

export function isRowNotFound(error: unknown): boolean {
  return error instanceof Prisma.PrismaClientKnownRequestError && NOT_FOUND_CODES.has(error.code);
}

export function isSerializationConflict(error: unknown): boolean {
  return (
    error instanceof Prisma.PrismaClientKnownRequestError && SERIALIZATION_CODES.has(error.code)
  );
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

export function isRestrictViolation(error: unknown): boolean {
  if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === RAW_QUERY_FAILED) {
    const metaCode = error.meta?.['code'];
    if (metaCode === 'restrict_violation' || metaCode === '23001') {
      return true;
    }
  }
  const message = error instanceof Error ? error.message : '';
  return message.includes('restrict_violation') || message.includes('fencing token');
}

export function isNumericOverflow(error: unknown): boolean {
  const message = error instanceof Error ? error.message : '';
  return (
    message.includes('numeric_value_out_of_range') ||
    message.includes('integer out of range') ||
    message.includes('22003')
  );
}

export function translateRuntimeCoordinationFailure(
  error: unknown,
): OsvRuntimeCoordinationRejectionCode {
  if (isUniqueViolation(error)) {
    return 'immutable_conflict';
  }
  if (isForeignKeyViolation(error)) {
    return 'foreign_key_conflict';
  }
  if (isCheckConstraintViolation(error) || isNumericOverflow(error)) {
    return isNumericOverflow(error) ? 'lease_integer_overflow' : 'check_constraint_failure';
  }
  if (isRowNotFound(error)) {
    return 'not_found';
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

export function tokensInclude(tokens: readonly string[], candidates: readonly string[]): boolean {
  const lowered = tokens.map((token) => token.toLowerCase());
  return candidates.some((candidate) => lowered.some((token) => token.includes(candidate)));
}
