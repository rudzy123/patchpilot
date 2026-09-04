/**
 * Session 11 Batch 5D bounded Prisma/PostgreSQL error translation.
 *
 * Unique conflicts are never classified as already_applied here. Callers must
 * reload the natural key and compare immutable fields. Public results never
 * include Prisma objects, SQL, constraint names, provider keys, or stacks.
 */

import { Prisma } from '@prisma/client';
import type { OsvPersistenceRejectionCode } from '@patchpilot/vulnerability-intelligence';

export type OsvUniqueConflictClass = 'natural_key' | 'absent_or_unusable_meta' | 'unrelated';

const UNAVAILABLE_CODES = new Set(['P1000', 'P1001', 'P1017']);
const SERIALIZATION_CODES = new Set(['P2034']);
const NOT_FOUND_CODES = new Set(['P2025']);
const FOREIGN_KEY_CODES = new Set(['P2003']);
const CHECK_CODES = new Set(['P2004', 'P2011']);

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
): OsvUniqueConflictClass {
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

export function isUnsatisfiableRegexConstraint(error: unknown): boolean {
  if (!(error instanceof Prisma.PrismaClientUnknownRequestError)) {
    return false;
  }
  return error.message.includes('2201B') || error.message.includes('invalid regular expression');
}

export function translateDatabaseFailure(error: unknown): OsvPersistenceRejectionCode {
  if (isUniqueViolation(error)) {
    return 'immutable_conflict';
  }
  if (isForeignKeyViolation(error)) {
    return 'scope_mismatch';
  }
  if (isCheckConstraintViolation(error) || isUnsatisfiableRegexConstraint(error)) {
    return 'invalid_field';
  }
  if (isRowNotFound(error)) {
    return 'invalid_state';
  }
  if (isSerializationConflict(error)) {
    return 'stale_pointer';
  }
  if (isTransactionAborted(error)) {
    return 'stale_pointer';
  }
  if (isDatabaseUnavailable(error)) {
    return 'invalid_state';
  }
  return 'invalid_state';
}

export function tokensInclude(tokens: readonly string[], candidates: readonly string[]): boolean {
  const set = new Set(tokens);
  return candidates.some((candidate) => set.has(candidate));
}
