/**
 * Session 13 Batch 2C bounded Prisma/PostgreSQL error translation for OSV
 * canary authorization adapters.
 *
 * Unique conflicts are never already_applied here. Callers reload the natural
 * key and compare immutable fields. Public results never include Prisma
 * objects, SQL, constraint names, credentials, tokens, or stacks.
 */

import { Prisma } from '@prisma/client';
import type { OsvCanaryAuthorizationRejectionCode } from '@patchpilot/vulnerability-intelligence';

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
  return typeof metaCode === 'string' ? metaCode : undefined;
}

export type CanaryUniqueConflictKind = 'listing_review' | 'consume_binding' | 'unclassified';

const LISTING_REVIEW_UNIQUE = new Set([
  'osv_canary_authorization_listing_auth_uidx',
  'osv_canary_authorization_listing_review_uidx',
  'listing_authorization_id',
  'listing_review_id',
]);
const CONSUME_BINDING_UNIQUE = new Set([
  'osv_canary_authorization_consumed_request_uidx',
  'osv_canary_authorization_consumed_run_uidx',
  'consumed_by_synchronization_request_id',
  'consumed_by_synchronization_run_id',
]);

function uniqueTokens(error: Prisma.PrismaClientKnownRequestError): readonly string[] {
  const tokens: string[] = [];
  const target = error.meta?.['target'];
  if (typeof target === 'string' && target.length > 0) {
    tokens.push(target);
  } else if (Array.isArray(target)) {
    for (const item of target) {
      if (typeof item === 'string' && item.length > 0) {
        tokens.push(item);
      }
    }
  }
  const constraint = error.meta?.['constraint'];
  if (typeof constraint === 'string' && constraint.length > 0) {
    tokens.push(constraint);
  }
  const metaMessage = error.meta?.['message'];
  if (typeof metaMessage === 'string') {
    for (const name of [...LISTING_REVIEW_UNIQUE, ...CONSUME_BINDING_UNIQUE]) {
      if (metaMessage.includes(name)) {
        tokens.push(name);
      }
    }
  }
  return tokens;
}

export function classifyCanaryUniqueConflict(error: unknown): CanaryUniqueConflictKind {
  if (!isUniqueViolation(error)) {
    return 'unclassified';
  }
  const tokens = uniqueTokens(error);
  if (tokens.some((token) => LISTING_REVIEW_UNIQUE.has(token))) {
    return 'listing_review';
  }
  if (tokens.some((token) => CONSUME_BINDING_UNIQUE.has(token))) {
    return 'consume_binding';
  }
  return 'unclassified';
}

export function isUniqueViolation(error: unknown): error is Prisma.PrismaClientKnownRequestError {
  if (!(error instanceof Prisma.PrismaClientKnownRequestError)) {
    return false;
  }
  if (error.code === 'P2002') {
    return true;
  }
  return error.code === RAW_QUERY_FAILED && postgresSqlState(error) === '23505';
}

export function isForeignKeyViolation(error: unknown): boolean {
  if (error instanceof Prisma.PrismaClientKnownRequestError && FOREIGN_KEY_CODES.has(error.code)) {
    return true;
  }
  return (
    error instanceof Prisma.PrismaClientKnownRequestError &&
    error.code === RAW_QUERY_FAILED &&
    postgresSqlState(error) === '23503'
  );
}

export function isCheckConstraintViolation(error: unknown): boolean {
  if (error instanceof Prisma.PrismaClientKnownRequestError && CHECK_CODES.has(error.code)) {
    return true;
  }
  return (
    error instanceof Prisma.PrismaClientKnownRequestError &&
    error.code === RAW_QUERY_FAILED &&
    postgresSqlState(error) === '23514'
  );
}

export function isRowNotFound(error: unknown): boolean {
  return error instanceof Prisma.PrismaClientKnownRequestError && NOT_FOUND_CODES.has(error.code);
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

export function isRestrictViolation(error: unknown): boolean {
  if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === RAW_QUERY_FAILED) {
    const metaCode = error.meta?.['code'];
    if (metaCode === 'restrict_violation' || metaCode === '23001') {
      return true;
    }
  }
  const message = error instanceof Error ? error.message : '';
  return message.includes('restrict_violation');
}

export function translateCanaryAuthorizationFailure(
  error: unknown,
): OsvCanaryAuthorizationRejectionCode {
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
