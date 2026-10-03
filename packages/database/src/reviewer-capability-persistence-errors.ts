/**
 * Bounded Prisma error translation for durable reviewer capabilities.
 * Results omit SQL, constraint names, trigger names, and stacks.
 */

import { Prisma } from '@prisma/client';
import {
  DURABLE_REVIEWER_CAPABILITY_REJECTION_CODES,
  type DurableReviewerCapabilityRejectionCode,
} from '@patchpilot/vulnerability-intelligence';

const UNAVAILABLE_CODES = new Set(['P1000', 'P1001', 'P1002', 'P1003', 'P1017']);
const TIMEOUT_CODES = new Set(['P1008', 'P2024']);
const RAW_QUERY_FAILED = 'P2010';

function postgresSqlState(error: Prisma.PrismaClientKnownRequestError): string | undefined {
  const metaCode = error.meta?.['code'];
  return typeof metaCode === 'string' ? metaCode : undefined;
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : '';
}

function sqlState(error: unknown): string | undefined {
  if (error instanceof Prisma.PrismaClientKnownRequestError) {
    return postgresSqlState(error);
  }
  if (error instanceof Prisma.PrismaClientUnknownRequestError) {
    return /code: "([0-9A-Z]{5})"/.exec(error.message)?.[1];
  }
  return undefined;
}

export function isDurableCapabilityUniqueViolation(error: unknown): boolean {
  if (error instanceof Prisma.PrismaClientKnownRequestError) {
    if (error.code === 'P2002') {
      return true;
    }
    return error.code === RAW_QUERY_FAILED && postgresSqlState(error) === '23505';
  }
  return sqlState(error) === '23505';
}

export function translateDurableCapabilityFailure(
  error: unknown,
): DurableReviewerCapabilityRejectionCode {
  const message = messageOf(error);
  if (message.includes('reviewer_capability_expired')) {
    return 'authority_expired';
  }
  const state = sqlState(error);
  if (state === '23001' || message.includes('append-only table')) {
    return 'append_only_rejected';
  }
  if (state === '23505') {
    return 'unique_violation';
  }
  if (state === '23503') {
    return 'foreign_key_violation';
  }
  if (state === '23514' || state === '23P01') {
    return 'check_constraint_violation';
  }
  if (state === '40P01' || state === '40001') {
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
    return 'unique_violation';
  }
  if (error.code === 'P2034') {
    return 'stale_compare_and_swap';
  }
  if (UNAVAILABLE_CODES.has(error.code)) {
    return 'database_unavailable';
  }
  if (TIMEOUT_CODES.has(error.code)) {
    return 'timeout';
  }
  if (error.code === 'P2003' || postgresSqlState(error) === '23503') {
    return 'foreign_key_violation';
  }
  if (error.code === 'P2004' || error.code === 'P2011') {
    return 'check_constraint_violation';
  }
  if (error.code === 'P2028') {
    return 'transaction_aborted';
  }
  return 'internal_failure';
}

export function asDurableRejectionCode(code: string): DurableReviewerCapabilityRejectionCode {
  if ((DURABLE_REVIEWER_CAPABILITY_REJECTION_CODES as readonly string[]).includes(code)) {
    return code as DurableReviewerCapabilityRejectionCode;
  }
  return 'internal_failure';
}
