/**
 * HTTP translation for one asset-scoped Product Match candidate page.
 * Query organization identity is rejected. Package names and revision ids stay out of logs.
 */

import { PERMISSION_DENIED } from '@patchpilot/auth';
import type { AppError } from '@patchpilot/domain';
import type { FastifyRequest } from 'fastify';
import type { Logger } from '@patchpilot/logger';
import type { TrustedActor } from '@patchpilot/auth';

import { INVALID_REQUEST, PRODUCT_MATCH_CANDIDATE_UNAVAILABLE } from './http-errors.js';

export const PRODUCT_MATCH_CANDIDATE_ROUTE = '/assets/:assetId/product-match-candidates';

export const PRODUCT_MATCH_CANDIDATE_DEFAULT_LIMIT = 10;

export const PRODUCT_MATCH_CANDIDATE_MAX_CURSOR_LENGTH = 2048;

/**
 * Process-local peer ceiling. Each API process allows this many candidate
 * reads per direct socket peer per window. Several processes multiply the
 * ceiling. Restarting the process clears it. There is no Redis store.
 */
export const PRODUCT_MATCH_CANDIDATE_PEER_LIMIT = Object.freeze({
  max: 30,
  windowMs: 60_000,
});

/**
 * Process-local organization ceiling. Unauthorized requests do not consume it.
 * Several processes multiply the ceiling. Restarting the process clears it.
 */
export const PRODUCT_MATCH_CANDIDATE_ORGANIZATION_LIMIT = Object.freeze({
  max: 20,
  windowMs: 60_000,
});

export const PRODUCT_MATCH_CANDIDATE_NOT_FOUND: AppError = Object.freeze({
  code: 'not_found',
  message: 'Not found.',
});

export const PRODUCT_MATCH_CANDIDATE_STALE_CURSOR: AppError = Object.freeze({
  code: 'conflict',
  message: 'stale_cursor',
});

export const PRODUCT_MATCH_CANDIDATE_INTERNAL: AppError = Object.freeze({
  code: 'internal',
  message: 'An internal error occurred.',
});

export type ProductMatchCandidatePublicOutcome =
  | 'page'
  | 'validation'
  | 'unauthorized'
  | 'forbidden'
  | 'not_found'
  | 'conflict'
  | 'rate_limited'
  | 'unavailable'
  | 'internal';

export function productMatchCandidateFailureError(status: string): AppError {
  switch (status) {
    case 'invalid_request':
      return INVALID_REQUEST;
    case 'authority_required':
    case 'authority_rejected':
      return PERMISSION_DENIED;
    case 'not_found':
      return PRODUCT_MATCH_CANDIDATE_NOT_FOUND;
    case 'stale_cursor':
      return PRODUCT_MATCH_CANDIDATE_STALE_CURSOR;
    case 'database_unavailable':
      return PRODUCT_MATCH_CANDIDATE_UNAVAILABLE;
    default:
      return PRODUCT_MATCH_CANDIDATE_INTERNAL;
  }
}

export function productMatchCandidateOutcomeForError(
  error: AppError,
): ProductMatchCandidatePublicOutcome {
  switch (error.code) {
    case 'validation':
      return 'validation';
    case 'unauthorized':
      return 'unauthorized';
    case 'forbidden':
      return 'forbidden';
    case 'not_found':
      return 'not_found';
    case 'conflict':
      return 'conflict';
    case 'rate_limited':
      return 'rate_limited';
    case 'internal':
      return error.message === PRODUCT_MATCH_CANDIDATE_UNAVAILABLE.message
        ? 'unavailable'
        : 'internal';
    default:
      return 'internal';
  }
}

export function parseProductMatchCandidateQuery(
  url: string,
):
  | { readonly ok: true; readonly limit: number; readonly cursor: string | null }
  | { readonly ok: false } {
  const question = url.indexOf('?');
  if (question < 0) {
    return { ok: true, limit: PRODUCT_MATCH_CANDIDATE_DEFAULT_LIMIT, cursor: null };
  }
  const query = url.slice(question + 1).split('#')[0] ?? '';
  if (query.length === 0) {
    return { ok: true, limit: PRODUCT_MATCH_CANDIDATE_DEFAULT_LIMIT, cursor: null };
  }
  const seen = new Set<string>();
  let limit = PRODUCT_MATCH_CANDIDATE_DEFAULT_LIMIT;
  let cursor: string | null = null;
  for (const part of query.split('&')) {
    if (part.length === 0) {
      return { ok: false };
    }
    const separator = part.indexOf('=');
    const rawKey = separator < 0 ? part : part.slice(0, separator);
    const rawValue = separator < 0 ? '' : part.slice(separator + 1);
    let key: string;
    let value: string;
    try {
      key = decodeURIComponent(rawKey.replace(/\+/g, ' '));
      value = decodeURIComponent(rawValue.replace(/\+/g, ' '));
    } catch {
      return { ok: false };
    }
    if (seen.has(key)) {
      return { ok: false };
    }
    seen.add(key);
    if (key === 'limit') {
      if (!/^(?:[1-9]|1[0-9]|20)$/.test(value)) {
        return { ok: false };
      }
      limit = Number(value);
    } else if (key === 'cursor') {
      if (value.length === 0 || value.length > PRODUCT_MATCH_CANDIDATE_MAX_CURSOR_LENGTH) {
        return { ok: false };
      }
      cursor = value;
    } else {
      return { ok: false };
    }
  }
  return { ok: true, limit, cursor };
}

export function logProductMatchCandidateOutcome(
  logger: Logger,
  request: FastifyRequest,
  outcome: ProductMatchCandidatePublicOutcome,
  details?: { readonly limit: number; readonly candidateCount: number },
): void {
  logger.info(
    {
      route: PRODUCT_MATCH_CANDIDATE_ROUTE,
      outcome,
      requestId: request.requestId,
      correlationId: request.correlationId,
      ...(details === undefined
        ? {}
        : { limit: details.limit, candidateCount: details.candidateCount }),
    },
    'product match candidate outcome',
  );
}

export type ProductMatchCandidateActor = TrustedActor;
