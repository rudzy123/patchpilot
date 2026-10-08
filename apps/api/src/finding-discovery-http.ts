/**
 * HTTP translation for controlled Finding target discovery.
 * Query organization identity is rejected. The cursor stays out of logs.
 */

import { PERMISSION_DENIED } from '@patchpilot/auth';
import type { AppError } from '@patchpilot/domain';
import type { FastifyRequest } from 'fastify';
import type { Logger } from '@patchpilot/logger';
import type { TrustedActor } from '@patchpilot/auth';

import { FINDING_NOT_FOUND, FINDING_INTERNAL, findingRateLimitedError } from './finding-http.js';
import { FINDING_OPERATOR_UNAVAILABLE, INVALID_REQUEST } from './http-errors.js';

export const DISCOVERY_ROUTE = '/assets/:assetId/controlled-finding-targets';

export const DISCOVERY_CURSOR_CONFLICT: AppError = Object.freeze({
  code: 'conflict',
  message: 'The page cursor is no longer current.',
});

export type DiscoveryPublicOutcome =
  | 'page'
  | 'validation'
  | 'unauthorized'
  | 'forbidden'
  | 'not_found'
  | 'conflict'
  | 'rate_limited'
  | 'unavailable'
  | 'internal';

export function discoveryFailureError(status: string): AppError {
  switch (status) {
    case 'invalid_request':
      return INVALID_REQUEST;
    case 'authority_required':
      return PERMISSION_DENIED;
    case 'not_found':
      return FINDING_NOT_FOUND;
    case 'stale_cursor':
      return DISCOVERY_CURSOR_CONFLICT;
    case 'database_unavailable':
      return FINDING_OPERATOR_UNAVAILABLE;
    default:
      return FINDING_INTERNAL;
  }
}

export function discoveryOutcomeForError(error: AppError): DiscoveryPublicOutcome {
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
      return error.message === FINDING_OPERATOR_UNAVAILABLE.message ? 'unavailable' : 'internal';
    default:
      return 'internal';
  }
}

export function parseDiscoveryQuery(
  url: string,
):
  | { readonly ok: true; readonly limit: number; readonly cursor: string | null }
  | { readonly ok: false } {
  const question = url.indexOf('?');
  if (question < 0) {
    return { ok: true, limit: 10, cursor: null };
  }
  const query = url.slice(question + 1).split('#')[0] ?? '';
  if (query.length === 0) {
    return { ok: true, limit: 10, cursor: null };
  }
  const seen = new Set<string>();
  let limit = 10;
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
      if (value.length === 0 || value.length > 4096) {
        return { ok: false };
      }
      cursor = value;
    } else {
      return { ok: false };
    }
  }
  return { ok: true, limit, cursor };
}

export function logDiscoveryOutcome(
  logger: Logger,
  request: FastifyRequest,
  outcome: DiscoveryPublicOutcome,
  actor: TrustedActor | null | undefined,
  page?: {
    readonly limit: number;
    readonly candidateCount: number;
    readonly oversizedCandidateCount: number;
  },
): void {
  const organizationId = actor?.organizationId;
  logger.info(
    {
      route: DISCOVERY_ROUTE,
      outcome,
      requestId: request.requestId,
      correlationId: request.correlationId,
      ...(actor === undefined || actor === null ? {} : { actorUserId: actor.userId }),
      ...(organizationId === undefined || organizationId === null ? {} : { organizationId }),
      ...(page === undefined
        ? {}
        : {
            limit: page.limit,
            candidateCount: page.candidateCount,
            oversizedCandidateCount: page.oversizedCandidateCount,
          }),
    },
    'controlled finding discovery outcome',
  );
}

export function discoveryRateLimitedError(): AppError {
  return findingRateLimitedError();
}
