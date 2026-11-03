import { selectDirectPeerIp } from '@patchpilot/auth';
import type { FastifyRequest } from 'fastify';

import { AUTH_HTTP_RATE_LIMITED } from './http-errors.js';

const UNKNOWN_PEER_KEY = 'unknown-peer';

/** One command body. Declared lengths above this are rejected before the parser. */
export const PRODUCT_MATCH_EVALUATION_BODY_LIMIT_BYTES = 1024;

/**
 * Process-local direct-peer ceiling. The key is the socket peer, never
 * X-Forwarded-For. Each API process keeps its own window. Several processes
 * multiply the ceiling. Restarting the process clears it. There is no Redis
 * store and no rate-limit migration.
 */
export const PRODUCT_MATCH_EVALUATION_PEER_LIMIT = Object.freeze({
  max: 5,
  windowMs: 60_000,
});

/**
 * Process-local organization ceiling, counted only after permission and body
 * validation. It is a separate window from Finding creation. Several processes
 * multiply the ceiling. Restarting the process clears it.
 */
export const PRODUCT_MATCH_EVALUATION_ORGANIZATION_LIMIT = Object.freeze({
  max: 5,
  windowMs: 60_000,
});

export function productMatchEvaluationDirectPeerRateLimitKey(request: FastifyRequest): string {
  return (
    selectDirectPeerIp({
      socketRemoteAddress: request.socket.remoteAddress,
    }) ?? UNKNOWN_PEER_KEY
  );
}

export function createProductMatchEvaluationPeerRateLimitError(
  _request: FastifyRequest,
  context: { statusCode: number },
): Error & { statusCode: number } {
  const error = new Error(AUTH_HTTP_RATE_LIMITED.message) as Error & { statusCode: number };
  error.statusCode = context.statusCode;
  return error;
}
