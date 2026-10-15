import { selectDirectPeerIp } from '@patchpilot/auth';
import type { FastifyRequest } from 'fastify';

import { AUTH_HTTP_RATE_LIMITED } from './http-errors.js';

const UNKNOWN_PEER_KEY = 'unknown-peer';

/** Accepted document ceiling. Oversized bodies fail before the application service. */
export const MAINTAINER_REVIEWED_ADVISORY_BODY_LIMIT_BYTES = 65_536;

/**
 * Process-local direct-peer ceiling for one advisory mutation route.
 * Each API process allows 5 requests per 60 seconds for that route.
 * Several API processes multiply the ceiling. Restarting the process
 * clears the window. There is no Redis store, no rate-limit table, and
 * no organization or revision key.
 */
export const MAINTAINER_REVIEWED_ADVISORY_PEER_LIMIT = Object.freeze({
  max: 5,
  windowMs: 60_000,
});

export function maintainerReviewedAdvisoryDirectPeerRateLimitKey(request: FastifyRequest): string {
  return (
    selectDirectPeerIp({
      socketRemoteAddress: request.socket.remoteAddress,
    }) ?? UNKNOWN_PEER_KEY
  );
}

export function createMaintainerReviewedAdvisoryPeerRateLimitError(
  _request: FastifyRequest,
  context: { statusCode: number },
): Error & { statusCode: number } {
  const error = new Error(AUTH_HTTP_RATE_LIMITED.message) as Error & { statusCode: number };
  error.statusCode = context.statusCode;
  return error;
}
