import { LOGIN_RATE_LIMITED, selectDirectPeerIp } from '@patchpilot/auth';
import type { FastifyRequest } from 'fastify';

import { AUTH_HTTP_RATE_LIMITED } from './http-errors.js';

/** In-memory per-process ceiling for authenticated auth routes. Login uses the configured IP limiter. */
export const AUTH_HTTP_ROUTE_RATE_LIMIT_MAX = 60;
export const AUTH_HTTP_ROUTE_RATE_LIMIT_WINDOW_MS = 60_000;

const UNKNOWN_PEER_KEY = 'unknown-peer';

export function authHttpRateLimitKey(request: FastifyRequest): string {
  return (
    selectDirectPeerIp({
      socketRemoteAddress: request.socket.remoteAddress,
    }) ?? UNKNOWN_PEER_KEY
  );
}

export function authHttpRateLimitMessage(request: FastifyRequest): string {
  if ((request.routeOptions.url ?? request.url.split('?')[0]) === '/auth/login') {
    return LOGIN_RATE_LIMITED.message;
  }

  return AUTH_HTTP_RATE_LIMITED.message;
}

export function createAuthHttpRateLimitError(
  request: FastifyRequest,
  context: { statusCode: number },
): Error & { statusCode: number } {
  const error = new Error(authHttpRateLimitMessage(request)) as Error & { statusCode: number };
  error.statusCode = context.statusCode;
  return error;
}
