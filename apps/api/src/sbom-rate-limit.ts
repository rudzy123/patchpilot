import { selectDirectPeerIp } from '@patchpilot/auth';
import type { FastifyRequest } from 'fastify';

import { AUTH_HTTP_RATE_LIMITED } from './http-errors.js';

const UNKNOWN_PEER_KEY = 'unknown-peer';

export function sbomHttpRateLimitKey(request: FastifyRequest): string {
  return (
    selectDirectPeerIp({
      socketRemoteAddress: request.socket.remoteAddress,
    }) ?? UNKNOWN_PEER_KEY
  );
}

export function createSbomHttpRateLimitError(
  _request: FastifyRequest,
  context: { statusCode: number },
): Error & { statusCode: number } {
  const error = new Error(AUTH_HTTP_RATE_LIMITED.message) as Error & { statusCode: number };
  error.statusCode = context.statusCode;
  return error;
}

export function createSbomOrganizationRateLimiter(options: { max: number; windowMs: number }) {
  const windows = new Map<string, { count: number; resetAt: number }>();
  return {
    consume(organizationId: string, now = Date.now()): boolean {
      const current = windows.get(organizationId);
      if (current === undefined || now >= current.resetAt) {
        windows.set(organizationId, { count: 1, resetAt: now + options.windowMs });
        return true;
      }
      if (current.count >= options.max) {
        return false;
      }
      current.count += 1;
      return true;
    },
  };
}
