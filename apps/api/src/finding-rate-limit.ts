import { selectDirectPeerIp } from '@patchpilot/auth';
import type { FastifyRequest } from 'fastify';

import { AUTH_HTTP_RATE_LIMITED } from './http-errors.js';

const UNKNOWN_PEER_KEY = 'unknown-peer';

export const FINDING_CREATION_BODY_LIMIT_BYTES = 4096;

export const FINDING_CREATION_PEER_LIMIT = Object.freeze({
  max: 5,
  windowMs: 60_000,
});

/**
 * Process-local creation ceiling. Each API process allows this many creations
 * per organization per window. Several processes multiply the ceiling. That
 * multiplication is an accepted residual. Restarting the process clears it.
 * There is no Redis store and no rate-limit migration.
 */
export const FINDING_CREATION_ORGANIZATION_LIMIT = Object.freeze({
  max: 5,
  windowMs: 60_000,
});

export const FINDING_INSPECTION_PEER_LIMIT = Object.freeze({
  max: 60,
  windowMs: 60_000,
});

export const FINDING_DISCOVERY_PEER_LIMIT = Object.freeze({
  max: 30,
  windowMs: 60_000,
});

/**
 * Process-local discovery ceiling. Each API process allows this many
 * discovery reads per organization per window. Several processes multiply
 * the ceiling. That multiplication is an accepted residual. Restarting the
 * process clears it. There is no Redis store and no rate-limit migration.
 * Discovery counters are independent of creation and inspection.
 */
export const FINDING_DISCOVERY_ORGANIZATION_LIMIT = Object.freeze({
  max: 20,
  windowMs: 60_000,
});

export type FindingOrganizationRateLimitDecision = 'allowed' | 'limited' | 'unavailable';

export type FindingOrganizationRateLimiter = {
  consume(organizationId: string, now?: number): FindingOrganizationRateLimitDecision;
};

export function findingDirectPeerRateLimitKey(request: FastifyRequest): string {
  return (
    selectDirectPeerIp({
      socketRemoteAddress: request.socket.remoteAddress,
    }) ?? UNKNOWN_PEER_KEY
  );
}

export function createFindingPeerRateLimitError(
  _request: FastifyRequest,
  context: { statusCode: number },
): Error & { statusCode: number } {
  const error = new Error(AUTH_HTTP_RATE_LIMITED.message) as Error & { statusCode: number };
  error.statusCode = context.statusCode;
  return error;
}

export function createFindingOrganizationRateLimiter(options: {
  max: number;
  windowMs: number;
}): FindingOrganizationRateLimiter {
  const windows = new Map<string, { count: number; resetAt: number }>();
  return {
    consume(organizationId: string, now = Date.now()): FindingOrganizationRateLimitDecision {
      const current = windows.get(organizationId);
      if (current === undefined || now >= current.resetAt) {
        windows.set(organizationId, { count: 1, resetAt: now + options.windowMs });
        return 'allowed';
      }
      if (current.count >= options.max) {
        return 'limited';
      }
      current.count += 1;
      return 'allowed';
    },
  };
}
