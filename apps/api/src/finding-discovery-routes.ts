/**
 * GET /assets/:assetId/controlled-finding-targets
 * Permission is checked before the asset read. The route does not create.
 */

import rateLimit from '@fastify/rate-limit';
import { PERMISSIONS, requirePermission, type TrustedActor } from '@patchpilot/auth';
import type { ServerConfig } from '@patchpilot/config';
import { controlledFindingDiscoveryResponseSchema } from '@patchpilot/contracts';
import { ORGANIZATION_CONTEXT_REQUIRED, type AppError } from '@patchpilot/domain';
import type { Logger } from '@patchpilot/logger';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

import {
  applyPrivateNoStore,
  bindSessionCookie,
  requireActiveOrganization,
  requireAuthenticatedSession,
  resolveBoundSession,
  type ResolvedAuthRequest,
} from './auth-plugin.js';
import type { AuthRuntime } from './auth-runtime.js';
import {
  DISCOVERY_ROUTE,
  discoveryFailureError,
  discoveryOutcomeForError,
  discoveryRateLimitedError,
  logDiscoveryOutcome,
  parseDiscoveryQuery,
} from './finding-discovery-http.js';
import type { FindingDiscoveryRuntime } from './finding-discovery-runtime.js';
import { requestCarriesBody } from './finding-http.js';
import {
  FINDING_DISCOVERY_ORGANIZATION_LIMIT,
  FINDING_DISCOVERY_PEER_LIMIT,
  createFindingOrganizationRateLimiter,
  createFindingPeerRateLimitError,
  findingDirectPeerRateLimitKey,
  type FindingOrganizationRateLimiter,
} from './finding-rate-limit.js';
import { FINDING_OPERATOR_UNAVAILABLE, INVALID_REQUEST, sendAppError } from './http-errors.js';

const ASSET_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

/** A GET body is invalid. This cap rejects a large body before the handler. */
export const DISCOVERY_REQUEST_BODY_LIMIT_BYTES = 1024;

export async function registerFindingDiscoveryRoutes(
  app: FastifyInstance,
  dependencies: {
    config: ServerConfig;
    logger: Logger;
    auth: AuthRuntime;
    discovery: FindingDiscoveryRuntime;
    discoveryOrganizationLimiter?: FindingOrganizationRateLimiter;
  },
): Promise<void> {
  const { config, logger, auth, discovery } = dependencies;
  const organizationLimiter =
    dependencies.discoveryOrganizationLimiter ??
    createFindingOrganizationRateLimiter(FINDING_DISCOVERY_ORGANIZATION_LIMIT);

  await app.register(async (scoped) => {
    await scoped.register(rateLimit, {
      global: true,
      hook: 'onRequest',
      skipOnError: false,
      max: FINDING_DISCOVERY_PEER_LIMIT.max,
      timeWindow: FINDING_DISCOVERY_PEER_LIMIT.windowMs,
      keyGenerator: findingDirectPeerRateLimitKey,
      errorResponseBuilder: createFindingPeerRateLimitError,
    });
    scoped.addHook('onRequest', async (request, reply) => {
      applyPrivateNoStore(request, reply);
    });
    scoped.setErrorHandler((error, request, reply) => {
      applyPrivateNoStore(request, reply);
      const statusCode = statusCodeOf(error);
      const appError =
        statusCode === 429
          ? discoveryRateLimitedError()
          : statusCode === 400 || statusCode === 413 || statusCode === 415
            ? INVALID_REQUEST
            : discoveryFailureError('internal_failure');
      logDiscoveryOutcome(logger, request, discoveryOutcomeForError(appError), undefined);
      return sendAppError(request, reply, appError);
    });

    scoped.get(
      DISCOVERY_ROUTE,
      { bodyLimit: DISCOVERY_REQUEST_BODY_LIMIT_BYTES },
      async (request, reply) => {
        const authRequest = request as ResolvedAuthRequest;
        bindSessionCookie(authRequest, config.auth.cookieName);
        await resolveBoundSession(authRequest, (sessionToken) =>
          auth.resolveSession.execute({ sessionToken }),
        );
        if (requireAuthenticatedSession(authRequest, reply) !== undefined) {
          logDiscoveryOutcome(logger, request, 'unauthorized', undefined);
          return reply;
        }
        if (requireActiveOrganization(authRequest, reply) !== undefined) {
          logDiscoveryOutcome(logger, request, 'forbidden', authRequest.actor);
          return reply;
        }
        const actor = authRequest.actor;
        if (
          actor === null ||
          actor.organizationId === null ||
          actor.membershipId === null ||
          actor.role === null
        ) {
          return reject(logger, request, reply, ORGANIZATION_CONTEXT_REQUIRED, actor);
        }
        const permitted = requirePermission(actor, PERMISSIONS.findingDiscoverControlled);
        if (!permitted.ok) {
          return reject(logger, request, reply, permitted.error, actor);
        }
        if (requestCarriesBody(request)) {
          return reject(logger, request, reply, INVALID_REQUEST, actor);
        }
        const assetId = readAssetId(request.params);
        if (assetId === null) {
          return reject(logger, request, reply, INVALID_REQUEST, actor);
        }
        const query = parseDiscoveryQuery(request.url);
        if (!query.ok) {
          return reject(logger, request, reply, INVALID_REQUEST, actor);
        }
        const budget = consumeOrganizationBudget(organizationLimiter, actor.organizationId);
        if (budget !== 'allowed') {
          return reject(
            logger,
            request,
            reply,
            budget === 'limited' ? discoveryRateLimitedError() : FINDING_OPERATOR_UNAVAILABLE,
            actor,
          );
        }
        let result;
        try {
          result = await discovery.execute({
            actor: {
              userId: actor.userId,
              sessionId: actor.sessionId,
              organizationId: actor.organizationId,
              membershipId: actor.membershipId,
              role: actor.role,
            },
            assetId,
            limit: query.limit,
            cursor: query.cursor,
          });
        } catch {
          return reject(logger, request, reply, discoveryFailureError('internal_failure'), actor);
        }
        if (result.status !== 'page') {
          return reject(logger, request, reply, discoveryFailureError(result.status), actor);
        }
        const body = controlledFindingDiscoveryResponseSchema.safeParse(result.page);
        if (!body.success) {
          return reject(logger, request, reply, discoveryFailureError('internal_failure'), actor);
        }
        logDiscoveryOutcome(logger, request, 'page', actor, {
          limit: query.limit,
          candidateCount: body.data.candidates.length,
          oversizedCandidateCount: body.data.oversizedCandidateCount,
        });
        return reply.status(200).send(body.data);
      },
    );
  });
}

function readAssetId(params: unknown): string | null {
  if (typeof params !== 'object' || params === null) {
    return null;
  }
  const assetId = Object.getOwnPropertyDescriptor(params, 'assetId')?.value;
  if (typeof assetId !== 'string' || !ASSET_ID.test(assetId)) {
    return null;
  }
  return assetId;
}

function consumeOrganizationBudget(
  limiter: FindingOrganizationRateLimiter,
  organizationId: string,
): 'allowed' | 'limited' | 'unavailable' {
  try {
    return limiter.consume(organizationId);
  } catch {
    return 'unavailable';
  }
}

function reject(
  logger: Logger,
  request: FastifyRequest,
  reply: FastifyReply,
  error: AppError,
  actor?: TrustedActor | null,
): FastifyReply {
  logDiscoveryOutcome(logger, request, discoveryOutcomeForError(error), actor);
  return sendAppError(request, reply, error);
}

function statusCodeOf(error: unknown): number {
  if (typeof error === 'object' && error !== null && 'statusCode' in error) {
    const statusCode = error.statusCode;
    if (typeof statusCode === 'number') {
      return statusCode;
    }
  }
  return 500;
}
