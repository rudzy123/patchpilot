/**
 * GET /assets/:assetId/product-match-candidates
 * Permission is checked before the asset read. The route does not evaluate or create a Finding.
 */

import rateLimit from '@fastify/rate-limit';
import { PERMISSIONS, requirePermission } from '@patchpilot/auth';
import type { ServerConfig } from '@patchpilot/config';
import { productMatchCandidatesResponseSchema } from '@patchpilot/contracts';
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
import { findingRateLimitedError, requestCarriesBody } from './finding-http.js';
import {
  createFindingOrganizationRateLimiter,
  createFindingPeerRateLimitError,
  findingDirectPeerRateLimitKey,
  type FindingOrganizationRateLimiter,
} from './finding-rate-limit.js';
import {
  INVALID_REQUEST,
  PRODUCT_MATCH_CANDIDATE_UNAVAILABLE,
  sendAppError,
} from './http-errors.js';
import {
  PRODUCT_MATCH_CANDIDATE_ORGANIZATION_LIMIT,
  PRODUCT_MATCH_CANDIDATE_PEER_LIMIT,
  PRODUCT_MATCH_CANDIDATE_ROUTE,
  logProductMatchCandidateOutcome,
  parseProductMatchCandidateQuery,
  productMatchCandidateFailureError,
  productMatchCandidateOutcomeForError,
} from './product-match-candidate-http.js';
import type { ProductMatchCandidateRuntime } from './product-match-candidate-runtime.js';

const ASSET_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

/** A GET body is invalid. This cap rejects a large body before the handler. */
export const PRODUCT_MATCH_CANDIDATE_REQUEST_BODY_LIMIT_BYTES = 1024;

export async function registerProductMatchCandidateRoutes(
  app: FastifyInstance,
  dependencies: {
    config: ServerConfig;
    logger: Logger;
    auth: AuthRuntime;
    productMatchCandidates: ProductMatchCandidateRuntime;
    productMatchCandidateOrganizationLimiter?: FindingOrganizationRateLimiter;
  },
): Promise<void> {
  const { config, logger, auth, productMatchCandidates } = dependencies;
  const organizationLimiter =
    dependencies.productMatchCandidateOrganizationLimiter ??
    createFindingOrganizationRateLimiter(PRODUCT_MATCH_CANDIDATE_ORGANIZATION_LIMIT);

  await app.register(async (scoped) => {
    await scoped.register(rateLimit, {
      global: true,
      hook: 'onRequest',
      skipOnError: false,
      max: PRODUCT_MATCH_CANDIDATE_PEER_LIMIT.max,
      timeWindow: PRODUCT_MATCH_CANDIDATE_PEER_LIMIT.windowMs,
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
          ? findingRateLimitedError()
          : statusCode === 400 || statusCode === 413 || statusCode === 415
            ? INVALID_REQUEST
            : productMatchCandidateFailureError('internal_failure');
      logProductMatchCandidateOutcome(
        logger,
        request,
        productMatchCandidateOutcomeForError(appError),
      );
      return sendAppError(request, reply, appError);
    });

    scoped.get(
      PRODUCT_MATCH_CANDIDATE_ROUTE,
      { bodyLimit: PRODUCT_MATCH_CANDIDATE_REQUEST_BODY_LIMIT_BYTES },
      async (request, reply) => {
        const authRequest = request as ResolvedAuthRequest;
        bindSessionCookie(authRequest, config.auth.cookieName);
        await resolveBoundSession(authRequest, (sessionToken) =>
          auth.resolveSession.execute({ sessionToken }),
        );
        if (requireAuthenticatedSession(authRequest, reply) !== undefined) {
          logProductMatchCandidateOutcome(logger, request, 'unauthorized');
          return reply;
        }
        if (requireActiveOrganization(authRequest, reply) !== undefined) {
          logProductMatchCandidateOutcome(logger, request, 'forbidden');
          return reply;
        }
        const actor = authRequest.actor;
        if (
          actor === null ||
          actor.organizationId === null ||
          actor.membershipId === null ||
          actor.role === null
        ) {
          return reject(logger, request, reply, ORGANIZATION_CONTEXT_REQUIRED);
        }
        const permitted = requirePermission(actor, PERMISSIONS.productMatchDiscoverControlled);
        if (!permitted.ok) {
          return reject(logger, request, reply, permitted.error);
        }
        if (requestCarriesBody(request)) {
          return reject(logger, request, reply, INVALID_REQUEST);
        }
        const assetId = readAssetId(request.params);
        if (assetId === null) {
          return reject(logger, request, reply, INVALID_REQUEST);
        }
        const query = parseProductMatchCandidateQuery(request.url);
        if (!query.ok) {
          return reject(logger, request, reply, INVALID_REQUEST);
        }
        const budget = consumeOrganizationBudget(organizationLimiter, actor.organizationId);
        if (budget !== 'allowed') {
          return reject(
            logger,
            request,
            reply,
            budget === 'limited' ? findingRateLimitedError() : PRODUCT_MATCH_CANDIDATE_UNAVAILABLE,
          );
        }
        let result;
        try {
          result = await productMatchCandidates.execute({
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
          return reject(
            logger,
            request,
            reply,
            productMatchCandidateFailureError('internal_failure'),
          );
        }
        if (result.status !== 'page') {
          return reject(logger, request, reply, productMatchCandidateFailureError(result.status));
        }
        const body = productMatchCandidatesResponseSchema.safeParse(result.page);
        if (!body.success || body.data.assetId !== assetId) {
          return reject(
            logger,
            request,
            reply,
            productMatchCandidateFailureError('internal_failure'),
          );
        }
        logProductMatchCandidateOutcome(logger, request, 'page', {
          limit: query.limit,
          candidateCount: body.data.candidates.length,
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
): FastifyReply {
  logProductMatchCandidateOutcome(logger, request, productMatchCandidateOutcomeForError(error));
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
