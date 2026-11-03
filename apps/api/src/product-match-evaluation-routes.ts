/**
 * POST /assets/:assetId/product-match-evaluations
 * One owner, one asset, one advisory revision. The route does not create
 * Findings. Organization scope comes from the authenticated actor.
 */

import rateLimit from '@fastify/rate-limit';
import {
  AUTHENTICATION_REQUIRED,
  PERMISSIONS,
  requirePermission,
  type TrustedActor,
} from '@patchpilot/auth';
import type { ServerConfig } from '@patchpilot/config';
import {
  assetIdParamSchema,
  deliberateProductMatchEvaluationRequestSchema,
} from '@patchpilot/contracts';
import { ORGANIZATION_CONTEXT_REQUIRED, type AppError } from '@patchpilot/domain';
import type { Logger } from '@patchpilot/logger';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

import {
  applyPrivateNoStore,
  bindSessionCookie,
  requireActiveOrganization,
  requireAllowedOrigin,
  requireAuthenticatedSession,
  requireSynchronizerCsrf,
  resolveBoundSession,
  type ResolvedAuthRequest,
} from './auth-plugin.js';
import type { AuthRuntime } from './auth-runtime.js';
import { declaredContentLength, parseFindingJsonContentType } from './finding-http.js';
import {
  createFindingOrganizationRateLimiter,
  type FindingOrganizationRateLimiter,
} from './finding-rate-limit.js';
import {
  AUTH_HTTP_RATE_LIMITED,
  INVALID_REQUEST,
  ORIGIN_NOT_ALLOWED,
  PRODUCT_MATCH_EVALUATION_UNAVAILABLE,
  sendAppError,
} from './http-errors.js';
import {
  PRODUCT_MATCH_EVALUATION_INTERNAL,
  productMatchEvaluationFailureError,
  productMatchEvaluationResultLogOutcome,
  publishProductMatchEvaluation,
  type ProductMatchEvaluationLogOutcome,
} from './product-match-evaluation-http.js';
import {
  PRODUCT_MATCH_EVALUATION_BODY_LIMIT_BYTES,
  PRODUCT_MATCH_EVALUATION_ORGANIZATION_LIMIT,
  PRODUCT_MATCH_EVALUATION_PEER_LIMIT,
  createProductMatchEvaluationPeerRateLimitError,
  productMatchEvaluationDirectPeerRateLimitKey,
} from './product-match-evaluation-rate-limit.js';
import type { ProductMatchEvaluationRuntime } from './product-match-evaluation-runtime.js';

export const PRODUCT_MATCH_EVALUATION_ROUTE = '/assets/:assetId/product-match-evaluations';

const AUTHORITY_HEADERS = [
  'x-organization-id',
  'x-membership-id',
  'x-user-id',
  'x-role',
  'x-permission',
  'x-permissions',
  'x-instance-operator',
  'x-advisory-grant',
] as const;

const COMPLETION_STATUSES = new Set<string>([
  'evaluated',
  'already_applied',
  'no_relevant_occurrence',
  'no_evaluable_occurrence',
]);

export async function registerProductMatchEvaluationRoutes(
  app: FastifyInstance,
  dependencies: {
    config: ServerConfig;
    logger: Logger;
    auth: AuthRuntime;
    productMatchEvaluation: ProductMatchEvaluationRuntime;
    productMatchEvaluationOrganizationLimiter?: FindingOrganizationRateLimiter;
  },
): Promise<void> {
  const { config, logger, auth, productMatchEvaluation } = dependencies;
  const organizationLimiter =
    dependencies.productMatchEvaluationOrganizationLimiter ??
    createFindingOrganizationRateLimiter(PRODUCT_MATCH_EVALUATION_ORGANIZATION_LIMIT);

  await app.register(async (scoped) => {
    scoped.addHook('onRequest', async (request, reply) => {
      applyPrivateNoStore(request, reply);
    });
    await scoped.register(rateLimit, {
      global: true,
      hook: 'onRequest',
      skipOnError: false,
      max: PRODUCT_MATCH_EVALUATION_PEER_LIMIT.max,
      timeWindow: PRODUCT_MATCH_EVALUATION_PEER_LIMIT.windowMs,
      keyGenerator: productMatchEvaluationDirectPeerRateLimitKey,
      errorResponseBuilder: createProductMatchEvaluationPeerRateLimitError,
    });
    scoped.addHook('onRequest', async (request, reply) => {
      if (urlCarriesQuery(request)) {
        return reject(logger, request, reply, INVALID_REQUEST, undefined, 'invalid_command');
      }
      if (!parseFindingJsonContentType(request.headers['content-type']).ok) {
        return reject(logger, request, reply, INVALID_REQUEST, undefined, 'invalid_command');
      }
      const length = declaredContentLength(request.headers['content-length']);
      if (
        length === 'invalid' ||
        (typeof length === 'number' && length > PRODUCT_MATCH_EVALUATION_BODY_LIMIT_BYTES)
      ) {
        return reject(logger, request, reply, INVALID_REQUEST, undefined, 'invalid_command');
      }
      return undefined;
    });
    scoped.setErrorHandler((error, request, reply) => {
      applyPrivateNoStore(request, reply);
      const statusCode = statusCodeOf(error);
      const limited = statusCode === 429;
      const invalid = statusCode === 400 || statusCode === 413 || statusCode === 415;
      const appError = limited
        ? AUTH_HTTP_RATE_LIMITED
        : invalid
          ? INVALID_REQUEST
          : PRODUCT_MATCH_EVALUATION_INTERNAL;
      const outcome: ProductMatchEvaluationLogOutcome = limited
        ? 'rate_limited'
        : invalid
          ? 'invalid_command'
          : 'internal_failure';
      logProductMatchEvaluation(logger, request, outcome, undefined);
      return sendAppError(request, reply, appError);
    });

    scoped.post(
      PRODUCT_MATCH_EVALUATION_ROUTE,
      { bodyLimit: PRODUCT_MATCH_EVALUATION_BODY_LIMIT_BYTES },
      async (request, reply) => {
        if (Array.isArray(request.headers.origin)) {
          return reject(logger, request, reply, ORIGIN_NOT_ALLOWED, undefined, 'forbidden');
        }
        if (requireAllowedOrigin(request, reply, config.corsAllowedOrigins) !== undefined) {
          logProductMatchEvaluation(logger, request, 'forbidden', undefined);
          return reply;
        }
        const authRequest = request as ResolvedAuthRequest;
        bindSessionCookie(authRequest, config.auth.cookieName);
        await resolveBoundSession(authRequest, (sessionToken) =>
          auth.resolveSession.execute({ sessionToken }),
        );
        if (requireAuthenticatedSession(authRequest, reply) !== undefined) {
          logProductMatchEvaluation(logger, request, 'unauthenticated', undefined);
          return reply;
        }
        if (Array.isArray(request.headers[config.auth.csrfHeaderName.toLowerCase()])) {
          return reject(
            logger,
            request,
            reply,
            AUTHENTICATION_REQUIRED,
            authRequest.actor,
            'unauthenticated',
          );
        }
        if (requireSynchronizerCsrf(authRequest, reply, config) !== undefined) {
          logProductMatchEvaluation(logger, request, 'unauthenticated', authRequest.actor);
          return reply;
        }
        if (requireActiveOrganization(authRequest, reply) !== undefined) {
          logProductMatchEvaluation(logger, request, 'forbidden', authRequest.actor);
          return reply;
        }
        const actor = authRequest.actor;
        if (
          actor === null ||
          actor.organizationId === null ||
          actor.membershipId === null ||
          actor.role === null
        ) {
          return reject(logger, request, reply, ORGANIZATION_CONTEXT_REQUIRED, actor, 'forbidden');
        }
        const permitted = requirePermission(actor, PERMISSIONS.productMatchEvaluateControlled);
        if (!permitted.ok) {
          return reject(logger, request, reply, permitted.error, actor, 'authority_required');
        }
        if (carriesAuthorityHeader(request) || parsedQueryPresent(request)) {
          return reject(logger, request, reply, INVALID_REQUEST, actor, 'invalid_command');
        }
        const params = assetIdParamSchema.safeParse(request.params);
        const body = deliberateProductMatchEvaluationRequestSchema.safeParse(request.body);
        if (!params.success || !body.success) {
          return reject(logger, request, reply, INVALID_REQUEST, actor, 'invalid_command');
        }
        const budget = consumeOrganizationBudget(organizationLimiter, actor.organizationId);
        if (budget !== 'allowed') {
          return reject(
            logger,
            request,
            reply,
            budget === 'limited' ? AUTH_HTTP_RATE_LIMITED : PRODUCT_MATCH_EVALUATION_UNAVAILABLE,
            actor,
            budget === 'limited' ? 'rate_limited' : 'unavailable',
          );
        }
        let result;
        try {
          result = await productMatchEvaluation.execute({
            actor: {
              userId: actor.userId,
              sessionId: actor.sessionId,
              organizationId: actor.organizationId,
              membershipId: actor.membershipId,
              role: actor.role,
            },
            assetId: params.data.assetId,
            advisoryRevisionId: body.data.advisoryRevisionId,
            requestId: request.requestId,
            correlationId: request.correlationId,
          });
        } catch {
          return reject(
            logger,
            request,
            reply,
            PRODUCT_MATCH_EVALUATION_INTERNAL,
            actor,
            'internal_failure',
          );
        }
        if (COMPLETION_STATUSES.has(result.status)) {
          const published = publishProductMatchEvaluation(result, {
            assetId: params.data.assetId,
            advisoryRevisionId: body.data.advisoryRevisionId,
          });
          if (published === null) {
            return reject(
              logger,
              request,
              reply,
              PRODUCT_MATCH_EVALUATION_INTERNAL,
              actor,
              'internal_failure',
            );
          }
          logProductMatchEvaluation(logger, request, published.body.status, actor);
          return reply.status(published.statusCode).send(published.body);
        }
        return reject(
          logger,
          request,
          reply,
          productMatchEvaluationFailureError(result.status),
          actor,
          productMatchEvaluationResultLogOutcome(result.status),
        );
      },
    );
  });
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

function carriesAuthorityHeader(request: FastifyRequest): boolean {
  return AUTHORITY_HEADERS.some((name) => request.headers[name] !== undefined);
}

function urlCarriesQuery(request: FastifyRequest): boolean {
  return [request.url, request.raw.url].some((value) => {
    if (typeof value !== 'string') {
      return false;
    }
    const path = value.split('#', 1)[0] ?? value;
    return path.includes('?');
  });
}

function parsedQueryPresent(request: FastifyRequest): boolean {
  const query = request.query;
  if (typeof query !== 'object' || query === null || Array.isArray(query)) {
    return true;
  }
  return Object.keys(query).length > 0;
}

function reject(
  logger: Logger,
  request: FastifyRequest,
  reply: FastifyReply,
  error: AppError,
  actor: TrustedActor | null | undefined,
  outcome: ProductMatchEvaluationLogOutcome,
): FastifyReply {
  logProductMatchEvaluation(logger, request, outcome, actor);
  return sendAppError(request, reply, error);
}

function logProductMatchEvaluation(
  logger: Logger,
  request: FastifyRequest,
  outcome: ProductMatchEvaluationLogOutcome,
  actor: TrustedActor | null | undefined,
): void {
  const organizationId = actor?.organizationId;
  logger.info(
    {
      route: PRODUCT_MATCH_EVALUATION_ROUTE,
      outcome,
      requestId: request.requestId,
      correlationId: request.correlationId,
      ...(actor === undefined || actor === null ? {} : { actorUserId: actor.userId }),
      ...(organizationId === undefined || organizationId === null ? {} : { organizationId }),
    },
    'product match evaluation outcome',
  );
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
