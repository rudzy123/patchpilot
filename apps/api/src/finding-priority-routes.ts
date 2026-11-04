/**
 * POST /findings/:findingId/risk-calculations
 * GET /findings/:findingId/priority
 * Organization comes from the trusted actor. The body cannot name a reason.
 */

import rateLimit from '@fastify/rate-limit';
import { PERMISSIONS, requirePermission, type TrustedActor } from '@patchpilot/auth';
import type { ServerConfig } from '@patchpilot/config';
import {
  controlledFindingIdParamSchema,
  findingRiskCalculationRequestSchema,
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
import {
  declaredContentLength,
  findingRateLimitedError,
  parseFindingJsonContentType,
  requestCarriesBody,
} from './finding-http.js';
import {
  PRIORITY_CALCULATION_ROUTE,
  PRIORITY_CALCULATION_UNAVAILABLE,
  PRIORITY_INSPECTION_UNAVAILABLE,
  PRIORITY_READ_ROUTE,
  priorityOutcomeForError,
  translatePriorityCalculation,
  translatePriorityRead,
  type PriorityPublicOutcome,
} from './finding-priority-http.js';
import {
  createFindingOrganizationRateLimiter,
  createFindingPeerRateLimitError,
  findingDirectPeerRateLimitKey,
  type FindingOrganizationRateLimiter,
} from './finding-rate-limit.js';
import type { ControlledPriorityRuntime } from './priority-runtime.js';
import {
  AUTH_HTTP_RATE_LIMITED,
  INVALID_REQUEST,
  ORIGIN_NOT_ALLOWED,
  sendAppError,
} from './http-errors.js';

export const PRIORITY_REQUEST_BODY_LIMIT_BYTES = 1024;

export const PRIORITY_CALCULATION_PEER_LIMIT = Object.freeze({
  max: 5,
  windowMs: 60_000,
});

export const PRIORITY_CALCULATION_ORGANIZATION_LIMIT = Object.freeze({
  max: 5,
  windowMs: 60_000,
});

export const PRIORITY_READ_PEER_LIMIT = Object.freeze({
  max: 30,
  windowMs: 60_000,
});

const AUTHORITY_HEADERS = [
  'x-organization-id',
  'x-membership-id',
  'x-role',
  'x-permission',
  'x-permissions',
] as const;

export async function registerFindingPriorityRoutes(
  app: FastifyInstance,
  dependencies: {
    config: ServerConfig;
    logger: Logger;
    auth: AuthRuntime;
    priority: ControlledPriorityRuntime;
    calculationOrganizationLimiter?: FindingOrganizationRateLimiter;
    calculationPeerKey?: (request: FastifyRequest) => string;
    readPeerKey?: (request: FastifyRequest) => string;
  },
): Promise<void> {
  const { config, logger, auth, priority } = dependencies;
  const organizationLimiter =
    dependencies.calculationOrganizationLimiter ??
    createFindingOrganizationRateLimiter(PRIORITY_CALCULATION_ORGANIZATION_LIMIT);
  const calculationPeer = dependencies.calculationPeerKey ?? findingDirectPeerRateLimitKey;
  const readPeer = dependencies.readPeerKey ?? findingDirectPeerRateLimitKey;

  await app.register(async (scoped) => {
    scoped.addHook('onRequest', async (request, reply) => {
      applyPrivateNoStore(request, reply);
    });

    await scoped.register(async (calculations) => {
      await calculations.register(rateLimit, {
        global: true,
        hook: 'onRequest',
        skipOnError: false,
        max: PRIORITY_CALCULATION_PEER_LIMIT.max,
        timeWindow: PRIORITY_CALCULATION_PEER_LIMIT.windowMs,
        keyGenerator: (request) => guardPeerKey(request, calculationPeer),
        errorResponseBuilder: createFindingPeerRateLimitError,
      });
      calculations.addHook('onRequest', async (request, reply) => {
        if (!parseFindingJsonContentType(request.headers['content-type']).ok) {
          return reject(logger, request, reply, INVALID_REQUEST, null, PRIORITY_CALCULATION_ROUTE);
        }
        const length = declaredContentLength(request.headers['content-length']);
        if (
          length === 'invalid' ||
          (typeof length === 'number' && length > PRIORITY_REQUEST_BODY_LIMIT_BYTES)
        ) {
          return reject(logger, request, reply, INVALID_REQUEST, null, PRIORITY_CALCULATION_ROUTE);
        }
        return undefined;
      });
      calculations.post(
        PRIORITY_CALCULATION_ROUTE,
        { bodyLimit: PRIORITY_REQUEST_BODY_LIMIT_BYTES },
        async (request, reply) => {
          if (Array.isArray(request.headers.origin)) {
            return reject(
              logger,
              request,
              reply,
              ORIGIN_NOT_ALLOWED,
              null,
              PRIORITY_CALCULATION_ROUTE,
            );
          }
          if (requireAllowedOrigin(request, reply, config.corsAllowedOrigins) !== undefined) {
            logPriority(logger, request, 'forbidden', undefined, PRIORITY_CALCULATION_ROUTE);
            return reply;
          }
          const authRequest = request as ResolvedAuthRequest;
          bindSessionCookie(authRequest, config.auth.cookieName);
          await resolveBoundSession(authRequest, (sessionToken) =>
            auth.resolveSession.execute({ sessionToken }),
          );
          if (requireAuthenticatedSession(authRequest, reply) !== undefined) {
            logPriority(logger, request, 'unauthorized', undefined, PRIORITY_CALCULATION_ROUTE);
            return reply;
          }
          if (Array.isArray(request.headers[config.auth.csrfHeaderName.toLowerCase()])) {
            return reject(
              logger,
              request,
              reply,
              INVALID_REQUEST,
              authRequest.actor,
              PRIORITY_CALCULATION_ROUTE,
            );
          }
          if (requireSynchronizerCsrf(authRequest, reply, config) !== undefined) {
            logPriority(
              logger,
              request,
              'unauthorized',
              authRequest.actor,
              PRIORITY_CALCULATION_ROUTE,
            );
            return reply;
          }
          const actor = requireActor(
            authRequest,
            reply,
            logger,
            request,
            PRIORITY_CALCULATION_ROUTE,
          );
          if (actor === undefined) {
            return reply;
          }
          const permitted = requirePermission(actor, PERMISSIONS.priorityCalculateControlled);
          if (!permitted.ok) {
            return reject(
              logger,
              request,
              reply,
              permitted.error,
              actor,
              PRIORITY_CALCULATION_ROUTE,
            );
          }
          if (carriesAuthorityHeader(request)) {
            return reject(
              logger,
              request,
              reply,
              INVALID_REQUEST,
              actor,
              PRIORITY_CALCULATION_ROUTE,
            );
          }
          const params = controlledFindingIdParamSchema.safeParse(request.params);
          const body = findingRiskCalculationRequestSchema.safeParse(request.body);
          if (!params.success || !body.success) {
            return reject(
              logger,
              request,
              reply,
              INVALID_REQUEST,
              actor,
              PRIORITY_CALCULATION_ROUTE,
            );
          }
          const budget = organizationLimiter.consume(actor.organizationId);
          if (budget !== 'allowed') {
            return reject(
              logger,
              request,
              reply,
              budget === 'limited' ? findingRateLimitedError() : PRIORITY_CALCULATION_UNAVAILABLE,
              actor,
              PRIORITY_CALCULATION_ROUTE,
            );
          }
          try {
            const result = await priority.calculate({
              actor: {
                userId: actor.userId,
                sessionId: actor.sessionId,
                organizationId: actor.organizationId,
                membershipId: actor.membershipId,
                role: actor.role,
              },
              findingId: params.data.findingId,
              correlationId: request.correlationId,
            });
            const translated = translatePriorityCalculation(result, params.data.findingId);
            if (!translated.ok) {
              return reject(
                logger,
                request,
                reply,
                translated.error,
                actor,
                PRIORITY_CALCULATION_ROUTE,
              );
            }
            logPriority(
              logger,
              request,
              translated.body.status === 'calculated' ? 'calculated' : 'already_applied',
              actor,
              PRIORITY_CALCULATION_ROUTE,
            );
            return reply.status(translated.statusCode).send(translated.body);
          } catch {
            return reject(
              logger,
              request,
              reply,
              PRIORITY_CALCULATION_UNAVAILABLE,
              actor,
              PRIORITY_CALCULATION_ROUTE,
            );
          }
        },
      );
    });

    await scoped.register(async (reads) => {
      await reads.register(rateLimit, {
        global: true,
        hook: 'onRequest',
        skipOnError: false,
        max: PRIORITY_READ_PEER_LIMIT.max,
        timeWindow: PRIORITY_READ_PEER_LIMIT.windowMs,
        keyGenerator: (request) => guardPeerKey(request, readPeer),
        errorResponseBuilder: createFindingPeerRateLimitError,
      });
      reads.get(
        PRIORITY_READ_ROUTE,
        { bodyLimit: PRIORITY_REQUEST_BODY_LIMIT_BYTES, exposeHeadRoute: false },
        async (request, reply) => {
          const authRequest = request as ResolvedAuthRequest;
          bindSessionCookie(authRequest, config.auth.cookieName);
          await resolveBoundSession(authRequest, (sessionToken) =>
            auth.resolveSession.execute({ sessionToken }),
          );
          if (requireAuthenticatedSession(authRequest, reply) !== undefined) {
            logPriority(logger, request, 'unauthorized', undefined, PRIORITY_READ_ROUTE);
            return reply;
          }
          const actor = requireActor(authRequest, reply, logger, request, PRIORITY_READ_ROUTE);
          if (actor === undefined) {
            return reply;
          }
          const findingPermission = requirePermission(actor, PERMISSIONS.findingInspect);
          if (!findingPermission.ok) {
            return reject(
              logger,
              request,
              reply,
              findingPermission.error,
              actor,
              PRIORITY_READ_ROUTE,
            );
          }
          const priorityPermission = requirePermission(actor, PERMISSIONS.priorityInspect);
          if (!priorityPermission.ok) {
            return reject(
              logger,
              request,
              reply,
              priorityPermission.error,
              actor,
              PRIORITY_READ_ROUTE,
            );
          }
          if (
            requestCarriesBody(request) ||
            requestHasQuery(request) ||
            carriesAuthorityHeader(request)
          ) {
            return reject(logger, request, reply, INVALID_REQUEST, actor, PRIORITY_READ_ROUTE);
          }
          const params = controlledFindingIdParamSchema.safeParse(request.params);
          if (!params.success) {
            return reject(logger, request, reply, INVALID_REQUEST, actor, PRIORITY_READ_ROUTE);
          }
          try {
            const result = await priority.read({
              actor: {
                userId: actor.userId,
                sessionId: actor.sessionId,
                organizationId: actor.organizationId,
                membershipId: actor.membershipId,
                role: actor.role,
              },
              findingId: params.data.findingId,
            });
            const translated = translatePriorityRead(result, params.data.findingId);
            if (!translated.ok) {
              return reject(logger, request, reply, translated.error, actor, PRIORITY_READ_ROUTE);
            }
            logPriority(
              logger,
              request,
              translated.body.status === 'not_calculated' ? 'not_calculated' : 'found',
              actor,
              PRIORITY_READ_ROUTE,
            );
            return reply.status(200).send(translated.body);
          } catch {
            return reject(
              logger,
              request,
              reply,
              PRIORITY_INSPECTION_UNAVAILABLE,
              actor,
              PRIORITY_READ_ROUTE,
            );
          }
        },
      );
    });
  });
}

type PriorityActor = TrustedActor & {
  organizationId: string;
  membershipId: string;
  role: NonNullable<TrustedActor['role']>;
};

function requireActor(
  request: ResolvedAuthRequest,
  reply: FastifyReply,
  logger: Logger,
  raw: FastifyRequest,
  route: string,
): PriorityActor | undefined {
  if (requireActiveOrganization(request, reply) !== undefined) {
    logPriority(logger, raw, 'forbidden', request.actor, route);
    return undefined;
  }
  const actor = request.actor;
  if (actor === null) {
    reject(logger, raw, reply, ORGANIZATION_CONTEXT_REQUIRED, actor, route);
    return undefined;
  }
  const organizationId = actor.organizationId;
  const membershipId = actor.membershipId;
  const role = actor.role;
  if (organizationId === null || membershipId === null || role === null) {
    reject(logger, raw, reply, ORGANIZATION_CONTEXT_REQUIRED, actor, route);
    return undefined;
  }
  return { ...actor, organizationId, membershipId, role };
}

function guardPeerKey(
  request: FastifyRequest,
  select: (request: FastifyRequest) => string,
): string {
  try {
    const key = select(request);
    if (typeof key !== 'string' || key.length === 0) {
      throw new Error('peer unavailable');
    }
    return key;
  } catch {
    const error = new Error(AUTH_HTTP_RATE_LIMITED.message) as Error & { statusCode: number };
    error.statusCode = 429;
    throw error;
  }
}

function requestHasQuery(request: FastifyRequest): boolean {
  const query = request.query;
  if (typeof query !== 'object' || query === null || Array.isArray(query)) {
    return true;
  }
  if (Object.keys(query).length > 0) {
    return true;
  }
  return [request.url, request.raw.url].some((value) => {
    if (typeof value !== 'string') {
      return false;
    }
    const path = value.split('#', 1)[0] ?? value;
    return path.includes('?');
  });
}

function carriesAuthorityHeader(request: FastifyRequest): boolean {
  return AUTHORITY_HEADERS.some((name) => request.headers[name] !== undefined);
}

function reject(
  logger: Logger,
  request: FastifyRequest,
  reply: FastifyReply,
  error: AppError,
  actor: TrustedActor | null,
  route: string,
): FastifyReply {
  logPriority(logger, request, priorityOutcomeForError(error), actor, route);
  return sendAppError(request, reply, error);
}

function logPriority(
  logger: Logger,
  request: FastifyRequest,
  outcome: PriorityPublicOutcome,
  actor: TrustedActor | null | undefined,
  route: string,
): void {
  const organizationId = actor?.organizationId;
  logger.info(
    {
      route,
      outcome,
      requestId: request.requestId,
      correlationId: request.correlationId,
      ...(actor === undefined || actor === null ? {} : { actorUserId: actor.userId }),
      ...(organizationId === undefined || organizationId === null ? {} : { organizationId }),
    },
    'controlled finding priority outcome',
  );
}
