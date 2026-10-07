import rateLimit from '@fastify/rate-limit';
import {
  AUTHENTICATION_REQUIRED,
  PERMISSIONS,
  requirePermission,
  type TrustedActor,
} from '@patchpilot/auth';
import type { ServerConfig } from '@patchpilot/config';
import {
  controlledFindingCreationRequestSchema,
  controlledFindingCreationResponseSchema,
  controlledFindingIdParamSchema,
  controlledFindingInspectionResponseSchema,
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
import type { FindingOperatorRuntime } from './finding-runtime.js';
import {
  creationFailureError,
  declaredContentLength,
  FINDING_INTERNAL,
  findingOutcomeForError,
  findingRateLimitedError,
  inspectionFailureError,
  parseFindingJsonContentType,
  requestCarriesBody,
  type FindingPublicOutcome,
} from './finding-http.js';
import {
  createFindingOrganizationRateLimiter,
  createFindingPeerRateLimitError,
  FINDING_CREATION_BODY_LIMIT_BYTES,
  FINDING_CREATION_ORGANIZATION_LIMIT,
  FINDING_CREATION_PEER_LIMIT,
  FINDING_INSPECTION_PEER_LIMIT,
  findingDirectPeerRateLimitKey,
  type FindingOrganizationRateLimiter,
} from './finding-rate-limit.js';
import {
  FINDING_OPERATOR_UNAVAILABLE,
  INVALID_REQUEST,
  ORIGIN_NOT_ALLOWED,
  sendAppError,
} from './http-errors.js';

const CREATION_ROUTE = '/findings';
const INSPECTION_ROUTE = '/findings/:findingId';

export async function registerFindingRoutes(
  app: FastifyInstance,
  dependencies: {
    config: ServerConfig;
    logger: Logger;
    auth: AuthRuntime;
    findings: FindingOperatorRuntime;
    findingOrganizationLimiter?: FindingOrganizationRateLimiter;
  },
): Promise<void> {
  const { config, logger, auth, findings } = dependencies;
  const organizationLimiter =
    dependencies.findingOrganizationLimiter ??
    createFindingOrganizationRateLimiter(FINDING_CREATION_ORGANIZATION_LIMIT);

  await app.register(async (scoped) => {
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
            : FINDING_INTERNAL;
      logFindingOutcome(logger, request, findingOutcomeForError(appError), undefined);
      return sendAppError(request, reply, appError);
    });

    await scoped.register(async (creations) => {
      await creations.register(rateLimit, {
        global: true,
        hook: 'onRequest',
        skipOnError: false,
        max: FINDING_CREATION_PEER_LIMIT.max,
        timeWindow: FINDING_CREATION_PEER_LIMIT.windowMs,
        keyGenerator: findingDirectPeerRateLimitKey,
        errorResponseBuilder: createFindingPeerRateLimitError,
      });
      creations.addHook('onRequest', async (request, reply) => {
        if (!parseFindingJsonContentType(request.headers['content-type']).ok) {
          return reject(logger, request, reply, INVALID_REQUEST);
        }
        const length = declaredContentLength(request.headers['content-length']);
        if (
          length === 'invalid' ||
          (typeof length === 'number' && length > FINDING_CREATION_BODY_LIMIT_BYTES)
        ) {
          return reject(logger, request, reply, INVALID_REQUEST);
        }
        return undefined;
      });

      creations.post(
        CREATION_ROUTE,
        { bodyLimit: FINDING_CREATION_BODY_LIMIT_BYTES },
        async (request, reply) => {
          if (Array.isArray(request.headers.origin)) {
            return reject(logger, request, reply, ORIGIN_NOT_ALLOWED);
          }
          if (requireAllowedOrigin(request, reply, config.corsAllowedOrigins) !== undefined) {
            logFindingOutcome(logger, request, 'forbidden', undefined);
            return reply;
          }
          const authRequest = request as ResolvedAuthRequest;
          bindSessionCookie(authRequest, config.auth.cookieName);
          await resolveBoundSession(authRequest, (sessionToken) =>
            auth.resolveSession.execute({ sessionToken }),
          );
          if (requireAuthenticatedSession(authRequest, reply) !== undefined) {
            logFindingOutcome(logger, request, 'unauthorized', undefined);
            return reply;
          }
          if (Array.isArray(request.headers[config.auth.csrfHeaderName.toLowerCase()])) {
            return reject(logger, request, reply, AUTHENTICATION_REQUIRED, authRequest.actor);
          }
          if (requireSynchronizerCsrf(authRequest, reply, config) !== undefined) {
            logFindingOutcome(logger, request, 'unauthorized', authRequest.actor);
            return reply;
          }
          if (requireActiveOrganization(authRequest, reply) !== undefined) {
            logFindingOutcome(logger, request, 'forbidden', authRequest.actor);
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
          const permitted = requirePermission(actor, PERMISSIONS.findingCreateControlled);
          if (!permitted.ok) {
            return reject(logger, request, reply, permitted.error, actor);
          }
          const parsed = controlledFindingCreationRequestSchema.safeParse(request.body);
          if (!parsed.success) {
            return reject(logger, request, reply, INVALID_REQUEST, actor);
          }
          const budget = consumeOrganizationBudget(organizationLimiter, actor.organizationId);
          if (budget !== 'allowed') {
            return reject(
              logger,
              request,
              reply,
              budget === 'limited' ? findingRateLimitedError() : FINDING_OPERATOR_UNAVAILABLE,
              actor,
            );
          }
          let result;
          try {
            result = await findings.creation.execute({
              actor: {
                userId: actor.userId,
                sessionId: actor.sessionId,
                organizationId: actor.organizationId,
                membershipId: actor.membershipId,
                role: actor.role,
              },
              request: parsed.data,
              correlationId: request.correlationId,
            });
          } catch {
            return reject(logger, request, reply, FINDING_INTERNAL, actor);
          }
          if (result.status !== 'created' && result.status !== 'already_applied') {
            return reject(logger, request, reply, creationFailureError(result.status), actor);
          }
          const body = controlledFindingCreationResponseSchema.safeParse({
            status: result.status,
            findingId: result.findingId,
          });
          if (!body.success) {
            return reject(logger, request, reply, FINDING_INTERNAL, actor);
          }
          logFindingOutcome(logger, request, result.status, actor);
          return reply.status(result.status === 'created' ? 201 : 200).send(body.data);
        },
      );
    });

    await scoped.register(async (inspections) => {
      await inspections.register(rateLimit, {
        global: true,
        hook: 'onRequest',
        skipOnError: false,
        max: FINDING_INSPECTION_PEER_LIMIT.max,
        timeWindow: FINDING_INSPECTION_PEER_LIMIT.windowMs,
        keyGenerator: findingDirectPeerRateLimitKey,
        errorResponseBuilder: createFindingPeerRateLimitError,
      });
      inspections.get(INSPECTION_ROUTE, async (request, reply) => {
        const authRequest = request as ResolvedAuthRequest;
        bindSessionCookie(authRequest, config.auth.cookieName);
        await resolveBoundSession(authRequest, (sessionToken) =>
          auth.resolveSession.execute({ sessionToken }),
        );
        if (requireAuthenticatedSession(authRequest, reply) !== undefined) {
          logFindingOutcome(logger, request, 'unauthorized', undefined);
          return reply;
        }
        if (requireActiveOrganization(authRequest, reply) !== undefined) {
          logFindingOutcome(logger, request, 'forbidden', authRequest.actor);
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
        const permitted = requirePermission(actor, PERMISSIONS.findingInspect);
        if (!permitted.ok) {
          return reject(logger, request, reply, permitted.error, actor);
        }
        if (requestCarriesBody(request)) {
          return reject(logger, request, reply, INVALID_REQUEST, actor);
        }
        const params = controlledFindingIdParamSchema.safeParse(request.params);
        if (!params.success) {
          return reject(logger, request, reply, INVALID_REQUEST, actor);
        }
        let result;
        try {
          result = await findings.inspection.execute({
            actor: {
              userId: actor.userId,
              sessionId: actor.sessionId,
              organizationId: actor.organizationId,
              membershipId: actor.membershipId,
              role: actor.role,
            },
            findingId: params.data.findingId,
          });
        } catch {
          return reject(logger, request, reply, FINDING_INTERNAL, actor);
        }
        if (result.status !== 'found') {
          return reject(logger, request, reply, inspectionFailureError(result.status), actor);
        }
        const body = controlledFindingInspectionResponseSchema.safeParse(result.projection);
        if (!body.success) {
          return reject(logger, request, reply, FINDING_INTERNAL, actor);
        }
        logFindingOutcome(logger, request, 'found', actor);
        return reply.status(200).send(body.data);
      });
    });
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

function reject(
  logger: Logger,
  request: FastifyRequest,
  reply: FastifyReply,
  error: AppError,
  actor?: TrustedActor | null,
): FastifyReply {
  logFindingOutcome(logger, request, findingOutcomeForError(error), actor);
  return sendAppError(request, reply, error);
}

function logFindingOutcome(
  logger: Logger,
  request: FastifyRequest,
  outcome: FindingPublicOutcome,
  actor: TrustedActor | null | undefined,
): void {
  const organizationId = actor?.organizationId;
  logger.info(
    {
      route: findingRouteTemplate(request),
      outcome,
      requestId: request.requestId,
      correlationId: request.correlationId,
      ...(actor === undefined || actor === null ? {} : { actorUserId: actor.userId }),
      ...(organizationId === undefined || organizationId === null ? {} : { organizationId }),
    },
    'controlled finding operator outcome',
  );
}

function findingRouteTemplate(request: FastifyRequest): string {
  const template = request.routeOptions.url;
  if (template === CREATION_ROUTE || template === INSPECTION_ROUTE) {
    return template;
  }
  return request.method === 'GET' ? INSPECTION_ROUTE : CREATION_ROUTE;
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
