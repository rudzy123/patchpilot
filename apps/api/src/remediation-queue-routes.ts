/**
 * GET /remediation-queue and POST /remediation-queue/export.
 * Organization comes from the trusted actor. There is no generic Finding list.
 */

import rateLimit from '@fastify/rate-limit';
import { PERMISSIONS, requirePermission, type TrustedActor } from '@patchpilot/auth';
import type { ServerConfig } from '@patchpilot/config';
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
  createFindingOrganizationRateLimiter,
  createFindingPeerRateLimitError,
  findingDirectPeerRateLimitKey,
  type FindingOrganizationRateLimiter,
} from './finding-rate-limit.js';
import {
  INVALID_REQUEST,
  ORIGIN_NOT_ALLOWED,
  REMEDIATION_QUEUE_UNAVAILABLE,
  sendAppError,
} from './http-errors.js';
import type { ControlledPriorityRuntime } from './priority-runtime.js';
import {
  REMEDIATION_QUEUE_EXPORT_ROUTE,
  REMEDIATION_QUEUE_ROUTE,
  parseRemediationQueueExportBody,
  parseRemediationQueueQuery,
  remediationQueueOutcomeForError,
  translateRemediationQueue,
  translateRemediationQueueExport,
  type RemediationQueuePublicOutcome,
} from './remediation-queue-http.js';

export const REMEDIATION_QUEUE_PEER_LIMIT = Object.freeze({
  max: 30,
  windowMs: 60_000,
});

export const REMEDIATION_QUEUE_ORGANIZATION_LIMIT = Object.freeze({
  max: 20,
  windowMs: 60_000,
});

const REQUEST_BODY_LIMIT_BYTES = 1024;

const AUTHORITY_HEADERS = [
  'x-organization-id',
  'x-membership-id',
  'x-role',
  'x-permission',
  'x-permissions',
] as const;

export async function registerRemediationQueueRoutes(
  app: FastifyInstance,
  dependencies: {
    config: ServerConfig;
    logger: Logger;
    auth: AuthRuntime;
    priority: ControlledPriorityRuntime;
    remediationQueueOrganizationLimiter?: FindingOrganizationRateLimiter;
  },
): Promise<void> {
  const { config, logger, auth, priority } = dependencies;
  const organizationLimiter =
    dependencies.remediationQueueOrganizationLimiter ??
    createFindingOrganizationRateLimiter(REMEDIATION_QUEUE_ORGANIZATION_LIMIT);

  await app.register(async (scoped) => {
    await scoped.register(rateLimit, {
      global: true,
      hook: 'onRequest',
      skipOnError: false,
      max: REMEDIATION_QUEUE_PEER_LIMIT.max,
      timeWindow: REMEDIATION_QUEUE_PEER_LIMIT.windowMs,
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
            : REMEDIATION_QUEUE_UNAVAILABLE;
      logQueue(
        logger,
        request,
        remediationQueueOutcomeForError(appError),
        undefined,
        null,
        queueRoute(request),
      );
      return sendAppError(request, reply, appError);
    });

    scoped.get(
      REMEDIATION_QUEUE_ROUTE,
      { bodyLimit: REQUEST_BODY_LIMIT_BYTES, exposeHeadRoute: false },
      async (request, reply) => {
        const authRequest = request as ResolvedAuthRequest;
        bindSessionCookie(authRequest, config.auth.cookieName);
        await resolveBoundSession(authRequest, (sessionToken) =>
          auth.resolveSession.execute({ sessionToken }),
        );
        if (requireAuthenticatedSession(authRequest, reply) !== undefined) {
          logQueue(logger, request, 'unauthorized', undefined, null);
          return reply;
        }
        const actor = requireActor(authRequest, reply, logger, request);
        if (actor === undefined) {
          return reply;
        }
        const queuePermission = requirePermission(actor, PERMISSIONS.remediationQueueRead);
        if (!queuePermission.ok) {
          return reject(logger, request, reply, queuePermission.error, actor, null);
        }
        const priorityPermission = requirePermission(actor, PERMISSIONS.priorityInspect);
        if (!priorityPermission.ok) {
          return reject(logger, request, reply, priorityPermission.error, actor, null);
        }
        if (requestCarriesBody(request) || carriesAuthorityHeader(request)) {
          return reject(logger, request, reply, INVALID_REQUEST, actor, null);
        }
        const query = parseRemediationQueueQuery(request.url);
        if (!query.ok) {
          return reject(logger, request, reply, INVALID_REQUEST, actor, null);
        }
        const budget = consumeOrganizationBudget(organizationLimiter, actor.organizationId);
        if (budget !== 'allowed') {
          return reject(
            logger,
            request,
            reply,
            budget === 'limited' ? findingRateLimitedError() : REMEDIATION_QUEUE_UNAVAILABLE,
            actor,
            query.section,
          );
        }
        try {
          const result = await priority.readQueue({
            actor: {
              userId: actor.userId,
              sessionId: actor.sessionId,
              organizationId: actor.organizationId,
              membershipId: actor.membershipId,
              role: actor.role,
            },
            section: query.section,
            limit: query.limit,
            cursor: query.cursor,
          });
          const translated = translateRemediationQueue(result);
          if (!translated.ok) {
            return reject(logger, request, reply, translated.error, actor, query.section);
          }
          logQueue(logger, request, 'page', actor, query.section);
          return reply.status(translated.statusCode).send(translated.body);
        } catch {
          return reject(
            logger,
            request,
            reply,
            REMEDIATION_QUEUE_UNAVAILABLE,
            actor,
            query.section,
          );
        }
      },
    );

    scoped.post(
      REMEDIATION_QUEUE_EXPORT_ROUTE,
      { bodyLimit: REQUEST_BODY_LIMIT_BYTES },
      async (request, reply) => {
        if (!parseFindingJsonContentType(request.headers['content-type']).ok) {
          return rejectExport(logger, request, reply, INVALID_REQUEST, null);
        }
        const length = declaredContentLength(request.headers['content-length']);
        if (
          length === 'invalid' ||
          (typeof length === 'number' && length > REQUEST_BODY_LIMIT_BYTES)
        ) {
          return rejectExport(logger, request, reply, INVALID_REQUEST, null);
        }
        if (Array.isArray(request.headers.origin)) {
          return rejectExport(logger, request, reply, ORIGIN_NOT_ALLOWED, null);
        }
        if (requireAllowedOrigin(request, reply, config.corsAllowedOrigins) !== undefined) {
          logQueue(logger, request, 'forbidden', undefined, null, REMEDIATION_QUEUE_EXPORT_ROUTE);
          return reply;
        }
        const authRequest = request as ResolvedAuthRequest;
        bindSessionCookie(authRequest, config.auth.cookieName);
        await resolveBoundSession(authRequest, (sessionToken) =>
          auth.resolveSession.execute({ sessionToken }),
        );
        if (requireAuthenticatedSession(authRequest, reply) !== undefined) {
          logQueue(
            logger,
            request,
            'unauthorized',
            undefined,
            null,
            REMEDIATION_QUEUE_EXPORT_ROUTE,
          );
          return reply;
        }
        if (Array.isArray(request.headers[config.auth.csrfHeaderName.toLowerCase()])) {
          return rejectExport(logger, request, reply, INVALID_REQUEST, authRequest.actor);
        }
        if (requireSynchronizerCsrf(authRequest, reply, config) !== undefined) {
          logQueue(
            logger,
            request,
            'unauthorized',
            authRequest.actor,
            null,
            REMEDIATION_QUEUE_EXPORT_ROUTE,
          );
          return reply;
        }
        const actor = requireActor(
          authRequest,
          reply,
          logger,
          request,
          REMEDIATION_QUEUE_EXPORT_ROUTE,
        );
        if (actor === undefined) {
          return reply;
        }
        const queuePermission = requirePermission(actor, PERMISSIONS.remediationQueueRead);
        if (!queuePermission.ok) {
          return rejectExport(logger, request, reply, queuePermission.error, actor);
        }
        const priorityPermission = requirePermission(actor, PERMISSIONS.priorityInspect);
        if (!priorityPermission.ok) {
          return rejectExport(logger, request, reply, priorityPermission.error, actor);
        }
        if (carriesAuthorityHeader(request) || requestHasQuery(request)) {
          return rejectExport(logger, request, reply, INVALID_REQUEST, actor);
        }
        const body = parseRemediationQueueExportBody(request.body);
        if (!body.ok) {
          return rejectExport(logger, request, reply, INVALID_REQUEST, actor);
        }
        const budget = consumeOrganizationBudget(organizationLimiter, actor.organizationId);
        if (budget !== 'allowed') {
          return rejectExport(
            logger,
            request,
            reply,
            budget === 'limited' ? findingRateLimitedError() : REMEDIATION_QUEUE_UNAVAILABLE,
            actor,
          );
        }
        try {
          const result = await priority.exportQueue({
            actor: {
              userId: actor.userId,
              sessionId: actor.sessionId,
              organizationId: actor.organizationId,
              membershipId: actor.membershipId,
              role: actor.role,
            },
            format: body.format,
            correlationId: request.correlationId,
          });
          const translated = translateRemediationQueueExport(result);
          if (!translated.ok) {
            return rejectExport(logger, request, reply, translated.error, actor);
          }
          logQueue(logger, request, 'exported', actor, null, REMEDIATION_QUEUE_EXPORT_ROUTE);
          return reply
            .status(translated.statusCode)
            .header('content-type', translated.contentType)
            .header('content-disposition', translated.contentDisposition)
            .send(Buffer.from(translated.body));
        } catch {
          return rejectExport(logger, request, reply, REMEDIATION_QUEUE_UNAVAILABLE, actor);
        }
      },
    );
  });
}

type QueueActor = TrustedActor & {
  organizationId: string;
  membershipId: string;
  role: NonNullable<TrustedActor['role']>;
};

function requireActor(
  request: ResolvedAuthRequest,
  reply: FastifyReply,
  logger: Logger,
  raw: FastifyRequest,
  route: string = REMEDIATION_QUEUE_ROUTE,
): QueueActor | undefined {
  if (requireActiveOrganization(request, reply) !== undefined) {
    logQueue(logger, raw, 'forbidden', request.actor, null, route);
    return undefined;
  }
  const actor = request.actor;
  if (
    actor === null ||
    actor.organizationId === null ||
    actor.membershipId === null ||
    actor.role === null
  ) {
    reject(logger, raw, reply, ORGANIZATION_CONTEXT_REQUIRED, actor, null, route);
    return undefined;
  }
  return actor as QueueActor;
}

function requestHasQuery(request: FastifyRequest): boolean {
  const query = request.query;
  if (typeof query !== 'object' || query === null || Array.isArray(query)) {
    return true;
  }
  return Object.keys(query).length > 0;
}

function queueRoute(request: FastifyRequest): string {
  const path = request.url.split('?')[0] ?? '';
  return path === REMEDIATION_QUEUE_EXPORT_ROUTE
    ? REMEDIATION_QUEUE_EXPORT_ROUTE
    : REMEDIATION_QUEUE_ROUTE;
}

function carriesAuthorityHeader(request: FastifyRequest): boolean {
  return AUTHORITY_HEADERS.some((name) => request.headers[name] !== undefined);
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
  actor: TrustedActor | null,
  section: 'ranked' | 'incomparable' | 'not_calculated' | null,
  route: string = REMEDIATION_QUEUE_ROUTE,
): FastifyReply {
  logQueue(logger, request, remediationQueueOutcomeForError(error), actor, section, route);
  return sendAppError(request, reply, error);
}

function rejectExport(
  logger: Logger,
  request: FastifyRequest,
  reply: FastifyReply,
  error: AppError,
  actor: TrustedActor | null,
): FastifyReply {
  return reject(logger, request, reply, error, actor, null, REMEDIATION_QUEUE_EXPORT_ROUTE);
}

function logQueue(
  logger: Logger,
  request: FastifyRequest,
  outcome: RemediationQueuePublicOutcome,
  actor: TrustedActor | null | undefined,
  section: 'ranked' | 'incomparable' | 'not_calculated' | null,
  route: string = REMEDIATION_QUEUE_ROUTE,
): void {
  const organizationId = actor?.organizationId;
  logger.info(
    {
      route,
      outcome,
      requestId: request.requestId,
      correlationId: request.correlationId,
      ...(section === null ? {} : { section }),
      ...(actor === undefined || actor === null ? {} : { actorUserId: actor.userId }),
      ...(organizationId === undefined || organizationId === null ? {} : { organizationId }),
    },
    'remediation queue outcome',
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
