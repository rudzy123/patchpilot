/**
 * GET /remediation-queue
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
  requireAuthenticatedSession,
  resolveBoundSession,
  type ResolvedAuthRequest,
} from './auth-plugin.js';
import type { AuthRuntime } from './auth-runtime.js';
import { requestCarriesBody, findingRateLimitedError } from './finding-http.js';
import {
  createFindingOrganizationRateLimiter,
  createFindingPeerRateLimitError,
  findingDirectPeerRateLimitKey,
  type FindingOrganizationRateLimiter,
} from './finding-rate-limit.js';
import { INVALID_REQUEST, REMEDIATION_QUEUE_UNAVAILABLE, sendAppError } from './http-errors.js';
import type { ControlledPriorityRuntime } from './priority-runtime.js';
import {
  REMEDIATION_QUEUE_ROUTE,
  parseRemediationQueueQuery,
  remediationQueueOutcomeForError,
  translateRemediationQueue,
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
      logQueue(logger, request, remediationQueueOutcomeForError(appError), undefined, null);
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
): QueueActor | undefined {
  if (requireActiveOrganization(request, reply) !== undefined) {
    logQueue(logger, raw, 'forbidden', request.actor, null);
    return undefined;
  }
  const actor = request.actor;
  if (
    actor === null ||
    actor.organizationId === null ||
    actor.membershipId === null ||
    actor.role === null
  ) {
    reject(logger, raw, reply, ORGANIZATION_CONTEXT_REQUIRED, actor, null);
    return undefined;
  }
  return actor as QueueActor;
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
): FastifyReply {
  logQueue(logger, request, remediationQueueOutcomeForError(error), actor, section);
  return sendAppError(request, reply, error);
}

function logQueue(
  logger: Logger,
  request: FastifyRequest,
  outcome: RemediationQueuePublicOutcome,
  actor: TrustedActor | null | undefined,
  section: 'ranked' | 'incomparable' | 'not_calculated' | null,
): void {
  const organizationId = actor?.organizationId;
  logger.info(
    {
      route: REMEDIATION_QUEUE_ROUTE,
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
