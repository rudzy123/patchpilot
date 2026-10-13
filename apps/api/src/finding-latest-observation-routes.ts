/**
 * GET /findings/:findingId/latest-observation
 * Read-only. The committed application service authorizes and selects.
 * This route does not inspect creation evidence and does not write.
 */

import rateLimit from '@fastify/rate-limit';
import { PERMISSIONS, requirePermission, type TrustedActor } from '@patchpilot/auth';
import type { ServerConfig } from '@patchpilot/config';
import { controlledFindingIdParamSchema } from '@patchpilot/contracts';
import { ORGANIZATION_CONTEXT_REQUIRED, type AppError } from '@patchpilot/domain';
import { INSPECT_CONTROLLED_FINDING_LATEST_OBSERVATION_COMMAND_SCHEMA_VERSION } from '@patchpilot/domain/controlled-finding-latest-observation';
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
  LATEST_OBSERVATION_ROUTE,
  latestObservationOutcomeForError,
  translateLatestObservationResult,
  type LatestObservationPublicOutcome,
} from './finding-latest-observation-http.js';
import { findingRateLimitedError, requestCarriesBody } from './finding-http.js';
import {
  FINDING_LATEST_OBSERVATION_PEER_LIMIT,
  createFindingPeerRateLimitError,
  findingDirectPeerRateLimitKey,
} from './finding-rate-limit.js';
import type { FindingOperatorRuntime } from './finding-runtime.js';
import {
  AUTH_HTTP_RATE_LIMITED,
  FINDING_OPERATOR_UNAVAILABLE,
  INVALID_REQUEST,
  sendAppError,
} from './http-errors.js';

/** A GET body is invalid. This cap rejects a large body before the handler. */
export const LATEST_OBSERVATION_REQUEST_BODY_LIMIT_BYTES = 1024;

const AUTHORITY_HEADERS = [
  'x-organization-id',
  'x-membership-id',
  'x-role',
  'x-permission',
  'x-permissions',
] as const;

export async function registerFindingLatestObservationRoutes(
  app: FastifyInstance,
  dependencies: {
    config: ServerConfig;
    logger: Logger;
    auth: AuthRuntime;
    findings: FindingOperatorRuntime;
    latestObservationPeerKey?: (request: FastifyRequest) => string;
  },
): Promise<void> {
  const { config, logger, auth, findings } = dependencies;
  const selectPeer = dependencies.latestObservationPeerKey ?? findingDirectPeerRateLimitKey;

  await app.register(async (scoped) => {
    scoped.addHook('onRequest', async (request, reply) => {
      applyPrivateNoStore(request, reply);
    });
    await scoped.register(rateLimit, {
      global: true,
      hook: 'onRequest',
      skipOnError: false,
      max: FINDING_LATEST_OBSERVATION_PEER_LIMIT.max,
      timeWindow: FINDING_LATEST_OBSERVATION_PEER_LIMIT.windowMs,
      keyGenerator: (request) => guardPeerKey(request, selectPeer),
      errorResponseBuilder: createFindingPeerRateLimitError,
    });
    scoped.setErrorHandler((error, request, reply) => {
      applyPrivateNoStore(request, reply);
      const statusCode = statusCodeOf(error);
      // Handler failures are caught inside the route and sent as 503.
      // A throw from peer selection or limiter evaluation reaches this hook first.
      const appError =
        statusCode === 400 || statusCode === 413 || statusCode === 415
          ? INVALID_REQUEST
          : findingRateLimitedError();
      logLatestObservation(logger, request, latestObservationOutcomeForError(appError), undefined);
      return sendAppError(request, reply, appError);
    });

    scoped.get(
      LATEST_OBSERVATION_ROUTE,
      { bodyLimit: LATEST_OBSERVATION_REQUEST_BODY_LIMIT_BYTES, exposeHeadRoute: false },
      async (request, reply) => {
        let actor: TrustedActor | null = null;
        try {
          const authRequest = request as ResolvedAuthRequest;
          bindSessionCookie(authRequest, config.auth.cookieName);
          await resolveBoundSession(authRequest, (sessionToken) =>
            auth.resolveSession.execute({ sessionToken }),
          );
          if (requireAuthenticatedSession(authRequest, reply) !== undefined) {
            logLatestObservation(logger, request, 'unauthorized', undefined);
            return reply;
          }
          if (requireActiveOrganization(authRequest, reply) !== undefined) {
            logLatestObservation(logger, request, 'forbidden', authRequest.actor);
            return reply;
          }
          actor = authRequest.actor;
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
          if (
            requestCarriesBody(request) ||
            requestHasQuery(request) ||
            carriesAuthorityHeader(request)
          ) {
            return reject(logger, request, reply, INVALID_REQUEST, actor);
          }
          const params = controlledFindingIdParamSchema.safeParse(request.params);
          if (!params.success) {
            return reject(logger, request, reply, INVALID_REQUEST, actor);
          }
          const result = await findings.latestObservation.execute({
            actor: {
              userId: actor.userId,
              sessionId: actor.sessionId,
              organizationId: actor.organizationId,
              membershipId: actor.membershipId,
              role: actor.role,
            },
            command: {
              schemaVersion: INSPECT_CONTROLLED_FINDING_LATEST_OBSERVATION_COMMAND_SCHEMA_VERSION,
              findingId: params.data.findingId,
            },
          });
          const translated = translateLatestObservationResult(result, params.data.findingId);
          if (!translated.ok) {
            return reject(logger, request, reply, translated.error, actor);
          }
          logLatestObservation(logger, request, 'found', actor);
          return reply.status(200).send(translated.body);
        } catch {
          return reject(logger, request, reply, FINDING_OPERATOR_UNAVAILABLE, actor);
        }
      },
    );
  });
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
): FastifyReply {
  logLatestObservation(logger, request, latestObservationOutcomeForError(error), actor);
  return sendAppError(request, reply, error);
}

function logLatestObservation(
  logger: Logger,
  request: FastifyRequest,
  outcome: LatestObservationPublicOutcome,
  actor: TrustedActor | null | undefined,
): void {
  const organizationId = actor?.organizationId;
  logger.info(
    {
      route: LATEST_OBSERVATION_ROUTE,
      outcome,
      requestId: request.requestId,
      correlationId: request.correlationId,
      ...(actor === undefined || actor === null ? {} : { actorUserId: actor.userId }),
      ...(organizationId === undefined || organizationId === null ? {} : { organizationId }),
    },
    'controlled finding latest-observation outcome',
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
