/**
 * Two cookie-authenticated instance-scoped mutations.
 * The session User is the principal. Organization membership is not authority.
 * Handlers delegate to the injected application boundary.
 */

import rateLimit from '@fastify/rate-limit';
import { AUTHENTICATION_REQUIRED, type TrustedActor } from '@patchpilot/auth';
import type { ServerConfig } from '@patchpilot/config';
import { maintainerReviewedAdvisoryRevisionParamSchema } from '@patchpilot/contracts';
import type { AppError } from '@patchpilot/domain';
import type { Logger } from '@patchpilot/logger';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

import {
  applyPrivateNoStore,
  bindSessionCookie,
  requireAllowedOrigin,
  requireAuthenticatedSession,
  requireSynchronizerCsrf,
  resolveBoundSession,
  type ResolvedAuthRequest,
} from './auth-plugin.js';
import type { AuthRuntime } from './auth-runtime.js';
import { readSingleHeader } from './headers.js';
import {
  ADVISORY_BODY_TOO_LARGE,
  ADVISORY_MUTATION_UNAVAILABLE,
  ADVISORY_UNSUPPORTED_MEDIA_TYPE,
  AUTH_HTTP_RATE_LIMITED,
  INVALID_REQUEST,
  ORIGIN_NOT_ALLOWED,
  sendAppError,
} from './http-errors.js';
import {
  advisoryContentEncodingRejected,
  advisoryOutcomeForError,
  advisoryStatusClass,
  declaredAdvisoryContentLength,
  parseAdvisoryJsonContentType,
  translateAdvisoryMutationResult,
  type AdvisoryPublicOutcome,
} from './maintainer-reviewed-advisory-http.js';
import {
  MAINTAINER_REVIEWED_ADVISORY_BODY_LIMIT_BYTES,
  MAINTAINER_REVIEWED_ADVISORY_PEER_LIMIT,
  createMaintainerReviewedAdvisoryPeerRateLimitError,
  maintainerReviewedAdvisoryDirectPeerRateLimitKey,
} from './maintainer-reviewed-advisory-rate-limit.js';
import type { MaintainerReviewedAdvisoryRuntime } from './maintainer-reviewed-advisory-runtime.js';

const SUBMISSION_ROUTE = '/intelligence/maintainer-reviewed-advisories';
const APPROVAL_ROUTE = '/intelligence/maintainer-reviewed-advisories/:revisionId/approval';

const AUTHORITY_HEADERS = [
  'x-organization-id',
  'x-membership-id',
  'x-user-id',
  'x-submitter-id',
  'x-reviewer-id',
  'x-acting-user',
  'x-acting-user-id',
  'x-role',
  'x-permission',
  'x-permissions',
  'x-instance-operator',
] as const;

const FORWARDED_ORIGIN_HEADERS = ['x-forwarded-host', 'x-forwarded-proto', 'forwarded'] as const;

export async function registerMaintainerReviewedAdvisoryRoutes(
  app: FastifyInstance,
  dependencies: {
    config: ServerConfig;
    logger: Logger;
    auth: AuthRuntime;
    advisories: MaintainerReviewedAdvisoryRuntime;
    submissionPeerKey?: (request: FastifyRequest) => string;
    approvalPeerKey?: (request: FastifyRequest) => string;
  },
): Promise<void> {
  const { config, logger, auth, advisories } = dependencies;

  await app.register(async (submission) => {
    await installMutationGuards(
      submission,
      logger,
      SUBMISSION_ROUTE,
      dependencies.submissionPeerKey,
    );
    submission.post(
      SUBMISSION_ROUTE,
      { bodyLimit: MAINTAINER_REVIEWED_ADVISORY_BODY_LIMIT_BYTES },
      async (request, reply) => {
        const actor = await authenticateMutation(
          config,
          logger,
          auth,
          request,
          reply,
          SUBMISSION_ROUTE,
        );
        if (actor === undefined) {
          return reply;
        }
        let result;
        try {
          result = await advisories.submission.execute({
            trustedSubmitterUserId: actor.userId,
            document: request.body,
          });
        } catch {
          return reject(
            logger,
            request,
            reply,
            SUBMISSION_ROUTE,
            ADVISORY_MUTATION_UNAVAILABLE,
            actor,
            503,
          );
        }
        const translated = translateAdvisoryMutationResult(result, 'submission');
        if (!translated.ok) {
          return reject(logger, request, reply, SUBMISSION_ROUTE, translated.error, actor);
        }
        logAdvisoryOutcome(
          logger,
          request,
          SUBMISSION_ROUTE,
          translated.body.result,
          translated.statusCode,
          actor,
        );
        return reply.status(translated.statusCode).send(translated.body);
      },
    );
  });

  await app.register(async (approval) => {
    await installMutationGuards(approval, logger, APPROVAL_ROUTE, dependencies.approvalPeerKey);
    approval.post(
      APPROVAL_ROUTE,
      { bodyLimit: MAINTAINER_REVIEWED_ADVISORY_BODY_LIMIT_BYTES },
      async (request, reply) => {
        const actor = await authenticateMutation(
          config,
          logger,
          auth,
          request,
          reply,
          APPROVAL_ROUTE,
        );
        if (actor === undefined) {
          return reply;
        }
        const params = maintainerReviewedAdvisoryRevisionParamSchema.safeParse(request.params);
        if (!params.success) {
          return reject(logger, request, reply, APPROVAL_ROUTE, INVALID_REQUEST, actor);
        }
        if (!approvalBodyIsEmpty(request.body)) {
          return reject(logger, request, reply, APPROVAL_ROUTE, INVALID_REQUEST, actor);
        }
        let result;
        try {
          result = await advisories.approval.execute({
            trustedReviewerUserId: actor.userId,
            advisoryRevisionId: params.data.revisionId,
            correlationId: request.correlationId,
          });
        } catch {
          return reject(
            logger,
            request,
            reply,
            APPROVAL_ROUTE,
            ADVISORY_MUTATION_UNAVAILABLE,
            actor,
            503,
          );
        }
        const translated = translateAdvisoryMutationResult(result, 'approval');
        if (!translated.ok) {
          return reject(logger, request, reply, APPROVAL_ROUTE, translated.error, actor);
        }
        logAdvisoryOutcome(
          logger,
          request,
          APPROVAL_ROUTE,
          translated.body.result,
          translated.statusCode,
          actor,
        );
        return reply.status(translated.statusCode).send(translated.body);
      },
    );
  });
}

async function installMutationGuards(
  scope: FastifyInstance,
  logger: Logger,
  route: string,
  peerKey: ((request: FastifyRequest) => string) | undefined,
): Promise<void> {
  const selectPeer = peerKey ?? maintainerReviewedAdvisoryDirectPeerRateLimitKey;
  scope.addHook('onRequest', async (request, reply) => {
    applyPrivateNoStore(request, reply);
  });
  await scope.register(rateLimit, {
    global: true,
    hook: 'onRequest',
    skipOnError: false,
    max: MAINTAINER_REVIEWED_ADVISORY_PEER_LIMIT.max,
    timeWindow: MAINTAINER_REVIEWED_ADVISORY_PEER_LIMIT.windowMs,
    keyGenerator: (request) => guardPeerKey(request, selectPeer),
    errorResponseBuilder: createMaintainerReviewedAdvisoryPeerRateLimitError,
  });
  scope.addHook('onRequest', async (request, reply) => {
    if (
      !parseAdvisoryJsonContentType(request.headers['content-type']).ok ||
      advisoryContentEncodingRejected(request.headers['content-encoding'])
    ) {
      return reject(logger, request, reply, route, ADVISORY_UNSUPPORTED_MEDIA_TYPE, null);
    }
    const length = declaredAdvisoryContentLength(request.headers['content-length']);
    if (length === 'invalid') {
      return reject(logger, request, reply, route, INVALID_REQUEST, null);
    }
    if (typeof length === 'number' && length > MAINTAINER_REVIEWED_ADVISORY_BODY_LIMIT_BYTES) {
      return reject(logger, request, reply, route, ADVISORY_BODY_TOO_LARGE, null);
    }
    return undefined;
  });
  scope.setErrorHandler((error, request, reply) => {
    applyPrivateNoStore(request, reply);
    const statusCode = statusCodeOf(error);
    const appError =
      statusCode === 429
        ? AUTH_HTTP_RATE_LIMITED
        : statusCode === 413
          ? ADVISORY_BODY_TOO_LARGE
          : statusCode === 415
            ? ADVISORY_UNSUPPORTED_MEDIA_TYPE
            : statusCode === 400
              ? INVALID_REQUEST
              : ADVISORY_MUTATION_UNAVAILABLE;
    logAdvisoryOutcome(
      logger,
      request,
      route,
      advisoryOutcomeForError(appError),
      statusCode === 429 || statusCode === 413 || statusCode === 415 || statusCode === 400
        ? statusCode
        : 503,
      null,
    );
    return sendAppError(request, reply, appError);
  });
}

async function authenticateMutation(
  config: ServerConfig,
  logger: Logger,
  auth: AuthRuntime,
  request: FastifyRequest,
  reply: FastifyReply,
  route: string,
): Promise<TrustedActor | undefined> {
  if (Array.isArray(request.headers.origin) || forwardedOriginAttempt(request)) {
    reject(logger, request, reply, route, ORIGIN_NOT_ALLOWED, null);
    return undefined;
  }
  if (requireAllowedOrigin(request, reply, config.corsAllowedOrigins) !== undefined) {
    logAdvisoryOutcome(logger, request, route, 'forbidden', 403, null);
    return undefined;
  }
  const authRequest = request as ResolvedAuthRequest;
  bindSessionCookie(authRequest, config.auth.cookieName);
  await resolveBoundSession(authRequest, (sessionToken) =>
    auth.resolveSession.execute({ sessionToken }),
  );
  if (requireAuthenticatedSession(authRequest, reply) !== undefined) {
    logAdvisoryOutcome(logger, request, route, 'unauthorized', 401, null);
    return undefined;
  }
  if (Array.isArray(request.headers[config.auth.csrfHeaderName.toLowerCase()])) {
    reject(logger, request, reply, route, AUTHENTICATION_REQUIRED, authRequest.actor);
    return undefined;
  }
  if (requireSynchronizerCsrf(authRequest, reply, config) !== undefined) {
    logAdvisoryOutcome(logger, request, route, 'unauthorized', 401, authRequest.actor);
    return undefined;
  }
  if (carriesAuthorityHeader(request) || requestHasQuery(request)) {
    reject(logger, request, reply, route, INVALID_REQUEST, authRequest.actor);
    return undefined;
  }
  const actor = authRequest.actor;
  if (actor === null) {
    reject(logger, request, reply, route, INVALID_REQUEST, null);
    return undefined;
  }
  return actor;
}

function approvalBodyIsEmpty(body: unknown): boolean {
  if (typeof body !== 'object' || body === null || Array.isArray(body)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(body);
  if (prototype !== Object.prototype && prototype !== null) {
    return false;
  }
  return Object.keys(body).length === 0;
}

function forwardedOriginAttempt(request: FastifyRequest): boolean {
  if (readSingleHeader(request.headers.origin) !== undefined) {
    return false;
  }
  return FORWARDED_ORIGIN_HEADERS.some((name) => request.headers[name] !== undefined);
}

function carriesAuthorityHeader(request: FastifyRequest): boolean {
  return AUTHORITY_HEADERS.some((name) => request.headers[name] !== undefined);
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

function reject(
  logger: Logger,
  request: FastifyRequest,
  reply: FastifyReply,
  route: string,
  error: AppError,
  actor: TrustedActor | null,
  statusCode?: number,
): FastifyReply {
  logAdvisoryOutcome(
    logger,
    request,
    route,
    advisoryOutcomeForError(error),
    statusCode ?? statusCodeForLoggedError(error),
    actor,
  );
  return sendAppError(request, reply, error);
}

function statusCodeForLoggedError(error: AppError): number {
  if (error.code === 'validation' && error.message === ADVISORY_BODY_TOO_LARGE.message) {
    return 413;
  }
  if (error.code === 'validation' && error.message === ADVISORY_UNSUPPORTED_MEDIA_TYPE.message) {
    return 415;
  }
  if (error.code === 'internal' && error.message === ADVISORY_MUTATION_UNAVAILABLE.message) {
    return 503;
  }
  switch (error.code) {
    case 'validation':
      return 400;
    case 'unauthorized':
      return 401;
    case 'forbidden':
      return 403;
    case 'not_found':
      return 404;
    case 'conflict':
      return 409;
    case 'rate_limited':
      return 429;
    case 'unprocessable_evidence':
    case 'internal':
      return 503;
  }
}

function logAdvisoryOutcome(
  logger: Logger,
  request: FastifyRequest,
  route: string,
  outcome: AdvisoryPublicOutcome,
  statusCode: number,
  actor: TrustedActor | null,
): void {
  logger.info(
    {
      route,
      method: 'POST',
      outcome,
      requestId: request.requestId,
      correlationId: request.correlationId,
      ...(actor === null ? {} : { actorUserId: actor.userId }),
    },
    'maintainer-reviewed advisory mutation',
  );
  logger.info(
    {
      metric: {
        route,
        method: 'POST',
        outcome,
        statusClass: advisoryStatusClass(statusCode),
      },
    },
    'maintainer-reviewed advisory metric',
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
