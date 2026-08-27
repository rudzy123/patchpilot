import rateLimit from '@fastify/rate-limit';
import {
  AUTHENTICATION_REQUIRED,
  LOGIN_UNAVAILABLE,
  selectDirectPeerIp,
  type TrustedActor,
} from '@patchpilot/auth';
import type { ServerConfig } from '@patchpilot/config';
import { loginRequestSchema, selectOrganizationRequestSchema } from '@patchpilot/contracts';
import type { Logger } from '@patchpilot/logger';
import type { AppError } from '@patchpilot/domain';
import type { FastifyInstance, FastifyRequest } from 'fastify';

import {
  AUTH_HTTP_ROUTE_RATE_LIMIT_MAX,
  AUTH_HTTP_ROUTE_RATE_LIMIT_WINDOW_MS,
  authHttpRateLimitKey,
  createAuthHttpRateLimitError,
} from './auth-http-rate-limit.js';

import {
  appendAuthAudit,
  loginFailedAuditInput,
  loginSucceededAuditInput,
  logoutAuditInput,
  organizationSelectedAuditInput,
} from './auth-audit.js';
import {
  applyAuthNoStore,
  bindSessionCookie,
  requireAllowedOrigin,
  requireAuthenticatedSession,
  requireJsonMutation,
  requireSynchronizerCsrf,
  resolveBoundSession,
  type ResolvedAuthRequest,
} from './auth-plugin.js';
import type { AuthRuntime } from './auth-runtime.js';
import { toOrganizationsResponse, toSessionResponse } from './auth-views.js';
import { clearSessionCookie, issueSessionCookie } from './cookies.js';
import { readSingleHeader } from './headers.js';
import { INVALID_REQUEST, sendAppError } from './http-errors.js';

export async function registerAuthRoutes(
  app: FastifyInstance,
  dependencies: {
    config: ServerConfig;
    logger: Logger;
    auth: AuthRuntime;
  },
): Promise<void> {
  const { config, logger, auth } = dependencies;

  await app.register(async (scoped) => {
    await scoped.register(rateLimit, {
      global: true,
      hook: 'onRequest',
      skipOnError: false,
      max: AUTH_HTTP_ROUTE_RATE_LIMIT_MAX,
      timeWindow: AUTH_HTTP_ROUTE_RATE_LIMIT_WINDOW_MS,
      keyGenerator: authHttpRateLimitKey,
      errorResponseBuilder: createAuthHttpRateLimitError,
    });

    scoped.addHook('onRequest', async (request, reply) => {
      applyAuthNoStore(request, reply);
    });

    scoped.post(
      '/auth/login',
      {
        config: {
          rateLimit: {
            max: config.auth.loginRateLimitIpMaxAttempts,
            timeWindow: config.auth.loginRateLimitIpWindowSeconds * 1000,
          },
        },
      },
      async (request, reply) => {
        bindSessionCookie(request as ResolvedAuthRequest, config.auth.cookieName);
        if (requireJsonMutation(request, reply) !== undefined) {
          return;
        }
        if (requireAllowedOrigin(request, reply, config.corsAllowedOrigins) !== undefined) {
          return;
        }

        const parsed = loginRequestSchema.safeParse(request.body);
        if (!parsed.success) {
          await appendAuthAudit(
            auth.audit,
            logger,
            loginFailedAuditInput({
              requestId: request.requestId,
              correlationId: request.correlationId,
              outcome: 'validation',
            }),
          );
          return sendAppError(request, reply, INVALID_REQUEST);
        }

        const forwardedFor = readSingleHeader(request.headers['x-forwarded-for']);
        const peerIp = selectDirectPeerIp({
          socketRemoteAddress: request.socket.remoteAddress,
          ...(forwardedFor === undefined ? {} : { xForwardedFor: forwardedFor }),
        });
        if (peerIp === undefined) {
          await appendAuthAudit(
            auth.audit,
            logger,
            loginFailedAuditInput({
              requestId: request.requestId,
              correlationId: request.correlationId,
              outcome: 'unavailable',
            }),
          );
          return sendAppError(request, reply, LOGIN_UNAVAILABLE);
        }

        const userAgent = requestUserAgent(request);
        const result = await auth.login.execute({
          email: parsed.data.email,
          password: parsed.data.password,
          peerIp,
          ...(userAgent === undefined ? {} : { userAgent }),
        });
        if (!result.ok) {
          await appendAuthAudit(
            auth.audit,
            logger,
            loginFailedAuditInput({
              requestId: request.requestId,
              correlationId: request.correlationId,
              outcome: loginFailureOutcome(result.error.code),
            }),
          );
          return sendAppError(request, reply, result.error);
        }

        await appendAuthAudit(
          auth.audit,
          logger,
          loginSucceededAuditInput({
            actor: result.value.actor,
            sessionId: result.value.sessionId,
            requestId: request.requestId,
            correlationId: request.correlationId,
          }),
        );
        issueSessionCookie(reply, config.auth, result.value.tokens.sessionToken);
        return reply.status(200).send(
          toSessionResponse({
            user: result.value.user,
            organization: result.value.organization,
            csrfToken: result.value.tokens.csrfToken,
            expiresAt: result.value.expiresAt,
          }),
        );
      },
    );

    scoped.post(
      '/auth/logout',
      {
        config: {
          rateLimit: {
            max: AUTH_HTTP_ROUTE_RATE_LIMIT_MAX,
            timeWindow: AUTH_HTTP_ROUTE_RATE_LIMIT_WINDOW_MS,
          },
        },
      },
      async (request, reply) => {
        bindSessionCookie(request as ResolvedAuthRequest, config.auth.cookieName);
        if (requireJsonMutation(request, reply) !== undefined) {
          return;
        }

        const authRequest = request as ResolvedAuthRequest;
        await resolveBoundSession(authRequest, (sessionToken) =>
          auth.resolveSession.execute({ sessionToken }),
        );

        if (authRequest.sessionToken !== null && authRequest.authSession !== null) {
          if (requireAllowedOrigin(request, reply, config.corsAllowedOrigins) !== undefined) {
            return;
          }
          if (requireSynchronizerCsrf(authRequest, reply, config) !== undefined) {
            return;
          }
        }

        const result = await auth.logout.execute(
          authRequest.sessionToken === null ? {} : { sessionToken: authRequest.sessionToken },
        );
        if (result.ok && result.value.revoked) {
          await appendAuthAudit(
            auth.audit,
            logger,
            logoutAuditInput({
              sessionId: result.value.sessionId,
              userId: result.value.userId,
              requestId: request.requestId,
              correlationId: request.correlationId,
            }),
          );
        }

        clearSessionCookie(reply, config.auth);
        return reply.status(204).send();
      },
    );

    scoped.get(
      '/auth/session',
      {
        config: {
          rateLimit: {
            max: AUTH_HTTP_ROUTE_RATE_LIMIT_MAX,
            timeWindow: AUTH_HTTP_ROUTE_RATE_LIMIT_WINDOW_MS,
          },
        },
      },
      async (request, reply) => {
        const authRequest = request as ResolvedAuthRequest;
        bindSessionCookie(authRequest, config.auth.cookieName);
        if (authRequest.sessionToken === null) {
          return sendAppError(request, reply, AUTHENTICATION_REQUIRED);
        }

        const result = await auth.readSession.execute({ sessionToken: authRequest.sessionToken });
        if (!result.ok) {
          return sendAppError(request, reply, result.error);
        }

        assignTrustedActor(authRequest, result.value.actor);
        return reply.status(200).send(
          toSessionResponse({
            user: result.value.user,
            organization: result.value.organization,
            csrfToken: result.value.csrfToken,
            expiresAt: result.value.expiresAt,
          }),
        );
      },
    );

    scoped.get(
      '/auth/organizations',
      {
        config: {
          rateLimit: {
            max: AUTH_HTTP_ROUTE_RATE_LIMIT_MAX,
            timeWindow: AUTH_HTTP_ROUTE_RATE_LIMIT_WINDOW_MS,
          },
        },
      },
      async (request, reply) => {
        const authRequest = request as ResolvedAuthRequest;
        bindSessionCookie(authRequest, config.auth.cookieName);
        await resolveBoundSession(authRequest, (sessionToken) =>
          auth.resolveSession.execute({ sessionToken }),
        );
        if (requireAuthenticatedSession(authRequest, reply) !== undefined) {
          return;
        }

        const result = await auth.listOrganizations.execute({
          sessionToken: authRequest.sessionToken ?? '',
        });
        if (!result.ok) {
          return sendAppError(request, reply, result.error);
        }

        return reply.status(200).send(
          toOrganizationsResponse(
            result.value.map((organization) => ({
              id: organization.organizationId,
              slug: organization.slug,
              name: organization.name,
              role: organization.role,
            })),
          ),
        );
      },
    );

    scoped.post(
      '/auth/select-organization',
      {
        config: {
          rateLimit: {
            max: AUTH_HTTP_ROUTE_RATE_LIMIT_MAX,
            timeWindow: AUTH_HTTP_ROUTE_RATE_LIMIT_WINDOW_MS,
          },
        },
      },
      async (request, reply) => {
        bindSessionCookie(request as ResolvedAuthRequest, config.auth.cookieName);
        if (requireJsonMutation(request, reply) !== undefined) {
          return;
        }
        if (requireAllowedOrigin(request, reply, config.corsAllowedOrigins) !== undefined) {
          return;
        }

        const authRequest = request as ResolvedAuthRequest;
        await resolveBoundSession(authRequest, (sessionToken) =>
          auth.resolveSession.execute({ sessionToken }),
        );
        if (requireAuthenticatedSession(authRequest, reply) !== undefined) {
          return;
        }
        if (requireSynchronizerCsrf(authRequest, reply, config) !== undefined) {
          return;
        }

        const parsed = selectOrganizationRequestSchema.safeParse(request.body);
        if (!parsed.success) {
          return sendAppError(request, reply, INVALID_REQUEST);
        }

        const result = await auth.selectOrganization.execute({
          sessionToken: authRequest.sessionToken ?? '',
          organizationId: parsed.data.organizationId,
        });
        if (!result.ok) {
          return sendAppError(request, reply, result.error);
        }

        assignTrustedActor(authRequest, result.value.actor);
        await appendAuthAudit(
          auth.audit,
          logger,
          organizationSelectedAuditInput({
            actor: result.value.actor,
            sessionId: result.value.sessionId,
            requestId: request.requestId,
            correlationId: request.correlationId,
          }),
        );
        issueSessionCookie(reply, config.auth, result.value.tokens.sessionToken);
        return reply.status(200).send(
          toSessionResponse({
            user: result.value.user,
            organization: result.value.organization,
            csrfToken: result.value.tokens.csrfToken,
            expiresAt: result.value.expiresAt,
          }),
        );
      },
    );
  });
}

function assignTrustedActor(request: ResolvedAuthRequest, actor: TrustedActor): void {
  request.actor = actor;
}

function loginFailureOutcome(
  code: AppError['code'],
): 'invalid_credentials' | 'rate_limited' | 'unavailable' | 'validation' {
  if (code === 'rate_limited') {
    return 'rate_limited';
  }
  if (code === 'internal') {
    return 'unavailable';
  }
  if (code === 'validation') {
    return 'validation';
  }
  return 'invalid_credentials';
}

function requestUserAgent(request: FastifyRequest): string | undefined {
  const value = readSingleHeader(request.headers['user-agent']);
  if (value === undefined) {
    return undefined;
  }

  const trimmed = value.trim();
  if (trimmed.length === 0) {
    return undefined;
  }

  return trimmed.slice(0, 512);
}
