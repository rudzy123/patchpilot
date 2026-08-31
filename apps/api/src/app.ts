import { randomUUID } from 'node:crypto';

import cookie from '@fastify/cookie';
import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import { LOGIN_RATE_LIMITED, type TrustedActor } from '@patchpilot/auth';
import { SBOM_IDEMPOTENCY_KEY_HEADER_NAME, type ServerConfig } from '@patchpilot/config';
import {
  healthLiveResponseSchema,
  healthReadyResponseSchema,
  utcNowIso,
  type HealthLiveResponse,
  type HealthReadyResponse,
} from '@patchpilot/contracts';
import { type Logger, createChildLogger } from '@patchpilot/logger';
import Fastify, { type FastifyInstance } from 'fastify';
import type { SessionRecord } from '@patchpilot/domain';

import { registerAssetRoutes } from './asset-routes.js';
import type { AssetRuntime } from './asset-runtime.js';
import { registerAuthRoutes } from './auth-routes.js';
import type { AuthRuntime } from './auth-runtime.js';
import { registerSbomRoutes } from './sbom-routes.js';
import type { SbomRuntime } from './sbom-runtime.js';
import { readSingleHeader } from './headers.js';
import { AUTH_HTTP_RATE_LIMITED } from './http-errors.js';
import { resolveRequestIdentifiers } from './ids.js';

export type DatabaseReadyCheck = (timeoutMs: number) => Promise<{ ok: boolean }>;

export type ApiDependencies = {
  config: ServerConfig;
  logger: Logger;
  checkDatabaseReady: DatabaseReadyCheck;
  auth: AuthRuntime;
  assets: AssetRuntime;
  sboms: SbomRuntime;
  now?: () => string;
  generateId?: () => string;
};

declare module 'fastify' {
  interface FastifyRequest {
    requestId: string;
    correlationId: string;
    actor: TrustedActor | null;
    authSession: SessionRecord | null;
    sessionToken: string | null;
  }
}

export async function buildApi(dependencies: ApiDependencies): Promise<FastifyInstance> {
  const generateId = dependencies.generateId ?? randomUUID;
  const now = dependencies.now ?? utcNowIso;
  const app = Fastify({
    logger: false,
    disableRequestLogging: true,
    trustProxy: false,
    bodyLimit: dependencies.config.requestBodyLimitBytes,
    ajv: {
      customOptions: {
        removeAdditional: true,
      },
    },
  });

  app.decorateRequest('requestId', '');
  app.decorateRequest('correlationId', '');
  app.decorateRequest('actor', null);
  app.decorateRequest('authSession', null);
  app.decorateRequest('sessionToken', null);

  await app.register(helmet, {
    global: true,
    contentSecurityPolicy: false,
    xPoweredBy: false,
  });

  await app.register(cookie);

  await app.register(cors, {
    origin: dependencies.config.corsAllowedOrigins,
    credentials: true,
    allowedHeaders: [
      'content-type',
      dependencies.config.requestIdHeader,
      dependencies.config.correlationIdHeader,
      dependencies.config.auth.csrfHeaderName,
      SBOM_IDEMPOTENCY_KEY_HEADER_NAME,
    ],
  });

  app.addHook('onRequest', async (request, reply) => {
    const headerName = dependencies.config.requestIdHeader.toLowerCase();
    const correlationHeaderName = dependencies.config.correlationIdHeader.toLowerCase();
    const identifiers = resolveRequestIdentifiers({
      requestIdHeader: readSingleHeader(request.headers[headerName]),
      correlationIdHeader: readSingleHeader(request.headers[correlationHeaderName]),
      generateId,
    });
    request.requestId = identifiers.requestId;
    request.correlationId = identifiers.correlationId;
    reply.header(dependencies.config.requestIdHeader, identifiers.requestId);
    reply.header(dependencies.config.correlationIdHeader, identifiers.correlationId);
  });

  app.setNotFoundHandler((request, reply) => {
    void reply.status(404).send({
      error: {
        code: 'not_found',
        message: 'Not found.',
        requestId: request.requestId,
        correlationId: request.correlationId,
      },
    });
  });

  app.setErrorHandler((error, request, reply) => {
    const statusCode = fastifyStatusCode(error);
    const isPayloadTooLarge = statusCode === 413;
    const isRateLimited = statusCode === 429;
    const code = isPayloadTooLarge
      ? 'validation'
      : isRateLimited
        ? 'rate_limited'
        : statusCode >= 400 && statusCode < 500
          ? 'validation'
          : 'internal';
    const publicMessage =
      dependencies.config.deploymentEnvironment === 'production' && code === 'internal'
        ? 'An internal error occurred.'
        : isPayloadTooLarge
          ? 'Request body is too large.'
          : isRateLimited
            ? rateLimitedPublicMessage(error)
            : errorMessage(error);

    dependencies.logger.error(
      {
        requestId: request.requestId,
        correlationId: request.correlationId,
        statusCode,
        err: {
          type: errorName(error),
          ...(dependencies.config.deploymentEnvironment === 'production'
            ? {}
            : { message: errorMessage(error) }),
        },
      },
      'request failed',
    );

    void reply.status(statusCode >= 400 ? statusCode : 500).send({
      error: {
        code,
        message: publicMessage,
        requestId: request.requestId,
        correlationId: request.correlationId,
      },
    });
  });

  app.get('/health/live', async (): Promise<HealthLiveResponse> => {
    const payload = {
      status: 'live' as const,
      service: 'api' as const,
      timestamp: now(),
      version: '0.0.0',
    };
    return healthLiveResponseSchema.parse(payload);
  });

  app.get('/health/ready', async (_request, reply): Promise<HealthReadyResponse> => {
    const database = await dependencies.checkDatabaseReady(dependencies.config.readinessTimeoutMs);
    const payload = {
      status: database.ok ? ('ready' as const) : ('not_ready' as const),
      service: 'api' as const,
      timestamp: now(),
      version: '0.0.0',
      checks: [{ name: 'database', status: database.ok ? ('up' as const) : ('down' as const) }],
    };
    const parsed = healthReadyResponseSchema.parse(payload);
    if (parsed.status === 'not_ready') {
      void reply.status(503);
    }

    return parsed;
  });

  await registerAuthRoutes(app, {
    config: dependencies.config,
    logger: dependencies.logger,
    auth: dependencies.auth,
  });

  await registerAssetRoutes(app, {
    config: dependencies.config,
    auth: dependencies.auth,
    assets: dependencies.assets,
  });

  await registerSbomRoutes(app, {
    config: dependencies.config,
    auth: dependencies.auth,
    sboms: dependencies.sboms,
  });

  app.addHook('onSend', async (request, _reply, payload) => {
    createChildLogger(dependencies.logger, {
      requestId: request.requestId,
      correlationId: request.correlationId,
    }).info(
      {
        req: {
          method: request.method,
          url: request.routeOptions.url ?? request.url.split('?')[0],
          headers: request.headers,
        },
      },
      'request completed',
    );
    return payload;
  });

  return app;
}

function fastifyStatusCode(error: unknown): number {
  if (typeof error === 'object' && error !== null && 'statusCode' in error) {
    const statusCode = error['statusCode'];
    if (typeof statusCode === 'number') {
      return statusCode;
    }
  }

  return 500;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'An internal error occurred.';
}

function errorName(error: unknown): string {
  return error instanceof Error ? error.name : 'Error';
}

function rateLimitedPublicMessage(error: unknown): string {
  const message = errorMessage(error);
  if (message === LOGIN_RATE_LIMITED.message || message === AUTH_HTTP_RATE_LIMITED.message) {
    return message;
  }

  return AUTH_HTTP_RATE_LIMITED.message;
}
