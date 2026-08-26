import { randomUUID } from 'node:crypto';

import cors from '@fastify/cors';
import helmet from '@fastify/helmet';
import { type ServerConfig } from '@patchpilot/config';
import {
  healthLiveResponseSchema,
  healthReadyResponseSchema,
  utcNowIso,
  type HealthLiveResponse,
  type HealthReadyResponse,
} from '@patchpilot/contracts';
import { type Logger, createChildLogger } from '@patchpilot/logger';
import Fastify, { type FastifyInstance } from 'fastify';

import { resolveRequestIdentifiers } from './ids.js';

export type DatabaseReadyCheck = (timeoutMs: number) => Promise<{ ok: boolean }>;

export type ApiDependencies = {
  config: ServerConfig;
  logger: Logger;
  checkDatabaseReady: DatabaseReadyCheck;
  now?: () => string;
  generateId?: () => string;
};

declare module 'fastify' {
  interface FastifyRequest {
    requestId: string;
    correlationId: string;
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

  await app.register(helmet, {
    global: true,
    contentSecurityPolicy: false,
    xPoweredBy: false,
  });

  await app.register(cors, {
    origin: dependencies.config.corsAllowedOrigins,
    credentials: true,
  });

  app.addHook('onRequest', async (request, reply) => {
    const headerName = dependencies.config.requestIdHeader.toLowerCase();
    const correlationHeaderName = dependencies.config.correlationIdHeader.toLowerCase();
    const identifiers = resolveRequestIdentifiers({
      requestIdHeader: headerValue(request.headers[headerName]),
      correlationIdHeader: headerValue(request.headers[correlationHeaderName]),
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
    const code = isPayloadTooLarge
      ? 'validation'
      : statusCode >= 400 && statusCode < 500
        ? 'validation'
        : 'internal';
    const publicMessage =
      dependencies.config.deploymentEnvironment === 'production' && code === 'internal'
        ? 'An internal error occurred.'
        : isPayloadTooLarge
          ? 'Request body is too large.'
          : errorMessage(error);

    dependencies.logger.error(
      {
        requestId: request.requestId,
        correlationId: request.correlationId,
        statusCode,
        err: { type: errorName(error), message: errorMessage(error) },
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
      checks: [{ name: 'postgresql', status: database.ok ? ('up' as const) : ('down' as const) }],
    };
    const parsed = healthReadyResponseSchema.parse(payload);
    if (parsed.status === 'not_ready') {
      void reply.status(503);
    }

    return parsed;
  });

  app.addHook('onSend', async (request, _reply, payload) => {
    createChildLogger(dependencies.logger, {
      requestId: request.requestId,
      correlationId: request.correlationId,
    }).info(
      {
        req: {
          method: request.method,
          url: request.url,
          headers: request.headers,
        },
      },
      'request completed',
    );
    return payload;
  });

  return app;
}

function headerValue(value: string | string[] | undefined): string | undefined {
  if (typeof value === 'string') {
    return value;
  }

  if (Array.isArray(value) && typeof value[0] === 'string') {
    return value[0];
  }

  return undefined;
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
