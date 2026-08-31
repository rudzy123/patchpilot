import type { Readable } from 'node:stream';

import rateLimit from '@fastify/rate-limit';
import { PERMISSIONS, requirePermission, type TrustedActor } from '@patchpilot/auth';
import {
  SBOM_IDEMPOTENCY_KEY_HEADER_NAME,
  SBOM_IDEMPOTENCY_KEY_MAX_LENGTH,
  SBOM_IDEMPOTENCY_KEY_MIN_LENGTH,
  type ServerConfig,
} from '@patchpilot/config';
import {
  assetIdParamSchema,
  assetSbomIdParamSchema,
  assetSbomIngestionIdParamSchema,
  sbomListQuerySchema,
} from '@patchpilot/contracts';
import { wrapRawIdempotencyKey, type AppError } from '@patchpilot/domain';
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
import { readSingleHeader } from './headers.js';
import {
  AUTH_HTTP_RATE_LIMITED,
  INVALID_REQUEST,
  SBOM_CHARSET_REQUIRED,
  SBOM_CONTENT_TYPE_PARAMETER_REJECTED,
  SBOM_CONTENT_TYPE_REQUIRED,
  SBOM_IDEMPOTENCY_KEY_REQUIRED,
  SBOM_UPLOAD_TOO_LARGE,
  sendAppError,
} from './http-errors.js';
import {
  bytesFromRequestBody,
  parseApprovedSbomContentType,
  parseDeclaredByteLength,
  parseIdempotencyKeyHeader,
} from './sbom-content-type.js';
import {
  createSbomHttpRateLimitError,
  createSbomOrganizationRateLimiter,
  sbomHttpRateLimitKey,
} from './sbom-rate-limit.js';
import type { SbomRuntime } from './sbom-runtime.js';
import {
  toSbomDetail,
  toSbomIngestionStatus,
  toSbomListResponse,
  toSbomUploadAcceptedResponse,
} from './sbom-views.js';

export async function registerSbomRoutes(
  app: FastifyInstance,
  dependencies: {
    config: ServerConfig;
    auth: AuthRuntime;
    sboms: SbomRuntime;
  },
): Promise<void> {
  const { config, auth, sboms } = dependencies;
  const organizationLimiter = createSbomOrganizationRateLimiter({
    max: config.sbom.uploadRateLimitMax,
    windowMs: config.sbom.uploadRateLimitWindowSeconds * 1000,
  });

  await app.register(async (scoped) => {
    scoped.addHook('onRequest', async (request, reply) => {
      applyPrivateNoStore(request, reply);
    });

    await scoped.register(async (uploads) => {
      await uploads.register(rateLimit, {
        global: true,
        hook: 'onRequest',
        skipOnError: false,
        max: config.sbom.uploadRateLimitMax,
        timeWindow: config.sbom.uploadRateLimitWindowSeconds * 1000,
        keyGenerator: sbomHttpRateLimitKey,
        errorResponseBuilder: createSbomHttpRateLimitError,
      });

      uploads.addContentTypeParser('application/json', passThroughBody);
      uploads.addContentTypeParser('application/vnd.cyclonedx+json', passThroughBody);

      uploads.post(
        '/assets/:assetId/sboms',
        {
          bodyLimit: config.sbom.uploadMaxBytes,
        },
        async (request, reply) => {
          const actor = await requireSbomUploadActor(request, reply, config, auth);
          if (actor === undefined) {
            return;
          }
          if (!organizationLimiter.consume(actor.organizationId)) {
            return sendAppError(request, reply, AUTH_HTTP_RATE_LIMITED);
          }

          const params = parseValue(assetIdParamSchema, request.params);
          if (!params.ok) {
            return sendAppError(request, reply, INVALID_REQUEST);
          }

          const contentType = parseApprovedSbomContentType(
            readSingleHeader(request.headers['content-type']),
          );
          if (!contentType.ok) {
            return sendAppError(request, reply, contentTypeError(contentType.reason));
          }

          const idempotencyKey = parseIdempotencyKeyHeader(
            readSingleHeader(request.headers[SBOM_IDEMPOTENCY_KEY_HEADER_NAME.toLowerCase()]),
            SBOM_IDEMPOTENCY_KEY_MIN_LENGTH,
            SBOM_IDEMPOTENCY_KEY_MAX_LENGTH,
          );
          if (!idempotencyKey.ok) {
            return sendAppError(request, reply, SBOM_IDEMPOTENCY_KEY_REQUIRED);
          }

          const declared = parseDeclaredByteLength(
            readSingleHeader(request.headers['content-length']),
            config.sbom.uploadMaxBytes,
          );
          if (!declared.ok) {
            return sendAppError(
              request,
              reply,
              declared.tooLarge ? SBOM_UPLOAD_TOO_LARGE : INVALID_REQUEST,
            );
          }

          const result = await sboms.upload.execute({
            actor,
            assetId: params.value.assetId,
            idempotencyKey: wrapRawIdempotencyKey(idempotencyKey.value),
            contentType: contentType.contentType,
            body: bytesFromRequestBody(request.body),
            maxBytes: config.sbom.uploadMaxBytes,
            parserVersion: config.sbom.parserVersion,
            normalizationVersion: config.sbom.normalizationVersion,
            idempotencyTtlMs: config.sbom.idempotencyTtlSeconds * 1000,
            correlationId: request.correlationId,
            requestId: request.requestId,
            signal: requestAbortSignal(request),
            ...(declared.value === undefined ? {} : { declaredByteLength: declared.value }),
          });
          if (!result.ok) {
            return sendAppError(request, reply, result.error);
          }

          return reply.status(202).send(toSbomUploadAcceptedResponse(result.value));
        },
      );
    });

    scoped.get('/assets/:assetId/sboms', async (request, reply) => {
      const actor = await requireSbomReadActor(request, reply, config, auth);
      if (actor === undefined) {
        return;
      }

      const params = parseValue(assetIdParamSchema, request.params);
      if (!params.ok) {
        return sendAppError(request, reply, INVALID_REQUEST);
      }
      const query = parseValue(sbomListQuerySchema, request.query);
      if (!query.ok) {
        return sendAppError(request, reply, INVALID_REQUEST);
      }

      const result = await sboms.list.execute({
        actor,
        assetId: params.value.assetId,
        query: query.value,
      });
      if (!result.ok) {
        return sendAppError(request, reply, result.error);
      }

      return reply.status(200).send(toSbomListResponse(result.value));
    });

    scoped.get('/assets/:assetId/sboms/:sbomId', async (request, reply) => {
      const actor = await requireSbomReadActor(request, reply, config, auth);
      if (actor === undefined) {
        return;
      }

      const params = parseValue(assetSbomIdParamSchema, request.params);
      if (!params.ok) {
        return sendAppError(request, reply, INVALID_REQUEST);
      }

      const result = await sboms.get.execute({
        actor,
        assetId: params.value.assetId,
        sbomId: params.value.sbomId,
      });
      if (!result.ok) {
        return sendAppError(request, reply, result.error);
      }

      return reply.status(200).send(toSbomDetail(result.value));
    });

    scoped.get('/assets/:assetId/sbom-ingestions/:ingestionId', async (request, reply) => {
      const actor = await requireSbomReadActor(request, reply, config, auth);
      if (actor === undefined) {
        return;
      }

      const params = parseValue(assetSbomIngestionIdParamSchema, request.params);
      if (!params.ok) {
        return sendAppError(request, reply, INVALID_REQUEST);
      }

      const result = await sboms.getIngestion.execute({
        actor,
        assetId: params.value.assetId,
        ingestionId: params.value.ingestionId,
      });
      if (!result.ok) {
        return sendAppError(request, reply, result.error);
      }

      return reply.status(200).send(toSbomIngestionStatus(result.value));
    });
  });
}

async function requireSbomReadActor(
  request: FastifyRequest,
  reply: FastifyReply,
  config: ServerConfig,
  auth: AuthRuntime,
): Promise<(TrustedActor & { organizationId: string; membershipId: string }) | undefined> {
  return requireSbomActor(request, reply, config, auth, PERMISSIONS.sbomRead, false);
}

async function requireSbomUploadActor(
  request: FastifyRequest,
  reply: FastifyReply,
  config: ServerConfig,
  auth: AuthRuntime,
): Promise<(TrustedActor & { organizationId: string; membershipId: string }) | undefined> {
  return requireSbomActor(request, reply, config, auth, PERMISSIONS.sbomUpload, true);
}

async function requireSbomActor(
  request: FastifyRequest,
  reply: FastifyReply,
  config: ServerConfig,
  auth: AuthRuntime,
  permission: (typeof PERMISSIONS)['sbomRead'] | (typeof PERMISSIONS)['sbomUpload'],
  mutation: boolean,
): Promise<(TrustedActor & { organizationId: string; membershipId: string }) | undefined> {
  const authRequest = request as ResolvedAuthRequest;
  bindSessionCookie(authRequest, config.auth.cookieName);

  if (mutation && requireAllowedOrigin(request, reply, config.corsAllowedOrigins) !== undefined) {
    return undefined;
  }

  await resolveBoundSession(authRequest, (sessionToken) =>
    auth.resolveSession.execute({ sessionToken }),
  );
  if (requireAuthenticatedSession(authRequest, reply) !== undefined) {
    return undefined;
  }
  if (mutation && requireSynchronizerCsrf(authRequest, reply, config) !== undefined) {
    return undefined;
  }
  if (requireActiveOrganization(authRequest, reply) !== undefined) {
    return undefined;
  }

  const actor = authRequest.actor;
  if (actor === null || actor.organizationId === null || actor.membershipId === null) {
    return undefined;
  }

  const permitted = requirePermission(actor, permission);
  if (!permitted.ok) {
    sendAppError(request, reply, permitted.error);
    return undefined;
  }

  return actor as TrustedActor & { organizationId: string; membershipId: string };
}

function contentTypeError(reason: 'media_type' | 'charset' | 'parameter'): AppError {
  if (reason === 'charset') {
    return SBOM_CHARSET_REQUIRED;
  }
  if (reason === 'parameter') {
    return SBOM_CONTENT_TYPE_PARAMETER_REJECTED;
  }
  return SBOM_CONTENT_TYPE_REQUIRED;
}

function passThroughBody(
  _request: FastifyRequest,
  payload: Readable,
  done: (error: null, body?: unknown) => void,
): void {
  done(null, payload);
}

function requestAbortSignal(request: FastifyRequest): AbortSignal {
  const controller = new AbortController();
  if (request.raw.aborted || request.raw.destroyed) {
    controller.abort();
    return controller.signal;
  }
  request.raw.once('aborted', () => {
    controller.abort();
  });
  return controller.signal;
}

function parseValue<T>(
  schema: { safeParse: (value: unknown) => { success: true; data: T } | { success: false } },
  value: unknown,
): { ok: true; value: T } | { ok: false } {
  const parsed = schema.safeParse(value);
  if (!parsed.success) {
    return { ok: false };
  }

  return { ok: true, value: parsed.data };
}
