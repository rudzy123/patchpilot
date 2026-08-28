import { PERMISSIONS, requirePermission, type TrustedActor } from '@patchpilot/auth';
import type { ServerConfig } from '@patchpilot/config';
import {
  archiveAssetRequestSchema,
  assetIdParamSchema,
  assetListQuerySchema,
  assetOptionsQuerySchema,
  createAssetRequestSchema,
  updateAssetRequestSchema,
} from '@patchpilot/contracts';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

import {
  applyPrivateNoStore,
  bindSessionCookie,
  requireActiveOrganization,
  requireAllowedOrigin,
  requireAuthenticatedSession,
  requireJsonMutation,
  requireSynchronizerCsrf,
  resolveBoundSession,
  type ResolvedAuthRequest,
} from './auth-plugin.js';
import type { AuthRuntime } from './auth-runtime.js';
import type { AssetRuntime } from './asset-runtime.js';
import {
  toAssetDetail,
  toAssetListResponse,
  toEnvironmentOptionsResponse,
  toMembershipOptionsResponse,
  toTeamOptionsResponse,
} from './asset-views.js';
import { INVALID_REQUEST, sendAppError } from './http-errors.js';

export async function registerAssetRoutes(
  app: FastifyInstance,
  dependencies: {
    config: ServerConfig;
    auth: AuthRuntime;
    assets: AssetRuntime;
  },
): Promise<void> {
  const { config, auth, assets } = dependencies;

  await app.register(async (scoped) => {
    scoped.addHook('onRequest', async (request, reply) => {
      applyPrivateNoStore(request, reply);
    });

    scoped.get('/assets', async (request, reply) => {
      const actor = await requireAssetReadActor(request, reply, config, auth);
      if (actor === undefined) {
        return;
      }

      const parsed = parseValue(assetListQuerySchema, request.query);
      if (!parsed.ok) {
        return sendAppError(request, reply, INVALID_REQUEST);
      }

      const result = await assets.list.execute({ actor, query: parsed.value });
      if (!result.ok) {
        return sendAppError(request, reply, result.error);
      }

      return reply.status(200).send(toAssetListResponse(result.value));
    });

    scoped.get('/assets/:assetId', async (request, reply) => {
      const actor = await requireAssetReadActor(request, reply, config, auth);
      if (actor === undefined) {
        return;
      }

      const params = parseValue(assetIdParamSchema, request.params);
      if (!params.ok) {
        return sendAppError(request, reply, INVALID_REQUEST);
      }

      const result = await assets.get.execute({ actor, assetId: params.value.assetId });
      if (!result.ok) {
        return sendAppError(request, reply, result.error);
      }

      return reply.status(200).send(toAssetDetail(result.value));
    });

    scoped.post('/assets', async (request, reply) => {
      const actor = await requireAssetManageActor(request, reply, config, auth);
      if (actor === undefined) {
        return;
      }

      const parsed = parseValue(createAssetRequestSchema, request.body);
      if (!parsed.ok) {
        return sendAppError(request, reply, INVALID_REQUEST);
      }

      const result = await assets.create.execute({
        actor,
        fields: parsed.value,
        correlationId: request.correlationId,
        requestId: request.requestId,
      });
      if (!result.ok) {
        return sendAppError(request, reply, result.error);
      }

      return reply.status(201).send(toAssetDetail(result.value));
    });

    scoped.patch('/assets/:assetId', async (request, reply) => {
      const actor = await requireAssetManageActor(request, reply, config, auth);
      if (actor === undefined) {
        return;
      }

      const params = parseValue(assetIdParamSchema, request.params);
      if (!params.ok) {
        return sendAppError(request, reply, INVALID_REQUEST);
      }

      const parsed = parseValue(updateAssetRequestSchema, request.body);
      if (!parsed.ok) {
        return sendAppError(request, reply, INVALID_REQUEST);
      }

      const result = await assets.update.execute({
        actor,
        assetId: params.value.assetId,
        fields: parsed.value,
        correlationId: request.correlationId,
        requestId: request.requestId,
      });
      if (!result.ok) {
        return sendAppError(request, reply, result.error);
      }

      return reply.status(200).send(toAssetDetail(result.value));
    });

    scoped.post('/assets/:assetId/archive', async (request, reply) => {
      const actor = await requireAssetManageActor(request, reply, config, auth);
      if (actor === undefined) {
        return;
      }

      const params = parseValue(assetIdParamSchema, request.params);
      if (!params.ok) {
        return sendAppError(request, reply, INVALID_REQUEST);
      }

      const parsed = parseValue(archiveAssetRequestSchema, request.body);
      if (!parsed.ok) {
        return sendAppError(request, reply, INVALID_REQUEST);
      }

      const result = await assets.archive.execute({
        actor,
        assetId: params.value.assetId,
        expectedVersion: parsed.value.expectedVersion,
        correlationId: request.correlationId,
        requestId: request.requestId,
      });
      if (!result.ok) {
        return sendAppError(request, reply, result.error);
      }

      return reply.status(200).send(toAssetDetail(result.value));
    });

    scoped.get('/asset-options/environments', async (request, reply) => {
      const actor = await requireAssetReadActor(request, reply, config, auth);
      if (actor === undefined) {
        return;
      }

      const parsed = parseValue(assetOptionsQuerySchema, request.query);
      if (!parsed.ok) {
        return sendAppError(request, reply, INVALID_REQUEST);
      }

      const result = await assets.listEnvironments.execute({
        actor,
        page: parsed.value,
      });
      if (!result.ok) {
        return sendAppError(request, reply, result.error);
      }

      return reply.status(200).send(toEnvironmentOptionsResponse(result.value));
    });

    scoped.get('/asset-options/teams', async (request, reply) => {
      const actor = await requireAssetReadActor(request, reply, config, auth);
      if (actor === undefined) {
        return;
      }

      const parsed = parseValue(assetOptionsQuerySchema, request.query);
      if (!parsed.ok) {
        return sendAppError(request, reply, INVALID_REQUEST);
      }

      const result = await assets.listTeams.execute({
        actor,
        page: parsed.value,
      });
      if (!result.ok) {
        return sendAppError(request, reply, result.error);
      }

      return reply.status(200).send(toTeamOptionsResponse(result.value));
    });

    scoped.get('/asset-options/memberships', async (request, reply) => {
      const actor = await requireAssetReadActor(request, reply, config, auth);
      if (actor === undefined) {
        return;
      }

      const parsed = parseValue(assetOptionsQuerySchema, request.query);
      if (!parsed.ok) {
        return sendAppError(request, reply, INVALID_REQUEST);
      }

      const result = await assets.listMemberships.execute({
        actor,
        page: parsed.value,
      });
      if (!result.ok) {
        return sendAppError(request, reply, result.error);
      }

      return reply.status(200).send(toMembershipOptionsResponse(result.value));
    });
  });
}

async function requireAssetReadActor(
  request: FastifyRequest,
  reply: FastifyReply,
  config: ServerConfig,
  auth: AuthRuntime,
): Promise<TrustedActor | undefined> {
  return requireAssetActor(request, reply, config, auth, PERMISSIONS.assetRead, false);
}

async function requireAssetManageActor(
  request: FastifyRequest,
  reply: FastifyReply,
  config: ServerConfig,
  auth: AuthRuntime,
): Promise<TrustedActor | undefined> {
  return requireAssetActor(request, reply, config, auth, PERMISSIONS.assetManage, true);
}

async function requireAssetActor(
  request: FastifyRequest,
  reply: FastifyReply,
  config: ServerConfig,
  auth: AuthRuntime,
  permission: (typeof PERMISSIONS)['assetRead'] | (typeof PERMISSIONS)['assetManage'],
  mutation: boolean,
): Promise<TrustedActor | undefined> {
  const authRequest = request as ResolvedAuthRequest;
  bindSessionCookie(authRequest, config.auth.cookieName);

  if (mutation) {
    if (requireJsonMutation(request, reply) !== undefined) {
      return undefined;
    }
    if (requireAllowedOrigin(request, reply, config.corsAllowedOrigins) !== undefined) {
      return undefined;
    }
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
  if (actor === null) {
    return undefined;
  }

  const permitted = requirePermission(actor, permission);
  if (!permitted.ok) {
    sendAppError(request, reply, permitted.error);
    return undefined;
  }

  return actor;
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
