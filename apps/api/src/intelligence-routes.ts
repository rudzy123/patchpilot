import { PERMISSIONS, requirePermission, type TrustedActor } from '@patchpilot/auth';
import type { ServerConfig } from '@patchpilot/config';
import { intelligenceProviderParamSchema } from '@patchpilot/contracts';
import {
  INTELLIGENCE_PROVIDER_NOT_FOUND,
  INTELLIGENCE_STATUS_INCONSISTENT,
  type IntelligenceStatusActor,
} from '@patchpilot/domain';
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
import { readSingleHeader } from './headers.js';
import { INVALID_REQUEST, sendAppError } from './http-errors.js';
import type { IntelligenceRuntime } from './intelligence-runtime.js';
import { toPublicProviderList, toPublicProviderStatus } from './intelligence-views.js';

export async function registerIntelligenceRoutes(
  app: FastifyInstance,
  dependencies: {
    config: ServerConfig;
    auth: AuthRuntime;
    intelligence: IntelligenceRuntime;
  },
): Promise<void> {
  const { config, auth, intelligence } = dependencies;

  await app.register(
    async (scoped) => {
      scoped.addHook('onRequest', async (request, reply) => {
        applyPrivateNoStore(request, reply);
      });

      scoped.setNotFoundHandler((request, reply) => {
        applyPrivateNoStore(request, reply);
        return sendAppError(request, reply, INTELLIGENCE_PROVIDER_NOT_FOUND);
      });

      scoped.get('/providers', async (request, reply) => {
        if (rejectGetRequestBody(request, reply) !== undefined) {
          return;
        }
        const actor = await requireIntelligenceReadActor(request, reply, config, auth);
        if (actor === undefined) {
          return;
        }

        const result = await intelligence.query.list({ actor: toStatusActor(actor) });
        if (!result.ok) {
          return sendAppError(request, reply, result.error);
        }

        try {
          return reply.status(200).send(toPublicProviderList(result.value));
        } catch {
          return sendAppError(request, reply, INTELLIGENCE_STATUS_INCONSISTENT);
        }
      });

      scoped.get('/providers/:provider/status', async (request, reply) => {
        if (rejectGetRequestBody(request, reply) !== undefined) {
          return;
        }
        const actor = await requireIntelligenceReadActor(request, reply, config, auth);
        if (actor === undefined) {
          return;
        }

        const parsed = intelligenceProviderParamSchema.safeParse(request.params);
        if (!parsed.success) {
          return sendAppError(request, reply, INTELLIGENCE_PROVIDER_NOT_FOUND);
        }

        const result = await intelligence.query.get({
          actor: toStatusActor(actor),
          provider: parsed.data.provider,
        });
        if (!result.ok) {
          return sendAppError(request, reply, result.error);
        }

        try {
          return reply.status(200).send(toPublicProviderStatus(result.value));
        } catch {
          return sendAppError(request, reply, INTELLIGENCE_STATUS_INCONSISTENT);
        }
      });
    },
    { prefix: '/intelligence' },
  );
}

async function requireIntelligenceReadActor(
  request: FastifyRequest,
  reply: FastifyReply,
  config: ServerConfig,
  auth: AuthRuntime,
): Promise<TrustedActor | undefined> {
  const authRequest = request as ResolvedAuthRequest;
  bindSessionCookie(authRequest, config.auth.cookieName);
  await resolveBoundSession(authRequest, (sessionToken) =>
    auth.resolveSession.execute({ sessionToken }),
  );
  if (requireAuthenticatedSession(authRequest, reply) !== undefined) {
    return undefined;
  }
  if (requireActiveOrganization(authRequest, reply) !== undefined) {
    return undefined;
  }

  const actor = authRequest.actor;
  if (actor === null) {
    return undefined;
  }

  const permitted = requirePermission(actor, PERMISSIONS.intelligenceRead);
  if (!permitted.ok) {
    sendAppError(request, reply, permitted.error);
    return undefined;
  }

  return actor;
}

function rejectGetRequestBody(
  request: FastifyRequest,
  reply: FastifyReply,
): FastifyReply | undefined {
  if (getRequestCarriesBody(request)) {
    return sendAppError(request, reply, INVALID_REQUEST);
  }
  return undefined;
}

function getRequestCarriesBody(request: FastifyRequest): boolean {
  const lengthHeader = readSingleHeader(request.headers['content-length']);
  if (lengthHeader !== undefined) {
    if (!/^\d+$/.test(lengthHeader) || Number(lengthHeader) > 0) {
      return true;
    }
  }

  const transfer = readSingleHeader(request.headers['transfer-encoding']);
  if (transfer === undefined) {
    return false;
  }
  const encodings = transfer
    .split(',')
    .map((part) => part.trim().toLowerCase())
    .filter((part) => part.length > 0);
  return encodings.some((encoding) => encoding !== 'identity');
}

function toStatusActor(actor: TrustedActor): IntelligenceStatusActor {
  return {
    userId: actor.userId,
    sessionId: actor.sessionId,
    organizationId: actor.organizationId,
    membershipId: actor.membershipId,
    permissions: actor.permissions,
  };
}
