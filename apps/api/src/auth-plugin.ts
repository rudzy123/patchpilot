import {
  AUTHENTICATION_REQUIRED,
  csrfTokenMatchesDigest,
  type TrustedActor,
} from '@patchpilot/auth';
import type { ServerConfig } from '@patchpilot/config';
import { ORGANIZATION_CONTEXT_REQUIRED, type Result, type SessionRecord } from '@patchpilot/domain';
import type { FastifyReply, FastifyRequest } from 'fastify';

import { readSessionCookie } from './cookies.js';
import { isJsonContentType, readSingleHeader } from './headers.js';
import { JSON_CONTENT_TYPE_REQUIRED, ORIGIN_NOT_ALLOWED, sendAppError } from './http-errors.js';
import { exactOriginAllowed } from './origin.js';

export type ResolvedAuthRequest = FastifyRequest & {
  actor: TrustedActor | null;
  authSession: SessionRecord | null;
  sessionToken: string | null;
};

export function applyAuthNoStore(_request: FastifyRequest, reply: FastifyReply): void {
  void reply.header('cache-control', 'no-store');
}

export function requireJsonMutation(
  request: FastifyRequest,
  reply: FastifyReply,
): FastifyReply | undefined {
  if (!isJsonContentType(request.headers['content-type'])) {
    return sendAppError(request, reply, JSON_CONTENT_TYPE_REQUIRED);
  }

  return undefined;
}

export function requireAllowedOrigin(
  request: FastifyRequest,
  reply: FastifyReply,
  allowedOrigins: readonly string[],
): FastifyReply | undefined {
  const origin = readSingleHeader(request.headers.origin);
  if (!exactOriginAllowed(origin, allowedOrigins)) {
    return sendAppError(request, reply, ORIGIN_NOT_ALLOWED);
  }

  return undefined;
}

export function bindSessionCookie(request: ResolvedAuthRequest, cookieName: string): void {
  request.actor = null;
  request.authSession = null;
  request.sessionToken = readSessionCookie(request, cookieName) ?? null;
}

export async function resolveBoundSession(
  request: ResolvedAuthRequest,
  resolve: (
    sessionToken: string,
  ) => Promise<Result<{ actor: TrustedActor; session: SessionRecord }>>,
): Promise<void> {
  const sessionToken = request.sessionToken;
  if (sessionToken === null) {
    return;
  }

  const resolved = await resolve(sessionToken);
  if (resolved.ok) {
    request.actor = resolved.value.actor;
    request.authSession = resolved.value.session;
  }
}

export function requireAuthenticatedSession(
  request: ResolvedAuthRequest,
  reply: FastifyReply,
): FastifyReply | undefined {
  if (request.actor === null || request.authSession === null || request.sessionToken === null) {
    return sendAppError(request, reply, AUTHENTICATION_REQUIRED);
  }

  return undefined;
}

export function requireActiveOrganization(
  request: ResolvedAuthRequest,
  reply: FastifyReply,
): FastifyReply | undefined {
  if (
    request.actor === null ||
    request.actor.organizationId === null ||
    request.actor.membershipId === null
  ) {
    return sendAppError(request, reply, ORGANIZATION_CONTEXT_REQUIRED);
  }

  return undefined;
}

export function applyPrivateNoStore(_request: FastifyRequest, reply: FastifyReply): void {
  void reply.header('cache-control', 'private, no-store');
}

export function requireSynchronizerCsrf(
  request: ResolvedAuthRequest,
  reply: FastifyReply,
  config: ServerConfig,
): FastifyReply | undefined {
  if (request.authSession === null) {
    return sendAppError(request, reply, AUTHENTICATION_REQUIRED);
  }

  const presented = readSingleHeader(request.headers[config.auth.csrfHeaderName.toLowerCase()]);
  if (!csrfTokenMatchesDigest(presented, request.authSession.csrfTokenHash)) {
    return sendAppError(request, reply, AUTHENTICATION_REQUIRED);
  }

  return undefined;
}
