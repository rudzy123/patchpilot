import type { AuthConfig } from '@patchpilot/config';
import type { FastifyReply, FastifyRequest } from 'fastify';

export function sessionCookieOptions(auth: AuthConfig) {
  return {
    path: '/' as const,
    httpOnly: true as const,
    secure: auth.cookieSecure,
    sameSite: 'lax' as const,
    signed: false as const,
    maxAge: auth.sessionAbsoluteTtlSeconds,
  };
}

export function readSessionCookie(request: FastifyRequest, cookieName: string): string | undefined {
  const value = request.cookies[cookieName];
  if (typeof value !== 'string' || value.length === 0) {
    return undefined;
  }

  return value;
}

export function issueSessionCookie(
  reply: FastifyReply,
  auth: AuthConfig,
  sessionToken: string,
): void {
  void reply.setCookie(auth.cookieName, sessionToken, sessionCookieOptions(auth));
}

export function clearSessionCookie(reply: FastifyReply, auth: AuthConfig): void {
  void reply.clearCookie(auth.cookieName, {
    path: '/',
    httpOnly: true,
    secure: auth.cookieSecure,
    sameSite: 'lax',
    signed: false,
  });
}
