import { LOGIN_RATE_LIMITED } from '@patchpilot/auth';
import type { FastifyRequest } from 'fastify';
import { describe, expect, it } from 'vitest';

import {
  authHttpRateLimitKey,
  authHttpRateLimitMessage,
  createAuthHttpRateLimitError,
} from './auth-http-rate-limit.js';
import { AUTH_HTTP_RATE_LIMITED } from './http-errors.js';

function requestStub(overrides: {
  socket: { remoteAddress: string | undefined };
  headers?: Record<string, string>;
  routeOptions?: { url: string };
  url?: string;
}): FastifyRequest {
  return overrides as unknown as FastifyRequest;
}

describe('auth HTTP rate limit helpers', () => {
  it('keys by the direct socket peer and ignores X-Forwarded-For', () => {
    const request = requestStub({
      socket: { remoteAddress: '192.0.2.10' },
      headers: { 'x-forwarded-for': '203.0.113.9' },
    });

    expect(authHttpRateLimitKey(request)).toBe('192.0.2.10');
  });

  it('groups missing peer addresses onto a shared key', () => {
    const request = requestStub({
      socket: { remoteAddress: undefined },
      headers: {},
    });

    expect(authHttpRateLimitKey(request)).toBe('unknown-peer');
  });

  it('uses the login message only on POST /auth/login', () => {
    const login = requestStub({
      socket: { remoteAddress: '192.0.2.10' },
      routeOptions: { url: '/auth/login' },
      url: '/auth/login',
    });
    const session = requestStub({
      socket: { remoteAddress: '192.0.2.10' },
      routeOptions: { url: '/auth/session' },
      url: '/auth/session',
    });

    expect(authHttpRateLimitMessage(login)).toBe(LOGIN_RATE_LIMITED.message);
    expect(authHttpRateLimitMessage(session)).toBe(AUTH_HTTP_RATE_LIMITED.message);

    const error = createAuthHttpRateLimitError(login, { statusCode: 429 });
    expect(error.statusCode).toBe(429);
    expect(error.message).toBe(LOGIN_RATE_LIMITED.message);
  });
});
