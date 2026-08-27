import { loadServerConfigFrom } from '@patchpilot/config';
import type { SessionResponse } from '@patchpilot/contracts';
import { createFoundationProductionTestEnv } from '@patchpilot/test-utils';
import { describe, expect, it } from 'vitest';

import {
  TEST_ORIGIN,
  VALID_PASSWORD,
  buildTestApi,
  createAuthTestHarness,
} from './auth-test-harness.js';

const SOCKET_IP = '192.0.2.10';
const FORWARDED_IP = '203.0.113.9';
const FOREIGN_ORGANIZATION_ID = '33333333-3333-4333-8333-333333333333';

describe('authentication routes', () => {
  it('logs in with generic failures, issues cookies, and ignores X-Forwarded-For', async () => {
    const { app, harness } = await buildTestApi({ membershipCount: 1 });
    const success = await login(app, harness.user.email, VALID_PASSWORD);
    expect(success.statusCode).toBe(200);
    expect(success.headers['cache-control']).toBe('no-store');
    const body = success.json() as SessionResponse;
    expect(body.user).toEqual({
      id: harness.user.id,
      displayName: harness.user.displayName,
    });
    expect(body.organization?.id).toBe(harness.organizations[0]?.id);
    expect(body.csrfToken.length).toBeGreaterThan(8);
    const setCookie = firstSetCookie(success);
    expect(setCookie.startsWith(`${harness.config.auth.cookieName}=`)).toBe(true);
    expect(setCookie).toMatch(/HttpOnly/i);
    expect(setCookie).toMatch(/Path=\//);
    expect(setCookie).toMatch(/SameSite=Lax/i);
    expect(setCookie).not.toMatch(/Domain=/i);
    expect(setCookie).not.toMatch(/Secure/i);
    expect(harness.limiter.consumeCalls[0]?.peerIp).toBe(SOCKET_IP);
    expect(JSON.stringify(harness.limiter.consumeCalls)).not.toContain(FORWARDED_IP);

    const unknown = await login(app, 'missing@synthetic.patchpilot.test', VALID_PASSWORD);
    const wrong = await login(app, harness.user.email, 'wrong-password-12');
    expect(unknown.statusCode).toBe(401);
    expect(wrong.statusCode).toBe(401);
    expect(unknown.json()).toMatchObject({
      error: { code: 'unauthorized', message: 'Invalid email or password.' },
    });
    expect(wrong.json().error.message).toBe(unknown.json().error.message);

    const extraActor = await login(app, harness.user.email, VALID_PASSWORD, {
      actorUserId: harness.user.id,
      actorType: 'system',
    });
    expect(extraActor.statusCode).toBe(200);
    expect(harness.audit.events.some((event) => event.actorType === 'system')).toBe(false);
    expect(harness.audit.events.some((event) => event.action === 'auth.login_succeeded')).toBe(
      true,
    );
    expect(harness.audit.events.some((event) => event.action === 'auth.login_failed')).toBe(true);
    assertNoSecrets(JSON.stringify(harness.audit.events), {
      password: VALID_PASSWORD,
      email: harness.user.email,
      csrfToken: body.csrfToken,
      cookie: cookieValue(setCookie, harness.config.auth.cookieName),
    });
    assertNoSecrets(harness.logs(), {
      password: VALID_PASSWORD,
      csrfToken: body.csrfToken,
      cookie: cookieValue(setCookie, harness.config.auth.cookieName),
    });
    await app.close();
  });

  it('uses production __Host- cookie attributes', async () => {
    const config = loadServerConfigFrom(createFoundationProductionTestEnv());
    const harness = createAuthTestHarness({ config, membershipCount: 1 });
    const { app } = await buildTestApi({ config, harness });
    const response = await app.inject({
      method: 'POST',
      url: '/auth/login',
      remoteAddress: SOCKET_IP,
      headers: {
        origin: 'https://patchpilot.example',
        'content-type': 'application/json',
      },
      payload: { email: harness.user.email, password: VALID_PASSWORD },
    });
    expect(response.statusCode).toBe(200);
    const setCookie = firstSetCookie(response);
    expect(setCookie.startsWith('__Host-patchpilot.sid=')).toBe(true);
    expect(setCookie).toMatch(/HttpOnly/i);
    expect(setCookie).toMatch(/Secure/i);
    expect(setCookie).toMatch(/SameSite=Lax/i);
    expect(setCookie).toMatch(/Path=\//);
    expect(setCookie).not.toMatch(/Domain=/i);
    await app.close();
  });

  it('rejects disallowed login Origin and non-JSON mutations', async () => {
    const { app, harness } = await buildTestApi();
    const evil = await app.inject({
      method: 'POST',
      url: '/auth/login',
      remoteAddress: SOCKET_IP,
      headers: {
        origin: 'https://evil.example',
        'content-type': 'application/json',
      },
      payload: { email: harness.user.email, password: VALID_PASSWORD },
    });
    expect(evil.statusCode).toBe(403);
    expect(evil.json()).toMatchObject({ error: { code: 'forbidden' } });

    const form = await app.inject({
      method: 'POST',
      url: '/auth/login',
      remoteAddress: SOCKET_IP,
      headers: {
        origin: TEST_ORIGIN,
        'content-type': 'application/x-www-form-urlencoded',
      },
      payload: `email=${harness.user.email}&password=${VALID_PASSWORD}`,
    });
    expect(form.statusCode).toBe(415);
    expect(form.json()).toMatchObject({ error: { code: 'validation' } });
    await app.close();
  });

  it('permits x-csrf-token in CORS only for approved origins', async () => {
    const { app } = await buildTestApi();
    const allowed = await app.inject({
      method: 'OPTIONS',
      url: '/auth/logout',
      headers: {
        origin: TEST_ORIGIN,
        'access-control-request-method': 'POST',
        'access-control-request-headers': 'content-type,x-csrf-token',
      },
    });
    expect(allowed.headers['access-control-allow-origin']).toBe(TEST_ORIGIN);
    expect(String(allowed.headers['access-control-allow-headers']).toLowerCase()).toContain(
      'x-csrf-token',
    );

    const denied = await app.inject({
      method: 'OPTIONS',
      url: '/auth/logout',
      headers: {
        origin: 'https://evil.example',
        'access-control-request-method': 'POST',
        'access-control-request-headers': 'content-type,x-csrf-token',
      },
    });
    expect(denied.headers['access-control-allow-origin']).not.toBe('https://evil.example');
    await app.close();
  });

  it('requires authentication for session reads and returns no-store plus a CSRF token', async () => {
    const { app, harness } = await buildTestApi({ membershipCount: 1 });
    const unauthenticated = await app.inject({ method: 'GET', url: '/auth/session' });
    expect(unauthenticated.statusCode).toBe(401);
    expect(unauthenticated.headers['cache-control']).toBe('no-store');

    const loggedIn = await login(app, harness.user.email, VALID_PASSWORD);
    const cookie = sessionCookieHeader(loggedIn, harness.config.auth.cookieName);
    const loginCsrf = (loggedIn.json() as SessionResponse).csrfToken;
    const session = await app.inject({
      method: 'GET',
      url: '/auth/session',
      headers: { cookie },
    });
    expect(session.statusCode).toBe(200);
    expect(session.headers['cache-control']).toBe('no-store');
    const body = session.json() as SessionResponse;
    expect(body.csrfToken).not.toBe(loginCsrf);
    expect(body.user.id).toBe(harness.user.id);
    await app.close();
  });

  it('lists only authorized organizations and rejects foreign selection', async () => {
    const { app, harness } = await buildTestApi({ membershipCount: 1 });
    const loggedIn = await login(app, harness.user.email, VALID_PASSWORD);
    const cookie = sessionCookieHeader(loggedIn, harness.config.auth.cookieName);
    const csrf = (loggedIn.json() as SessionResponse).csrfToken;

    const listed = await app.inject({
      method: 'GET',
      url: '/auth/organizations',
      headers: { cookie },
    });
    expect(listed.statusCode).toBe(200);
    expect(listed.headers['cache-control']).toBe('no-store');
    expect(listed.json()).toEqual({
      organizations: [
        {
          id: harness.organizations[0]?.id,
          slug: 'org-one',
          name: 'One',
          role: 'owner',
        },
      ],
    });

    const foreign = await app.inject({
      method: 'POST',
      url: '/auth/select-organization',
      headers: {
        origin: TEST_ORIGIN,
        'content-type': 'application/json',
        cookie,
        'x-csrf-token': csrf,
      },
      payload: { organizationId: FOREIGN_ORGANIZATION_ID },
    });
    expect(foreign.statusCode).toBe(404);
    expect(foreign.json()).toMatchObject({
      error: { code: 'not_found', message: 'Organization not found.' },
    });
    await app.close();
  });

  it('rotates session and CSRF tokens on organization selection and requires Origin plus CSRF', async () => {
    const { app, harness } = await buildTestApi({ membershipCount: 2 });
    const loggedIn = await login(app, harness.user.email, VALID_PASSWORD);
    const cookieName = harness.config.auth.cookieName;
    const firstCookie = sessionCookieHeader(loggedIn, cookieName);
    const firstToken = cookieValue(firstSetCookie(loggedIn), cookieName);
    const firstCsrf = (loggedIn.json() as SessionResponse).csrfToken;
    expect((loggedIn.json() as SessionResponse).organization).toBeNull();

    const missingCsrf = await app.inject({
      method: 'POST',
      url: '/auth/select-organization',
      headers: {
        origin: TEST_ORIGIN,
        'content-type': 'application/json',
        cookie: firstCookie,
      },
      payload: { organizationId: harness.organizations[1]?.id },
    });
    expect(missingCsrf.statusCode).toBe(401);

    const selected = await app.inject({
      method: 'POST',
      url: '/auth/select-organization',
      headers: {
        origin: TEST_ORIGIN,
        'content-type': 'application/json',
        cookie: firstCookie,
        'x-csrf-token': firstCsrf,
      },
      payload: { organizationId: harness.organizations[1]?.id },
    });
    expect(selected.statusCode).toBe(200);
    const next = selected.json() as SessionResponse;
    expect(next.organization?.id).toBe(harness.organizations[1]?.id);
    expect(next.csrfToken).not.toBe(firstCsrf);
    const nextToken = cookieValue(firstSetCookie(selected), cookieName);
    expect(nextToken).not.toBe(firstToken);

    const stale = await app.inject({
      method: 'GET',
      url: '/auth/session',
      headers: { cookie: firstCookie },
    });
    expect(stale.statusCode).toBe(401);

    const fresh = await app.inject({
      method: 'GET',
      url: '/auth/session',
      headers: { cookie: `${cookieName}=${nextToken}` },
    });
    expect(fresh.statusCode).toBe(200);
    expect(
      harness.audit.events.some((event) => event.action === 'auth.organization_selected'),
    ).toBe(true);
    await app.close();
  });

  it('logs out idempotently and requires CSRF only when a live session cookie is present', async () => {
    const { app, harness } = await buildTestApi();
    const missing = await app.inject({
      method: 'POST',
      url: '/auth/logout',
      headers: {
        origin: TEST_ORIGIN,
        'content-type': 'application/json',
      },
      payload: {},
    });
    expect(missing.statusCode).toBe(204);
    expect(missing.headers['cache-control']).toBe('no-store');

    const loggedIn = await login(app, harness.user.email, VALID_PASSWORD);
    const cookieName = harness.config.auth.cookieName;
    const cookie = sessionCookieHeader(loggedIn, cookieName);
    const csrf = (loggedIn.json() as SessionResponse).csrfToken;

    const withoutCsrf = await app.inject({
      method: 'POST',
      url: '/auth/logout',
      headers: {
        origin: TEST_ORIGIN,
        'content-type': 'application/json',
        cookie,
      },
      payload: {},
    });
    expect(withoutCsrf.statusCode).toBe(401);

    const loggedOut = await app.inject({
      method: 'POST',
      url: '/auth/logout',
      headers: {
        origin: TEST_ORIGIN,
        'content-type': 'application/json',
        cookie,
        'x-csrf-token': csrf,
      },
      payload: {},
    });
    expect(loggedOut.statusCode).toBe(204);
    const cleared = firstSetCookie(loggedOut);
    expect(cleared).toMatch(/Max-Age=0/i);

    const again = await app.inject({
      method: 'POST',
      url: '/auth/logout',
      headers: {
        origin: TEST_ORIGIN,
        'content-type': 'application/json',
        cookie,
        'x-csrf-token': csrf,
      },
      payload: {},
    });
    expect(again.statusCode).toBe(204);
    expect(harness.audit.events.filter((event) => event.action === 'auth.logout')).toHaveLength(1);
    await app.close();
  });

  it('fails closed when the login limiter is unavailable', async () => {
    const { app, harness } = await buildTestApi({ limiterUnavailable: true });
    const known = await login(app, harness.user.email, VALID_PASSWORD);
    const unknown = await login(app, 'missing@synthetic.patchpilot.test', VALID_PASSWORD);
    expect(known.statusCode).toBe(503);
    expect(unknown.statusCode).toBe(503);
    expect(known.json()).toMatchObject({
      error: { code: 'internal', message: 'Login is temporarily unavailable.' },
    });
    expect(unknown.json().error.message).toBe(known.json().error.message);
    await app.close();
  });
});

async function login(
  app: Awaited<ReturnType<typeof buildTestApi>>['app'],
  email: string,
  password: string,
  extraBody: Record<string, unknown> = {},
) {
  return app.inject({
    method: 'POST',
    url: '/auth/login',
    remoteAddress: SOCKET_IP,
    headers: {
      origin: TEST_ORIGIN,
      'content-type': 'application/json',
      'x-forwarded-for': FORWARDED_IP,
    },
    payload: { email, password, ...extraBody },
  });
}

function firstSetCookie(response: { headers: { [key: string]: unknown } }): string {
  const header = response.headers['set-cookie'];
  if (typeof header === 'string') {
    return header;
  }
  if (Array.isArray(header) && typeof header[0] === 'string') {
    return header[0];
  }
  throw new Error('expected Set-Cookie');
}

function cookieValue(setCookie: string, name: string): string {
  const prefix = `${name}=`;
  const part = setCookie.split(';', 1)[0];
  if (part === undefined || !part.startsWith(prefix)) {
    throw new Error('cookie name mismatch');
  }
  return part.slice(prefix.length);
}

function sessionCookieHeader(
  response: { headers: { [key: string]: unknown } },
  name: string,
): string {
  return `${name}=${cookieValue(firstSetCookie(response), name)}`;
}

function assertNoSecrets(
  serialized: string,
  secrets: { password: string; email?: string; csrfToken: string; cookie: string },
): void {
  expect(serialized).not.toContain(secrets.password);
  expect(serialized).not.toContain(secrets.csrfToken);
  expect(serialized).not.toContain(secrets.cookie);
  if (secrets.email !== undefined) {
    expect(serialized.toLowerCase()).not.toContain(secrets.email.toLowerCase());
  }
}
