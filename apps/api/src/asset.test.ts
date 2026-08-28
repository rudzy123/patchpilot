import { randomUUID } from 'node:crypto';

import type { AssetDetail, AssetListResponse, SessionResponse } from '@patchpilot/contracts';
import { encodeAssetListCursor } from '@patchpilot/contracts';
import { describe, expect, it } from 'vitest';

import { createMemoryAssetInventory } from './asset-test-harness.js';
import {
  TEST_ORIGIN,
  VALID_PASSWORD,
  buildTestApi,
  createAuthTestHarness,
} from './auth-test-harness.js';

const SOCKET_IP = '192.0.2.10';
const FOREIGN_ASSET_ID = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';

describe('asset inventory routes', () => {
  it('rejects unauthenticated access with a stable unauthorized envelope', async () => {
    const { app } = await boot({ role: 'admin' });
    const response = await app.inject({ method: 'GET', url: '/assets' });
    expect(response.statusCode).toBe(401);
    expect(response.headers['cache-control']).toBe('private, no-store');
    expectEnvelope(response, 'unauthorized', 'Authentication required.');
    await app.close();
  });

  it('requires active Organization context before reads and mutations', async () => {
    const { app, session } = await boot({ role: 'admin', membershipCount: 2 });
    const listed = await app.inject({
      method: 'GET',
      url: '/assets',
      headers: { cookie: session.cookie },
    });
    const created = await mutate(app, session, 'POST', '/assets', {
      name: 'Payments',
      assetType: 'application',
    });
    expect(listed.statusCode).toBe(403);
    expect(created.statusCode).toBe(403);
    expectEnvelope(listed, 'forbidden', 'Organization context is required.');
    expectEnvelope(created, 'forbidden', 'Organization context is required.');
    await app.close();
  });

  it('allows viewer reads and denies viewer mutations', async () => {
    const { app, session, inventory, organizationId } = await boot({ role: 'viewer' });
    const seeded = await inventory.seedAsset(organizationId, baseCommand('Readable'));

    const listed = await app.inject({
      method: 'GET',
      url: '/assets',
      headers: { cookie: session.cookie },
    });
    const detail = await app.inject({
      method: 'GET',
      url: `/assets/${seeded.id}`,
      headers: { cookie: session.cookie },
    });
    const created = await mutate(app, session, 'POST', '/assets', {
      name: 'Denied',
      assetType: 'service',
    });

    expect(listed.statusCode).toBe(200);
    expect(detail.statusCode).toBe(200);
    expect((listed.json() as AssetListResponse).items.map((item) => item.id)).toEqual([seeded.id]);
    expect((detail.json() as AssetDetail).name).toBe('Readable');
    expect(created.statusCode).toBe(403);
    expectEnvelope(created, 'forbidden', 'Permission denied.');
    await app.close();
  });

  it('allows admin mutations and returns private no-store asset bodies', async () => {
    const { app, session, harness } = await boot({ role: 'admin' });
    const created = await mutate(app, session, 'POST', '/assets', {
      name: 'Admin App',
      assetType: 'application',
      description: 'Tracked service',
    });
    expect(created.statusCode).toBe(201);
    expect(created.headers['cache-control']).toBe('private, no-store');
    const body = created.json() as AssetDetail;
    expect(body.name).toBe('Admin App');
    expect(body.lifecycleStatus).toBe('active');
    expect(body).not.toHaveProperty('organizationId');
    expect(body).not.toHaveProperty('audit');
    expect(JSON.stringify(body)).not.toContain(VALID_PASSWORD);
    expect(JSON.stringify(body)).not.toContain(session.csrf);
    expect(harness.logs()).not.toContain(VALID_PASSWORD);
    expect(harness.logs()).not.toContain(session.csrf);
    await app.close();
  });

  it('hides cross-tenant reads, updates, and archives behind not-found', async () => {
    const { app, session, inventory, harness } = await boot({ role: 'admin' });
    const foreignOrgId = harness.organizations[1]?.id;
    if (foreignOrgId === undefined) {
      throw new Error('expected a second organization');
    }
    const foreign = await inventory.seedAsset(foreignOrgId, baseCommand('Foreign'));

    const listed = await app.inject({
      method: 'GET',
      url: '/assets',
      headers: { cookie: session.cookie },
    });
    const read = await app.inject({
      method: 'GET',
      url: `/assets/${foreign.id}`,
      headers: { cookie: session.cookie },
    });
    const updated = await mutate(app, session, 'PATCH', `/assets/${foreign.id}`, {
      expectedVersion: 1,
      name: 'Stolen',
    });
    const archived = await mutate(app, session, 'POST', `/assets/${foreign.id}/archive`, {
      expectedVersion: 1,
    });
    const missing = await app.inject({
      method: 'GET',
      url: `/assets/${FOREIGN_ASSET_ID}`,
      headers: { cookie: session.cookie },
    });

    expect((listed.json() as AssetListResponse).items.map((item) => item.id)).not.toContain(
      foreign.id,
    );
    expect(read.statusCode).toBe(404);
    expect(updated.statusCode).toBe(404);
    expect(archived.statusCode).toBe(404);
    expect(missing.statusCode).toBe(404);
    expectEnvelope(read, 'not_found', 'Asset not found.');
    expectEnvelope(updated, 'not_found', 'Asset not found.');
    expectEnvelope(archived, 'not_found', 'Asset not found.');
    expect(read.json().error.message).toBe(missing.json().error.message);
    await app.close();
  });

  it('rejects invalid UUID path params', async () => {
    const { app, session } = await boot({ role: 'admin' });
    const response = await app.inject({
      method: 'GET',
      url: '/assets/not-a-uuid',
      headers: { cookie: session.cookie },
    });
    expect(response.statusCode).toBe(400);
    expectEnvelope(response, 'validation', 'Invalid request.');
    await app.close();
  });

  it('rejects unknown fields on create and update', async () => {
    const { app, session } = await boot({ role: 'admin' });
    const created = await mutate(app, session, 'POST', '/assets', {
      name: 'Payments',
      assetType: 'application',
      organizationId: randomUUID(),
    });
    expect(created.statusCode).toBe(400);
    expectEnvelope(created, 'validation', 'Invalid request.');
    await app.close();
  });

  it('rejects a PATCH without expectedVersion', async () => {
    const { app, session, inventory, organizationId } = await boot({ role: 'admin' });
    const asset = await inventory.seedAsset(organizationId, baseCommand('Versioned'));
    const response = await mutate(app, session, 'PATCH', `/assets/${asset.id}`, {
      name: 'Renamed',
    });
    expect(response.statusCode).toBe(400);
    expectEnvelope(response, 'validation', 'Invalid request.');
    await app.close();
  });

  it('rejects invalid CSRF on mutations', async () => {
    const { app, session } = await boot({ role: 'admin' });
    const response = await app.inject({
      method: 'POST',
      url: '/assets',
      remoteAddress: SOCKET_IP,
      headers: {
        origin: TEST_ORIGIN,
        'content-type': 'application/json',
        cookie: session.cookie,
        'x-csrf-token': 'wrong-token',
      },
      payload: { name: 'Payments', assetType: 'application' },
    });
    expect(response.statusCode).toBe(401);
    expectEnvelope(response, 'unauthorized', 'Authentication required.');
    await app.close();
  });

  it('rejects missing Origin on mutations', async () => {
    const { app, session } = await boot({ role: 'admin' });
    const response = await app.inject({
      method: 'POST',
      url: '/assets',
      remoteAddress: SOCKET_IP,
      headers: {
        'content-type': 'application/json',
        cookie: session.cookie,
        'x-csrf-token': session.csrf,
      },
      payload: { name: 'Payments', assetType: 'application' },
    });
    expect(response.statusCode).toBe(403);
    expectEnvelope(response, 'forbidden', 'Origin is not allowed.');
    await app.close();
  });

  it('rejects the wrong content type on mutations', async () => {
    const { app, session } = await boot({ role: 'admin' });
    const response = await app.inject({
      method: 'POST',
      url: '/assets',
      remoteAddress: SOCKET_IP,
      headers: {
        origin: TEST_ORIGIN,
        'content-type': 'application/x-www-form-urlencoded',
        cookie: session.cookie,
        'x-csrf-token': session.csrf,
      },
      payload: 'name=Payments&assetType=application',
    });
    expect(response.statusCode).toBe(415);
    expect(response.json()).toMatchObject({ error: { code: 'validation' } });
    await app.close();
  });

  it('returns a stable name-conflict envelope for an active duplicate', async () => {
    const { app, session, inventory, organizationId } = await boot({ role: 'admin' });
    await inventory.seedAsset(organizationId, baseCommand('Payments'));
    const conflict = await mutate(app, session, 'POST', '/assets', {
      name: 'payments',
      assetType: 'application',
    });
    expect(conflict.statusCode).toBe(409);
    expectEnvelope(conflict, 'conflict', 'Asset name already exists.');
    await app.close();
  });

  it('returns a stable version-conflict envelope', async () => {
    const { app, session, inventory, organizationId } = await boot({ role: 'admin' });
    const asset = await inventory.seedAsset(organizationId, baseCommand('Versioned'));
    const conflict = await mutate(app, session, 'PATCH', `/assets/${asset.id}`, {
      expectedVersion: 99,
      name: 'Renamed',
    });
    expect(conflict.statusCode).toBe(409);
    expectEnvelope(conflict, 'conflict', 'Asset version conflict.');
    await app.close();
  });

  it('returns a stable archived-asset envelope', async () => {
    const { app, session, inventory, organizationId } = await boot({ role: 'admin' });
    const asset = await inventory.seedAsset(organizationId, baseCommand('Legacy'));
    const archived = await mutate(app, session, 'POST', `/assets/${asset.id}/archive`, {
      expectedVersion: 1,
    });
    expect(archived.statusCode).toBe(200);
    expect((archived.json() as AssetDetail).lifecycleStatus).toBe('archived');

    const update = await mutate(app, session, 'PATCH', `/assets/${asset.id}`, {
      expectedVersion: 2,
      name: 'Still legacy',
    });
    const again = await mutate(app, session, 'POST', `/assets/${asset.id}/archive`, {
      expectedVersion: 2,
    });
    expect(update.statusCode).toBe(409);
    expect(again.statusCode).toBe(409);
    expectEnvelope(update, 'conflict', 'Asset is archived.');
    expectEnvelope(again, 'conflict', 'Asset is archived.');
    await app.close();
  });

  it('paginates the asset list with an opaque cursor', async () => {
    const { app, session, inventory, organizationId } = await boot({ role: 'admin' });
    await inventory.seedAsset(organizationId, baseCommand('Zebra'));
    const bravo = await inventory.seedAsset(organizationId, baseCommand('Bravo'));
    await inventory.seedAsset(organizationId, baseCommand('alpha'));

    const first = await app.inject({
      method: 'GET',
      url: '/assets?limit=2',
      headers: { cookie: session.cookie },
    });
    expect(first.statusCode).toBe(200);
    const firstBody = first.json() as AssetListResponse;
    expect(firstBody.items.map((item) => item.name)).toEqual(['alpha', 'Bravo']);
    expect(firstBody.nextCursor).toBe(encodeAssetListCursor({ v: 1, n: 'Bravo', i: bravo.id }));

    const second = await app.inject({
      method: 'GET',
      url: `/assets?limit=2&cursor=${encodeURIComponent(firstBody.nextCursor ?? '')}`,
      headers: { cookie: session.cookie },
    });
    const secondBody = second.json() as AssetListResponse;
    expect(secondBody.items.map((item) => item.name)).toEqual(['Zebra']);
    expect(secondBody.nextCursor).toBeNull();
    await app.close();
  });

  it('applies approved list filters', async () => {
    const { app, session, inventory, organizationId } = await boot({ role: 'admin' });
    const environment = inventory.seedEnvironment({
      organizationId,
      name: 'production',
      slug: 'production',
    });
    const team = inventory.seedTeam({
      organizationId,
      name: 'Platform',
      slug: 'platform',
    });
    await inventory.seedAsset(organizationId, {
      ...baseCommand('Filter Target'),
      assetType: 'service',
      businessCriticality: 'high',
      internetExposure: 'internet_facing',
      environmentId: environment.id,
      owningTeamId: team.id,
      tags: ['payments'],
    });
    await inventory.seedAsset(organizationId, baseCommand('Filter Other'));

    const byType = await app.inject({
      method: 'GET',
      url: '/assets?assetType=service&tag=payments&namePrefix=Filter%20T',
      headers: { cookie: session.cookie },
    });
    expect(byType.statusCode).toBe(200);
    expect((byType.json() as AssetListResponse).items.map((item) => item.name)).toEqual([
      'Filter Target',
    ]);
    await app.close();
  });

  it('excludes archived environments, archived teams, and revoked memberships from options', async () => {
    const { app, session, inventory, organizationId, harness } = await boot({ role: 'admin' });
    const activeEnv = inventory.seedEnvironment({
      organizationId,
      name: 'production',
      slug: 'production',
    });
    inventory.seedEnvironment({
      organizationId,
      name: 'legacy',
      slug: 'legacy',
      status: 'archived',
    });
    const activeTeam = inventory.seedTeam({
      organizationId,
      name: 'Platform',
      slug: 'platform',
    });
    inventory.seedTeam({
      organizationId,
      name: 'Old',
      slug: 'old',
      status: 'archived',
    });
    const activeMembership = inventory.seedMembership({
      organizationId,
      userId: harness.user.id,
      displayName: 'Active Member',
      role: 'admin',
    });
    inventory.seedMembership({
      organizationId,
      userId: randomUUID(),
      displayName: 'Revoked Member',
      status: 'revoked',
    });

    const environments = await app.inject({
      method: 'GET',
      url: '/asset-options/environments',
      headers: { cookie: session.cookie },
    });
    const teams = await app.inject({
      method: 'GET',
      url: '/asset-options/teams',
      headers: { cookie: session.cookie },
    });
    const memberships = await app.inject({
      method: 'GET',
      url: '/asset-options/memberships',
      headers: { cookie: session.cookie },
    });

    expect(environments.statusCode).toBe(200);
    expect(environments.headers['cache-control']).toBe('private, no-store');
    expect(environments.json()).toEqual({
      items: [
        {
          id: activeEnv.id,
          name: 'production',
          slug: 'production',
          sensitivityClass: 'production',
        },
      ],
      nextCursor: null,
    });
    expect(teams.json()).toEqual({
      items: [{ id: activeTeam.id, name: 'Platform', slug: 'platform' }],
      nextCursor: null,
    });
    expect(memberships.json()).toEqual({
      items: [
        {
          membershipId: activeMembership.id,
          displayName: 'Active Member',
          role: 'admin',
        },
      ],
      nextCursor: null,
    });
    await app.close();
  });

  it('preserves request and correlation ids on the error envelope', async () => {
    const { app } = await boot({ role: 'admin' });
    const response = await app.inject({
      method: 'GET',
      url: '/assets',
      headers: {
        'x-request-id': 'req-asset-1',
        'x-correlation-id': 'corr-asset-1',
      },
    });
    expect(response.statusCode).toBe(401);
    expect(response.headers['x-request-id']).toBe('req-asset-1');
    expect(response.headers['x-correlation-id']).toBe('corr-asset-1');
    expect(response.json()).toEqual({
      error: {
        code: 'unauthorized',
        message: 'Authentication required.',
        requestId: 'req-asset-1',
        correlationId: 'corr-asset-1',
      },
    });
    expect(JSON.stringify(response.json())).not.toContain('stack');
    await app.close();
  });
});

async function boot(options: { role: 'viewer' | 'admin'; membershipCount?: 1 | 2 }) {
  const inventory = createMemoryAssetInventory();
  const harness = createAuthTestHarness({
    membershipCount: options.membershipCount ?? 1,
    primaryRole: options.role,
  });
  const { app } = await buildTestApi({ harness, assets: inventory.runtime });
  const organizationId = harness.organizations[0]?.id;
  if (organizationId === undefined) {
    throw new Error('expected home organization');
  }

  if (options.membershipCount === 2) {
    const loggedIn = await login(app, harness.user.email);
    return {
      app,
      harness,
      inventory,
      organizationId,
      session: sessionFrom(loggedIn, harness.config.auth.cookieName),
    };
  }

  const loggedIn = await login(app, harness.user.email);
  return {
    app,
    harness,
    inventory,
    organizationId,
    session: sessionFrom(loggedIn, harness.config.auth.cookieName),
  };
}

async function login(app: Awaited<ReturnType<typeof buildTestApi>>['app'], email: string) {
  return app.inject({
    method: 'POST',
    url: '/auth/login',
    remoteAddress: SOCKET_IP,
    headers: {
      origin: TEST_ORIGIN,
      'content-type': 'application/json',
    },
    payload: { email, password: VALID_PASSWORD },
  });
}

function sessionFrom(
  response: Awaited<ReturnType<typeof login>>,
  cookieName: string,
): { cookie: string; csrf: string } {
  const setCookie = firstSetCookie(response);
  const prefix = `${cookieName}=`;
  const part = setCookie.split(';', 1)[0];
  if (part === undefined || !part.startsWith(prefix)) {
    throw new Error('cookie name mismatch');
  }
  return {
    cookie: `${cookieName}=${part.slice(prefix.length)}`,
    csrf: (response.json() as SessionResponse).csrfToken,
  };
}

async function mutate(
  app: Awaited<ReturnType<typeof buildTestApi>>['app'],
  session: { cookie: string; csrf: string },
  method: 'POST' | 'PATCH',
  url: string,
  payload: Record<string, unknown>,
) {
  return app.inject({
    method,
    url,
    remoteAddress: SOCKET_IP,
    headers: {
      origin: TEST_ORIGIN,
      'content-type': 'application/json',
      cookie: session.cookie,
      'x-csrf-token': session.csrf,
    },
    payload,
  });
}

function baseCommand(name: string) {
  return {
    name,
    assetType: 'application' as const,
    businessCriticality: 'unspecified' as const,
    internetExposure: 'unknown' as const,
    dataClassification: 'unspecified' as const,
    owners: [],
    tags: [],
    externalIdentifiers: [],
  };
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

function expectEnvelope(response: { json: () => unknown }, code: string, message: string): void {
  expect(response.json()).toMatchObject({
    error: { code, message },
  });
  const body = response.json() as { error?: { requestId?: string; correlationId?: string } };
  expect(typeof body.error?.requestId).toBe('string');
  expect(typeof body.error?.correlationId).toBe('string');
}
