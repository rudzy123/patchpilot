import { loadServerConfigFrom } from '@patchpilot/config';
import type {
  SbomDetail,
  SbomIngestionStatus,
  SbomListResponse,
  SbomUploadAcceptedResponse,
  SessionResponse,
} from '@patchpilot/contracts';
import { createFoundationTestEnv } from '@patchpilot/test-utils';
import { describe, expect, it } from 'vitest';

import {
  TEST_ORIGIN,
  VALID_PASSWORD,
  buildTestApi,
  createAuthTestHarness,
} from './auth-test-harness.js';
import { createMemorySbomInventory } from './sbom-test-harness.js';

const SOCKET_IP = '192.0.2.10';
const FOREIGN_SBOM_ID = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const SAMPLE_BODY = '{"bomFormat":"CycloneDX","specVersion":"1.6","version":1}';

describe('SBOM routes', () => {
  it('rejects unauthenticated access with a stable unauthorized envelope', async () => {
    const { app } = await boot({ role: 'admin' });
    const response = await app.inject({ method: 'GET', url: `/assets/${assetIdPlaceholder}/sboms` });
    expect(response.statusCode).toBe(401);
    expect(response.headers['cache-control']).toBe('private, no-store');
    expectEnvelope(response, 'unauthorized', 'Authentication required.');
    await app.close();
  });

  it('requires active Organization context before reads and uploads', async () => {
    const { app, session, assetId } = await boot({ role: 'admin', membershipCount: 2 });
    const listed = await app.inject({
      method: 'GET',
      url: `/assets/${assetId}/sboms`,
      headers: { cookie: session.cookie },
    });
    const uploaded = await upload(app, session, assetId, SAMPLE_BODY);
    expect(listed.statusCode).toBe(403);
    expect(uploaded.statusCode).toBe(403);
    expectEnvelope(listed, 'forbidden', 'Organization context is required.');
    expectEnvelope(uploaded, 'forbidden', 'Organization context is required.');
    await app.close();
  });

  it('allows viewer reads and denies viewer uploads', async () => {
    const { app, session, assetId } = await boot({ role: 'viewer' });

    const listed = await app.inject({
      method: 'GET',
      url: `/assets/${assetId}/sboms`,
      headers: { cookie: session.cookie },
    });
    const uploaded = await upload(app, session, assetId, SAMPLE_BODY);
    expect(listed.statusCode).toBe(200);
    expect(listed.headers['cache-control']).toBe('private, no-store');
    expect(uploaded.statusCode).toBe(403);
    expectEnvelope(uploaded, 'forbidden', 'Permission denied.');
    await app.close();
  });

  it('accepts an authorized CycloneDX JSON upload without leaking storage internals', async () => {
    const { app, session, assetId, inventory, harness } = await boot({ role: 'member' });
    const response = await upload(app, session, assetId, SAMPLE_BODY, {
      contentType: 'application/vnd.cyclonedx+json; charset=utf-8',
      idempotencyKey: 'upload-1',
    });
    expect(response.statusCode).toBe(202);
    expect(response.headers['cache-control']).toBe('private, no-store');
    const body = response.json() as SbomUploadAcceptedResponse;
    expect(body.state).toBe('accepted');
    expect(body.assetId).toBe(assetId);
    expect(body.specificationType).toBe('cyclonedx');
    expect(body.source).toBe('upload');
    expectForbiddenFields(body);
    expect(inventory.outbox).toHaveLength(1);
    expect(inventory.outbox[0]?.eventType).toBe('sbom.ingestion.requested.v1');
    expect(harness.logs()).not.toContain('upload-1');
    expect(harness.logs()).not.toContain(VALID_PASSWORD);
    expect(JSON.stringify(inventory.outbox[0]?.payload)).not.toContain(SAMPLE_BODY);
    await app.close();
  });

  it('replays the same Idempotency-Key without a second outbox event', async () => {
    const { app, session, assetId, inventory } = await boot({ role: 'admin' });
    const first = await upload(app, session, assetId, SAMPLE_BODY, { idempotencyKey: 'same-key' });
    const second = await upload(app, session, assetId, SAMPLE_BODY, { idempotencyKey: 'same-key' });
    expect(first.statusCode).toBe(202);
    expect(second.statusCode).toBe(202);
    expect(second.json()).toEqual(first.json());
    expect(inventory.outbox).toHaveLength(1);
    await app.close();
  });

  it('hides cross-tenant SBOM reads and uploads behind tenant-safe not-found', async () => {
    const { app, session, assetId, inventory, harness } = await boot({ role: 'admin' });
    const foreignOrgId = harness.organizations[1]?.id;
    if (foreignOrgId === undefined) {
      throw new Error('expected a second organization');
    }
    const foreignAsset = await inventory.assets.seedAsset(foreignOrgId, baseAsset('Foreign'));
    const missingAsset = await app.inject({
      method: 'GET',
      url: `/assets/${foreignAsset.id}/sboms`,
      headers: { cookie: session.cookie },
    });
    const uploaded = await upload(app, session, foreignAsset.id, SAMPLE_BODY);
    const missingSbom = await app.inject({
      method: 'GET',
      url: `/assets/${assetId}/sboms/${FOREIGN_SBOM_ID}`,
      headers: { cookie: session.cookie },
    });
    const unknownAsset = await app.inject({
      method: 'GET',
      url: `/assets/${FOREIGN_SBOM_ID}/sboms`,
      headers: { cookie: session.cookie },
    });
    expect(missingAsset.statusCode).toBe(404);
    expect(uploaded.statusCode).toBe(404);
    expect(unknownAsset.statusCode).toBe(404);
    expectEnvelope(missingAsset, 'not_found', 'Asset not found.');
    expectEnvelope(uploaded, 'not_found', 'Asset not found.');
    expectEnvelope(unknownAsset, 'not_found', 'Asset not found.');
    expect(missingSbom.statusCode).toBe(404);
    expectEnvelope(missingSbom, 'not_found', 'SBOM not found.');
    await app.close();
  });

  it('rejects uploads to an archived Asset', async () => {
    const { app, session, assetId, inventory, organizationId } = await boot({ role: 'admin' });
    const asset = inventory.assets.assets.get(assetId);
    if (asset === undefined) {
      throw new Error('expected seeded asset');
    }
    const archived = await inventory.assets.runtime.archive.execute({
      actor: {
        userId: '00000000-0000-4000-8000-000000000001',
        sessionId: '00000000-0000-4000-8000-000000000002',
        organizationId,
        membershipId: '00000000-0000-4000-8000-000000000003',
        permissions: ['asset:manage'],
      },
      assetId,
      expectedVersion: asset.version,
      correlationId: 'corr-archive',
    });
    expect(archived.ok).toBe(true);
    const uploaded = await upload(app, session, assetId, SAMPLE_BODY);
    expect(uploaded.statusCode).toBe(409);
    expectEnvelope(uploaded, 'conflict', 'Asset is archived.');
    await app.close();
  });

  it('rejects invalid CSRF, missing Origin, and missing Idempotency-Key', async () => {
    const { app, session, assetId } = await boot({ role: 'admin' });
    const csrf = await app.inject({
      method: 'POST',
      url: `/assets/${assetId}/sboms`,
      remoteAddress: SOCKET_IP,
      headers: {
        origin: TEST_ORIGIN,
        'content-type': 'application/json',
        cookie: session.cookie,
        'x-csrf-token': 'wrong-token',
        'idempotency-key': 'k1',
      },
      payload: SAMPLE_BODY,
    });
    const origin = await app.inject({
      method: 'POST',
      url: `/assets/${assetId}/sboms`,
      remoteAddress: SOCKET_IP,
      headers: {
        'content-type': 'application/json',
        cookie: session.cookie,
        'x-csrf-token': session.csrf,
        'idempotency-key': 'k2',
      },
      payload: SAMPLE_BODY,
    });
    const idempotency = await app.inject({
      method: 'POST',
      url: `/assets/${assetId}/sboms`,
      remoteAddress: SOCKET_IP,
      headers: {
        origin: TEST_ORIGIN,
        'content-type': 'application/json',
        cookie: session.cookie,
        'x-csrf-token': session.csrf,
      },
      payload: SAMPLE_BODY,
    });
    expect(csrf.statusCode).toBe(401);
    expectEnvelope(csrf, 'unauthorized', 'Authentication required.');
    expect(origin.statusCode).toBe(403);
    expectEnvelope(origin, 'forbidden', 'Origin is not allowed.');
    expect(idempotency.statusCode).toBe(400);
    expectEnvelope(idempotency, 'validation', 'Idempotency-Key is required.');
    await app.close();
  });

  it('rejects unapproved media types, non-UTF-8 charset, and extra parameters', async () => {
    const { app, session, assetId } = await boot({ role: 'admin' });
    const zip = await upload(app, session, assetId, SAMPLE_BODY, {
      contentType: 'application/zip',
    });
    const charset = await upload(app, session, assetId, SAMPLE_BODY, {
      contentType: 'application/json; charset=utf-16',
    });
    const extra = await upload(app, session, assetId, SAMPLE_BODY, {
      contentType: 'application/json; boundary=abc',
    });
    expect(zip.statusCode).toBe(415);
    expect(charset.statusCode).toBe(400);
    expectEnvelope(charset, 'validation', 'UTF-8 charset is required.');
    expect(extra.statusCode).toBe(400);
    expectEnvelope(extra, 'validation', 'Unsupported Content-Type parameter.');
    await app.close();
  });

  it('rejects an oversize upload against the per-route body limit', async () => {
    const { app, session, assetId, config } = await boot({ role: 'admin', uploadMaxBytes: 65_536 });
    const response = await upload(
      app,
      session,
      assetId,
      'x'.repeat(config.sbom.uploadMaxBytes + 1),
    );
    expect(response.statusCode).toBe(413);
    expect(response.json()).toMatchObject({ error: { code: 'validation' } });
    await app.close();
  });

  it('returns public list, detail, and ingestion status without lease or parser internals', async () => {
    const { app, session, assetId } = await boot({ role: 'admin' });
    const uploaded = await upload(app, session, assetId, SAMPLE_BODY);
    const accepted = uploaded.json() as SbomUploadAcceptedResponse;

    const listed = await app.inject({
      method: 'GET',
      url: `/assets/${assetId}/sboms`,
      headers: { cookie: session.cookie },
    });
    const detail = await app.inject({
      method: 'GET',
      url: `/assets/${assetId}/sboms/${accepted.sbomId}`,
      headers: { cookie: session.cookie },
    });
    const ingestion = await app.inject({
      method: 'GET',
      url: `/assets/${assetId}/sbom-ingestions/${accepted.ingestionId}`,
      headers: { cookie: session.cookie },
    });

    expect(listed.statusCode).toBe(200);
    expect(detail.statusCode).toBe(200);
    expect(ingestion.statusCode).toBe(200);
    expect(listed.headers['cache-control']).toBe('private, no-store');
    const listBody = listed.json() as SbomListResponse;
    expect(listBody.items.map((item) => item.id)).toEqual([accepted.sbomId]);
    expectForbiddenFields(listBody);
    expectForbiddenFields(detail.json() as SbomDetail);
    expectForbiddenFields(ingestion.json() as SbomIngestionStatus);
    expect((detail.json() as SbomDetail).currentIngestion.id).toBe(accepted.ingestionId);
    await app.close();
  });

  it('rate-limits by direct peer IP and ignores X-Forwarded-For', async () => {
    const { app, session, assetId } = await boot({ role: 'admin', rateLimitMax: 1 });
    const first = await upload(app, session, assetId, SAMPLE_BODY, { idempotencyKey: 'one' });
    const second = await app.inject({
      method: 'POST',
      url: `/assets/${assetId}/sboms`,
      remoteAddress: SOCKET_IP,
      headers: {
        origin: TEST_ORIGIN,
        'content-type': 'application/json',
        cookie: session.cookie,
        'x-csrf-token': session.csrf,
        'idempotency-key': 'two',
        'x-forwarded-for': '203.0.113.9',
      },
      payload: SAMPLE_BODY,
    });
    const listed = await app.inject({
      method: 'GET',
      url: `/assets/${assetId}/sboms`,
      remoteAddress: SOCKET_IP,
      headers: { cookie: session.cookie },
    });
    expect(first.statusCode).toBe(202);
    expect(second.statusCode).toBe(429);
    expectEnvelope(second, 'rate_limited', 'Too many requests. Try again later.');
    expect(listed.statusCode).toBe(200);
    await app.close();
  });

  it('rate-limits uploads by Organization across distinct peer IPs', async () => {
    const { app, session, assetId } = await boot({ role: 'admin', rateLimitMax: 1 });
    const first = await upload(app, session, assetId, SAMPLE_BODY, { idempotencyKey: 'org-one' });
    const second = await app.inject({
      method: 'POST',
      url: `/assets/${assetId}/sboms`,
      remoteAddress: '192.0.2.20',
      headers: {
        origin: TEST_ORIGIN,
        'content-type': 'application/json',
        cookie: session.cookie,
        'x-csrf-token': session.csrf,
        'idempotency-key': 'org-two',
      },
      payload: SAMPLE_BODY,
    });
    expect(first.statusCode).toBe(202);
    expect(second.statusCode).toBe(429);
    expectEnvelope(second, 'rate_limited', 'Too many requests. Try again later.');
    await app.close();
  });
});

const assetIdPlaceholder = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';

async function boot(options: {
  role: 'viewer' | 'member' | 'admin';
  membershipCount?: 1 | 2;
  uploadMaxBytes?: number;
  rateLimitMax?: number;
}) {
  const env = {
    ...createFoundationTestEnv(),
    ...(options.uploadMaxBytes === undefined
      ? {}
      : { SBOM_UPLOAD_MAX_BYTES: String(options.uploadMaxBytes) }),
    ...(options.rateLimitMax === undefined
      ? {}
      : { SBOM_UPLOAD_RATE_LIMIT_MAX: String(options.rateLimitMax) }),
  };
  const config = loadServerConfigFrom(env);
  const inventory = createMemorySbomInventory();
  const harness = createAuthTestHarness({
    membershipCount: options.membershipCount ?? 1,
    primaryRole: options.role,
    config,
  });
  const { app } = await buildTestApi({
    harness,
    config,
    assets: inventory.assets.runtime,
    sboms: inventory.runtime,
  });
  const organizationId = harness.organizations[0]?.id;
  if (organizationId === undefined) {
    throw new Error('expected home organization');
  }
  const seeded = await inventory.assets.seedAsset(organizationId, baseAsset('Tracked'));
  const loggedIn = await login(app, harness.user.email);
  return {
    app,
    harness,
    inventory,
    organizationId,
    assetId: seeded.id,
    config,
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

async function upload(
  app: Awaited<ReturnType<typeof buildTestApi>>['app'],
  session: { cookie: string; csrf: string },
  assetId: string,
  payload: string,
  options?: { contentType?: string; idempotencyKey?: string },
) {
  return app.inject({
    method: 'POST',
    url: `/assets/${assetId}/sboms`,
    remoteAddress: SOCKET_IP,
    headers: {
      origin: TEST_ORIGIN,
      'content-type': options?.contentType ?? 'application/json',
      cookie: session.cookie,
      'x-csrf-token': session.csrf,
      'idempotency-key': options?.idempotencyKey ?? 'default-key',
    },
    payload,
  });
}

function baseAsset(name: string) {
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
}

function expectForbiddenFields(body: unknown): void {
  const serialized = JSON.stringify(body);
  expect(serialized).not.toContain('objectKey');
  expect(serialized).not.toContain('originalFilename');
  expect(serialized).not.toContain('filename');
  expect(serialized).not.toContain('workerIdentifier');
  expect(serialized).not.toContain('leaseExpiresAt');
  expect(serialized).not.toContain('auditPayload');
  expect(serialized).not.toContain('ajvErrors');
  expect(serialized).not.toContain('parserException');
}
