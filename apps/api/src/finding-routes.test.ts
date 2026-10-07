import { randomUUID } from 'node:crypto';

import { digestSessionToken } from '@patchpilot/auth';
import type { SessionResponse } from '@patchpilot/contracts';
import {
  FINDING_CREATION_POLICY_ID,
  FINDING_CREATION_POLICY_VERSION,
  FINDING_INSPECTION_PROJECTION_SCHEMA_VERSION,
  FINDING_INSPECTION_RESULT_SCHEMA_VERSION,
} from '@patchpilot/domain';
import type { FastifyInstance } from 'fastify';
import { describe, expect, it } from 'vitest';

import type { AuthTestHarness } from './auth-test-harness.js';
import {
  TEST_ORIGIN,
  VALID_PASSWORD,
  buildTestApi,
  createAuthTestHarness,
} from './auth-test-harness.js';
import type { FindingOperatorRuntime } from './finding-runtime.js';
import {
  FINDING_CREATION_ORGANIZATION_LIMIT,
  createFindingOrganizationRateLimiter,
  type FindingOrganizationRateLimiter,
} from './finding-rate-limit.js';

const ASSET = '44444444-4444-4444-8444-444444444444';
const COMPONENT = '55555555-5555-4555-8555-555555555555';
const VULNERABILITY = '66666666-6666-4666-8666-666666666666';
const INGESTION = '77777777-7777-4777-8777-777777777777';
const EVIDENCE_A = '88888888-8888-4888-8888-888888888888';
const EVIDENCE_B = '99999999-9999-4999-8999-999999999999';
const FINDING = 'abababab-abab-4bab-8bab-abababababab';
const ABSENT = 'cdcdcdcd-cdcd-4dcd-8dcd-cdcdcdcdcdcd';
const LOGIN_IP = '192.0.2.10';

type RoleName = 'owner' | 'admin' | 'member' | 'viewer';

type CreationCall = {
  organizationId: string | null;
  correlationId: string;
  request: unknown;
};

function creationBody(evidence: string[] = [EVIDENCE_A, EVIDENCE_B]): Record<string, unknown> {
  return {
    assetId: ASSET,
    componentId: COMPONENT,
    vulnerabilityId: VULNERABILITY,
    expectedSbomIngestionId: INGESTION,
    expectedProductMatchEvidenceIds: evidence,
  };
}

function projection() {
  return {
    schemaVersion: FINDING_INSPECTION_PROJECTION_SCHEMA_VERSION,
    findingId: FINDING,
    state: 'open' as const,
    asset: { id: ASSET, displayName: 'Tracked asset' },
    component: {
      id: COMPONENT,
      ecosystem: 'npm',
      namespace: null,
      name: 'reviewed-npm-widget',
    },
    vulnerability: { id: VULNERABILITY, publicId: 'REVIEWED-EXAMPLE' },
    affectedVersions: {
      values: ['1.1.0', '1.2.0'],
      truncated: false,
      omittedDistinctCount: 0,
      distinctCount: 2,
    },
    affectedOccurrenceCount: 2,
    otherOccurrenceCount: 0,
    otherOccurrenceClassification: 'no_other_occurrences_in_creation_ingestion' as const,
    createdAt: '2026-10-07T15:00:00.000Z',
    creationObservationPolicy: {
      policyId: FINDING_CREATION_POLICY_ID,
      policyVersion: FINDING_CREATION_POLICY_VERSION,
    },
    explanationCodes: ['finding_created_from_affected_product_match_evidence'] as const,
    creationEvidenceApplicability: 'current' as const,
  };
}

function scriptedFindings(status: string = 'created'): {
  runtime: FindingOperatorRuntime;
  creations: CreationCall[];
  inspections: string[];
} {
  const creations: CreationCall[] = [];
  const inspections: string[] = [];
  return {
    creations,
    inspections,
    runtime: {
      creation: {
        async execute(input) {
          creations.push({
            organizationId: input.actor.organizationId,
            correlationId: input.correlationId,
            request: input.request,
          });
          if (status === 'created' || status === 'already_applied') {
            return { status, findingId: FINDING };
          }
          if (status === 'throw') {
            throw new Error('SELECT * FROM finding WHERE prisma P2002 reviewer.two');
          }
          return { status: status as 'not_found' };
        },
      },
      inspection: {
        async execute(input) {
          inspections.push(String(input.findingId));
          if (input.findingId === FINDING) {
            return {
              schemaVersion: FINDING_INSPECTION_RESULT_SCHEMA_VERSION,
              status: 'found' as const,
              projection: projection(),
            };
          }
          if (input.findingId === 'unavailable') {
            return {
              schemaVersion: FINDING_INSPECTION_RESULT_SCHEMA_VERSION,
              status: 'database_unavailable' as const,
            };
          }
          return {
            schemaVersion: FINDING_INSPECTION_RESULT_SCHEMA_VERSION,
            status: 'not_found' as const,
          };
        },
      },
    },
  };
}

describe('controlled finding operator routes', () => {
  it('rejects unauthenticated creation and inspection', async () => {
    const { app } = await boot('owner');
    const created = await post(app, null, creationBody(), '198.51.100.1', {
      origin: TEST_ORIGIN,
      'content-type': 'application/json',
    });
    const inspected = await app.inject({
      method: 'GET',
      url: `/findings/${FINDING}`,
      remoteAddress: '198.51.100.2',
    });
    expect(created.statusCode).toBe(401);
    expect(inspected.statusCode).toBe(401);
    expect(created.headers['cache-control']).toBe('private, no-store');
    expect(inspected.headers['cache-control']).toBe('private, no-store');
    expectEnvelope(created, 'unauthorized', 'Authentication required.');
    expectEnvelope(inspected, 'unauthorized', 'Authentication required.');
    expect(confidential(created.json())).toBe(true);
    await app.close();
  });

  it('rejects a session without an active organization', async () => {
    const { app, session } = await boot('owner', { membershipCount: 2 });
    const created = await post(app, session, creationBody(), '198.51.100.3');
    const inspected = await get(app, session, FINDING, '198.51.100.4');
    expect(created.statusCode).toBe(403);
    expect(inspected.statusCode).toBe(403);
    expectEnvelope(created, 'forbidden', 'Organization context is required.');
    expectEnvelope(inspected, 'forbidden', 'Organization context is required.');
    await app.close();
  });

  it('requires JSON, an allowed origin, and CSRF only for creation', async () => {
    const script = scriptedFindings();
    const { app, session } = await boot('owner', { findings: script.runtime });
    const text = await post(app, session, creationBody(), '198.51.100.5', {
      'content-type': 'text/plain',
    });
    const charset = await post(app, session, creationBody(), '198.51.100.6', {
      'content-type': 'application/json; charset=utf-16',
    });
    const missingOrigin = await app.inject({
      method: 'POST',
      url: '/findings',
      remoteAddress: '198.51.100.7',
      headers: {
        'content-type': 'application/json',
        cookie: session.cookie,
        'x-csrf-token': session.csrf,
      },
      payload: creationBody(),
    });
    const badOrigin = await post(app, session, creationBody(), '198.51.100.8', {
      origin: 'https://evil.example',
    });
    const missingCsrf = await app.inject({
      method: 'POST',
      url: '/findings',
      remoteAddress: '198.51.100.9',
      headers: {
        origin: TEST_ORIGIN,
        'content-type': 'application/json',
        cookie: session.cookie,
      },
      payload: creationBody(),
    });
    const inspected = await app.inject({
      method: 'GET',
      url: `/findings/${FINDING}`,
      remoteAddress: '198.51.100.10',
      headers: { cookie: session.cookie },
    });
    expect(text.statusCode).toBe(400);
    expect(charset.statusCode).toBe(400);
    expect(missingOrigin.statusCode).toBe(403);
    expect(badOrigin.statusCode).toBe(403);
    expect(missingCsrf.statusCode).toBe(401);
    expectEnvelope(text, 'validation', 'Invalid request.');
    expectEnvelope(missingOrigin, 'forbidden', 'Origin is not allowed.');
    expectEnvelope(missingCsrf, 'unauthorized', 'Authentication required.');
    expect(inspected.statusCode).toBe(200);
    expect(script.creations).toHaveLength(0);
    await app.close();
  });

  it('rejects an oversized body and an evidence set above 16 before persistence', async () => {
    const script = scriptedFindings();
    const { app, session } = await boot('owner', { findings: script.runtime });
    const oversized = await app.inject({
      method: 'POST',
      url: '/findings',
      remoteAddress: '198.51.100.11',
      headers: {
        origin: TEST_ORIGIN,
        'content-type': 'application/json',
        'content-length': '4097',
      },
      payload: 'x'.repeat(4097),
    });
    const tooMany = Array.from({ length: 17 }, (_value, index) => {
      const suffix = index.toString(16).padStart(12, '0');
      return `aaaaaaaa-aaaa-4aaa-8aaa-${suffix}`;
    });
    const wide = await post(app, session, creationBody(tooMany), '198.51.100.12');
    expect(oversized.statusCode).toBe(400);
    expect(wide.statusCode).toBe(400);
    expectEnvelope(oversized, 'validation', 'Invalid request.');
    expectEnvelope(wide, 'validation', 'Invalid request.');
    expect(script.creations).toHaveLength(0);
    expect(confidential(oversized.json())).toBe(true);
    await app.close();
  });

  it('rate limits creation and inspection by the direct socket and ignores X-Forwarded-For', async () => {
    const { app } = await boot('owner');
    const peer = '198.51.100.20';
    const statuses: number[] = [];
    for (let index = 0; index < 6; index += 1) {
      const response = await app.inject({
        method: 'POST',
        url: '/findings',
        remoteAddress: peer,
        headers: {
          origin: TEST_ORIGIN,
          'content-type': 'application/json',
          'x-forwarded-for': `203.0.113.${index + 1}`,
        },
        payload: creationBody(),
      });
      statuses.push(response.statusCode);
    }
    expect(statuses.slice(0, 5)).toEqual([401, 401, 401, 401, 401]);
    expect(statuses[5]).toBe(429);
    const inspectionPeer = '198.51.100.21';
    let limited = 0;
    for (let index = 0; index < 61; index += 1) {
      const response = await app.inject({
        method: 'GET',
        url: `/findings/${FINDING}`,
        remoteAddress: inspectionPeer,
        headers: { 'x-forwarded-for': '203.0.113.50' },
      });
      if (response.statusCode === 429) {
        limited = index + 1;
        break;
      }
      expect(response.statusCode).toBe(401);
    }
    expect(limited).toBe(61);
    await app.close();
  });

  it('keeps creation owner-only, inspection owner-or-admin, and does not spend organization budget on denial', async () => {
    const script = scriptedFindings();
    let consumed = 0;
    const { app, session, harness } = await boot('owner', {
      findings: script.runtime,
      findingOrganizationLimiter: {
        consume() {
          consumed += 1;
          return consumed > 5 ? 'limited' : 'allowed';
        },
      },
    });
    const home = harness.organizations[0]?.id;
    if (home === undefined) {
      throw new Error('expected home organization');
    }
    for (const role of ['admin', 'member', 'viewer'] as const) {
      setRole(harness, role);
      for (let index = 0; index < 2; index += 1) {
        const denied = await post(app, session, creationBody(), `203.0.113.${index + 1}`);
        const hidden = await get(app, session, FINDING, `203.0.113.${index + 10}`);
        expect(denied.statusCode, role).toBe(403);
        expectEnvelope(denied, 'forbidden', 'Permission denied.');
        expect(hidden.statusCode, role).toBe(role === 'admin' ? 200 : 403);
      }
    }
    expect(consumed).toBe(0);
    expect(script.creations).toHaveLength(0);
    setRole(harness, 'owner');
    const injected = await post(
      app,
      session,
      { ...creationBody(), organizationId: randomUUID() },
      '203.0.113.30',
    );
    expect(injected.statusCode).toBe(400);
    expect(consumed).toBe(0);
    const created = await post(app, session, creationBody(), '203.0.113.31', {
      'x-correlation-id': 'cccccccc-cccc-4ccc-8ccc-cccccccccccc',
    });
    expect(created.statusCode).toBe(201);
    expect(created.json()).toEqual({ status: 'created', findingId: FINDING });
    expect(script.creations[0]?.organizationId).toBe(home);
    expect(script.creations[0]?.request).toEqual(creationBody());
    expect(consumed).toBe(1);
    const queried = await app.inject({
      method: 'POST',
      url: `/findings?organizationId=${randomUUID()}`,
      remoteAddress: '203.0.113.32',
      headers: mutationHeaders(session),
      payload: creationBody(),
    });
    expect(queried.statusCode).toBe(201);
    expect(script.creations[1]?.organizationId).toBe(home);
    const inspected = await get(app, session, FINDING, '203.0.113.33');
    expect(inspected.statusCode).toBe(200);
    expect(inspected.headers['cache-control']).toBe('private, no-store');
    expect(inspected.json()).toEqual(projection());
    expect(JSON.stringify(inspected.json())).not.toContain(EVIDENCE_A);
    expect(JSON.stringify(inspected.json())).not.toContain('reviewer');
    expect(inspected.json()).not.toHaveProperty('organizationId');
    const absent = await get(app, session, ABSENT, '203.0.113.34');
    const foreign = await get(app, session, FINDING, '203.0.113.35');
    script.inspections.length = 0;
    const missing = await get(app, session, ABSENT, '203.0.113.36');
    expect(absent.statusCode).toBe(404);
    expect(missing.json().error.code).toBe('not_found');
    expect(missing.json().error.message).toBe('Not found.');
    expect(JSON.stringify(missing.json())).not.toContain(ABSENT);
    expect(foreign.statusCode).toBe(200);
    expect(harness.logs()).not.toContain(session.csrf);
    expect(harness.logs()).not.toContain(EVIDENCE_A);
    expect(harness.logs()).not.toContain(FINDING);
    await app.close();
  });

  it('translates creation and inspection failures without disclosure', async () => {
    const cases: Array<{ status: string; http: number; code: string; message: string }> = [
      { status: 'invalid_command', http: 400, code: 'validation', message: 'Invalid request.' },
      { status: 'not_found', http: 404, code: 'not_found', message: 'Not found.' },
      { status: 'target_mismatch', http: 404, code: 'not_found', message: 'Not found.' },
      {
        status: 'evidence_set_mismatch',
        http: 409,
        code: 'conflict',
        message: 'The request conflicts with the current evidence.',
      },
      {
        status: 'evidence_not_current',
        http: 409,
        code: 'conflict',
        message: 'The request conflicts with the current evidence.',
      },
      {
        status: 'evidence_unavailable',
        http: 422,
        code: 'unprocessable_evidence',
        message: 'The evidence cannot be used for this request.',
      },
      {
        status: 'database_unavailable',
        http: 503,
        code: 'internal',
        message: 'Finding operator is temporarily unavailable.',
      },
      {
        status: 'malformed_persisted_state',
        http: 500,
        code: 'internal',
        message: 'An internal error occurred.',
      },
      { status: 'throw', http: 500, code: 'internal', message: 'An internal error occurred.' },
    ];
    for (const [index, entry] of cases.entries()) {
      const script = scriptedFindings(entry.status);
      const { app, session, harness } = await boot('owner', { findings: script.runtime });
      const response = await post(app, session, creationBody(), `203.0.113.${40 + index}`);
      expect(response.statusCode, entry.status).toBe(entry.http);
      expectEnvelope(response, entry.code, entry.message);
      expect(confidential(response.json())).toBe(true);
      expect(JSON.stringify(response.json())).not.toContain(EVIDENCE_A);
      expect(JSON.stringify(response.json())).not.toContain(FINDING);
      expect(harness.logs()).not.toContain('SELECT');
      expect(harness.logs()).not.toContain(EVIDENCE_A);
      await app.close();
    }
    const unavailable = scriptedFindings();
    const faulted = await boot('owner', {
      findings: unavailable.runtime,
      findingOrganizationLimiter: {
        consume() {
          throw new Error('prisma P2002 finding_pkey');
        },
      },
    });
    const limited = await post(faulted.app, faulted.session, creationBody(), '203.0.113.60');
    expect(limited.statusCode).toBe(503);
    expectEnvelope(limited, 'internal', 'Finding operator is temporarily unavailable.');
    expect(faulted.harness.logs()).not.toContain('P2002');
    expect(unavailable.creations).toHaveLength(0);
    await faulted.app.close();
  });

  it('does not register a list, preview, or lifecycle route', async () => {
    const { app } = await boot('owner');
    const printed = app.printRoutes();
    expect(printed).toContain('findings (POST)');
    expect(printed).toContain(':findingId (GET, HEAD)');
    expect(printed).not.toContain('findings (GET)');
    expect(printed).not.toMatch(/preview/i);
    for (const url of ['/findings', '/findings/preview', `/findings/${FINDING}/accept`]) {
      const response = await app.inject({ method: 'GET', url, remoteAddress: '198.51.100.70' });
      if (url === '/findings') {
        expect(response.statusCode).toBe(404);
      }
    }
    const transition = await app.inject({
      method: 'POST',
      url: `/findings/${FINDING}/accept`,
      remoteAddress: '198.51.100.71',
      headers: { 'content-type': 'application/json', origin: TEST_ORIGIN },
      payload: {},
    });
    expect(transition.statusCode).toBe(404);
    await app.close();
  });
});

describe('controlled finding operator adversarial review', () => {
  it('rejects invalid, revoked, and expired sessions before creation or inspection', async () => {
    const script = scriptedFindings();
    const { app, session, harness } = await boot('owner', { findings: script.runtime });
    const token = rawSessionToken(session.cookie, harness.config.auth.cookieName);
    const tokenHash = digestSessionToken(token);
    const invalidCookie = `${harness.config.auth.cookieName}=not-a-session`;
    const invalid = await post(
      app,
      { cookie: invalidCookie, csrf: session.csrf },
      creationBody(),
      '198.51.100.120',
    );
    const invalidGet = await get(
      app,
      { cookie: invalidCookie, csrf: session.csrf },
      FINDING,
      '198.51.100.121',
    );
    await harness.sessions.revokeCurrent({
      tokenHash,
      revokedAt: new Date(),
      revokeReason: 'logout',
    });
    const revoked = await post(app, session, creationBody(), '198.51.100.122');
    const {
      app: expiredApp,
      session: expiredSession,
      harness: expiredHarness,
    } = await boot('owner', {
      findings: script.runtime,
    });
    const expiredToken = rawSessionToken(
      expiredSession.cookie,
      expiredHarness.config.auth.cookieName,
    );
    await expiredHarness.sessions.updateThrottledLastSeen({
      tokenHash: digestSessionToken(expiredToken),
      lastSeenAt: new Date(),
      idleExpiresAt: new Date(Date.now() - 60_000),
      minLastSeenAt: new Date(Date.now() + 60_000),
    });
    const expired = await post(expiredApp, expiredSession, creationBody(), '198.51.100.123');
    const expiredGet = await get(expiredApp, expiredSession, FINDING, '198.51.100.124');
    expect(invalid.statusCode).toBe(401);
    expect(invalidGet.statusCode).toBe(401);
    expect(revoked.statusCode).toBe(401);
    expect(expired.statusCode).toBe(401);
    expect(expiredGet.statusCode).toBe(401);
    expectEnvelope(expired, 'unauthorized', 'Authentication required.');
    expect(script.creations).toHaveLength(0);
    expect(script.inspections).toHaveLength(0);
    await app.close();
    await expiredApp.close();
  });

  it('drops inactive organizations and memberships before the application services', async () => {
    const script = scriptedFindings();
    const archived = await boot('owner', { findings: script.runtime });
    const home = archived.harness.organizations[0];
    if (home === undefined) {
      throw new Error('expected home organization');
    }
    home.status = 'archived';
    const archivedCreate = await post(
      archived.app,
      archived.session,
      creationBody(),
      '198.51.100.130',
    );
    const archivedRead = await get(archived.app, archived.session, FINDING, '198.51.100.131');
    const revoked = await boot('owner', { findings: script.runtime });
    const membership = revoked.harness.memberships.rows[0]?.membership;
    if (membership === undefined) {
      throw new Error('expected membership');
    }
    membership.status = 'revoked';
    const revokedCreate = await post(
      revoked.app,
      revoked.session,
      creationBody(),
      '198.51.100.132',
    );
    const otherUser = await boot('owner', { findings: script.runtime });
    const bound = otherUser.harness.memberships.rows[0]?.membership;
    if (bound === undefined) {
      throw new Error('expected membership');
    }
    bound.userId = '12121212-1212-4121-8121-121212121212';
    const disagreed = await post(
      otherUser.app,
      otherUser.session,
      creationBody(),
      '198.51.100.133',
    );
    expect(archivedCreate.statusCode).toBe(403);
    expect(archivedRead.statusCode).toBe(403);
    expect(revokedCreate.statusCode).toBe(403);
    expect(disagreed.statusCode).toBe(403);
    expectEnvelope(disagreed, 'forbidden', 'Organization context is required.');
    expect(script.creations).toHaveLength(0);
    expect(script.inspections).toHaveLength(0);
    await archived.app.close();
    await revoked.app.close();
    await otherUser.app.close();
  });

  it('rejects ambient authority, malformed acknowledgements, and non-JSON bodies before issuance', async () => {
    const script = scriptedFindings();
    let consumed = 0;
    const { app, session } = await boot('owner', {
      findings: script.runtime,
      findingOrganizationLimiter: {
        consume() {
          consumed += 1;
          return 'allowed';
        },
      },
    });
    const member = await boot('member', { findings: script.runtime });
    const bodies: Record<string, unknown>[] = [
      { ...creationBody(), organizationId: randomUUID() },
      { ...creationBody(), membershipId: randomUUID() },
      { ...creationBody(), findingId: FINDING },
      { ...creationBody(), role: 'owner' },
      { ...creationBody(), permissions: ['finding:create_controlled'] },
      { ...creationBody(), state: 'closed' },
      { ...creationBody(), explanation: 'trusted text' },
      { ...creationBody(), createdAt: '2026-10-07T15:00:00.000Z' },
      { ...creationBody(), idempotencyKey: 'replay-me' },
      { ...creationBody(), assetId: 'abababab-abab-4bab-8bab-abababababab'.toUpperCase() },
      {
        ...creationBody(),
        expectedProductMatchEvidenceIds: ['abababab-abab-4bab-8bab-abababababab'.toUpperCase()],
      },
      { ...creationBody(), expectedProductMatchEvidenceIds: [] },
      { ...creationBody(), expectedProductMatchEvidenceIds: [EVIDENCE_B, EVIDENCE_A] },
      { ...creationBody(), expectedProductMatchEvidenceIds: [EVIDENCE_A, EVIDENCE_A] },
    ];
    for (const [index, body] of bodies.entries()) {
      const response = await post(app, session, body, `198.51.100.${140 + index}`);
      expect(response.statusCode, JSON.stringify(Object.keys(body))).toBe(400);
      expectEnvelope(response, 'validation', 'Invalid request.');
      expect(JSON.stringify(response.json())).not.toContain(EVIDENCE_A);
    }
    const triage = await post(
      member.app,
      member.session,
      { ...creationBody(), permissions: ['finding:triage'] },
      '198.51.100.160',
    );
    const readOnly = await get(member.app, member.session, FINDING, '198.51.100.161');
    expect(triage.statusCode).toBe(403);
    expect(readOnly.statusCode).toBe(403);
    const malformed = await app.inject({
      method: 'POST',
      url: '/findings',
      remoteAddress: '198.51.100.162',
      headers: {
        origin: TEST_ORIGIN,
        'content-type': 'application/json',
        cookie: session.cookie,
        'x-csrf-token': session.csrf,
      },
      payload: `{"assetId":"${ASSET}","marker":"evidence-secret-marker"`,
    });
    expect(malformed.statusCode).toBe(400);
    expectEnvelope(malformed, 'validation', 'Invalid request.');
    expect(JSON.stringify(malformed.json())).not.toContain('evidence-secret-marker');
    expect(JSON.stringify(malformed.json())).not.toContain('Unexpected');
    const textJson = await post(app, session, creationBody(), '198.51.100.163', {
      'content-type': 'text/json',
    });
    const badParameter = await post(app, session, creationBody(), '198.51.100.164', {
      'content-type': 'application/json; charset=utf-8; boundary=nope',
    });
    const nullOrigin = await post(app, session, creationBody(), '198.51.100.165', {
      origin: 'null',
    });
    const stale = await boot('owner', { findings: script.runtime });
    await stale.harness.sessions.replaceCsrfToken({
      tokenHash: digestSessionToken(
        rawSessionToken(stale.session.cookie, stale.harness.config.auth.cookieName),
      ),
      nextCsrfTokenHash: 'ab'.repeat(32),
    });
    const staleCsrf = await post(stale.app, stale.session, creationBody(), '198.51.100.166');
    const badCsrf = await post(
      app,
      { cookie: session.cookie, csrf: 'not-the-token' },
      creationBody(),
      '198.51.100.167',
    );
    expect(textJson.statusCode).toBe(400);
    expect(badParameter.statusCode).toBe(400);
    expect(nullOrigin.statusCode).toBe(403);
    expect(staleCsrf.statusCode).toBe(401);
    expect(badCsrf.statusCode).toBe(401);
    expect(consumed).toBe(0);
    expect(script.creations).toHaveLength(0);
    expect(script.inspections).toHaveLength(0);
    await app.close();
    await member.app.close();
    await stale.app.close();
  });

  it('keeps peer buckets independent of forwarding headers, inspection, and other organizations', async () => {
    const script = scriptedFindings();
    const limiter = createFindingOrganizationRateLimiter(FINDING_CREATION_ORGANIZATION_LIMIT);
    const { app, session } = await boot('owner', {
      findings: script.runtime,
      findingOrganizationLimiter: limiter,
    });
    for (let index = 0; index < 10; index += 1) {
      const denied = await post(app, null, creationBody(), `203.0.113.${index + 1}`, {
        origin: TEST_ORIGIN,
        'content-type': 'application/json',
        'x-forwarded-for': '198.51.100.200',
      });
      expect(denied.statusCode).toBe(401);
    }
    const mappedPeer = '198.51.100.210';
    for (let index = 0; index < 5; index += 1) {
      const response = await app.inject({
        method: 'POST',
        url: '/findings',
        remoteAddress: index === 4 ? `::ffff:${mappedPeer}` : mappedPeer,
        headers: {
          origin: TEST_ORIGIN,
          'content-type': 'application/json',
          'x-forwarded-for': `2001:db8::${index + 1}`,
        },
        payload: creationBody(),
      });
      expect(response.statusCode).toBe(401);
    }
    const mappedLimited = await app.inject({
      method: 'POST',
      url: '/findings',
      remoteAddress: mappedPeer,
      headers: { origin: TEST_ORIGIN, 'content-type': 'application/json' },
      payload: creationBody(),
    });
    expect(mappedLimited.statusCode).toBe(429);
    expect(mappedLimited.headers['cache-control']).toBe('private, no-store');
    expectEnvelope(mappedLimited, 'rate_limited', 'Too many requests. Try again later.');
    expect(JSON.stringify(mappedLimited.json())).not.toContain(EVIDENCE_A);
    const samePeerInspection = await app.inject({
      method: 'GET',
      url: `/findings/${FINDING}`,
      remoteAddress: mappedPeer,
    });
    expect(samePeerInspection.statusCode).toBe(401);
    const health = await app.inject({
      method: 'GET',
      url: '/health/live',
      remoteAddress: mappedPeer,
    });
    expect(health.statusCode).toBe(200);
    const ipv6 = await app.inject({
      method: 'POST',
      url: '/findings',
      remoteAddress: '2001:db8::10',
      headers: { origin: TEST_ORIGIN, 'content-type': 'application/json' },
      payload: creationBody(),
    });
    expect(ipv6.statusCode).toBe(401);
    for (let index = 0; index < 5; index += 1) {
      const created = await post(app, session, creationBody(), `198.51.100.${220 + index}`);
      expect(created.statusCode).toBe(201);
    }
    const organizationLimited = await post(app, session, creationBody(), '198.51.100.230');
    expect(organizationLimited.statusCode).toBe(429);
    expectEnvelope(organizationLimited, 'rate_limited', 'Too many requests. Try again later.');
    expect(script.creations).toHaveLength(5);
    const uppercase = await get(app, session, FINDING.toUpperCase(), '198.51.100.231');
    expect(uppercase.statusCode).toBe(400);
    expect(script.inspections).toHaveLength(0);
    const headed = await app.inject({
      method: 'HEAD',
      url: `/findings/${FINDING}`,
      remoteAddress: '198.51.100.232',
      headers: { cookie: session.cookie },
    });
    expect(headed.statusCode).toBe(200);
    expect(headed.body).toBe('');
    expect(headed.headers['cache-control']).toBe('private, no-store');
    const withBody = await app.inject({
      method: 'GET',
      url: `/findings/${FINDING}`,
      remoteAddress: '198.51.100.233',
      headers: {
        cookie: session.cookie,
        'content-type': 'application/json',
        'content-length': '2',
      },
      payload: '{}',
    });
    expect(withBody.statusCode).toBe(400);
    expect(script.inspections).toHaveLength(1);
    await app.close();
  });

  it('translates inspection failures without exposing persistence internals', async () => {
    const findingId = FINDING;
    const runtime: FindingOperatorRuntime = {
      creation: {
        async execute() {
          return { status: 'authority_required' };
        },
      },
      inspection: {
        async execute() {
          return {
            schemaVersion: FINDING_INSPECTION_RESULT_SCHEMA_VERSION,
            status: 'database_unavailable' as const,
          };
        },
      },
    };
    const unavailable = await boot('admin', { findings: runtime });
    const down = await get(unavailable.app, unavailable.session, findingId, '198.51.100.240');
    expect(down.statusCode).toBe(503);
    expectEnvelope(down, 'internal', 'Finding operator is temporarily unavailable.');
    expect(JSON.stringify(down.json())).not.toContain(findingId);
    await unavailable.app.close();
    const malformedRuntime: FindingOperatorRuntime = {
      creation: {
        async execute() {
          return { status: 'authority_required' };
        },
      },
      inspection: {
        async execute() {
          return {
            schemaVersion: FINDING_INSPECTION_RESULT_SCHEMA_VERSION,
            status: 'malformed_persisted_state' as const,
          };
        },
      },
    };
    const malformed = await boot('owner', { findings: malformedRuntime });
    const broken = await get(malformed.app, malformed.session, findingId, '198.51.100.241');
    expect(broken.statusCode).toBe(500);
    expectEnvelope(broken, 'internal', 'An internal error occurred.');
    expect(JSON.stringify(broken.json())).not.toContain('malformed_persisted_state');
    await malformed.app.close();
  });
});

async function boot(
  role: RoleName,
  options?: {
    membershipCount?: 1 | 2;
    findings?: FindingOperatorRuntime;
    findingOrganizationLimiter?: FindingOrganizationRateLimiter;
  },
) {
  const harness = createAuthTestHarness({
    membershipCount: options?.membershipCount ?? 1,
    primaryRole: role,
  });
  const built = await buildTestApi({
    harness,
    ...(options?.findings === undefined ? {} : { findings: options.findings }),
    ...(options?.findingOrganizationLimiter === undefined
      ? {}
      : { findingOrganizationLimiter: options.findingOrganizationLimiter }),
  });
  const loggedIn = await built.app.inject({
    method: 'POST',
    url: '/auth/login',
    remoteAddress: LOGIN_IP,
    headers: { origin: TEST_ORIGIN, 'content-type': 'application/json' },
    payload: { email: harness.user.email, password: VALID_PASSWORD },
  });
  expect(loggedIn.statusCode).toBe(200);
  return {
    app: built.app,
    harness,
    session: sessionFrom(loggedIn, harness.config.auth.cookieName),
  };
}

function setRole(harness: AuthTestHarness, role: RoleName): void {
  const row = harness.memberships.rows[0];
  if (row === undefined) {
    throw new Error('expected a membership');
  }
  row.membership.role = role;
}

async function post(
  app: FastifyInstance,
  session: { cookie: string; csrf: string } | null,
  payload: Record<string, unknown>,
  remoteAddress: string,
  headers?: Record<string, string>,
) {
  return app.inject({
    method: 'POST',
    url: '/findings',
    remoteAddress,
    headers: {
      ...(session === null ? {} : mutationHeaders(session)),
      ...headers,
    },
    payload,
  });
}

async function get(
  app: FastifyInstance,
  session: { cookie: string; csrf: string },
  findingId: string,
  remoteAddress: string,
) {
  return app.inject({
    method: 'GET',
    url: `/findings/${findingId}`,
    remoteAddress,
    headers: { cookie: session.cookie },
  });
}

function mutationHeaders(session: { cookie: string; csrf: string }): Record<string, string> {
  return {
    origin: TEST_ORIGIN,
    'content-type': 'application/json',
    cookie: session.cookie,
    'x-csrf-token': session.csrf,
  };
}

function rawSessionToken(cookie: string, cookieName: string): string {
  const prefix = `${cookieName}=`;
  if (!cookie.startsWith(prefix) || cookie.slice(prefix.length).length === 0) {
    throw new Error('cookie name mismatch');
  }
  return cookie.slice(prefix.length);
}

function sessionFrom(
  response: { headers: { [key: string]: unknown }; json: () => unknown },
  cookieName: string,
): { cookie: string; csrf: string } {
  const header = response.headers['set-cookie'];
  const setCookie =
    typeof header === 'string' ? header : Array.isArray(header) ? header[0] : undefined;
  if (typeof setCookie !== 'string') {
    throw new Error('expected Set-Cookie');
  }
  const part = setCookie.split(';', 1)[0];
  const prefix = `${cookieName}=`;
  if (part === undefined || !part.startsWith(prefix)) {
    throw new Error('cookie name mismatch');
  }
  return {
    cookie: `${cookieName}=${part.slice(prefix.length)}`,
    csrf: (response.json() as SessionResponse).csrfToken,
  };
}

function expectEnvelope(
  response: { json: () => { error?: { code?: string; message?: string; requestId?: string } } },
  code: string,
  message: string,
): void {
  const body = response.json();
  expect(body.error?.code).toBe(code);
  expect(body.error?.message).toBe(message);
  expect(typeof body.error?.requestId).toBe('string');
}

function confidential(body: unknown): boolean {
  const serialized = JSON.stringify(body);
  return (
    !serialized.includes('SELECT') &&
    !serialized.includes('prisma') &&
    !serialized.includes('P2002') &&
    !serialized.includes('reviewer') &&
    !serialized.toLowerCase().includes('stack')
  );
}
