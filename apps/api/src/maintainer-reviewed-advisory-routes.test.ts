import type { SessionResponse } from '@patchpilot/contracts';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { describe, expect, it } from 'vitest';

import {
  TEST_ORIGIN,
  VALID_PASSWORD,
  buildTestApi,
  createAuthTestHarness,
} from './auth-test-harness.js';
import type { MaintainerReviewedAdvisoryRuntime } from './maintainer-reviewed-advisory-runtime.js';

const REVISION = '33333333-3333-4333-8333-33333333333a';
const OTHER_REVISION = '44444444-4444-4444-8444-444444444444';
const FINGERPRINT = 'a'.repeat(64);

type Script = {
  runtime: MaintainerReviewedAdvisoryRuntime;
  submissions: Array<{ userId: string; document: unknown }>;
  approvals: Array<{ userId: string; revisionId: string; correlationId: string }>;
};

function scripted(submissionOutcome = 'submitted', approvalOutcome = 'approved'): Script {
  const submissions: Script['submissions'] = [];
  const approvals: Script['approvals'] = [];
  return {
    submissions,
    approvals,
    runtime: {
      submission: {
        async execute(input) {
          submissions.push({ userId: input.trustedSubmitterUserId, document: input.document });
          if (submissionOutcome === 'throw') {
            throw new Error('SELECT seal prisma P2002 capability_required');
          }
          if (submissionOutcome === 'submitted' || submissionOutcome === 'already_applied') {
            return { outcome: submissionOutcome, revisionId: REVISION };
          }
          return { outcome: submissionOutcome };
        },
      },
      approval: {
        async execute(input) {
          approvals.push({
            userId: input.trustedReviewerUserId,
            revisionId: input.advisoryRevisionId,
            correlationId: input.correlationId,
          });
          if (approvalOutcome === 'throw') {
            throw new Error('UPDATE reviewer_capability_issuance SET seal');
          }
          if (approvalOutcome === 'approved' || approvalOutcome === 'already_applied') {
            return { outcome: approvalOutcome, revisionId: input.advisoryRevisionId };
          }
          return { outcome: approvalOutcome };
        },
      },
    },
  };
}

function document(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schemaVersion: 'maintainer_reviewed_advisory_document_v1',
    advisoryFamilyId: 'FAMILYROUTE0001',
    revisionNumber: 1,
    vulnerabilityId: '55555555-5555-4555-8555-555555555555',
    aliases: ['CVE-2026-10001'],
    packageEcosystem: 'npm',
    packageName: 'left-pad',
    packageUrl: null,
    affectedRanges: [{ type: 'SEMVER', events: [{ introduced: '1.0.0' }, { fixed: '1.2.0' }] }],
    withdrawal: 'not_withdrawn',
    supersedesRevisionId: null,
    sourceLicenseDecision: { spdxLicenseId: 'CC-BY-4.0' },
    authorIdentity: 'not-used-by-the-route',
    submissionCorrelationId: '66666666-6666-4666-8666-666666666666',
    ...extra,
  };
}

describe('maintainer-reviewed advisory routes', () => {
  it('rejects missing and invalid sessions before the service', async () => {
    const script = scripted();
    const { app, session } = await boot(script.runtime);
    const missing = await post(app, null, document(), '198.51.100.1');
    const invalid = await post(
      app,
      { cookie: 'patchpilot.sid=not-a-session', csrf: session.csrf },
      document(),
      '198.51.100.2',
    );
    expect(missing.statusCode).toBe(401);
    expect(invalid.statusCode).toBe(401);
    expectEnvelope(missing, 'unauthorized', 'Authentication required.');
    expect(missing.headers['cache-control']).toBe('private, no-store');
    expect(invalid.headers['cache-control']).toBe('private, no-store');
    expect(script.submissions).toHaveLength(0);
    await app.close();
  });

  it('rejects a disabled user at session authentication and does not call the service', async () => {
    const script = scripted();
    const { app, session, harness } = await boot(script.runtime);
    const user = harness.users.users.get(harness.user.id);
    if (user === undefined) {
      throw new Error('expected user');
    }
    user.status = 'disabled';
    const response = await post(app, session, document(), '198.51.100.3');
    expect(response.statusCode).toBe(401);
    expectEnvelope(response, 'unauthorized', 'Authentication required.');
    expect(script.submissions).toHaveLength(0);
    await app.close();
  });

  it('does not require an organization and does not treat owner as advisory authority', async () => {
    const unscoped = scripted();
    const unscopedBoot = await boot(unscoped.runtime, { membershipCount: 0 });
    const submitted = await post(
      unscopedBoot.app,
      unscopedBoot.session,
      document(),
      '198.51.100.4',
    );
    expect(submitted.statusCode).toBe(201);
    expect(submitted.json()).toEqual({
      schemaVersion: 'maintainer_reviewed_advisory_submission_transport_v1',
      result: 'submitted',
      advisoryRevisionId: REVISION,
    });
    expect(unscoped.submissions[0]?.userId).toBe(unscopedBoot.harness.user.id);
    expect(submitted.json()).not.toHaveProperty('organizationId');
    await unscopedBoot.app.close();

    const owner = scripted('authority_rejected', 'authority_rejected');
    const ownerBoot = await boot(owner.runtime, { role: 'owner' });
    const denied = await post(ownerBoot.app, ownerBoot.session, document(), '198.51.100.5');
    const approval = await approve(ownerBoot.app, ownerBoot.session, REVISION, '198.51.100.6');
    expect(denied.statusCode).toBe(403);
    expect(approval.statusCode).toBe(403);
    expectEnvelope(denied, 'forbidden', 'Advisory authority was not granted.');
    expectEnvelope(approval, 'forbidden', 'Advisory authority was not granted.');
    await ownerBoot.app.close();
  });

  it('enforces JSON, body size, origin, CSRF, and an empty query before the service', async () => {
    const script = scripted();
    const { app, session } = await boot(script.runtime);
    const text = await post(app, session, document(), '198.51.100.10', {
      'content-type': 'text/plain',
    });
    const form = await post(app, session, document(), '198.51.100.11', {
      'content-type': 'application/x-www-form-urlencoded',
    });
    const encoded = await post(app, session, document(), '198.51.100.12', {
      'content-encoding': 'gzip',
    });
    const missingOrigin = await app.inject({
      method: 'POST',
      url: '/intelligence/maintainer-reviewed-advisories',
      remoteAddress: '198.51.100.13',
      headers: {
        'content-type': 'application/json',
        cookie: session.cookie,
        'x-csrf-token': session.csrf,
      },
      payload: document(),
    });
    const forwarded = await app.inject({
      method: 'POST',
      url: '/intelligence/maintainer-reviewed-advisories',
      remoteAddress: '198.51.100.14',
      headers: {
        'content-type': 'application/json',
        cookie: session.cookie,
        'x-csrf-token': session.csrf,
        'x-forwarded-host': '127.0.0.1:3000',
      },
      payload: document(),
    });
    const badOrigin = await post(app, session, document(), '198.51.100.15', {
      origin: 'https://evil.example',
      'x-forwarded-host': '127.0.0.1:3000',
    });
    const missingCsrf = await post(
      app,
      { cookie: session.cookie, csrf: '' },
      document(),
      '198.51.100.16',
    );
    const badCsrf = await post(
      app,
      { cookie: session.cookie, csrf: 'not-the-token' },
      document(),
      '198.51.100.17',
    );
    const queried = await app.inject({
      method: 'POST',
      url: '/intelligence/maintainer-reviewed-advisories?organizationId=11111111-1111-4111-8111-111111111111&provider=osv',
      remoteAddress: '198.51.100.18',
      headers: mutationHeaders(session),
      payload: document(),
    });
    const oversized = await app.inject({
      method: 'POST',
      url: '/intelligence/maintainer-reviewed-advisories',
      remoteAddress: '198.51.100.19',
      headers: { ...mutationHeaders(session), 'content-length': '65537' },
      payload: document(),
    });
    expect(text.statusCode).toBe(415);
    expect(form.statusCode).toBe(415);
    expect(encoded.statusCode).toBe(415);
    expect(missingOrigin.statusCode).toBe(403);
    expect(forwarded.statusCode).toBe(403);
    expect(badOrigin.statusCode).toBe(403);
    expect(missingCsrf.statusCode).toBe(401);
    expect(badCsrf.statusCode).toBe(401);
    expect(queried.statusCode).toBe(400);
    expect(oversized.statusCode).toBe(413);
    expectEnvelope(text, 'validation', 'Unsupported media type.');
    expectEnvelope(oversized, 'validation', 'Request body is too large.');
    expect(text.headers['cache-control']).toBe('private, no-store');
    expect(oversized.headers['cache-control']).toBe('private, no-store');
    expect(queried.headers['cache-control']).toBe('private, no-store');
    expect(script.submissions).toHaveLength(0);
    await app.close();
  });

  it('limits each route by the direct socket and ignores X-Forwarded-For', async () => {
    const script = scripted();
    const { app } = await boot(script.runtime);
    const peer = '198.51.100.30';
    const statuses: number[] = [];
    for (let index = 0; index < 6; index += 1) {
      const response = await app.inject({
        method: 'POST',
        url: '/intelligence/maintainer-reviewed-advisories',
        remoteAddress: peer,
        headers: {
          origin: TEST_ORIGIN,
          'content-type': 'application/json',
          'x-forwarded-for': `203.0.113.${index + 1}`,
        },
        payload: document(),
      });
      statuses.push(response.statusCode);
    }
    expect(statuses.slice(0, 5)).toEqual([401, 401, 401, 401, 401]);
    expect(statuses[5]).toBe(429);
    expect(script.submissions).toHaveLength(0);
    const mapped = '198.51.100.31';
    for (let index = 0; index < 5; index += 1) {
      const response = await app.inject({
        method: 'POST',
        url: '/intelligence/maintainer-reviewed-advisories',
        remoteAddress: `::ffff:${mapped}`,
        headers: { origin: TEST_ORIGIN, 'content-type': 'application/json' },
        payload: document(),
      });
      expect(response.statusCode).toBe(401);
    }
    const shared = await app.inject({
      method: 'POST',
      url: '/intelligence/maintainer-reviewed-advisories',
      remoteAddress: mapped,
      headers: { origin: TEST_ORIGIN, 'content-type': 'application/json' },
      payload: document(),
    });
    expect(shared.statusCode).toBe(429);
    expect(shared.headers['cache-control']).toBe('private, no-store');
    expectEnvelope(shared, 'rate_limited', 'Too many requests. Try again later.');
    const approvalPeer = '198.51.100.32';
    let approvalLimited = 0;
    for (let index = 0; index < 6; index += 1) {
      const response = await app.inject({
        method: 'POST',
        url: `/intelligence/maintainer-reviewed-advisories/${REVISION}/approval`,
        remoteAddress: approvalPeer,
        headers: {
          origin: TEST_ORIGIN,
          'content-type': 'application/json',
          'x-forwarded-for': '203.0.113.99',
        },
        payload: {},
      });
      if (response.statusCode === 429) {
        approvalLimited = index + 1;
      }
    }
    expect(approvalLimited).toBe(6);
    expect(script.approvals).toHaveLength(0);
    await app.close();
  });

  it('fails closed when the limiter cannot select a peer', async () => {
    const script = scripted();
    const { app, session } = await boot(script.runtime, {
      submissionPeerKey: () => {
        throw new Error('limiter store down');
      },
    });
    const response = await post(app, session, document(), '198.51.100.40');
    expect(response.statusCode).toBe(429);
    expectEnvelope(response, 'rate_limited', 'Too many requests. Try again later.');
    expect(response.headers['cache-control']).toBe('private, no-store');
    expect(script.submissions).toHaveLength(0);
    await app.close();
  });

  it('submits once, replays, and translates closed failures without disclosure', async () => {
    const created = scripted('submitted');
    const createdBoot = await boot(created.runtime);
    const first = await post(createdBoot.app, createdBoot.session, document(), '198.51.100.50');
    expect(first.statusCode).toBe(201);
    expect(first.headers['cache-control']).toBe('private, no-store');
    expect(created.submissions).toHaveLength(1);
    expect(created.submissions[0]?.document).toEqual(document());
    expect(createdBoot.harness.logs()).not.toContain(REVISION);
    expect(createdBoot.harness.logs()).not.toContain('left-pad');
    expect(createdBoot.harness.logs()).not.toContain(FINGERPRINT);
    expect(createdBoot.harness.logs()).not.toContain(createdBoot.session.csrf);
    const metrics = metricRecords(createdBoot.harness.logs());
    expect(metrics.length).toBeGreaterThan(0);
    expect(Object.keys(metrics[0] ?? {}).sort()).toEqual([
      'method',
      'outcome',
      'route',
      'statusClass',
    ]);
    expect(metrics[0]).toMatchObject({
      route: '/intelligence/maintainer-reviewed-advisories',
      method: 'POST',
      outcome: 'submitted',
      statusClass: '2xx',
    });
    await createdBoot.app.close();

    const replay = scripted('already_applied');
    const replayBoot = await boot(replay.runtime);
    const again = await post(replayBoot.app, replayBoot.session, document(), '198.51.100.51');
    expect(again.statusCode).toBe(200);
    expect(again.json()).toMatchObject({ result: 'already_applied', advisoryRevisionId: REVISION });
    await replayBoot.app.close();

    const cases: Array<{ outcome: string; status: number; code: string; message: string }> = [
      { outcome: 'invalid_command', status: 400, code: 'validation', message: 'Invalid request.' },
      {
        outcome: 'malformed_document',
        status: 400,
        code: 'validation',
        message: 'Invalid request.',
      },
      {
        outcome: 'unsupported_origin',
        status: 400,
        code: 'validation',
        message: 'Invalid request.',
      },
      {
        outcome: 'authority_rejected',
        status: 403,
        code: 'forbidden',
        message: 'Advisory authority was not granted.',
      },
      {
        outcome: 'immutable_conflict',
        status: 409,
        code: 'conflict',
        message: 'The request conflicts with the stored advisory.',
      },
      {
        outcome: 'malformed_persisted_state',
        status: 503,
        code: 'internal',
        message: 'Maintainer-reviewed advisory storage is temporarily unavailable.',
      },
      {
        outcome: 'database_unavailable',
        status: 503,
        code: 'internal',
        message: 'Maintainer-reviewed advisory storage is temporarily unavailable.',
      },
    ];
    for (const [index, item] of cases.entries()) {
      const script = scripted(item.outcome);
      const booted = await boot(script.runtime);
      const response = await post(
        booted.app,
        booted.session,
        document({ origin: 'provider_derived', contentFingerprint: FINGERPRINT }),
        `198.51.100.${60 + index}`,
      );
      expect(response.statusCode, item.outcome).toBe(item.status);
      expectEnvelope(response, item.code, item.message);
      expect(response.headers['cache-control']).toBe('private, no-store');
      expect(JSON.stringify(response.json())).not.toContain(FINGERPRINT);
      expect(JSON.stringify(response.json())).not.toContain('left-pad');
      expect(JSON.stringify(response.json())).not.toContain('prisma');
      expect(script.submissions).toHaveLength(1);
      await booted.app.close();
    }
  });

  it('approves once, replays, and hides capability and self-approval detail', async () => {
    const approved = scripted('submitted', 'approved');
    const approvedBoot = await boot(approved.runtime);
    const first = await approve(approvedBoot.app, approvedBoot.session, REVISION, '198.51.100.80');
    expect(first.statusCode).toBe(201);
    expect(first.json()).toEqual({
      schemaVersion: 'maintainer_reviewed_advisory_approval_transport_v1',
      result: 'approved',
      advisoryRevisionId: REVISION,
    });
    expect(approved.approvals).toEqual([
      {
        userId: approvedBoot.harness.user.id,
        revisionId: REVISION,
        correlationId: expect.any(String),
      },
    ]);
    expect(JSON.stringify(first.json())).not.toMatch(/capability|seal|issuer|fingerprint/i);
    expect(approvedBoot.harness.logs()).not.toContain(REVISION);
    await approvedBoot.app.close();

    const replay = scripted('submitted', 'already_applied');
    const replayBoot = await boot(replay.runtime);
    const again = await approve(replayBoot.app, replayBoot.session, REVISION, '198.51.100.81');
    expect(again.statusCode).toBe(200);
    expect(again.json()).toMatchObject({ result: 'already_applied' });
    await replayBoot.app.close();

    const pathCases = [
      `/intelligence/maintainer-reviewed-advisories/${REVISION.toUpperCase()}/approval`,
      `/intelligence/maintainer-reviewed-advisories/${encodeURIComponent(` ${REVISION}`)}/approval`,
      '/intelligence/maintainer-reviewed-advisories/not-a-uuid/approval',
    ];
    const pathScript = scripted();
    const pathBoot = await boot(pathScript.runtime);
    for (const [index, url] of pathCases.entries()) {
      const response = await pathBoot.app.inject({
        method: 'POST',
        url,
        remoteAddress: `198.51.100.${82 + index}`,
        headers: mutationHeaders(pathBoot.session),
        payload: {},
      });
      expect(response.statusCode, url).toBe(400);
      expect(response.headers['cache-control']).toBe('private, no-store');
    }
    expect(pathScript.approvals).toHaveLength(0);
    await pathBoot.app.close();

    const rejectedBodies = [
      { advisoryRevisionId: OTHER_REVISION },
      { purpose: 'approve_maintainer_reviewed_advisory_for_product_evaluation' },
      { capabilityId: REVISION, capabilitySeal: 'seal' },
      { reviewerIdentity: REVISION },
      { organizationId: REVISION },
    ];
    const bodyScript = scripted();
    const bodyBoot = await boot(bodyScript.runtime);
    for (const [index, payload] of rejectedBodies.entries()) {
      const response = await bodyBoot.app.inject({
        method: 'POST',
        url: `/intelligence/maintainer-reviewed-advisories/${REVISION}/approval`,
        remoteAddress: `198.51.100.${90 + index}`,
        headers: mutationHeaders(bodyBoot.session),
        payload,
      });
      expect(response.statusCode).toBe(400);
      expect(JSON.stringify(response.json())).not.toContain('seal');
    }
    expect(bodyScript.approvals).toHaveLength(0);
    await bodyBoot.app.close();

    const hidden = [
      'separation_of_duties_required',
      'capability_required',
      'capability_rejected',
      'capability_expired',
    ];
    const hiddenMessages: string[] = [];
    for (const [index, outcome] of hidden.entries()) {
      const script = scripted('submitted', outcome);
      const booted = await boot(script.runtime);
      const response = await approve(
        booted.app,
        booted.session,
        REVISION,
        `198.51.100.${100 + index}`,
      );
      expect(response.statusCode, outcome).toBe(403);
      expectEnvelope(response, 'forbidden', 'The approval was not recorded.');
      hiddenMessages.push(response.json().error.message);
      expect(JSON.stringify(response.json())).not.toMatch(
        /capability|seal|issuer|separation|author/i,
      );
      expect(script.approvals).toHaveLength(1);
      await booted.app.close();
    }
    expect(new Set(hiddenMessages).size).toBe(1);

    const conflict = scripted('submitted', 'immutable_conflict');
    const conflictBoot = await boot(conflict.runtime);
    const conflicted = await approve(
      conflictBoot.app,
      conflictBoot.session,
      REVISION,
      '198.51.100.110',
    );
    expect(conflicted.statusCode).toBe(409);
    expectEnvelope(conflicted, 'conflict', 'The request conflicts with the stored advisory.');
    await conflictBoot.app.close();

    const missing = scripted('submitted', 'not_found');
    const missingBoot = await boot(missing.runtime);
    const absent = await approve(
      missingBoot.app,
      missingBoot.session,
      OTHER_REVISION,
      '198.51.100.111',
    );
    expect(absent.statusCode).toBe(404);
    expectEnvelope(absent, 'not_found', 'Not found.');
    expect(JSON.stringify(absent.json())).not.toContain(OTHER_REVISION);
    await missingBoot.app.close();

    const unavailable = scripted('submitted', 'database_unavailable');
    const unavailableBoot = await boot(unavailable.runtime);
    const down = await approve(
      unavailableBoot.app,
      unavailableBoot.session,
      REVISION,
      '198.51.100.112',
    );
    expect(down.statusCode).toBe(503);
    expect(JSON.stringify(down.json())).not.toMatch(/database|prisma|sql/i);
    await unavailableBoot.app.close();

    const thrown = scripted('submitted', 'throw');
    const thrownBoot = await boot(thrown.runtime);
    const exploded = await approve(thrownBoot.app, thrownBoot.session, REVISION, '198.51.100.113');
    expect(exploded.statusCode).toBe(503);
    expect(JSON.stringify(exploded.json())).not.toMatch(/seal|UPDATE|prisma/i);
    await thrownBoot.app.close();
  });
});

async function boot(
  advisories: MaintainerReviewedAdvisoryRuntime,
  options?: {
    membershipCount?: 0 | 1 | 2;
    role?: 'owner' | 'admin' | 'member' | 'viewer';
    submissionPeerKey?: (request: FastifyRequest) => string;
  },
) {
  const harness = createAuthTestHarness({
    membershipCount: options?.membershipCount ?? 1,
    primaryRole: options?.role ?? 'owner',
  });
  const { app } = await buildTestApi({
    harness,
    advisories,
    ...(options?.submissionPeerKey === undefined
      ? {}
      : { submissionPeerKey: options.submissionPeerKey }),
  });
  const session = await login(app, harness.config.auth.cookieName);
  return { app, harness, session };
}

async function login(
  app: FastifyInstance,
  cookieName: string,
): Promise<{ cookie: string; csrf: string }> {
  const response = await app.inject({
    method: 'POST',
    url: '/auth/login',
    remoteAddress: '192.0.2.40',
    headers: { origin: TEST_ORIGIN, 'content-type': 'application/json' },
    payload: { email: 'owner@synthetic.patchpilot.test', password: VALID_PASSWORD },
  });
  expect(response.statusCode).toBe(200);
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
    cookie: part,
    csrf: (response.json() as SessionResponse).csrfToken,
  };
}

function mutationHeaders(
  session: { cookie: string; csrf: string },
  extra: Record<string, string> = {},
): Record<string, string> {
  return {
    origin: TEST_ORIGIN,
    'content-type': 'application/json',
    cookie: session.cookie,
    ...(session.csrf.length === 0 ? {} : { 'x-csrf-token': session.csrf }),
    ...extra,
  };
}

async function post(
  app: FastifyInstance,
  session: { cookie: string; csrf: string } | null,
  payload: Record<string, unknown>,
  remoteAddress: string,
  extraHeaders: Record<string, string> = {},
) {
  return app.inject({
    method: 'POST',
    url: '/intelligence/maintainer-reviewed-advisories',
    remoteAddress,
    headers:
      session === null
        ? { origin: TEST_ORIGIN, 'content-type': 'application/json', ...extraHeaders }
        : mutationHeaders(session, extraHeaders),
    payload,
  });
}

async function approve(
  app: FastifyInstance,
  session: { cookie: string; csrf: string },
  revisionId: string,
  remoteAddress: string,
) {
  return app.inject({
    method: 'POST',
    url: `/intelligence/maintainer-reviewed-advisories/${revisionId}/approval`,
    remoteAddress,
    headers: mutationHeaders(session),
    payload: {},
  });
}

function expectEnvelope(
  response: { json: () => { error: { code: string; message: string } } },
  code: string,
  message: string,
): void {
  expect(response.json().error.code).toBe(code);
  expect(response.json().error.message).toBe(message);
}

function metricRecords(logs: string): Array<Record<string, string>> {
  return logs
    .split('\n')
    .filter((line) => line.includes('maintainer-reviewed advisory metric'))
    .map((line) => JSON.parse(line) as { metric: Record<string, string> })
    .map((entry) => entry.metric);
}
