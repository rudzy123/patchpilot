import type { FastifyInstance } from 'fastify';
import { describe, expect, it } from 'vitest';

import {
  TEST_ORIGIN,
  VALID_PASSWORD,
  buildTestApi,
  createAuthTestHarness,
} from './auth-test-harness.js';
import type { ControlledPriorityRuntime } from './priority-runtime.js';

const FINDING = 'abababab-abab-4bab-8bab-abababababab';
const OTHER = 'cdcdcdcd-cdcd-4dcd-8dcd-cdcdcdcdcdcd';
const CALCULATION = '12121212-1212-4212-8212-121212121212';
const LOGIN_IP = '192.0.2.40';

type RoleName = 'owner' | 'admin' | 'member' | 'viewer';

function runtime(result?: Partial<ControlledPriorityRuntime>): {
  runtime: ControlledPriorityRuntime;
  calls: string[];
} {
  const calls: string[] = [];
  return {
    calls,
    runtime: {
      async calculate(input) {
        calls.push(`calculate:${input.actor.role}:${input.findingId}`);
        const organizationId = input.actor.organizationId ?? input.findingId;
        return {
          kind: 'calculated',
          calculation: {
            id: CALCULATION,
            organizationId,
            findingId: input.findingId,
            riskPolicyId: '55555555-5555-4555-8555-555555555555',
            policyVersion: 2,
            policyDefinitionSha256: 'a'.repeat(64),
            calculatedAt: new Date('2026-06-01T00:00:00.000Z'),
            factors: {
              schemaVersion: 2,
              factors: [],
              rules: [],
              escalationReasons: [],
              evidenceSummary: { observed: 0, unknown: 0, unavailable: 0 },
              weightedScoreCenti: 0,
              upliftCenti: 0,
              sources: {
                evidenceIds: [],
                advisoryRevisionIds: [],
                componentOccurrenceIds: [],
                intelligenceSourceRecordIds: [],
                kev: { state: 'unavailable', reason: 'no_active_generation' },
              },
            },
            result: {
              schemaVersion: 1,
              priority: 0,
              priorityBand: 'P4',
              dueDateRecommendationDays: 180,
              escalationRecommendation: false,
            },
            calculationEngineVersion: '@patchpilot/policy-engine@1',
            calculationReason: 'initial',
            inputFingerprint: 'b'.repeat(64),
          },
        };
      },
      async read(input) {
        calls.push(`read:${input.actor.role}:${input.findingId}`);
        if (input.findingId === OTHER) {
          return { kind: 'not_found' };
        }
        return { kind: 'not_calculated', findingId: input.findingId };
      },
      async readQueue() {
        return { kind: 'unavailable' };
      },
      async exportQueue() {
        return { kind: 'unavailable' };
      },
      async recordReview(input) {
        calls.push(`review:${input.actor.role}:${input.findingId}`);
        return { kind: 'not_found' };
      },
      ...result,
    },
  };
}

describe('controlled finding priority routes', () => {
  it('lets an owner calculate and keeps not_calculated free of band fields', async () => {
    const script = runtime();
    const { app, session } = await boot('owner', script.runtime);
    const created = await post(app, session, FINDING);
    expect(created.statusCode).toBe(201);
    expect(created.json()).toMatchObject({
      schemaVersion: 'finding_risk_calculation_v1',
      status: 'calculated',
      findingId: FINDING,
      calculationReason: 'initial',
    });
    const current = await get(app, session, FINDING);
    expect(current.statusCode).toBe(200);
    expect(current.headers['cache-control']).toBe('private, no-store');
    const body = current.json();
    expect(body).toEqual({
      schemaVersion: 'finding_priority_v1',
      status: 'not_calculated',
      findingId: FINDING,
    });
    expect(body).not.toHaveProperty('priorityBand');
    expect(script.calls).toEqual([`calculate:owner:${FINDING}`, `read:owner:${FINDING}`]);
    await app.close();
  });

  it('denies admin calculation and member or viewer reads', async () => {
    const admin = runtime();
    const member = runtime();
    const viewer = runtime();
    const sessions = await Promise.all([
      boot('admin', admin.runtime),
      boot('member', member.runtime),
      boot('viewer', viewer.runtime),
    ]);
    expect((await post(sessions[0].app, sessions[0].session, FINDING)).statusCode).toBe(403);
    expect((await get(sessions[1].app, sessions[1].session, FINDING)).statusCode).toBe(403);
    expect((await get(sessions[2].app, sessions[2].session, FINDING)).statusCode).toBe(403);
    expect(admin.calls).toEqual([]);
    expect(member.calls).toEqual([]);
    expect(viewer.calls).toEqual([]);
    await closeAll(...sessions);
  });

  it('rejects a missing CSRF token, a foreign origin, and a read query', async () => {
    const script = runtime();
    const { app, session } = await boot('owner', script.runtime);
    const missing = await post(app, session, FINDING, { csrf: false });
    const origin = await app.inject({
      method: 'POST',
      url: `/findings/${FINDING}/risk-calculations`,
      remoteAddress: '198.51.100.20',
      headers: {
        origin: 'https://evil.example',
        'content-type': 'application/json',
        cookie: session.cookie,
        'x-csrf-token': session.csrf,
      },
      payload: {},
    });
    const query = await app.inject({
      method: 'GET',
      url: `/findings/${FINDING}/priority?band=P1`,
      remoteAddress: '198.51.100.21',
      headers: { cookie: session.cookie },
    });
    expect(missing.statusCode).toBe(401);
    expect(origin.statusCode).toBe(403);
    expect(query.statusCode).toBe(400);
    expect(script.calls).toEqual([]);
    await app.close();
  });

  it('returns the same not_found for an absent Finding and does not calculate on read', async () => {
    const script = runtime();
    const { app, session } = await boot('owner', script.runtime);
    const response = await get(app, session, OTHER);
    expect(response.statusCode).toBe(404);
    expect(response.json()).toMatchObject({ error: { code: 'not_found' } });
    expect(script.calls).toEqual([`read:owner:${OTHER}`]);
    await app.close();
  });

  it('returns 503 when the policy is unvalidated and 200 on exact replay', async () => {
    const unavailable = runtime({
      async calculate() {
        return { kind: 'priority_policy_unavailable', reason: 'unvalidated' };
      },
    });
    const replay = runtime({
      async calculate(input) {
        const base = await runtime().runtime.calculate(input);
        if (base.kind !== 'calculated') {
          return base;
        }
        return { kind: 'replayed', calculation: base.calculation };
      },
    });
    const first = await boot('owner', unavailable.runtime);
    const denied = await post(first.app, first.session, FINDING);
    expect(denied.statusCode).toBe(503);
    expect(denied.json()).toMatchObject({
      error: { code: 'internal', message: 'Priority policy is unavailable.' },
    });
    await first.app.close();
    const second = await boot('owner', replay.runtime);
    const again = await post(second.app, second.session, FINDING);
    expect(again.statusCode).toBe(200);
    expect(again.json()).toMatchObject({ status: 'already_applied' });
    await second.app.close();
  });

  it('lets an owner record a review and keeps the reason out of the log', async () => {
    const reason = 'priority-review-reason-token';
    const script = runtime({
      async recordReview(input) {
        return {
          kind: 'recorded',
          reviewId: '88888888-8888-4888-8888-888888888888',
          findingId: input.findingId,
          riskCalculationId: input.command.riskCalculationId,
        };
      },
    });
    const harness = createAuthTestHarness({ membershipCount: 1, primaryRole: 'owner' });
    const built = await buildTestApi({ harness, priority: script.runtime });
    const loggedIn = await built.app.inject({
      method: 'POST',
      url: '/auth/login',
      remoteAddress: LOGIN_IP,
      headers: { origin: TEST_ORIGIN, 'content-type': 'application/json' },
      payload: { email: harness.user.email, password: VALID_PASSWORD },
    });
    const session = sessionFrom(loggedIn, harness.config.auth.cookieName);
    const response = await review(built.app, session, {
      schemaVersion: 'priority_review_v1',
      riskCalculationId: CALCULATION,
      supersedesReviewId: null,
      decision: 'accepted',
      reason,
    });
    expect(response.statusCode).toBe(201);
    expect(response.json()).toEqual({
      schemaVersion: 'priority_review_v1',
      status: 'recorded',
      reviewId: '88888888-8888-4888-8888-888888888888',
      findingId: FINDING,
      riskCalculationId: CALCULATION,
    });
    expect(JSON.stringify(response.json())).not.toContain(reason);
    expect(harness.logs()).not.toContain(reason);
    await built.app.close();
  });

  it('denies an admin review and rejects a missing token or foreign origin', async () => {
    const admin = runtime();
    const owner = runtime();
    const adminBoot = await boot('admin', admin.runtime);
    const ownerBoot = await boot('owner', owner.runtime);
    const body = {
      schemaVersion: 'priority_review_v1',
      riskCalculationId: CALCULATION,
      supersedesReviewId: null,
      decision: 'accepted',
    };
    expect((await review(adminBoot.app, adminBoot.session, body)).statusCode).toBe(403);
    const missing = await review(ownerBoot.app, ownerBoot.session, body, { csrf: false });
    const origin = await ownerBoot.app.inject({
      method: 'POST',
      url: `/findings/${FINDING}/priority-reviews`,
      remoteAddress: '198.51.100.31',
      headers: {
        origin: 'https://evil.example',
        'content-type': 'application/json',
        cookie: ownerBoot.session.cookie,
        'x-csrf-token': ownerBoot.session.csrf,
      },
      payload: body,
    });
    expect(missing.statusCode).toBe(401);
    expect(origin.statusCode).toBe(403);
    expect(admin.calls).toEqual([]);
    expect(owner.calls).toEqual([]);
    await closeAll(adminBoot, ownerBoot);
  });

  it('returns the review conflict tokens and exact replay', async () => {
    const stale = runtime({
      async recordReview() {
        return { kind: 'review_not_current' };
      },
    });
    const oldCalculation = runtime({
      async recordReview() {
        return { kind: 'calculation_not_current' };
      },
    });
    const replay = runtime({
      async recordReview(input) {
        return {
          kind: 'already_applied',
          reviewId: '88888888-8888-4888-8888-888888888888',
          findingId: input.findingId,
          riskCalculationId: input.command.riskCalculationId,
        };
      },
    });
    const body = {
      schemaVersion: 'priority_review_v1',
      riskCalculationId: CALCULATION,
      supersedesReviewId: null,
      decision: 'accepted',
    };
    const first = await boot('owner', stale.runtime);
    const second = await boot('owner', oldCalculation.runtime);
    const third = await boot('owner', replay.runtime);
    expect((await review(first.app, first.session, body)).json()).toMatchObject({
      error: { code: 'conflict', message: 'review_not_current' },
    });
    expect((await review(second.app, second.session, body)).json()).toMatchObject({
      error: { code: 'conflict', message: 'calculation_not_current' },
    });
    const again = await review(third.app, third.session, body);
    expect(again.statusCode).toBe(200);
    expect(again.json()).toMatchObject({ status: 'already_applied' });
    await closeAll(first, second, third);
  });
});

async function boot(role: RoleName, priority: ControlledPriorityRuntime) {
  const harness = createAuthTestHarness({ membershipCount: 1, primaryRole: role });
  const built = await buildTestApi({ harness, priority });
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
    session: sessionFrom(loggedIn, harness.config.auth.cookieName),
  };
}

async function post(
  app: FastifyInstance,
  session: { cookie: string; csrf: string },
  findingId: string,
  options?: { csrf?: boolean },
) {
  return app.inject({
    method: 'POST',
    url: `/findings/${findingId}/risk-calculations`,
    remoteAddress: '198.51.100.10',
    headers: {
      origin: TEST_ORIGIN,
      'content-type': 'application/json',
      cookie: session.cookie,
      ...(options?.csrf === false ? {} : { 'x-csrf-token': session.csrf }),
    },
    payload: {},
  });
}

async function review(
  app: FastifyInstance,
  session: { cookie: string; csrf: string },
  payload: Record<string, string | null>,
  options?: { csrf?: boolean },
) {
  return app.inject({
    method: 'POST',
    url: `/findings/${FINDING}/priority-reviews`,
    remoteAddress: '198.51.100.30',
    headers: {
      origin: TEST_ORIGIN,
      'content-type': 'application/json',
      cookie: session.cookie,
      ...(options?.csrf === false ? {} : { 'x-csrf-token': session.csrf }),
    },
    payload,
  });
}

async function get(app: FastifyInstance, session: { cookie: string }, findingId: string) {
  return app.inject({
    method: 'GET',
    url: `/findings/${findingId}/priority`,
    remoteAddress: '198.51.100.11',
    headers: { cookie: session.cookie },
  });
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
  const body = response.json() as { csrfToken?: string };
  if (typeof body.csrfToken !== 'string') {
    throw new Error('expected csrf');
  }
  return { cookie: `${cookieName}=${part.slice(prefix.length)}`, csrf: body.csrfToken };
}

async function closeAll(...sessions: { app: FastifyInstance }[]): Promise<void> {
  await Promise.all(sessions.map(async (session) => session.app.close()));
}
