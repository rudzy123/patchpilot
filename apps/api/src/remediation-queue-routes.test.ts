import type { FastifyInstance } from 'fastify';
import { describe, expect, it } from 'vitest';

import {
  BUILTIN_PRIORITY_POLICY_KEY,
  BUILTIN_PRIORITY_POLICY_VERSION,
  PRIORITY_CALCULATION_ENGINE_VERSION,
  REMEDIATION_QUEUE_EXPORT_CAP,
  type RemediationQueueExportDocument,
} from '@patchpilot/domain';

import {
  TEST_ORIGIN,
  VALID_PASSWORD,
  buildTestApi,
  createAuthTestHarness,
} from './auth-test-harness.js';
import type { ControlledPriorityRuntime } from './priority-runtime.js';
import {
  REMEDIATION_QUEUE_EXPORT_CSV_HEADER,
  serializeRemediationQueueExport,
} from './remediation-queue-http.js';
import { REMEDIATION_QUEUE_ORGANIZATION_LIMIT } from './remediation-queue-routes.js';

const FINDING = 'abababab-abab-4bab-8bab-abababababab';
const ASSET = 'cdcdcdcd-cdcd-4dcd-8dcd-cdcdcdcdcdcd';
const POLICY = '12121212-1212-4212-8212-121212121212';
const HASH = 'ab'.repeat(32);
const AT = '2026-11-04T18:00:00.000Z';

type RoleName = 'owner' | 'admin' | 'member' | 'viewer';

function runtime(kind: 'page' | 'stale_cursor' | 'priority_policy_unavailable' | 'unavailable'): {
  runtime: ControlledPriorityRuntime;
  calls: string[];
} {
  const calls: string[] = [];
  return {
    calls,
    runtime: {
      async calculate() {
        return { kind: 'internal_failure' };
      },
      async read() {
        return { kind: 'unavailable' };
      },
      async recordReview() {
        return { kind: 'unavailable' };
      },
      async exportQueue() {
        return { kind: 'unavailable' as const };
      },
      async readQueue(input) {
        calls.push(`${input.actor.role}:${input.section}:${input.limit}:${input.cursor ?? ''}`);
        if (
          kind === 'stale_cursor' ||
          kind === 'priority_policy_unavailable' ||
          kind === 'unavailable'
        ) {
          return { kind };
        }
        if (input.section === 'not_calculated') {
          return {
            kind: 'page',
            page: {
              asOf: AT,
              reference: reference(),
              counts: { ranked: 0, incomparable: 0, not_calculated: 1 },
              section: 'not_calculated',
              limit: input.limit,
              nextCursor: null,
              rows: [
                {
                  findingId: FINDING,
                  assetId: ASSET,
                  assetName: 'queue <asset>',
                  componentName: 'reviewed-npm-widget',
                  componentVersion: '1.1.0',
                  vulnerabilityPublicId: 'OSV-1',
                  humanReview: { status: 'none', priorReviewExists: false },
                },
              ],
            },
          };
        }
        return {
          kind: 'page',
          page: {
            asOf: AT,
            reference: reference(),
            counts: { ranked: 1, incomparable: 0, not_calculated: 0 },
            section: 'ranked',
            limit: input.limit,
            nextCursor: null,
            rows: [
              {
                findingId: FINDING,
                assetId: ASSET,
                assetName: 'queue <asset>',
                componentName: 'reviewed-npm-widget',
                componentVersion: '1.1.0',
                vulnerabilityPublicId: 'OSV-1',
                priorityBand: 'P2',
                priority: 68,
                policy: {
                  riskPolicyId: POLICY,
                  policyKey: 'patchpilot.builtin.v0',
                  policyVersion: 2,
                  policyDefinitionSha256: HASH,
                },
                calculatedAt: AT,
                inputsChanged: { status: 'none_detected', signals: [] },
                humanReview: { status: 'none', priorReviewExists: false },
              },
            ],
          },
        };
      },
    },
  };
}

function reference() {
  return {
    policyKey: 'patchpilot.builtin.v0' as const,
    policyVersion: 2 as const,
    policyDefinitionSha256: HASH,
    engineVersion: PRIORITY_CALCULATION_ENGINE_VERSION,
  };
}

describe('remediation queue route', () => {
  it('returns three closed sections to an owner and denies a member', async () => {
    const owner = runtime('page');
    const ownerApp = await boot('owner', owner.runtime);
    const ranked = await get(ownerApp.app, ownerApp.session, 'section=ranked');
    expect(ranked.statusCode).toBe(200);
    expect(ranked.headers['cache-control']).toBe('private, no-store');
    expect(ranked.json()).toMatchObject({
      schemaVersion: 'remediation_queue_v1',
      section: 'ranked',
      rows: [{ assetName: 'queue <asset>', priorityBand: 'P2', priority: 68 }],
    });
    const absent = await get(ownerApp.app, ownerApp.session, 'section=not_calculated');
    expect(absent.statusCode).toBe(200);
    expect(absent.json().rows[0]).toEqual({
      findingId: FINDING,
      assetId: ASSET,
      assetName: 'queue <asset>',
      componentName: 'reviewed-npm-widget',
      componentVersion: '1.1.0',
      vulnerabilityPublicId: 'OSV-1',
      humanReview: { status: 'none', priorReviewExists: false },
    });
    expect(owner.calls[0]).toBe('owner:ranked:20:');
    const member = runtime('page');
    const memberApp = await boot('member', member.runtime);
    const denied = await get(memberApp.app, memberApp.session, 'section=ranked');
    expect(denied.statusCode).toBe(403);
    expect(member.calls).toEqual([]);
    const viewer = runtime('page');
    const viewerApp = await boot('viewer', viewer.runtime);
    const viewerDenied = await get(viewerApp.app, viewerApp.session, 'section=ranked');
    expect(viewerDenied.statusCode).toBe(403);
    await closeAll(ownerApp, memberApp, viewerApp);
  });

  it('rejects an organization query, a body, and a stale cursor', async () => {
    const script = runtime('stale_cursor');
    const { app, session } = await boot('admin', script.runtime);
    const missing = await get(app, session, '');
    expect(missing.statusCode).toBe(400);
    const organization = await get(app, session, `section=ranked&organizationId=${ASSET}`);
    expect(organization.statusCode).toBe(400);
    const body = await app.inject({
      method: 'GET',
      url: '/remediation-queue?section=ranked',
      headers: { cookie: session.cookie, 'content-type': 'application/json' },
      payload: {},
    });
    expect(body.statusCode).toBe(400);
    const stale = await get(app, session, 'section=ranked&cursor=abc');
    expect(stale.statusCode).toBe(409);
    expect(stale.json().error.message).toBe('The page cursor is no longer current.');
    expect(script.calls).toEqual(['admin:ranked:20:abc']);
    await app.close();
  });

  it('returns the priority-policy failure without rows', async () => {
    const script = runtime('priority_policy_unavailable');
    const { app, session } = await boot('owner', script.runtime);
    const response = await get(app, session, 'section=ranked');
    expect(response.statusCode).toBe(503);
    expect(response.json().error.message).toBe('Priority policy is unavailable.');
    expect(response.json()).not.toHaveProperty('rows');
    await app.close();
  });

  it('limits an organization after 20 requests', async () => {
    expect(REMEDIATION_QUEUE_ORGANIZATION_LIMIT.max).toBe(20);
    const script = runtime('unavailable');
    const { app, session } = await boot('owner', script.runtime);
    const statuses: number[] = [];
    for (let attempt = 0; attempt < 21; attempt += 1) {
      const response = await get(app, session, 'section=ranked');
      statuses.push(response.statusCode);
    }
    expect(statuses.slice(0, 20).every((status) => status === 503)).toBe(true);
    expect(statuses[20]).toBe(429);
    await app.close();
  });

  it('exports JSON and CSV for owners and admins without calculating priority', async () => {
    const owner = exportRuntime();
    const ownerApp = await boot('owner', owner.runtime);
    const json = await postExport(
      ownerApp.app,
      ownerApp.session,
      { format: 'json' },
      {
        correlationId: 'export-json-1',
      },
    );
    expect(json.statusCode).toBe(200);
    expect(json.headers['content-type']).toBe('application/json; charset=utf-8');
    expect(json.headers['content-disposition']).toBe(
      'attachment; filename="remediation-queue.json"',
    );
    expect(json.headers['cache-control']).toBe('private, no-store');
    expect(json.body).toBe(
      Buffer.from(serializeRemediationQueueExport(exportDocument('json'))).toString('utf8'),
    );
    expect(
      json.body.startsWith('{"schemaVersion":"remediation_queue_export_v1","format":"json"'),
    ).toBe(true);
    expect(json.body).not.toContain(' :');
    expect(owner.calls).toEqual([
      `owner:${ownerApp.harness.organizations[0]?.id}:json:export-json-1`,
    ]);
    expect(ownerApp.harness.logs()).not.toContain('queue <asset>');
    expect(ownerApp.harness.logs()).not.toContain('OSV-1');
    const admin = exportRuntime();
    const adminApp = await boot('admin', admin.runtime);
    const csv = await postExport(
      adminApp.app,
      adminApp.session,
      { format: 'csv' },
      {
        correlationId: 'export-csv-1',
      },
    );
    expect(csv.statusCode).toBe(200);
    expect(csv.headers['content-type']).toBe('text/csv; charset=utf-8');
    expect(csv.headers['content-disposition']).toBe('attachment; filename="remediation-queue.csv"');
    expect(csv.body.startsWith(`${REMEDIATION_QUEUE_EXPORT_CSV_HEADER}\n`)).toBe(true);
    expect(admin.calls).toEqual([
      `admin:${adminApp.harness.organizations[0]?.id}:csv:export-csv-1`,
    ]);
    expect(admin.calls.some((call) => call.startsWith('calculate'))).toBe(false);
    await closeAll(ownerApp, adminApp);
  });

  it('denies members, viewers, and unauthenticated export requests before the snapshot', async () => {
    const member = exportRuntime();
    const memberApp = await boot('member', member.runtime);
    const memberDenied = await postExport(memberApp.app, memberApp.session, { format: 'json' });
    expect(memberDenied.statusCode).toBe(403);
    const viewer = exportRuntime();
    const viewerApp = await boot('viewer', viewer.runtime);
    const viewerDenied = await postExport(viewerApp.app, viewerApp.session, { format: 'csv' });
    expect(viewerDenied.statusCode).toBe(403);
    const anonymous = exportRuntime();
    const anonymousApp = await boot('owner', anonymous.runtime);
    const unauthenticated = await anonymousApp.app.inject({
      method: 'POST',
      url: '/remediation-queue/export',
      remoteAddress: '198.51.100.22',
      headers: { origin: TEST_ORIGIN, 'content-type': 'application/json' },
      payload: { format: 'json' },
    });
    expect(unauthenticated.statusCode).toBe(401);
    expect(member.calls).toEqual([]);
    expect(viewer.calls).toEqual([]);
    expect(anonymous.calls).toEqual([]);
    await closeAll(memberApp, viewerApp, anonymousApp);
  });

  it('rejects client authority, a bad body, CSRF, and Origin before export', async () => {
    const script = exportRuntime();
    const { app, session, harness } = await boot('owner', script.runtime);
    const foreignOrganizationId = harness.organizations[1]?.id ?? ASSET;
    const cases = [
      postExport(app, session, { format: 'json', organizationId: foreignOrganizationId }),
      postExport(app, session, { format: 'xml' }),
      postExport(app, session, { format: 'json', extra: true }),
      postExport(app, session, {}),
      app.inject({
        method: 'POST',
        url: `/remediation-queue/export?organizationId=${foreignOrganizationId}`,
        remoteAddress: '198.51.100.23',
        headers: {
          origin: TEST_ORIGIN,
          'content-type': 'application/json',
          cookie: session.cookie,
          'x-csrf-token': session.csrf,
        },
        payload: { format: 'json' },
      }),
      app.inject({
        method: 'POST',
        url: '/remediation-queue/export',
        remoteAddress: '198.51.100.24',
        headers: {
          origin: TEST_ORIGIN,
          'content-type': 'application/json',
          cookie: session.cookie,
          'x-csrf-token': session.csrf,
          'x-organization-id': foreignOrganizationId,
        },
        payload: { format: 'json' },
      }),
      postExport(app, session, { format: 'json' }, { csrf: false }),
      postExport(app, session, { format: 'json' }, { origin: 'https://evil.example' }),
    ];
    const responses = await Promise.all(cases);
    expect(responses.map((response) => response.statusCode)).toEqual([
      400, 400, 400, 400, 400, 400, 401, 403,
    ]);
    expect(script.calls).toEqual([]);
    await app.close();
  });

  it('maps policy, cap, and correlation failures without a file', async () => {
    const policy = exportRuntime('priority_policy_unavailable');
    const policyApp = await boot('owner', policy.runtime);
    const policyResponse = await postExport(policyApp.app, policyApp.session, { format: 'json' });
    expect(policyResponse.statusCode).toBe(503);
    expect(policyResponse.json().error.message).toBe('Priority policy is unavailable.');
    const cap = exportRuntime('cap_exceeded');
    const capApp = await boot('admin', cap.runtime);
    const capResponse = await postExport(capApp.app, capApp.session, { format: 'csv' });
    expect(capResponse.statusCode).toBe(409);
    expect(capResponse.json().error.message).toBe('Remediation queue export exceeds 150 findings.');
    expect(capResponse.headers['content-disposition']).toBeUndefined();
    const conflict = exportRuntime('correlation_conflict');
    const conflictApp = await boot('owner', conflict.runtime);
    const conflictResponse = await postExport(conflictApp.app, conflictApp.session, {
      format: 'json',
    });
    expect(conflictResponse.statusCode).toBe(409);
    expect(conflictResponse.json().error.message).toBe('The export was not recorded.');
    await closeAll(policyApp, capApp, conflictApp);
  });
});

function exportRuntime(
  kind:
    | 'exported'
    | 'priority_policy_unavailable'
    | 'cap_exceeded'
    | 'correlation_conflict'
    | 'unavailable' = 'exported',
): { runtime: ControlledPriorityRuntime; calls: string[] } {
  const calls: string[] = [];
  return {
    calls,
    runtime: {
      async calculate() {
        calls.push('calculate');
        return { kind: 'internal_failure' };
      },
      async read() {
        calls.push('read');
        return { kind: 'unavailable' };
      },
      async readQueue() {
        calls.push('readQueue');
        return { kind: 'unavailable' };
      },
      async recordReview() {
        calls.push('review');
        return { kind: 'unavailable' };
      },
      async exportQueue(input) {
        calls.push(
          `${input.actor.role}:${input.actor.organizationId}:${input.format}:${input.correlationId}`,
        );
        if (kind !== 'exported') {
          return { kind };
        }
        const document = exportDocument(input.format);
        const body = serializeRemediationQueueExport(document);
        return {
          kind: 'exported',
          body,
          sha256: HASH,
          byteLength: body.byteLength,
          document,
        };
      },
    },
  };
}

function exportDocument(format: 'json' | 'csv'): RemediationQueueExportDocument {
  return {
    format,
    asOf: AT,
    reference: reference(),
    counts: { ranked: 1, incomparable: 0, not_calculated: 0 },
    rowCount: 1,
    cap: REMEDIATION_QUEUE_EXPORT_CAP,
    sections: {
      ranked: [
        {
          findingId: FINDING,
          assetId: ASSET,
          assetName: 'queue <asset>',
          componentName: 'reviewed-npm-widget',
          componentVersion: '1.1.0',
          vulnerabilityPublicId: 'OSV-1',
          priorityBand: 'P2',
          priority: 68,
          policy: {
            riskPolicyId: POLICY,
            policyKey: BUILTIN_PRIORITY_POLICY_KEY,
            policyVersion: BUILTIN_PRIORITY_POLICY_VERSION,
            policyDefinitionSha256: HASH,
          },
          calculatedAt: AT,
          inputsChanged: { status: 'none_detected', signals: [] },
          humanReview: {
            status: 'corrected',
            priorReviewExists: true,
            reviewId: FINDING,
            correctedBand: 'P4',
            expiresAt: AT,
          },
        },
      ],
      incomparable: [],
      not_calculated: [],
    },
  };
}

async function boot(role: RoleName, priority: ControlledPriorityRuntime) {
  const harness = createAuthTestHarness({ membershipCount: 1, primaryRole: role });
  const built = await buildTestApi({ harness, priority });
  const loggedIn = await built.app.inject({
    method: 'POST',
    url: '/auth/login',
    remoteAddress: '192.0.2.40',
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

async function postExport(
  app: FastifyInstance,
  session: { cookie: string; csrf: string },
  payload: { format?: string; organizationId?: string; extra?: boolean },
  options?: { csrf?: boolean; origin?: string; correlationId?: string },
) {
  return app.inject({
    method: 'POST',
    url: '/remediation-queue/export',
    remoteAddress: '198.51.100.21',
    headers: {
      origin: options?.origin ?? TEST_ORIGIN,
      'content-type': 'application/json',
      cookie: session.cookie,
      ...(options?.csrf === false ? {} : { 'x-csrf-token': session.csrf }),
      ...(options?.correlationId === undefined
        ? {}
        : { 'x-correlation-id': options.correlationId }),
    },
    payload,
  });
}

async function get(app: FastifyInstance, session: { cookie: string }, query: string) {
  return app.inject({
    method: 'GET',
    url: query.length === 0 ? '/remediation-queue' : `/remediation-queue?${query}`,
    remoteAddress: '198.51.100.20',
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
