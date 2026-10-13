import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import type { SessionResponse } from '@patchpilot/contracts';
import {
  FINDING_CREATION_POLICY_ID,
  FINDING_CREATION_POLICY_VERSION,
  FINDING_INSPECTION_PROJECTION_SCHEMA_VERSION,
  FINDING_INSPECTION_RESULT_SCHEMA_VERSION,
} from '@patchpilot/domain';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { describe, expect, it } from 'vitest';

import {
  TEST_ORIGIN,
  VALID_PASSWORD,
  buildTestApi,
  createAuthTestHarness,
} from './auth-test-harness.js';
import {
  LATEST_OBSERVATION_METRIC_LABEL_KEYS,
  latestObservationMetricLabels,
} from './finding-latest-observation-http.js';
import type { FindingOperatorRuntime } from './finding-runtime.js';

const ASSET = '44444444-4444-4444-8444-444444444444';
const COMPONENT = '55555555-5555-4555-8555-555555555555';
const VULNERABILITY = '66666666-6666-4666-8666-666666666666';
const FINDING = 'abababab-abab-4bab-8bab-abababababab';
const ABSENT = 'cdcdcdcd-cdcd-4dcd-8dcd-cdcdcdcdcdcd';
const OBSERVED_AT = '2026-10-08T12:00:00.123456Z';
const SECRET_VERSION = 'zz-secret-version';
const LOGIN_IP = '192.0.2.40';

type RoleName = 'owner' | 'admin' | 'member' | 'viewer';
type Aggregate = 'affected' | 'unaffected' | 'unknown' | 'component_absent';
type LatestCall = { organizationId: string | null; findingId: string };

function inspectionProjection() {
  return {
    schemaVersion: FINDING_INSPECTION_PROJECTION_SCHEMA_VERSION,
    findingId: FINDING,
    state: 'open' as const,
    asset: { id: ASSET, displayName: 'Tracked asset' },
    component: { id: COMPONENT, ecosystem: 'npm', namespace: null, name: 'reviewed-npm-widget' },
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

function foundResult(input?: {
  findingId?: string;
  observationSource?: 'creation' | 'latest_repeated';
  aggregate?: Aggregate;
  versions?: readonly string[];
  affectedSupportCount?: number;
  unaffectedSupportCount?: number;
  unknownSupportCount?: number;
  unknownVersionSupportCount?: number;
  graphCompleteness?: 'complete' | 'no_dependencies';
  mappedResult?: string;
}) {
  const aggregate = input?.aggregate ?? 'affected';
  const observationSource =
    input?.observationSource ?? (aggregate === 'affected' ? 'creation' : 'latest_repeated');
  const evidence =
    aggregate === 'component_absent'
      ? {
          kind: 'component_absence' as const,
          graphCompleteness: input?.graphCompleteness ?? 'no_dependencies',
          componentCount: 2,
          dependencyEdgeCount: input?.graphCompleteness === 'complete' ? 1 : 0,
        }
      : {
          kind: 'occurrence_support' as const,
          affectedSupportCount:
            input?.affectedSupportCount ?? (observationSource === 'creation' ? 1 : 0),
          unaffectedSupportCount: input?.unaffectedSupportCount ?? 0,
          unknownSupportCount: input?.unknownSupportCount ?? 0,
          unknownVersionSupportCount: input?.unknownVersionSupportCount ?? 0,
          knownVersions: input?.versions ?? [],
        };
  return {
    schemaVersion: 'finding_latest_observation_external_result_v1' as const,
    status: 'found' as const,
    projection: {
      schemaVersion: 'finding_latest_observation_projection_v1' as const,
      findingId: input?.findingId ?? FINDING,
      assetId: ASSET,
      componentId: COMPONENT,
      vulnerabilityId: VULNERABILITY,
      observationSource,
      observedAt: OBSERVED_AT,
      aggregate,
      mappedResult: input?.mappedResult ?? 'present',
      evidence,
    },
  };
}

function scriptedFindings(latest: (findingId: string) => unknown = () => foundResult()): {
  runtime: FindingOperatorRuntime;
  calls: LatestCall[];
} {
  const calls: LatestCall[] = [];
  return {
    calls,
    runtime: {
      creation: {
        async execute() {
          return { status: 'authority_required' };
        },
      },
      inspection: {
        async execute() {
          return {
            schemaVersion: FINDING_INSPECTION_RESULT_SCHEMA_VERSION,
            status: 'found' as const,
            projection: inspectionProjection(),
          };
        },
      },
      latestObservation: {
        async execute(input) {
          calls.push({
            organizationId: input.actor.organizationId,
            findingId: input.command.findingId,
          });
          const result = latest(input.command.findingId);
          if (result === 'throw') {
            throw new Error('SELECT latest_observation prisma mappedResult reviewer.two');
          }
          return result as never;
        },
      },
    },
  };
}

describe('controlled finding latest-observation route', () => {
  it('lets owners and admins read and denies members and viewers', async () => {
    const script = scriptedFindings();
    const owner = await boot('owner', script.runtime);
    const admin = await boot('admin', script.runtime);
    const member = await boot('member', script.runtime);
    const viewer = await boot('viewer', script.runtime);
    const ownerView = await get(owner.app, owner.session, FINDING, '198.51.100.1');
    const adminView = await get(admin.app, admin.session, FINDING, '198.51.100.2');
    const memberView = await get(member.app, member.session, FINDING, '198.51.100.3');
    const viewerView = await get(viewer.app, viewer.session, FINDING, '198.51.100.4');
    expect(ownerView.statusCode).toBe(200);
    expect(adminView.statusCode).toBe(200);
    expect(ownerView.json()).toMatchObject({
      schemaVersion: 'finding_latest_observation_transport_v1',
      findingId: FINDING,
      observationSource: 'creation',
      aggregate: 'affected',
    });
    expect(adminView.json()).toEqual(ownerView.json());
    expect(memberView.statusCode).toBe(403);
    expect(viewerView.statusCode).toBe(403);
    expectEnvelope(memberView, 'forbidden', 'Permission denied.');
    expectEnvelope(viewerView, 'forbidden', 'Permission denied.');
    expect(script.calls.map((call) => call.findingId)).toEqual([FINDING, FINDING]);
    await closeAll(owner, admin, member, viewer);
  });

  it('requires an authenticated session, an active organization, and an active membership', async () => {
    const script = scriptedFindings();
    const { app } = await boot('owner', script.runtime);
    const anonymous = await app.inject({
      method: 'GET',
      url: `/findings/${FINDING}/latest-observation`,
      remoteAddress: '198.51.100.5',
    });
    expect(anonymous.statusCode).toBe(401);
    expectEnvelope(anonymous, 'unauthorized', 'Authentication required.');
    expect(anonymous.headers['cache-control']).toBe('private, no-store');
    const unscoped = await boot('owner', script.runtime, { membershipCount: 2 });
    const missingOrg = await get(unscoped.app, unscoped.session, FINDING, '198.51.100.6');
    expect(missingOrg.statusCode).toBe(403);
    expectEnvelope(missingOrg, 'forbidden', 'Organization context is required.');
    const inactive = await boot('owner', script.runtime);
    const membership = inactive.harness.memberships.rows[0]?.membership;
    if (membership === undefined) {
      throw new Error('expected membership');
    }
    membership.status = 'revoked';
    const revoked = await get(inactive.app, inactive.session, FINDING, '198.51.100.7');
    expect(revoked.statusCode).toBe(403);
    expectEnvelope(revoked, 'forbidden', 'Organization context is required.');
    expect(script.calls).toHaveLength(0);
    await app.close();
    await unscoped.app.close();
    await inactive.app.close();
  });

  it('rejects substitute permissions and caller-supplied authority', async () => {
    const memberScript = scriptedFindings();
    const member = await boot('member', memberScript.runtime);
    const denied = await get(member.app, member.session, FINDING, '198.51.100.8');
    expect(denied.statusCode).toBe(403);
    expectEnvelope(denied, 'forbidden', 'Permission denied.');
    expect(memberScript.calls).toHaveLength(0);
    const script = scriptedFindings();
    const owner = await boot('owner', script.runtime);
    const headed = await get(owner.app, owner.session, FINDING, '198.51.100.9', {
      'x-permission': 'finding:create_controlled',
      'x-organization-id': ASSET,
    });
    const queried = await owner.app.inject({
      method: 'GET',
      url: `/findings/${FINDING}/latest-observation?permission=finding:inspect&organizationId=${ASSET}`,
      remoteAddress: '198.51.100.10',
      headers: { cookie: owner.session.cookie },
    });
    expect(headed.statusCode).toBe(400);
    expect(queried.statusCode).toBe(400);
    expectEnvelope(headed, 'validation', 'Invalid request.');
    expect(script.calls).toHaveLength(0);
    await member.app.close();
    await owner.app.close();
  });

  it('rejects a malformed id, an unexpected query, and an unexpected body before the service', async () => {
    const script = scriptedFindings();
    const { app, session } = await boot('owner', script.runtime);
    const malformed = await get(app, session, 'not-a-finding', '198.51.100.10');
    const uppercase = await get(app, session, FINDING.toUpperCase(), '198.51.100.11');
    const queried = await app.inject({
      method: 'GET',
      url: `/findings/${FINDING}/latest-observation?cursor=next&aggregate=affected`,
      remoteAddress: '198.51.100.12',
      headers: { cookie: session.cookie },
    });
    const bodied = await app.inject({
      method: 'GET',
      url: `/findings/${FINDING}/latest-observation`,
      remoteAddress: '198.51.100.13',
      headers: {
        cookie: session.cookie,
        'content-type': 'application/json',
        'content-length': '2',
      },
      payload: '{}',
    });
    const textBody = await app.inject({
      method: 'GET',
      url: `/findings/${FINDING}/latest-observation`,
      remoteAddress: '198.51.100.14',
      headers: {
        cookie: session.cookie,
        'content-type': 'text/plain',
        'content-length': '4',
      },
      payload: 'nope',
    });
    const emptyKey = await app.inject({
      method: 'GET',
      url: `/findings/${FINDING}/latest-observation?=1&historyLimit=2`,
      remoteAddress: '198.51.100.15',
      headers: { cookie: session.cookie },
    });
    const repeatedKey = await app.inject({
      method: 'GET',
      url: `/findings/${FINDING}/latest-observation?aggregate=affected&aggregate=unknown`,
      remoteAddress: '198.51.100.16',
      headers: { cookie: session.cookie },
    });
    expect(malformed.statusCode).toBe(400);
    expect(uppercase.statusCode).toBe(400);
    expect(queried.statusCode).toBe(400);
    expect(bodied.statusCode).toBe(400);
    expect(textBody.statusCode).toBe(400);
    expect(emptyKey.statusCode).toBe(400);
    expect(repeatedKey.statusCode).toBe(400);
    expectEnvelope(uppercase, 'validation', 'Invalid request.');
    expectEnvelope(textBody, 'validation', 'Invalid request.');
    expect(textBody.headers['cache-control']).toBe('private, no-store');
    expect(script.calls).toHaveLength(0);
    await app.close();
  });

  it('does not require a mutation CSRF token or an allowed origin', async () => {
    const script = scriptedFindings();
    const { app, session } = await boot('owner', script.runtime);
    const response = await app.inject({
      method: 'GET',
      url: `/findings/${FINDING}/latest-observation`,
      remoteAddress: '198.51.100.14',
      headers: { cookie: session.cookie, origin: 'https://evil.example' },
    });
    expect(response.statusCode).toBe(200);
    expect(response.headers['cache-control']).toBe('private, no-store');
    expect(script.calls).toHaveLength(1);
    await app.close();
  });

  it('publishes creation fallback and each public aggregate without mappedResult', async () => {
    const cases = [
      foundResult({
        observationSource: 'creation',
        aggregate: 'affected',
        affectedSupportCount: 1,
      }),
      foundResult({
        observationSource: 'latest_repeated',
        aggregate: 'affected',
        affectedSupportCount: 1,
        versions: ['1.0.0', SECRET_VERSION],
        mappedResult: 'present',
      }),
      foundResult({
        observationSource: 'latest_repeated',
        aggregate: 'unaffected',
        unaffectedSupportCount: 1,
        mappedResult: 'absent',
      }),
      foundResult({
        observationSource: 'latest_repeated',
        aggregate: 'unknown',
        unknownSupportCount: 1,
        mappedResult: 'inconclusive',
      }),
      foundResult({
        observationSource: 'latest_repeated',
        aggregate: 'component_absent',
        graphCompleteness: 'complete',
        mappedResult: 'absent',
      }),
    ];
    for (const [index, result] of cases.entries()) {
      const script = scriptedFindings(() => result);
      const { app, session } = await boot('owner', script.runtime);
      const response = await get(app, session, FINDING, `198.51.100.${20 + index}`);
      expect(response.statusCode, result.projection.aggregate).toBe(200);
      expect(response.headers['cache-control']).toBe('private, no-store');
      const body = response.json() as Record<string, unknown>;
      expect(body['observationSource']).toBe(result.projection.observationSource);
      expect(body['aggregate']).toBe(result.projection.aggregate);
      expect(body['observedAt']).toBe(OBSERVED_AT);
      expect(body).not.toHaveProperty('mappedResult');
      expect(body).not.toHaveProperty('assetId');
      expect(body).not.toHaveProperty('componentId');
      expect(body).not.toHaveProperty('vulnerabilityId');
      expect(body).not.toHaveProperty('explanationCodes');
      const serialized = JSON.stringify(body);
      expect(serialized).not.toMatch(/"(present|absent|inconclusive)"/);
      expect(serialized).not.toContain(ASSET);
      expect(serialized).not.toContain('componentCount');
      expect(serialized).not.toContain('dependencyEdgeCount');
      await app.close();
    }
  });

  it('strips prohibited projection fields and rejects an unsupported envelope', async () => {
    const hostile = foundResult({
      observationSource: 'latest_repeated',
      aggregate: 'affected',
      affectedSupportCount: 1,
      versions: ['1.0.0'],
      mappedResult: 'present',
    });
    hostile.projection = {
      ...hostile.projection,
      history: [{ observationId: 'obs-1' }],
      supportIds: ['support-1'],
      replayFingerprint: 'fingerprint-1',
    } as typeof hostile.projection;
    const script = scriptedFindings(() => hostile);
    const { app, session } = await boot('owner', script.runtime);
    const response = await get(app, session, FINDING, '198.51.100.33');
    expect(response.statusCode).toBe(200);
    const serialized = JSON.stringify(response.json());
    expect(serialized).not.toContain('history');
    expect(serialized).not.toContain('support-1');
    expect(serialized).not.toContain('fingerprint-1');
    expect(serialized).not.toContain('mappedResult');
    await app.close();

    const rejected = [
      { ...foundResult(), schemaVersion: 'finding_latest_observation_external_result_v2' },
      {
        ...foundResult(),
        projection: {
          ...foundResult().projection,
          schemaVersion: 'finding_latest_observation_projection_v2',
        },
      },
      {
        schemaVersion: 'finding_latest_observation_external_result_v1',
        status: 'not_found',
        diagnostic: 'malformed_persisted_state',
      },
      { status: 'not_found' },
      {
        schemaVersion: 'finding_latest_observation_external_result_v1',
        status: 'found',
        projection: foundResult().projection,
        history: [],
      },
    ];
    for (const [index, result] of rejected.entries()) {
      const rejectedScript = scriptedFindings(() => result);
      const rejectedApp = await boot('owner', rejectedScript.runtime);
      const denied = await get(
        rejectedApp.app,
        rejectedApp.session,
        FINDING,
        `198.51.100.${34 + index}`,
      );
      expect(denied.statusCode).toBe(503);
      expectEnvelope(denied, 'internal', 'Finding operator is temporarily unavailable.');
      expect(denied.headers['cache-control']).toBe('private, no-store');
      expect(JSON.stringify(denied.json())).not.toContain('malformed');
      expect(JSON.stringify(denied.json())).not.toContain(FINDING);
      await rejectedApp.app.close();
    }
  });

  it('keeps the first eight sorted known versions and the omitted count', async () => {
    const versions = [
      '1.0.0',
      '1.0.1',
      '1.0.2',
      '1.0.3',
      '1.0.4',
      '1.0.5',
      '1.0.6',
      '1.0.7',
      '1.0.8',
    ];
    const script = scriptedFindings(() =>
      foundResult({
        observationSource: 'latest_repeated',
        aggregate: 'affected',
        affectedSupportCount: 9,
        versions,
      }),
    );
    const { app, session } = await boot('owner', script.runtime);
    const response = await get(app, session, FINDING, '198.51.100.30');
    expect(response.statusCode).toBe(200);
    const evidence = response.json().evidence as {
      knownVersions: {
        values: string[];
        truncated: boolean;
        omittedDistinctCount: number;
        distinctCount: number;
      };
    };
    expect(evidence.knownVersions).toEqual({
      values: versions.slice(0, 8),
      truncated: true,
      omittedDistinctCount: 1,
      distinctCount: 9,
    });
    await app.close();
  });

  it('returns one public not-found body for absent and foreign findings', async () => {
    const script = scriptedFindings((findingId) =>
      findingId === FINDING
        ? {
            schemaVersion: 'finding_latest_observation_external_result_v1',
            status: 'not_found',
          }
        : {
            schemaVersion: 'finding_latest_observation_external_result_v1',
            status: 'not_found',
          },
    );
    const { app, session } = await boot('owner', script.runtime);
    const absent = await get(app, session, ABSENT, '198.51.100.31');
    const foreign = await get(app, session, FINDING, '198.51.100.32');
    expect(absent.statusCode).toBe(404);
    expect(foreign.statusCode).toBe(404);
    expect(absent.json().error.code).toBe(foreign.json().error.code);
    expect(absent.json().error.message).toBe(foreign.json().error.message);
    expect(absent.json().error.message).toBe('Not found.');
    expect(JSON.stringify(absent.json())).not.toContain(ABSENT);
    expect(JSON.stringify(foreign.json())).not.toContain(FINDING);
    expect(absent.headers['cache-control']).toBe('private, no-store');
    expect(foreign.headers['cache-control']).toBe('private, no-store');
    await app.close();
  });

  it('maps malformed state, database failure, and contract mismatch to one 503', async () => {
    const unavailable = {
      schemaVersion: 'finding_latest_observation_external_result_v1' as const,
      status: 'unavailable' as const,
    };
    for (const [index, result] of [
      unavailable,
      'throw',
      foundResult({ findingId: ABSENT }),
    ].entries()) {
      const script = scriptedFindings(() => result);
      const { app, session, harness } = await boot('owner', script.runtime);
      const response = await get(app, session, FINDING, `198.51.100.${40 + index}`);
      expect(response.statusCode).toBe(503);
      expectEnvelope(response, 'internal', 'Finding operator is temporarily unavailable.');
      expect(response.headers['cache-control']).toBe('private, no-store');
      const serialized = JSON.stringify(response.json());
      expect(serialized).not.toContain('malformed');
      expect(serialized).not.toContain('database');
      expect(serialized).not.toContain('SELECT');
      expect(serialized).not.toContain(FINDING);
      expect(serialized).not.toContain(SECRET_VERSION);
      expect(harness.logs()).not.toContain(FINDING);
      expect(harness.logs()).not.toContain('SELECT');
      await app.close();
    }
  });

  it('keeps creation inspection successful when latest-observation is unavailable', async () => {
    const script = scriptedFindings(() => 'throw');
    const { app, session } = await boot('owner', script.runtime);
    const latest = await get(app, session, FINDING, '198.51.100.50');
    const inspected = await app.inject({
      method: 'GET',
      url: `/findings/${FINDING}`,
      remoteAddress: '198.51.100.51',
      headers: { cookie: session.cookie },
    });
    expect(latest.statusCode).toBe(503);
    expect(inspected.statusCode).toBe(200);
    expect(inspected.json()).toEqual(inspectionProjection());
    expect(inspected.json()).not.toHaveProperty('observationSource');
    expect(inspected.headers['cache-control']).toBe('private, no-store');
    await app.close();
  });

  it('limits the direct peer, ignores X-Forwarded-For, and fails closed', async () => {
    const script = scriptedFindings();
    const { app, session } = await boot('owner', script.runtime);
    const peer = '198.51.100.60';
    const statuses: number[] = [];
    for (let index = 0; index < 31; index += 1) {
      const response = await get(app, session, FINDING, peer, {
        'x-forwarded-for': `203.0.113.${index + 1}`,
      });
      statuses.push(response.statusCode);
    }
    expect(statuses.slice(0, 30)).toEqual(Array.from({ length: 30 }, () => 200));
    expect(statuses[30]).toBe(429);
    expect(script.calls).toHaveLength(30);
    const limited = await get(app, session, ABSENT, peer);
    expect(limited.statusCode).toBe(429);
    expectEnvelope(limited, 'rate_limited', 'Too many requests. Try again later.');
    expect(limited.headers['cache-control']).toBe('private, no-store');
    expect(JSON.stringify(limited.json())).not.toContain(ABSENT);
    expect(script.calls).toHaveLength(30);
    const otherPeer = await get(app, session, FINDING, '198.51.100.61', {
      'x-forwarded-for': '203.0.113.1',
    });
    expect(otherPeer.statusCode).toBe(200);
    const inspected = await app.inject({
      method: 'GET',
      url: `/findings/${FINDING}`,
      remoteAddress: peer,
      headers: { cookie: session.cookie },
    });
    expect(inspected.statusCode).toBe(200);
    expect(inspected.json()).toEqual(inspectionProjection());
    const now = Date.now;
    Date.now = () => now() + 60_000;
    try {
      const reset = await get(app, session, FINDING, peer);
      expect(reset.statusCode).toBe(200);
    } finally {
      Date.now = now;
    }
    const mapped = await boot('owner', scriptedFindings().runtime);
    const mappedPeer = '::ffff:198.51.100.70';
    for (let index = 0; index < 30; index += 1) {
      const response = await get(mapped.app, mapped.session, FINDING, mappedPeer);
      expect(response.statusCode).toBe(200);
    }
    const collapsed = await get(mapped.app, mapped.session, FINDING, '198.51.100.70');
    expect(collapsed.statusCode).toBe(429);
    await app.close();
    await mapped.app.close();

    const failing = scriptedFindings();
    const closed = await boot('owner', failing.runtime, {
      latestObservationPeerKey: () => {
        throw new Error('limiter store unavailable');
      },
    });
    const rejected = await get(closed.app, closed.session, FINDING, '198.51.100.71');
    expect(rejected.statusCode).toBe(429);
    expectEnvelope(rejected, 'rate_limited', 'Too many requests. Try again later.');
    expect(rejected.headers['cache-control']).toBe('private, no-store');
    expect(failing.calls).toHaveLength(0);
    expect(closed.harness.logs()).not.toContain(FINDING);
    await closed.app.close();
  });

  it('logs the route template and keeps metric labels bounded', async () => {
    const script = scriptedFindings(() =>
      foundResult({
        observationSource: 'latest_repeated',
        aggregate: 'affected',
        affectedSupportCount: 1,
        versions: [SECRET_VERSION],
      }),
    );
    const { app, session, harness } = await boot('owner', script.runtime);
    const before = harness.audit.events.length;
    const response = await get(app, session, FINDING, '198.51.100.80');
    expect(response.statusCode).toBe(200);
    const logs = harness.logs();
    expect(logs).toContain('/findings/:findingId/latest-observation');
    expect(logs).toContain('"outcome":"found"');
    expect(logs).not.toContain(FINDING);
    expect(logs).not.toContain(SECRET_VERSION);
    expect(logs).not.toContain(OBSERVED_AT);
    expect(logs).not.toContain('latest_repeated');
    expect(logs).not.toContain('component_absent');
    expect(harness.audit.events).toHaveLength(before);
    expect(harness.audit.events.map((event) => event.action)).not.toContain('finding.inspected');
    expect(harness.audit.events.map((event) => event.action)).not.toContain('finding.observed');
    const labels = latestObservationMetricLabels({ outcome: 'found', statusCode: 200 });
    expect(Object.keys(labels).sort()).toEqual([...LATEST_OBSERVATION_METRIC_LABEL_KEYS].sort());
    expect(labels).toEqual({
      route: '/findings/:findingId/latest-observation',
      method: 'GET',
      outcome: 'found',
      statusClass: '2xx',
    });
    expect(JSON.stringify(labels)).not.toContain(FINDING);
    const source = readFileSync(
      path.join(path.dirname(fileURLToPath(import.meta.url)), 'finding-latest-observation-http.ts'),
      'utf8',
    );
    expect(source).toContain('LATEST_OBSERVATION_METRIC_LABEL_KEYS');
    expect(source).not.toContain('auditEvent');
    await app.close();
  });

  it('scopes the service call to the trusted organization', async () => {
    const script = scriptedFindings();
    const { app, session, harness } = await boot('owner', script.runtime);
    const home = harness.organizations[0]?.id;
    const response = await get(app, session, FINDING, '198.51.100.81');
    expect(response.statusCode).toBe(200);
    expect(script.calls[0]).toEqual({ organizationId: home, findingId: FINDING });
    expect(JSON.stringify(script.calls[0])).not.toContain('permission');
    await app.close();
  });
});

async function boot(
  role: RoleName,
  findings: FindingOperatorRuntime,
  options?: {
    membershipCount?: 1 | 2;
    latestObservationPeerKey?: (request: FastifyRequest) => string;
  },
) {
  const harness = createAuthTestHarness({
    membershipCount: options?.membershipCount ?? 1,
    primaryRole: role,
  });
  const built = await buildTestApi({
    harness,
    findings,
    ...(options?.latestObservationPeerKey === undefined
      ? {}
      : { latestObservationPeerKey: options.latestObservationPeerKey }),
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

async function closeAll(...sessions: { app: FastifyInstance }[]): Promise<void> {
  await Promise.all(sessions.map(async (session) => session.app.close()));
}

async function get(
  app: FastifyInstance,
  session: { cookie: string },
  findingId: string,
  remoteAddress: string,
  headers?: Record<string, string>,
) {
  return app.inject({
    method: 'GET',
    url: `/findings/${findingId}/latest-observation`,
    remoteAddress,
    headers: { cookie: session.cookie, ...headers },
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
